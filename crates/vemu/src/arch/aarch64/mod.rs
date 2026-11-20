//! The aarch64 machine: QEMU `virt`-like layout ([`layout`]), arm64 `Image`
//! boot ([`loader`]), a generated device tree ([`dtb`]) with a GICv3 (or
//! a GICv2 on KVM hosts that only emulate that) and
//! PSCI over HVC, virtio-mmio devices, a PL031 real-time clock
//! ([`pl031`]) and an optional debug PL011 ([`pl011`]).

pub mod dtb;
pub mod layout;
pub mod loader;
pub mod pl011;
pub mod pl031;

use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};

use vemu_core::MmioDevice;
use vemu_hv::{ArchVmInfo, BootState, GicInfo, GicRequest, VmConfig};
use vemu_virtio::MMIO_SIZE;

use super::{ArchHelp, ArchMachine, ArchSetup, BuildCtx, RamRegion, VirtioSlot};
use crate::bootfile::Initrd;
use crate::cli::Config;
use crate::irq::VmIrqLine;
use dtb::{MachineDesc, RtcNode, UartNode, VirtioNode};
use layout::BootLayout;
use loader::KernelImage;
use pl011::Pl011;
use pl031::Pl031;

/// The aarch64 machine, between [`ArchMachine::prepare`] and
/// [`ArchMachine::build`].
pub struct Aarch64 {
    kernel: KernelImage,
    initrd: Option<Initrd>,
    boot: BootLayout,
}

impl ArchMachine for Aarch64 {
    const MAX_CPUS: usize = layout::MAX_CPUS;
    /// Linux's arm64 COMMAND_LINE_SIZE.
    const CMDLINE_MAX: usize = 2048;
    const VIRTIO_SLOTS: usize = layout::VIRTIO_SLOTS;
    const HELP: ArchHelp = ArchHelp {
        guest: "an arm64",
        kernel: "uncompressed arm64 Linux Image (arch/arm64/boot/Image)",
        initrd: "initramfs / initrd loaded next to the device tree",
        debug_uart: "add a write-only PL011 at 0x09000000 printing to\n                         \
                     stderr (for earlycon / console=ttyAMA0)",
    };

    fn prepare(cfg: &Config) -> Result<Aarch64, String> {
        // Sizes come from the files' metadata, so nothing too large for the
        // guest is read; the initrd is copied straight into guest RAM later.
        let kernel = KernelImage::from_file(&cfg.kernel, cfg.memory).map_err(|e| e.to_string())?;
        let initrd = cfg
            .initrd
            .as_deref()
            .map(|p| Initrd::open(p, cfg.memory))
            .transpose()?;
        let boot = layout::boot_layout(
            cfg.memory,
            kernel.text_offset(),
            kernel.load_size(),
            initrd.as_ref().map(Initrd::size),
        )
        .map_err(|e| e.to_string())?;
        Ok(Aarch64 {
            kernel,
            initrd,
            boot,
        })
    }

    fn vm_config(&self, cfg: &Config) -> VmConfig {
        VmConfig {
            cpus: cfg.cpus,
            gic: GicRequest {
                dist_base: layout::GIC_DIST_BASE,
                redist_base: layout::GIC_REDIST_BASE,
                v2_cpu_base: layout::GIC_V2_CPU_BASE,
            },
        }
    }

    fn ram_regions(&self, cfg: &Config) -> Vec<RamRegion> {
        vec![RamRegion {
            gpa: layout::RAM_BASE,
            size: cfg.memory,
        }]
    }

    fn virtio_slot(&self, info: &ArchVmInfo, n: usize) -> Result<VirtioSlot, String> {
        let irq = layout::virtio_intid(n);
        check_spi(&info.gic, irq)?;
        Ok(VirtioSlot {
            base: layout::virtio_slot_base(n),
            size: MMIO_SIZE,
            irq,
        })
    }

    fn build(self, ctx: BuildCtx<'_>) -> Result<ArchSetup, String> {
        let Aarch64 {
            kernel,
            mut initrd,
            boot,
        } = self;
        let mem = ctx.ram;
        mem.write(boot.kernel, kernel.bytes())
            .map_err(|e| format!("cannot load the kernel: {e}"))?;
        drop(kernel);
        if let (Some((start, _)), Some(initrd)) = (boot.initrd, initrd.as_mut()) {
            initrd.load(mem, start)?;
        }
        drop(initrd);

        // GICv3, or GICv2 (KVM hosts without GICv3 emulation): dtb.rs
        // describes either.
        let gic = ctx.info.gic;

        let uart = if ctx.cfg.debug_uart {
            let node = UartNode {
                base: layout::UART_BASE,
                size: layout::UART_SIZE,
                intid: layout::UART_INTID,
            };
            check_spi(&gic, node.intid)?;
            let irq = Arc::new(VmIrqLine::new(ctx.vm.clone(), node.intid));
            let dev: Arc<Mutex<dyn MmioDevice>> =
                Arc::new(Mutex::new(Pl011::new(Box::new(std::io::stderr()), irq)));
            ctx.mmio.insert("pl011", node.base, node.size, dev)?;
            Some(node)
        } else {
            None
        };

        // The wall clock, always present (as on QEMU `virt`): without it the
        // guest boots at 1970 until something like NTP corrects it.
        let rtc = RtcNode {
            base: layout::RTC_BASE,
            size: layout::RTC_SIZE,
            intid: layout::RTC_INTID,
        };
        check_spi(&gic, rtc.intid)?;
        let irq = Arc::new(VmIrqLine::new(ctx.vm.clone(), rtc.intid));
        let dev: Arc<Mutex<dyn MmioDevice>> = Arc::new(Mutex::new(Pl031::new(irq)));
        ctx.mmio.insert("pl031", rtc.base, rtc.size, dev)?;

        let virtio: Vec<VirtioNode> = ctx
            .virtio
            .iter()
            .map(|s| VirtioNode {
                base: s.base,
                size: s.size,
                intid: s.irq,
            })
            .collect();
        let (rng_seed, kaslr_seed) = boot_seeds()?;
        let dtb = dtb::build(&MachineDesc {
            cpus: ctx.cfg.cpus,
            ram_base: layout::RAM_BASE,
            ram_size: ctx.cfg.memory,
            info: *ctx.info,
            cmdline: ctx.cmdline,
            initrd: boot.initrd,
            virtio: &virtio,
            uart,
            rtc: Some(rtc),
            rng_seed,
            kaslr_seed,
        })
        .map_err(|e| format!("cannot build the device tree: {e}"))?;
        if dtb.len() as u64 > layout::DTB_MAX_SIZE {
            return Err(format!("device tree too large ({} bytes)", dtb.len()));
        }
        mem.write(boot.dtb, &dtb)
            .map_err(|e| format!("cannot load the device tree: {e}"))?;

        Ok(ArchSetup {
            boot: BootState {
                pc: boot.kernel,
                x0: boot.dtb,
            },
        })
    }
}

/// Check the GIC can raise `intid`.
fn check_spi(gic: &GicInfo, intid: u32) -> Result<(), String> {
    if gic.is_spi(intid) {
        Ok(())
    } else {
        Err(format!(
            "interrupt {intid} is outside the GIC's SPI range {}..{}",
            gic.spi_base,
            gic.spi_base + gic.spi_count
        ))
    }
}

/// Fresh entropy for the guest's `rng-seed` and `kaslr-seed`.
fn boot_seeds() -> Result<([u8; 32], u64), String> {
    let mut buf = [0u8; 40];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    let mut rng = [0u8; 32];
    rng.copy_from_slice(&buf[..32]);
    let kaslr = u64::from_le_bytes(buf[32..].try_into().expect("8 bytes"));
    Ok((rng, kaslr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use vemu_hv::GicVersion;

    const MIB: u64 = 1 << 20;

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vemu-aarch64-{name}-{}", std::process::id()))
    }

    fn gic(spi_base: u32, spi_count: u32) -> GicInfo {
        GicInfo {
            version: GicVersion::V3,
            dist_base: layout::GIC_DIST_BASE,
            dist_size: 0x10000,
            redist_base: layout::GIC_REDIST_BASE,
            redist_region_size: 0x20000,
            redist_stride: 0x20000,
            cpu_base: 0,
            cpu_size: 0,
            spi_base,
            spi_count,
        }
    }

    #[test]
    fn spi_range_is_checked() {
        assert!(check_spi(&gic(32, 988), 48).is_ok());
        assert!(check_spi(&gic(32, 988), 1019).is_ok());
        let e = check_spi(&gic(32, 16), 48).unwrap_err();
        assert_eq!(e, "interrupt 48 is outside the GIC's SPI range 32..48");
        assert!(check_spi(&gic(32, 988), 31).is_err());
    }

    #[test]
    fn initrd_too_large_for_the_layout_is_refused_from_its_size() {
        // Fits in RAM, but not next to the kernel and DTB: refused by the
        // layout, from the metadata size alone (sparse file, never read).
        let path = temp_file("sparse");
        let f = File::create(&path).unwrap();
        f.set_len(60 * MIB).unwrap();
        let initrd = Initrd::open(&path, 64 * MIB).unwrap();
        assert!(layout::boot_layout(64 * MIB, 0, 8 * MIB, Some(initrd.size())).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}
