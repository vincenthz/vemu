//! Device tree for the machine.
//!
//! Modelled on what QEMU's `virt` machine generates for `-accel hvf
//! -cpu host` with GICv3 (or `-accel kvm` with GICv2 on a host whose KVM
//! only emulates a GICv2), minus what vemu doesn't have (PCIe, flash,
//! fw_cfg, GPIO, PMU). Differences from QEMU worth knowing:
//!
//! - only populated virtio-mmio slots get a node (QEMU lists all 32), so the
//!   guest doesn't probe empty windows;
//! - virtio interrupts are level-high (QEMU says edge): the transport models
//!   a level line that stays up until the driver acknowledges;
//! - the GIC redistributor `reg` covers just this VM's vCPUs
//!   ([`GicInfo::redist_region_size`]);
//! - no `arm,armv8-pmu` node: the PMU is not exposed (Hypervisor.framework
//!   has none; the KVM backend does not enable KVM_ARM_VCPU_PMU_V3);
//! - a GICv2 `reg` has the sizes KVM emulates (distributor 4 KiB, CPU
//!   interface 8 KiB) rather than QEMU's 64 KiB windows.
//!
//! The `cpu` nodes' `reg` (and so PSCI `CPU_ON` targets) is the MPIDR
//! affinity the backend gives each vCPU ([`ArchVmInfo::mpidr`]): Aff0 =
//! index on HVF, 16 vCPUs per Aff1 on KVM.

use vemu_fdt::{FdtWriter, GIC_PPI, GIC_SPI, IRQ_TYPE_LEVEL_HIGH};
use vemu_hv::{ArchVmInfo, GicVersion};

/// The PL031 real-time clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcNode {
    pub base: u64,
    pub size: u64,
    pub intid: u32,
}

/// One populated virtio-mmio slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioNode {
    pub base: u64,
    pub size: u64,
    /// Absolute GIC INTID (an SPI).
    pub intid: u32,
}

/// The debug PL011.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UartNode {
    pub base: u64,
    pub size: u64,
    pub intid: u32,
}

/// Everything the device tree describes.
pub struct MachineDesc<'a> {
    pub cpus: usize,
    pub ram_base: u64,
    pub ram_size: u64,
    /// The interrupt controller and the vCPUs' MPIDRs, from
    /// [`vemu_hv::Vm::arch_info`].
    pub info: ArchVmInfo,
    pub cmdline: &'a str,
    /// `[start, end)` of the initrd in guest memory.
    pub initrd: Option<(u64, u64)>,
    pub virtio: &'a [VirtioNode],
    /// When set, the UART also becomes `/chosen/stdout-path` (so a bare
    /// `earlycon` on the command line finds it).
    pub uart: Option<UartNode>,
    /// The PL031 (always present on a real machine; optional for tests).
    pub rtc: Option<RtcNode>,
    /// Entropy for `/chosen/rng-seed` (seeds the guest CRNG at boot).
    pub rng_seed: [u8; 32],
    /// `/chosen/kaslr-seed`.
    pub kaslr_seed: u64,
}

/// Architected timer PPIs (secure phys, non-secure phys, virtual, hyp), as
/// DT PPI numbers (INTID - 16): 29, 30, 27, 26.
const TIMER_PPIS: [u32; 4] = [13, 14, 11, 10];
/// GICv2 only: PPI `interrupts` cells carry the CPUs the PPI is wired to
/// in bits 15:8 (`GIC_CPU_MASK_SIMPLE(n)` of the kernel's
/// dt-bindings/interrupt-controller/arm-gic.h); GICv3 has no such field.
fn gic_v2_cpu_mask(cpus: usize) -> u32 {
    ((1u32 << cpus.min(8)) - 1) << 8
}
/// Frequency advertised for the PrimeCells' clocks: the AMBA bus needs an
/// `apb_pclk` to probe the PL011 and PL031; only the PL011 driver uses the
/// rate, for baud-rate maths, which this UART ignores.
const UART_CLOCK_HZ: u32 = 24_000_000;

/// Build the DTB.
pub fn build(m: &MachineDesc<'_>) -> vemu_fdt::Result<Vec<u8>> {
    let mut fdt = FdtWriter::new();
    let gic_phandle = fdt.alloc_phandle();
    let clk_phandle = fdt.alloc_phandle();

    let root = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_string("model", "vemu")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_u32("interrupt-parent", gic_phandle)?;
    fdt.property_null("dma-coherent")?;

    let chosen = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", m.cmdline)?;
    if let Some((start, end)) = m.initrd {
        fdt.property_u64("linux,initrd-start", start)?;
        fdt.property_u64("linux,initrd-end", end)?;
    }
    if let Some(u) = m.uart {
        fdt.property_string("stdout-path", &format!("/pl011@{:x}", u.base))?;
    }
    fdt.property("rng-seed", &m.rng_seed)?;
    fdt.property_u64("kaslr-seed", m.kaslr_seed)?;
    fdt.end_node(chosen)?;

    let memory = fdt.begin_node(&format!("memory@{:x}", m.ram_base))?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[m.ram_base, m.ram_size])?;
    fdt.end_node(memory)?;

    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 1)?;
    fdt.property_u32("#size-cells", 0)?;
    for i in 0..m.cpus {
        // MPIDR_EL1 affinity of vCPU i (Aff2.Aff1.Aff0: fits one cell).
        let mpidr = m.info.mpidr(i) as u32;
        let cpu = fdt.begin_node(&format!("cpu@{mpidr:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        fdt.property_u32("reg", mpidr)?;
        fdt.property_string("enable-method", "psci")?;
        fdt.end_node(cpu)?;
    }
    fdt.end_node(cpus)?;

    let psci = fdt.begin_node("psci")?;
    fdt.property_string_list("compatible", &["arm,psci-1.0", "arm,psci-0.2"])?;
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci)?;

    let g = &m.info.gic;
    let gic = fdt.begin_node(&format!("intc@{:x}", g.dist_base))?;
    fdt.property_string(
        "compatible",
        match g.version {
            GicVersion::V3 => "arm,gic-v3",
            GicVersion::V2 => "arm,cortex-a15-gic",
        },
    )?;
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("ranges")?;
    match g.version {
        GicVersion::V3 => {
            fdt.property_u32("#redistributor-regions", 1)?;
            fdt.property_array_u64(
                "reg",
                &[
                    g.dist_base,
                    g.dist_size,
                    g.redist_base,
                    g.redist_region_size,
                ],
            )?;
        }
        GicVersion::V2 => {
            fdt.property_array_u64("reg", &[g.dist_base, g.dist_size, g.cpu_base, g.cpu_size])?;
        }
    }
    fdt.property_u32("phandle", gic_phandle)?;
    fdt.end_node(gic)?;

    let timer = fdt.begin_node("timer")?;
    fdt.property_string_list("compatible", &["arm,armv8-timer", "arm,armv7-timer"])?;
    let ppi_flags = IRQ_TYPE_LEVEL_HIGH
        | match g.version {
            GicVersion::V3 => 0,
            GicVersion::V2 => gic_v2_cpu_mask(m.cpus),
        };
    let irqs: Vec<u32> = TIMER_PPIS
        .iter()
        .flat_map(|&ppi| [GIC_PPI, ppi, ppi_flags])
        .collect();
    fdt.property_array_u32("interrupts", &irqs)?;
    fdt.property_null("always-on")?;
    fdt.end_node(timer)?;

    if m.uart.is_some() || m.rtc.is_some() {
        let clk = fdt.begin_node("apb-pclk")?;
        fdt.property_string("compatible", "fixed-clock")?;
        fdt.property_u32("#clock-cells", 0)?;
        fdt.property_u32("clock-frequency", UART_CLOCK_HZ)?;
        fdt.property_string("clock-output-names", "clk24mhz")?;
        fdt.property_u32("phandle", clk_phandle)?;
        fdt.end_node(clk)?;
    }

    if let Some(u) = m.uart {
        let uart = fdt.begin_node(&format!("pl011@{:x}", u.base))?;
        fdt.property_string_list("compatible", &["arm,pl011", "arm,primecell"])?;
        fdt.property_array_u64("reg", &[u.base, u.size])?;
        fdt.property_array_u32("interrupts", &spi(u.intid))?;
        fdt.property_string_list("clock-names", &["uartclk", "apb_pclk"])?;
        fdt.property_array_u32("clocks", &[clk_phandle, clk_phandle])?;
        fdt.end_node(uart)?;
    }

    // As QEMU `virt` describes it (the binding has no `clocks` for the
    // counter itself; `apb_pclk` is the AMBA bus clock).
    if let Some(r) = m.rtc {
        let rtc = fdt.begin_node(&format!("pl031@{:x}", r.base))?;
        fdt.property_string_list("compatible", &["arm,pl031", "arm,primecell"])?;
        fdt.property_array_u64("reg", &[r.base, r.size])?;
        fdt.property_array_u32("interrupts", &spi(r.intid))?;
        fdt.property_string("clock-names", "apb_pclk")?;
        fdt.property_u32("clocks", clk_phandle)?;
        fdt.end_node(rtc)?;
    }

    for v in m.virtio {
        let node = fdt.begin_node(&format!("virtio_mmio@{:x}", v.base))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[v.base, v.size])?;
        fdt.property_array_u32("interrupts", &spi(v.intid))?;
        fdt.property_null("dma-coherent")?;
        fdt.end_node(node)?;
    }

    fdt.end_node(root)?;
    fdt.finish()
}

/// `interrupts` cells for a level-high SPI with absolute INTID `intid`.
fn spi(intid: u32) -> [u32; 3] {
    [GIC_SPI, intid - 32, IRQ_TYPE_LEVEL_HIGH]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::layout;
    use std::process::Command;
    use vemu_hv::GicInfo;

    fn gic_v3(cpus: u64) -> GicInfo {
        GicInfo {
            version: GicVersion::V3,
            dist_base: layout::GIC_DIST_BASE,
            dist_size: 0x10000,
            redist_base: layout::GIC_REDIST_BASE,
            redist_region_size: cpus * 0x20000,
            redist_stride: 0x20000,
            cpu_base: 0,
            cpu_size: 0,
            spi_base: 32,
            spi_count: 988,
        }
    }

    /// What the KVM backend reports for a GICv2 host.
    fn gic_v2() -> GicInfo {
        GicInfo {
            version: GicVersion::V2,
            dist_base: layout::GIC_DIST_BASE,
            dist_size: 0x1000,
            redist_base: 0,
            redist_region_size: 0,
            redist_stride: 0,
            cpu_base: layout::GIC_V2_CPU_BASE,
            cpu_size: 0x2000,
            spi_base: 32,
            spi_count: 256,
        }
    }

    /// HVF's report: Aff0 = index.
    fn hvf(gic: GicInfo) -> ArchVmInfo {
        ArchVmInfo {
            gic,
            mpidr_aff0_cpus: 256,
        }
    }

    fn desc<'a>(virtio: &'a [VirtioNode], uart: bool) -> MachineDesc<'a> {
        MachineDesc {
            cpus: 2,
            ram_base: layout::RAM_BASE,
            ram_size: 1 << 30,
            info: hvf(gic_v3(2)),
            cmdline: "console=hvc0 quiet",
            initrd: Some((0x7fe0_0000 - 0x10000, 0x7fe0_0000 - 0x123)),
            virtio,
            uart: uart.then_some(UartNode {
                base: layout::UART_BASE,
                size: layout::UART_SIZE,
                intid: layout::UART_INTID,
            }),
            rtc: Some(RtcNode {
                base: layout::RTC_BASE,
                size: layout::RTC_SIZE,
                intid: layout::RTC_INTID,
            }),
            rng_seed: [0xab; 32],
            kaslr_seed: 0x1122_3344_5566_7788,
        }
    }

    fn slots(n: usize) -> Vec<VirtioNode> {
        (0..n)
            .map(|i| VirtioNode {
                base: layout::virtio_slot_base(i),
                size: layout::VIRTIO_SLOT_SIZE,
                intid: layout::virtio_intid(i),
            })
            .collect()
    }

    /// Decompile with dtc, checking it has no complaints; `None` (test
    /// skipped) when dtc is not installed.
    fn dts(dtb: &[u8], name: &str) -> Option<String> {
        let dir = std::env::temp_dir().join(format!("vemu-dtb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.dtb"));
        std::fs::write(&path, dtb).unwrap();
        let fork_guard = crate::test_support::fork_lock();
        let out = Command::new("dtc")
            .args(["-I", "dtb", "-O", "dts"])
            .arg(&path)
            .output();
        drop(fork_guard);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        let Ok(out) = out else {
            eprintln!("skipping: dtc not installed");
            return None;
        };
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "dtc failed: {stderr}");
        assert!(stderr.trim().is_empty(), "dtc warnings: {stderr}");
        Some(String::from_utf8(out.stdout).unwrap())
    }

    fn assert_contains(dts: &str, want: &[&str]) {
        for w in want {
            assert!(dts.contains(w), "missing {w:?} in:\n{dts}");
        }
    }

    #[test]
    fn builds_valid_header() {
        let v = slots(3);
        let dtb = build(&desc(&v, true)).unwrap();
        assert_eq!(&dtb[0..4], &0xd00d_feed_u32.to_be_bytes());
        let total = u32::from_be_bytes(dtb[4..8].try_into().unwrap()) as usize;
        assert_eq!(total, dtb.len());
        assert!((dtb.len() as u64) < layout::DTB_MAX_SIZE);
    }

    /// Decompile with dtc (when installed) and check the important bits.
    #[test]
    fn dtc_decompiles_cleanly() {
        let v = slots(2);
        let dtb = build(&desc(&v, true)).unwrap();
        let Some(dts) = dts(&dtb, "machine") else {
            return;
        };
        assert_contains(
            &dts,
            &[
                "bootargs = \"console=hvc0 quiet\";",
                "linux,initrd-start = <0x00 0x7fdf0000>;",
                "linux,initrd-end = <0x00 0x7fdffedd>;",
                "stdout-path = \"/pl011@9000000\";",
                "memory@40000000 {",
                "reg = <0x00 0x40000000 0x00 0x40000000>;",
                "cpu@1 {",
                "enable-method = \"psci\";",
                "compatible = \"arm,psci-1.0\", \"arm,psci-0.2\";",
                "method = \"hvc\";",
                "intc@8000000 {",
                "compatible = \"arm,gic-v3\";",
                "#redistributor-regions = <0x01>;",
                "reg = <0x00 0x8000000 0x00 0x10000 0x00 0x80a0000 0x00 0x40000>;",
                "interrupts = <0x01 0x0d 0x04 0x01 0x0e 0x04 0x01 0x0b 0x04 0x01 0x0a 0x04>;",
                "pl011@9000000 {",
                "interrupts = <0x00 0x01 0x04>;",
                "pl031@9010000 {",
                "compatible = \"arm,pl031\", \"arm,primecell\";",
                "reg = <0x00 0x9010000 0x00 0x1000>;",
                "interrupts = <0x00 0x02 0x04>;",
                "clock-names = \"apb_pclk\";",
                "virtio_mmio@a000000 {",
                "virtio_mmio@a000200 {",
                "reg = <0x00 0xa000200 0x00 0x200>;",
                "interrupts = <0x00 0x11 0x04>;",
            ],
        );
        assert!(!dts.contains("virtio_mmio@a000400"));
        assert!(!dts.contains("cpu@2"));
    }

    /// The GICv2 variant (KVM on hosts without GICv3 emulation): QEMU
    /// `virt`'s `arm,cortex-a15-gic` node, distributor + CPU interface, and
    /// PPIs routed to every CPU.
    #[test]
    fn gic_v2_variant() {
        let v = slots(1);
        let m = MachineDesc {
            cpus: 4,
            info: ArchVmInfo {
                gic: gic_v2(),
                mpidr_aff0_cpus: 16,
            },
            ..desc(&v, true)
        };
        let dtb = build(&m).unwrap();
        let Some(dts) = dts(&dtb, "gicv2") else {
            return;
        };
        assert_contains(
            &dts,
            &[
                "intc@8000000 {",
                "compatible = \"arm,cortex-a15-gic\";",
                "#interrupt-cells = <0x03>;",
                "interrupt-controller;",
                "reg = <0x00 0x8000000 0x00 0x1000 0x00 0x8010000 0x00 0x2000>;",
                // GIC_CPU_MASK_SIMPLE(4) | IRQ_TYPE_LEVEL_HIGH = 0xf04.
                "interrupts = <0x01 0x0d 0xf04 0x01 0x0e 0xf04 0x01 0x0b 0xf04 0x01 0x0a 0xf04>;",
                "cpu@3 {",
                // SPIs carry no CPU mask.
                "interrupts = <0x00 0x01 0x04>;",
                "interrupts = <0x00 0x10 0x04>;",
            ],
        );
        assert!(!dts.contains("redistributor"));
        assert!(!dts.contains("arm,gic-v3"));
    }

    #[test]
    fn gic_v2_cpu_masks() {
        assert_eq!(gic_v2_cpu_mask(1), 0x100);
        assert_eq!(gic_v2_cpu_mask(2), 0x300);
        assert_eq!(gic_v2_cpu_mask(8), 0xff00);
        assert_eq!(
            gic_v2_cpu_mask(9),
            0xff00,
            "a GICv2 has at most 8 CPU interfaces"
        );
    }

    /// With KVM's MPIDR layout (16 vCPUs per Aff1), vCPU 16 is `cpu@100`
    /// with `reg = <0x100>`: what KVM's in-kernel PSCI matches CPU_ON
    /// targets against.
    #[test]
    fn cpu_reg_is_the_backend_mpidr() {
        let m = MachineDesc {
            cpus: 18,
            info: ArchVmInfo {
                gic: gic_v3(18),
                mpidr_aff0_cpus: 16,
            },
            ..desc(&[], false)
        };
        let kvm = build(&m).unwrap();
        // HVF numbers them flat.
        let flat = build(&MachineDesc {
            info: hvf(gic_v3(18)),
            ..m
        })
        .unwrap();
        let (Some(kvm), Some(flat)) = (dts(&kvm, "mpidr"), dts(&flat, "flat")) else {
            return;
        };
        assert_contains(
            &kvm,
            &[
                "cpu@0 {",
                "cpu@f {",
                "reg = <0x0f>;",
                "cpu@100 {",
                "reg = <0x100>;",
                "cpu@101 {",
                "reg = <0x101>;",
            ],
        );
        assert!(!kvm.contains("cpu@10 {"), "{kvm}");
        assert!(!kvm.contains("cpu@11 {"), "{kvm}");
        assert_contains(&flat, &["cpu@10 {", "reg = <0x10>;", "cpu@11 {"]);
        assert!(!flat.contains("cpu@100"));
    }

    /// Without the debug UART the RTC still gets the `apb_pclk` the AMBA
    /// bus needs to probe it.
    #[test]
    fn rtc_without_uart_has_its_bus_clock() {
        let dtb = build(&desc(&[], false)).unwrap();
        let Some(dts) = dts(&dtb, "rtc") else {
            return;
        };
        assert_contains(
            &dts,
            &[
                "apb-pclk {",
                "compatible = \"fixed-clock\";",
                "pl031@9010000 {",
                "clock-names = \"apb_pclk\";",
            ],
        );
        assert!(!dts.contains("pl011"));
        assert!(!dts.contains("stdout-path"));
    }

    #[test]
    fn minimal_machine() {
        let dtb = build(&MachineDesc {
            cpus: 1,
            initrd: None,
            rtc: None,
            ..desc(&[], false)
        })
        .unwrap();
        let s = String::from_utf8_lossy(&dtb);
        assert!(!s.contains("pl011"));
        assert!(!s.contains("pl031"));
        assert!(!s.contains("apb-pclk"));
        assert!(!s.contains("stdout-path"));
        assert!(!s.contains("linux,initrd-start"));
    }
}
