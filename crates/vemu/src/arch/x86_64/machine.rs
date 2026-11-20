//! [`ArchMachine`] for x86_64: the glue between the common machine code and
//! the pure parts of this module (layout, bzImage, boot tables, devices).

use std::sync::Arc;

use vemu_hv::{ArchVmInfo, VmConfig};
use vemu_virtio::MMIO_SIZE;

use super::acpi::VirtioDev;
use super::boot::{self, MachineDesc};
use super::bzimage::BzImage;
use super::devices;
use super::layout::{self, BootLayout};
use super::uart::Serial16550;
use crate::arch::{ArchHelp, ArchMachine, ArchSetup, BuildCtx, RamRegion, VirtioSlot};
use crate::bootfile::Initrd;
use crate::cli::Config;
use crate::irq::VmIrqLine;

const _: () = assert!(MMIO_SIZE <= layout::VIRTIO_SLOT_SIZE);

/// The x86_64 machine, between [`ArchMachine::prepare`] and
/// [`ArchMachine::build`].
pub struct X86_64 {
    kernel: BzImage,
    initrd: Option<Initrd>,
    boot: BootLayout,
}

impl ArchMachine for X86_64 {
    const MAX_CPUS: usize = 64;
    /// Linux's x86 COMMAND_LINE_SIZE.
    const CMDLINE_MAX: usize = layout::CMDLINE_MAX as usize;
    const VIRTIO_SLOTS: usize = layout::VIRTIO_SLOTS;
    const HELP: ArchHelp = ArchHelp {
        guest: "an x86_64",
        kernel: "x86_64 Linux bzImage (arch/x86/boot/bzImage)",
        initrd: "initramfs / initrd",
        debug_uart: "add a 16550 UART at I/O port 0x3f8 printing to\n                         \
                     stderr (for earlyprintk / console=ttyS0)",
    };

    fn prepare(cfg: &Config) -> Result<X86_64, String> {
        layout::check_ram_size(cfg.memory).map_err(|e| e.to_string())?;
        let kernel = BzImage::from_file(&cfg.kernel, cfg.memory).map_err(|e| e.to_string())?;
        boot::check_cmdline(&kernel, &cfg.cmdline())?;
        for w in boot::cmdline_warnings(&cfg.cmdline()) {
            crate::log!("warning: {w}");
        }
        let initrd = cfg
            .initrd
            .as_deref()
            .map(|p| Initrd::open(p, cfg.memory))
            .transpose()?;
        let boot = layout::boot_layout(
            cfg.memory,
            &kernel.placement(),
            initrd.as_ref().map(Initrd::size),
        )
        .map_err(|e| e.to_string())?;
        Ok(X86_64 {
            kernel,
            initrd,
            boot,
        })
    }

    fn vm_config(&self, cfg: &Config) -> VmConfig {
        VmConfig { cpus: cfg.cpus }
    }

    fn ram_regions(&self, cfg: &Config) -> Vec<RamRegion> {
        layout::ram_ranges(cfg.memory)
            .into_iter()
            .map(|(gpa, size)| RamRegion { gpa, size })
            .collect()
    }

    fn virtio_slot(&self, _info: &ArchVmInfo, n: usize) -> Result<VirtioSlot, String> {
        if n >= layout::VIRTIO_SLOTS {
            return Err(format!(
                "no virtio slot {n} (the machine has {})",
                layout::VIRTIO_SLOTS
            ));
        }
        Ok(VirtioSlot {
            base: layout::virtio_slot_base(n),
            size: MMIO_SIZE,
            irq: layout::virtio_gsi(n),
        })
    }

    fn build(self, ctx: BuildCtx<'_>) -> Result<ArchSetup, String> {
        let X86_64 {
            kernel,
            mut initrd,
            boot,
        } = self;
        // Nothing to read from the (empty) x86 ArchVmInfo, no MMIO devices
        // besides the virtio transports.
        let BuildCtx {
            cfg,
            cmdline,
            vm,
            info: _,
            ram,
            virtio,
            mmio: _,
            pio,
            control,
        } = ctx;
        let virtio: Vec<VirtioDev> = virtio
            .iter()
            .map(|s| VirtioDev {
                base: s.base,
                size: s.size,
                gsi: s.irq,
            })
            .collect();
        let state = boot::load(
            ram,
            &kernel,
            &boot,
            initrd.as_mut(),
            &MachineDesc {
                cpus: cfg.cpus,
                ram_size: cfg.memory,
                cmdline,
                virtio: &virtio,
                com1: cfg.debug_uart,
            },
        )?;
        drop(kernel);
        drop(initrd);

        let uart = cfg.debug_uart.then(|| {
            let irq = Arc::new(VmIrqLine::new(vm.clone(), layout::COM1_GSI));
            Serial16550::new(Box::new(std::io::stderr()), irq)
        });
        devices::install(pio, control, uart)?;
        Ok(ArchSetup { boot: state })
    }
}
