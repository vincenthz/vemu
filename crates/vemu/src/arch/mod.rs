//! Guest-architecture machine models behind one interface, [`ArchMachine`].
//!
//! The common code (`machine.rs`) owns everything that is the same on every
//! architecture: the command line, the VM and its RAM, the virtio devices
//! and their transports, the MMIO and port-I/O buses, the vCPU threads and
//! shutdown. An architecture module supplies what differs: boot-image
//! formats and placement, the guest-physical map (RAM regions, virtio slot
//! addresses and interrupt lines), firmware tables (DTB, ACPI/e820),
//! architecture-only devices (debug UART, i8042, ACPI registers, ...) and
//! the boot vCPU's entry state. Exactly one module is compiled, for the host
//! architecture (the guest architecture always equals the host's), and
//! [`Machine`] names it. See docs/kvm-design.md, "Binary arch interface".

use std::sync::Arc;

use vemu_core::GuestMemory;
use vemu_hv::{ArchVmInfo, BootState, Vm, VmConfig};

use crate::bus::{MmioBus, PortIoBus};
use crate::cli::Config;
use crate::power::Control;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::Aarch64 as Machine;

// Also built for tests elsewhere: its pure parts are tested on every host.
#[cfg(any(target_arch = "x86_64", test))]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86_64 as Machine;

/// Most vCPUs the host architecture's machine supports (`--cpus` limit).
pub const MAX_CPUS: usize = <Machine as ArchMachine>::MAX_CPUS;

/// One guest RAM region. The common code allocates one [`GuestMemory`]
/// holding every region (`GuestMemory::with_regions`) and maps it into the
/// VM, one memory slot per region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRegion {
    pub gpa: u64,
    pub size: u64,
}

/// Where virtio-mmio slot `n` sits and which interrupt line it raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioSlot {
    /// Guest-physical base of the transport's registers.
    pub base: u64,
    /// Size of the MMIO window (at least `vemu_virtio::MMIO_SIZE`).
    pub size: u64,
    /// [`Vm::set_irq_line`] number: aarch64 GIC SPI INTID, x86_64 IOAPIC
    /// GSI.
    pub irq: u32,
}

/// Architecture-specific lines of `--help`.
#[derive(Debug, Clone, Copy)]
pub struct ArchHelp {
    /// Guest kind in the summary line, e.g. "an arm64".
    pub guest: &'static str,
    /// Description of `--kernel PATH`.
    pub kernel: &'static str,
    /// Description of `--initrd PATH`.
    pub initrd: &'static str,
    /// Description of `--debug-uart` (continuation lines indented by 25
    /// spaces).
    pub debug_uart: &'static str,
}

/// What the common code hands to [`ArchMachine::build`]: the VM with its RAM
/// mapped, the virtio transports already on the MMIO bus, and the buses
/// for the architecture's own devices.
pub struct BuildCtx<'a> {
    pub cfg: &'a Config,
    /// Final kernel command line (already length-checked against
    /// [`ArchMachine::CMDLINE_MAX`]).
    pub cmdline: &'a str,
    pub vm: &'a Arc<dyn Vm>,
    /// `vm.arch_info()` (x86_64: nothing in it).
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub info: &'a ArchVmInfo,
    /// All guest RAM, mapped: one [`GuestMemory`] with one region per
    /// [`ArchMachine::ram_regions`] entry (x86_64: below and above the PCI
    /// hole). The virtio devices DMA through it too.
    pub ram: &'a Arc<GuestMemory>,
    /// The populated virtio slots, in slot order (console, disks, net), as
    /// returned by [`ArchMachine::virtio_slot`]; for the firmware tables.
    pub virtio: &'a [VirtioSlot],
    /// For architecture devices (debug UART, ...); holds the virtio
    /// transports already. (x86_64 has no MMIO devices of its own.)
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub mmio: &'a mut MmioBus,
    /// For x86 port-I/O devices; empty.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub pio: &'a mut PortIoBus,
    /// For devices that end the machine (ACPI sleep/reset registers, i8042
    /// reset): `control.request_exit(Exit::PowerOff | Exit::Reset)`.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub control: &'a Arc<Control>,
}

/// Result of [`ArchMachine::build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchSetup {
    /// Entry state of vCPU 0, applied with `Vcpu::set_boot_state` on its
    /// thread after `Vm::finalize`. Secondary vCPUs are started by the guest
    /// (PSCI `CPU_ON`, INIT/SIPI) inside the backend.
    pub boot: BootState,
}

/// A guest machine model. The common code calls, in order: [`prepare`]
/// (before the VM exists), [`vm_config`], [`ram_regions`], then
/// [`virtio_slot`] for each virtio device, and finally [`build`].
///
/// [`prepare`]: ArchMachine::prepare
/// [`vm_config`]: ArchMachine::vm_config
/// [`ram_regions`]: ArchMachine::ram_regions
/// [`virtio_slot`]: ArchMachine::virtio_slot
/// [`build`]: ArchMachine::build
pub trait ArchMachine: Sized {
    /// Most vCPUs (`--cpus` accepts `1..=MAX_CPUS`).
    const MAX_CPUS: usize;
    /// Longest kernel command line accepted, including the terminating NUL
    /// (Linux's COMMAND_LINE_SIZE).
    const CMDLINE_MAX: usize;
    /// Number of virtio-mmio slots (more devices are refused).
    const VIRTIO_SLOTS: usize;
    const HELP: ArchHelp;

    /// Check everything that depends on user input and can fail, before the
    /// VM exists: open and parse the kernel, open and size the initrd
    /// (`crate::bootfile::Initrd`), validate the RAM size and place the boot
    /// images. Errors are user-facing messages.
    fn prepare(cfg: &Config) -> Result<Self, String>;

    /// The VM to create (`cfg.cpus`, aarch64 GIC placement).
    fn vm_config(&self, cfg: &Config) -> VmConfig;

    /// Guest RAM regions: ascending, page-aligned, with a hole between any
    /// two (what `GuestMemory::with_regions` accepts).
    fn ram_regions(&self, cfg: &Config) -> Vec<RamRegion>;

    /// Placement of virtio slot `n < VIRTIO_SLOTS`; an error if the VM
    /// cannot raise its interrupt (e.g. outside the GIC's SPI range).
    fn virtio_slot(&self, info: &ArchVmInfo, n: usize) -> Result<VirtioSlot, String>;

    /// Load the boot images into RAM, add the architecture's devices to the
    /// buses, write the firmware tables, and return the boot vCPU's state.
    fn build(self, ctx: BuildCtx<'_>) -> Result<ArchSetup, String>;
}
