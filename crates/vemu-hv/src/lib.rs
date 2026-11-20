//! Hypervisor abstraction for vemu: VMs, vCPUs and in-kernel interrupt
//! controllers, for aarch64 and x86_64 guests on the same-arch host.
//!
//! The VMM programs against the arch-neutral [`Vm`] and [`Vcpu`] traits;
//! [`create_vm`] picks the host backend: Hypervisor.framework on
//! macOS/aarch64 (`src/hvf/`), KVM on Linux (`src/kvm/`). The per-arch guest
//! types ([`Reg`], [`BootState`], [`ArchVmInfo`], and on aarch64 the GIC
//! types) live in [`aarch64`] and [`x86_64`] and are re-exported here for
//! the host architecture. See docs/kvm-design.md for the design.
//!
//! What a backend handles by itself, so the VMM only sees device work
//! ([`VcpuExit`]):
//!
//! - idling (WFI/WFE, HLT), timers and IPIs through the in-kernel interrupt
//!   controller (see `docs/research/hvf.md` for HVF),
//! - aarch64: PSCI (CPU_ON/OFF, AFFINITY_INFO, ...; SYSTEM_OFF/RESET surface
//!   as [`VcpuExit::SystemEvent`]), benign system-register traps (OS lock,
//!   debug comms channel, ...) emulated as RAZ/WI and logged once when
//!   unknown, and SMC (answered NOT_SUPPORTED),
//! - instruction decoding for MMIO (the access is reported decoded; the PC is
//!   advanced by the backend).

use std::fmt;
use std::io;
use std::sync::Arc;

pub mod aarch64;
pub mod x86_64;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod hvf;

#[cfg(target_os = "linux")]
mod kvm;

/// The KVM backend's pure parts (ABI definitions, exit decoding) are
/// unit-tested on every host, not only on Linux.
#[cfg(all(test, not(target_os = "linux")))]
#[allow(dead_code)]
mod kvm {
    pub(crate) mod abi;
    pub(crate) mod exit;
    /// `kvm/aarch64.rs`'s pure part (arm64 UAPI, register ids, vGIC
    /// geometry, IPA choice).
    mod aarch64 {
        pub(crate) mod abi;
    }
}

#[cfg(target_arch = "aarch64")]
pub use aarch64::{ArchVmInfo, BootState, GicInfo, GicRequest, GicVersion, Reg};
#[cfg(target_arch = "x86_64")]
pub use x86_64::{ArchVmInfo, BootState, Reg};

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("vemu-hv supports aarch64 and x86_64 hosts only");

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error from a hypervisor operation: the operation that failed plus either
/// the backend's return code, a description, or the guest state of an exit
/// the backend could not handle.
#[derive(Debug, Clone)]
pub struct Error {
    op: &'static str,
    kind: ErrorKind,
}

/// What went wrong, see [`Error::kind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// The backend API returned this code (e.g. an `hv_return_t`, an errno).
    Backend(i32),
    /// Invalid argument or state, detected by this crate.
    Invalid(String),
    /// The guest did something the backend cannot handle or forward
    /// (undecodable MMIO, instruction fetch outside RAM, unknown exception).
    Guest(GuestFault),
}

/// Guest state captured for an exit that `run()` could not handle
/// (aarch64 terms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestFault {
    /// Short description, e.g. "data abort without instruction syndrome".
    pub what: &'static str,
    /// Exception syndrome (ESR_EL2) of the exit.
    pub esr: u64,
    /// Faulting guest virtual address (FAR).
    pub far: u64,
    /// Faulting guest-physical address, when the exit provides one.
    pub ipa: u64,
    /// Guest PC of the faulting instruction.
    pub pc: u64,
}

// Constructors are used by the backends, not all of which exist on every
// host.
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
impl Error {
    pub(crate) fn backend(op: &'static str, code: i32) -> Error {
        Error {
            op,
            kind: ErrorKind::Backend(code),
        }
    }

    /// An [`ErrorKind::Invalid`] error of operation `op`. Public so that
    /// code outside the backends (wrappers, test doubles of [`Vm`] and
    /// [`Vcpu`]) can report errors in the same type.
    pub fn invalid(op: &'static str, msg: impl Into<String>) -> Error {
        Error {
            op,
            kind: ErrorKind::Invalid(msg.into()),
        }
    }

    pub(crate) fn guest(op: &'static str, fault: GuestFault) -> Error {
        Error {
            op,
            kind: ErrorKind::Guest(fault),
        }
    }

    /// Name of the operation that failed (e.g. `"hv_vcpu_run"`, `"run"`).
    pub fn op(&self) -> &'static str {
        self.op
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The backend return code, if this error came from the backend API.
    pub fn code(&self) -> Option<i32> {
        match self.kind {
            ErrorKind::Backend(code) => Some(code),
            _ => None,
        }
    }

    /// The captured guest state, if this error is an unhandled guest exit.
    pub fn guest_fault(&self) -> Option<&GuestFault> {
        match &self.kind {
            ErrorKind::Guest(f) => Some(f),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Backend(code) => {
                write!(f, "{}: ", self.op)?;
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                if let Some(name) = hvf::return_name(*code) {
                    return write!(f, "{name} ({:#x})", *code as u32);
                }
                // KVM backend codes are errno values.
                #[cfg(target_os = "linux")]
                return write!(f, "{}", io::Error::from_raw_os_error(*code));
                #[cfg(not(target_os = "linux"))]
                write!(f, "backend error {:#x}", *code as u32)
            }
            ErrorKind::Invalid(msg) => write!(f, "{}: {msg}", self.op),
            ErrorKind::Guest(g) => write!(
                f,
                "{}: {} (ESR={:#x} EC={:#x} FAR={:#x} IPA={:#x} PC={:#x})",
                self.op,
                g.what,
                g.esr,
                aarch64::esr::ec(g.esr),
                g.far,
                g.ipa,
                g.pc
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = match e.kind {
            ErrorKind::Invalid(_) => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// Parameters of a new VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmConfig {
    /// Number of vCPUs the VM will have (indices `0..cpus`).
    pub cpus: usize,
    /// Where the VMM wants the GIC (the backend reports what it created in
    /// [`Vm::arch_info`]).
    #[cfg(target_arch = "aarch64")]
    pub gic: GicRequest,
}

impl Default for VmConfig {
    /// One vCPU; on aarch64 the GIC at the QEMU `virt` addresses
    /// ([`GicRequest::default`]).
    fn default() -> VmConfig {
        VmConfig {
            cpus: 1,
            #[cfg(target_arch = "aarch64")]
            gic: GicRequest::default(),
        }
    }
}

/// Create a VM with the host's backend and its in-kernel interrupt
/// controller: HVF + GICv3 on macOS/aarch64, KVM on Linux; an error
/// elsewhere.
///
/// HVF allows only one VM per process at a time; creating a second one while
/// the first is alive fails. A VM is destroyed when the last reference to it
/// (the `Arc` and every [`Vcpu`]) is dropped.
pub fn create_vm(cfg: &VmConfig) -> Result<Arc<dyn Vm>> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        hvf::create_vm(cfg)
    }
    #[cfg(target_os = "linux")]
    {
        kvm::create_vm(cfg)
    }
    #[cfg(not(any(all(target_os = "macos", target_arch = "aarch64"), target_os = "linux")))]
    {
        let _ = cfg;
        Err(Error::invalid(
            "create_vm",
            "no hypervisor backend for this host (vemu supports macOS/aarch64 and Linux/KVM)",
        ))
    }
}

/// A virtual machine: guest-physical address space, interrupt controller and
/// vCPU factory. Shared between threads.
///
/// Lifecycle: [`create_vm`] → [`Vm::map_memory`] (each RAM region) →
/// [`Vm::create_vcpu`] for every index in order (0, 1, ...), each on its own
/// thread → [`Vm::finalize`] → [`Vcpu::set_boot_state`] on the boot vCPU →
/// every vCPU thread calls [`Vcpu::run`] in a loop.
pub trait Vm: Send + Sync {
    /// aarch64: the GIC the backend actually created (version, bases, sizes,
    /// SPI range). x86_64: nothing yet.
    fn arch_info(&self) -> ArchVmInfo;

    /// Map guest RAM read/write/exec: every region of `mem.regions()` at its
    /// guest-physical address (HVF: one mapping each; KVM: one memory slot
    /// each). The vemu binary passes one `GuestMemory` holding all of RAM
    /// (x86_64: below and above the MMIO hole); calling it again for other,
    /// non-overlapping memory is allowed too.
    ///
    /// The mapping refers to `mem`'s host pages, so the VM keeps a reference
    /// to `mem` until it is destroyed (the last reference to the VM and every
    /// [`Vcpu`] dropped): dropping the caller's `Arc` early is safe.
    fn map_memory(&self, mem: &Arc<vemu_core::GuestMemory>) -> Result<()>;

    /// Set the level of a level-triggered interrupt line. aarch64: `irq` is
    /// the absolute GIC INTID of an SPI (>= 32, e.g. 48). x86_64: an IOAPIC
    /// GSI. Callable from any thread; an idle target vCPU notices the
    /// interrupt promptly.
    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()>;

    /// Create vCPU `index` bound to the *calling thread*, which then owns it
    /// (HVF requirement; KVM: the thread that runs it). Each index once, in
    /// index order: call it for `index` only after it returned for `index -
    /// 1`. KVM refuses another order (it numbers vCPUs in creation order, and
    /// the arm64 vGICv2 routes interrupts by that number, so it must equal
    /// the index); it never waits for another thread's creation. A failed
    /// creation can be retried.
    ///
    /// aarch64: MPIDR_EL1 affinity = `arch_info().mpidr(index)` (HVF: Aff0
    /// = index; KVM: 16 vCPUs per Aff1); the vCPU starts at EL1h with
    /// interrupts masked (CPSR 0x3c5), MMU and caches off, PC 0. vCPU 0 is
    /// powered on; the others start powered off (see [`Vcpu::run`]). KVM
    /// initialises aarch64 vCPUs (`KVM_ARM_VCPU_INIT`) in [`Vm::finalize`],
    /// once they all exist (api.rst), so their registers are only
    /// accessible after it.
    ///
    /// Create every vCPU before running any of them: the GIC assigns
    /// redistributor frames in creation order and Linux discovers its
    /// topology once at boot.
    ///
    /// The calling thread is meant to be dedicated to the vCPU: the HVF
    /// backend raises its QoS class (USER_INTERACTIVE) so that guest timers
    /// wake an idle vCPU close to on time. It never uses a real-time policy,
    /// which would let a CPU-bound guest starve the host.
    fn create_vcpu(&self, index: usize) -> Result<Box<dyn Vcpu>>;

    /// Complete VM setup after every vCPU exists and before the first
    /// [`Vcpu::run`] (KVM: per-vCPU setup that needs every vCPU to exist,
    /// i.e. aarch64 `KVM_ARM_VCPU_INIT`, then the vGIC `CTRL_INIT`; HVF:
    /// nothing). Call once, from any thread, while no vCPU is running.
    fn finalize(&self) -> Result<()>;

    /// Force vCPU `index` out of `run()` (returns [`VcpuExit::Kicked`]) as soon
    /// as possible, including from WFI/HLT and from a powered-off wait.
    /// Sticky if the vCPU is not currently in `run()`: the next `run()`
    /// returns `Kicked` immediately. Several kicks before the vCPU notices
    /// collapse into one `Kicked`. No-op for vCPUs not (or no longer)
    /// created.
    fn kick(&self, index: usize);
}

/// A virtual CPU. Not `Send`: it stays on the thread that created it.
pub trait Vcpu {
    fn index(&self) -> usize;

    /// Put the vCPU in its boot state and power it on.
    ///
    /// aarch64 ([`aarch64::BootState`]): as from reset (EL1h, D/A/I/F masked,
    /// MMU and caches off), PC = `pc`, X0 = `x0` (the DTB), X1..X3 = 0, no
    /// MMIO read pending; MPIDR_EL1 and the virtual counter are unchanged.
    /// Meant for the boot vCPU; on a secondary it powers the vCPU on without
    /// PSCI `CPU_ON` (tests use that).
    ///
    /// x86_64 ([`x86_64::BootState`]): long mode per the Linux 64-bit boot
    /// protocol; boot vCPU only (the others wait for INIT/SIPI).
    fn set_boot_state(&mut self, s: &BootState) -> Result<()>;

    /// Run until an exit the VMM must handle.
    ///
    /// The backend handles internally: WFI/WFE and HLT (sleeping until an
    /// interrupt, a timer deadline, or a kick), timer exits, canceled runs;
    /// aarch64: unknown/benign sysreg traps (RAZ/WI, logged once), SMC
    /// (X0 = NOT_SUPPORTED), PSCI over `HVC #0`.
    ///
    /// Secondary vCPUs need no help from the VMM to start: aarch64
    /// secondaries are powered off until the guest's PSCI `CPU_ON` (HVF
    /// emulates PSCI in this crate, KVM in the kernel), and `run()` of a
    /// powered-off vCPU blocks until `CPU_ON` (which resets it to the entry
    /// state) or a kick; `CPU_OFF` makes it block again. x86_64 secondaries
    /// wait in the kernel for INIT/SIPI. So the VMM starts every vCPU thread
    /// and just calls `run()` in a loop.
    fn run(&mut self) -> Result<VcpuExit>;

    /// Complete the preceding [`VcpuExit::MmioRead`]: write `value`
    /// (zero-extended to the access size, sign-extended if the instruction
    /// asked) to the target register. Must be called before the next `run()`.
    fn complete_mmio_read(&mut self, value: u64) -> Result<()>;

    /// Complete the preceding [`VcpuExit::IoIn`] with the low `len` bytes of
    /// `value` (x86_64; an error on aarch64). Must be called before the next
    /// `run()`.
    fn complete_io_in(&mut self, value: u32) -> Result<()>;

    /// Read a guest register (debugging and tests).
    fn get_reg(&self, reg: Reg) -> Result<u64>;

    /// Write a guest register (debugging and tests).
    fn set_reg(&mut self, reg: Reg, val: u64) -> Result<()>;
}

/// Why [`Vcpu::run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuExit {
    /// The guest loads `len` bytes (1, 2, 4 or 8) from MMIO address `addr`.
    /// Answer with [`Vcpu::complete_mmio_read`].
    MmioRead { addr: u64, len: usize },
    /// The guest stores the low `len` bytes of `data` to MMIO address `addr`.
    MmioWrite { addr: u64, len: usize, data: u64 },
    /// x86_64 only: `IN` of `len` bytes (1, 2 or 4) from `port`. Answer with
    /// [`Vcpu::complete_io_in`].
    IoIn { port: u16, len: usize },
    /// x86_64 only: `OUT` of the low `len` bytes of `data` to `port`.
    IoOut { port: u16, len: usize, data: u32 },
    /// The guest asked to power off or reset the machine (aarch64: PSCI
    /// SYSTEM_OFF / SYSTEM_RESET; x86_64: triple fault = `Reset`). The vCPU
    /// should not be run again. (x86 ACPI poweroff arrives as an
    /// `IoOut`/`MmioWrite` to the VMM's ACPI sleep register instead.)
    SystemEvent(SystemEvent),
    /// aarch64, HVF only: an `HVC` with a non-zero immediate, which is not an
    /// SMCCC call. It is complete when `run()` returns: the PC is past the
    /// HVC and X0 = -1 (NOT_SUPPORTED), so a VMM can ignore this exit. Tests
    /// use it as a guest-to-host signal. KVM never reports it.
    Hvc { imm: u16 },
    /// [`Vm::kick`] was called.
    Kicked,
}

/// See [`VcpuExit::SystemEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    Shutdown,
    Reset,
}
