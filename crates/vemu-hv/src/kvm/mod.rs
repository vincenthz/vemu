//! Linux KVM backend: the arch-independent layer (see docs/kvm-design.md).
//!
//! This file owns everything that is the same on aarch64 and x86_64:
//! `/dev/kvm` (API version 12, capability checks), the VM fd, memory slots,
//! vCPU fds and their `kvm_run` mapping, `KVM_RUN` with exit decoding and
//! the MMIO / port-I/O completion protocol (`exit.rs`), `KVM_IRQ_LINE`, and
//! kicking vCPUs. The arch modules (`aarch64.rs`, `x86_64.rs`) plug in
//! through [`ArchVm`] / [`ArchVcpu`]: VM type, in-kernel interrupt
//! controller, vCPU init, registers, boot state, and exits this layer does
//! not know. `abi.rs` holds the `linux/kvm.h` mirrors, checked against the
//! real headers by `scripts/kvm-abi/check.sh`.
//!
//! # Threads
//!
//! A vCPU belongs to the thread that called [`Vm::create_vcpu`]: the
//! returned `Box<dyn Vcpu>` is `!Send`, every vCPU ioctl (including the arch
//! hooks) runs on that thread, and the kick signal is aimed at it. The one
//! exception is [`ArchVm::init_vcpu`], which [`Vm::finalize`] calls for every
//! vCPU from the finalizing thread before any vCPU runs (KVM only requires
//! vCPU ioctls to come from the VM's process).
//!
//! # vCPU creation order
//!
//! KVM numbers vCPUs in creation order (`vcpu_idx`), apart from the id
//! userspace passes to `KVM_CREATE_VCPU` (`vcpu_id`, here the index), and
//! some code uses one where it means the other: the arm64 vGICv2 targets
//! private interrupts by `vcpu_id` but delivers SGIs and SPIs by `vcpu_idx`
//! (vgic-init.c, vgic-mmio-v2.c). So vCPUs must be created in index order:
//! [`Vm::create_vcpu`] refuses index `i` until vCPUs `0..i` exist (it never
//! waits, so a failed or missing creation cannot hang another thread).
//! api.rst (`KVM_ARM_VCPU_INIT`) also asks for every vCPU to exist before
//! the first `KVM_ARM_VCPU_INIT`, which is why that happens in
//! [`Vm::finalize`] ([`ArchVm::init_vcpu`]) rather than at creation.
//!
//! # Guest memory
//!
//! [`Vm::map_memory`] keeps a reference to every `GuestMemory` it mapped in
//! the VM (`Inner`), which every vCPU keeps alive: KVM resolves a memory
//! slot's host address lazily, so the mapping must outlive every slot and
//! every `KVM_RUN`.
//!
//! # Kicks
//!
//! [`Vm::kick`] sets the vCPU's sticky flag, stores 1 to
//! `kvm_run.immediate_exit`, and, if the vCPU is inside (or about to enter)
//! `KVM_RUN`, sends its thread the kick signal (`SIGRTMIN`, a no-op handler
//! installed once per process *without* `SA_RESTART`, unblocked on vCPU
//! threads). `run()` clears `immediate_exit`, *then* tests the flag, *then*
//! enters `KVM_RUN` (all `SeqCst`):
//!
//! - flag seen: return `Kicked` without entering the guest;
//! - flag not seen: the kicker set it later, so its `immediate_exit = 1`
//!   comes after our clear: either `KVM_RUN` reads 1 and returns `EINTR`
//!   at once, or it already read 0 and is running, in which case the kicker
//!   sees `in_run` and its signal forces `KVM_RUN` out with `EINTR` (from
//!   the guest or from the in-kernel HLT/WFI wait). `EINTR` loops back to
//!   the flag test, which then reports `Kicked`.
//!
//! So a kick is never lost, and several kicks before the vCPU notices
//! collapse into one `Kicked` (one flag). A leftover `immediate_exit` or
//! signal only costs one extra `EINTR` round trip. The signal is only sent
//! while `in_run` is set, so a vCPU thread busy in the VMM (device
//! emulation) is normally not interrupted; a kick racing with the end of
//! `KVM_RUN` can still interrupt a blocking system call there with `EINTR`
//! (std's `write_all`, `Mutex`, ... retry; device code must too).
//!
//! # Completion and register access
//!
//! KVM finishes an MMIO / I/O instruction at the next `KVM_RUN`. So that
//! `get_reg`/`set_reg`/`set_boot_state` see a consistent vCPU (as on HVF,
//! where the backend completes the instruction itself), they first *flush*:
//! `KVM_RUN` with `immediate_exit = 1`, which completes the pending
//! operation without running guest code (api.rst, "kvm_run"). Normal
//! `run()` loops never need that extra call.

pub(crate) mod abi;
pub(crate) mod exit;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::cell::Cell;
use std::fs::OpenOptions;
use std::io;
use std::mem::{self, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::ptr::{self, NonNull};
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use crate::{ArchVmInfo, BootState, Error, Reg, Result, Vcpu, VcpuExit, Vm, VmConfig};
use abi::*;
use exit::{Before, Decoded, Pending, RunPtr};

/// The host arch's hooks: each arch file defines `pub(super) struct Arch`
/// implementing [`ArchVm`].
#[cfg(target_arch = "aarch64")]
type HostArch = aarch64::Arch;
#[cfg(target_arch = "x86_64")]
type HostArch = x86_64::Arch;

/// [`crate::create_vm`] on Linux.
pub(crate) fn create_vm(cfg: &VmConfig) -> Result<Arc<dyn Vm>> {
    create_vm_with::<HostArch>(cfg)
}

// --- arch hooks ------------------------------------------------------------

/// VM-level hooks of an arch (`kvm/aarch64.rs`, `kvm/x86_64.rs`). The
/// common layer calls them in this order:
///
/// 1. [`ArchVm::vm_type`] (no VM yet), `KVM_CREATE_VM(type)`,
/// 2. [`ArchVm::new`] right after `KVM_CREATE_VM`: before any memory slot
///    or vCPU (x86: `KVM_SET_TSS_ADDR`, `KVM_SET_IDENTITY_MAP_ADDR`,
///    `KVM_CREATE_IRQCHIP`, `KVM_CREATE_PIT2`; aarch64: create the vGIC
///    device and set its addresses),
/// 3. `map_memory` (any number of times), then for each vCPU in index
///    order, on its own thread: `KVM_CREATE_VCPU(index)`, mmap of
///    `kvm_run`, then [`ArchVm::create_vcpu`] (aarch64: nothing in the
///    kernel yet; x86: CPUID, MSRs, FPU, LAPIC LINT0/1),
/// 4. once all vCPUs exist, from the thread calling [`Vm::finalize`]:
///    [`ArchVm::init_vcpu`] for every vCPU in index order (aarch64:
///    `KVM_ARM_VCPU_INIT` with PSCI 0.2, POWER_OFF unless index 0), then
///    [`ArchVm::finalize`] (aarch64: vGIC `CTRL_INIT`), before the first
///    run,
/// 5. [`ArchVm::irq_line`] / [`ArchVm::arch_info`] at any time, from any
///    thread.
///
/// Errors are [`Error`]s (`Error::invalid` for messages, `Error::backend`
/// with an errno for failed ioctls: the `Fd`/`VmFd`/`VcpuFd` helpers
/// already return those).
pub(crate) trait ArchVm: Send + Sync + Sized + 'static {
    type Vcpu: ArchVcpu;

    /// Machine type for `KVM_CREATE_VM` (aarch64: IPA size bits from
    /// `KVM_CAP_ARM_VM_IPA_SIZE`; x86: 0). `cfg.cpus` is already checked
    /// against `KVM_CAP_MAX_VCPUS` / `KVM_CAP_MAX_VCPU_ID` (>= 1).
    fn vm_type(kvm: &Kvm, cfg: &VmConfig) -> Result<u64>;

    /// Arch VM setup right after `KVM_CREATE_VM` (see the trait docs).
    fn new(kvm: &Kvm, vm: &VmFd, cfg: &VmConfig) -> Result<Self>;

    /// [`Vm::arch_info`].
    fn arch_info(&self) -> ArchVmInfo;

    /// Validate a [`Vm::set_irq_line`] number and return the
    /// `kvm_irq_level.irq` value to pass to `KVM_IRQ_LINE` (x86: the GSI;
    /// aarch64: `KVM_ARM_IRQ_TYPE_SPI << 24 | intid`).
    fn irq_line(&self, irq: u32) -> Result<u32>;

    /// Arch vCPU setup after `KVM_CREATE_VCPU(index)` (vCPU id = index) and
    /// the `kvm_run` mmap, on the vCPU's thread. Other vCPUs may not exist
    /// yet: setup that depends on the topology belongs in
    /// [`ArchVm::init_vcpu`].
    fn create_vcpu(&self, kvm: &Kvm, vm: &VmFd, vcpu: &VcpuFd, index: usize) -> Result<Self::Vcpu>;

    /// Setup of vCPU `index` that needs every vCPU to exist (aarch64:
    /// `KVM_ARM_VCPU_INIT`, see api.rst). Called by [`Vm::finalize`] on the
    /// finalizing thread, for each vCPU in index order, before
    /// [`ArchVm::finalize`]; the vCPU's own thread is not running it then.
    fn init_vcpu(&self, vcpu: &VcpuFd, index: usize) -> Result<()> {
        let _ = (vcpu, index);
        Ok(())
    }

    /// [`Vm::finalize`]: after every vCPU exists and was initialised by
    /// [`ArchVm::init_vcpu`], before the first run.
    fn finalize(&self, vm: &VmFd) -> Result<()>;
}

/// vCPU-level hooks of an arch. Called on the vCPU's thread only, and
/// never while a completion is half done: the common layer has flushed
/// pending MMIO / I/O first (see the module docs), so registers are
/// consistent.
pub(crate) trait ArchVcpu: 'static {
    /// [`Vcpu::set_boot_state`]: entry state and power on (aarch64:
    /// core regs via `KVM_SET_ONE_REG`, `KVM_SET_MP_STATE` RUNNABLE for a
    /// secondary; x86: long-mode `KVM_SET_SREGS`/`KVM_SET_REGS`). Any MMIO /
    /// I/O the vCPU was in has been abandoned (reads complete as 0) and
    /// flushed before this is called.
    fn set_boot_state(&mut self, vcpu: &VcpuFd, s: &BootState) -> Result<()>;

    /// [`Vcpu::get_reg`].
    fn get_reg(&self, vcpu: &VcpuFd, reg: Reg) -> Result<u64>;

    /// [`Vcpu::set_reg`].
    fn set_reg(&mut self, vcpu: &VcpuFd, reg: Reg, val: u64) -> Result<()>;

    /// An exit the common layer does not decode (anything but MMIO, IO,
    /// SYSTEM_EVENT, SHUTDOWN, INTR, INTERNAL_ERROR, FAIL_ENTRY, UNKNOWN,
    /// EXCEPTION), e.g. `KVM_EXIT_DEBUG`, `KVM_EXIT_HLT` (only without an
    /// in-kernel irqchip), `KVM_EXIT_ARM_NISV`. `data` is a copy of the
    /// `kvm_run` exit union. `Ok(None)` re-enters the guest.
    fn handle_exit(
        &mut self,
        vcpu: &VcpuFd,
        reason: u32,
        data: &KvmRunUnion,
    ) -> Result<Option<VcpuExit>> {
        let _ = (vcpu, data);
        Err(Error::invalid(
            "run",
            format!("unhandled KVM exit {} ({reason})", exit_reason_name(reason)),
        ))
    }

    /// Guest state appended to fatal-exit errors (e.g. `" (RIP=... CR0=...)"`);
    /// must not fail.
    fn fault_context(&self, vcpu: &VcpuFd) -> String {
        let _ = vcpu;
        String::new()
    }
}

// --- fds and ioctls ----------------------------------------------------------

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// A KVM file descriptor (system, VM, vCPU or device) with ioctl helpers.
/// Errors are `Error::backend(op, errno)`.
#[derive(Debug)]
pub(crate) struct Fd(OwnedFd);

impl Fd {
    /// Take ownership of the fd an ioctl returned (`ret >= 0`).
    fn from_ret(op: &'static str, ret: i32) -> Result<Fd> {
        if ret < 0 {
            return Err(Error::invalid(op, "ioctl returned an invalid fd"));
        }
        // SAFETY: `ret` is a new descriptor that nothing else owns (the
        // ioctl just created it).
        Ok(Fd(unsafe { OwnedFd::from_raw_fd(ret) }))
    }

    pub(crate) fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// An `_IO` ioctl whose argument is a value (or unused: pass 0; musl's
    /// variadic `ioctl` always gets an explicit third argument). Returns the
    /// non-negative result.
    pub(crate) fn ioctl_val(&self, op: &'static str, req: u32, arg: u64) -> Result<i32> {
        if ioc_dir(req) != IOC_NONE {
            return Err(Error::invalid(
                op,
                format!("ioctl {req:#x} takes a pointer, not a value"),
            ));
        }
        // SAFETY: an _IO request: the kernel treats `arg` as a number, so
        // no memory of this process is accessed.
        let ret = unsafe { libc::ioctl(self.raw(), req as libc::Ioctl, arg as libc::c_ulong) };
        if ret < 0 {
            Err(Error::backend(op, last_errno()))
        } else {
            Ok(ret)
        }
    }

    /// An ioctl whose argument points at `*arg`.
    ///
    /// # Safety
    ///
    /// The kernel must not access more than `size_of::<T>()` bytes at `arg`
    /// (true for fixed-size structs whose size is the one encoded in `req`;
    /// NOT for flexible-array requests like `KVM_GET_SUPPORTED_CPUID`, whose
    /// `T` must then be a buffer big enough for the count it declares), and
    /// must only write bit patterns valid for `T`. Any pointers inside `*arg`
    /// (e.g. `kvm_one_reg.addr`) must be valid for what the kernel does
    /// with them.
    pub(crate) unsafe fn ioctl_ptr<T>(
        &self,
        op: &'static str,
        req: u32,
        arg: *mut T,
    ) -> Result<i32> {
        if ioc_dir(req) == IOC_NONE || ioc_size(req) > size_of::<T>() {
            return Err(Error::invalid(
                op,
                format!(
                    "ioctl {req:#x} argument size {} does not match {} bytes",
                    ioc_size(req),
                    size_of::<T>()
                ),
            ));
        }
        // SAFETY: the caller guarantees the kernel's accesses stay within
        // `*arg`.
        let ret = unsafe { libc::ioctl(self.raw(), req as libc::Ioctl, arg) };
        if ret < 0 {
            Err(Error::backend(op, last_errno()))
        } else {
            Ok(ret)
        }
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_SET_DEVICE_ATTR` on a device or vCPU fd; `value` (if any) is
    /// what `kvm_device_attr.addr` points at (the kernel only reads it).
    pub(crate) fn set_device_attr(
        &self,
        op: &'static str,
        group: u32,
        attr: u64,
        value: Option<&u64>,
    ) -> Result<()> {
        let mut a = KvmDeviceAttr {
            flags: 0,
            group,
            attr,
            addr: value.map_or(0, |v| v as *const u64 as u64),
        };
        // SAFETY: fixed-size kvm_device_attr; for SET the kernel only reads
        // through `addr` (at most the 8 bytes of `*value` for the attributes
        // vemu uses: addresses and counts).
        unsafe { self.ioctl_ptr(op, KVM_SET_DEVICE_ATTR, &mut a) }.map(drop)
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_HAS_DEVICE_ATTR`: whether the device supports the attribute.
    pub(crate) fn has_device_attr(&self, group: u32, attr: u64) -> bool {
        let mut a = KvmDeviceAttr {
            flags: 0,
            group,
            attr,
            addr: 0,
        };
        // SAFETY: fixed-size kvm_device_attr; HAS does not dereference addr.
        unsafe { self.ioctl_ptr("KVM_HAS_DEVICE_ATTR", KVM_HAS_DEVICE_ATTR, &mut a) }.is_ok()
    }
}

/// `/dev/kvm`.
#[derive(Debug)]
pub(crate) struct Kvm {
    fd: Fd,
}

impl Kvm {
    /// Open `/dev/kvm` (close-on-exec) and check `KVM_GET_API_VERSION`.
    pub(crate) fn open() -> Result<Kvm> {
        const OP: &str = "open /dev/kvm";
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/kvm")
            .map_err(|e| {
                let hint = match e.raw_os_error() {
                    Some(libc::ENOENT) => {
                        " (KVM is not available: no kvm module, or no virtualization support)"
                    }
                    Some(libc::EACCES | libc::EPERM) => {
                        " (this user may not use KVM: usually it must be in the kvm group)"
                    }
                    // The node exists but no driver serves it (seen in a
                    // container or a guest with a copied /dev).
                    Some(libc::ENODEV | libc::ENXIO) if cfg!(target_arch = "x86_64") => {
                        " (the kvm driver is not loaded: modprobe kvm_intel or kvm_amd; or \
                         virtualization is off in the firmware)"
                    }
                    Some(libc::ENODEV | libc::ENXIO) => {
                        " (no kvm driver behind /dev/kvm: the kernel lacks KVM, or was not \
                         booted at EL2)"
                    }
                    _ => "",
                };
                Error::invalid(OP, format!("{e}{hint}"))
            })?;
        let kvm = Kvm {
            fd: Fd(OwnedFd::from(file)),
        };
        let version = kvm
            .fd
            .ioctl_val("KVM_GET_API_VERSION", KVM_GET_API_VERSION, 0)?;
        if version != KVM_API_VERSION {
            return Err(Error::invalid(
                "KVM_GET_API_VERSION",
                format!("KVM API version {version}, vemu needs {KVM_API_VERSION}"),
            ));
        }
        Ok(kvm)
    }

    #[allow(dead_code)] // arch helper
    pub(crate) fn fd(&self) -> &Fd {
        &self.fd
    }

    /// `KVM_CHECK_EXTENSION` on `/dev/kvm`: 0 if unsupported (or on error),
    /// else the capability's value (often 1).
    pub(crate) fn check_extension(&self, cap: u32) -> i32 {
        self.fd
            .ioctl_val("KVM_CHECK_EXTENSION", KVM_CHECK_EXTENSION, u64::from(cap))
            .unwrap_or(0)
    }

    fn vcpu_mmap_size(&self) -> Result<usize> {
        let n = self
            .fd
            .ioctl_val("KVM_GET_VCPU_MMAP_SIZE", KVM_GET_VCPU_MMAP_SIZE, 0)?;
        Ok(n as usize)
    }

    fn create_vm(&self, machine_type: u64) -> Result<VmFd> {
        const OP: &str = "KVM_CREATE_VM";
        // KVM_CREATE_VM can fail with EINTR (a signal during setup).
        let mut tries = 0;
        loop {
            match self.fd.ioctl_val(OP, KVM_CREATE_VM, machine_type) {
                Ok(fd) => {
                    return Ok(VmFd {
                        fd: Fd::from_ret(OP, fd)?,
                    });
                }
                Err(e) if e.code() == Some(libc::EINTR) && tries < 16 => tries += 1,
                Err(e) => return Err(e),
            }
        }
    }
}

/// A VM fd.
#[derive(Debug)]
pub(crate) struct VmFd {
    fd: Fd,
}

impl VmFd {
    #[allow(dead_code)] // arch helper
    pub(crate) fn fd(&self) -> &Fd {
        &self.fd
    }

    /// `KVM_CHECK_EXTENSION` on the VM (KVM_CAP_CHECK_EXTENSION_VM, Linux
    /// 4.0+): the value for this VM (e.g. its type), or `Err` if the kernel
    /// lacks VM-level checks (use [`Kvm::check_extension`] then).
    pub(crate) fn check_extension(&self, cap: u32) -> Result<i32> {
        self.fd
            .ioctl_val("KVM_CHECK_EXTENSION", KVM_CHECK_EXTENSION, u64::from(cap))
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_ENABLE_CAP` on the VM.
    pub(crate) fn enable_cap(&self, cap: u32, args: [u64; 4]) -> Result<()> {
        let mut c = KvmEnableCap {
            cap,
            args,
            ..KvmEnableCap::default()
        };
        // SAFETY: fixed-size struct, read by the kernel.
        unsafe { self.fd.ioctl_ptr("KVM_ENABLE_CAP", KVM_ENABLE_CAP, &mut c) }.map(drop)
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_CREATE_DEVICE` of `type_` (`enum kvm_device_type`): the device fd.
    pub(crate) fn create_device(&self, type_: u32) -> Result<Fd> {
        const OP: &str = "KVM_CREATE_DEVICE";
        let mut d = KvmCreateDevice {
            type_,
            fd: 0,
            flags: 0,
        };
        // SAFETY: fixed-size struct, read and written by the kernel.
        unsafe { self.fd.ioctl_ptr(OP, KVM_CREATE_DEVICE, &mut d) }?;
        Fd::from_ret(OP, d.fd as i32)
    }

    /// `KVM_IRQ_LINE` with an arch-encoded `irq` ([`ArchVm::irq_line`]).
    pub(crate) fn irq_line(&self, irq: u32, level: bool) -> Result<()> {
        let mut l = KvmIrqLevel {
            irq,
            level: level as u32,
        };
        // SAFETY: fixed-size struct, read by the kernel.
        unsafe { self.fd.ioctl_ptr("KVM_IRQ_LINE", KVM_IRQ_LINE, &mut l) }.map(drop)
    }

    /// # Safety
    ///
    /// `r.userspace_addr .. + r.memory_size` must be a mapping of this
    /// process that stays valid while the slot exists (the VM's life).
    unsafe fn set_user_memory_region(&self, r: &KvmUserspaceMemoryRegion) -> Result<()> {
        let mut r = *r;
        // SAFETY: fixed-size struct, read by the kernel; the memory it
        // describes is the caller's responsibility.
        unsafe {
            self.fd.ioctl_ptr(
                "KVM_SET_USER_MEMORY_REGION",
                KVM_SET_USER_MEMORY_REGION,
                &mut r,
            )
        }
        .map(drop)
    }

    fn create_vcpu(&self, id: u64) -> Result<VcpuFd> {
        const OP: &str = "KVM_CREATE_VCPU";
        let fd = self.fd.ioctl_val(OP, KVM_CREATE_VCPU, id)?;
        Ok(VcpuFd {
            fd: Fd::from_ret(OP, fd)?,
        })
    }
}

/// A vCPU fd (used on the vCPU's thread only, except by
/// [`ArchVm::init_vcpu`]).
#[derive(Debug)]
pub(crate) struct VcpuFd {
    fd: Fd,
}

impl VcpuFd {
    #[allow(dead_code)] // arch helper
    pub(crate) fn fd(&self) -> &Fd {
        &self.fd
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_GET_ONE_REG` of a 64-bit register.
    pub(crate) fn get_one_reg(&self, id: u64) -> Result<u64> {
        const OP: &str = "KVM_GET_ONE_REG";
        if one_reg_size(id) != 8 {
            return Err(Error::invalid(
                OP,
                format!("register {id:#x} is not 64-bit"),
            ));
        }
        let mut val = 0u64;
        let mut r = KvmOneReg {
            id,
            addr: &mut val as *mut u64 as u64,
        };
        // SAFETY: fixed-size struct; the kernel writes the register's 8
        // bytes (size checked above) to `val`.
        unsafe { self.fd.ioctl_ptr(OP, KVM_GET_ONE_REG, &mut r) }?;
        Ok(val)
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_SET_ONE_REG` of a 64-bit register.
    pub(crate) fn set_one_reg(&self, id: u64, val: u64) -> Result<()> {
        const OP: &str = "KVM_SET_ONE_REG";
        if one_reg_size(id) != 8 {
            return Err(Error::invalid(
                OP,
                format!("register {id:#x} is not 64-bit"),
            ));
        }
        let mut r = KvmOneReg {
            id,
            addr: &val as *const u64 as u64,
        };
        // SAFETY: fixed-size struct; the kernel reads 8 bytes from `val`.
        unsafe { self.fd.ioctl_ptr(OP, KVM_SET_ONE_REG, &mut r) }.map(drop)
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_GET_MP_STATE`.
    pub(crate) fn get_mp_state(&self) -> Result<u32> {
        let mut s = KvmMpState::default();
        // SAFETY: fixed-size struct, written by the kernel.
        unsafe {
            self.fd
                .ioctl_ptr("KVM_GET_MP_STATE", KVM_GET_MP_STATE, &mut s)
        }?;
        Ok(s.mp_state)
    }

    #[allow(dead_code)] // arch helper (kvm/aarch64.rs, kvm/x86_64.rs)
    /// `KVM_SET_MP_STATE` (e.g. [`KVM_MP_STATE_RUNNABLE`]).
    pub(crate) fn set_mp_state(&self, mp_state: u32) -> Result<()> {
        let mut s = KvmMpState { mp_state };
        // SAFETY: fixed-size struct, read by the kernel.
        unsafe {
            self.fd
                .ioctl_ptr("KVM_SET_MP_STATE", KVM_SET_MP_STATE, &mut s)
        }
        .map(drop)
    }

    /// `KVM_RUN`, errno kept for the caller to classify.
    fn run(&self) -> io::Result<()> {
        // SAFETY: an _IO request without argument (explicit 0 for musl's
        // variadic ioctl); the kernel only touches the kvm_run mapping.
        let ret = unsafe { libc::ioctl(self.fd.raw(), KVM_RUN as libc::Ioctl, 0 as libc::c_ulong) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// The vCPU's `kvm_run` mapping, unmapped on drop.
struct RunMap {
    run: RunPtr,
}

impl RunMap {
    fn new(vcpu: &VcpuFd, size: usize) -> Result<RunMap> {
        // SAFETY: maps the vCPU fd's shared kvm_run area (offset 0, the size
        // KVM_GET_VCPU_MMAP_SIZE reported); checked for MAP_FAILED.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu.fd.raw(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Error::backend("mmap kvm_run", last_errno()));
        }
        let p = NonNull::new(p.cast::<KvmRun>())
            .ok_or_else(|| Error::invalid("mmap kvm_run", "null mapping"))?;
        // SAFETY: a fresh page-aligned (so 8-aligned) mapping of `size >=
        // size_of::<KvmRun>()` bytes (checked at VM creation), owned by this
        // RunMap until drop; other threads only store immediate_exit
        // atomically (kick).
        Ok(RunMap {
            run: unsafe { RunPtr::new(p, size) },
        })
    }
}

impl Drop for RunMap {
    fn drop(&mut self) {
        // SAFETY: our own mapping; the vCPU was unpublished from kick()
        // before this runs (KvmVcpu::drop), so nothing else references it.
        let ret = unsafe { libc::munmap(self.run.as_ptr().cast(), self.run.size()) };
        debug_assert_eq!(ret, 0, "munmap kvm_run");
    }
}

// --- kick signal -------------------------------------------------------------

/// The signal that kicks a vCPU thread out of `KVM_RUN`.
fn kick_signal() -> libc::c_int {
    libc::SIGRTMIN()
}

extern "C" fn on_kick_signal(_: libc::c_int) {
    // Nothing: the point is to interrupt KVM_RUN (EINTR).
}

/// Install the no-op kick handler, once per process, without SA_RESTART
/// (KVM_RUN returns EINTR either way; other interrupted calls do too).
fn install_kick_handler() -> Result<()> {
    static INSTALLED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    INSTALLED
        .get_or_init(|| {
            let sig = kick_signal();
            // SAFETY: sigaction with a zero-initialised (valid) struct:
            // first only reading the current action, then installing ours
            // with an empty mask and no flags; checked for failure.
            unsafe {
                let mut old: libc::sigaction = mem::zeroed();
                if libc::sigaction(sig, ptr::null(), &mut old) != 0 {
                    return Err(format!("sigaction: {}", io::Error::last_os_error()));
                }
                if old.sa_sigaction != libc::SIG_DFL && old.sa_sigaction != libc::SIG_IGN {
                    return Err(format!(
                        "signal {sig} (SIGRTMIN, used to kick vCPUs) already has a handler"
                    ));
                }
                let mut sa: libc::sigaction = mem::zeroed();
                sa.sa_sigaction =
                    on_kick_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
                libc::sigemptyset(&mut sa.sa_mask);
                sa.sa_flags = 0;
                if libc::sigaction(sig, &sa, ptr::null_mut()) != 0 {
                    return Err(format!("sigaction: {}", io::Error::last_os_error()));
                }
            }
            Ok(())
        })
        .clone()
        .map_err(|m| Error::invalid("create_vm", m))
}

/// Make sure the calling (vCPU) thread can receive the kick signal (it may
/// have inherited a mask that blocks it).
fn unblock_kick_signal() -> Result<()> {
    // SAFETY: sigset operations on a local set; pthread_sigmask only
    // changes this thread's mask.
    let ret = unsafe {
        let mut set: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, kick_signal());
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, ptr::null_mut())
    };
    if ret != 0 {
        return Err(Error::backend("pthread_sigmask", ret));
    }
    Ok(())
}

// --- VM ------------------------------------------------------------------------

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What [`Vm::kick`] and [`Vm::finalize`] need to reach a live vCPU.
struct KickTarget {
    thread: libc::pthread_t,
    run: NonNull<KvmRun>,
    /// The vCPU's fd, for [`ArchVm::init_vcpu`].
    fd: Arc<VcpuFd>,
}

// SAFETY: a KickTarget is only used under its slot's lock, while the vCPU it
// names is alive (it unpublishes itself, under that lock, before its thread
// can exit or its kvm_run is unmapped); it is then used only for an atomic
// store to immediate_exit, pthread_kill, and vCPU ioctls on `fd`.
unsafe impl Send for KickTarget {}

/// Per-vCPU-index state shared between the VM handle and the vCPU.
#[derive(Default)]
struct Slot {
    /// Pending kick, consumed by `run()`.
    kick: AtomicBool,
    /// The vCPU thread is about to enter, or is in, KVM_RUN.
    in_run: AtomicBool,
    /// The live vCPU; `None` before creation and after drop.
    target: Mutex<Option<KickTarget>>,
}

struct MemSlots {
    /// KVM_CAP_NR_MEMSLOTS.
    max: u32,
    /// `[start, end)` of slot `i`.
    used: Vec<(u64, u64)>,
    /// The memory behind the slots: kept alive as long as the VM (and so
    /// every vCPU) is, since KVM reads and writes it through the slots'
    /// host addresses.
    owners: Vec<Arc<vemu_core::GuestMemory>>,
}

struct Inner<A: ArchVm> {
    arch: A,
    vm: VmFd,
    kvm: Kvm,
    /// KVM_GET_VCPU_MMAP_SIZE.
    run_size: usize,
    slots: Box<[Slot]>,
    /// Number of vCPUs KVM has created: they are indices `0..created`
    /// (creation is in index order, see the module docs), and the next one
    /// must be index `created`. Held across `KVM_CREATE_VCPU`.
    created: Mutex<usize>,
    /// Set by a successful [`Vm::finalize`].
    finalized: Mutex<bool>,
    mem: Mutex<MemSlots>,
}

/// [`Vm`] of the KVM backend. vCPUs keep the VM alive (`Arc<Inner>`).
struct KvmVm<A: ArchVm> {
    inner: Arc<Inner<A>>,
}

/// Highest vCPU count / id KVM accepts (api.rst, KVM_CREATE_VCPU).
fn vcpu_limits(kvm: &Kvm) -> (usize, usize) {
    let positive = |n: i32| (n > 0).then_some(n as usize);
    let max = positive(kvm.check_extension(KVM_CAP_MAX_VCPUS))
        .or_else(|| positive(kvm.check_extension(KVM_CAP_NR_VCPUS)))
        .unwrap_or(4);
    let max_id = positive(kvm.check_extension(KVM_CAP_MAX_VCPU_ID)).unwrap_or(max);
    (max, max_id)
}

fn create_vm_with<A: ArchVm>(cfg: &VmConfig) -> Result<Arc<dyn Vm>> {
    Ok(Arc::new(new_vm::<A>(cfg)?))
}

fn new_vm<A: ArchVm>(cfg: &VmConfig) -> Result<KvmVm<A>> {
    const OP: &str = "create_vm";
    if cfg.cpus == 0 {
        return Err(Error::invalid(OP, "a VM needs at least one vCPU"));
    }
    install_kick_handler()?;
    let kvm = Kvm::open()?;
    for (cap, name) in [
        (KVM_CAP_USER_MEMORY, "KVM_CAP_USER_MEMORY"),
        (
            KVM_CAP_IMMEDIATE_EXIT,
            "KVM_CAP_IMMEDIATE_EXIT (Linux 4.11+)",
        ),
    ] {
        if kvm.check_extension(cap) <= 0 {
            return Err(Error::invalid(OP, format!("KVM lacks {name}")));
        }
    }
    let (max, max_id) = vcpu_limits(&kvm);
    if cfg.cpus > max.min(max_id) {
        return Err(Error::invalid(
            OP,
            format!(
                "{} vCPUs requested, KVM supports {}",
                cfg.cpus,
                max.min(max_id)
            ),
        ));
    }
    let run_size = kvm.vcpu_mmap_size()?;
    if run_size < size_of::<KvmRun>() {
        return Err(Error::invalid(
            OP,
            format!("kvm_run mapping of {run_size} bytes is smaller than struct kvm_run"),
        ));
    }
    let vm_type = A::vm_type(&kvm, cfg)?;
    let vm = kvm.create_vm(vm_type)?;
    let positive = |n: i32| (n > 0).then_some(n as u32);
    let max_slots = vm
        .check_extension(KVM_CAP_NR_MEMSLOTS)
        .ok()
        .and_then(positive)
        .or_else(|| positive(kvm.check_extension(KVM_CAP_NR_MEMSLOTS)))
        .unwrap_or(32);
    let arch = A::new(&kvm, &vm, cfg)?;
    Ok(KvmVm {
        inner: Arc::new(Inner {
            arch,
            vm,
            kvm,
            run_size,
            slots: (0..cfg.cpus).map(|_| Slot::default()).collect(),
            created: Mutex::new(0),
            finalized: Mutex::new(false),
            mem: Mutex::new(MemSlots {
                max: max_slots,
                used: Vec::new(),
                owners: Vec::new(),
            }),
        }),
    })
}

impl<A: ArchVm> KvmVm<A> {
    /// [`Vm::create_vcpu`] with the concrete type.
    fn create_kvm_vcpu(&self, index: usize) -> Result<KvmVcpu<A>> {
        const OP: &str = "create_vcpu";
        if index >= self.inner.slots.len() {
            return Err(Error::invalid(
                OP,
                format!("vCPU index {index} out of range"),
            ));
        }
        // In index order, so that KVM's vcpu_idx == vcpu_id (module docs).
        // Never waits for another thread's creation: refuses instead.
        let fd = {
            let mut created = lock(&self.inner.created);
            if index < *created {
                return Err(Error::invalid(
                    OP,
                    format!("vCPU {index} was already created"),
                ));
            }
            if index > *created {
                return Err(Error::invalid(
                    OP,
                    format!(
                        "vCPU {index} before vCPU {}: KVM numbers vCPUs in creation order, \
                         so they must be created in index order",
                        *created
                    ),
                ));
            }
            // On failure nothing was created in the kernel: the index can
            // be retried. On success the index is used for good (KVM vCPU
            // ids cannot be reused), even if the setup below fails.
            let fd =
                unblock_kick_signal().and_then(|()| self.inner.vm.create_vcpu(index as u64))?;
            *created += 1;
            fd
        };
        KvmVcpu::create(self.inner.clone(), index, fd)
    }
}

impl<A: ArchVm> Vm for KvmVm<A> {
    fn arch_info(&self) -> ArchVmInfo {
        self.inner.arch.arch_info()
    }

    fn map_memory(&self, mem: &Arc<vemu_core::GuestMemory>) -> Result<()> {
        const OP: &str = "map_memory";
        let mut slots = lock(&self.inner.mem);
        let regions = mem.regions();
        for r in regions {
            let (start, end) = (r.gpa, r.gpa_end());
            if let Some(&(s, e)) = slots.used.iter().find(|&&(s, e)| start < e && s < end) {
                return Err(Error::invalid(
                    OP,
                    format!("RAM {start:#x}..{end:#x} overlaps mapped RAM {s:#x}..{e:#x}"),
                ));
            }
        }
        if slots.used.len() + regions.len() > slots.max as usize {
            return Err(Error::invalid(
                OP,
                format!("KVM supports {} memory slots", slots.max),
            ));
        }
        // Before the first slot refers to it (and kept even if a later slot
        // fails: the earlier ones stay registered).
        slots.owners.push(mem.clone());
        for r in regions {
            let slot = slots.used.len() as u32;
            let region = KvmUserspaceMemoryRegion {
                slot,
                flags: 0,
                guest_phys_addr: r.gpa,
                memory_size: r.size as u64,
                // `host_offset` lies inside `mem`'s mapping (GuestMemory).
                userspace_addr: mem.host_base() as u64 + r.host_offset as u64,
            };
            // SAFETY: the range is a live, page-aligned anonymous mapping
            // owned by `mem`, which `slots.owners` keeps alive for the life
            // of the VM: until `Inner` drops, after every vCPU (each holds
            // an `Arc<Inner>`) and so after every KVM_RUN. The VM fd closes
            // with `Inner` too.
            unsafe { self.inner.vm.set_user_memory_region(&region) }?;
            slots.used.push((r.gpa, r.gpa_end()));
        }
        Ok(())
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        let line = self.inner.arch.irq_line(irq)?;
        self.inner.vm.irq_line(line, level)
    }

    fn create_vcpu(&self, index: usize) -> Result<Box<dyn Vcpu>> {
        Ok(Box::new(self.create_kvm_vcpu(index)?))
    }

    fn finalize(&self) -> Result<()> {
        const OP: &str = "finalize";
        let inner = &*self.inner;
        let mut finalized = lock(&inner.finalized);
        if *finalized {
            return Err(Error::invalid(OP, "the VM is already finalized"));
        }
        // Every vCPU exists (api.rst wants that before the first
        // KVM_ARM_VCPU_INIT); initialise them in index order.
        for (index, slot) in inner.slots.iter().enumerate() {
            // Holding the lock keeps the vCPU (and its fd) alive.
            let target = lock(&slot.target);
            let Some(t) = target.as_ref() else {
                return Err(Error::invalid(
                    OP,
                    format!("vCPU {index} does not exist: create every vCPU first"),
                ));
            };
            inner.arch.init_vcpu(&t.fd, index)?;
        }
        inner.arch.finalize(&inner.vm)?;
        *finalized = true;
        Ok(())
    }

    fn kick(&self, index: usize) {
        let Some(slot) = self.inner.slots.get(index) else {
            return;
        };
        // Holding the lock keeps the target alive (KvmVcpu::drop
        // unpublishes under it).
        let target = lock(&slot.target);
        let Some(t) = target.as_ref() else {
            return;
        };
        // Order matters, see the module docs: flag, immediate_exit, then
        // the signal if the vCPU may be inside KVM_RUN.
        slot.kick.store(true, SeqCst);
        // SAFETY: `t.run` is the live kvm_run mapping of the vCPU (see
        // KickTarget); immediate_exit is only accessed atomically by
        // userspace.
        let ie = unsafe { AtomicU8::from_ptr(ptr::addr_of_mut!((*t.run.as_ptr()).immediate_exit)) };
        ie.store(1, SeqCst);
        if slot.in_run.load(SeqCst) {
            // SAFETY: the thread is alive: the vCPU never leaves its
            // thread and unpublishes itself (under this lock) when dropped.
            let ret = unsafe { libc::pthread_kill(t.thread, kick_signal()) };
            debug_assert_eq!(ret, 0, "pthread_kill");
        }
    }
}

// --- vCPU ------------------------------------------------------------------------

/// [`Vcpu`] of the KVM backend. `!Send` (raw `kvm_run` pointer): it stays on
/// its creating thread.
struct KvmVcpu<A: ArchVm> {
    vm: Arc<Inner<A>>,
    index: usize,
    arch: A::Vcpu,
    /// Dropped (unmapped) before `fd` is closed.
    run: RunMap,
    /// Shared with the slot's [`KickTarget`] while the vCPU is alive.
    fd: Arc<VcpuFd>,
    /// Exit/completion protocol state (a `Cell`: `get_reg(&self)` flushes).
    pending: Cell<Pending>,
}

impl<A: ArchVm> KvmVcpu<A> {
    /// Finish creating vCPU `index`, whose `KVM_CREATE_VCPU` returned `fd`.
    fn create(vm: Arc<Inner<A>>, index: usize, fd: VcpuFd) -> Result<KvmVcpu<A>> {
        let slot = &vm.slots[index];
        let fd = Arc::new(fd);
        let run = RunMap::new(&fd, vm.run_size)?;
        let arch = vm.arch.create_vcpu(&vm.kvm, &vm.vm, &fd, index)?;
        *lock(&slot.target) = Some(KickTarget {
            // SAFETY: no preconditions.
            thread: unsafe { libc::pthread_self() },
            // SAFETY: as_ptr of a live mapping is non-null.
            run: unsafe { NonNull::new_unchecked(run.run.as_ptr()) },
            fd: fd.clone(),
        });
        Ok(KvmVcpu {
            vm,
            index,
            arch,
            run,
            fd,
            pending: Cell::new(Pending::None),
        })
    }

    fn slot(&self) -> &Slot {
        &self.vm.slots[self.index]
    }

    fn is_retry(e: &io::Error) -> bool {
        matches!(e.raw_os_error(), Some(libc::EINTR | libc::EAGAIN))
    }

    /// Error for a fatal exit.
    fn fault(&self, msg: String) -> Error {
        let ctx = self.arch.fault_context(&self.fd);
        Error::invalid("run", format!("vCPU {}: {msg}{ctx}", self.index))
    }

    /// Error for KVM_RUN failing with something else than EINTR/EAGAIN.
    fn run_error(&self, e: io::Error) -> Error {
        let mut msg = format!("KVM_RUN: {e}");
        match e.raw_os_error() {
            Some(libc::EFAULT | libc::EHWPOISON)
                if self.run.run.exit_reason() == KVM_EXIT_MEMORY_FAULT =>
            {
                // SAFETY: plain-data union member, filled for this exit.
                let m = unsafe { self.run.run.exit_data().memory_fault };
                msg += &format!(
                    " (guest memory fault at {:#x}+{:#x}, flags {:#x})",
                    m.gpa, m.size, m.flags
                );
            }
            Some(libc::ENOEXEC) => msg += " (vCPU not initialised, or guest executed outside RAM)",
            Some(libc::ENOSYS) if cfg!(target_arch = "aarch64") => {
                msg += " (data abort outside RAM without a valid syndrome: the guest used an MMIO \
                        access KVM cannot decode, e.g. load/store pair or writeback)"
            }
            _ => {}
        }
        self.fault(msg)
    }

    /// Decode the exit in kvm_run; `Ok(None)` to re-enter the guest.
    fn handle_exit(&mut self) -> Result<Option<VcpuExit>> {
        match exit::decode(&self.run.run) {
            Decoded::Exit(e, p) => {
                self.pending.set(p);
                Ok(Some(e))
            }
            Decoded::Again => Ok(None),
            Decoded::Arch(reason) => {
                let data = self.run.run.exit_data();
                self.arch.handle_exit(&self.fd, reason, &data)
            }
            Decoded::Fault(msg) => Err(self.fault(msg)),
        }
    }

    /// Finish a half-done MMIO / I/O instruction without running the guest
    /// (`KVM_RUN` with immediate_exit = 1), so registers are consistent.
    fn flush(&self) -> Result<()> {
        if !exit::needs_flush(self.pending.get()) {
            return Ok(());
        }
        self.run.run.immediate_exit().store(1, SeqCst);
        let r = self.fd.run();
        self.pending.set(Pending::None);
        match r {
            // The completion produced another exit (e.g. the second half of
            // a 16-byte x86 MMIO access): run() returns it next.
            Ok(()) => self.pending.set(Pending::Exit),
            Err(e) if Self::is_retry(&e) => {}
            Err(e) => return Err(self.run_error(e)),
        }
        Ok(())
    }
}

impl<A: ArchVm> Vcpu for KvmVcpu<A> {
    fn index(&self) -> usize {
        self.index
    }

    fn set_boot_state(&mut self, s: &BootState) -> Result<()> {
        // Drop whatever the vCPU was in the middle of; the kernel must
        // finish it (with reads returning 0) before new registers go in, or
        // it would complete the old instruction on top of them. That
        // includes an exit a flush produced that run() has not returned
        // yet (`Exit`, e.g. the next fragment of a split x86 MMIO access):
        // `abandon` decodes it. Each flush can produce one more fragment.
        for _ in 0..8 {
            self.pending
                .set(exit::abandon(self.pending.get(), &self.run.run));
            self.flush()?;
            if self.pending.get() != Pending::Exit {
                break;
            }
        }
        self.pending.set(Pending::None);
        self.arch.set_boot_state(&self.fd, s)
    }

    fn run(&mut self) -> Result<VcpuExit> {
        loop {
            exit::check_completed(self.pending.get()).map_err(|m| Error::invalid("run", m))?;
            if self.slot().kick.swap(false, SeqCst) {
                return Ok(VcpuExit::Kicked);
            }
            match exit::before_run(self.pending.get(), &self.run.run) {
                Before::Exit(e, p) => {
                    self.pending.set(p);
                    return Ok(e);
                }
                Before::Decode => {
                    self.pending.set(Pending::None);
                    if let Some(e) = self.handle_exit()? {
                        return Ok(e);
                    }
                    continue;
                }
                Before::Run => {}
            }
            // Kick protocol (module docs): announce, clear immediate_exit,
            // re-test the flag, enter.
            let slot = &self.vm.slots[self.index];
            slot.in_run.store(true, SeqCst);
            self.run.run.immediate_exit().store(0, SeqCst);
            if slot.kick.swap(false, SeqCst) {
                slot.in_run.store(false, SeqCst);
                return Ok(VcpuExit::Kicked);
            }
            let r = self.fd.run();
            slot.in_run.store(false, SeqCst);
            // Any KVM_RUN consumes the completion written before it (the
            // kernel completes before looking at immediate_exit/signals).
            self.pending.set(Pending::None);
            match r {
                Ok(()) => {
                    if let Some(e) = self.handle_exit()? {
                        return Ok(e);
                    }
                }
                // Kicked (reported at the loop top), a stray signal or a
                // leftover immediate_exit, or (x86) an AP woken by SIPI.
                Err(e) if Self::is_retry(&e) => {}
                Err(e) => return Err(self.run_error(e)),
            }
        }
    }

    fn complete_mmio_read(&mut self, value: u64) -> Result<()> {
        let p = exit::complete_mmio_read(self.pending.get(), &self.run.run, value)
            .map_err(|m| Error::invalid("complete_mmio_read", m))?;
        self.pending.set(p);
        Ok(())
    }

    fn complete_io_in(&mut self, value: u32) -> Result<()> {
        let p = exit::complete_io_in(self.pending.get(), &self.run.run, value)
            .map_err(|m| Error::invalid("complete_io_in", m))?;
        self.pending.set(p);
        Ok(())
    }

    fn get_reg(&self, reg: Reg) -> Result<u64> {
        self.flush()?;
        self.arch.get_reg(&self.fd, reg)
    }

    fn set_reg(&mut self, reg: Reg, val: u64) -> Result<()> {
        self.flush()?;
        self.arch.set_reg(&self.fd, reg, val)
    }
}

impl<A: ArchVm> Drop for KvmVcpu<A> {
    fn drop(&mut self) {
        // Unpublish first so kick() no longer touches kvm_run or the thread;
        // then the fields drop: arch state, the mapping, the fd.
        *lock(&self.slot().target) = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    #[test]
    fn kick_handler_has_no_sa_restart() {
        install_kick_handler().unwrap();
        // SAFETY: reads the current action into a zeroed struct.
        let sa = unsafe {
            let mut sa: libc::sigaction = mem::zeroed();
            assert_eq!(libc::sigaction(kick_signal(), ptr::null(), &mut sa), 0);
            sa
        };
        // A handler is installed. (Not compared with `on_kick_signal`'s
        // address: function addresses are not unique in Rust, and an
        // optimised build gave a different one for this empty function.)
        assert_ne!(sa.sa_sigaction, libc::SIG_DFL);
        assert_ne!(sa.sa_sigaction, libc::SIG_IGN);
        assert_eq!(sa.sa_flags & libc::SA_RESTART, 0);
        // Idempotent.
        install_kick_handler().unwrap();
    }

    /// The kick signal interrupts a blocking system call with EINTR, as it
    /// must interrupt KVM_RUN (runs without /dev/kvm).
    #[test]
    fn kick_signal_interrupts_blocking_calls() {
        install_kick_handler().unwrap();
        let mut fds = [0; 2];
        // SAFETY: valid out array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        let done = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
        let d = done.clone();
        let t = std::thread::spawn(move || {
            unblock_kick_signal().unwrap();
            // SAFETY: no preconditions.
            // (pthread_t is a pointer on musl: send it as an integer.)
            tid_tx
                .send(unsafe { libc::pthread_self() } as usize)
                .unwrap();
            let mut b = 0u8;
            // SAFETY: reads one byte into `b`.
            let n = unsafe { libc::read(rd, (&mut b as *mut u8).cast(), 1) };
            let err = io::Error::last_os_error().raw_os_error();
            d.store(true, SeqCst);
            // Stay alive until the main thread stops signalling us.
            exit_rx.recv().unwrap();
            (n, err)
        });
        let tid = tid_rx.recv().unwrap() as libc::pthread_t;
        let start = Instant::now();
        while !done.load(SeqCst) && start.elapsed() < Duration::from_secs(5) {
            // SAFETY: the thread is alive until we send on exit_tx.
            unsafe { libc::pthread_kill(tid, kick_signal()) };
            std::thread::sleep(Duration::from_millis(10));
        }
        if !done.load(SeqCst) {
            // Unblock it so the test fails instead of hanging.
            // SAFETY: writes one byte from a local.
            unsafe { libc::write(wr, [0u8].as_ptr().cast(), 1) };
        }
        exit_tx.send(()).unwrap();
        let (n, err) = t.join().unwrap();
        assert_eq!((n, err), (-1, Some(libc::EINTR)));
        // SAFETY: our pipe fds.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
    }

    #[test]
    fn ioctl_helpers_reject_mismatched_requests() {
        let devnull = std::fs::File::open("/dev/null").unwrap();
        let fd = Fd(OwnedFd::from(devnull));
        // A pointer request through the value helper.
        assert!(fd.ioctl_val("x", KVM_SET_USER_MEMORY_REGION, 0).is_err());
        // A buffer smaller than the request's size.
        let mut small = 0u32;
        // SAFETY: rejected before any system call.
        assert!(unsafe { fd.ioctl_ptr("x", KVM_SET_USER_MEMORY_REGION, &mut small) }.is_err());
        // A value request through the pointer helper.
        // SAFETY: rejected before any system call.
        assert!(unsafe { fd.ioctl_ptr("x", KVM_RUN, &mut small) }.is_err());
        // /dev/null rejects KVM ioctls with ENOTTY, reported as an errno.
        let e = fd
            .ioctl_val("KVM_GET_API_VERSION", KVM_GET_API_VERSION, 0)
            .unwrap_err();
        assert_eq!(e.code(), Some(libc::ENOTTY));
        assert!(e.to_string().contains("KVM_GET_API_VERSION: "), "{e}");
    }

    /// Real-KVM test of the common layer on x86_64 hosts with /dev/kvm,
    /// using a minimal arch (no irqchip; the vCPU starts in real mode at
    /// the reset vector). Skipped without /dev/kvm.
    #[cfg(target_arch = "x86_64")]
    mod x86 {
        use super::*;
        use crate::VcpuExit::*;
        use vemu_core::GuestMemory;

        const KVM_GET_REGS: u32 = ior::<[u64; 18]>(0x81);
        const KVM_SET_REGS: u32 = iow::<[u64; 18]>(0x82);

        /// vCPU index whose arch setup fails (after KVM_CREATE_VCPU).
        const FAILING_VCPU: usize = 2;

        struct TestArch;
        struct TestVcpu;

        /// `kvm_regs` (rax..r15, rip, rflags).
        fn regs(vcpu: &VcpuFd) -> Result<[u64; 18]> {
            let mut regs = [0u64; 18];
            // SAFETY: kvm_regs is 18 u64, written by the kernel.
            unsafe { vcpu.fd().ioctl_ptr("KVM_GET_REGS", KVM_GET_REGS, &mut regs) }?;
            Ok(regs)
        }

        impl ArchVm for TestArch {
            type Vcpu = TestVcpu;
            fn vm_type(_: &Kvm, _: &VmConfig) -> Result<u64> {
                Ok(0)
            }
            fn new(_: &Kvm, vm: &VmFd, _: &VmConfig) -> Result<TestArch> {
                // Real mode needs it on hosts without unrestricted guest.
                vm.fd()
                    .ioctl_val("KVM_SET_TSS_ADDR", KVM_SET_TSS_ADDR, 0xfffb_d000)?;
                Ok(TestArch)
            }
            fn arch_info(&self) -> ArchVmInfo {
                ArchVmInfo::default()
            }
            fn irq_line(&self, irq: u32) -> Result<u32> {
                Err(Error::invalid(
                    "set_irq_line",
                    format!("no irqchip for {irq}"),
                ))
            }
            fn create_vcpu(&self, _: &Kvm, _: &VmFd, _: &VcpuFd, i: usize) -> Result<TestVcpu> {
                if i == FAILING_VCPU {
                    return Err(Error::invalid("create_vcpu", "test arch"));
                }
                Ok(TestVcpu)
            }
            fn finalize(&self, _: &VmFd) -> Result<()> {
                Ok(())
            }
        }

        impl ArchVcpu for TestVcpu {
            /// Only sets RIP (CS keeps the reset segment).
            fn set_boot_state(&mut self, vcpu: &VcpuFd, s: &BootState) -> Result<()> {
                let mut regs = regs(vcpu)?;
                regs[16] = s.rip;
                // SAFETY: kvm_regs is 18 u64, read by the kernel.
                unsafe { vcpu.fd().ioctl_ptr("KVM_SET_REGS", KVM_SET_REGS, &mut regs) }?;
                Ok(())
            }
            fn get_reg(&self, vcpu: &VcpuFd, reg: Reg) -> Result<u64> {
                let regs = regs(vcpu)?;
                match reg {
                    Reg::Rax => Ok(regs[0]),
                    Reg::Rip => Ok(regs[16]),
                    _ => Err(Error::invalid("get_reg", "test arch")),
                }
            }
            fn set_reg(&mut self, _: &VcpuFd, _: Reg, _: u64) -> Result<()> {
                Err(Error::invalid("set_reg", "test arch"))
            }
        }

        /// 16-bit real-mode guest at 0xF000 in the segment at 0xFFFF0000
        /// (reset CS base), entered through a near jump at 0xFFF0.
        const CODE: &[u8] = &[
            0xBA, 0xF8, 0x03, // mov dx, 0x3f8
            0xB0, 0x41, // mov al, 'A'
            0xEE, // out dx, al
            0xEC, // in al, dx            (IP after: 0xF007)
            0xE6, 0x80, // out 0x80, al
            0xB8, 0x00, 0x20, // mov ax, 0x2000
            0x8E, 0xD8, // mov ds, ax
            0x66, 0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
            0x66, 0xA3, 0x00, 0x00, // mov [0], eax       (MMIO 0x20000)
            0x66, 0xA1, 0x08, 0x00, // mov eax, [8]       (MMIO 0x20008)
            0x66, 0xE7, 0x81, // out 0x81, eax
            0x31, 0xC0, // xor ax, ax
            0x8E, 0xD8, // mov ds, ax
            0x8E, 0xC0, // mov es, ax
            0xBF, 0x00, 0x01, // mov di, 0x100
            0xB9, 0x03, 0x00, // mov cx, 3
            0xBA, 0x82, 0x00, // mov dx, 0x82
            0xF3, 0x6C, // rep insb            (string I/O)
            0xA1, 0x00, 0x01, // mov ax, [0x100]
            0xE7, 0x83, // out 0x83, ax
            0xA0, 0x02, 0x01, // mov al, [0x102]
            0xE6, 0x84, // out 0x84, al
            0xBE, 0x00, 0x01, // mov si, 0x100
            0xB9, 0x03, 0x00, // mov cx, 3
            0xBA, 0x85, 0x00, // mov dx, 0x85
            0xF3, 0x6E, // rep outsb
            0xB8, 0x00, 0x20, // mov ax, 0x2000
            0x8E, 0xD8, // mov ds, ax
            0x66, 0xA1, 0x10, 0x00, // mov eax, [0x10]    (MMIO 0x20010)
            0x66, 0xE7, 0x86, // out 0x86, eax
            0xEB, 0xFE, // jmp $
        ];

        fn run_ok(v: &mut dyn Vcpu) -> VcpuExit {
            v.run().unwrap_or_else(|e| panic!("run: {e}"))
        }

        fn have_kvm() -> bool {
            let ok = std::fs::metadata("/dev/kvm").is_ok();
            if !ok {
                eprintln!("skipped: no /dev/kvm");
            }
            ok
        }

        /// RIP-only boot state for the test arch.
        fn boot(rip: u64) -> BootState {
            BootState {
                rip,
                rsi: 0,
                rsp: 0,
                cr3: 0,
                gdt_base: 0,
            }
        }

        /// RAM (low 64 KiB and the top 64 KiB, with the reset vector's
        /// `jmp 0xF000`) holding `code` at 0xFFFF_F000 (CS:IP 0xF000).
        fn guest_memory(code: &[u8]) -> Arc<GuestMemory> {
            let mem = GuestMemory::with_regions(&[(0, 0x1_0000), (0xFFFF_0000, 0x1_0000)]).unwrap();
            mem.write(0xFFFF_F000, code).unwrap();
            mem.write(0xFFFF_FFF0, &[0xE9, 0x0D, 0xF0]).unwrap(); // jmp 0xF000
            mem
        }

        /// set_boot_state while a flush left the second fragment of a
        /// page-crossing MMIO read in kvm_run (`Pending::Exit`): the kernel
        /// still holds that instruction, so it must be finished (read as 0)
        /// before the new registers go in, not replayed on top of them.
        /// Also: the VM keeps the guest memory it mapped alive.
        #[test]
        fn set_boot_state_after_a_split_mmio_fragment() {
            if !have_kvm() {
                return;
            }
            #[rustfmt::skip]
            let mut code = vec![
                0xB8, 0x00, 0x20,             // mov ax, 0x2000
                0x8E, 0xD8,                   // mov ds, ax
                0x66, 0xA1, 0xFE, 0x0F,       // mov eax, [0xFFE]  (MMIO 0x20FFE, 4 bytes: 2 + 2)
                0x66, 0xE7, 0x80,             // out 0x80, eax
                0xEB, 0xFE,                   // jmp $
            ];
            code.resize(0x100, 0xF4);
            // New entry point at 0xF100.
            code.extend_from_slice(&[
                0xB0, 0x77, // mov al, 0x77
                0xE6, 0x90, // out 0x90, al
                0xEB, 0xFE, // jmp $
            ]);
            let kvm_vm = new_vm::<TestArch>(&VmConfig { cpus: 1 }).unwrap();
            let mem = guest_memory(&code);
            kvm_vm.map_memory(&mem).unwrap();
            // The VM holds its own reference: the caller's can go.
            assert_eq!(Arc::strong_count(&mem), 2);
            let weak = Arc::downgrade(&mem);
            drop(mem);
            let mut vcpu = kvm_vm.create_kvm_vcpu(0).unwrap();
            kvm_vm.finalize().unwrap();
            let v = &mut vcpu;

            assert_eq!(
                run_ok(v),
                MmioRead {
                    addr: 0x2_0FFE,
                    len: 2
                }
            );
            v.complete_mmio_read(0x1111).unwrap();
            // The flush finishes the first fragment and stops at the second.
            let _ = v.get_reg(Reg::Rax).unwrap();
            assert_eq!(v.pending.get(), Pending::Exit);
            v.set_boot_state(&boot(0xF100)).unwrap();
            assert_eq!(v.pending.get(), Pending::None);
            assert_eq!(v.get_reg(Reg::Rip).unwrap(), 0xF100);
            assert_eq!(
                run_ok(v),
                IoOut {
                    port: 0x90,
                    len: 1,
                    data: 0x77
                }
            );

            // Memory lives until the VM and its vCPUs are gone.
            assert!(weak.upgrade().is_some());
            drop(kvm_vm);
            assert!(weak.upgrade().is_some(), "freed under a live vCPU");
            drop(vcpu);
            assert!(weak.upgrade().is_none());
        }

        /// vCPUs are created in index order, so that KVM's vcpu_idx (its
        /// creation counter) equals vcpu_id; out-of-order calls fail at once
        /// rather than wait, and a failure does not block later indices.
        #[test]
        fn vcpus_are_created_in_index_order() {
            if !have_kvm() {
                return;
            }
            let vm = new_vm::<TestArch>(&VmConfig { cpus: 4 }).unwrap();
            let e = vm.create_kvm_vcpu(1).err().expect("vCPU 1 before vCPU 0");
            assert!(e.to_string().contains("index order"), "{e}");
            assert!(vm.create_kvm_vcpu(4).is_err(), "out of range");
            assert!(vm.finalize().is_err(), "no vCPU yet");
            // Each vCPU on its own thread, the next one started after the
            // previous one exists (as the VMM does).
            let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
            let done_rx = Arc::new(Mutex::new(done_rx));
            let mut threads = Vec::new();
            for i in 0..2 {
                let (vm, done_rx) = (vm.inner.clone(), done_rx.clone());
                let (tx, rx) = std::sync::mpsc::channel();
                threads.push(std::thread::spawn(move || {
                    let vm = KvmVm { inner: vm };
                    let v = vm.create_kvm_vcpu(i);
                    tx.send(v.as_ref().map(drop).map_err(|e| e.to_string()))
                        .unwrap();
                    // Keep the vCPU alive until the test is done.
                    let _ = lock(&done_rx).recv();
                    drop(v);
                }));
                rx.recv_timeout(Duration::from_secs(10))
                    .expect("vCPU thread")
                    .unwrap();
            }
            assert!(vm.create_kvm_vcpu(1).is_err(), "created twice");
            assert!(vm.create_kvm_vcpu(3).is_err(), "vCPU 3 before vCPU 2");
            // The arch setup of vCPU 2 fails after KVM created it: the index
            // is used up, but vCPU 3 can still be created (KVM counted 2).
            assert!(vm.create_kvm_vcpu(FAILING_VCPU).is_err());
            assert!(vm.create_kvm_vcpu(FAILING_VCPU).is_err(), "id reused");
            let v3 = vm.create_kvm_vcpu(3).unwrap();
            // vCPU 2 does not exist: finalize says so instead of hanging.
            let e = vm.finalize().expect_err("finalize without vCPU 2");
            assert!(e.to_string().contains("vCPU 2"), "{e}");
            drop(v3);
            drop(done_tx);
            for t in threads {
                t.join().unwrap();
            }
        }

        #[test]
        fn real_kvm_common_layer() {
            if !have_kvm() {
                return;
            }
            let kvm_vm = Arc::new(new_vm::<TestArch>(&VmConfig { cpus: 1 }).unwrap());
            let vm: Arc<dyn Vm> = kvm_vm.clone();
            let mem = guest_memory(CODE);
            vm.map_memory(&mem).unwrap();
            // Overlapping RAM is refused.
            let again = GuestMemory::new(0x8000, 0x1000).unwrap();
            assert!(vm.map_memory(&again).is_err());
            assert!(vm.set_irq_line(5, true).is_err());
            assert!(vm.create_vcpu(1).is_err());
            let mut v = kvm_vm.create_kvm_vcpu(0).unwrap();
            assert!(vm.create_vcpu(0).is_err());
            vm.finalize().unwrap();
            let v = &mut v;

            // A kick before run() is sticky; several collapse into one.
            vm.kick(0);
            vm.kick(0);
            assert_eq!(run_ok(v), Kicked);

            assert_eq!(
                run_ok(v),
                IoOut {
                    port: 0x3f8,
                    len: 1,
                    data: 0x41
                }
            );
            assert_eq!(
                run_ok(v),
                IoIn {
                    port: 0x3f8,
                    len: 1
                }
            );
            assert!(v.run().is_err(), "IoIn must be completed first");
            v.complete_io_in(0x5a).unwrap();
            // Register reads flush the completion: AL and IP are updated.
            assert_eq!(v.get_reg(Reg::Rax).unwrap() & 0xff, 0x5a);
            assert_eq!(v.get_reg(Reg::Rip).unwrap(), 0xF007);
            assert_eq!(
                run_ok(v),
                IoOut {
                    port: 0x80,
                    len: 1,
                    data: 0x5a
                }
            );
            assert_eq!(
                run_ok(v),
                MmioWrite {
                    addr: 0x2_0000,
                    len: 4,
                    data: 0x1234_5678
                }
            );
            assert_eq!(
                run_ok(v),
                MmioRead {
                    addr: 0x2_0008,
                    len: 4
                }
            );
            assert!(v.complete_io_in(0).is_err());
            v.complete_mmio_read(0xcafe_f00d).unwrap();
            assert_eq!(
                run_ok(v),
                IoOut {
                    port: 0x81,
                    len: 4,
                    data: 0xcafe_f00d
                }
            );
            for b in [0x10, 0x11, 0x12] {
                assert_eq!(run_ok(v), IoIn { port: 0x82, len: 1 });
                // KVM batches `rep insb` into one KVM_EXIT_IO with count 3,
                // which run() hands out element by element.
                assert!(
                    matches!(v.pending.get(), Pending::Pio(p) if p.count == 3),
                    "{:?}",
                    v.pending.get()
                );
                v.complete_io_in(b).unwrap();
            }
            assert_eq!(
                run_ok(v),
                IoOut {
                    port: 0x83,
                    len: 2,
                    data: 0x1110
                }
            );
            assert_eq!(
                run_ok(v),
                IoOut {
                    port: 0x84,
                    len: 1,
                    data: 0x12
                }
            );
            for b in [0x10, 0x11, 0x12] {
                assert_eq!(
                    run_ok(v),
                    IoOut {
                        port: 0x85,
                        len: 1,
                        data: b
                    }
                );
            }

            // set_boot_state abandons a pending read: the kernel completes
            // it with 0 before the arch hook sets RIP (here: to the next
            // instruction, `out 0x86, eax` at 0xF04E).
            assert_eq!(
                run_ok(v),
                MmioRead {
                    addr: 0x2_0010,
                    len: 4
                }
            );
            v.set_boot_state(&boot(0xF04E)).unwrap();
            assert_eq!(v.pending.get(), Pending::None);
            assert_eq!(v.get_reg(Reg::Rip).unwrap(), 0xF04E);
            assert_eq!(
                run_ok(v),
                IoOut {
                    port: 0x86,
                    len: 4,
                    data: 0
                }
            );

            // The guest now spins: a kick from another thread gets it out.
            let kicker = |delay: Duration| {
                let vm = vm.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    vm.kick(0);
                })
            };
            for _ in 0..20 {
                let t = kicker(Duration::from_millis(20));
                let start = Instant::now();
                assert_eq!(run_ok(v), Kicked);
                assert!(start.elapsed() >= Duration::from_millis(15));
                t.join().unwrap();
            }
            // Kicks racing with entry are not lost (no delay).
            for _ in 0..200 {
                let t = kicker(Duration::ZERO);
                assert_eq!(run_ok(v), Kicked);
                t.join().unwrap();
            }
            // Two kicks before run(): one Kicked, then the guest runs again
            // until the next kick.
            vm.kick(0);
            vm.kick(0);
            assert_eq!(run_ok(v), Kicked);
            let t = kicker(Duration::from_millis(100));
            let start = Instant::now();
            assert_eq!(run_ok(v), Kicked);
            assert!(
                start.elapsed() >= Duration::from_millis(90),
                "double kick reported twice"
            );
            t.join().unwrap();
        }
    }
}
