//! Hypervisor.framework backend (macOS on Apple Silicon, macOS 15+ for the
//! in-kernel GIC).
//!
//! Behaviour this backend relies on, measured on macOS 27 (details and
//! evidence in `docs/research/hvf.md`):
//!
//! - With `hv_gic_create`, WFI never exits to userspace: `hv_vcpu_run` blocks
//!   in the kernel until an interrupt (SPI, SGI from another vCPU, virtual
//!   timer PPI 27) is pending or `hv_vcpus_exit` cancels the run. Timer and
//!   SGIs are delivered entirely in-kernel; `HV_EXIT_REASON_VTIMER_ACTIVATED`
//!   is not used.
//! - `hv_vcpus_exit` on a vCPU that is not inside `hv_vcpu_run` makes its next
//!   run return `CANCELED` at once; several such calls collapse into one.
//! - HVC exits report the PC *after* the HVC; SMC, sysreg and data-abort exits
//!   report the PC *of* the trapping instruction.
//! - The in-kernel WFI sleep is subject to XNU timer coalescing: on a normal
//!   thread a guest timer 1-20 ms ahead fires 25-50% late (up to ~5 ms).
//!   vCPU threads get QoS USER_INTERACTIVE, which keeps the slack to a few
//!   hundred microseconds for short timers. A time-constraint (real-time)
//!   policy would make timers exact, but is deliberately NOT used: a guest
//!   spinning on as many vCPUs as the host has cores starved watchdogd and
//!   panicked the host (watchdog timeout) during review. See
//!   docs/research/hvf.md §4.

mod ffi;
mod sysreg;

use std::collections::HashSet;
use std::io::Write as _;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::aarch64::esr::{self, DataAbort, SysReg, SysRegAccess};
use crate::aarch64::psci::{self, Outcome, PowerTable};
use crate::aarch64::{
    ArchVmInfo, BootState, GicInfo, GicVersion, Reg, load_value, pstate_after_skip, store_value,
};
use crate::{Error, GuestFault, Result, SystemEvent, Vcpu, VcpuExit, Vm, VmConfig};
use ffi::*;
use sysreg::{Action, SysRegs};

pub(crate) use ffi::return_name;

/// Initial SCTLR_EL1: MMU and caches off, little-endian, and the bits that are
/// RES1 on CPUs without the matching features (LSMAOE, nTLSMD, EIS, TSCXT,
/// EOS). This is Linux's INIT_SCTLR_EL1_MMU_OFF; the framework's default is 0.
const SCTLR_EL1_RESET: u64 = 0x30d0_0800;
/// Initial CPSR: EL1h with D, A, I and F masked.
const CPSR_RESET: u64 = 0x3c5;
/// MPIDR_EL1 bit 31 is RES1.
const MPIDR_RES1: u64 = 1 << 31;

/// Set while a VM exists: HVF supports one VM per process.
static VM_EXISTS: AtomicBool = AtomicBool::new(false);

fn check(op: &'static str, ret: hv_return_t) -> Result<()> {
    if ret == HV_SUCCESS {
        Ok(())
    } else {
        Err(Error::backend(op, ret))
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The process-wide "a VM exists" claim, released on drop.
struct VmClaim;

impl VmClaim {
    fn acquire() -> Result<VmClaim> {
        VM_EXISTS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| VmClaim)
            .map_err(|_| {
                Error::invalid(
                    "create_vm",
                    "a VM already exists in this process (HVF allows one)",
                )
            })
    }
}

impl Drop for VmClaim {
    fn drop(&mut self) {
        VM_EXISTS.store(false, Ordering::Release);
    }
}

/// An owned `os_object` reference (`hv_vm_config_t`, `hv_gic_config_t`).
struct OsObject(*mut std::ffi::c_void);

impl OsObject {
    fn new(op: &'static str, p: *mut std::ffi::c_void) -> Result<OsObject> {
        if p.is_null() {
            Err(Error::invalid(op, "framework returned no object"))
        } else {
            Ok(OsObject(p))
        }
    }
}

impl Drop for OsObject {
    fn drop(&mut self) {
        // SAFETY: we own one reference to this live os_object (checked
        // non-null at construction) and give it up exactly once.
        unsafe { os_release(self.0) };
    }
}

/// GIC geometry reported by the framework for this host.
struct GicParams {
    dist_size: u64,
    dist_align: u64,
    redist_region_size: u64,
    redist_size: u64,
    redist_align: u64,
    spi_base: u32,
    spi_count: u32,
}

impl GicParams {
    fn query() -> Result<GicParams> {
        let mut v = [0usize; 5];
        let (mut spi_base, mut spi_count) = (0u32, 0u32);
        // SAFETY: each call writes one value through a valid, exclusive
        // out-pointer; none requires a VM to exist.
        unsafe {
            check(
                "hv_gic_get_distributor_size",
                hv_gic_get_distributor_size(&mut v[0]),
            )?;
            check(
                "hv_gic_get_distributor_base_alignment",
                hv_gic_get_distributor_base_alignment(&mut v[1]),
            )?;
            check(
                "hv_gic_get_redistributor_region_size",
                hv_gic_get_redistributor_region_size(&mut v[2]),
            )?;
            check(
                "hv_gic_get_redistributor_size",
                hv_gic_get_redistributor_size(&mut v[3]),
            )?;
            check(
                "hv_gic_get_redistributor_base_alignment",
                hv_gic_get_redistributor_base_alignment(&mut v[4]),
            )?;
            check(
                "hv_gic_get_spi_interrupt_range",
                hv_gic_get_spi_interrupt_range(&mut spi_base, &mut spi_count),
            )?;
        }
        Ok(GicParams {
            dist_size: v[0] as u64,
            dist_align: v[1] as u64,
            redist_region_size: v[2] as u64,
            redist_size: v[3] as u64,
            redist_align: v[4] as u64,
            spi_base,
            spi_count,
        })
    }

    /// Validate `cfg` against the host limits and derive the VM's GIC layout.
    fn layout(&self, cfg: &VmConfig, max_cpus: u32) -> Result<GicInfo> {
        const OP: &str = "create_vm";
        let (dist_base, redist_base) = (cfg.gic.dist_base, cfg.gic.redist_base);
        if cfg.cpus == 0 || cfg.cpus > max_cpus as usize {
            return Err(Error::invalid(
                OP,
                format!("cpus must be 1..={max_cpus}, got {}", cfg.cpus),
            ));
        }
        if !dist_base.is_multiple_of(self.dist_align) {
            return Err(Error::invalid(
                OP,
                format!(
                    "GIC distributor base {dist_base:#x} is not {:#x}-aligned",
                    self.dist_align
                ),
            ));
        }
        if !redist_base.is_multiple_of(self.redist_align) {
            return Err(Error::invalid(
                OP,
                format!(
                    "GIC redistributor base {redist_base:#x} is not {:#x}-aligned",
                    self.redist_align
                ),
            ));
        }
        let redist_used = cfg.cpus as u64 * self.redist_size;
        if redist_used > self.redist_region_size {
            return Err(Error::invalid(
                OP,
                "redistributor region too small for the vCPU count",
            ));
        }
        let (d0, d1) = (dist_base, dist_base + self.dist_size);
        let (r0, r1) = (redist_base, redist_base + redist_used);
        if d0 < r1 && r0 < d1 {
            return Err(Error::invalid(
                OP,
                "GIC distributor and redistributor regions overlap",
            ));
        }
        Ok(GicInfo {
            version: GicVersion::V3,
            dist_base,
            dist_size: self.dist_size,
            redist_base,
            redist_region_size: redist_used,
            redist_stride: self.redist_size,
            cpu_base: 0,
            cpu_size: 0,
            spi_base: self.spi_base,
            spi_count: self.spi_count,
        })
    }
}

/// Per-vCPU-index state shared between the VM handle and the vCPU.
#[derive(Default)]
struct Slot {
    /// The live vCPU's framework id; `None` before creation and after destroy.
    id: Mutex<Option<hv_vcpu_t>>,
    /// Set once the index has been used, so it cannot be created twice.
    taken: AtomicBool,
    /// Pending kick, consumed by `run()`.
    kick: AtomicBool,
}

/// The VM proper. Kept alive by the [`HvfVm`] handle and by every vCPU, so
/// `hv_vm_destroy` only runs once all vCPUs are destroyed.
struct Inner {
    gic: GicInfo,
    /// IPA width of the guest-physical address space.
    ipa_bits: u32,
    /// Shared vtimer offset: every vCPU sees the same CNTVCT_EL0, starting
    /// near 0 at VM creation.
    vtimer_offset: u64,
    slots: Box<[Slot]>,
    /// PSCI power state of every vCPU (this backend emulates PSCI).
    power: PowerTable,
    /// `[start, end)` of every mapped RAM region, to validate PSCI `CPU_ON`
    /// entry points.
    ram: Mutex<Vec<(u64, u64)>>,
    /// The memory behind the mappings, kept alive until after
    /// `hv_vm_destroy` (fields drop after `Drop::drop`).
    memory: Mutex<Vec<Arc<vemu_core::GuestMemory>>>,
    /// Unknown sysregs already reported (each is logged once per VM).
    logged_sysregs: Mutex<HashSet<SysReg>>,
    /// Dropped after `hv_vm_destroy` (fields drop after `Drop::drop`).
    _claim: VmClaim,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: every vCPU holds an Arc<Inner> and destroys itself on drop,
        // so none is left; the process has exactly this one VM.
        let ret = unsafe { hv_vm_destroy() };
        debug_assert_eq!(ret, HV_SUCCESS, "hv_vm_destroy");
    }
}

/// [`Vm`] handle of the HVF backend.
pub(crate) struct HvfVm {
    inner: Arc<Inner>,
}

pub(crate) fn create_vm(cfg: &VmConfig) -> Result<Arc<dyn Vm>> {
    let claim = VmClaim::acquire()?;
    let params = GicParams::query()?;
    let mut max_cpus = 0u32;
    // SAFETY: valid out-pointer.
    check("hv_vm_get_max_vcpu_count", unsafe {
        hv_vm_get_max_vcpu_count(&mut max_cpus)
    })?;
    let gic = params.layout(cfg, max_cpus)?;

    let mut ipa_bits = 0u32;
    // SAFETY: valid out-pointer.
    check("hv_vm_config_get_default_ipa_size", unsafe {
        hv_vm_config_get_default_ipa_size(&mut ipa_bits)
    })?;
    // SAFETY: plain constructor; the result is checked and owned below.
    let config = OsObject::new("hv_vm_config_create", unsafe { hv_vm_config_create() })?;
    // SAFETY: `config` is a live VM configuration object.
    check("hv_vm_config_set_ipa_size", unsafe {
        hv_vm_config_set_ipa_size(config.0, ipa_bits)
    })?;
    // SAFETY: `config` is live; the claim guarantees no other VM exists.
    check("hv_vm_create", unsafe { hv_vm_create(config.0) })?;
    drop(config);

    // From here on, dropping `inner` destroys the VM.
    let inner = Arc::new(Inner {
        gic,
        ipa_bits,
        // SAFETY: no preconditions.
        vtimer_offset: unsafe { mach_absolute_time() },
        slots: (0..cfg.cpus).map(|_| Slot::default()).collect(),
        power: PowerTable::new(cfg.cpus),
        ram: Mutex::new(Vec::new()),
        memory: Mutex::new(Vec::new()),
        logged_sysregs: Mutex::new(HashSet::new()),
        _claim: claim,
    });

    // The GIC must be created after the VM and before any vCPU.
    // SAFETY: plain constructor; the result is checked and owned below.
    let gic_config = OsObject::new("hv_gic_config_create", unsafe { hv_gic_config_create() })?;
    // SAFETY (three calls): `gic_config` is a live GIC configuration object,
    // the VM exists and has no vCPU yet.
    unsafe {
        check(
            "hv_gic_config_set_distributor_base",
            hv_gic_config_set_distributor_base(gic_config.0, gic.dist_base),
        )?;
        check(
            "hv_gic_config_set_redistributor_base",
            hv_gic_config_set_redistributor_base(gic_config.0, gic.redist_base),
        )?;
        check("hv_gic_create", hv_gic_create(gic_config.0))?;
    }
    Ok(Arc::new(HvfVm { inner }))
}

impl Vm for HvfVm {
    fn arch_info(&self) -> ArchVmInfo {
        ArchVmInfo {
            gic: self.inner.gic,
            // create_vcpu sets MPIDR_EL1 Aff0 = index.
            mpidr_aff0_cpus: 256,
        }
    }

    fn map_memory(&self, mem: &Arc<vemu_core::GuestMemory>) -> Result<()> {
        // Before the first mapping refers to it (and kept even if a later
        // one fails: the earlier ones stay).
        lock(&self.inner.memory).push(mem.clone());
        // One mapping per region: a multi-region GuestMemory is contiguous on
        // the host but has holes in guest-physical space.
        for r in mem.regions() {
            // SAFETY: `host_offset..+size` of `host_base()` is a live,
            // page-aligned part of the anonymous mapping owned by `mem`
            // (GuestMemory invariant); `Inner::memory` keeps `mem` alive
            // until after `hv_vm_destroy`, i.e. after every vCPU is gone.
            check("hv_vm_map", unsafe {
                hv_vm_map(
                    mem.host_base().add(r.host_offset).cast(),
                    r.gpa,
                    r.size,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
                )
            })?;
            lock(&self.inner.ram).push((r.gpa, r.gpa_end()));
        }
        Ok(())
    }

    fn set_irq_line(&self, intid: u32, level: bool) -> Result<()> {
        if !self.inner.gic.is_spi(intid) {
            return Err(Error::invalid(
                "set_irq_line",
                format!("INTID {intid} is not an SPI"),
            ));
        }
        // SAFETY: the VM and its GIC exist; hv_gic_set_spi may be called from
        // any thread.
        check("hv_gic_set_spi", unsafe { hv_gic_set_spi(intid, level) })
    }

    fn create_vcpu(&self, index: usize) -> Result<Box<dyn Vcpu>> {
        const OP: &str = "create_vcpu";
        let slot = self
            .inner
            .slots
            .get(index)
            .ok_or_else(|| Error::invalid(OP, format!("vCPU index {index} out of range")))?;
        if slot.taken.swap(true, Ordering::AcqRel) {
            return Err(Error::invalid(
                OP,
                format!("vCPU {index} was already created"),
            ));
        }
        let vcpu = HvfVcpu::create(self.inner.clone(), index);
        if vcpu.is_err() {
            slot.taken.store(false, Ordering::Release);
        }
        Ok(Box::new(vcpu?))
    }

    fn finalize(&self) -> Result<()> {
        Ok(())
    }

    fn kick(&self, index: usize) {
        let Some(slot) = self.inner.slots.get(index) else {
            return;
        };
        // Holding the lock keeps the id valid (the vCPU cannot be destroyed
        // concurrently).
        let id = lock(&slot.id);
        if let Some(mut id) = *id {
            // Flag first: run() re-checks it after every canceled run.
            slot.kick.store(true, Ordering::Release);
            // SAFETY: `id` names a live vCPU of this VM; hv_vcpus_exit may be
            // called from any thread.
            let ret = unsafe { hv_vcpus_exit(&mut id, 1) };
            debug_assert_eq!(ret, HV_SUCCESS, "hv_vcpus_exit");
            // A powered-off vCPU waits in run() for CPU_ON: wake it too.
            self.inner.power.wake();
        }
    }
}

/// An MMIO load waiting for [`Vcpu::complete_mmio_read`].
#[derive(Debug, Clone, Copy)]
struct PendingRead {
    /// Destination register; 31 = XZR (value discarded).
    rt: u8,
    len: usize,
    sign_extend: bool,
    /// 64-bit (Xn) destination.
    sf: bool,
}

/// [`Vcpu`] of the HVF backend. The raw exit pointer makes it `!Send`, as
/// required: HVF vCPUs belong to their creating thread.
struct HvfVcpu {
    vm: Arc<Inner>,
    index: usize,
    id: hv_vcpu_t,
    /// Exit information, written by the framework on each `hv_vcpu_run`.
    exit: *const hv_vcpu_exit_t,
    pending_read: Option<PendingRead>,
    sysregs: SysRegs,
    /// Mirrors `vm.power.state(index) == On`. Only this vCPU's thread turns
    /// it on (CPU_ON pickup, set_boot_state) or off (CPU_OFF), so the copy
    /// is exact and run() needs no lock per exit.
    powered: bool,
}

impl HvfVcpu {
    fn create(vm: Arc<Inner>, index: usize) -> Result<HvfVcpu> {
        if let Err(err) = set_vcpu_thread_qos() {
            // Not eprintln!: it panics when stderr is a closed pipe.
            let _ = writeln!(
                std::io::stderr(),
                "vemu-hv: vCPU {index}: cannot set the thread QoS class ({err}); \
                 guest timers may fire late"
            );
        }
        let mut id: hv_vcpu_t = 0;
        let mut exit: *const hv_vcpu_exit_t = ptr::null();
        // SAFETY: valid out-pointers; a null config selects the defaults.
        // Fails if this thread already owns a vCPU.
        check("hv_vcpu_create", unsafe {
            hv_vcpu_create(&mut id, &mut exit, ptr::null_mut())
        })?;
        // From here on, dropping `vcpu` destroys the framework vCPU.
        let vcpu = HvfVcpu {
            vm,
            index,
            id,
            exit,
            pending_read: None,
            sysregs: SysRegs::default(),
            powered: index == 0,
        };
        vcpu.init()?;
        *lock(&vcpu.vm.slots[index].id) = Some(id);
        Ok(vcpu)
    }

    /// Initial register state; see [`Vm::create_vcpu`].
    fn init(&self) -> Result<()> {
        // GICv3 routes by affinity: MPIDR must be set before the vCPU runs.
        self.set_sys_reg(HV_SYS_REG_MPIDR_EL1, MPIDR_RES1 | self.index as u64)?;
        self.set_power_on_state()?;
        // Advertise only the IPA range the VM really has (the host value is
        // larger than the default IPA size).
        let mmfr0 = self.get_sys_reg(HV_SYS_REG_ID_AA64MMFR0_EL1)?;
        let parange = mmfr0 & 0xf;
        let limit = parange_for_ipa_bits(self.vm.ipa_bits);
        if parange > limit {
            self.set_sys_reg(HV_SYS_REG_ID_AA64MMFR0_EL1, (mmfr0 & !0xf) | limit)?;
        }
        // SAFETY: own vCPU, called on its thread.
        check("hv_vcpu_set_vtimer_offset", unsafe {
            hv_vcpu_set_vtimer_offset(self.id, self.vm.vtimer_offset)
        })
    }

    /// The reset values that matter for entering a kernel: EL1h with
    /// interrupts masked, MMU and caches off.
    fn set_power_on_state(&self) -> Result<()> {
        self.set_sys_reg(HV_SYS_REG_SCTLR_EL1, SCTLR_EL1_RESET)?;
        self.set_hv_reg(HV_REG_CPSR, CPSR_RESET)
    }

    /// Enter at `entry` with X0 = `context`, in the state the arm64 boot
    /// protocol and PSCI `CPU_ON` require: as from reset (EL1h, DAIF masked,
    /// MMU and caches off), even if the vCPU ran before and was powered off
    /// (with the MMU still on, the physical entry address would be
    /// translated through stale page tables). MPIDR_EL1 and the virtual
    /// counter offset are kept; other registers keep their values.
    fn enter(&mut self, entry: u64, context: u64) -> Result<()> {
        self.pending_read = None;
        self.set_power_on_state()?;
        self.set_hv_reg(HV_REG_PC, entry)?;
        self.set_hv_reg(HV_REG_X0, context)?;
        for r in 1..=3 {
            self.set_hv_reg(HV_REG_X0 + r, 0)?;
        }
        Ok(())
    }

    /// Handle an SMCCC call (`HVC #0`) as PSCI firmware. `Ok(None)` means
    /// re-enter the guest (or wait, after CPU_OFF).
    fn handle_psci(&mut self) -> Result<Option<VcpuExit>> {
        let mut x = [0u64; 4];
        for (r, v) in x.iter_mut().enumerate() {
            *v = self.get_hv_reg(HV_REG_X0 + r as u32)?;
        }
        let vm = self.vm.clone();
        let is_ram = |gpa: u64, len: u64| {
            lock(&vm.ram)
                .iter()
                .any(|&(start, end)| gpa >= start && gpa.checked_add(len).is_some_and(|e| e <= end))
        };
        match psci::dispatch(x, self.index, &vm.power, is_ram) {
            Outcome::Return(v) => {
                self.set_hv_reg(HV_REG_X0, v as u64)?;
                Ok(None)
            }
            Outcome::CpuOff => {
                self.powered = false;
                Ok(None)
            }
            Outcome::SystemOff => Ok(Some(VcpuExit::SystemEvent(SystemEvent::Shutdown))),
            Outcome::SystemReset => Ok(Some(VcpuExit::SystemEvent(SystemEvent::Reset))),
        }
    }

    fn get_hv_reg(&self, reg: hv_reg_t) -> Result<u64> {
        let mut v = 0;
        // SAFETY: own vCPU on its thread; valid out-pointer.
        check("hv_vcpu_get_reg", unsafe {
            hv_vcpu_get_reg(self.id, reg, &mut v)
        })?;
        Ok(v)
    }

    fn set_hv_reg(&self, reg: hv_reg_t, v: u64) -> Result<()> {
        // SAFETY: own vCPU on its thread.
        check("hv_vcpu_set_reg", unsafe {
            hv_vcpu_set_reg(self.id, reg, v)
        })
    }

    fn get_sys_reg(&self, reg: hv_sys_reg_t) -> Result<u64> {
        let mut v = 0;
        // SAFETY: own vCPU on its thread; valid out-pointer.
        check("hv_vcpu_get_sys_reg", unsafe {
            hv_vcpu_get_sys_reg(self.id, reg, &mut v)
        })?;
        Ok(v)
    }

    fn set_sys_reg(&self, reg: hv_sys_reg_t, v: u64) -> Result<()> {
        // SAFETY: own vCPU on its thread.
        check("hv_vcpu_set_sys_reg", unsafe {
            hv_vcpu_set_sys_reg(self.id, reg, v)
        })
    }

    /// Read general-purpose register `n` as an instruction operand: 31 is XZR.
    fn xreg(&self, n: u8) -> Result<u64> {
        if n == 31 {
            Ok(0)
        } else {
            self.get_hv_reg(HV_REG_X0 + u32::from(n))
        }
    }

    /// Write general-purpose register `n` as an instruction result: writes to
    /// 31 (XZR) are discarded.
    fn set_xreg(&self, n: u8, v: u64) -> Result<()> {
        if n == 31 {
            Ok(())
        } else {
            self.set_hv_reg(HV_REG_X0 + u32::from(n), v)
        }
    }

    /// Step over the trapping instruction, which the backend has emulated.
    /// Every emulation path (MMIO, sysreg trap, SMC, WFx) goes through here.
    /// Besides the PC, PSTATE must show the instruction as completed: a guest
    /// software-stepping it (MDSCR_EL1.SS) trapped with PSTATE.SS=1, and
    /// leaving it set would run one more instruction before the step
    /// exception; BTYPE from a branch onto it must not be checked against the
    /// next instruction.
    fn skip_insn(&self, esr: u64) -> Result<()> {
        let pc = self.get_hv_reg(HV_REG_PC)?;
        self.set_hv_reg(HV_REG_PC, pc.wrapping_add(esr::insn_len(esr)))?;
        let cpsr = self.get_hv_reg(HV_REG_CPSR)?;
        let skipped = pstate_after_skip(cpsr);
        if skipped != cpsr {
            self.set_hv_reg(HV_REG_CPSR, skipped)?;
        }
        Ok(())
    }

    fn fault(&self, what: &'static str, exc: &hv_vcpu_exit_exception_t) -> Error {
        Error::guest(
            "run",
            GuestFault {
                what,
                esr: exc.syndrome,
                far: exc.virtual_address,
                ipa: exc.physical_address,
                pc: self.get_hv_reg(HV_REG_PC).unwrap_or(u64::MAX),
            },
        )
    }

    /// Handle an `HV_EXIT_REASON_EXCEPTION`. `Ok(None)` means handled here,
    /// re-enter the guest.
    fn handle_exception(&mut self, exc: &hv_vcpu_exit_exception_t) -> Result<Option<VcpuExit>> {
        let syn = exc.syndrome;
        match esr::ec(syn) {
            esr::EC_DABT_LOWER => self.handle_mmio(exc),
            // The PC already points past the HVC. SMCCC uses HVC #0 (the
            // device tree names HVC as the PSCI conduit); other immediates
            // are not SMCCC calls.
            esr::EC_HVC64 => match esr::imm16(syn) {
                0 => self.handle_psci(),
                imm => {
                    self.set_hv_reg(HV_REG_X0, psci::NOT_SUPPORTED as u64)?;
                    Ok(Some(VcpuExit::Hvc { imm }))
                }
            },
            // The PC points at the SMC. There is no secure firmware behind
            // it: answer NOT_SUPPORTED, as KVM does.
            esr::EC_SMC64 => {
                self.skip_insn(syn)?;
                self.set_hv_reg(HV_REG_X0, psci::NOT_SUPPORTED as u64)?;
                Ok(None)
            }
            esr::EC_SYSREG => {
                self.handle_sysreg(syn)?;
                self.skip_insn(syn)?;
                Ok(None)
            }
            // Not trapped while the in-kernel GIC exists (WFI idles in
            // hv_vcpu_run). Should the framework ever trap one, completing it
            // at once is architecturally a spurious wake-up, which guests
            // tolerate.
            esr::EC_WFX => {
                self.skip_insn(syn)?;
                Ok(None)
            }
            esr::EC_IABT_LOWER => Err(self.fault("instruction fetch outside guest RAM", exc)),
            esr::EC_UNKNOWN => Err(self.fault("exception with unknown reason", exc)),
            _ => Err(self.fault("unhandled exception class", exc)),
        }
    }

    /// A stage-2 data abort: an access outside guest RAM, i.e. MMIO.
    fn handle_mmio(&mut self, exc: &hv_vcpu_exit_exception_t) -> Result<Option<VcpuExit>> {
        let syn = exc.syndrome;
        let d = DataAbort::decode(syn);
        if d.s1ptw {
            return Err(self.fault("stage-1 page-table walk outside guest RAM", exc));
        }
        if d.cm {
            // Cache maintenance by VA on MMIO: nothing is cached there.
            self.skip_insn(syn)?;
            return Ok(None);
        }
        if !d.isv {
            return Err(self.fault("MMIO access without instruction syndrome (ISV=0)", exc));
        }
        let addr = exc.physical_address;
        let exit = if d.write {
            let data = store_value(self.xreg(d.srt)?, d.len);
            VcpuExit::MmioWrite {
                addr,
                len: d.len,
                data,
            }
        } else {
            self.pending_read = Some(PendingRead {
                rt: d.srt,
                len: d.len,
                sign_extend: d.sign_extend,
                sf: d.sf,
            });
            VcpuExit::MmioRead { addr, len: d.len }
        };
        self.skip_insn(syn)?;
        Ok(Some(exit))
    }

    fn handle_sysreg(&mut self, syn: u64) -> Result<()> {
        let a = SysRegAccess::decode(syn);
        let val = if a.read { 0 } else { self.xreg(a.rt)? };
        match self.sysregs.access(a.reg, a.read, val) {
            Action::Done(v) if a.read => self.set_xreg(a.rt, v),
            Action::Done(_) => Ok(()),
            Action::Mdccint if a.read => {
                self.set_xreg(a.rt, self.get_sys_reg(HV_SYS_REG_MDCCINT_EL1)?)
            }
            Action::Mdccint => self.set_sys_reg(HV_SYS_REG_MDCCINT_EL1, val),
            Action::Unknown => {
                if lock(&self.vm.logged_sysregs).insert(a.reg) {
                    let _ = writeln!(
                        std::io::stderr(),
                        "vemu-hv: vCPU {}: unhandled {} system register {} at PC {:#x}; \
                         treating it as RAZ/WI (logged once)",
                        self.index,
                        if a.read { "read of" } else { "write to" },
                        a.reg,
                        self.get_hv_reg(HV_REG_PC)?,
                    );
                }
                if a.read {
                    self.set_xreg(a.rt, 0)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Give the calling (vCPU) thread QoS USER_INTERACTIVE, so that the
/// framework's in-kernel WFI sleep gets little timer-coalescing slack (see the
/// module documentation). Never a real-time policy: that lets a busy guest
/// starve the host.
fn set_vcpu_thread_qos() -> std::result::Result<(), std::io::Error> {
    // SAFETY: only changes the calling thread's QoS class; no pointers.
    let rc = unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0)
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(rc))
    }
}

/// Largest ID_AA64MMFR0_EL1.PARange encoding that fits in `bits`.
fn parange_for_ipa_bits(bits: u32) -> u64 {
    const RANGES: [u32; 7] = [32, 36, 40, 42, 44, 48, 52];
    RANGES.iter().rposition(|&r| r <= bits).unwrap_or(0) as u64
}

impl Vcpu for HvfVcpu {
    fn index(&self) -> usize {
        self.index
    }

    fn get_reg(&self, reg: Reg) -> Result<u64> {
        match reg {
            Reg::X(n @ 0..=30) => self.get_hv_reg(HV_REG_X0 + u32::from(n)),
            Reg::X(n) => Err(Error::invalid("get_reg", format!("no register X{n}"))),
            Reg::Sp => self.get_sys_reg(HV_SYS_REG_SP_EL1),
            Reg::Pc => self.get_hv_reg(HV_REG_PC),
            Reg::Cpsr => self.get_hv_reg(HV_REG_CPSR),
        }
    }

    fn set_reg(&mut self, reg: Reg, val: u64) -> Result<()> {
        match reg {
            Reg::X(n @ 0..=30) => self.set_hv_reg(HV_REG_X0 + u32::from(n), val),
            Reg::X(n) => Err(Error::invalid("set_reg", format!("no register X{n}"))),
            Reg::Sp => self.set_sys_reg(HV_SYS_REG_SP_EL1, val),
            Reg::Pc => self.set_hv_reg(HV_REG_PC, val),
            Reg::Cpsr => self.set_hv_reg(HV_REG_CPSR, val),
        }
    }

    fn set_boot_state(&mut self, s: &BootState) -> Result<()> {
        self.enter(s.pc, s.x0)?;
        self.vm.power.power_on(self.index);
        self.powered = true;
        Ok(())
    }

    fn run(&mut self) -> Result<VcpuExit> {
        if self.pending_read.is_some() {
            return Err(Error::invalid("run", "previous MmioRead was not completed"));
        }
        let vm = self.vm.clone();
        let kick = &vm.slots[self.index].kick;
        loop {
            if kick.swap(false, Ordering::AcqRel) {
                return Ok(VcpuExit::Kicked);
            }
            if !self.powered {
                // Powered off: wait for PSCI CPU_ON from another vCPU, or a
                // kick (reported at the loop top).
                if let Some((entry, context)) = vm.power.wait_for_power_on(self.index, kick) {
                    self.enter(entry, context)?;
                    self.powered = true;
                }
                continue;
            }
            // SAFETY: own vCPU, on its thread.
            check("hv_vcpu_run", unsafe { hv_vcpu_run(self.id) })?;
            // SAFETY: the framework keeps `exit` valid for the vCPU's lifetime
            // and has just filled it; we copy it out before the next run.
            let exit = unsafe { *self.exit };
            match exit.reason {
                // Either a kick (the flag is set: reported at the loop top) or
                // the leftover cancel of a kick that run() already reported
                // before entering the guest: just re-enter.
                HV_EXIT_REASON_CANCELED => {}
                HV_EXIT_REASON_EXCEPTION => {
                    if let Some(e) = self.handle_exception(&exit.exception)? {
                        return Ok(e);
                    }
                }
                // Not delivered when the in-kernel GIC exists (it injects PPI 27
                // itself). Ignoring it is safe: the framework keeps the timer
                // masked for exits, and the GIC still sees the timer line.
                HV_EXIT_REASON_VTIMER_ACTIVATED => {}
                _ => return Err(self.fault("unknown exit reason", &exit.exception)),
            }
        }
    }

    fn complete_mmio_read(&mut self, value: u64) -> Result<()> {
        let p = self
            .pending_read
            .take()
            .ok_or_else(|| Error::invalid("complete_mmio_read", "no MmioRead pending"))?;
        self.set_xreg(p.rt, load_value(value, p.len, p.sign_extend, p.sf))
    }

    fn complete_io_in(&mut self, _value: u32) -> Result<()> {
        Err(Error::invalid(
            "complete_io_in",
            "no port I/O on aarch64 (no IoIn pending)",
        ))
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        // Unpublish first so kick() no longer targets this id.
        *lock(&self.vm.slots[self.index].id) = None;
        // SAFETY: own vCPU; HvfVcpu is !Send, so this runs on the owning thread.
        let ret = unsafe { hv_vcpu_destroy(self.id) };
        debug_assert_eq!(ret, HV_SUCCESS, "hv_vcpu_destroy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::GicRequest;

    #[test]
    fn parange() {
        assert_eq!(parange_for_ipa_bits(36), 1);
        assert_eq!(parange_for_ipa_bits(40), 2);
        assert_eq!(parange_for_ipa_bits(41), 2);
        assert_eq!(parange_for_ipa_bits(52), 6);
        assert_eq!(parange_for_ipa_bits(30), 0);
    }

    fn params() -> GicParams {
        GicParams {
            dist_size: 0x1_0000,
            dist_align: 0x1_0000,
            redist_region_size: 0x200_0000,
            redist_size: 0x2_0000,
            redist_align: 0x1_0000,
            spi_base: 32,
            spi_count: 988,
        }
    }

    #[test]
    fn layout() {
        let p = params();
        let cfg = VmConfig {
            cpus: 4,
            ..VmConfig::default()
        };
        let g = p.layout(&cfg, 64).unwrap();
        assert_eq!(g.redist_region_size, 4 * 0x2_0000);
        assert_eq!(g.redist_stride, 0x2_0000);
        assert_eq!(g.version, GicVersion::V3);
        assert_eq!((g.dist_base, g.redist_base), (0x0800_0000, 0x080A_0000));
        assert_eq!((g.spi_base, g.spi_count), (32, 988));
        assert!(
            p.layout(
                &VmConfig {
                    cpus: 0,
                    ..cfg.clone()
                },
                64
            )
            .is_err()
        );
        assert!(
            p.layout(
                &VmConfig {
                    cpus: 65,
                    ..cfg.clone()
                },
                64
            )
            .is_err()
        );
        assert!(
            p.layout(
                &VmConfig {
                    gic: GicRequest {
                        dist_base: 0x0800_1000,
                        ..cfg.gic
                    },
                    ..cfg.clone()
                },
                64
            )
            .is_err()
        );
        assert!(
            p.layout(
                &VmConfig {
                    gic: GicRequest {
                        redist_base: 0x0800_0000,
                        ..cfg.gic
                    },
                    ..cfg.clone()
                },
                64
            )
            .is_err()
        );
        assert!(p.layout(&VmConfig { cpus: 300, ..cfg }, 512).is_err());
    }
}
