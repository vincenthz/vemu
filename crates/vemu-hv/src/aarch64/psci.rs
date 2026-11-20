//! PSCI 1.0 firmware over HVC (Arm DEN 0022), plus the SMCCC discovery calls
//! (Arm DEN 0028), for backends without in-kernel PSCI (HVF; KVM implements
//! PSCI itself).
//!
//! Implemented: PSCI_VERSION, CPU_ON, CPU_OFF, AFFINITY_INFO,
//! MIGRATE_INFO_TYPE (2: no trusted OS needing migration), SYSTEM_OFF,
//! SYSTEM_RESET and PSCI_FEATURES. Everything else, including CPU_SUSPEND,
//! MIGRATE and SMCCC_VERSION, returns NOT_SUPPORTED: with SMCCC_VERSION
//! unsupported a guest assumes SMCCC 1.0 and makes no further SMCCC
//! discovery calls (ARCH_FEATURES, TRNG, vendor hypervisor services).
//!
//! Results are returned in X0 sign-extended to 64 bits, like QEMU, for both
//! the SMC32 and SMC64 calling conventions.
//!
//! [`PowerTable`] holds the PSCI view of every vCPU. The backend's `run()`
//! of a vCPU that is not [`PowerState::On`] blocks in
//! [`PowerTable::wait_for_power_on`] until `CPU_ON` (or a kick), then resets
//! the vCPU to the entry state and runs it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

pub const PSCI_VERSION: u32 = 0x8400_0000;
pub const CPU_SUSPEND_32: u32 = 0x8400_0001;
pub const CPU_SUSPEND_64: u32 = 0xc400_0001;
pub const CPU_OFF: u32 = 0x8400_0002;
pub const CPU_ON_32: u32 = 0x8400_0003;
pub const CPU_ON_64: u32 = 0xc400_0003;
pub const AFFINITY_INFO_32: u32 = 0x8400_0004;
pub const AFFINITY_INFO_64: u32 = 0xc400_0004;
pub const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
pub const SYSTEM_OFF: u32 = 0x8400_0008;
pub const SYSTEM_RESET: u32 = 0x8400_0009;
pub const PSCI_FEATURES: u32 = 0x8400_000a;
pub const SMCCC_VERSION: u32 = 0x8000_0000;

/// PSCI 1.0: major 1 in bits 31:16, minor 0.
const VERSION_1_0: i64 = 0x1_0000;

pub const SUCCESS: i64 = 0;
pub const NOT_SUPPORTED: i64 = -1;
pub const INVALID_PARAMETERS: i64 = -2;
pub const ALREADY_ON: i64 = -4;
pub const ON_PENDING: i64 = -5;
pub const INVALID_ADDRESS: i64 = -9;

/// AFFINITY_INFO results.
pub const AFFINITY_ON: i64 = 0;
pub const AFFINITY_OFF: i64 = 1;
pub const AFFINITY_ON_PENDING: i64 = 2;

/// MIGRATE_INFO_TYPE: "Trusted OS is either not present or does not require
/// migration".
const MIGRATE_TYPE_NONE: i64 = 2;

/// MPIDR affinity fields (Aff3 39:32, Aff2 23:16, Aff1 15:8, Aff0 7:0).
/// vCPU `i` has Aff0 = `i`, the other fields 0.
const MPIDR_AFFINITY_MASK: u64 = 0xff_00ff_ffff;

/// What the backend must do after a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Write this value to X0 and resume the guest.
    Return(i64),
    /// CPU_OFF succeeded (the caller is already marked off): stop running
    /// this vCPU until the next CPU_ON.
    CpuOff,
    SystemOff,
    SystemReset,
}

/// PSCI view of one vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Off,
    /// `CPU_ON` accepted; the vCPU's `run()` has not picked it up yet.
    OnPending {
        entry: u64,
        context: u64,
    },
    On,
}

/// Why `CPU_ON` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuOnError {
    AlreadyOn,
    OnPending,
}

/// Power states of all vCPUs of a VM, shared between their threads.
///
/// vCPU 0 (the boot CPU) starts [`PowerState::On`], the others
/// [`PowerState::Off`], as on a machine whose firmware releases only the boot
/// CPU.
pub struct PowerTable {
    cpus: Mutex<Vec<PowerState>>,
    cond: Condvar,
}

impl PowerTable {
    pub fn new(cpus: usize) -> PowerTable {
        PowerTable {
            cpus: Mutex::new(
                (0..cpus)
                    .map(|i| {
                        if i == 0 {
                            PowerState::On
                        } else {
                            PowerState::Off
                        }
                    })
                    .collect(),
            ),
            cond: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Vec<PowerState>> {
        self.cpus.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn cpus(&self) -> usize {
        self.lock().len()
    }

    /// The state of vCPU `index`.
    ///
    /// # Panics
    /// If `index` is out of range.
    pub fn state(&self, index: usize) -> PowerState {
        self.lock()[index]
    }

    /// Ask vCPU `target` to start at `entry` with X0 = `context`.
    ///
    /// # Panics
    /// If `target` is out of range (callers validate guest input first).
    pub fn cpu_on(&self, target: usize, entry: u64, context: u64) -> Result<(), CpuOnError> {
        let mut s = self.lock();
        match s[target] {
            PowerState::On => Err(CpuOnError::AlreadyOn),
            PowerState::OnPending { .. } => Err(CpuOnError::OnPending),
            PowerState::Off => {
                s[target] = PowerState::OnPending { entry, context };
                self.cond.notify_all();
                Ok(())
            }
        }
    }

    /// vCPU `index` powered itself off (PSCI `CPU_OFF`).
    pub fn cpu_off(&self, index: usize) {
        self.lock()[index] = PowerState::Off;
    }

    /// The VMM gave vCPU `index` its boot state: it is on, whatever it was.
    pub fn power_on(&self, index: usize) {
        self.lock()[index] = PowerState::On;
    }

    /// Block until vCPU `index` is asked to power on, then mark it on and
    /// return `Some((entry, context))`. Returns `None` as soon as `kick` is
    /// set (without clearing it), so that a kick ends the wait; whoever sets
    /// `kick` must then call [`PowerTable::wake`].
    pub fn wait_for_power_on(&self, index: usize, kick: &AtomicBool) -> Option<(u64, u64)> {
        let mut s = self.lock();
        loop {
            // Checked under the lock, which wake() takes after setting the
            // flag: a kick cannot slip between this check and the wait.
            if kick.load(Ordering::Acquire) {
                return None;
            }
            if let PowerState::OnPending { entry, context } = s[index] {
                s[index] = PowerState::On;
                return Some((entry, context));
            }
            s = self.cond.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Wake every vCPU blocked in [`PowerTable::wait_for_power_on`] so it
    /// re-checks its kick flag.
    pub fn wake(&self) {
        let _s = self.lock();
        self.cond.notify_all();
    }
}

/// Handle the SMCCC call in `x[0..4]` (X0 = function ID, X1..X3 =
/// arguments) made by vCPU `caller`. `is_ram(gpa, len)` tells whether a
/// `CPU_ON` entry point lies in guest RAM.
pub fn dispatch(
    x: [u64; 4],
    caller: usize,
    power: &PowerTable,
    is_ram: impl Fn(u64, u64) -> bool,
) -> Outcome {
    let fid = x[0] as u32;
    // SMC32 calls (bit 30 clear) take 32-bit arguments in W1..W3.
    let arg = |i: usize| {
        if fid & (1 << 30) == 0 {
            x[i] & 0xffff_ffff
        } else {
            x[i]
        }
    };
    let ret = match fid {
        PSCI_VERSION => VERSION_1_0,
        CPU_OFF => {
            power.cpu_off(caller);
            return Outcome::CpuOff;
        }
        CPU_ON_32 | CPU_ON_64 => cpu_on(power, &is_ram, arg(1), arg(2), arg(3)),
        AFFINITY_INFO_32 | AFFINITY_INFO_64 => affinity_info(power, arg(1), arg(2)),
        MIGRATE_INFO_TYPE => MIGRATE_TYPE_NONE,
        SYSTEM_OFF => return Outcome::SystemOff,
        SYSTEM_RESET => return Outcome::SystemReset,
        PSCI_FEATURES => features(arg(1) as u32),
        _ => NOT_SUPPORTED,
    };
    Outcome::Return(ret)
}

fn cpu_index(power: &PowerTable, mpidr: u64) -> Option<usize> {
    let aff = mpidr & MPIDR_AFFINITY_MASK;
    (aff < power.cpus() as u64).then_some(aff as usize)
}

fn cpu_on(
    power: &PowerTable,
    is_ram: &impl Fn(u64, u64) -> bool,
    target: u64,
    entry: u64,
    context: u64,
) -> i64 {
    let Some(target) = cpu_index(power, target) else {
        return INVALID_PARAMETERS;
    };
    if !entry.is_multiple_of(4) || !is_ram(entry, 4) {
        return INVALID_ADDRESS;
    }
    match power.cpu_on(target, entry, context) {
        Ok(()) => SUCCESS,
        Err(CpuOnError::AlreadyOn) => ALREADY_ON,
        Err(CpuOnError::OnPending) => ON_PENDING,
    }
}

fn affinity_info(power: &PowerTable, target: u64, lowest_level: u64) -> i64 {
    // Only affinity level 0 (individual CPUs) is described.
    if lowest_level != 0 {
        return INVALID_PARAMETERS;
    }
    match cpu_index(power, target).map(|i| power.state(i)) {
        None => INVALID_PARAMETERS,
        Some(PowerState::On) => AFFINITY_ON,
        Some(PowerState::Off) => AFFINITY_OFF,
        Some(PowerState::OnPending { .. }) => AFFINITY_ON_PENDING,
    }
}

fn features(fid: u32) -> i64 {
    match fid {
        PSCI_VERSION | CPU_OFF | CPU_ON_32 | CPU_ON_64 | AFFINITY_INFO_32 | AFFINITY_INFO_64
        | MIGRATE_INFO_TYPE | SYSTEM_OFF | SYSTEM_RESET | PSCI_FEATURES => SUCCESS,
        // Not offered: Linux then neither idles through PSCI nor probes
        // SMCCC 1.1 services.
        CPU_SUSPEND_32 | CPU_SUSPEND_64 | SMCCC_VERSION => NOT_SUPPORTED,
        _ => NOT_SUPPORTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    const RAM: (u64, u64) = (0x4000_0000, 1 << 20);

    fn is_ram(gpa: u64, len: u64) -> bool {
        gpa >= RAM.0 && gpa + len <= RAM.0 + RAM.1
    }

    fn call(p: &PowerTable, x: [u64; 4]) -> Outcome {
        dispatch(x, 0, p, is_ram)
    }

    /// Take a pending CPU_ON for `index` (never kicked).
    fn take(p: &PowerTable, index: usize) -> Option<(u64, u64)> {
        p.wait_for_power_on(index, &AtomicBool::new(false))
    }

    #[test]
    fn version_and_features() {
        let p = PowerTable::new(2);
        assert_eq!(
            call(&p, [PSCI_VERSION as u64, 0, 0, 0]),
            Outcome::Return(0x1_0000)
        );
        let feat = |f: u32| call(&p, [PSCI_FEATURES as u64, f as u64, 0, 0]);
        assert_eq!(feat(CPU_ON_64), Outcome::Return(SUCCESS));
        assert_eq!(feat(SYSTEM_OFF), Outcome::Return(SUCCESS));
        assert_eq!(feat(CPU_SUSPEND_64), Outcome::Return(NOT_SUPPORTED));
        assert_eq!(feat(CPU_SUSPEND_32), Outcome::Return(NOT_SUPPORTED));
        assert_eq!(feat(SMCCC_VERSION), Outcome::Return(NOT_SUPPORTED));
        assert_eq!(
            call(&p, [SMCCC_VERSION as u64, 0, 0, 0]),
            Outcome::Return(NOT_SUPPORTED)
        );
        assert_eq!(
            call(&p, [0xdead_beef, 0, 0, 0]),
            Outcome::Return(NOT_SUPPORTED)
        );
        assert_eq!(
            call(&p, [MIGRATE_INFO_TYPE as u64, 0, 0, 0]),
            Outcome::Return(2)
        );
        // The upper half of X0 is ignored (SMCCC: function ID is W0).
        assert_eq!(
            call(&p, [0xffff_ffff_0000_0000 | PSCI_VERSION as u64, 0, 0, 0]),
            Outcome::Return(0x1_0000)
        );
    }

    #[test]
    fn boot_cpu_starts_on() {
        let p = PowerTable::new(3);
        assert_eq!(p.state(0), PowerState::On);
        assert_eq!(p.state(1), PowerState::Off);
        assert_eq!(p.state(2), PowerState::Off);
        p.power_on(2);
        assert_eq!(p.state(2), PowerState::On);
    }

    #[test]
    fn cpu_on_and_affinity() {
        let p = PowerTable::new(2);
        let on = |t: u64, e: u64| call(&p, [CPU_ON_64 as u64, t, e, 0x55]);
        let aff = |t: u64, l: u64| call(&p, [AFFINITY_INFO_64 as u64, t, l, 0]);
        assert_eq!(aff(0, 0), Outcome::Return(AFFINITY_ON));
        assert_eq!(aff(1, 0), Outcome::Return(AFFINITY_OFF));
        assert_eq!(on(2, 0x4000_0000), Outcome::Return(INVALID_PARAMETERS));
        assert_eq!(on(0x100, 0x4000_0000), Outcome::Return(INVALID_PARAMETERS));
        assert_eq!(on(1, 0x1000), Outcome::Return(INVALID_ADDRESS));
        assert_eq!(on(1, 0x4000_0002), Outcome::Return(INVALID_ADDRESS));
        assert_eq!(on(1, 0x4010_0000), Outcome::Return(INVALID_ADDRESS));
        assert_eq!(on(1, 0x4000_0800), Outcome::Return(SUCCESS));
        assert_eq!(aff(1, 0), Outcome::Return(AFFINITY_ON_PENDING));
        assert_eq!(on(1, 0x4000_0800), Outcome::Return(ON_PENDING));
        assert_eq!(take(&p, 1), Some((0x4000_0800, 0x55)));
        assert_eq!(aff(1, 0), Outcome::Return(AFFINITY_ON));
        assert_eq!(on(1, 0x4000_0800), Outcome::Return(ALREADY_ON));
        assert_eq!(aff(1, 1), Outcome::Return(INVALID_PARAMETERS));
        assert_eq!(aff(5, 0), Outcome::Return(INVALID_PARAMETERS));
        assert_eq!(
            dispatch([CPU_OFF as u64, 0, 0, 0], 1, &p, is_ram),
            Outcome::CpuOff
        );
        assert_eq!(aff(1, 0), Outcome::Return(AFFINITY_OFF));
        // CPU hotplug: an offlined CPU can be started again.
        assert_eq!(on(1, 0x4000_0800), Outcome::Return(SUCCESS));
    }

    #[test]
    fn smc32_arguments_are_truncated() {
        let p = PowerTable::new(2);
        let x = [
            CPU_ON_32 as u64,
            0xffff_ffff_0000_0001,
            0x1_4000_0100,
            0x1_0000_0002,
        ];
        assert_eq!(call(&p, x), Outcome::Return(SUCCESS));
        assert_eq!(take(&p, 1), Some((0x4000_0100, 2)));
    }

    #[test]
    fn system_calls() {
        let p = PowerTable::new(1);
        assert_eq!(call(&p, [SYSTEM_OFF as u64, 0, 0, 0]), Outcome::SystemOff);
        assert_eq!(
            call(&p, [SYSTEM_RESET as u64, 0, 0, 0]),
            Outcome::SystemReset
        );
    }

    #[test]
    fn power_on_off_cycle_across_threads() {
        let p = Arc::new(PowerTable::new(2));
        let waiter = {
            let p = p.clone();
            thread::spawn(move || take(&p, 1))
        };
        p.cpu_on(1, 0x4000_1000, 7).unwrap();
        assert_eq!(waiter.join().unwrap(), Some((0x4000_1000, 7)));
        assert_eq!(p.state(1), PowerState::On);
        assert_eq!(p.cpu_on(1, 0, 0), Err(CpuOnError::AlreadyOn));
        p.cpu_off(1);
        assert_eq!(p.state(1), PowerState::Off);
        // A vCPU that was powered off can be started again.
        let waiter = {
            let p = p.clone();
            thread::spawn(move || take(&p, 1))
        };
        p.cpu_on(1, 0x4000_2000, 8).unwrap();
        assert_eq!(waiter.join().unwrap(), Some((0x4000_2000, 8)));
    }

    #[test]
    fn kick_ends_the_wait() {
        let p = Arc::new(PowerTable::new(2));
        let kick = Arc::new(AtomicBool::new(false));
        let waiter = {
            let (p, kick) = (p.clone(), kick.clone());
            thread::spawn(move || p.wait_for_power_on(1, &kick))
        };
        thread::sleep(Duration::from_millis(20));
        kick.store(true, Ordering::Release);
        p.wake();
        assert_eq!(waiter.join().unwrap(), None);
        assert!(kick.load(Ordering::Acquire), "the flag is left for run()");
        assert_eq!(p.state(1), PowerState::Off);
        // Already kicked: returns at once, even with a CPU_ON pending.
        p.cpu_on(1, 0x4000_0000, 0).unwrap();
        assert_eq!(p.wait_for_power_on(1, &kick), None);
        kick.store(false, Ordering::Release);
        assert_eq!(p.wait_for_power_on(1, &kick), Some((0x4000_0000, 0)));
    }
}
