//! Emulation of the system registers that trap to userspace under HVF.
//!
//! With the in-kernel GIC and EL2 disabled, Hypervisor.framework handles the
//! timers, GIC CPU interface, ID registers and debug breakpoint/watchpoint
//! registers itself. What still reaches the VMM (measured on macOS 27, see
//! `docs/research/hvf.md`) is the OS lock / OS double lock, DBGPRCR_EL1, the
//! debug communications channel registers and LORegions. All of them are
//! emulated here as "debug features absent".

use crate::aarch64::esr::SysReg;

/// OSLAR_EL1: OS Lock Access Register (write-only).
const OSLAR_EL1: SysReg = SysReg::new(2, 0, 1, 0, 4);
/// OSLSR_EL1: OS Lock Status Register (read-only).
const OSLSR_EL1: SysReg = SysReg::new(2, 0, 1, 1, 4);
/// OSDLR_EL1: OS Double Lock Register.
const OSDLR_EL1: SysReg = SysReg::new(2, 0, 1, 3, 4);
/// DBGPRCR_EL1: Debug Power Control Register.
const DBGPRCR_EL1: SysReg = SysReg::new(2, 0, 1, 4, 4);
/// MDCCSR_EL0: Debug Comms Channel status.
const MDCCSR_EL0: SysReg = SysReg::new(2, 3, 0, 1, 0);
/// MDCCINT_EL1: Debug Comms Channel interrupt enable.
const MDCCINT_EL1: SysReg = SysReg::new(2, 0, 0, 2, 0);

/// What the vCPU loop must do for a trapped access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read: put this value in Rt. Write: nothing more to do.
    Done(u64),
    /// MDCCINT_EL1 is kept by the framework (HV_SYS_REG_MDCCINT_EL1): forward
    /// the access there.
    Mdccint,
    /// Not a register we know: read-as-zero / write-ignored. The caller logs it
    /// once.
    Unknown,
}

/// Per-vCPU state of the emulated registers.
#[derive(Debug, Default)]
pub struct SysRegs {
    /// OSLSR_EL1.OSLK, set/cleared by writes to OSLAR_EL1.
    os_lock: bool,
}

impl SysRegs {
    /// Emulate one trapped access. `val` is the written value (ignored for
    /// reads).
    pub fn access(&mut self, reg: SysReg, read: bool, val: u64) -> Action {
        match (reg, read) {
            (OSLAR_EL1, false) => {
                self.os_lock = val & 1 != 0;
                Action::Done(0)
            }
            // OSLM = 0b10 (OS lock implemented, bit 3), OSLK at bit 1.
            (OSLSR_EL1, true) => Action::Done(0b1000 | (u64::from(self.os_lock) << 1)),
            (OSDLR_EL1, _) | (DBGPRCR_EL1, _) | (MDCCSR_EL0, true) => Action::Done(0),
            (MDCCINT_EL1, _) => Action::Mdccint,
            _ => Action::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_lock() {
        let mut s = SysRegs::default();
        assert_eq!(s.access(OSLSR_EL1, true, 0), Action::Done(0b1000));
        assert_eq!(s.access(OSLAR_EL1, false, 1), Action::Done(0));
        assert_eq!(s.access(OSLSR_EL1, true, 0), Action::Done(0b1010));
        assert_eq!(s.access(OSLAR_EL1, false, 0), Action::Done(0));
        assert_eq!(s.access(OSLSR_EL1, true, 0), Action::Done(0b1000));
    }

    #[test]
    fn raz_wi() {
        let mut s = SysRegs::default();
        assert_eq!(s.access(OSDLR_EL1, true, 0), Action::Done(0));
        assert_eq!(s.access(OSDLR_EL1, false, 1), Action::Done(0));
        assert_eq!(s.access(MDCCSR_EL0, true, 0), Action::Done(0));
        assert_eq!(s.access(MDCCINT_EL1, false, 0), Action::Mdccint);
        // LORC_EL1: unknown to us.
        assert_eq!(
            s.access(SysReg::new(3, 0, 10, 4, 3), true, 0),
            Action::Unknown
        );
        // OSLAR_EL1 is write-only: a read is unknown.
        assert_eq!(s.access(OSLAR_EL1, true, 0), Action::Unknown);
    }
}
