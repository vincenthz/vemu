//! A guest software-stepping (MDSCR_EL1.SS) over an instruction the backend
//! emulates (MMIO access, sysreg trap, SMC, PSCI HVC) must take the step exception right
//! after that instruction, as on hardware: the backend has to clear PSTATE.SS
//! when it moves the PC past the instruction. It also clears PSTATE.BTYPE.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use std::time::Duration;

use common::{HVC_GUEST_EXCEPTION, Machine, check_guest_exception, start_at};
use vemu_hv::{Reg, Vcpu, VcpuExit};

std::arch::global_asm!(
    include_str!("guest/common.s"),
    include_str!("guest/singlestep.s")
);

/// MMIO window used by the guest programs (outside RAM and the GIC).
const MMIO: u64 = 0x0a00_0000;
/// MDSCR_EL1.KDE | MDSCR_EL1.SS: software step enabled at EL1.
const MDSCR_KDE_SS: u64 = (1 << 13) | 1;
/// ESR EC of a software step exception taken without a change of EL.
const EC_SOFTSTEP_CUR: u64 = 0x33;
/// HVC immediate of the guest's step-exception report.
const HVC_STEP: u16 = 0x55;
const PSTATE_SS: u64 = 1 << 21;
const PSTATE_BTYPE: u64 = 0b11 << 10;

/// How a stepped instruction leaves `run()` before the step exception.
#[derive(Clone, Copy, Debug)]
enum Emulated {
    /// Handled inside `run()` (or by hardware).
    None,
    MmioWrite,
    MmioRead,
    Hvc,
}

#[test]
fn software_step_over_emulated_instructions() {
    common::watchdog(Duration::from_secs(30));
    let m = Machine::new(1);
    let mut v = m.vcpu(0);
    let cases = [
        ("nop", m.gpa(label!(t_ss_nop)), Emulated::None, 1),
        (
            "mmio store",
            m.gpa(label!(t_ss_store)),
            Emulated::MmioWrite,
            2,
        ),
        ("mmio load", m.gpa(label!(t_ss_load)), Emulated::MmioRead, 3),
        ("msr oslar_el1", m.gpa(label!(t_ss_msr)), Emulated::None, 4),
        ("mrs oslsr_el1", m.gpa(label!(t_ss_mrs)), Emulated::None, 5),
        ("smc", m.gpa(label!(t_ss_smc)), Emulated::None, 6),
        ("hvc #0 (psci)", m.gpa(label!(t_ss_psci)), Emulated::None, 9),
        ("hvc", m.gpa(label!(t_ss_hvc)), Emulated::Hvc, 7),
    ];
    for (name, target, how, done_imm) in cases {
        // Stepping on: exactly the instruction at `target` runs.
        enter(&m, &mut *v, target, MDSCR_KDE_SS);
        expect_emulated(&mut *v, how, target, name);
        let exit = v.run().unwrap();
        check_guest_exception(&*v, exit);
        assert_eq!(exit, VcpuExit::Hvc { imm: HVC_STEP }, "{name}: step exit");
        let esr = v.get_reg(Reg::X(1)).unwrap();
        let elr = v.get_reg(Reg::X(2)).unwrap();
        assert_eq!(esr >> 26, EC_SOFTSTEP_CUR, "{name}: ESR_EL1 = {esr:#x}");
        assert_eq!(
            elr as i64 - target as i64,
            4,
            "{name}: step exception after one instruction"
        );
        assert_eq!(
            v.get_reg(Reg::X(7)).unwrap(),
            0,
            "{name}: the next instruction ran"
        );
        if matches!(how, Emulated::MmioRead) {
            assert_eq!(v.get_reg(Reg::X(6)).unwrap(), 0x42, "{name}: loaded value");
        }
        if name.starts_with("mrs") {
            assert_eq!(v.get_reg(Reg::X(6)).unwrap(), 0b1000, "{name}: OSLSR_EL1");
        }

        // Stepping off: the same code runs through to its HVC.
        enter(&m, &mut *v, target, 0);
        expect_emulated(&mut *v, how, target, name);
        let exit = v.run().unwrap();
        check_guest_exception(&*v, exit);
        assert_eq!(exit, VcpuExit::Hvc { imm: done_imm }, "{name}: unstepped");
        assert_eq!(v.get_reg(Reg::X(7)).unwrap(), 1, "{name}: unstepped");
    }

    // BLR onto an MMIO store: the CPU traps with PSTATE.BTYPE set for the
    // branch target; once the store is emulated, BTYPE is cleared.
    start_at(&mut *v, m.gpa(label!(t_bt_call)));
    v.set_reg(Reg::X(5), m.gpa(label!(t_bt_store))).unwrap();
    v.set_reg(Reg::X(7), 0).unwrap();
    let exit = v.run().unwrap();
    check_guest_exception(&*v, exit);
    assert!(
        matches!(exit, VcpuExit::MmioWrite { addr: MMIO, .. }),
        "{exit:?}"
    );
    let cpsr = v.get_reg(Reg::Cpsr).unwrap();
    assert_eq!(cpsr & PSTATE_BTYPE, 0, "BTYPE after the store: {cpsr:#x}");
    assert_eq!(v.get_reg(Reg::Pc).unwrap(), m.gpa(label!(t_bt_store)) + 4);
    let exit = v.run().unwrap();
    check_guest_exception(&*v, exit);
    assert_eq!(exit, VcpuExit::Hvc { imm: 8 });
    assert_eq!(v.get_reg(Reg::X(7)).unwrap(), 1);
}

/// Start `_t_ss_setup`, which ERETs to `target` with SPSR.SS set and
/// MDSCR_EL1 = `mdscr`.
fn enter(m: &Machine, v: &mut dyn Vcpu, target: u64, mdscr: u64) {
    start_at(v, m.gpa(label!(t_ss_setup)));
    v.set_reg(Reg::X(0), target).unwrap();
    v.set_reg(Reg::X(4), mdscr).unwrap();
    v.set_reg(Reg::X(19), MMIO).unwrap();
    v.set_reg(Reg::X(1), 0).unwrap();
    v.set_reg(Reg::X(6), 0).unwrap();
    v.set_reg(Reg::X(7), 0).unwrap();
}

/// Run to the exit of the instruction at `target` (if it leaves `run()`) and
/// check the backend left PSTATE.SS clear with the PC past the instruction.
fn expect_emulated(v: &mut dyn Vcpu, how: Emulated, target: u64, name: &str) {
    let want = match how {
        Emulated::None => return,
        Emulated::MmioWrite => VcpuExit::MmioWrite {
            addr: MMIO,
            len: 8,
            data: 0,
        },
        Emulated::MmioRead => VcpuExit::MmioRead { addr: MMIO, len: 8 },
        Emulated::Hvc => VcpuExit::Hvc { imm: 0x77 },
    };
    let exit = v.run().unwrap();
    assert_ne!(
        exit,
        VcpuExit::Hvc {
            imm: HVC_GUEST_EXCEPTION
        },
        "{name}: guest exception ESR={:#x}",
        v.get_reg(Reg::X(1)).unwrap()
    );
    assert_eq!(exit, want, "{name}");
    assert_eq!(v.get_reg(Reg::Pc).unwrap(), target + 4, "{name}: PC");
    if !matches!(how, Emulated::Hvc) {
        let cpsr = v.get_reg(Reg::Cpsr).unwrap();
        assert_eq!(cpsr & PSTATE_SS, 0, "{name}: PSTATE.SS = {cpsr:#x}");
    }
    if matches!(how, Emulated::MmioRead) {
        v.complete_mmio_read(0x42).unwrap();
    }
}
