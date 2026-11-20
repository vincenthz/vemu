//! MMIO decoding, HVC/SMC, emulated system registers, initial vCPU state and
//! VM lifecycle, against a real HVF VM.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use std::time::Duration;

use common::{Machine, RAM_BASE, boot_at, expect_hvc, start_at};
use vemu_hv::{ErrorKind, Reg, Vcpu, VcpuExit, VmConfig};

std::arch::global_asm!(include_str!("guest/common.s"), include_str!("guest/mmio.s"));

/// MMIO window used by the guest programs (outside RAM and the GIC).
const MMIO: u64 = 0x0a00_0000;
const GARBAGE: u64 = 0xdead_beef_dead_beef;

#[test]
fn mmio_hvc_smc_sysreg_state() {
    common::watchdog(Duration::from_secs(60));
    {
        let m = Machine::new(2);
        assert!(
            vemu_hv::create_vm(&VmConfig::default()).is_err(),
            "second VM in one process"
        );
        let mut v = m.vcpu(0);
        v.set_reg(Reg::X(19), MMIO).unwrap();

        stores(&m, &mut *v);
        loads(&m, &mut *v);
        hvc_smc(&m, &mut *v);
        sysregs(&m, &mut *v);
        initial_state(&m, &mut *v);
        reset(&m, &mut *v);
        undecodable(&m, &mut *v);
        api_misuse(&m, &mut *v);
    }
    // Everything dropped: the VM is destroyed and a new one (with its GIC) can
    // be created in the same process.
    let m = Machine::new(1);
    let mut v = m.vcpu(0);
    start_at(&mut *v, m.gpa(label!(t_hvc)));
    assert_eq!(
        expect_hvc(&mut *v, 0x11),
        0x1_0001,
        "PSCI works in the new VM"
    );
}

fn stores(m: &Machine, v: &mut dyn Vcpu) {
    start_at(v, m.gpa(label!(t_store)));
    let x = 0x1122_3344_5566_7788u64;
    // (addr, len, data, instructions since the previous store)
    let expected = [
        (MMIO, 8, x, 0),
        (MMIO + 0x8, 4, x & 0xffff_ffff, 1),
        (MMIO + 0x12, 2, x & 0xffff, 1),
        (MMIO + 0x1b, 1, x & 0xff, 1),
        (MMIO + 0x20, 8, 0, 1),
        (MMIO + 0x28, 4, 0, 1),
        (MMIO + 0x2e, 2, 0, 1),
        (MMIO + 0x2f, 1, 0, 1),
        (MMIO - 4, 4, x & 0xffff_ffff, 1),
        (MMIO + 0x30, 8, x, 2),
    ];
    for (i, &(addr, len, data, insns)) in expected.iter().enumerate() {
        let pc = v.get_reg(Reg::Pc).unwrap();
        let exit = v.run().unwrap();
        assert_eq!(exit, VcpuExit::MmioWrite { addr, len, data }, "store #{i}");
        if i > 0 {
            // The backend stepped over each store exactly once.
            assert_eq!(
                v.get_reg(Reg::Pc).unwrap(),
                pc + 4 * insns,
                "PC after store #{i}"
            );
        }
    }
    expect_hvc(v, 1);
}

fn loads(m: &Machine, v: &mut dyn Vcpu) {
    start_at(v, m.gpa(label!(t_load)));
    for r in [2, 3, 4, 5, 6, 7, 8, 13, 14, 15] {
        v.set_reg(Reg::X(r), GARBAGE).unwrap();
    }
    // (addr, len, device value, register, expected register value)
    let cases: [(u64, usize, u64, Option<u8>, u64); 11] = [
        (
            MMIO,
            8,
            0x8877_6655_4433_2211,
            Some(2),
            0x8877_6655_4433_2211,
        ),
        // W destination: upper half zeroed, extra device bits dropped
        (MMIO + 0x4, 4, 0xffff_ffff_8000_0001, Some(3), 0x8000_0001),
        (MMIO + 0x8, 1, 0x1ff, Some(4), 0xff),
        (MMIO + 0xa, 2, 0x8001, Some(5), 0x8001),
        (MMIO + 0xc, 1, 0x80, Some(6), 0xffff_ffff_ffff_ff80), // ldrsb x
        (MMIO + 0xd, 1, 0x80, Some(7), 0xffff_ff80),           // ldrsb w
        (MMIO + 0xe, 2, 0x8000, Some(8), 0xffff_ffff_ffff_8000), // ldrsh x
        (MMIO + 0x10, 2, 0x8000, Some(13), 0xffff_8000),       // ldrsh w
        (MMIO + 0x14, 4, 0x8000_0000, Some(14), 0xffff_ffff_8000_0000), // ldrsw
        (MMIO + 0x18, 8, 0x1234, None, 0),                     // ldr xzr
        (MMIO + 0x1f, 1, 0x7f, Some(15), 0x7f),
    ];
    for (i, &(addr, len, value, _, _)) in cases.iter().enumerate() {
        assert_eq!(
            v.run().unwrap(),
            VcpuExit::MmioRead { addr, len },
            "load #{i}"
        );
        v.complete_mmio_read(value).unwrap();
    }
    expect_hvc(v, 2);
    for (i, &(_, _, _, reg, want)) in cases.iter().enumerate() {
        if let Some(r) = reg {
            assert_eq!(v.get_reg(Reg::X(r)).unwrap(), want, "load #{i} into x{r}");
        }
    }
}

fn hvc_smc(m: &Machine, v: &mut dyn Vcpu) {
    // HVC #0 (PSCI_VERSION) is handled inside run(): the first exit is the
    // HVC #0x11 after it, with PSCI 1.0 + 1 in x1.
    start_at(v, m.gpa(label!(t_hvc)));
    assert_eq!(
        expect_hvc(v, 0x11),
        0x1_0001,
        "resumed right after the HVC #0 with its result in x0"
    );
    // After an HVC exit the PC is already past the HVC; a non-SMCCC HVC
    // answers NOT_SUPPORTED.
    assert_eq!(v.get_reg(Reg::Pc).unwrap(), m.gpa(label!(t_hvc_insn)) + 12);
    assert_eq!(v.get_reg(Reg::X(0)).unwrap(), u64::MAX, "NOT_SUPPORTED");

    // SMC: NOT_SUPPORTED (-1) in x0, no exit, resumed right after the SMC.
    start_at(v, m.gpa(label!(t_smc)));
    assert_eq!(expect_hvc(v, 0x12), 0, "x0 + 1 after the SMC");
    assert_eq!(
        v.get_reg(Reg::Pc).unwrap(),
        m.gpa(label!(t_smc_insn)) + 12,
        "PC past the SMC, the ADD and the HVC"
    );
}

fn sysregs(m: &Machine, v: &mut dyn Vcpu) {
    start_at(v, m.gpa(label!(t_sysreg)));
    // All accesses are handled inside run(): the next exit is the HVC.
    expect_hvc(v, 3);
    let x = |r| v.get_reg(Reg::X(r)).unwrap();
    assert_eq!(x(2), 0b1010, "OSLSR_EL1 with the OS lock set");
    assert_eq!(x(3), 0b1000, "OSLSR_EL1 after unlock");
    assert_eq!(x(4), 0, "OSDLR_EL1");
    assert_eq!(x(5), 0, "MDCCSR_EL0");
    assert_eq!(x(7), x(6), "MDCCINT_EL1 round trip");
    assert_eq!(x(8), 0, "unknown sysreg reads as zero");
}

fn initial_state(m: &Machine, v: &mut dyn Vcpu) {
    start_at(v, m.gpa(label!(t_state)));
    expect_hvc(v, 4);
    let x = |r| v.get_reg(Reg::X(r)).unwrap();
    assert_eq!(x(1), 0x8000_0000, "MPIDR_EL1 of vCPU 0");
    // MMU, caches and alignment checks off, little-endian; the RES1 bits we set
    // are kept (the CPU adds ITD/SED, RES1 without AArch32 EL0).
    assert_eq!(x(2) & 0x0200_100f, 0, "SCTLR_EL1 = {:#x}", x(2));
    assert_eq!(x(2) & 0x30d0_0800, 0x30d0_0800, "SCTLR_EL1 = {:#x}", x(2));
    assert_eq!(x(3) & 0xf, 1, "PARange = 36 bits (the VM's IPA size)");
    // The vtimer offset makes CNTVCT start near 0 at VM creation (24 MHz).
    assert!(x(4) < 24_000_000 * 30, "CNTVCT_EL0 = {:#x}", x(4));
    assert_eq!(x(5), 1 << 2, "CurrentEL = EL1");
    assert_eq!(
        (x(6) >> 24) & 0xf,
        1,
        "ID_AA64PFR0_EL1.GIC: system register interface"
    );
    assert_eq!(v.get_reg(Reg::Cpsr).unwrap() & 0xf, 0x5, "EL1h");
}

fn reset(m: &Machine, v: &mut dyn Vcpu) {
    // The guest turns the caches on and unmasks interrupts...
    start_at(v, m.gpa(label!(t_sctlr)));
    expect_hvc(v, 7);
    let sctlr = v.get_reg(Reg::X(1)).unwrap();
    assert_eq!(sctlr & 0x1004, 0x1004, "SCTLR_EL1 = {sctlr:#x}");
    assert_eq!(v.get_reg(Reg::Cpsr).unwrap() & 0x3c0, 0, "DAIF clear");
    // ...and is left with an MMIO load pending.
    start_at(v, m.gpa(label!(t_load)));
    assert!(matches!(v.run().unwrap(), VcpuExit::MmioRead { .. }));
    v.set_reg(Reg::Cpsr, 0x4).unwrap(); // EL1t, nothing masked
    for r in 1..=3 {
        v.set_reg(Reg::X(r), 0x1111 * r as u64).unwrap();
    }

    // set_boot_state() brings back the power-on state at the entry point
    // (dropping the pending load), and run() works again.
    let entry = m.gpa(label!(t_state));
    boot_at(v, entry, 0x4000_8000);
    assert_eq!(v.get_reg(Reg::Cpsr).unwrap(), 0x3c5, "EL1h, DAIF masked");
    assert_eq!(v.get_reg(Reg::Pc).unwrap(), entry);
    assert_eq!(v.get_reg(Reg::X(0)).unwrap(), 0x4000_8000, "X0 = DTB");
    for r in 1..=3 {
        assert_eq!(v.get_reg(Reg::X(r)).unwrap(), 0, "X{r}");
    }
    expect_hvc(v, 4);
    let x = |r| v.get_reg(Reg::X(r)).unwrap();
    assert_eq!(x(2) & 0x0200_100f, 0, "SCTLR_EL1 after reset = {:#x}", x(2));
    assert_eq!(x(1), 0x8000_0000, "MPIDR_EL1 kept");
}

fn undecodable(m: &Machine, v: &mut dyn Vcpu) {
    let pc = m.gpa(label!(t_ldp));
    start_at(v, pc);
    let e = v.run().unwrap_err();
    let f = *e
        .guest_fault()
        .unwrap_or_else(|| panic!("ldp: expected a guest fault, got {e}"));
    assert_eq!(f.esr >> 26, 0x24, "data abort: {e}");
    assert_eq!(f.esr & (1 << 24), 0, "ISV=0: {e}");
    assert_eq!((f.ipa, f.pc), (MMIO, pc), "{e}");
    assert!(e.to_string().contains("ESR="), "{e}");

    // Writeback addressing modes carry no syndrome on Apple silicon either
    // (measured): run() reports them instead of mis-emulating them.
    let pc = m.gpa(label!(t_writeback));
    start_at(v, pc);
    let e = v.run().unwrap_err();
    let f = e
        .guest_fault()
        .unwrap_or_else(|| panic!("str pre-index: expected a guest fault, got {e}"));
    assert_eq!(f.esr & (1 << 24), 0, "ISV=0: {e}");
    assert_eq!((f.ipa, f.pc), (MMIO + 8, pc), "{e}");

    // Instruction fetch outside RAM.
    start_at(v, 0x1000_0000);
    let e = v.run().unwrap_err();
    let f = e.guest_fault().expect("guest fault");
    assert_eq!((f.esr >> 26, f.pc), (0x20, 0x1000_0000), "{e}");
}

fn api_misuse(m: &Machine, v: &mut dyn Vcpu) {
    assert!(v.get_reg(Reg::X(31)).is_err());
    assert!(v.complete_mmio_read(0).is_err(), "no MmioRead pending");
    assert!(v.complete_io_in(0).is_err(), "no port I/O on aarch64");
    // run() refuses to continue while a load is incomplete.
    start_at(v, m.gpa(label!(t_load)));
    assert!(matches!(v.run().unwrap(), VcpuExit::MmioRead { .. }));
    assert!(matches!(v.run().unwrap_err().kind(), ErrorKind::Invalid(_)));
    v.complete_mmio_read(0).unwrap();

    assert!(m.vm.create_vcpu(0).is_err(), "index created twice");
    assert!(m.vm.create_vcpu(2).is_err(), "index out of range");
    // One vCPU per thread: index 1 fails here but stays available elsewhere.
    assert!(m.vm.create_vcpu(1).is_err(), "second vCPU on one thread");
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut v1 = m.vcpu(1);
            // A secondary starts powered off: run() waits for CPU_ON, but a
            // (sticky) kick still ends it.
            m.vm.kick(1);
            assert_eq!(v1.run().unwrap(), VcpuExit::Kicked);
            boot_at(&mut *v1, m.gpa(label!(t_state)), 0);
            expect_hvc(&mut *v1, 4);
            assert_eq!(
                v1.get_reg(Reg::X(1)).unwrap(),
                0x8000_0001,
                "MPIDR_EL1 of vCPU 1"
            );
        });
    });
    // Kicking a destroyed or never-created vCPU is a no-op.
    m.vm.kick(1);
    m.vm.kick(7);
    let _ = RAM_BASE;
}
