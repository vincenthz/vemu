//! PSCI emulated by the HVF backend: CPU_ON of a powered-off secondary (whose
//! `run()` blocks until then), the reset it implies, AFFINITY_INFO, CPU_OFF
//! and CPU hotplug, kicks of a powered-off vCPU, SYSTEM_OFF/SYSTEM_RESET as
//! `SystemEvent` exits.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use std::sync::{Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use common::{Machine, check_guest_exception, expect_hvc, start_at};
use vemu_hv::aarch64::psci;
use vemu_hv::{Reg, SystemEvent, Vcpu, VcpuExit};

std::arch::global_asm!(include_str!("guest/common.s"), include_str!("guest/psci.s"));

/// What vCPU 1 reported when it started.
#[derive(Debug)]
struct Started {
    context: u64,
    sctlr: u64,
    daif: u64,
}

/// Make the call in `x` on vCPU 0 (sitting in `_t_psci_call`); its result.
fn call(v: &mut dyn Vcpu, x: [u64; 4]) -> i64 {
    for (r, val) in x.into_iter().enumerate() {
        v.set_reg(Reg::X(r as u8), val).unwrap();
    }
    expect_hvc(v, 1) as i64
}

fn affinity(v: &mut dyn Vcpu, cpu: u64) -> i64 {
    call(v, [psci::AFFINITY_INFO_64 as u64, cpu, 0, 0])
}

/// Poll AFFINITY_INFO until vCPU `cpu` is off.
fn wait_off(v: &mut dyn Vcpu, cpu: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while affinity(v, cpu) != psci::AFFINITY_OFF {
        assert!(Instant::now() < deadline, "vCPU {cpu} never powered off");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn cpu_on_off_affinity_system_events() {
    common::watchdog(Duration::from_secs(60));
    let m = Machine::new(2);
    let created = Barrier::new(2);
    let (tx, rx) = mpsc::channel();

    thread::scope(|s| {
        let secondary = s.spawn(|| {
            let mut v = m.vcpu(1);
            created.wait();
            // Powered off: each run() blocks until CPU_ON, then the guest
            // reports and powers itself off again.
            for _ in 0..2 {
                let exit = v.run().unwrap();
                check_guest_exception(&*v, exit);
                assert_eq!(exit, VcpuExit::Hvc { imm: 2 });
                let x = |r| v.get_reg(Reg::X(r)).unwrap();
                tx.send(Started {
                    context: x(1),
                    sctlr: x(2),
                    daif: x(3),
                })
                .unwrap();
            }
            // Off again: only a kick ends this run().
            assert_eq!(v.run().unwrap(), VcpuExit::Kicked);
        });

        let mut v = m.vcpu(0);
        created.wait();
        start_at(&mut *v, m.gpa(label!(t_psci_call)));
        let v = &mut *v;
        let entry = m.gpa(label!(t_psci_sec));
        assert_eq!(call(v, [psci::PSCI_VERSION as u64, 0, 0, 0]), 0x1_0000);
        assert_eq!(affinity(v, 0), psci::AFFINITY_ON);
        assert_eq!(affinity(v, 1), psci::AFFINITY_OFF);
        let cpu_on = |v: &mut dyn Vcpu, target: u64, entry: u64, ctx: u64| {
            call(v, [psci::CPU_ON_64 as u64, target, entry, ctx])
        };
        assert_eq!(cpu_on(v, 1, 0x1000, 0), psci::INVALID_ADDRESS, "not RAM");
        assert_eq!(cpu_on(v, 2, entry, 0), psci::INVALID_PARAMETERS);
        assert_eq!(cpu_on(v, 0, entry, 0), psci::ALREADY_ON);
        thread::sleep(Duration::from_millis(50));
        assert!(rx.try_recv().is_err(), "vCPU 1 ran before CPU_ON");

        for context in [0x1234, 0x5678] {
            assert_eq!(cpu_on(v, 1, entry, context), psci::SUCCESS);
            let st = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("vCPU 1 did not start");
            eprintln!("vCPU 1 started: {st:x?}");
            assert_eq!(st.context, context, "X0 = context");
            // Fresh from reset each time, although the first run turned the
            // caches on and unmasked interrupts before CPU_OFF.
            assert_eq!(st.sctlr & 0x1005, 0, "MMU/caches off: {:#x}", st.sctlr);
            assert_eq!(st.daif, 0x3c0, "DAIF masked");
            wait_off(v, 1);
        }
        m.vm.kick(1);
        secondary.join().unwrap();

        // SYSTEM_OFF and SYSTEM_RESET leave run() as system events.
        v.set_reg(Reg::X(0), psci::SYSTEM_OFF as u64).unwrap();
        assert_eq!(
            v.run().unwrap(),
            VcpuExit::SystemEvent(SystemEvent::Shutdown)
        );
        start_at(v, m.gpa(label!(t_psci_call)));
        v.set_reg(Reg::X(0), psci::SYSTEM_RESET as u64).unwrap();
        assert_eq!(v.run().unwrap(), VcpuExit::SystemEvent(SystemEvent::Reset));
    });
}
