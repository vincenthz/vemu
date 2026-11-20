//! Two vCPUs: an SGI (IPI) sent by one wakes the other from WFI, and an SPI
//! routed to the second vCPU wakes it — all without the VMM's help, which is
//! what lets `run()` leave WFI to the in-kernel GIC.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use std::sync::{Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use common::{Machine, boot_at, check_guest_exception, expect_hvc, start_at};
use vemu_hv::{Reg, VcpuExit};

std::arch::global_asm!(include_str!("guest/common.s"), include_str!("guest/smp.s"));

/// What the waiter thread observed.
#[derive(Debug)]
enum Event {
    Ready { rd_base: u64 },
    Irq { intid: u64, at: Instant },
}

#[test]
fn sgi_and_routed_spi_wake_wfi() {
    common::watchdog(Duration::from_secs(60));
    let m = Machine::new(2);
    let created = Barrier::new(2);
    let (tx, rx) = mpsc::channel();

    thread::scope(|s| {
        let waiter = s.spawn(|| {
            let mut v = m.vcpu(1);
            created.wait();
            // A secondary: powered off until given a boot state.
            boot_at(&mut *v, m.gpa(label!(t_waiter)), 0);
            let rd_base = expect_hvc(&mut *v, 7);
            tx.send(Event::Ready { rd_base }).unwrap();
            // Two interrupts, then a kick to finish. Nothing else may surface:
            // the WFI waits are handled entirely inside run().
            for _ in 0..2 {
                let intid = expect_hvc(&mut *v, 8);
                tx.send(Event::Irq {
                    intid,
                    at: Instant::now(),
                })
                .unwrap();
            }
            let exit = v.run().unwrap();
            check_guest_exception(&*v, exit);
            assert_eq!(exit, VcpuExit::Kicked);
        });

        let mut v = m.vcpu(0);
        created.wait(); // both vCPUs exist before either runs
        start_at(&mut *v, m.gpa(label!(t_sender)));
        let rd0 = expect_hvc(&mut *v, 9);
        let Event::Ready { rd_base: rd1 } = rx.recv().unwrap() else {
            panic!("waiter not ready")
        };
        let g = m.vm.arch_info().gic;
        eprintln!("redistributors: vCPU0 at {rd0:#x}, vCPU1 at {rd1:#x}");
        assert_ne!(rd0, rd1);
        for rd in [rd0, rd1] {
            assert!(rd >= g.redist_base && rd < g.redist_base + g.redist_region_size);
            assert_eq!((rd - g.redist_base) % g.redist_stride, 0);
        }

        // Let vCPU 1 settle into WFI, then IPI it: SGI 5 to Aff0 = 1.
        thread::sleep(Duration::from_millis(100));
        v.set_reg(Reg::X(22), (5 << 24) | (1 << 1)).unwrap();
        let sent = Instant::now();
        expect_hvc(&mut *v, 10);
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("SGI not delivered")
        {
            Event::Irq { intid, at } => {
                let latency = at.saturating_duration_since(sent);
                eprintln!("SGI 5: vCPU1 woke {latency:?} after vCPU0 was resumed to send it");
                assert_eq!(intid, 5);
                assert!(
                    latency < Duration::from_millis(20),
                    "SGI wake-up latency {latency:?}"
                );
            }
            e => panic!("unexpected {e:?}"),
        }

        // SPI 49 routed to vCPU 1 (GICD_IROUTER), raised from this thread.
        expect_hvc(&mut *v, 11);
        thread::sleep(Duration::from_millis(100));
        let raised = Instant::now();
        m.vm.set_irq_line(49, true).unwrap();
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("SPI not delivered")
        {
            Event::Irq { intid, at } => {
                let latency = at.saturating_duration_since(raised);
                eprintln!("SPI 49: vCPU1 woke {latency:?} after set_irq_line()");
                assert_eq!(intid, 49);
                assert!(
                    latency < Duration::from_millis(20),
                    "SPI wake-up latency {latency:?}"
                );
            }
            e => panic!("unexpected {e:?}"),
        }
        m.vm.set_irq_line(49, false).unwrap();
        // vCPU 0 never took an interrupt.
        assert_eq!(m.irq_record(0).1, 0);

        m.vm.kick(1);
        waiter.join().unwrap();
    });
}
