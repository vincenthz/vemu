//! Kicks (from WFI and sticky), the virtual timer and SPIs through the
//! in-kernel GIC, on one vCPU of a real HVF VM.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::{Machine, expect_hvc, start_at};
use vemu_hv::{Reg, Vcpu, VcpuExit, Vm};

std::arch::global_asm!(include_str!("guest/common.s"), include_str!("guest/irq.s"));

/// Kick vCPU `index` of `vm` from another thread after `delay`.
fn kick_after(vm: &Arc<dyn Vm>, index: usize, delay: Duration) -> thread::JoinHandle<Instant> {
    let vm = vm.clone();
    thread::spawn(move || {
        thread::sleep(delay);
        vm.kick(index);
        Instant::now()
    })
}

#[test]
fn kick_vtimer_spi() {
    common::watchdog(Duration::from_secs(60));
    let m = Machine::new(1);
    let mut v = m.vcpu(0);
    kick_from_wfi(&m, &mut *v);
    sticky_kick(&m, &mut *v);
    vtimer(&m, &mut *v);
    spi(&m, &mut *v);
    assert!(m.vm.set_irq_line(31, true).is_err(), "PPI is not an SPI");
    let g = m.vm.arch_info().gic;
    assert!(
        m.vm.set_irq_line(g.spi_base + g.spi_count, true).is_err(),
        "past the last SPI"
    );
}

fn kick_from_wfi(m: &Machine, v: &mut dyn Vcpu) {
    start_at(v, m.gpa(label!(t_wfi_masked)));
    let t0 = Instant::now();
    let kicker = kick_after(&m.vm, 0, Duration::from_millis(100));
    assert_eq!(v.run().unwrap(), VcpuExit::Kicked);
    let woke = Instant::now();
    let kicked_at = kicker.join().unwrap();
    assert!(
        woke - t0 >= Duration::from_millis(100),
        "returned before the kick"
    );
    let latency = woke.saturating_duration_since(kicked_at);
    eprintln!("kick from WFI: run() returned {latency:?} after kick()");
    assert!(
        latency < Duration::from_millis(20),
        "kick latency {latency:?}"
    );
    // The kick terminated the WFI: resuming continues after it.
    expect_hvc(v, 1);
}

fn sticky_kick(m: &Machine, v: &mut dyn Vcpu) {
    // A kick while the vCPU is outside run() is reported by the next run(),
    // before entering the guest (which would spin forever).
    start_at(v, m.gpa(label!(t_spin)));
    m.vm.kick(0);
    m.vm.kick(0); // several pending kicks collapse into one
    let t0 = Instant::now();
    assert_eq!(v.run().unwrap(), VcpuExit::Kicked);
    assert!(t0.elapsed() < Duration::from_millis(20));

    // The framework still holds the cancel from those kicks; it must not
    // surface as a second Kicked. Only the later kick ends this run.
    let t0 = Instant::now();
    let kicker = kick_after(&m.vm, 0, Duration::from_millis(150));
    assert_eq!(v.run().unwrap(), VcpuExit::Kicked);
    kicker.join().unwrap();
    assert!(
        t0.elapsed() >= Duration::from_millis(150),
        "spurious Kicked after {:?}",
        t0.elapsed()
    );

    // And after a consumed kick, an ordinary exit comes through unchanged.
    m.vm.kick(0);
    assert_eq!(v.run().unwrap(), VcpuExit::Kicked);
    start_at(v, m.gpa(label!(t_hvc2)));
    expect_hvc(v, 2);
}

fn vtimer(m: &Machine, v: &mut dyn Vcpu) {
    m.clear_irq_record(0);
    start_at(v, m.gpa(label!(t_vtimer)));
    let t0 = Instant::now();
    // No exit reaches the VMM until the guest's handler took PPI 27.
    let intid = expect_hvc(v, 3);
    let elapsed = t0.elapsed();
    let ticks = v.get_reg(Reg::X(2)).unwrap();
    eprintln!("vtimer: IRQ {intid} after {elapsed:?} ({ticks} guest ticks)");
    assert_eq!(intid, 27, "virtual timer PPI");
    assert_eq!(m.irq_record(0).1, 1, "exactly one timer interrupt");
    assert!(ticks >= 240_000, "fired early: {ticks} ticks");
    assert!(elapsed >= Duration::from_millis(10) && elapsed < Duration::from_millis(500));
}

fn spi(m: &Machine, v: &mut dyn Vcpu) {
    m.clear_irq_record(0);
    start_at(v, m.gpa(label!(t_spi)));
    expect_hvc(v, 4);
    // The guest is (or will shortly be) in WFI; raise the line from another
    // thread while the vCPU is inside run().
    let vm = m.vm.clone();
    let raiser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        vm.set_irq_line(48, true).unwrap();
        Instant::now()
    });
    let intid = expect_hvc(v, 5);
    let woke = Instant::now();
    let raised_at = raiser.join().unwrap();
    m.vm.set_irq_line(48, false).unwrap();
    let latency = woke.saturating_duration_since(raised_at);
    eprintln!("SPI 48: delivered, run() returned {latency:?} after set_irq_line()");
    assert_eq!(intid, 48);
    assert_eq!(m.irq_record(0).1, 1);
    assert!(
        latency < Duration::from_millis(20),
        "SPI wake-up latency {latency:?}"
    );
}
