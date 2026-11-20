//! Arm PL031 real-time clock (Arm DDI 0224), so an aarch64 guest knows the
//! wall-clock time from its first instruction (Linux `rtc-pl031`, then
//! `CONFIG_RTC_HCTOSYS` or `hwclock --hctosys`).
//!
//! The counter is the host's UTC time in whole seconds plus an offset that
//! a guest write to the load register (RTCLR, e.g. `hwclock --systohc`)
//! changes. The offset lives only as long as the VM: like QEMU's
//! `-rtc base=utc`, every boot starts at the host's time again.
//!
//! The match register raises the alarm interrupt when the counter reaches
//! it (`rtcwake`, `/sys/class/rtc/rtc0/wakealarm`). The deadline is served by
//! one sleeping thread, started on the first alarm and stopped when the
//! device is dropped; a guest that never sets an alarm never gets one.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vemu_core::{IrqLine, MmioDevice};

/// Data register: the current count (read-only).
const DR: u64 = 0x000;
/// Match register.
const MR: u64 = 0x004;
/// Load register: writing it sets the count.
const LR: u64 = 0x008;
/// Control register: bit 0 "RTC start", which reads 1 once started and
/// cannot be cleared (writes are ignored, as on QEMU's model).
const CR: u64 = 0x00c;
/// Interrupt mask set/clear.
const IMSC: u64 = 0x010;
/// Raw interrupt status.
const RIS: u64 = 0x014;
/// Masked interrupt status.
const MIS: u64 = 0x018;
/// Interrupt clear (write-only).
const ICR: u64 = 0x01c;
/// PeriphID0..3 then PCellID0..3, one byte per 32-bit register.
const ID_BASE: u64 = 0xfe0;
const ID: [u8; 8] = [0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

/// The only interrupt: the match (alarm) interrupt.
const INT_ALARM: u32 = 1;

/// Source of the host's wall-clock time, in nanoseconds since the Unix epoch.
/// A trait so the tests can drive time by hand.
pub trait WallClock: Send + Sync + 'static {
    fn now_ns(&self) -> u128;
}

/// The host's real UTC clock.
pub struct HostClock;

impl WallClock for HostClock {
    fn now_ns(&self) -> u128 {
        // A host clock before 1970 reads as the epoch.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    }
}

struct Regs {
    /// Count = (host seconds + offset) mod 2^32.
    offset: i64,
    /// Last value written to LR (reads return it, as the TRM says).
    lr: u32,
    mr: u32,
    imsc: u32,
    ris: u32,
    /// Interrupt line level last driven.
    level: bool,
    /// Host time (ns) at which the counter reaches MR, while one is pending.
    alarm_at: Option<u128>,
    /// The alarm thread must exit.
    shutdown: bool,
}

struct Shared {
    regs: Mutex<Regs>,
    wake: Condvar,
    irq: Arc<dyn IrqLine>,
    clock: Box<dyn WallClock>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Regs> {
        // The registers stay consistent at every unlock, so a panic while
        // locked leaves nothing half-done: ignore poisoning.
        self.regs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn host_secs(&self) -> i64 {
        (self.clock.now_ns() / 1_000_000_000) as i64
    }

    fn count(&self, r: &Regs) -> u32 {
        self.host_secs().wrapping_add(r.offset) as u32
    }

    fn update_irq(&self, r: &mut Regs) {
        let level = r.ris & r.imsc != 0;
        if level != r.level {
            r.level = level;
            self.irq.set_level(level);
        }
    }

    /// Recompute the alarm after MR or the count changed (QEMU's
    /// `pl031_set_alarm`): a match due now is raised at once, otherwise the
    /// alarm fires at the host second where the counter reaches MR.
    /// Returns whether the alarm thread has a new deadline to wait for.
    fn rearm(&self, r: &mut Regs) -> bool {
        let now_ns = self.clock.now_ns();
        let secs = (now_ns / 1_000_000_000) as i64;
        let ticks = r.mr.wrapping_sub(secs.wrapping_add(r.offset) as u32);
        if ticks == 0 {
            r.alarm_at = None;
            r.ris |= INT_ALARM;
            self.update_irq(r);
            false
        } else {
            // Up to 2^32 - 1 s (136 years) ahead: fits a u128 of ns easily.
            r.alarm_at = Some((secs as u128 + ticks as u128) * 1_000_000_000);
            true
        }
    }
}

/// The alarm thread: sleep until the pending deadline, then raise the
/// alarm. It never spins: with no alarm it waits on the condition variable.
fn alarm_thread(s: Arc<Shared>) {
    let mut r = s.lock();
    loop {
        if r.shutdown {
            return;
        }
        let Some(at) = r.alarm_at else {
            r = s.wake.wait(r).unwrap_or_else(|e| e.into_inner());
            continue;
        };
        let now = s.clock.now_ns();
        if now >= at {
            r.alarm_at = None;
            r.ris |= INT_ALARM;
            s.update_irq(&mut r);
            continue;
        }
        // Re-check at least once a minute, so a host clock change (NTP step,
        // sleep) is noticed before long.
        let wait = Duration::from_nanos((at - now).min(60_000_000_000) as u64);
        r = s
            .wake
            .wait_timeout(r, wait)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

pub struct Pl031 {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Pl031 {
    pub fn new(irq: Arc<dyn IrqLine>) -> Pl031 {
        Pl031::with_clock(irq, Box::new(HostClock))
    }

    pub fn with_clock(irq: Arc<dyn IrqLine>, clock: Box<dyn WallClock>) -> Pl031 {
        Pl031 {
            shared: Arc::new(Shared {
                regs: Mutex::new(Regs {
                    offset: 0,
                    lr: 0,
                    mr: 0,
                    imsc: 0,
                    ris: 0,
                    level: false,
                    alarm_at: None,
                    shutdown: false,
                }),
                wake: Condvar::new(),
                irq,
                clock,
            }),
            thread: None,
        }
    }

    /// Hand a new deadline to the alarm thread, starting it the first time.
    fn kick_alarm(&mut self) {
        if self.thread.is_none() {
            let s = self.shared.clone();
            match std::thread::Builder::new()
                .name("vemu-pl031".into())
                .spawn(move || alarm_thread(s))
            {
                Ok(t) => self.thread = Some(t),
                // No thread, no alarm interrupt: the clock itself still works.
                Err(e) => {
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!("vemu: pl031: cannot start the alarm thread: {e}\n"),
                    );
                }
            }
        }
        self.shared.wake.notify_all();
    }

    fn read_reg(&self, offset: u64) -> u32 {
        let r = self.shared.lock();
        match offset {
            DR => self.shared.count(&r),
            MR => r.mr,
            // The last value loaded (TRM; QEMU too), not the live count.
            LR => r.lr,
            CR => 1,
            IMSC => r.imsc,
            RIS => r.ris,
            MIS => r.ris & r.imsc,
            ID_BASE..0x1000 if offset.is_multiple_of(4) => {
                ID[((offset - ID_BASE) / 4) as usize].into()
            }
            _ => 0,
        }
    }

    fn write_reg(&mut self, offset: u64, v: u32) {
        let kick = {
            let s = &*self.shared;
            let mut r = s.lock();
            match offset {
                MR => {
                    r.mr = v;
                    s.rearm(&mut r)
                }
                LR => {
                    r.lr = v;
                    r.offset = i64::from(v) - s.host_secs();
                    s.rearm(&mut r)
                }
                IMSC => {
                    r.imsc = v & INT_ALARM;
                    s.update_irq(&mut r);
                    false
                }
                ICR => {
                    r.ris &= !(v & INT_ALARM);
                    s.update_irq(&mut r);
                    false
                }
                // DR, RIS and MIS are read-only; CR cannot stop the clock.
                _ => false,
            }
        };
        if kick {
            self.kick_alarm();
        }
    }
}

impl Drop for Pl031 {
    fn drop(&mut self) {
        self.shared.lock().shutdown = true;
        self.shared.wake.notify_all();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl MmioDevice for Pl031 {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // 32-bit registers; a narrower access reads the low bytes of the
        // register at the word-aligned offset.
        let v = self.read_reg(offset & !3).to_le_bytes();
        let n = data.len().min(4);
        data[..n].copy_from_slice(&v[..n]);
        data[n..].fill(0);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let mut v = [0u8; 4];
        let n = data.len().min(4);
        v[..n].copy_from_slice(&data[..n]);
        self.write_reg(offset & !3, u32::from_le_bytes(v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    #[derive(Default)]
    struct Line(Mutex<Vec<bool>>, Condvar);
    impl IrqLine for Line {
        fn set_level(&self, level: bool) {
            self.0.lock().unwrap().push(level);
            self.1.notify_all();
        }
    }
    impl Line {
        fn edges(&self) -> Vec<bool> {
            self.0.lock().unwrap().clone()
        }
        /// Wait (bounded) until `n` edges were seen.
        fn wait_edges(&self, n: usize, limit: Duration) -> Vec<bool> {
            let end = Instant::now() + limit;
            let mut g = self.0.lock().unwrap();
            while g.len() < n && Instant::now() < end {
                g = self.1.wait_timeout(g, Duration::from_millis(20)).unwrap().0;
            }
            g.clone()
        }
    }

    /// A clock the test sets by hand (ns since the epoch).
    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);
    impl WallClock for FakeClock {
        fn now_ns(&self) -> u128 {
            self.0.load(Ordering::SeqCst).into()
        }
    }
    impl FakeClock {
        fn set_secs(&self, s: f64) {
            self.0.store((s * 1e9) as u64, Ordering::SeqCst);
        }
    }

    fn rd(d: &mut Pl031, off: u64, len: usize) -> u64 {
        let mut b = [0u8; 8];
        d.read(off, &mut b[..len]);
        u64::from_le_bytes(b)
    }

    fn wr(d: &mut Pl031, off: u64, v: u32) {
        d.write(off, &v.to_le_bytes());
    }

    fn fake(start: f64) -> (Pl031, FakeClock, Arc<Line>) {
        let clock = FakeClock::default();
        clock.set_secs(start);
        let line = Arc::new(Line::default());
        (
            Pl031::with_clock(line.clone(), Box::new(clock.clone())),
            clock,
            line,
        )
    }

    #[test]
    fn counts_host_seconds_and_ids() {
        let (mut d, clock, _) = fake(1_700_000_000.9);
        assert_eq!(rd(&mut d, DR, 4), 1_700_000_000);
        clock.set_secs(1_700_000_001.0);
        assert_eq!(rd(&mut d, DR, 4), 1_700_000_001);
        assert_eq!(rd(&mut d, CR, 4), 1);
        wr(&mut d, CR, 0); // cannot stop the clock
        assert_eq!(rd(&mut d, CR, 4), 1);
        let ids: Vec<u64> = (0..8).map(|i| rd(&mut d, ID_BASE + 4 * i, 4)).collect();
        assert_eq!(ids, vec![0x31, 0x10, 0x14, 0, 0x0d, 0xf0, 0x05, 0xb1]);
        // Narrow reads give the low bytes of the register.
        assert_eq!(rd(&mut d, DR, 2), 1_700_000_001 & 0xffff);
        assert_eq!(rd(&mut d, DR + 1, 4), 1_700_000_001); // word-aligned
        assert_eq!(rd(&mut d, 0x020, 4), 0); // reserved
    }

    #[test]
    fn real_host_clock_is_close_to_system_time() {
        let line = Arc::new(Line::default());
        let mut d = Pl031::new(line);
        let host = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let dr = rd(&mut d, DR, 4);
        assert!(dr.abs_diff(host & 0xffff_ffff) <= 1, "{dr} vs {host}");
    }

    #[test]
    fn load_register_sets_the_count() {
        let (mut d, clock, _) = fake(1000.5);
        assert_eq!(rd(&mut d, LR, 4), 0);
        wr(&mut d, LR, 50);
        assert_eq!(rd(&mut d, DR, 4), 50);
        clock.set_secs(1003.0);
        assert_eq!(rd(&mut d, DR, 4), 53);
        assert_eq!(rd(&mut d, LR, 4), 50, "LR reads the value loaded");
        // Wraps at 2^32, like the 32-bit hardware counter.
        wr(&mut d, LR, u32::MAX);
        clock.set_secs(1005.0);
        assert_eq!(rd(&mut d, DR, 4), 1);
    }

    #[test]
    fn match_now_raises_at_once_and_follows_the_mask() {
        let (mut d, _, line) = fake(500.0);
        wr(&mut d, MR, 500);
        assert_eq!(rd(&mut d, RIS, 4), 1);
        assert_eq!(rd(&mut d, MIS, 4), 0);
        assert!(line.edges().is_empty(), "masked: no interrupt");
        wr(&mut d, IMSC, 0xffff_ffff);
        assert_eq!(rd(&mut d, IMSC, 4), 1);
        assert_eq!(rd(&mut d, MIS, 4), 1);
        wr(&mut d, ICR, 1);
        assert_eq!(rd(&mut d, RIS, 4), 0);
        assert_eq!(line.edges(), vec![true, false]);
        // Writes to read-only registers change nothing.
        wr(&mut d, RIS, 1);
        wr(&mut d, DR, 7);
        assert_eq!(rd(&mut d, RIS, 4), 0);
        assert_eq!(rd(&mut d, DR, 4), 500);
    }

    #[test]
    fn alarm_fires_when_the_counter_reaches_the_match() {
        let (mut d, clock, line) = fake(100.2);
        wr(&mut d, IMSC, 1);
        wr(&mut d, MR, 102);
        assert_eq!(rd(&mut d, RIS, 4), 0);
        // Not yet due: the thread re-checks and keeps waiting.
        clock.set_secs(101.9);
        d.shared.wake.notify_all();
        std::thread::sleep(Duration::from_millis(50));
        assert!(line.edges().is_empty());
        // Due: the thread notices on its next wake-up.
        clock.set_secs(102.0);
        d.shared.wake.notify_all();
        assert_eq!(line.wait_edges(1, Duration::from_secs(5)), vec![true]);
        assert_eq!(rd(&mut d, RIS, 4), 1);
        wr(&mut d, ICR, 1);
        assert_eq!(line.edges(), vec![true, false]);
    }

    #[test]
    fn moving_the_match_or_the_count_rearms() {
        let (mut d, clock, line) = fake(10.0);
        wr(&mut d, IMSC, 1);
        wr(&mut d, MR, 20);
        // Re-programmed further out before it fired: the old deadline is gone.
        wr(&mut d, MR, 1_000);
        clock.set_secs(25.0);
        d.shared.wake.notify_all();
        std::thread::sleep(Duration::from_millis(50));
        assert!(line.edges().is_empty());
        // Loading the counter to the match value raises it at once.
        wr(&mut d, LR, 1_000);
        assert_eq!(line.edges(), vec![true]);
        assert!(d.shared.lock().alarm_at.is_none());
    }

    #[test]
    fn real_alarm_one_second_ahead() {
        let line = Arc::new(Line::default());
        let mut d = Pl031::new(line.clone());
        wr(&mut d, IMSC, 1);
        let now = rd(&mut d, DR, 4) as u32;
        let t0 = Instant::now();
        wr(&mut d, MR, now.wrapping_add(1));
        assert_eq!(line.wait_edges(1, Duration::from_secs(5)), vec![true]);
        assert!(t0.elapsed() <= Duration::from_millis(1_500));
    }

    #[test]
    fn drop_stops_the_alarm_thread() {
        let (mut d, _, _) = fake(0.0);
        wr(&mut d, MR, 3_600);
        assert!(d.thread.is_some());
        let t0 = Instant::now();
        drop(d);
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn thread_starts_only_with_a_deadline() {
        // Reading the clock and masking interrupts never start it.
        let (mut d, _, _) = fake(0.0);
        wr(&mut d, IMSC, 1);
        wr(&mut d, ICR, 1);
        rd(&mut d, DR, 4);
        assert!(d.thread.is_none());
        // Loading the counter re-arms against MR (here 0, far ahead).
        wr(&mut d, LR, 5);
        assert!(d.thread.is_some());
    }
}
