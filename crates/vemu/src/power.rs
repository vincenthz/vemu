//! Machine shutdown, shared by all threads.
//!
//! Anyone may request the machine to stop ([`Control::request_exit`]): a
//! vCPU thread on a guest power-off/reset event or a VMM error, a device
//! (e.g. an ACPI sleep register), the console on Ctrl-A x. The first request
//! wins and wakes the main thread, which then kicks the vCPUs out of
//! `run()`. vCPU power states (PSCI) belong to the hypervisor backend.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

/// Why the machine stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// The guest powered off (PSCI SYSTEM_OFF, ACPI S5).
    PowerOff,
    /// The guest asked for a reset (vemu exits rather than rebooting).
    Reset,
    /// The user asked to quit (Ctrl-A x).
    Quit,
    /// A VMM error (vCPU failure, ...).
    Error(String),
    /// The machine ran longer than its timeout (`vemu build`).
    Timeout(std::time::Duration),
}

impl Exit {
    /// Process exit status for this outcome.
    pub fn status(&self) -> i32 {
        match self {
            Exit::PowerOff | Exit::Reset | Exit::Quit => 0,
            Exit::Error(_) | Exit::Timeout(_) => 1,
        }
    }
}

/// Shared shutdown state of the machine.
pub struct Control {
    exit: Mutex<Option<Exit>>,
    cond: Condvar,
    /// Mirrors `exit.is_some()` for cheap polling from the vCPU loop.
    exiting: AtomicBool,
}

impl Default for Control {
    fn default() -> Control {
        Control::new()
    }
}

impl Control {
    pub fn new() -> Control {
        Control {
            exit: Mutex::new(None),
            cond: Condvar::new(),
            exiting: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Exit>> {
        self.exit.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Request the machine to stop. The first request decides the outcome;
    /// later ones are ignored.
    pub fn request_exit(&self, exit: Exit) {
        let mut s = self.lock();
        if s.is_none() {
            *s = Some(exit);
            self.exiting.store(true, Ordering::Release);
            self.cond.notify_all();
        }
    }

    pub fn is_exiting(&self) -> bool {
        self.exiting.load(Ordering::Acquire)
    }

    /// Block until an exit is requested, or `timeout` passes (then the
    /// machine is stopped with [`Exit::Timeout`]), and return the exit.
    pub fn wait_for_exit_or(&self, timeout: Option<std::time::Duration>) -> Exit {
        let Some(timeout) = timeout else {
            return self.wait_for_exit();
        };
        let deadline = std::time::Instant::now() + timeout;
        let mut s = self.lock();
        loop {
            if let Some(e) = &*s {
                return e.clone();
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                drop(s);
                self.request_exit(Exit::Timeout(timeout));
                s = self.lock();
                continue;
            }
            s = self
                .cond
                .wait_timeout(s, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Block until an exit is requested and return it.
    pub fn wait_for_exit(&self) -> Exit {
        let mut s = self.lock();
        loop {
            if let Some(e) = &*s {
                return e.clone();
            }
            s = self.cond.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn exit_wakes_waiters_and_first_wins() {
        let c = Arc::new(Control::new());
        let main = {
            let c = c.clone();
            thread::spawn(move || c.wait_for_exit())
        };
        assert!(!c.is_exiting());
        c.request_exit(Exit::PowerOff);
        c.request_exit(Exit::Error("late".into()));
        assert!(c.is_exiting());
        assert_eq!(main.join().unwrap(), Exit::PowerOff);
        assert_eq!(c.wait_for_exit().status(), 0);
        assert_eq!(Exit::Error("x".into()).status(), 1);
    }

    #[test]
    fn timeout_stops_the_machine() {
        use std::time::{Duration, Instant};
        let c = Control::new();
        let t0 = Instant::now();
        let e = c.wait_for_exit_or(Some(Duration::from_millis(50)));
        assert_eq!(e, Exit::Timeout(Duration::from_millis(50)));
        assert!(t0.elapsed() >= Duration::from_millis(50));
        assert!(c.is_exiting());
        assert_eq!(e.status(), 1);
        // An exit before the deadline wins.
        let c = Arc::new(Control::new());
        let c2 = c.clone();
        let t = thread::spawn(move || c2.wait_for_exit_or(Some(Duration::from_secs(30))));
        c.request_exit(Exit::PowerOff);
        assert_eq!(t.join().unwrap(), Exit::PowerOff);
        assert_eq!(c.wait_for_exit_or(None), Exit::PowerOff);
    }
}
