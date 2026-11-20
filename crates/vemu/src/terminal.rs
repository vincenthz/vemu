//! Host terminal raw mode, restored on every way out of the process, and
//! VMM log lines that stay readable while the terminal is raw.
//!
//! Restoration paths: [`restore`] (normal exit), an `atexit` handler (any
//! `std::process::exit`), the panic hook installed by `main`, and handlers
//! for SIGHUP/SIGINT/SIGQUIT/SIGTERM that restore the terminal and then die
//! from the signal as if unhandled.

use std::fmt;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Terminal settings before raw mode. Written once, before `RAW` is set.
static SAVED: OnceLock<libc::termios> = OnceLock::new();
/// Raw mode is active (and `SAVED` holds what to restore).
static RAW: AtomicBool = AtomicBool::new(false);

const STDIN: libc::c_int = libc::STDIN_FILENO;
const SIGNALS: [libc::c_int; 4] = [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];

/// Whether `fd` refers to a terminal.
pub fn is_tty(fd: libc::c_int) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// Put the terminal on stdin into raw mode: no echo, no line editing, no
/// signal keys (Ctrl-C goes to the guest), no output post-processing (the
/// guest's tty layer produces `\r\n`).
pub fn enter_raw_mode() -> io::Result<()> {
    let mut t = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr fills the termios on success; checked below.
    if unsafe { libc::tcgetattr(STDIN, t.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: initialised by the successful tcgetattr.
    let saved = unsafe { t.assume_init() };
    let saved = *SAVED.get_or_init(|| saved);
    install_restore_hooks();

    let mut raw = saved;
    // SAFETY: cfmakeraw only modifies the struct it is given.
    unsafe { libc::cfmakeraw(&mut raw) };
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    // SAFETY: valid termios for the stdin descriptor.
    if unsafe { libc::tcsetattr(STDIN, libc::TCSANOW, &raw) } != 0 {
        return Err(io::Error::last_os_error());
    }
    RAW.store(true, Ordering::SeqCst);
    Ok(())
}

/// Restore the terminal if raw mode is active. Idempotent and
/// async-signal-safe (an atomic swap and `tcsetattr`).
pub fn restore() {
    if RAW.swap(false, Ordering::SeqCst)
        && let Some(t) = SAVED.get()
    {
        // SAFETY: `t` came from tcgetattr on the same descriptor.
        unsafe { libc::tcsetattr(STDIN, libc::TCSANOW, t) };
    }
}

pub fn is_raw() -> bool {
    RAW.load(Ordering::Relaxed)
}

/// Print `vemu: <msg>` on stderr, ending the line with `\r\n` while the
/// terminal is raw so it starts at column 0.
///
/// Never panics: a line that cannot be written is lost. Guests trigger log
/// lines (an unhandled port, say), and with stderr on a pipe whose reader
/// is gone the write fails with EPIPE (Rust ignores SIGPIPE); `eprint!`
/// would panic there and the panic hook would end the VM.
pub fn log_line(args: fmt::Arguments<'_>) {
    let nl = if is_raw() { "\r\n" } else { "\n" };
    // One write, so concurrent lines do not interleave.
    let line = format!("vemu: {args}{nl}");
    // Unit tests: eprint!, which the test harness captures (with
    // --nocapture it is a plain stderr write that panics on error).
    #[cfg(test)]
    if !tests::DIRECT_STDERR.load(Ordering::Relaxed) {
        eprint!("{line}");
        return;
    }
    let _ = io::stderr().lock().write_all(line.as_bytes());
}

extern "C" fn restore_at_exit() {
    restore();
}

extern "C" fn restore_on_signal(sig: libc::c_int) {
    restore();
    // SAFETY: signal() and raise() are async-signal-safe; with the default
    // disposition back in place the process terminates from `sig` as if it
    // had never been caught (the signal is unblocked when we return).
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

fn install_restore_hooks() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: registering a plain extern "C" function with no captured
        // state.
        unsafe { libc::atexit(restore_at_exit) };
        for sig in SIGNALS {
            // SAFETY: the handler only calls async-signal-safe functions; the
            // sigaction struct is fully initialised (zeroed, then filled).
            unsafe {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = restore_on_signal as extern "C" fn(libc::c_int) as usize;
                libc::sigemptyset(&mut sa.sa_mask);
                sa.sa_flags = 0;
                libc::sigaction(sig, &sa, std::ptr::null_mut());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::{Command, Stdio};
    use std::sync::atomic::AtomicBool;

    /// [`log_line`] writes to stderr as outside tests.
    pub(super) static DIRECT_STDERR: AtomicBool = AtomicBool::new(false);

    /// Env var marking the child process of [`log_line_survives_broken_stderr`].
    const BROKEN_STDERR_CHILD: &str = "VEMU_TEST_BROKEN_STDERR_CHILD";

    /// A pipe; both ends close-on-exec.
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: pipe fills two fds on success; checked.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        for fd in fds {
            // SAFETY: fd is one we just opened.
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                -1
            );
        }
        // SAFETY: freshly opened fds owned by nothing else.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// Logging with stderr on a pipe that has no reader (EPIPE) must not
    /// panic: guests can trigger log lines, and a panic ends the VM. Runs in
    /// a child process whose stderr is that pipe.
    #[test]
    fn log_line_survives_broken_stderr() {
        if std::env::var_os(BROKEN_STDERR_CHILD).is_some() {
            DIRECT_STDERR.store(true, Ordering::Relaxed);
            for i in 0..3 {
                log_line(format_args!("line {i} into a broken pipe"));
            }
            return;
        }
        let name = "terminal::tests::log_line_survives_broken_stderr";
        let fork_guard = crate::test_support::fork_lock();
        let (reader, writer) = pipe();
        drop(reader);
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(BROKEN_STDERR_CHILD, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap();
        drop(fork_guard);
        let out = out.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed: {:?}\n{stdout}",
            out.status
        );
        assert!(
            stdout.contains("1 passed"),
            "child did not run the test:\n{stdout}"
        );
    }
}
