//! Host side of the guest console (virtio-console, `hvc0`).
//!
//! - `stdio`: guest output to stdout, host stdin to the guest. When stdin is
//!   a terminal it is put in raw mode and an escape key is recognised:
//!   `Ctrl-A x` quits, `Ctrl-A h` prints help, `Ctrl-A Ctrl-A` sends a
//!   literal Ctrl-A. Input from a pipe or file is passed through untouched
//!   and its end (EOF) only stops input, not the guest.
//! - `unix:PATH`: a listening unix socket serving one client at a time;
//!   output is dropped while no client is connected (and when the client
//!   doesn't keep up, so a stalled client never stalls a vCPU).
//! - `none`: output discarded, no input.
//!
//! Guest output is written from vCPU threads (inside the console device);
//! input is read by a dedicated thread and pushed into [`ConsoleInput`],
//! which holds it until the guest has the console open. Pipe, file and
//! socket input waits while the guest is 1 MiB behind (nothing is lost);
//! terminal input never waits, so the escape keys always work, and drops
//! what the full buffer cannot take.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use vemu_virtio::console::ConsoleInput;

use crate::cli::SerialConfig;
use crate::power::{Control, Exit};
use crate::terminal;

/// The escape key: Ctrl-A.
const ESCAPE: u8 = 0x01;

const HELP: &str = "Ctrl-A x  quit vemu\r\nCtrl-A h  this help\r\nCtrl-A Ctrl-A  send Ctrl-A";

/// An opened console backend, before its input side is started.
pub struct Serial {
    kind: Kind,
}

enum Kind {
    Stdio,
    Unix(UnixServer),
    None,
    Capture(crate::cli::Capture),
}

impl Serial {
    /// Open the backend. For `unix:PATH` this binds the socket (replacing a
    /// stale socket file that nothing listens on; refusing a live socket or
    /// anything that is not a socket).
    pub fn open(cfg: &SerialConfig) -> io::Result<Serial> {
        let kind = match cfg {
            SerialConfig::Stdio => Kind::Stdio,
            SerialConfig::Unix(path) => Kind::Unix(UnixServer::bind(path)?),
            SerialConfig::None => Kind::None,
            SerialConfig::Capture(c) => Kind::Capture(c.clone()),
        };
        Ok(Serial { kind })
    }

    /// Writer for guest output.
    pub fn output(&self) -> Box<dyn Write + Send> {
        match &self.kind {
            Kind::Stdio => Box::new(io::stdout()),
            Kind::Unix(s) => Box::new(UnixOutput {
                client: s.client.clone(),
                warned: false,
            }),
            Kind::None => Box::new(io::sink()),
            Kind::Capture(c) => Box::new(CaptureOutput(c.clone())),
        }
    }

    /// Start feeding host input to the guest. For a terminal on stdin this
    /// switches it to raw mode (restored by [`terminal::restore`] and the
    /// exit hooks).
    pub fn start_input(&mut self, input: ConsoleInput, control: Arc<Control>) -> io::Result<()> {
        match &mut self.kind {
            Kind::Stdio => {
                let tty = terminal::is_tty(libc::STDIN_FILENO);
                if tty {
                    terminal::enter_raw_mode()?;
                }
                // Detached: it may block in read until the process exits.
                drop(spawn("console-stdin", move || {
                    stdin_loop(&input, &control, tty)
                })?);
            }
            Kind::Unix(s) => {
                let listener = s.listener.try_clone()?;
                let client = s.client.clone();
                let stop = s.stop.clone();
                s.thread = Some(spawn("console-unix", move || {
                    accept_loop(listener, &client, &input, &stop)
                })?);
            }
            Kind::None | Kind::Capture(_) => {}
        }
        Ok(())
    }
}

/// Guest output into a [`crate::cli::Capture`] writer.
struct CaptureOutput(crate::cli::Capture);

impl Write for CaptureOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut w = self.0.0.lock().unwrap_or_else(PoisonError::into_inner);
        w.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .flush()
    }
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new().name(name.into()).spawn(f)
}

fn stdin_loop(input: &ConsoleInput, control: &Control, tty: bool) {
    let mut stdin = io::stdin().lock();
    let mut filter = EscapeFilter::default();
    let mut buf = [0u8; 4096];
    let mut out = Vec::with_capacity(buf.len());
    loop {
        let n = match stdin.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                crate::log!("console: reading stdin failed: {e}; input stopped");
                return;
            }
        };
        if !tty {
            input.push(&buf[..n]);
            continue;
        }
        out.clear();
        let cmd = filter.feed(&buf[..n], &mut out);
        // Never block here: Ctrl-A x must work even if the guest stopped
        // reading.
        input.try_push(&out);
        match cmd {
            Some(EscapeCommand::Quit) => {
                control.request_exit(Exit::Quit);
                return;
            }
            Some(EscapeCommand::Help) => crate::log!("console escapes:\r\n{HELP}"),
            None => {}
        }
    }
}

/// A command typed after the escape key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeCommand {
    Quit,
    Help,
}

/// Strips `Ctrl-A <key>` sequences out of terminal input.
#[derive(Default)]
struct EscapeFilter {
    after_escape: bool,
}

impl EscapeFilter {
    /// Append the bytes meant for the guest to `out`. Stops at the first
    /// command and returns it (the rest of the input is dropped then, which
    /// only matters for Quit; Help is rare enough not to care).
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Option<EscapeCommand> {
        for &b in input {
            if !self.after_escape {
                if b == ESCAPE {
                    self.after_escape = true;
                } else {
                    out.push(b);
                }
                continue;
            }
            self.after_escape = false;
            match b {
                ESCAPE => out.push(ESCAPE),
                b'x' | b'X' => return Some(EscapeCommand::Quit),
                b'h' | b'H' | b'?' => return Some(EscapeCommand::Help),
                _ => {} // unknown escape: swallowed, like QEMU
            }
        }
        None
    }
}

type ClientSlot = Arc<Mutex<Option<UnixStream>>>;

/// First and longest wait before retrying a failed accept().
const ACCEPT_RETRY_MIN: Duration = Duration::from_millis(10);
const ACCEPT_RETRY_MAX: Duration = Duration::from_secs(1);

/// The listening socket for `unix:PATH`. On drop it stops the accept thread
/// and removes the socket file, if the path still names this socket.
struct UnixServer {
    path: PathBuf,
    /// `(st_dev, st_ino)` of the socket file bound here.
    id: (u64, u64),
    listener: UnixListener,
    client: ClientSlot,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UnixServer {
    fn bind(path: &Path) -> io::Result<UnixServer> {
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_socket() => remove_stale_socket(path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            Err(_) => {}
        }
        let listener = UnixListener::bind(path)
            .map_err(|e| io::Error::new(e.kind(), format!("bind {}: {e}", path.display())))?;
        let m = std::fs::symlink_metadata(path)
            .map_err(|e| io::Error::new(e.kind(), format!("stat {}: {e}", path.display())))?;
        Ok(UnixServer {
            path: path.to_path_buf(),
            id: (m.dev(), m.ino()),
            listener,
            client: Arc::new(Mutex::new(None)),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
        })
    }

    /// Whether the path still names the socket bound here (another process
    /// may have removed it and bound its own).
    fn owns_path(&self) -> bool {
        std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == self.id)
    }
}

/// Remove the socket file at `path` if nothing listens on it any more (left
/// behind by a process that was killed); refuse if something does.
fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "{} is in use: another process (a running vemu?) is listening on it",
                path.display()
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io::Error::new(
                    e.kind(),
                    format!("cannot remove stale socket {}: {e}", path.display()),
                )),
                _ => Ok(()),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("cannot check whether {} is in use: {e}", path.display()),
        )),
    }
}

impl Drop for UnixServer {
    fn drop(&mut self) {
        // Stop the accept thread: wake its read of the client (EOF) or its
        // accept (a connection of our own), after which it sees `stop`.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(c) = lock(&self.client).take() {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        if self.owns_path() {
            if self.thread.is_some() {
                let _ = UnixStream::connect(&self.path);
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn lock(slot: &ClientSlot) -> std::sync::MutexGuard<'_, Option<UnixStream>> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Errors after which accept() can never succeed on this listener. Anything
/// else (EMFILE/ENFILE when the fd table is full, ECONNABORTED, ENOBUFS,
/// ...) is transient: the console must come back once it clears.
fn accept_error_is_fatal(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK | libc::EOPNOTSUPP | libc::EFAULT)
    )
}

/// Serve clients one after the other: the connected client's input goes to
/// the guest until it disconnects; then the next pending client is accepted.
/// Runs until `stop` is set (the server is dropped); a failing accept() is
/// retried with a growing delay.
fn accept_loop(
    listener: UnixListener,
    client: &ClientSlot,
    input: &ConsoleInput,
    stop: &AtomicBool,
) {
    let mut retry = ACCEPT_RETRY_MIN;
    let mut failing = false;
    while !stop.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if accept_error_is_fatal(&e) => {
                crate::log!("console: accept failed: {e}; console socket closed");
                return;
            }
            Err(e) => {
                if !failing {
                    failing = true;
                    crate::log!("console: accept failed: {e}; retrying");
                }
                thread::sleep(retry);
                retry = (retry * 2).min(ACCEPT_RETRY_MAX);
                continue;
            }
        };
        if failing {
            failing = false;
            crate::log!("console: accepting clients again");
        }
        retry = ACCEPT_RETRY_MIN;
        let mut reader = match stream.try_clone() {
            Ok(r) => r,
            Err(e) => {
                crate::log!("console: cannot use client connection: {e}");
                continue;
            }
        };
        {
            // Checked under the lock Drop takes to shut the client down, so
            // a client is either seen (and shut down) by Drop or never used.
            let mut slot = lock(client);
            if stop.load(Ordering::SeqCst) {
                return;
            }
            *slot = Some(stream);
        }
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => input.push(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        *lock(client) = None;
    }
}

/// Guest output to the connected client, if any. Never blocks: data the
/// socket buffer can't take right now is dropped.
struct UnixOutput {
    client: ClientSlot,
    warned: bool,
}

impl Write for UnixOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut slot = lock(&self.client);
        let Some(stream) = slot.as_ref() else {
            return Ok(buf.len());
        };
        let fd = stream.as_raw_fd();
        let mut rest = buf;
        while !rest.is_empty() {
            // SAFETY: `rest` is a valid buffer; `fd` is the live client socket
            // (held by the locked slot). MSG_DONTWAIT makes just this call
            // non-blocking, leaving the reader thread's blocking reads alone.
            let n = unsafe { libc::send(fd, rest.as_ptr().cast(), rest.len(), libc::MSG_DONTWAIT) };
            if n >= 0 {
                rest = &rest[n as usize..];
                continue;
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    if !self.warned {
                        self.warned = true;
                        crate::log!("console: client is not reading; dropping output");
                    }
                }
                // Gone (EPIPE, ECONNRESET): forget it; the accept loop sees
                // EOF and takes the next client. Shutting down wakes its read.
                _ => {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    *slot = None;
                }
            }
            break;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use vemu_virtio::console::Console;

    fn filter(chunks: &[&[u8]]) -> (Vec<u8>, Option<EscapeCommand>) {
        let mut f = EscapeFilter::default();
        let mut out = Vec::new();
        for c in chunks {
            if let Some(cmd) = f.feed(c, &mut out) {
                return (out, Some(cmd));
            }
        }
        (out, None)
    }

    #[test]
    fn escapes() {
        assert_eq!(filter(&[b"ls\r"]), (b"ls\r".to_vec(), None));
        assert_eq!(filter(&[b"a\x01\x01b"]), (b"a\x01b".to_vec(), None));
        assert_eq!(
            filter(&[b"ab\x01xcd"]),
            (b"ab".to_vec(), Some(EscapeCommand::Quit))
        );
        // Escape split across reads.
        assert_eq!(
            filter(&[b"a\x01", b"x"]),
            (b"a".to_vec(), Some(EscapeCommand::Quit))
        );
        assert_eq!(filter(&[b"\x01", b"\x01z"]), (b"\x01z".to_vec(), None));
        assert_eq!(filter(&[b"\x01h"]), (vec![], Some(EscapeCommand::Help)));
        // Unknown escapes are swallowed.
        assert_eq!(filter(&[b"\x01qok"]), (b"ok".to_vec(), None));
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vemu-{name}-{}.sock", std::process::id()))
    }

    #[test]
    fn unix_bind_replaces_only_stale_sockets() {
        let path = temp_path("bind");
        let _ = std::fs::remove_file(&path);
        // A stale socket: its listener is gone (the process was killed).
        let fork_guard = crate::test_support::fork_lock();
        drop(UnixListener::bind(&path).unwrap());
        let a = UnixServer::bind(&path).unwrap();
        drop(fork_guard);
        // A live one is refused, and stays reachable.
        let e = UnixServer::bind(&path).err().expect("live socket replaced");
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        assert!(e.to_string().contains("in use"), "{e}");
        UnixStream::connect(&path).expect("live socket still reachable");
        drop(a);
        assert!(!path.exists(), "socket file removed on drop");
        std::fs::write(&path, b"x").unwrap();
        assert!(UnixServer::bind(&path).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"x",
            "regular file untouched"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn unix_drop_leaves_a_replaced_path_alone() {
        let path = temp_path("replaced");
        let _ = std::fs::remove_file(&path);
        let a = UnixServer::bind(&path).unwrap();
        // Someone removed A's file and bound their own socket there.
        std::fs::remove_file(&path).unwrap();
        let b = UnixServer::bind(&path).unwrap();
        drop(a);
        assert!(path.exists(), "A's drop removed B's socket");
        UnixStream::connect(&path).expect("B still reachable");
        drop(b);
        assert!(!path.exists());
    }

    #[test]
    fn unix_drop_stops_the_accept_thread() {
        let path = temp_path("stop");
        let mut serial = Serial::open(&SerialConfig::Unix(path.clone())).unwrap();
        let (_console, input) = Console::new(Box::new(io::sink()));
        serial.start_input(input, Arc::new(Control::new())).unwrap();
        // With a client connected, so the thread is blocked reading it.
        let _client = UnixStream::connect(&path).unwrap();
        let Kind::Unix(s) = &mut serial.kind else {
            unreachable!()
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while lock(&s.client).is_none() {
            assert!(Instant::now() < deadline, "client not accepted");
            thread::sleep(Duration::from_millis(5));
        }
        let t = s.thread.take().unwrap();
        // Keep a handle so Drop still knows a thread runs.
        s.thread = Some(thread::spawn(|| {}));
        drop(serial);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !t.is_finished() {
            assert!(Instant::now() < deadline, "accept thread still running");
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!path.exists());
    }

    /// Env var marking the child process of [`unix_accept_survives_emfile`].
    const EMFILE_CHILD: &str = "VEMU_TEST_EMFILE_CHILD";

    /// A full fd table (EMFILE, which a guest can cause through the NAT's
    /// host sockets) must not end the console: once fds are free again, new
    /// clients are served. Runs in a child process, as it lowers the
    /// process-wide fd limit (to 64; nothing is exhausted beyond that).
    #[test]
    fn unix_accept_survives_emfile() {
        if std::env::var_os(EMFILE_CHILD).is_none() {
            let name = "serial::tests::unix_accept_survives_emfile";
            let fork_guard = crate::test_support::fork_lock();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture", "--test-threads=1"])
                .env(EMFILE_CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            drop(fork_guard);
            let out = child.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
            assert!(
                stdout.contains("1 passed"),
                "child did not run the test:\n{stdout}"
            );
            // Which call runs out of fds varies by OS: accept() itself (macOS),
            // or (seen on Linux/musl) the try_clone() of the accepted stream.
            let accept_failed =
                stderr.contains("console: accept failed") && stderr.contains("retrying");
            let clone_failed = stderr.contains("console: cannot use client connection");
            assert!(
                accept_failed || clone_failed,
                "the console never hit EMFILE:\n{stderr}"
            );
            if accept_failed {
                assert!(stderr.contains("accepting clients again"), "{stderr}");
            }
            return;
        }

        let path = temp_path("emfile");
        let mut serial = Serial::open(&SerialConfig::Unix(path.clone())).unwrap();
        let (_console, input) = Console::new(Box::new(io::sink()));
        serial
            .start_input(input.clone(), Arc::new(Control::new()))
            .unwrap();

        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `lim` is a valid rlimit to fill / read.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        lim.rlim_cur = 64;
        // SAFETY: as above; lowers only this (child) process's soft limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) }, 0);
        let mut filler = Vec::new();
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(f) => filler.push(f),
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(libc::EMFILE), "{e}");
                    break;
                }
            }
            assert!(filler.len() <= 64, "fd limit not applied");
        }
        // Free one fd for the client; the server's accept() then has none.
        filler.pop();
        let first = UnixStream::connect(&path).unwrap();
        thread::sleep(Duration::from_millis(500));
        drop(filler);
        drop(first);

        let mut client = UnixStream::connect(&path).unwrap();
        client.write_all(b"back").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while input.pending() < 4 {
            assert!(Instant::now() < deadline, "console never came back");
            thread::sleep(Duration::from_millis(10));
        }
        drop(client);
        drop(serial);
    }

    #[test]
    fn unix_output_and_input() {
        let path = temp_path("io");
        let mut serial = Serial::open(&SerialConfig::Unix(path.clone())).unwrap();
        let mut out = serial.output();
        // No client: output is dropped without error.
        out.write_all(b"lost").unwrap();
        let (_console, input) = Console::new(Box::new(io::sink()));
        let control = Arc::new(Control::new());
        serial.start_input(input.clone(), control).unwrap();

        let mut client = UnixStream::connect(&path).unwrap();
        client.write_all(b"typed").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while input.pending() < 5 {
            assert!(Instant::now() < deadline, "input not delivered");
            thread::sleep(Duration::from_millis(5));
        }
        out.write_all(b"hello").unwrap();
        let mut got = [0u8; 5];
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");
        drop(client);
        // After the client leaves, output is dropped again.
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Kind::Unix(s) = &serial.kind
            && lock(&s.client).is_some()
        {
            assert!(Instant::now() < deadline, "client not released");
            thread::sleep(Duration::from_millis(5));
        }
        out.write_all(b"lost again").unwrap();
        drop(serial);
        assert!(!path.exists());
    }
}
