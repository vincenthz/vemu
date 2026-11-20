//! `vemu build CONFIG`: make an Alpine Linux image with a builder VM.
//!
//! The vemu-build crate prepares everything on the host (config, the
//! verified minirootfs, the builder initramfs with its generated `/init`,
//! the sparse `OUT.partial`). This module runs the builder VM in this
//! process with the ordinary machine code ([`machine::run`]): the kernel,
//! that initramfs, 2 vCPUs, 1 GiB, user-mode NAT without forwards, and
//! `OUT.partial` as `/dev/vda`. Its console goes to `OUT.build.log` (and to
//! stderr with `-v`) through a capture sink that also watches for the
//! guest's `VEMU-BUILD-OK <nonce>` line. Only that line followed by a
//! power-off makes the build a success; then `OUT.partial` becomes `OUT`
//! (synced, renamed, 0444). Anything else (a power-off without the marker,
//! a reboot or kernel panic, the timeout, a VMM error, a signal) deletes
//! `OUT.partial` and reports the last console lines.
//!
//! The signal handlers are installed before anything is downloaded or
//! created, and remove whatever [`vemu_build::cleanup`] holds at the time
//! (a partial download and its curl, the initramfs, `OUT.partial`); the
//! panic hook in main.rs does the same. Messages go to stderr through
//! [`say`], which ignores write errors: a closed stderr (`| head`) must not
//! panic the build halfway.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

use vemu_build::script::{FAIL_MARKER, OK_MARKER, STEP_PREFIX};
use vemu_disk::Format;

use crate::cli::{Capture, Config, DiskConfig, NetConfig, SerialConfig};
use crate::machine;
use crate::power::Exit;

/// Console lines shown when a build fails.
const TAIL_LINES: usize = 30;

/// A line on stderr; errors (a closed pipe) are ignored.
fn err_line(m: &str) {
    let mut e = io::stderr().lock();
    let _ = e.write_all(m.as_bytes());
    let _ = e.write_all(b"\n");
}

/// A `vemu build: ` message on stderr.
fn say(m: &str) {
    err_line(&format!("vemu build: {m}"));
}

/// Run `vemu build`; returns the exit status.
pub fn run(opts: &vemu_build::Options) -> i32 {
    let start = Instant::now();
    install_cleanup();
    let prepared = match vemu_build::prepare(opts, &mut |m| say(m)) {
        Ok(p) => p,
        Err(e) => {
            say(&format!("error: {e}"));
            return 1;
        }
    };

    let log = match File::create(&prepared.log_path) {
        Ok(f) => f,
        Err(e) => {
            say(&format!(
                "error: cannot create {}: {e}",
                prepared.log_path.display()
            ));
            return 1;
        }
    };
    let console = Arc::new(Mutex::new(BuildConsole::new(
        log,
        format!("{OK_MARKER} {}", prepared.nonce),
        opts.verbose,
        start,
    )));
    let sink: Arc<Mutex<dyn Write + Send>> = console.clone();
    let cfg = Config {
        kernel: prepared.kernel.clone(),
        initrd: Some(prepared.initrd.path().to_path_buf()),
        append: Some(prepared.cmdline.clone()),
        memory: vemu_build::BUILDER_MEMORY,
        cpus: vemu_build::BUILDER_CPUS,
        disks: vec![DiskConfig {
            path: prepared.target.partial().to_path_buf(),
            read_only: false,
            snapshot: false,
            format: Format::Raw,
        }],
        net: NetConfig::User {
            hostfwd: Vec::new(),
        },
        serial: SerialConfig::Capture(Capture(sink)),
        debug_uart: false,
        timeout: Some(Duration::from_secs(opts.timeout_secs)),
    };
    say(&format!(
        "booting the builder VM ({} vCPUs, {} MiB, kernel {}, initramfs {} MiB); log: {}",
        cfg.cpus,
        cfg.memory >> 20,
        prepared.kernel.display(),
        prepared.initrd_size >> 20,
        prepared.log_path.display()
    ));
    let result = machine::run(&cfg);
    let (ok, failure, tail) = {
        let mut c = console.lock().unwrap_or_else(PoisonError::into_inner);
        c.end();
        (
            c.ok,
            c.failure.clone(),
            c.tail.iter().cloned().collect::<Vec<_>>(),
        )
    };
    let why = match (&result, ok) {
        (Ok(Exit::PowerOff), true) => None,
        (Err(e), _) => Some(format!("cannot run the builder VM: {e}")),
        (Ok(Exit::Timeout(t)), _) => Some(format!(
            "the builder did not finish within {} s (--timeout)",
            t.as_secs()
        )),
        (Ok(Exit::Reset), _) => {
            Some("the builder VM rebooted (a kernel panic, or /init died) without finishing".into())
        }
        (Ok(Exit::Error(e)), _) => Some(format!("VM error: {e}")),
        (Ok(Exit::Quit), _) => Some("interrupted".into()),
        (Ok(Exit::PowerOff), false) => Some(match failure {
            Some(f) => format!("the build failed in the guest: {f}"),
            None => "the builder powered off without finishing (no success marker)".into(),
        }),
    };
    if let Some(why) = why {
        say(&format!("error: {why}"));
        if !opts.verbose && !tail.is_empty() {
            err_line(&format!(
                "--- last {} console lines ({}) ---",
                tail.len(),
                prepared.log_path.display()
            ));
            for l in &tail {
                err_line(l);
            }
            err_line("---");
        }
        say(&format!(
            "{} removed; the full console log is {}",
            prepared.target.partial().display(),
            prepared.log_path.display()
        ));
        return 1;
    }

    let out = prepared.target.out().to_path_buf();
    let kernel = prepared.kernel.clone();
    let ssh = prepared.config.ssh.is_some();
    let (version, arch, size) = (
        prepared.release.version.clone(),
        prepared.release.arch.clone(),
        prepared.config.size,
    );
    let vemu_build::Prepared { target, initrd, .. } = prepared;
    drop(initrd);
    if let Err(e) = target.commit() {
        say(&format!("error: {e}"));
        return 1;
    }
    let allocated = std::fs::metadata(&out)
        .map(|m| m.blocks() * 512)
        .unwrap_or(0);
    say(&format!(
        "built {} in {} s: Alpine {version} {arch}, {} MiB image, {} MiB allocated on disk, read-only",
        out.display(),
        start.elapsed().as_secs(),
        size >> 20,
        allocated >> 20
    ));
    // A closed stdout must not turn the finished build into a failure.
    let mut o = io::stdout().lock();
    let _ = o.write_all(usage_hint(&out, &kernel, ssh).as_bytes());
    let _ = o.flush();
    0
}

/// How to boot the new image.
pub fn usage_hint(out: &Path, kernel: &Path, ssh: bool) -> String {
    let o = sh(&out.to_string_lossy());
    let k = sh(&kernel.to_string_lossy());
    // Both runs get the ssh forward that the last line tells to use.
    let fwd = if ssh { " -p 2222:22" } else { "" };
    let mut s = format!(
        "\nThe image is a read-only golden image. Give each VM an overlay:\n\
         \x20 vemu overlay create {o} vm1.vov\n\
         \x20 vemu --kernel {k} --disk vm1.vov --append \"root=/dev/vda rw\"{fwd}\n\
         Or a throwaway run (its writes are discarded at exit):\n\
         \x20 vemu --kernel {k} --disk {o},snapshot --append \"root=/dev/vda rw\"{fwd}\n\
         Log in as root on the console (no password)"
    );
    if ssh {
        s.push_str(", or with your key: ssh -p 2222 root@127.0.0.1");
    }
    s.push_str(". poweroff in the guest ends vemu.\n");
    s
}

/// Quote `s` for a POSIX shell when it needs it.
fn sh(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-+,:@=".contains(&b))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The builder console: to the log file (and stderr with `-v`), split into
/// lines to find the markers, the progress lines and the tail.
struct BuildConsole {
    log: File,
    marker: String,
    verbose: bool,
    start: Instant,
    line: Vec<u8>,
    tail: VecDeque<String>,
    ok: bool,
    failure: Option<String>,
    log_failed: bool,
}

impl BuildConsole {
    fn new(log: File, marker: String, verbose: bool, start: Instant) -> BuildConsole {
        BuildConsole {
            log,
            marker,
            verbose,
            start,
            line: Vec::new(),
            tail: VecDeque::with_capacity(TAIL_LINES),
            ok: false,
            failure: None,
            log_failed: false,
        }
    }

    fn feed_line(&mut self) {
        let raw = std::mem::take(&mut self.line);
        let text = String::from_utf8_lossy(&raw);
        let text = text.trim_end_matches('\r');
        if text.contains(&self.marker) {
            self.ok = true;
        }
        if let Some(i) = text.find(FAIL_MARKER) {
            let rest = text[i + FAIL_MARKER.len()..].trim_start_matches(':').trim();
            self.failure.get_or_insert_with(|| rest.to_string());
        }
        if !self.verbose
            && let Some(step) = text.strip_prefix(STEP_PREFIX)
        {
            say(&format!("[{:4} s] {step}", self.start.elapsed().as_secs()));
        }
        if self.tail.len() == TAIL_LINES {
            self.tail.pop_front();
        }
        self.tail.push_back(text.to_string());
    }

    /// The console closed: take an unterminated last line too.
    fn end(&mut self) {
        if !self.line.is_empty() {
            self.feed_line();
        }
        let _ = self.log.flush();
    }
}

impl Write for BuildConsole {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.log_failed {
            let clean: Vec<u8> = buf.iter().copied().filter(|&b| b != b'\r').collect();
            if let Err(e) = self.log.write_all(&clean) {
                self.log_failed = true;
                say(&format!("warning: writing the build log failed: {e}"));
            }
        }
        if self.verbose {
            let _ = io::stderr().write_all(buf);
        }
        for &b in buf {
            if b == b'\n' {
                self.feed_line();
            } else if self.line.len() < 64 << 10 {
                self.line.push(b);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.log.flush()
    }
}

extern "C" fn cleanup_on_signal(sig: libc::c_int) {
    vemu_build::cleanup::run_now();
    // SAFETY: signal() and raise() are async-signal-safe; with the default
    // action restored, the process dies of the signal.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Remove what the build has registered (temporary files, OUT.partial,
/// curl) if SIGINT, SIGTERM, SIGHUP or SIGQUIT ends it. A signal ignored at
/// startup (SIGINT and SIGQUIT for a background job, or under nohup) stays
/// ignored.
fn install_cleanup() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            // SAFETY: the handler only calls async-signal-safe functions
            // (cleanup::run_now reads atomics, kills and unlinks).
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &mut old) == 0
                    && old.sa_sigaction == libc::SIG_IGN
                {
                    continue;
                }
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = cleanup_on_signal as extern "C" fn(libc::c_int) as usize;
                libc::sigemptyset(&mut sa.sa_mask);
                libc::sigaction(sig, &sa, std::ptr::null_mut());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn console(verbose: bool) -> (BuildConsole, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "vemu-build-console-{}-{verbose}",
            std::process::id()
        ));
        let f = File::create(&path).unwrap();
        (
            BuildConsole::new(f, "VEMU-BUILD-OK abc123".into(), verbose, Instant::now()),
            path,
        )
    }

    #[test]
    fn markers_and_tail() {
        let (mut c, path) = console(true);
        c.write_all(b"line one\r\n+ echo \"VEMU-BUILD-OK $NONCE\"\r\nVEMU-BUILD")
            .unwrap();
        assert!(!c.ok, "the script's text without the nonce does not count");
        c.write_all(b"-OK abc12").unwrap();
        assert!(!c.ok);
        c.write_all(b"3\r\n").unwrap();
        assert!(c.ok);
        for i in 0..40 {
            writeln!(c, "l{i}").unwrap();
        }
        c.write_all(b"unterminated").unwrap();
        c.end();
        assert_eq!(c.tail.len(), TAIL_LINES);
        assert_eq!(c.tail.back().unwrap(), "unterminated");
        assert_eq!(c.tail.front().unwrap(), "l11");
        let log = std::fs::read_to_string(&path).unwrap();
        assert!(log.starts_with("line one\n") && !log.contains('\r'));
        std::fs::remove_file(&path).unwrap();

        let (mut c, path) = console(true);
        c.write_all(
            b"VEMU-BUILD-OK wrong\nVEMU-BUILD-FAILED: installing packages: apk could not install\n",
        )
        .unwrap();
        c.end();
        assert!(!c.ok);
        assert_eq!(
            c.failure.as_deref(),
            Some("installing packages: apk could not install")
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn hint() {
        let h = usage_hint(Path::new("/img/a.raw"), Path::new("/k/Image"), true);
        assert!(h.contains("vemu overlay create /img/a.raw vm1.vov\n"));
        assert!(h.contains("vemu --kernel /k/Image --disk vm1.vov --append \"root=/dev/vda rw\""));
        assert!(h.contains("--disk vm1.vov --append \"root=/dev/vda rw\" -p 2222:22\n"));
        assert!(
            h.contains("--disk /img/a.raw,snapshot --append \"root=/dev/vda rw\" -p 2222:22\n")
        );
        assert!(h.contains("ssh -p 2222 root@127.0.0.1"));
        let h = usage_hint(
            Path::new("/my images/a.raw"),
            Path::new("/k/bzImage"),
            false,
        );
        assert!(h.contains("vemu overlay create '/my images/a.raw' vm1.vov"));
        assert!(!h.contains("-p 2222") && !h.contains("ssh -p"));
        assert_eq!(sh("it's"), r"'it'\''s'");
    }
}
