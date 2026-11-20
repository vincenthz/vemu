//! End-to-end boots of the test guest with the real `vemu` binary: on
//! macOS (HVF) and Linux (KVM). The guest is the host's architecture:
//! `testdata/{Image,initramfs.cpio.gz,disk.img}` on aarch64,
//! `testdata/x86_64/{bzImage,initramfs.cpio.gz,disk.img}` on x86_64 (see
//! scripts/mk-testdata.sh).
//!
//! Each test runs vemu as a child process under a deadline. Tests are skipped
//! (with a message) when the fixtures are missing or the host has no
//! usable hypervisor (Linux: read-write `/dev/kvm`). The tests take
//! [`one_vm_at_a_time`] so that a plain `cargo test` never runs several VMs
//! concurrently.
//!
//! Environment overrides, for running a cross-built test executable on
//! another machine: `VEMU_TEST_BIN` (the vemu binary to run) and
//! `VEMU_TESTDATA` (the `testdata` directory).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, Once, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(60);

/// Serialises the tests in this file: each boots real VMs (up to 1 GiB and 4
/// vCPUs), and running them in parallel would multiply the host load.
fn one_vm_at_a_time() -> MutexGuard<'static, ()> {
    static VM: Mutex<()> = Mutex::new(());
    VM.lock().unwrap_or_else(PoisonError::into_inner)
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The host architecture's kernel image name.
const KERNEL: &str = if cfg!(target_arch = "x86_64") {
    "bzImage"
} else {
    "Image"
};

/// A fixture of the host architecture's test guest.
fn testdata(name: &str) -> PathBuf {
    let dir = std::env::var_os("VEMU_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("testdata"));
    if cfg!(target_arch = "x86_64") {
        dir.join("x86_64").join(name)
    } else {
        dir.join(name)
    }
}

/// The vemu binary (on macOS ad-hoc signed with the hypervisor
/// entitlement); `None` (test skipped) without fixtures or a hypervisor.
fn vemu() -> Option<PathBuf> {
    if cfg!(target_os = "linux") {
        let kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm");
        if let Err(e) = kvm {
            eprintln!("skipping: no usable /dev/kvm ({e})");
            return None;
        }
    } else if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        eprintln!("skipping: no hypervisor backend on this host");
        return None;
    }
    for f in [KERNEL, "initramfs.cpio.gz", "disk.img"] {
        if !testdata(f).exists() {
            eprintln!(
                "skipping: {} missing (run scripts/mk-testdata.sh)",
                testdata(f).display()
            );
            return None;
        }
    }
    let bin = std::env::var_os("VEMU_TEST_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_vemu")));
    if !cfg!(target_os = "macos") {
        return Some(bin);
    }
    static SIGN: Once = Once::new();
    SIGN.call_once(|| {
        let ok = Command::new("codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg(root().join("vemu.entitlements"))
            .arg(&bin)
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "codesign failed");
    });
    Some(bin)
}

fn base_args(cmdline: &str) -> Vec<String> {
    vec![
        "--kernel".into(),
        testdata(KERNEL).display().to_string(),
        "--initrd".into(),
        testdata("initramfs.cpio.gz").display().to_string(),
        "--append".into(),
        cmdline.into(),
        "--net".into(),
        "none".into(),
    ]
}

/// Wait for `child` to exit within [`DEADLINE`], killing it otherwise.
fn wait(child: &mut Child) -> ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("vemu did not exit within {DEADLINE:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Run vemu with `stdin` bytes piped in; returns (status, stdout, stderr).
fn run(bin: &Path, args: &[String], stdin: &[u8]) -> (ExitStatus, String, String) {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let data = stdin.to_vec();
    let writer = thread::spawn(move || {
        let _ = input.write_all(&data);
    });
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let reader = thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let ereader = thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });
    let status = wait(&mut child);
    writer.join().unwrap();
    (status, reader.join().unwrap(), ereader.join().unwrap())
}

#[test]
fn test_mode_boot_with_disk() {
    let _vm = one_vm_at_a_time();
    let Some(bin) = vemu() else { return };
    for cpus in ["1", "2", "4"] {
        // loglevel=4: kernel warnings still show, but no info messages
        // (e.g. CONFIG_DEBUG_STACK_USAGE's) land in the middle of a line
        // init is printing on the same console.
        let mut args = base_args("console=hvc0 loglevel=4 vemu.test=1");
        args.extend(["--cpus".into(), cpus.into()]);
        args.extend([
            "--disk".into(),
            format!("{},ro", testdata("disk.img").display()),
        ]);
        let (status, out, err) = run(&bin, &args, b"");
        assert!(status.success(), "cpus={cpus}: {status}\n{out}\n{err}");
        assert!(out.contains("vemu-init: up"), "{out}");
        assert!(out.contains(&format!("cpus={cpus}\r\n")), "{out}");
        assert!(
            out.contains("vemu-init: disk /dev/vda 131072 sectors"),
            "{out}"
        );
        assert!(out.contains("vemu-init: done"), "{out}");
        // Neither "unhandled MMIO" nor (x86) "unhandled port I/O".
        assert!(!err.contains("unhandled"), "{err}");
    }
}

#[test]
fn piped_console_input() {
    let _vm = one_vm_at_a_time();
    let Some(bin) = vemu() else { return };
    let mut args = base_args("quiet vemu.test=1 vemu.run=sh");
    args.extend([
        "--disk".into(),
        format!("{},ro", testdata("disk.img").display()),
    ]);
    // Written at once, long before the guest console is up.
    let (status, out, err) = run(
        &bin,
        &args,
        b"echo hi-from-host\nhead -c 16 /dev/vda; echo\npoweroff -f\n",
    );
    assert!(status.success(), "{status}\n{out}\n{err}");
    // The command echo, then its output on a line of its own.
    assert!(out.contains("\nhi-from-host\r\n"), "{out}");
    assert!(out.contains("\nVEMU-DISK-MARKER\r\n"), "{out}");
}

#[test]
fn unix_socket_console() {
    let _vm = one_vm_at_a_time();
    let Some(bin) = vemu() else { return };
    let dir = std::env::temp_dir().join(format!("vemu-boot-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("console.sock");
    let mut args = base_args("vemu.test=1 vemu.run=sh");
    args.extend(["--serial".into(), format!("unix:{}", sock.display())]);
    let mut child = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let start = Instant::now();
    let mut conn = loop {
        match UnixStream::connect(&sock) {
            Ok(c) => break c,
            Err(_) if start.elapsed() < DEADLINE => thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("cannot connect to {}: {e}", sock.display()),
        }
    };
    conn.set_read_timeout(Some(DEADLINE)).unwrap();
    let mut seen = Vec::new();
    let mut read_until = |conn: &mut UnixStream, tok: &[u8]| {
        let mut buf = [0u8; 4096];
        while !seen.windows(tok.len()).any(|w| w == tok) {
            let n = conn.read(&mut buf).unwrap();
            assert!(
                n > 0,
                "console closed; got {:?}",
                String::from_utf8_lossy(&seen)
            );
            seen.extend_from_slice(&buf[..n]);
        }
    };
    read_until(&mut conn, b"# ");
    conn.write_all(b"echo hi-from-socket\n").unwrap();
    read_until(&mut conn, b"\nhi-from-socket\r\n");
    conn.write_all(b"poweroff -f\n").unwrap();
    let status = wait(&mut child);
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    assert!(status.success(), "{status}\n{err}");
    assert!(!sock.exists(), "socket file left behind");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn user_network_dhcp() {
    let _vm = one_vm_at_a_time();
    let Some(bin) = vemu() else { return };
    let mut args = base_args("quiet vemu.test=1");
    // A bad forward spec is a usage error.
    args.truncate(args.len() - 2);
    args.extend(["--net".into(), "user,hostfwd=tcp:127.0.0.1:0-:22".into()]);
    let (status, out, err) = run(&bin, &args, b"");
    assert_eq!(
        status.code(),
        Some(2),
        "port 0 is not a valid forward: {out}"
    );
    assert!(err.contains("invalid hostfwd"), "{err}");

    // No --net: the default user-mode NAT, whose DHCP server leases 10.0.2.15.
    args.truncate(args.len() - 2);
    let (status, out, err) = run(&bin, &args, b"");
    assert!(status.success(), "{status}\n{out}\n{err}");
    assert!(out.contains("vemu-init: eth0 10.0.2.15/24\r\n"), "{out}");
    assert!(out.contains("vemu-init: done"), "{out}");
}
