//! Command-line parsing.
//!
//! Hand-written (std only). Options take their value either as the next
//! argument (`--cpus 2`) or inline (`--cpus=2`). `vemu overlay ...` is a
//! subcommand (the first argument; running a VM always starts with an
//! option, so the two never clash).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vemu_disk::{DiskOptions, Format};
use vemu_net::{HostFwd, Proto};

use crate::arch::{ArchMachine, MAX_CPUS, Machine};

/// Usage text printed by `--help` and after a usage error.
pub fn usage() -> String {
    let h = Machine::HELP;
    format!(
        "\
usage: vemu --kernel PATH [options]
       vemu overlay create|info ...   (golden images; see vemu overlay --help)
       vemu build CONFIG [options]    (make an Alpine Linux image; see vemu build --help)

Boot {guest} Linux kernel in a hardware-virtualized VM (no CPU emulation).

options:
  --kernel PATH          {kernel}
  --initrd PATH          {initrd}
  --append CMDLINE       kernel command line (console=hvc0 is added when it
                         names no console=)
  --memory SIZE          guest RAM, e.g. 512M, 2G; a bare number is MiB
                         (default 1G)
  --cpus N               number of vCPUs (default 1)
  --disk PATH[,OPT]...   disk as virtio-blk (/dev/vda, vdb, ... in command-line
                         order); repeatable. PATH is a raw image or a vemu
                         overlay (recognized by its header). OPT:
                           ro        read-only
                           snapshot  writes go to a throwaway overlay on the
                                     raw image PATH, deleted at exit
                           format=raw|overlay
                                     do not detect the format
  --net user[,hostfwd=SPEC]...|none
                         network: user-mode NAT with port forwards
                         (SPEC like tcp::2222-:22), or none (default user)
  -p, --publish [HOSTADDR:]HOSTPORT:GUESTPORT[/tcp|/udp]
                         forward a host port to the guest: vemu listens on
                         HOSTADDR:HOSTPORT (default 127.0.0.1, this host
                         only; 0.0.0.0 for all interfaces) and forwards
                         each connection (tcp, the default) or datagram
                         (udp) to the guest's GUESTPORT; repeatable. The
                         same as --net user,hostfwd=... (e.g. -p 2222:22)
  --serial stdio|unix:PATH|none
                         where the guest console (hvc0) goes (default stdio).
                         On a terminal, Ctrl-A x quits, Ctrl-A Ctrl-A sends
                         Ctrl-A. unix:PATH serves one client at a time.
  --debug-uart           {debug_uart}
  -h, --help             show this help
  -V, --version          show the version
",
        guest = h.guest,
        kernel = h.kernel,
        initrd = h.initrd,
        debug_uart = h.debug_uart,
    )
}

/// Default guest RAM size.
pub const DEFAULT_MEMORY: u64 = 1 << 30;

/// Usage text of `vemu overlay`.
pub fn overlay_usage() -> String {
    format!(
        "\
usage: vemu overlay create BASE OVERLAY [--block-size N]
       vemu overlay info OVERLAY

Golden images and overlays. An overlay is a sparse file that holds a VM's
writes on top of a read-only golden image (a raw image, BASE): blocks the VM
has not written are read from BASE, which is never modified. Any number of
VMs can run on one golden image at once, each with its own overlay.

  create BASE OVERLAY    create the overlay OVERLAY on BASE (an existing
                         file is never overwritten). OVERLAY records BASE's
                         path (relative to OVERLAY's directory when they
                         share one besides /), size, modification time and a
                         sample of its content; if BASE changes, the overlay
                         is refused.
    --block-size N       allocation unit: a power of two from 512 to 2M,
                         e.g. 4K or 64K (default {default_bs}K)
  info OVERLAY           show the overlay's golden image and whether it is
                         usable, its sizes, and how much it holds; exits 1 if
                         the golden image is missing or changed

Run a VM on an overlay with --disk OVERLAY (,ro to only read it).
--disk BASE,snapshot instead writes to a temporary overlay in $TMPDIR that
is deleted when vemu exits (even if it is killed).

Example:
  vemu overlay create golden.raw vm1.vov     # once per VM
  vemu --kernel Image --disk vm1.vov         # writes persist in vm1.vov
  vemu --kernel Image --disk golden.raw,snapshot   # writes are discarded
  vemu overlay info vm1.vov
",
        default_bs = vemu_disk::DEFAULT_BLOCK_SIZE / 1024,
    )
}

/// Usage text of `vemu build`.
pub fn build_usage() -> String {
    format!(
        "\
usage: vemu build CONFIG [-o OUT] [--force] [--cache DIR] [--kernel PATH]
                  [--timeout SECS] [-v]

Make a bootable Alpine Linux disk image (a raw ext4 image, sparse) from the
small declarative CONFIG file. vemu boots a builder VM ({cpus} vCPUs, {mem} GiB,
user-mode network) on the kernel, with the Alpine minirootfs as its initramfs
and the new image as /dev/vda; the guest formats it and installs Alpine with
apk. The host needs no root. Downloads go through the system curl (https,
sha256-checked) and are cached.

  -o, --output OUT       the image (default: the config's output =, else
                         <config name>.raw next to the config). It is built
                         as OUT.partial and renamed to OUT, read-only, only
                         when the build succeeds; the console log is
                         OUT.build.log
  --force                replace an existing OUT (overlays on it are then
                         refused: its fingerprint changes)
  --cache DIR            download cache (default: $XDG_CACHE_HOME/vemu,
                         ~/Library/Caches/vemu on macOS, ~/.cache/vemu)
  --kernel PATH          the builder kernel, overriding the config's kernel =
                         (the image boots with it too)
  --timeout SECS         give up after SECS seconds (default {timeout})
  -v, --verbose          show the builder's console on stderr
  -h, --help             show this help

Config keys (docs/image-builder.md has the reference):
  arch size alpine mirror sha256 insecure community kernel modules hostname
  timezone output; [network] dhcp ntp; [ssh] enable server authorized_keys;
  [packages] list; [files] /path/in/image = host/path [mode]; [run] script

Example (examples/alpine.conf):
  vemu build alpine.conf -o alpine.raw
  vemu overlay create alpine.raw vm1.vov
  vemu --kernel Image --disk vm1.vov --append \"root=/dev/vda rw\" -p 2222:22
",
        cpus = vemu_build::BUILDER_CPUS,
        mem = vemu_build::BUILDER_MEMORY >> 30,
        timeout = vemu_build::DEFAULT_TIMEOUT_SECS,
    )
}

/// What the command line asks for.
#[derive(Debug, PartialEq)]
pub enum Command {
    Run(Config),
    Help,
    Version,
    Overlay(OverlayCommand),
    Build(vemu_build::Options),
    BuildHelp,
}

/// `vemu overlay ...`.
#[derive(Debug, PartialEq, Eq)]
pub enum OverlayCommand {
    Create {
        base: PathBuf,
        overlay: PathBuf,
        block_size: u32,
    },
    Info {
        overlay: PathBuf,
    },
    Help,
}

/// A fully parsed machine configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub kernel: PathBuf,
    pub initrd: Option<PathBuf>,
    /// The `--append` value as given (see [`Config::cmdline`]).
    pub append: Option<String>,
    /// Guest RAM in bytes.
    pub memory: u64,
    pub cpus: usize,
    pub disks: Vec<DiskConfig>,
    pub net: NetConfig,
    pub serial: SerialConfig,
    pub debug_uart: bool,
    /// Stop the machine after this long (`vemu build` only; the command
    /// line has no such option).
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskConfig {
    pub path: PathBuf,
    pub read_only: bool,
    /// Writes go to a throwaway overlay (`,snapshot`).
    pub snapshot: bool,
    pub format: Format,
}

impl DiskConfig {
    pub fn options(&self) -> DiskOptions {
        DiskOptions {
            read_only: self.read_only,
            snapshot: self.snapshot,
            format: self.format,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetConfig {
    None,
    /// User-mode NAT with the given host port forwards (qemu syntax on the
    /// command line, e.g. `tcp:127.0.0.1:2222-:22`).
    User {
        hostfwd: Vec<HostFwd>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialConfig {
    Stdio,
    Unix(PathBuf),
    None,
    /// Guest output goes to this writer, no input (`vemu build`; not on
    /// the command line).
    Capture(Capture),
}

/// A shared writer for [`SerialConfig::Capture`].
#[derive(Clone)]
pub struct Capture(pub Arc<Mutex<dyn std::io::Write + Send>>);

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Capture(..)")
    }
}

impl PartialEq for Capture {
    fn eq(&self, other: &Capture) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Capture {}

impl Config {
    /// The kernel command line: `--append`, plus `console=hvc0` unless it
    /// already selects a console.
    pub fn cmdline(&self) -> String {
        let append = self.append.as_deref().unwrap_or("").trim();
        if append.split_whitespace().any(|w| w.starts_with("console=")) {
            append.to_string()
        } else if append.is_empty() {
            "console=hvc0".to_string()
        } else {
            format!("{append} console=hvc0")
        }
    }
}

/// Parse the arguments after the program name.
pub fn parse<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter().peekable();
    if args.peek().is_some_and(|a| a == "overlay") {
        args.next();
        return parse_overlay(args).map(Command::Overlay);
    }
    if args.peek().is_some_and(|a| a == "build") {
        args.next();
        return parse_build(args);
    }
    let mut kernel = None;
    let mut initrd = None;
    let mut append = None;
    let mut memory = None;
    let mut cpus = None;
    let mut disks = Vec::new();
    let mut net = None;
    let mut publish = Vec::new();
    let mut serial = None;
    let mut debug_uart = false;

    while let Some(arg) = args.next() {
        let Some(s) = arg.to_str() else {
            return Err(format!("unexpected argument {arg:?}"));
        };
        let (name, inline) = match s.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(OsString::from(v))),
            _ => (s, None),
        };
        let mut value = |what: &str| -> Result<OsString, String> {
            inline
                .clone()
                .or_else(|| args.next())
                .ok_or_else(|| format!("{name} needs a value ({what})"))
        };
        match name {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--kernel" => set_once(&mut kernel, name, PathBuf::from(value("PATH")?))?,
            "--initrd" => set_once(&mut initrd, name, PathBuf::from(value("PATH")?))?,
            "--append" => set_once(&mut append, name, utf8(name, value("CMDLINE")?)?)?,
            "--memory" | "-m" => {
                let v = utf8(name, value("SIZE")?)?;
                set_once(&mut memory, name, parse_size(&v)?)?
            }
            "--cpus" | "--smp" => {
                let v = utf8(name, value("N")?)?;
                set_once(&mut cpus, name, parse_cpus(&v)?)?
            }
            "--disk" => disks.push(parse_disk(&utf8(name, value("PATH[,OPT]...")?)?)?),
            "--net" => {
                let v = utf8(name, value("user|none")?)?;
                set_once(&mut net, name, parse_net(&v)?)?
            }
            "-p" | "--publish" => {
                let v = utf8(name, value("[HOSTADDR:]HOSTPORT:GUESTPORT[/tcp|/udp]")?)?;
                publish.push(parse_publish(&v)?)
            }
            "--serial" => {
                let v = utf8(name, value("stdio|unix:PATH|none")?)?;
                set_once(&mut serial, name, parse_serial(&v)?)?
            }
            "--debug-uart" => {
                if inline.is_some() {
                    return Err("--debug-uart takes no value".into());
                }
                debug_uart = true;
            }
            _ => return Err(format!("unknown option {s:?}")),
        }
    }

    let kernel = kernel.ok_or("--kernel is required")?;
    let net = match net {
        Some(NetConfig::None) if !publish.is_empty() => {
            return Err("-p/--publish needs the user network, not --net none".into());
        }
        Some(NetConfig::None) => NetConfig::None,
        Some(NetConfig::User { mut hostfwd }) => {
            hostfwd.extend(publish);
            NetConfig::User { hostfwd }
        }
        None => NetConfig::User { hostfwd: publish },
    };
    if let NetConfig::User { hostfwd } = &net {
        check_forwards(hostfwd)?;
    }
    Ok(Command::Run(Config {
        kernel,
        initrd,
        append,
        memory: memory.unwrap_or(DEFAULT_MEMORY),
        cpus: cpus.unwrap_or(1),
        disks,
        net,
        serial: serial.unwrap_or(SerialConfig::Stdio),
        debug_uart,
        timeout: None,
    }))
}

/// `vemu build` arguments (after the word `build`).
fn parse_build(mut args: impl Iterator<Item = OsString>) -> Result<Command, String> {
    let mut config = None;
    let mut output = None;
    let mut force = false;
    let mut cache = None;
    let mut kernel = None;
    let mut timeout = None;
    let mut verbose = false;
    while let Some(arg) = args.next() {
        let s = arg.to_str().unwrap_or("");
        let (name, inline) = match s.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(OsString::from(v))),
            _ => (s, None),
        };
        let mut value = |what: &str| -> Result<OsString, String> {
            inline
                .clone()
                .or_else(|| args.next())
                .ok_or_else(|| format!("build: {name} needs a value ({what})"))
        };
        let flag = |inline: &Option<OsString>| match inline {
            Some(_) => Err(format!("build: {name} takes no value")),
            None => Ok(()),
        };
        match name {
            "-h" | "--help" => return Ok(Command::BuildHelp),
            "-o" | "--output" => set_once(&mut output, name, PathBuf::from(value("OUT")?))?,
            "--cache" => set_once(&mut cache, name, PathBuf::from(value("DIR")?))?,
            "--kernel" => set_once(&mut kernel, name, PathBuf::from(value("PATH")?))?,
            "--timeout" => {
                let v = utf8(name, value("SECS")?)?;
                let secs = v
                    .parse::<u64>()
                    .ok()
                    .filter(|s| (10..=86_400).contains(s))
                    .ok_or_else(|| {
                        format!("build: --timeout: expected 10 to 86400 seconds, got {v:?}")
                    })?;
                set_once(&mut timeout, name, secs)?
            }
            "--force" => {
                flag(&inline)?;
                force = true;
            }
            "-v" | "--verbose" => {
                flag(&inline)?;
                verbose = true;
            }
            _ if s.starts_with('-') && s.len() > 1 => {
                return Err(format!("build: unknown option {s:?}"));
            }
            _ => {
                let msg = format!("build: unexpected argument {s:?} (one CONFIG only)");
                set_once(&mut config, "CONFIG", PathBuf::from(&arg)).map_err(|_| msg)?
            }
        }
    }
    Ok(Command::Build(vemu_build::Options {
        config: config.ok_or("build: expected a CONFIG file")?,
        output,
        force,
        cache,
        kernel,
        timeout_secs: timeout.unwrap_or(vemu_build::DEFAULT_TIMEOUT_SECS),
        verbose,
    }))
}

fn set_once<T>(slot: &mut Option<T>, name: &str, v: T) -> Result<(), String> {
    if slot.replace(v).is_some() {
        return Err(format!("{name} given more than once"));
    }
    Ok(())
}

fn utf8(name: &str, v: OsString) -> Result<String, String> {
    v.into_string()
        .map_err(|v| format!("{name}: value {:?} is not valid UTF-8", OsStr::new(&v)))
}

/// Parse a memory size: a number with an optional binary suffix K, M, G or T
/// (case-insensitive, optionally followed by `B` or `iB`). A bare number is
/// MiB, as in QEMU's `-m`.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let bad = || format!("invalid memory size {s:?} (expected e.g. 512M or 2G)");
    let t = s.trim();
    let digits = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, suffix) = t.split_at(digits);
    let n: u64 = num.parse().map_err(|_| bad())?;
    let suffix = suffix.to_ascii_lowercase();
    let unit = suffix
        .strip_suffix("ib")
        .or_else(|| suffix.strip_suffix('b'))
        .unwrap_or(&suffix);
    let shift = match unit {
        "" if suffix.is_empty() => 20,
        "" => 0, // "512B": plain bytes
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        _ => return Err(bad()),
    };
    n.checked_mul(1 << shift).filter(|&v| v > 0).ok_or_else(bad)
}

fn parse_cpus(s: &str) -> Result<usize, String> {
    match s.trim().parse::<usize>() {
        Ok(n) if (1..=MAX_CPUS).contains(&n) => Ok(n),
        _ => Err(format!("--cpus: expected 1..={MAX_CPUS}, got {s:?}")),
    }
}

/// `PATH[,ro|,rw|,snapshot|,format=raw|overlay|auto]...`. The path itself
/// must not contain a comma.
fn parse_disk(s: &str) -> Result<DiskConfig, String> {
    let mut parts = s.split(',');
    let path = parts.next().unwrap_or_default();
    if path.is_empty() {
        return Err("--disk: missing path".into());
    }
    let mut read_only = false;
    let mut snapshot = false;
    let mut format = Format::Auto;
    for opt in parts {
        match opt {
            "ro" | "readonly" => read_only = true,
            "rw" => read_only = false,
            "snapshot" => snapshot = true,
            "format=raw" => format = Format::Raw,
            "format=overlay" => format = Format::Overlay,
            "format=auto" => format = Format::Auto,
            _ => {
                return Err(format!(
                    "--disk: unknown option {opt:?} (expected ro, rw, snapshot or \
                     format=raw|overlay)"
                ));
            }
        }
    }
    if snapshot && read_only {
        return Err(format!(
            "--disk {path}: snapshot and ro together make no sense (a snapshot disk is \
             writable, and its writes are discarded at exit); use one or the other"
        ));
    }
    if snapshot && format == Format::Overlay {
        return Err(format!(
            "--disk {path}: a snapshot of an overlay would chain overlays, which is not \
             supported"
        ));
    }
    Ok(DiskConfig {
        path: PathBuf::from(path),
        read_only,
        snapshot,
        format,
    })
}

/// `vemu overlay` arguments (after the word `overlay`).
fn parse_overlay(mut args: impl Iterator<Item = OsString>) -> Result<OverlayCommand, String> {
    let sub = match args.next() {
        None => return Err("overlay: expected create or info".into()),
        Some(a) => a,
    };
    let sub = sub.to_str().unwrap_or("");
    if matches!(sub, "-h" | "--help" | "help") {
        return Ok(OverlayCommand::Help);
    }
    if !matches!(sub, "create" | "info") {
        return Err(format!(
            "overlay: unknown command {sub:?} (expected create or info)"
        ));
    }
    let mut paths = Vec::new();
    let mut block_size = None;
    while let Some(arg) = args.next() {
        let s = arg.to_str().unwrap_or("");
        let (name, inline) = match s.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (s, None),
        };
        match name {
            "-h" | "--help" => return Ok(OverlayCommand::Help),
            "--block-size" if sub == "create" => {
                let v = match inline {
                    Some(v) => v,
                    None => utf8(name, args.next().ok_or("--block-size needs a value (N)")?)?,
                };
                set_once(&mut block_size, name, parse_block_size(&v)?)?;
            }
            _ if s.starts_with('-') && s.len() > 1 => {
                return Err(format!("overlay {sub}: unknown option {s:?}"));
            }
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    match (sub, paths.len()) {
        ("create", 2) => {
            let overlay = paths.pop().unwrap();
            let base = paths.pop().unwrap();
            Ok(OverlayCommand::Create {
                base,
                overlay,
                block_size: block_size.unwrap_or(vemu_disk::DEFAULT_BLOCK_SIZE),
            })
        }
        ("create", _) => Err("overlay create: expected BASE OVERLAY".into()),
        ("info", 1) => Ok(OverlayCommand::Info {
            overlay: paths.pop().unwrap(),
        }),
        _ => Err("overlay info: expected OVERLAY".into()),
    }
}

/// A block size in bytes, with an optional K or M suffix (KiB, MiB).
pub fn parse_block_size(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let digits = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, suffix) = t.split_at(digits);
    let shift = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        _ => 64,
    };
    num.parse::<u64>()
        .ok()
        .filter(|_| shift < 64)
        .and_then(|n| n.checked_mul(1 << shift))
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&n| vemu_disk::check_block_size(n).is_ok())
        .ok_or_else(|| {
            format!(
                "--block-size: expected a power of two from {} to {}, e.g. 4K or 64K, got {s:?}",
                vemu_disk::MIN_BLOCK_SIZE,
                "2M"
            )
        })
}

fn parse_net(s: &str) -> Result<NetConfig, String> {
    if s == "none" {
        return Ok(NetConfig::None);
    }
    let mut parts = s.split(',');
    if parts.next() != Some("user") {
        return Err(format!(
            "--net: expected user[,hostfwd=SPEC]... or none, got {s:?}"
        ));
    }
    let mut hostfwd = Vec::new();
    for opt in parts {
        match opt.split_once('=') {
            Some(("hostfwd", spec)) => {
                hostfwd.push(spec.parse().map_err(|e| format!("--net user: {e}"))?)
            }
            _ => return Err(format!("--net user: unknown option {opt:?}")),
        }
    }
    Ok(NetConfig::User { hostfwd })
}

/// `-p [HOSTADDR:]HOSTPORT:GUESTPORT[/tcp|/udp]`, docker-style, except that
/// the host address defaults to 127.0.0.1: a forward stays local to the
/// host unless it names another address (0.0.0.0 for all interfaces).
fn parse_publish(s: &str) -> Result<HostFwd, String> {
    let err = |m: &str| {
        format!("-p {s:?}: {m} (expected [HOSTADDR:]HOSTPORT:GUESTPORT[/tcp|/udp], e.g. 2222:22)")
    };
    let (ports, proto) = match s.rsplit_once('/') {
        None => (s, Proto::Tcp),
        Some((p, "tcp")) => (p, Proto::Tcp),
        Some((p, "udp")) => (p, Proto::Udp),
        Some((_, other)) => return Err(err(&format!("unknown protocol {other:?}"))),
    };
    let parts: Vec<&str> = ports.split(':').collect();
    let (addr, host, guest) = match parts[..] {
        [host, guest] => (None, host, guest),
        [addr, host, guest] => (Some(addr), host, guest),
        _ => return Err(err("wrong number of fields")),
    };
    let host_addr = match addr {
        None => std::net::Ipv4Addr::LOCALHOST,
        Some(a) => a
            .parse()
            .map_err(|_| err(&format!("bad host address {a:?} (an IPv4 address)")))?,
    };
    let port = |p: &str, what: &str| match p.parse::<u16>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(err(&format!("bad {what} port {p:?} (1 to 65535)"))),
    };
    Ok(HostFwd {
        proto,
        host_addr,
        host_port: port(host, "host")?,
        guest_port: port(guest, "guest")?,
    })
}

/// Refuse two forwards of one host port (same protocol, same or overlapping
/// address: 0.0.0.0 covers every address), which could not both listen.
fn check_forwards(fwds: &[HostFwd]) -> Result<(), String> {
    for (i, a) in fwds.iter().enumerate() {
        for b in &fwds[..i] {
            let overlap = a.host_addr == b.host_addr
                || a.host_addr.is_unspecified()
                || b.host_addr.is_unspecified();
            if a.proto == b.proto && a.host_port == b.host_port && overlap {
                return Err(format!(
                    "{} host port {}:{} is forwarded twice ({a} and {b})",
                    a.proto, a.host_addr, a.host_port
                ));
            }
        }
    }
    Ok(())
}

fn parse_serial(s: &str) -> Result<SerialConfig, String> {
    match s {
        "stdio" => Ok(SerialConfig::Stdio),
        "none" => Ok(SerialConfig::None),
        _ => match s.strip_prefix("unix:") {
            Some(p) if !p.is_empty() => Ok(SerialConfig::Unix(PathBuf::from(p))),
            _ => Err(format!(
                "--serial: expected stdio, unix:PATH or none, got {s:?}"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Config, String> {
        match parse(args.iter().map(OsString::from))? {
            Command::Run(c) => Ok(c),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn publish() {
        let fwd = |args: &[&str]| -> Vec<String> {
            let mut a = vec!["--kernel", "k"];
            a.extend_from_slice(args);
            match run(&a).unwrap().net {
                NetConfig::User { hostfwd } => hostfwd.iter().map(|f| f.to_string()).collect(),
                NetConfig::None => panic!("no network"),
            }
        };
        // Local by default, tcp by default; an address and /udp when given.
        assert_eq!(fwd(&["-p", "2222:22"]), ["tcp:127.0.0.1:2222-:22"]);
        assert_eq!(
            fwd(&[
                "--publish",
                "0.0.0.0:8080:80",
                "--publish=5353:53/udp",
                "-p",
                "9:9/tcp"
            ]),
            [
                "tcp:0.0.0.0:8080-:80",
                "udp:127.0.0.1:5353-:53",
                "tcp:127.0.0.1:9-:9"
            ]
        );
        // The same as hostfwd: both kinds add up, in either order (the
        // --net ones first).
        let both = ["tcp:127.0.0.1:2222-:22", "tcp:127.0.0.1:8080-:80"];
        let net = "user,hostfwd=tcp:127.0.0.1:2222-:22";
        assert_eq!(fwd(&["--net", net, "-p", "8080:80"]), both);
        assert_eq!(fwd(&["-p", "8080:80", "--net", net]), both);
        // One host port for tcp and for udp is fine; so are two addresses.
        assert_eq!(fwd(&["-p", "53:53", "-p", "53:53/udp"]).len(), 2);
        assert_eq!(
            fwd(&["-p", "127.0.0.1:80:80", "-p", "10.0.0.1:80:81"]).len(),
            2
        );
    }

    #[test]
    fn publish_errors() {
        let e = |args: &[&str]| {
            let mut a = vec!["--kernel", "k"];
            a.extend_from_slice(args);
            run(&a).unwrap_err()
        };
        for bad in [
            "22",
            "1:2:3:4",
            "2222:22/sctp",
            "0:22",
            "2222:0",
            "70000:22",
            "x:22",
            ":2222:22",
            "localhost:2222:22",
            "2222:22/",
        ] {
            let m = e(&["-p", bad]);
            assert!(m.starts_with(&format!("-p {bad:?}: ")), "{bad}: {m}");
            assert!(m.contains("HOSTPORT:GUESTPORT"), "{bad}: {m}");
        }
        assert!(e(&["-p"]).contains("needs a value"));
        assert!(e(&["--net", "none", "-p", "2222:22"]).contains("not --net none"));
        assert!(e(&["-p", "2222:22", "--net", "none"]).contains("not --net none"));
        // A host port forwarded twice, whatever the syntax.
        let m = e(&["-p", "2222:22", "-p", "2222:23"]);
        assert!(
            m.contains("tcp host port 127.0.0.1:2222 is forwarded twice"),
            "{m}"
        );
        assert!(e(&["-p", "0.0.0.0:80:80", "-p", "80:81"]).contains("forwarded twice"));
        assert!(e(&["--net", "user,hostfwd=tcp::80-:80", "-p", "80:80"]).contains("twice"));
        assert!(e(&["--net", "user,hostfwd=udp::53-:53,hostfwd=udp::53-:54"]).contains("twice"));
    }

    #[test]
    fn defaults() {
        let c = run(&["--kernel", "Image"]).unwrap();
        assert_eq!(c.kernel, PathBuf::from("Image"));
        assert_eq!(c.memory, 1 << 30);
        assert_eq!(c.cpus, 1);
        assert_eq!(c.net, NetConfig::User { hostfwd: vec![] });
        assert_eq!(c.serial, SerialConfig::Stdio);
        assert!(!c.debug_uart);
        assert_eq!(c.cmdline(), "console=hvc0");
    }

    #[test]
    fn full() {
        let c = run(&[
            "--kernel=k",
            "--initrd",
            "i",
            "--append",
            "quiet",
            "--memory=2G",
            "--cpus",
            "4",
            "--disk",
            "a.img",
            "--disk=b.img,ro",
            "--net",
            "user,hostfwd=tcp::2222-:22,hostfwd=udp::53-:53",
            "--serial",
            "unix:/tmp/s",
            "--debug-uart",
        ])
        .unwrap();
        assert_eq!(c.initrd, Some(PathBuf::from("i")));
        assert_eq!(c.memory, 2 << 30);
        assert_eq!(c.cpus, 4);
        assert_eq!(
            c.disks,
            vec![
                DiskConfig {
                    path: "a.img".into(),
                    read_only: false,
                    snapshot: false,
                    format: Format::Auto,
                },
                DiskConfig {
                    path: "b.img".into(),
                    read_only: true,
                    snapshot: false,
                    format: Format::Auto,
                },
            ]
        );
        assert_eq!(
            c.net,
            NetConfig::User {
                hostfwd: vec![
                    "tcp::2222-:22".parse().unwrap(),
                    "udp::53-:53".parse().unwrap()
                ]
            }
        );
        assert_eq!(c.serial, SerialConfig::Unix("/tmp/s".into()));
        assert!(c.debug_uart);
        assert_eq!(c.cmdline(), "quiet console=hvc0");
    }

    #[test]
    fn cmdline_keeps_explicit_console() {
        let c = run(&["--kernel", "k", "--append", " console=ttyAMA0 earlycon "]).unwrap();
        assert_eq!(c.cmdline(), "console=ttyAMA0 earlycon");
        // A word merely containing "console=" does not count.
        let c = run(&["--kernel", "k", "--append", "xconsole=1"]).unwrap();
        assert_eq!(c.cmdline(), "xconsole=1 console=hvc0");
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1024"), Ok(1 << 30));
        assert_eq!(parse_size("512M"), Ok(512 << 20));
        assert_eq!(parse_size("512mib"), Ok(512 << 20));
        assert_eq!(parse_size("2g"), Ok(2 << 30));
        assert_eq!(parse_size("2GB"), Ok(2 << 30));
        assert_eq!(parse_size("65536K"), Ok(64 << 20));
        assert_eq!(parse_size("4096b"), Ok(4096));
        for bad in ["", "G", "1X", "-1G", "0", "1.5G", "99999999999T"] {
            assert!(parse_size(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn errors() {
        let err = |a: &[&str]| run(a).unwrap_err();
        assert!(err(&[]).contains("--kernel is required"));
        assert!(err(&["--kernel"]).contains("needs a value"));
        assert!(err(&["--kernel", "k", "--kernel", "k"]).contains("more than once"));
        assert!(err(&["--kernel", "k", "--cpus", "0"]).contains("--cpus"));
        assert!(err(&["--kernel", "k", "--cpus", "65"]).contains("--cpus"));
        assert!(err(&["--kernel", "k", "--disk", "x,rx"]).contains("unknown option"));
        assert!(err(&["--kernel", "k", "--disk", ",ro"]).contains("missing path"));
        assert!(err(&["--kernel", "k", "--net", "tap"]).contains("--net"));
        assert!(err(&["--kernel", "k", "--net", "user,foo=1"]).contains("unknown option"));
        assert!(err(&["--kernel", "k", "--net", "user,hostfwd="]).contains("invalid hostfwd"));
        assert!(err(&["--kernel", "k", "--net", "user,hostfwd=tcp::22"]).contains("hostfwd"));
        assert!(err(&["--kernel", "k", "--serial", "unix:"]).contains("--serial"));
        assert!(err(&["--kernel", "k", "--serial", "pty"]).contains("--serial"));
        assert!(err(&["--kernel", "k", "--debug-uart=1"]).contains("no value"));
        assert!(err(&["--kernel", "k", "--bogus"]).contains("unknown option"));
        assert!(err(&["--kernel", "k", "stray"]).contains("unknown option"));
    }

    #[test]
    fn help_and_version() {
        let p = |a: &[&str]| parse(a.iter().map(OsString::from)).unwrap();
        assert_eq!(p(&["--help"]), Command::Help);
        assert_eq!(p(&["--kernel", "k", "-h"]), Command::Help);
        assert_eq!(p(&["--version"]), Command::Version);
    }

    #[test]
    fn disk_options() {
        let d = |s: &str| parse_disk(s);
        let c = d("g.raw,snapshot").unwrap();
        assert!(c.snapshot && !c.read_only && c.format == Format::Auto);
        let c = d("x.vov,ro,format=overlay").unwrap();
        assert!(c.read_only && c.format == Format::Overlay);
        assert_eq!(d("odd.img,format=raw").unwrap().format, Format::Raw);
        assert!(
            d("g.raw,snapshot,ro")
                .unwrap_err()
                .contains("make no sense")
        );
        assert!(
            d("g.raw,ro,snapshot")
                .unwrap_err()
                .contains("make no sense")
        );
        assert!(
            d("g.vov,snapshot,format=overlay")
                .unwrap_err()
                .contains("chain")
        );
        assert!(
            d("g.raw,format=qcow2")
                .unwrap_err()
                .contains("unknown option")
        );
        let o = d("a,snapshot").unwrap().options();
        assert!(o.snapshot && !o.read_only);
    }

    #[test]
    fn overlay_subcommand() {
        let p = |a: &[&str]| parse(a.iter().map(OsString::from));
        assert_eq!(
            p(&["overlay", "create", "g.raw", "vm.vov"]).unwrap(),
            Command::Overlay(OverlayCommand::Create {
                base: "g.raw".into(),
                overlay: "vm.vov".into(),
                block_size: 4096,
            })
        );
        for args in [
            &["overlay", "create", "--block-size", "64K", "g", "o"][..],
            &["overlay", "create", "g", "o", "--block-size=65536"],
        ] {
            assert!(matches!(
                p(args).unwrap(),
                Command::Overlay(OverlayCommand::Create {
                    block_size: 65536,
                    ..
                })
            ));
        }
        assert_eq!(
            p(&["overlay", "info", "vm.vov"]).unwrap(),
            Command::Overlay(OverlayCommand::Info {
                overlay: "vm.vov".into()
            })
        );
        for help in [&["overlay", "--help"][..], &["overlay", "info", "-h"]] {
            assert_eq!(p(help).unwrap(), Command::Overlay(OverlayCommand::Help));
        }
        let err = |a: &[&str]| p(a).unwrap_err();
        assert!(err(&["overlay"]).contains("expected create or info"));
        assert!(err(&["overlay", "mkdir"]).contains("unknown command"));
        assert!(err(&["overlay", "create", "g"]).contains("BASE OVERLAY"));
        assert!(err(&["overlay", "info"]).contains("expected OVERLAY"));
        assert!(err(&["overlay", "info", "a", "--block-size", "4K"]).contains("unknown option"));
        assert!(
            err(&["overlay", "create", "g", "o", "--block-size", "3000"]).contains("power of two")
        );
        assert!(
            err(&["overlay", "create", "g", "o", "--block-size", "4M"]).contains("power of two")
        );
        // Running a VM is unaffected; "overlay" elsewhere is a stray word.
        assert!(matches!(p(&["--kernel", "k"]).unwrap(), Command::Run(_)));
        assert!(err(&["--kernel", "k", "overlay"]).contains("unknown option"));
    }

    #[test]
    fn build_subcommand() {
        let p = |a: &[&str]| parse(a.iter().map(OsString::from));
        let Command::Build(o) = p(&["build", "a.conf"]).unwrap() else {
            panic!("not a build");
        };
        assert_eq!(
            o,
            vemu_build::Options {
                config: "a.conf".into(),
                output: None,
                force: false,
                cache: None,
                kernel: None,
                timeout_secs: 900,
                verbose: false,
            }
        );
        let Command::Build(o) = p(&[
            "build",
            "--force",
            "-o",
            "x.raw",
            "--cache=/c",
            "--kernel",
            "K",
            "--timeout",
            "60",
            "-v",
            "a.conf",
        ])
        .unwrap() else {
            panic!("not a build");
        };
        assert_eq!(o.output, Some("x.raw".into()));
        assert_eq!(o.cache, Some("/c".into()));
        assert_eq!(o.kernel, Some("K".into()));
        assert!(o.force && o.verbose);
        assert_eq!(o.timeout_secs, 60);
        assert_eq!(p(&["build", "--help"]).unwrap(), Command::BuildHelp);
        let err = |a: &[&str]| p(a).unwrap_err();
        assert!(err(&["build"]).contains("expected a CONFIG"));
        assert!(err(&["build", "a", "b"]).contains("one CONFIG only"));
        assert!(err(&["build", "a", "--timeout", "5"]).contains("10 to 86400"));
        assert!(err(&["build", "a", "--bogus"]).contains("unknown option"));
        assert!(err(&["build", "a", "--force=1"]).contains("takes no value"));
        assert!(err(&["build", "a", "-o"]).contains("needs a value"));
        assert!(usage().contains("vemu build CONFIG"));
        assert!(build_usage().contains("--timeout SECS"));
    }

    #[test]
    fn block_sizes() {
        assert_eq!(parse_block_size("512"), Ok(512));
        assert_eq!(parse_block_size("4k"), Ok(4096));
        assert_eq!(parse_block_size("64KiB"), Ok(65536));
        assert_eq!(parse_block_size("2M"), Ok(2 << 20));
        for bad in ["", "K", "256", "1000", "4G", "99999999999999999999", "4X"] {
            assert!(parse_block_size(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn net_none() {
        let c = run(&["--kernel", "k", "--net", "none"]).unwrap();
        assert_eq!(c.net, NetConfig::None);
        let c = run(&["--kernel", "k", "--net", "user"]).unwrap();
        assert_eq!(c.net, NetConfig::User { hostfwd: vec![] });
    }
}
