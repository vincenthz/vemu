//! The `vemu build` configuration file.
//!
//! Line-oriented: `key = value`, `[section]` headers, and comment lines
//! starting with `#` (a `#` later in a line is part of the value). Values
//! are words separated by spaces; a word may be double-quoted to hold
//! spaces (`"my key.pub"`, with `\"` and `\\` inside quotes). List keys
//! take several words and may be repeated; other keys take one word and
//! may appear once. Unknown keys and sections, repeated keys and sections,
//! and bad values are errors naming `file:line`.
//!
//! Relative host paths are resolved against the config file's directory;
//! `~` and `~/...` expand to `$HOME`.
//!
//! ```text
//! arch = aarch64            # default: the host's (must be the host's)
//! size = 1G                 # image size (default 1G)
//! alpine = latest-stable    # or v3.24, or 3.24.4
//! mirror = https://dl-cdn.alpinelinux.org/alpine
//! sha256 = <hex>            # pin the minirootfs
//! insecure = false          # allow an http:// mirror
//! community = false         # also enable the community repository
//! kernel = path             # builder kernel (also the one to boot the image)
//! modules = path            # kernel modules tarball (lib/modules/...)
//! hostname = vemu
//! timezone = UTC
//! output = path             # default: <config name>.raw next to the config
//! [network]   dhcp = true, ntp = true
//! [ssh]       enable = false, server = openssh|dropbear, authorized_keys = path...
//! [packages]  list = name...
//! [files]     /path/in/image = host/path [mode]
//! [run]       script = host/path
//! ```

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::release::Spec;
use crate::sha256::is_hex_digest;

/// Default Alpine mirror.
pub const DEFAULT_MIRROR: &str = "https://dl-cdn.alpinelinux.org/alpine";
/// Default image size.
pub const DEFAULT_SIZE: u64 = 1 << 30;
/// Smallest and largest image sizes.
pub const MIN_SIZE: u64 = 128 << 20;
pub const MAX_SIZE: u64 = 2 << 40;

/// A place in a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loc {
    pub file: PathBuf,
    pub line: usize,
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file.display(), self.line)
    }
}

/// A config error, at a place in the file when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub loc: Option<Loc>,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.loc {
            Some(l) => write!(f, "{l}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn at(loc: &Loc, message: impl Into<String>) -> Error {
        Error {
            loc: Some(loc.clone()),
            message: message.into(),
        }
    }
}

/// Guest (and host) architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }

    /// The host's architecture, if vemu supports it.
    pub fn host() -> Option<Arch> {
        match std::env::consts::ARCH {
            "aarch64" => Some(Arch::Aarch64),
            "x86_64" => Some(Arch::X86_64),
            _ => None,
        }
    }

    fn parse(s: &str) -> Option<Arch> {
        match s {
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            "x86_64" | "amd64" => Some(Arch::X86_64),
            _ => None,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshServer {
    OpenSsh,
    Dropbear,
}

/// A host path from the config, with where it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPath {
    pub path: PathBuf,
    pub loc: Loc,
}

/// One `[files]` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Absolute path in the image (checked: no `..`, `.` or empty parts).
    pub image: String,
    pub host: HostPath,
    /// Explicit mode; default: the host file's permission bits.
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The config file.
    pub path: PathBuf,
    pub arch: Arch,
    pub size: u64,
    pub alpine: Spec,
    pub mirror: String,
    pub insecure: bool,
    pub sha256: Option<String>,
    pub community: bool,
    pub kernel: Option<HostPath>,
    pub modules: Option<HostPath>,
    pub hostname: String,
    pub timezone: String,
    /// The output image (default: `<config stem>.raw` in the config's
    /// directory).
    pub output: PathBuf,
    pub dhcp: bool,
    pub ntp: bool,
    pub ssh: Option<SshServer>,
    pub authorized_keys: Vec<HostPath>,
    pub packages: Vec<String>,
    pub files: Vec<FileEntry>,
    pub run: Option<HostPath>,
}

/// Read and parse the config file at `path`.
pub fn load(path: &Path) -> Result<Config, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| Error {
        loc: None,
        message: format!("cannot read {}: {e}", path.display()),
    })?;
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    let host = Arch::host().ok_or_else(|| Error {
        loc: None,
        message: format!("unsupported host architecture {}", std::env::consts::ARCH),
    })?;
    parse(path, &text, home.as_deref(), host)
}

const SECTIONS: [&str; 5] = ["network", "ssh", "packages", "files", "run"];

/// Parse config `text` read from `path`; `home` expands `~`, `host` is the
/// host's architecture (the only one that can be built).
pub fn parse(path: &Path, text: &str, home: Option<&Path>, host: Arch) -> Result<Config, Error> {
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let dir = if dir.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        dir
    };
    let ctx = Ctx { dir: &dir, home };
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    let mut c = Config {
        path: path.to_path_buf(),
        arch: host,
        size: DEFAULT_SIZE,
        alpine: Spec::LatestStable,
        mirror: DEFAULT_MIRROR.to_string(),
        insecure: false,
        sha256: None,
        community: false,
        kernel: None,
        modules: None,
        hostname: "vemu".into(),
        timezone: "UTC".into(),
        output: dir.join(format!("{stem}.raw")),
        dhcp: true,
        ntp: true,
        ssh: None,
        authorized_keys: Vec::new(),
        packages: Vec::new(),
        files: Vec::new(),
        run: None,
    };
    let mut ssh_enable = None;
    let mut ssh_server = None;
    let mut mirror_loc = None;
    let mut section = String::new();
    let mut seen_sections = HashSet::new();
    let mut seen_keys: HashSet<(String, String)> = HashSet::new();

    for (n, raw) in text.lines().enumerate() {
        let loc = Loc {
            file: path.to_path_buf(),
            line: n + 1,
        };
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest.strip_suffix(']').map(str::trim).ok_or_else(|| {
                Error::at(
                    &loc,
                    format!("bad section header {line:?} (expected [name])"),
                )
            })?;
            if !SECTIONS.contains(&name) {
                return Err(Error::at(
                    &loc,
                    format!(
                        "unknown section [{name}] (expected one of [{}])",
                        SECTIONS.join("], [")
                    ),
                ));
            }
            if !seen_sections.insert(name.to_string()) {
                return Err(Error::at(&loc, format!("section [{name}] appears twice")));
            }
            section = name.to_string();
            continue;
        }
        let (key, words) = split_line(line).map_err(|m| Error::at(&loc, m))?;
        let where_ = if section.is_empty() {
            String::new()
        } else {
            format!("[{section}] ")
        };
        let list_key = matches!(
            (section.as_str(), key.as_str()),
            ("ssh", "authorized_keys") | ("packages", "list")
        );
        if section != "files" && !list_key && !seen_keys.insert((section.clone(), key.clone())) {
            return Err(Error::at(&loc, format!("{where_}{key} is given twice")));
        }
        let one = || -> Result<&str, Error> {
            match words.as_slice() {
                [w] => Ok(w.as_str()),
                [] => Err(Error::at(&loc, format!("{where_}{key} needs a value"))),
                _ => Err(Error::at(
                    &loc,
                    format!(
                        "{where_}{key} takes one value, got {} (quote a value that has spaces)",
                        words.len()
                    ),
                )),
            }
        };
        let bool_ = || -> Result<bool, Error> {
            let v = one()?;
            parse_bool(v).ok_or_else(|| {
                Error::at(
                    &loc,
                    format!("{where_}{key}: expected true or false, got {v:?}"),
                )
            })
        };
        let path_ = |v: &str| -> Result<HostPath, Error> {
            Ok(HostPath {
                path: ctx
                    .resolve(v)
                    .map_err(|m| Error::at(&loc, format!("{where_}{key}: {m}")))?,
                loc: loc.clone(),
            })
        };
        match (section.as_str(), key.as_str()) {
            ("", "arch") => {
                let v = one()?;
                let arch = Arch::parse(v).ok_or_else(|| {
                    Error::at(&loc, format!("arch: expected aarch64 or x86_64, got {v:?}"))
                })?;
                if arch != host {
                    return Err(Error::at(
                        &loc,
                        format!(
                            "arch = {arch}, but this host is {host}: vemu has no CPU emulation, so the builder VM \
                             (and the image) must be the host's architecture. Build {arch} images on {} host",
                            match arch {
                                Arch::X86_64 => "an x86_64 Linux (KVM)",
                                Arch::Aarch64 =>
                                    "an aarch64 (a Mac with Apple silicon, or aarch64 Linux with KVM)",
                            }
                        ),
                    ));
                }
                c.arch = arch;
            }
            ("", "size") => {
                let v = one()?;
                c.size = parse_size(v).map_err(|m| Error::at(&loc, format!("size: {m}")))?;
            }
            ("", "alpine") => {
                c.alpine =
                    Spec::parse(one()?).map_err(|m| Error::at(&loc, format!("alpine: {m}")))?
            }
            ("", "mirror") => {
                let v = one()?.trim_end_matches('/');
                if !(v.starts_with("https://") || v.starts_with("http://"))
                    || v.len() < 9
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_graphic() && !b"\"'`\\$;<>|&(){}".contains(&b))
                {
                    return Err(Error::at(
                        &loc,
                        format!("mirror: expected an https:// URL, got {v:?}"),
                    ));
                }
                c.mirror = v.to_string();
                mirror_loc = Some(loc.clone());
            }
            ("", "insecure") => c.insecure = bool_()?,
            ("", "sha256") => {
                let v = one()?;
                if !is_hex_digest(v) {
                    return Err(Error::at(
                        &loc,
                        format!("sha256: expected 64 hex digits, got {v:?}"),
                    ));
                }
                c.sha256 = Some(v.to_ascii_lowercase());
            }
            ("", "community") => c.community = bool_()?,
            ("", "kernel") => c.kernel = Some(path_(one()?)?),
            ("", "modules") => c.modules = Some(path_(one()?)?),
            ("", "hostname") => {
                let v = one()?;
                if !is_hostname(v) {
                    return Err(Error::at(
                        &loc,
                        format!(
                            "hostname: {v:?} is not a valid host name (letters, digits and '-', dot-separated labels of up to 63, at most {HOST_NAME_MAX} in all)"
                        ),
                    ));
                }
                c.hostname = v.to_string();
            }
            ("", "timezone") => {
                let v = one()?;
                if !is_timezone(v) {
                    return Err(Error::at(
                        &loc,
                        format!(
                            "timezone: expected a zone name like UTC or Europe/Paris, got {v:?}"
                        ),
                    ));
                }
                c.timezone = v.to_string();
            }
            ("", "output") => c.output = path_(one()?)?.path,
            ("network", "dhcp") => c.dhcp = bool_()?,
            ("network", "ntp") => c.ntp = bool_()?,
            ("ssh", "enable") => ssh_enable = Some((bool_()?, loc.clone())),
            ("ssh", "server") => {
                ssh_server = Some(match one()? {
                    "openssh" => SshServer::OpenSsh,
                    "dropbear" => SshServer::Dropbear,
                    v => {
                        return Err(Error::at(
                            &loc,
                            format!("[ssh] server: expected openssh or dropbear, got {v:?}"),
                        ));
                    }
                })
            }
            ("ssh", "authorized_keys") => {
                if words.is_empty() {
                    return Err(Error::at(&loc, "[ssh] authorized_keys needs a value"));
                }
                for w in &words {
                    c.authorized_keys.push(path_(w)?);
                }
            }
            ("packages", "list") => {
                if words.is_empty() {
                    return Err(Error::at(&loc, "[packages] list needs a value"));
                }
                for w in words.iter() {
                    if !is_package(w) {
                        return Err(Error::at(
                            &loc,
                            format!("[packages] list: {w:?} is not a package name"),
                        ));
                    }
                    if !c.packages.contains(w) {
                        c.packages.push(w.clone());
                    }
                }
            }
            ("files", image) => {
                let image = check_image_path(image)
                    .map_err(|m| Error::at(&loc, format!("[files] {image}: {m}")))?;
                if c.files.iter().any(|f| f.image == image) {
                    return Err(Error::at(&loc, format!("[files] {image} is given twice")));
                }
                let (host_path, mode) = match words.as_slice() {
                    [h] => (h, None),
                    [h, m] => (
                        h,
                        Some(parse_mode(m).ok_or_else(|| {
                            Error::at(
                                &loc,
                                format!(
                                    "[files] {image}: bad mode {m:?} (expected octal, like 0644)"
                                ),
                            )
                        })?),
                    ),
                    _ => {
                        return Err(Error::at(
                            &loc,
                            format!("[files] {image}: expected `= host/path [mode]`"),
                        ));
                    }
                };
                let host = HostPath {
                    path: ctx
                        .resolve(host_path)
                        .map_err(|m| Error::at(&loc, format!("[files] {image}: {m}")))?,
                    loc: loc.clone(),
                };
                c.files.push(FileEntry { image, host, mode });
            }
            ("run", "script") => c.run = Some(path_(one()?)?),
            (s, k) => {
                let known = match s {
                    "" => {
                        "arch, size, alpine, mirror, sha256, insecure, community, kernel, modules, hostname, timezone, output"
                    }
                    "network" => "dhcp, ntp",
                    "ssh" => "enable, server, authorized_keys",
                    "packages" => "list",
                    _ => "script",
                };
                let what = if s.is_empty() {
                    "top-level key".to_string()
                } else {
                    format!("key in [{s}]")
                };
                return Err(Error::at(
                    &loc,
                    format!("unknown {what} {k:?} (expected one of: {known})"),
                ));
            }
        }
    }

    if !c.insecure && c.mirror.starts_with("http://") {
        let loc = mirror_loc.expect("set with the mirror");
        return Err(Error::at(
            &loc,
            "mirror: http:// is not authenticated; use an https:// mirror (or set insecure = true, \
             and then pin sha256 =, since the release index is not trustworthy either)",
        ));
    }
    match ssh_enable {
        Some((true, loc)) => {
            if c.authorized_keys.is_empty() {
                return Err(Error::at(
                    &loc,
                    "[ssh] enable = true needs authorized_keys: root logs in with a key only (there is no password)",
                ));
            }
            c.ssh = Some(ssh_server.unwrap_or(SshServer::OpenSsh));
        }
        _ => {
            if let Some(k) = c.authorized_keys.first() {
                return Err(Error::at(
                    &k.loc,
                    "[ssh] authorized_keys is set but enable is not true",
                ));
            }
        }
    }
    Ok(c)
}

struct Ctx<'a> {
    dir: &'a Path,
    home: Option<&'a Path>,
}

impl Ctx<'_> {
    /// A host path from the config: `~` expanded, relative to the config's
    /// directory.
    fn resolve(&self, v: &str) -> Result<PathBuf, String> {
        if v == "~" || v.starts_with("~/") {
            let home = self.home.ok_or("~ needs $HOME, which is not set")?;
            return Ok(match v.strip_prefix("~/") {
                Some(rest) => home.join(rest),
                None => home.to_path_buf(),
            });
        }
        if v.starts_with('~') {
            return Err(format!("{v:?}: only ~ and ~/ are expanded (not ~user)"));
        }
        let p = Path::new(v);
        Ok(if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.dir.join(p)
        })
    }
}

/// `key = words...`: the key is a bare word up to `=` or whitespace, or
/// a quoted word (for `[files]` image paths with spaces).
fn split_line(line: &str) -> Result<(String, Vec<String>), String> {
    let (key, rest) = if line.starts_with('"') {
        let (k, rest) = quoted(line)?;
        (k, rest)
    } else {
        let end = line
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(line.len());
        (line[..end].to_string(), &line[end..])
    };
    let rest = rest.trim_start();
    let Some(value) = rest.strip_prefix('=') else {
        return Err(format!("expected `key = value`, got {line:?}"));
    };
    if key.is_empty() {
        return Err(format!("missing key before '=' in {line:?}"));
    }
    Ok((key, words(value)?))
}

/// A double-quoted word at the start of `s` and the rest after it.
fn quoted(s: &str) -> Result<(String, &str), String> {
    let mut out = String::new();
    let mut chars = s.char_indices().skip(1);
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((out, &s[i + 1..])),
            '\\' => match chars.next() {
                Some((_, c @ ('"' | '\\'))) => out.push(c),
                _ => return Err("in quotes, \\ may only escape \" or \\".into()),
            },
            c => out.push(c),
        }
    }
    Err(format!("unterminated quote in {s:?}"))
}

/// Split a value into words (spaces separate; double quotes group).
fn words(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        if rest.starts_with('"') {
            let (w, r) = quoted(rest)?;
            if r.starts_with(|c: char| !c.is_whitespace()) {
                return Err(format!("expected a space after the quoted value in {s:?}"));
            }
            out.push(w);
            rest = r.trim_start();
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let w = &rest[..end];
            if w.contains('"') {
                return Err(format!("stray quote in {w:?}"));
            }
            out.push(w.to_string());
            rest = rest[end..].trim_start();
        }
    }
    Ok(out)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// An image size: a number with a K, M, G or T suffix (binary units, an
/// optional trailing `B`/`iB`); a bare number is MiB. A whole number of
/// MiB from 128M to 2T.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let bad = || format!("invalid size {s:?} (expected e.g. 1G or 1536M)");
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, suffix) = s.split_at(digits);
    let n: u64 = num.parse().map_err(|_| bad())?;
    let lower = suffix.to_ascii_lowercase();
    let unit = lower
        .strip_suffix("ib")
        .or_else(|| lower.strip_suffix('b'))
        .unwrap_or(&lower);
    let shift = match unit {
        "" if lower.is_empty() => 20,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        _ => return Err(bad()),
    };
    let v = n.checked_mul(1 << shift).ok_or_else(bad)?;
    if v % (1 << 20) != 0 {
        return Err(format!("{s:?} is not a whole number of MiB"));
    }
    if !(MIN_SIZE..=MAX_SIZE).contains(&v) {
        return Err(format!("{s:?} is out of range (128M to 2T)"));
    }
    Ok(v)
}

/// Linux's limit on the host name (`__NEW_UTS_LEN`).
pub const HOST_NAME_MAX: usize = 64;

/// An octal mode, at most 0o7777.
fn parse_mode(s: &str) -> Option<u32> {
    let digits = s.strip_prefix("0o").unwrap_or(s);
    if digits.is_empty() || digits.len() > 5 {
        return None;
    }
    u32::from_str_radix(digits, 8).ok().filter(|&m| m <= 0o7777)
}

/// An RFC 1123 host name that Linux can set: at most 64 bytes in all
/// (`sethostname(2)` refuses longer ones with EINVAL, the UTS nodename
/// limit), labels of at most 63.
pub fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= HOST_NAME_MAX
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// A tz database name (`UTC`, `Europe/Paris`, `Etc/GMT+5`).
pub fn is_timezone(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('/')
        && !s.ends_with('/')
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+-/".contains(&b))
}

/// An apk world entry: a name, optionally with a version constraint or a
/// repository tag (`curl`, `py3-pip`, `busybox=1.37.0-r31`, `foo@testing`).
pub fn is_package(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-=<>~@:".contains(&b))
}

/// An absolute path in the image: no `..`, `.` or empty components, no
/// control characters, not `/` itself.
pub fn check_image_path(s: &str) -> Result<String, String> {
    if !s.starts_with('/') {
        return Err("the path in the image must be absolute".into());
    }
    let parts: Vec<&str> = s[1..].split('/').collect();
    if parts.contains(&"..") {
        return Err("the path in the image must not contain '..'".into());
    }
    if parts.iter().any(|p| p.is_empty() || *p == ".") || s.chars().any(char::is_control) {
        return Err(
            "the path in the image must be clean (no '//', '.' or control characters)".into(),
        );
    }
    if parts.is_empty() || s == "/" {
        return Err("cannot replace /".into());
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_parses() {
        let text = include_str!("../../../examples/alpine.conf");
        let c = parse(
            Path::new("/repo/examples/alpine.conf"),
            text,
            Some(Path::new("/home/me")),
            Arch::Aarch64,
        )
        .unwrap();
        assert_eq!(c.output, PathBuf::from("/repo/examples/alpine.raw"));
        assert_eq!(
            c.kernel.unwrap().path,
            PathBuf::from("/repo/examples/../testdata/Image")
        );
        assert_eq!(c.ssh, Some(SshServer::OpenSsh));
        assert_eq!(
            c.authorized_keys[0].path,
            PathBuf::from("/home/me/.ssh/id_ed25519.pub")
        );
        assert_eq!(c.packages, ["curl", "ca-certificates"]);
        assert_eq!((c.hostname.as_str(), c.dhcp, c.ntp), ("alpine", true, true));
    }

    fn p(text: &str) -> Result<Config, Error> {
        parse(
            Path::new("/cfg/dir/my.conf"),
            text,
            Some(Path::new("/home/me")),
            Arch::Aarch64,
        )
    }

    fn e(text: &str) -> String {
        p(text).unwrap_err().to_string()
    }

    #[test]
    fn defaults() {
        let c = p("# nothing\n\n").unwrap();
        assert_eq!(c.arch, Arch::Aarch64);
        assert_eq!(c.size, 1 << 30);
        assert_eq!(c.alpine, Spec::LatestStable);
        assert_eq!(c.mirror, DEFAULT_MIRROR);
        assert!(!c.insecure && !c.community && c.sha256.is_none());
        assert_eq!((c.hostname.as_str(), c.timezone.as_str()), ("vemu", "UTC"));
        assert_eq!(c.output, PathBuf::from("/cfg/dir/my.raw"));
        assert!(c.dhcp && c.ntp);
        assert!(c.ssh.is_none() && c.authorized_keys.is_empty());
        assert!(c.packages.is_empty() && c.files.is_empty() && c.run.is_none());
        assert!(c.kernel.is_none() && c.modules.is_none());
        // A config in the current directory.
        let c = parse(Path::new("x.conf"), "", None, Arch::X86_64).unwrap();
        assert_eq!(c.output, PathBuf::from("./x.raw"));
        assert_eq!(c.arch, Arch::X86_64);
    }

    #[test]
    fn full() {
        let c = p(r#"
arch = arm64
size = 2G
alpine = v3.24
mirror = https://mirror.example/alpine/
sha256 = 4B14C18F7E90A063B61462EA1462A5732C154BF6ADAD594974FE6487CD98A8DE
community = yes
kernel = ../k/Image
modules = ~/mods.tar.gz
hostname = web-1.lan
timezone = Europe/Paris
output = /images/out.raw

[network]
dhcp = true
ntp = off

[ssh]
enable = true
server = dropbear
authorized_keys = ~/.ssh/id_ed25519.pub "keys/with space.pub"
authorized_keys = /abs/k.pub

[packages]
list = curl  htop
list = py3-pip curl busybox=1.37.0-r31

[files]
/etc/motd = motd.txt
"/opt/my app/run" = bin/run 0755
/usr/local/bin/tool = /abs/tool 4755

[run]
script = setup.sh
"#)
        .unwrap();
        assert_eq!(c.size, 2 << 30);
        assert_eq!(c.alpine, Spec::Branch("v3.24".into()));
        assert_eq!(c.mirror, "https://mirror.example/alpine");
        assert_eq!(
            c.sha256.as_deref(),
            Some("4b14c18f7e90a063b61462ea1462a5732c154bf6adad594974fe6487cd98a8de")
        );
        assert!(c.community);
        assert_eq!(
            c.kernel.as_ref().unwrap().path,
            PathBuf::from("/cfg/dir/../k/Image")
        );
        assert_eq!(c.kernel.as_ref().unwrap().loc.line, 8);
        assert_eq!(
            c.modules.unwrap().path,
            PathBuf::from("/home/me/mods.tar.gz")
        );
        assert_eq!(c.hostname, "web-1.lan");
        assert_eq!(c.timezone, "Europe/Paris");
        assert_eq!(c.output, PathBuf::from("/images/out.raw"));
        assert!(c.dhcp && !c.ntp);
        assert_eq!(c.ssh, Some(SshServer::Dropbear));
        let keys: Vec<_> = c.authorized_keys.iter().map(|k| k.path.clone()).collect();
        assert_eq!(
            keys,
            [
                PathBuf::from("/home/me/.ssh/id_ed25519.pub"),
                "/cfg/dir/keys/with space.pub".into(),
                "/abs/k.pub".into()
            ]
        );
        assert_eq!(
            c.packages,
            ["curl", "htop", "py3-pip", "busybox=1.37.0-r31"]
        );
        assert_eq!(c.files.len(), 3);
        assert_eq!(
            (c.files[0].image.as_str(), c.files[0].mode),
            ("/etc/motd", None)
        );
        assert_eq!(c.files[0].host.path, PathBuf::from("/cfg/dir/motd.txt"));
        assert_eq!(
            (c.files[1].image.as_str(), c.files[1].mode),
            ("/opt/my app/run", Some(0o755))
        );
        assert_eq!(c.files[2].mode, Some(0o4755));
        assert_eq!(c.files[2].host.loc.line, 31);
        assert_eq!(c.run.unwrap().path, PathBuf::from("/cfg/dir/setup.sh"));
    }

    /// Every error names the file and line.
    #[test]
    fn errors_have_file_and_line() {
        let cases: &[(&str, usize, &str)] = &[
            (
                "size = 1G\nbogus = 1\n",
                2,
                "unknown top-level key \"bogus\"",
            ),
            ("[network]\nssh = 1\n", 2, "unknown key in [network]"),
            ("\n[weird]\n", 2, "unknown section [weird]"),
            ("[ssh]\n[ssh]\n", 2, "appears twice"),
            ("[ssh\n", 1, "bad section header"),
            ("size = 1G\nsize = 2G\n", 2, "size is given twice"),
            ("size = huge\n", 1, "invalid size"),
            ("size = 64M\n", 1, "out of range"),
            ("size = 1536K\n", 1, "whole number of MiB"),
            (
                "arch = x86_64\n",
                1,
                "Build x86_64 images on an x86_64 Linux (KVM) host",
            ),
            ("arch = riscv64\n", 1, "expected aarch64 or x86_64"),
            ("alpine = edge\n", 1, "edge has no releases"),
            ("alpine = 3.x\n", 1, "expected latest-stable"),
            ("mirror = ftp://x\n", 1, "expected an https:// URL"),
            (
                "mirror = http://plain.example/alpine\n",
                1,
                "not authenticated",
            ),
            ("sha256 = abc\n", 1, "64 hex digits"),
            ("community = maybe\n", 1, "expected true or false"),
            ("hostname = bad_name\n", 1, "not a valid host name"),
            ("hostname = a b\n", 1, "takes one value"),
            ("hostname =\n", 1, "needs a value"),
            ("timezone = ../etc/passwd\n", 1, "zone name"),
            ("kernel = ~bob/Image\n", 1, "~user"),
            ("just a line\n", 1, "expected `key = value`"),
            ("= value\n", 1, "missing key"),
            ("hostname = \"unterminated\n", 1, "unterminated quote"),
            ("[ssh]\nenable = true\n", 2, "needs authorized_keys"),
            ("[ssh]\nauthorized_keys = k.pub\n", 2, "enable is not true"),
            (
                "[ssh]\nserver = telnet\n",
                2,
                "expected openssh or dropbear",
            ),
            ("[packages]\nlist = good -bad\n", 2, "not a package name"),
            ("[packages]\nlist = a;rm\n", 2, "not a package name"),
            ("[files]\netc/x = y\n", 2, "must be absolute"),
            ("[files]\n/etc/../x = y\n", 2, "'..'"),
            ("[files]\n/etc//x = y\n", 2, "clean"),
            ("[files]\n/x = y 999\n", 2, "bad mode"),
            (
                "[files]\n/x = y 0644 extra\n",
                2,
                "expected `= host/path [mode]`",
            ),
            ("[files]\n/x = a\n/x = b\n", 3, "given twice"),
            ("[run]\nscript = a\nscript = b\n", 3, "given twice"),
            ("[run]\nexec = a\n", 2, "unknown key in [run]"),
        ];
        for &(text, line, want) in cases {
            let msg = e(text);
            assert!(
                msg.starts_with(&format!("/cfg/dir/my.conf:{line}: ")),
                "{text:?}: {msg}"
            );
            assert!(msg.contains(want), "{text:?}: {msg}");
        }
        // http:// is fine with insecure = true (in either order).
        assert!(p("mirror = http://plain.example/alpine\ninsecure = true\n").is_ok());
        assert!(p("insecure = true\nmirror = http://plain.example/alpine\n").is_ok());
        // ~ without $HOME.
        let msg = parse(Path::new("a.conf"), "kernel = ~/k\n", None, Arch::Aarch64)
            .unwrap_err()
            .to_string();
        assert!(
            msg.starts_with("a.conf:1: ") && msg.contains("$HOME"),
            "{msg}"
        );
    }

    #[test]
    fn values() {
        assert_eq!(parse_size("1024"), Ok(1 << 30));
        assert_eq!(parse_size("1536M"), Ok(1536 << 20));
        assert_eq!(parse_size("2GiB"), Ok(2 << 30));
        assert_eq!(parse_mode("0644"), Some(0o644));
        assert_eq!(parse_mode("755"), Some(0o755));
        assert_eq!(parse_mode("17777"), None);
        assert_eq!(parse_mode("8"), None);
        assert!(is_hostname("a") && is_hostname("x-1.example.org"));
        assert!(!is_hostname("-a") && !is_hostname("a..b") && !is_hostname(&"a".repeat(64)));
        // Linux caps the whole name at 64 bytes, whatever the labels.
        let n64 = format!("{}.{}", "a".repeat(62), "b");
        let n65 = format!("{}.{}", "a".repeat(62), "bb");
        assert!(is_hostname(&n64) && !is_hostname(&n65));
        assert!(!is_hostname(&format!(
            "{}.{}",
            "a".repeat(63),
            "b".repeat(20)
        )));
        let e = p(&format!("hostname = {n65}\n")).unwrap_err();
        assert_eq!(e.loc.as_ref().unwrap().line, 1);
        assert!(e.to_string().contains("64"), "{e}");
        assert!(is_timezone("America/Argentina/Buenos_Aires") && is_timezone("Etc/GMT+5"));
        assert!(!is_timezone("Europe/../x") && !is_timezone("/UTC") && !is_timezone("a b"));
        assert_eq!(words(r#"a "b c" "d\"e""#).unwrap(), ["a", "b c", "d\"e"]);
        assert!(words(r#""a"b"#).is_err());
        assert!(words(r#"a"b"#).is_err());
        assert_eq!(check_image_path("/etc/motd"), Ok("/etc/motd".into()));
        assert!(check_image_path("/").is_err());
        assert!(check_image_path("/a/./b").is_err());
        // A '#' after the start of a line is part of the value.
        assert_eq!(p("hostname = a#b\n").unwrap_err().loc.unwrap().line, 1);
    }
}
