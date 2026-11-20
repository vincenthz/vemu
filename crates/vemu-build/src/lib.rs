//! `vemu build`: make an Alpine Linux disk image with a builder VM.
//!
//! The host side (this crate, std only) reads the config ([`config`]),
//! resolves and downloads the Alpine minirootfs (through the system curl,
//! [`fetch`], verified with [`sha256`] against the release index,
//! [`release`]), turns it into an initramfs ([`inflate`], [`tar`],
//! [`cpio`], [`initramfs`]) whose `/init` is a generated script
//! ([`script`]), and creates the sparse target image ([`output`]). The
//! `vemu` binary then boots the builder VM in-process with the target as
//! `/dev/vda`; the guest does all the filesystem work (mkfs, apk, the
//! configuration), so the host needs no root, no mkfs and no loop mounts.
//! See docs/image-builder.md.

pub mod cleanup;
pub mod config;
pub mod cpio;
pub mod fetch;
pub mod inflate;
pub mod initramfs;
pub mod output;
pub mod release;
pub mod script;
pub mod sha256;
pub mod tar;

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use config::{Config, Error as ConfigError, FileEntry};
use fetch::{Cache, Curl};
use initramfs::Payload;
use release::{Release, Spec};
use script::{PayloadItem, Plan};

/// The builder VM's resources.
pub const BUILDER_CPUS: usize = 2;
pub const BUILDER_MEMORY: u64 = 1 << 30;
/// Default `--timeout`.
pub const DEFAULT_TIMEOUT_SECS: u64 = 900;
/// Most host data carried into the builder (it lives in the builder's RAM).
pub const MAX_PAYLOAD: usize = 256 << 20;

/// Size limits of downloads.
const MAX_INDEX: u64 = 1 << 20;
const MAX_TARBALL: u64 = 64 << 20;

/// `vemu build` options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub config: PathBuf,
    pub output: Option<PathBuf>,
    pub force: bool,
    pub cache: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub timeout_secs: u64,
    pub verbose: bool,
}

/// Everything ready for the builder VM.
#[derive(Debug)]
pub struct Prepared {
    pub config: Config,
    pub release: Release,
    /// The builder kernel (absolute when it could be made so).
    pub kernel: PathBuf,
    pub initrd: TempFile,
    pub initrd_size: u64,
    pub target: output::Target,
    pub log_path: PathBuf,
    pub nonce: String,
    pub cmdline: String,
    pub plan: Plan,
}

/// A file deleted on drop (and by [`cleanup::run_now`] while it exists).
#[derive(Debug)]
pub struct TempFile {
    path: PathBuf,
    _guard: cleanup::PathGuard,
}

impl TempFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// A fresh random nonce (hex), from /dev/urandom.
pub fn nonce() -> Result<String, String> {
    let mut b = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(sha256::hex(&b))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The minirootfs to build from.
#[derive(Debug)]
pub struct Source {
    pub release: Release,
    pub tarball: Vec<u8>,
    /// Taken from the cache (nothing downloaded).
    pub cached: bool,
}

/// Resolve the release `cfg` asks for and get its tarball, verified.
/// `say` gets progress lines.
///
/// The cache index is reused only under the terms it was written with: an
/// entry resolved over verified https on this same mirror, or one whose
/// digest this config pins (on this same mirror). Entries resolved with
/// `insecure = true` and no pin are never recorded, so an unauthenticated
/// digest can never reach a later build ([`fetch::Trust`]).
pub fn resolve(
    cfg: &Config,
    cache: &Cache,
    curl: &Curl,
    say: &mut dyn FnMut(&str),
) -> Result<Source, String> {
    let arch = cfg.arch.as_str();
    let spec = cfg.alpine.to_string();
    let mirror = cfg.mirror.as_str();
    let tmp = cache.tmp_dir();
    let pin = cfg.sha256.as_deref();

    // The release an index entry names is what `alpine =` asks for.
    let fits_spec = |r: &Release| match &cfg.alpine {
        Spec::LatestStable => true,
        Spec::Branch(b) => r.branch == *b,
        Spec::Exact(v) => r.version == *v && r.branch == Spec::exact_branch(v),
    };
    // An entry this config may trust.
    let trusted = |i: &fetch::Indexed| {
        i.release.arch == arch
            && i.mirror == mirror
            && match i.trust {
                fetch::Trust::Https => true,
                fetch::Trust::Pinned => pin == Some(i.release.sha256.as_str()),
            }
    };

    // A pinned digest already in the cache needs no network at all, if a
    // trusted entry says it is the release `alpine =` asks for.
    let mut release = pin.and_then(|sha| {
        cache
            .find(|i| i.release.sha256 == sha && trusted(i) && fits_spec(&i.release))
            .filter(|_| cache.load(sha).is_some())
            .map(|i| i.release)
    });
    if release.is_none() {
        release = Some(match &cfg.alpine {
            Spec::Exact(v) => match cache.find(|i| i.spec == spec && trusted(i)) {
                Some(i) => i.release,
                None => {
                    let url = release::sha256_url(mirror, v, arch);
                    say(&format!("fetching {url}"));
                    let text = curl.fetch(&url, &tmp, 4096, 60)?;
                    release::exact_release(v, arch, &String::from_utf8_lossy(&text))
                        .map_err(|e| format!("{url}: {e}"))?
                }
            },
            Spec::LatestStable | Spec::Branch(_) => {
                let branch = match &cfg.alpine {
                    Spec::Branch(b) => b.clone(),
                    _ => "latest-stable".to_string(),
                };
                let url = release::yaml_url(mirror, &branch, arch);
                say(&format!("fetching {url}"));
                match curl.fetch(&url, &tmp, MAX_INDEX, 60) {
                    Ok(yaml) => {
                        release::parse_latest_releases(&String::from_utf8_lossy(&yaml), arch)
                            .map_err(|e| format!("{url}: {e}"))?
                    }
                    Err(e) => match cache.find(|i| i.spec == spec && trusted(i)) {
                        Some(i) if cache.load(&i.release.sha256).is_some() => {
                            say(&format!(
                                "warning: {e}; using the cached Alpine {} resolved earlier for {spec}",
                                i.release.version
                            ));
                            i.release
                        }
                        _ => return Err(e),
                    },
                }
            }
        });
    }
    let release = release.expect("resolved above");
    if let Some(pin) = &cfg.sha256
        && *pin != release.sha256
    {
        return Err(format!(
            "sha256 pin mismatch: the config pins {pin}, but Alpine {} ({}) is published with sha256 {}",
            release.version, release.file, release.sha256
        ));
    }
    let (tarball, cached) = match cache.load(&release.sha256) {
        Some(t) => (t, true),
        None => {
            let url = release.url(mirror);
            say(&format!("downloading {url}"));
            let data = curl.fetch(
                &url,
                &tmp,
                release.size.map_or(MAX_TARBALL, |s| s.min(MAX_TARBALL)),
                600,
            )?;
            let got = sha256::hex_digest(&data);
            if got != release.sha256 {
                return Err(format!(
                    "{url}: sha256 is {got}, but the release index says {}: refusing it",
                    release.sha256
                ));
            }
            cache.store(&release.sha256, &data)?;
            (data, false)
        }
    };
    // Pinned or not, the digest is now known to match; record how far it
    // can be trusted. An unpinned insecure resolution is not recorded (the
    // tarball, stored by its digest, is harmless: only a trusted digest
    // ever names it).
    let trust = if !cfg.insecure {
        Some(fetch::Trust::Https)
    } else if pin.is_some() {
        Some(fetch::Trust::Pinned)
    } else {
        say(
            "warning: insecure = true without a sha256 = pin: this release is not trusted, and is not recorded for reuse",
        );
        None
    };
    if let Some(t) = trust {
        cache.record(&spec, &release, mirror, t, now())?;
    }
    Ok(Source {
        release,
        tarball,
        cached,
    })
}

/// Read at most `max` bytes of the regular file `path`.
fn read_file(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let m = fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if m.len() > max as u64 {
        return Err(format!(
            "{} is larger than {} MiB",
            path.display(),
            max >> 20
        ));
    }
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Collect the host data the config names.
pub fn load_payload(cfg: &Config) -> Result<Payload, ConfigError> {
    let mut p = Payload::default();
    let mut keys = Vec::new();
    for k in &cfg.authorized_keys {
        let at = |m: String| ConfigError::at(&k.loc, format!("[ssh] authorized_keys: {m}"));
        let data = read_file(&k.path, 1 << 20).map_err(at)?;
        let text =
            String::from_utf8(data).map_err(|_| at(format!("{} is not text", k.path.display())))?;
        if text.contains("PRIVATE KEY") {
            return Err(at(format!(
                "{} is a private key; give the public key (.pub)",
                k.path.display()
            )));
        }
        if !text
            .lines()
            .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        {
            return Err(at(format!("{} has no keys", k.path.display())));
        }
        keys.extend_from_slice(text.as_bytes());
        if !keys.ends_with(b"\n") {
            keys.push(b'\n');
        }
    }
    if !keys.is_empty() {
        p.authorized_keys = Some(keys);
    }
    for f in &cfg.files {
        add_files(&mut p, f)
            .map_err(|m| ConfigError::at(&f.host.loc, format!("[files] {}: {m}", f.image)))?;
    }
    if let Some(m) = &cfg.modules {
        let data = read_file(&m.path, MAX_PAYLOAD)
            .map_err(|e| ConfigError::at(&m.loc, format!("modules: {e}")))?;
        if !data.starts_with(&[0x1f, 0x8b]) {
            return Err(ConfigError::at(
                &m.loc,
                format!("modules: {} is not a .tar.gz", m.path.display()),
            ));
        }
        p.modules = Some(data);
    }
    if let Some(r) = &cfg.run {
        let data = read_file(&r.path, 1 << 20)
            .map_err(|e| ConfigError::at(&r.loc, format!("[run] script: {e}")))?;
        p.run = Some(data);
    }
    if p.size() > MAX_PAYLOAD {
        return Err(ConfigError {
            loc: None,
            message: format!(
                "{}: the files, modules and keys add up to {} MiB; the builder carries at most {} MiB",
                cfg.path.display(),
                p.size() >> 20,
                MAX_PAYLOAD >> 20
            ),
        });
    }
    Ok(p)
}

/// One `[files]` entry: a file, or a directory tree (regular files and
/// directories only).
fn add_files(p: &mut Payload, f: &FileEntry) -> Result<(), String> {
    let m = fs::metadata(&f.host.path)
        .map_err(|e| format!("cannot read {}: {e}", f.host.path.display()))?;
    let mode_of = |m: &fs::Metadata| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o7777
    };
    if m.is_file() {
        let data = read_file(&f.host.path, MAX_PAYLOAD)?;
        p.files.push(PayloadItem::File {
            index: p.file_data.len(),
            image: f.image.clone(),
            mode: f.mode.unwrap_or(mode_of(&m)),
        });
        p.file_data.push(data);
        return Ok(());
    }
    if !m.is_dir() {
        return Err(format!(
            "{} is not a regular file or a directory",
            f.host.path.display()
        ));
    }
    p.files.push(PayloadItem::Dir {
        image: f.image.clone(),
        mode: f.mode.unwrap_or(mode_of(&m)),
    });
    let mut stack = vec![(f.host.path.clone(), f.image.clone())];
    while let Some((host, image)) = stack.pop() {
        let mut names: Vec<_> = fs::read_dir(&host)
            .map_err(|e| format!("cannot list {}: {e}", host.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("cannot list {}: {e}", host.display()))?;
        names.sort_by_key(|e| e.file_name());
        for e in names {
            let name = e.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| format!("{}: a file name is not UTF-8", host.display()))?;
            let hp = e.path();
            let ip = format!("{image}/{name}");
            config::check_image_path(&ip).map_err(|m| format!("{}: {m}", hp.display()))?;
            let m = fs::symlink_metadata(&hp).map_err(|e| format!("{}: {e}", hp.display()))?;
            if m.is_dir() {
                p.files.push(PayloadItem::Dir {
                    image: ip.clone(),
                    mode: mode_of(&m),
                });
                stack.push((hp, ip));
            } else if m.is_file() {
                let data = read_file(&hp, MAX_PAYLOAD)?;
                p.files.push(PayloadItem::File {
                    index: p.file_data.len(),
                    image: ip,
                    mode: mode_of(&m),
                });
                p.file_data.push(data);
            } else {
                return Err(format!(
                    "{} is not a regular file or a directory (symbolic links are not copied)",
                    hp.display()
                ));
            }
            if p.size() > MAX_PAYLOAD {
                return Err(format!("more than {} MiB of files", MAX_PAYLOAD >> 20));
            }
        }
    }
    Ok(())
}

/// The guest script's inputs.
pub fn plan(cfg: &Config, release: &Release, payload: &Payload) -> Plan {
    Plan {
        arch: cfg.arch.as_str().to_string(),
        branch: release.branch.clone(),
        version: release.version.clone(),
        mirror: cfg.mirror.clone(),
        community: cfg.community,
        hostname: cfg.hostname.clone(),
        timezone: cfg.timezone.clone(),
        dhcp: cfg.dhcp,
        ntp: cfg.ntp,
        ssh: cfg.ssh,
        packages: cfg.packages.clone(),
        files: payload.files.clone(),
        modules: payload.modules.is_some(),
        run: payload.run.as_ref().map(|r| r.starts_with(b"#!")),
    }
}

/// The builder's kernel command line.
pub fn cmdline(nonce: &str, epoch: u64) -> String {
    // panic=-1: a guest panic reboots at once, which ends the build.
    format!("console=hvc0 quiet panic=-1 vemu.build={nonce} vemu.epoch={epoch}")
}

/// Everything up to booting the builder: config, release, payload,
/// initramfs, target image. `say` gets progress lines.
pub fn prepare(opts: &Options, say: &mut dyn FnMut(&str)) -> Result<Prepared, String> {
    let cfg = config::load(&opts.config).map_err(|e| e.to_string())?;
    let out = opts.output.clone().unwrap_or_else(|| cfg.output.clone());
    output::check(&out, opts.force)?;
    let kernel = match (&opts.kernel, &cfg.kernel) {
        (Some(k), _) => k.clone(),
        (None, Some(k)) => {
            if !k.path.is_file() {
                return Err(format!(
                    "{}: kernel {}: not a file",
                    k.loc,
                    k.path.display()
                ));
            }
            k.path.clone()
        }
        (None, None) => {
            return Err(format!(
                "{}: no kernel: set kernel = in the config or pass --kernel (the builder VM boots it, \
                 and it is the kernel to boot the image with)",
                cfg.path.display()
            ));
        }
    };
    let kernel =
        fs::canonicalize(&kernel).map_err(|e| format!("kernel {}: {e}", kernel.display()))?;
    let payload = load_payload(&cfg).map_err(|e| e.to_string())?;

    let cache_dir = opts
        .cache
        .clone()
        .or_else(fetch::default_cache_dir)
        .ok_or("no cache directory: set $HOME, $XDG_CACHE_HOME or pass --cache DIR")?;
    let cache = Cache::open(&cache_dir)?;
    let curl = Curl::new(cfg.insecure);
    let src = resolve(&cfg, &cache, &curl, say)?;
    say(&format!(
        "Alpine {} ({}, {}), minirootfs sha256 {}{}",
        src.release.version,
        src.release.branch,
        src.release.arch,
        src.release.sha256,
        if src.cached {
            " (cached)"
        } else {
            " (verified)"
        }
    ));

    let mut payload = payload;
    payload.manifest = manifest(&cfg, &src.release, &payload);
    let plan = plan(&cfg, &src.release, &payload);
    let init = script::generate(&plan);

    let nonce = nonce()?;
    // The initramfs carries the [files] data, keys and the [run] script:
    // only this user may read it. It goes in the cache directory (0700,
    // checked), not the shared temporary directory.
    let initrd_path = cache.temp_initrd_path(&nonce[..12]);
    let initrd = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&initrd_path)
            .map_err(|e| format!("cannot create {}: {e}", initrd_path.display()))?
    };
    let initrd_file = TempFile {
        _guard: cleanup::register_path(&initrd_path),
        path: initrd_path,
    };
    let initrd_size = initramfs::write(&src.tarball, &init, &payload, BufWriter::new(initrd))?;

    let target = output::Target::create(&out, cfg.size, opts.force)?;
    Ok(Prepared {
        log_path: output::log_path(&out),
        cmdline: cmdline(&nonce, now()),
        config: cfg,
        release: src.release,
        kernel,
        initrd: initrd_file,
        initrd_size,
        target,
        nonce,
        plan,
    })
}

fn manifest(cfg: &Config, r: &Release, p: &Payload) -> String {
    let mut s = format!(
        "alpine {} {} {} sha256 {}\nmirror {}\nsize {} MiB\nhostname {}\n",
        r.version,
        r.branch,
        r.arch,
        r.sha256,
        cfg.mirror,
        cfg.size >> 20,
        cfg.hostname
    );
    if let Some(k) = &p.authorized_keys {
        s.push_str(&format!(
            "authorized_keys {} lines\n",
            String::from_utf8_lossy(k).lines().count()
        ));
    }
    s.push_str(&format!(
        "files {} items, {} bytes\n",
        p.files.len(),
        p.file_data.iter().map(Vec::len).sum::<usize>()
    ));
    if let Some(m) = &p.modules {
        s.push_str(&format!("modules {} bytes\n", m.len()));
    }
    if let Some(r) = &p.run {
        s.push_str(&format!("run script {} bytes\n", r.len()));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vemu-build-lib-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn payload_from_config() {
        let d = dir("payload");
        fs::write(d.join("k.pub"), "ssh-ed25519 AAAAC3 me@host").unwrap();
        fs::write(d.join("motd"), "hi\n").unwrap();
        fs::set_permissions(d.join("motd"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::create_dir_all(d.join("tree/sub")).unwrap();
        fs::write(d.join("tree/a"), "a").unwrap();
        fs::write(d.join("tree/sub/b"), "b").unwrap();
        fs::set_permissions(d.join("tree/sub/b"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(d.join("run.sh"), "echo hi\n").unwrap();
        let text = "[ssh]\nenable = true\nauthorized_keys = k.pub\n[files]\n/etc/motd = motd\n/etc/issue = motd 0600\n/opt/tree = tree\n[run]\nscript = run.sh\n";
        let cfg =
            config::parse(&d.join("t.conf"), text, None, config::Arch::host().unwrap()).unwrap();
        let p = load_payload(&cfg).unwrap();
        assert_eq!(
            p.authorized_keys.as_deref(),
            Some(&b"ssh-ed25519 AAAAC3 me@host\n"[..])
        );
        assert_eq!(
            p.files,
            [
                PayloadItem::File {
                    index: 0,
                    image: "/etc/motd".into(),
                    mode: 0o640
                },
                PayloadItem::File {
                    index: 1,
                    image: "/etc/issue".into(),
                    mode: 0o600
                },
                PayloadItem::Dir {
                    image: "/opt/tree".into(),
                    mode: 0o755
                },
                PayloadItem::File {
                    index: 2,
                    image: "/opt/tree/a".into(),
                    mode: 0o644
                },
                PayloadItem::Dir {
                    image: "/opt/tree/sub".into(),
                    mode: 0o755
                },
                PayloadItem::File {
                    index: 3,
                    image: "/opt/tree/sub/b".into(),
                    mode: 0o700
                },
            ]
        );
        assert_eq!(
            p.file_data,
            [
                b"hi\n".to_vec(),
                b"hi\n".to_vec(),
                b"a".to_vec(),
                b"b".to_vec()
            ]
        );
        assert_eq!(p.run.as_deref(), Some(&b"echo hi\n"[..]));
        let r = Release {
            version: "3.24.4".into(),
            branch: "v3.24".into(),
            arch: "aarch64".into(),
            file: "f".into(),
            sha256: "0".repeat(64),
            size: None,
        };
        let plan = plan(&cfg, &r, &p);
        assert_eq!(plan.run, Some(false));
        assert!(plan.ssh.is_some());

        // Errors carry the config line.
        fs::write(d.join("id"), "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        std::os::unix::fs::symlink("motd", d.join("tree/link")).unwrap();
        for (text, want) in [
            (
                "[ssh]\nenable = true\nauthorized_keys = id\n",
                "t.conf:3: [ssh] authorized_keys: ",
            ),
            (
                "[ssh]\nenable = true\nauthorized_keys = missing.pub\n",
                "t.conf:3: [ssh] authorized_keys: cannot read",
            ),
            (
                "[files]\n/x = missing\n",
                "t.conf:2: [files] /x: cannot read",
            ),
            ("[files]\n/x = tree\n", "symbolic links are not copied"),
            ("modules = motd\n", "t.conf:1: modules: "),
            (
                "[run]\nscript = nope.sh\n",
                "t.conf:2: [run] script: cannot read",
            ),
        ] {
            let cfg = config::parse(&d.join("t.conf"), text, None, config::Arch::host().unwrap())
                .unwrap();
            let e = load_payload(&cfg).unwrap_err().to_string();
            assert!(e.contains(want), "{text:?}: {e}");
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn cmdline_and_nonce() {
        let a = nonce().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, nonce().unwrap());
        let c = cmdline(&a, 1_795_000_000);
        assert!(c.contains(&format!("vemu.build={a}")) && c.contains("vemu.epoch=1795000000"));
        assert!(c.contains("panic=-1") && c.starts_with("console=hvc0"));
    }

    /// A curl stand-in serving `<scheme>://HOST/PATH` from `root/HOST/PATH`
    /// (-o DEST), logging each URL to `log`.
    fn fake_curl(d: &Path, root: &Path, log: &Path) -> Curl {
        let fake = d.join("curl");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=$2; shift; done\necho \"$1\" >> {log}\n\
                 f={root}/${{1#*://}}\n[ -f \"$f\" ] || {{ echo 'curl: (22) 404' >&2; exit 22; }}\ncp \"$f\" \"$out\"\n",
                log = log.display(),
                root = root.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        Curl::with_program(&fake, false)
    }

    /// Publish `tarball` as Alpine `version` under `www` (a mirror's root):
    /// the tarball, its .sha256, and the branch's and latest-stable's
    /// latest-releases.yaml.
    fn publish(www: &Path, arch: &str, version: &str, tarball: &[u8]) -> String {
        let sha = sha256::hex_digest(tarball);
        let branch = Spec::exact_branch(version);
        let file = release::tarball_name(version, arch);
        let rel = www.join(format!("{branch}/releases/{arch}"));
        fs::create_dir_all(&rel).unwrap();
        fs::write(rel.join(&file), tarball).unwrap();
        fs::write(
            rel.join(format!("{file}.sha256")),
            format!("{sha}  {file}\n"),
        )
        .unwrap();
        let yaml = format!(
            "---\n-\n  branch: {branch}\n  arch: {arch}\n  version: {version}\n  flavor: alpine-minirootfs\n  file: {file}\n  size: {}\n  sha256: {sha}\n",
            tarball.len()
        );
        fs::write(rel.join("latest-releases.yaml"), &yaml).unwrap();
        let ls = www.join(format!("latest-stable/releases/{arch}"));
        fs::create_dir_all(&ls).unwrap();
        fs::write(ls.join("latest-releases.yaml"), &yaml).unwrap();
        sha
    }

    /// An index entry resolved over plain http with insecure = true (and
    /// no pin) is never reused by another config, so a MITM'd digest
    /// cannot reach a later https build; nor can an entry from another
    /// mirror. A pinned digest is reused only for the `alpine =` it fits.
    #[test]
    fn cache_reuse_is_trust_aware() {
        let d = dir("trust");
        let arch = config::Arch::host().unwrap();
        let a = arch.as_str();
        let good = b"the genuine minirootfs".to_vec();
        let evil = b"EVIL TARBALL".to_vec();
        let good_sha = publish(&d.join("www/mirror.test/alpine"), a, "3.24.4", &good);
        let evil_sha = publish(&d.join("www/evil.test/alpine"), a, "3.24.4", &evil);
        let log = d.join("urls");
        let curl = fake_curl(&d, &d.join("www"), &log);
        // What a config with insecure = true runs (Curl::new(cfg.insecure)).
        let http_curl = Curl::with_program(d.join("curl"), true);
        let offline = Curl::with_program("/nonexistent/curl-xyz", false);
        let cache = Cache::open(&d.join("cache")).unwrap();
        let cfg = |text: &str| config::parse(&d.join("t.conf"), text, None, arch).unwrap();
        let mut quiet = |_: &str| {};
        let secure = "mirror = https://mirror.test/alpine\n";
        let mitm = "mirror = http://evil.test/alpine\ninsecure = true\n";

        // Build A: an insecure http mirror (a MITM), exact and branch specs.
        for spec in ["alpine = 3.24.4\n", ""] {
            let mut said = Vec::new();
            let src = resolve(
                &cfg(&format!("{mitm}{spec}")),
                &cache,
                &http_curl,
                &mut |m: &str| said.push(m.to_string()),
            )
            .unwrap();
            assert_eq!(src.release.sha256, evil_sha);
            assert!(said.iter().any(|m| m.contains("not recorded")), "{said:?}");
        }
        assert!(cache.index().is_empty(), "unpinned insecure: not recorded");
        // Build B, the default-style https config: it fetches its own index
        // and gets the genuine tarball, online...
        let src = resolve(
            &cfg(&format!("{secure}alpine = 3.24.4\n")),
            &cache,
            &curl,
            &mut quiet,
        )
        .unwrap();
        assert_eq!(
            (src.release.sha256.as_str(), src.tarball.as_slice()),
            (good_sha.as_str(), &good[..])
        );
        // ... and offline, it never falls back to the MITM'd release.
        fs::remove_dir_all(d.join("cache")).unwrap();
        let cache = Cache::open(&d.join("cache")).unwrap();
        resolve(
            &cfg(&format!("{mitm}alpine = 3.24.4\n")),
            &cache,
            &http_curl,
            &mut quiet,
        )
        .unwrap();
        resolve(&cfg(mitm), &cache, &http_curl, &mut quiet).unwrap();
        for spec in ["alpine = 3.24.4\n", ""] {
            let e = resolve(
                &cfg(&format!("{secure}{spec}")),
                &cache,
                &offline,
                &mut quiet,
            )
            .unwrap_err();
            assert!(e.contains("not found"), "{spec:?}: {e}");
        }
        // An entry from another mirror, even over https, is not reused.
        resolve(
            &cfg(&format!("{secure}alpine = 3.24.4\n")),
            &cache,
            &curl,
            &mut quiet,
        )
        .unwrap();
        let other = "mirror = https://other.test/alpine\nalpine = 3.24.4\n";
        assert!(resolve(&cfg(other), &cache, &offline, &mut quiet).is_err());
        // The same mirror, offline: reused (exact releases are immutable).
        let src = resolve(
            &cfg(&format!("{secure}alpine = 3.24.4\n")),
            &cache,
            &offline,
            &mut quiet,
        )
        .unwrap();
        assert!(src.cached && src.release.sha256 == good_sha);

        // Insecure with a pin: recorded as pinned, and reused only by a
        // config pinning the same digest.
        let pin = format!("sha256 = {good_sha}\n");
        let plain_good = "mirror = http://mirror.test/alpine\ninsecure = true\nalpine = 3.24.4\n";
        resolve(
            &cfg(&format!("{plain_good}{pin}")),
            &cache,
            &http_curl,
            &mut quiet,
        )
        .unwrap();
        assert!(
            cache
                .index()
                .iter()
                .any(|i| i.trust == fetch::Trust::Pinned)
        );
        resolve(
            &cfg(&format!("{plain_good}{pin}")),
            &cache,
            &offline,
            &mut quiet,
        )
        .unwrap();
        assert!(resolve(&cfg(plain_good), &cache, &offline, &mut quiet).is_err());

        // A pin and a cached tarball do not override `alpine =`: the cached
        // 3.24.4 does not satisfy v3.20 (offline: an error, not 3.24.4).
        let e = resolve(
            &cfg(&format!("{secure}alpine = v3.20\n{pin}")),
            &cache,
            &offline,
            &mut quiet,
        )
        .unwrap_err();
        assert!(e.contains("not found"), "{e}");
        let e = resolve(
            &cfg(&format!("{secure}alpine = 3.20.1\n{pin}")),
            &cache,
            &offline,
            &mut quiet,
        )
        .unwrap_err();
        assert!(e.contains("not found"), "{e}");
        // ... while the release it is satisfies it, with no network.
        for spec in ["alpine = v3.24\n", "alpine = 3.24.4\n", ""] {
            let src = resolve(
                &cfg(&format!("{secure}{spec}{pin}")),
                &cache,
                &offline,
                &mut quiet,
            )
            .unwrap_or_else(|e| panic!("{spec:?}: {e}"));
            assert_eq!((src.release.version.as_str(), src.cached), ("3.24.4", true));
        }
        // Online, v3.20 with that pin is a pin mismatch (as on a cold cache).
        publish(
            &d.join("www/mirror.test/alpine"),
            a,
            "3.20.1",
            b"old minirootfs",
        );
        let e = resolve(
            &cfg(&format!("{secure}alpine = v3.20\n{pin}")),
            &cache,
            &curl,
            &mut quiet,
        )
        .unwrap_err();
        assert!(e.contains("sha256 pin mismatch"), "{e}");
        assert!(
            fs::read_to_string(&log)
                .unwrap()
                .contains("http://evil.test/")
        );
        fs::remove_dir_all(&d).unwrap();
    }

    /// resolve() against a fake curl serving files from a directory: the
    /// trust chain (index digest, tarball digest), the pin, the cache.
    #[test]
    fn resolve_with_fake_mirror() {
        let d = dir("resolve");
        let www = d.join("www/mirror.test/alpine");
        let arch = config::Arch::host().unwrap();
        let a = arch.as_str();
        fs::create_dir_all(www.join(format!("v3.24/releases/{a}"))).unwrap();
        fs::create_dir_all(www.join(format!("latest-stable/releases/{a}"))).unwrap();
        let tarball = b"pretend this is a tar.gz".to_vec();
        let sha = sha256::hex_digest(&tarball);
        let file = release::tarball_name("3.24.4", a);
        fs::write(www.join(format!("v3.24/releases/{a}/{file}")), &tarball).unwrap();
        let yaml = format!(
            "---\n-\n  branch: v3.24\n  arch: {a}\n  version: 3.24.4\n  flavor: alpine-minirootfs\n  file: {file}\n  size: {}\n  sha256: {sha}\n",
            tarball.len()
        );
        fs::write(
            www.join(format!("latest-stable/releases/{a}/latest-releases.yaml")),
            &yaml,
        )
        .unwrap();
        let curl = fake_curl(&d, &d.join("www"), &d.join("urls"));
        let cache = Cache::open(&d.join("cache")).unwrap();
        let cfg_for = |text: &str| {
            config::parse(
                &d.join("t.conf"),
                &format!("mirror = https://mirror.test/alpine\n{text}"),
                None,
                arch,
            )
            .unwrap()
        };
        let urls = || {
            fs::read_to_string(d.join("urls"))
                .unwrap_or_default()
                .lines()
                .count()
        };
        let mut quiet = |_: &str| {};

        let src = resolve(&cfg_for(""), &cache, &curl, &mut quiet).unwrap();
        assert_eq!(
            (
                src.release.version.as_str(),
                src.release.sha256.as_str(),
                src.cached
            ),
            ("3.24.4", sha.as_str(), false)
        );
        assert_eq!(src.tarball, tarball);
        assert_eq!(urls(), 2, "index + tarball");
        // Again: the index is fetched, the tarball comes from the cache.
        let src = resolve(&cfg_for(""), &cache, &curl, &mut quiet).unwrap();
        assert!(src.cached);
        assert_eq!(urls(), 3);
        // Pinned and cached: no network at all.
        let src = resolve(
            &cfg_for(&format!("sha256 = {sha}\n")),
            &cache,
            &curl,
            &mut quiet,
        )
        .unwrap();
        assert!(src.cached);
        assert_eq!(urls(), 3);
        // A pin that does not match the index is refused.
        let e = resolve(
            &cfg_for(&format!("sha256 = {}\n", "0".repeat(64))),
            &cache,
            &curl,
            &mut quiet,
        )
        .unwrap_err();
        assert!(e.contains("sha256 pin mismatch"), "{e}");
        // A tampered tarball on the mirror is refused (and not cached).
        fs::remove_dir_all(d.join("cache")).unwrap();
        let cache = Cache::open(&d.join("cache")).unwrap();
        fs::write(
            www.join(format!("v3.24/releases/{a}/{file}")),
            b"evil bytes, same length!",
        )
        .unwrap();
        let e = resolve(&cfg_for(""), &cache, &curl, &mut quiet).unwrap_err();
        assert!(e.contains("refusing it"), "{e}");
        assert!(cache.load(&sha).is_none());
        // Exact release: its .sha256 file, once; then the cache index.
        fs::write(www.join(format!("v3.24/releases/{a}/{file}")), &tarball).unwrap();
        fs::write(
            www.join(format!("v3.24/releases/{a}/{file}.sha256")),
            format!("{sha}  {file}\n"),
        )
        .unwrap();
        let before = urls();
        let src = resolve(&cfg_for("alpine = 3.24.4\n"), &cache, &curl, &mut quiet).unwrap();
        assert_eq!(src.release.branch, "v3.24");
        assert_eq!(urls(), before + 2);
        resolve(&cfg_for("alpine = 3.24.4\n"), &cache, &curl, &mut quiet).unwrap();
        assert_eq!(
            urls(),
            before + 2,
            "exact releases are immutable: no refetch"
        );
        // Offline (the index 404s): latest-stable falls back to what it
        // resolved to before, with a warning.
        resolve(&cfg_for(""), &cache, &curl, &mut quiet).unwrap();
        fs::remove_file(www.join(format!("latest-stable/releases/{a}/latest-releases.yaml")))
            .unwrap();
        let mut said = Vec::new();
        let src = resolve(&cfg_for(""), &cache, &curl, &mut |m: &str| {
            said.push(m.to_string())
        })
        .unwrap();
        assert_eq!(src.release.version, "3.24.4");
        assert!(
            said.iter()
                .any(|m| m.contains("warning") && m.contains("cached Alpine 3.24.4")),
            "{said:?}"
        );
        // A branch never resolved before has no fallback.
        let e = resolve(&cfg_for("alpine = v3.23\n"), &cache, &curl, &mut quiet).unwrap_err();
        assert!(e.contains("404"), "{e}");
        fs::remove_dir_all(&d).unwrap();
    }
}
