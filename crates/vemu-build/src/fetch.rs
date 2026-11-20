//! Downloads through the system `curl`, and the download cache.
//!
//! curl runs with `-q` first (so no `.curlrc` can change it, e.g. turn off
//! certificate checks with `insecure`), `-fsSL`, https only (also for
//! redirects) unless the config says `insecure = true`, connect and total
//! timeouts, a few retries and a size cap, in its own process group and
//! registered for [`crate::cleanup`]. Whatever it fetches is untrusted
//! until its SHA-256 is checked by the caller.
//!
//! The cache (`$XDG_CACHE_HOME/vemu`, `~/Library/Caches/vemu` on macOS,
//! `~/.cache/vemu` elsewhere, or `--cache DIR`) holds minirootfs tarballs
//! named by their SHA-256 (`alpine/<sha256>.tar.gz`, re-verified on every
//! use) and an index of the releases resolved so far
//! (`alpine/releases.tsv`), so a pinned or exact release builds without
//! fetching anything from the release directory again. Each index entry
//! records the mirror and how its digest was trusted ([`Trust`]); the
//! caller reuses an entry only under the same terms. The cache must
//! belong to the user and not be writable by others.
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use crate::release::{Release, is_branch, is_version, tarball_name};
use crate::sha256::{hex_digest, is_hex_digest};

/// The system curl.
#[derive(Debug, Clone)]
pub struct Curl {
    program: PathBuf,
    /// Also allow http:// (the config's `insecure = true`).
    pub insecure: bool,
}

impl Curl {
    pub fn new(insecure: bool) -> Curl {
        Curl::with_program("curl", insecure)
    }

    pub fn with_program(program: impl Into<PathBuf>, insecure: bool) -> Curl {
        Curl {
            program: program.into(),
            insecure,
        }
    }

    /// Check `url` is one we may fetch.
    pub fn check_url(&self, url: &str) -> Result<(), String> {
        let ok_scheme =
            url.starts_with("https://") || (self.insecure && url.starts_with("http://"));
        if !ok_scheme {
            return Err(format!("refusing to download {url}: not an https:// URL"));
        }
        if url.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(format!(
                "refusing to download {url:?}: bad characters in the URL"
            ));
        }
        Ok(())
    }

    /// Download `url` into `dest` (created or truncated): at most
    /// `max_bytes`, within `max_secs`.
    pub fn download(
        &self,
        url: &str,
        dest: &Path,
        max_bytes: u64,
        max_secs: u32,
    ) -> Result<(), String> {
        self.check_url(url)?;
        let protos = if self.insecure {
            "=http,https"
        } else {
            "=https"
        };
        let mut cmd = Command::new(&self.program);
        // -q must come first: curl then reads no curlrc.
        cmd.args(["-q", "-fsSL", "--proto", protos, "--proto-redir", protos])
            .args([
                "--connect-timeout",
                "20",
                "--retry",
                "2",
                "--retry-delay",
                "1",
            ])
            .arg("--max-time")
            .arg(max_secs.to_string())
            .arg("--max-filesize")
            .arg(max_bytes.to_string())
            .arg("-o")
            .arg(dest)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // Its own process group: a terminal's Ctrl-C reaches vemu only,
        // whose handler then stops curl (cleanup::run_now) and removes the
        // partial download. On Linux, curl also dies with vemu.
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
            #[cfg(target_os = "linux")]
            // SAFETY: prctl is async-signal-safe, as pre_exec requires.
            unsafe {
                cmd.pre_exec(|| {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                    Ok(())
                });
            }
        }
        let child = cmd.spawn().map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                format!(
                    "cannot run {}: not found. vemu build downloads Alpine with the system curl; install curl",
                    self.program.display()
                )
            } else {
                format!("cannot run {}: {e}", self.program.display())
            }
        })?;
        let guard = crate::cleanup::register_child(child.id());
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for {}: {e}", self.program.display()))?;
        drop(guard);
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            let msg = msg.trim();
            let hint = match out.status.code() {
                Some(6) => " (cannot resolve the host: offline?)",
                Some(7) => " (cannot connect: offline, or a firewall?)",
                Some(28) => " (timed out)",
                Some(35 | 60) => " (TLS failure: is the system clock right?)",
                Some(63) => " (larger than expected)",
                _ => "",
            };
            let _ = fs::remove_file(dest);
            return Err(format!(
                "download of {url} failed: curl exited with {}{hint}{}{msg}",
                out.status
                    .code()
                    .map_or("a signal".to_string(), |c| c.to_string()),
                if msg.is_empty() { "" } else { ": " },
            ));
        }
        let len = fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
        if len > max_bytes {
            let _ = fs::remove_file(dest);
            return Err(format!(
                "download of {url}: {len} bytes, more than the {max_bytes} expected"
            ));
        }
        Ok(())
    }

    /// Download `url` (at most `max_bytes`) into memory, through a
    /// temporary file in `tmp_dir`.
    pub fn fetch(
        &self,
        url: &str,
        tmp_dir: &Path,
        max_bytes: u64,
        max_secs: u32,
    ) -> Result<Vec<u8>, String> {
        let tmp = tmp_dir.join(format!(
            "{DOWNLOAD_PREFIX}{}-{}",
            std::process::id(),
            unique()
        ));
        // The name is unique to this process: curl creates it.
        let _guard = crate::cleanup::register_path(&tmp);
        let r = self
            .download(url, &tmp, max_bytes, max_secs)
            .and_then(|()| {
                fs::read(&tmp).map_err(|e| format!("reading the download of {url}: {e}"))
            });
        let _ = fs::remove_file(&tmp);
        r
    }
}

/// Temporary files in the cache directory: downloads, [`write_atomic`]'s,
/// and the builder initramfs ([`Cache::temp_initrd_path`]).
const DOWNLOAD_PREFIX: &str = ".download-";
const TMP_PREFIX: &str = ".tmp-";
const INITRD_PREFIX: &str = ".initrd-";
/// Such files older than this are leftovers of a process that was killed
/// (SIGKILL, a crash): a build lasts at most a day (`--timeout`).
const STALE: Duration = Duration::from_secs(2 * 86400);

/// A process-unique counter value, for temporary names.
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// The default cache directory, from the environment.
pub fn default_cache_dir() -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(x) = var("XDG_CACHE_HOME").filter(|p| p.is_absolute()) {
        return Some(x.join("vemu"));
    }
    let home = var("HOME")?;
    Some(if cfg!(target_os = "macos") {
        home.join("Library/Caches/vemu")
    } else {
        home.join(".cache/vemu")
    })
}

/// Why an index entry's digest was trusted when it was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// It came from the release index fetched over verified https
    /// (`insecure = false`).
    Https,
    /// It came from an unauthenticated index (`insecure = true`) and
    /// matched the config's `sha256 =` pin: only a config that pins the
    /// same digest (on the same mirror) may reuse it. An unpinned
    /// insecure resolution is never recorded.
    Pinned,
}

impl Trust {
    fn as_str(self) -> &'static str {
        match self {
            Trust::Https => "https",
            Trust::Pinned => "pinned",
        }
    }

    fn parse(s: &str) -> Option<Trust> {
        match s {
            "https" => Some(Trust::Https),
            "pinned" => Some(Trust::Pinned),
            _ => None,
        }
    }
}

/// A cached release, as recorded in the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indexed {
    /// The `alpine =` value it was resolved for.
    pub spec: String,
    pub release: Release,
    /// The mirror it was resolved on.
    pub mirror: String,
    pub trust: Trust,
    /// When it was resolved (seconds since the epoch).
    pub time: u64,
}

/// The download cache.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Open (creating, mode 0700) the cache at `root`. It must be owned by
    /// this user and not writable by anyone else (another user could
    /// otherwise plant index entries or tarballs). Leftover temporary
    /// files of killed builds are removed.
    pub fn open(root: &Path) -> Result<Cache, String> {
        let dir = root.join("alpine");
        let mut b = fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&dir)
            .map_err(|e| format!("cannot create the cache directory {}: {e}", dir.display()))?;
        check_private_dir(root)?;
        check_private_dir(&dir)?;
        let cache = Cache {
            root: root.to_path_buf(),
        };
        cache.sweep(SystemTime::now());
        Ok(cache)
    }

    /// Remove temporary files older than [`STALE`].
    fn sweep(&self, now: SystemTime) {
        let Ok(rd) = fs::read_dir(self.dir()) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if ![DOWNLOAD_PREFIX, TMP_PREFIX, INITRD_PREFIX]
                .iter()
                .any(|p| name.starts_with(p))
            {
                continue;
            }
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > STALE);
            if old {
                let _ = fs::remove_file(e.path());
            }
        }
    }

    /// A fresh path for the builder initramfs (in the 0700 cache
    /// directory: it holds the [files] data). `tag` makes it unique.
    pub fn temp_initrd_path(&self, tag: &str) -> PathBuf {
        self.dir()
            .join(format!("{INITRD_PREFIX}{}-{tag}.cpio", std::process::id()))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir(&self) -> PathBuf {
        self.root.join("alpine")
    }

    /// Where the tarball with this digest is kept.
    pub fn tarball_path(&self, sha256: &str) -> PathBuf {
        self.dir().join(format!("{sha256}.tar.gz"))
    }

    /// The cached tarball with this digest, verified (a corrupt one is
    /// deleted and reported missing).
    pub fn load(&self, sha256: &str) -> Option<Vec<u8>> {
        if !is_hex_digest(sha256) {
            return None;
        }
        let path = self.tarball_path(sha256);
        let data = fs::read(&path).ok()?;
        if hex_digest(&data) == sha256 {
            Some(data)
        } else {
            let _ = fs::remove_file(&path);
            None
        }
    }

    /// Keep `data` (already verified to have digest `sha256`).
    pub fn store(&self, sha256: &str, data: &[u8]) -> Result<PathBuf, String> {
        let path = self.tarball_path(sha256);
        write_atomic(&path, data).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(path)
    }

    /// Temporary-file directory inside the cache (same filesystem).
    pub fn tmp_dir(&self) -> PathBuf {
        self.dir()
    }

    fn index_path(&self) -> PathBuf {
        self.dir().join("releases.tsv")
    }

    /// Every valid index line.
    pub fn index(&self) -> Vec<Indexed> {
        let Ok(text) = fs::read_to_string(self.index_path()) else {
            return Vec::new();
        };
        text.lines().filter_map(parse_index_line).collect()
    }

    /// The most recently resolved entry matching `pred`.
    pub fn find(&self, pred: impl Fn(&Indexed) -> bool) -> Option<Indexed> {
        self.index()
            .into_iter()
            .filter(|i| pred(i))
            .max_by_key(|i| i.time)
    }

    /// Record that `spec` resolved to `release` on `mirror` at `time`,
    /// trusted as `trust`.
    pub fn record(
        &self,
        spec: &str,
        release: &Release,
        mirror: &str,
        trust: Trust,
        time: u64,
    ) -> Result<(), String> {
        if !is_index_mirror(mirror) {
            return Err(format!(
                "cannot record mirror {mirror:?} in the cache index"
            ));
        }
        let mut entries: Vec<Indexed> = self
            .index()
            .into_iter()
            .filter(|i| {
                !(i.spec == spec
                    && i.release.arch == release.arch
                    && i.release.sha256 == release.sha256
                    && i.mirror == mirror)
            })
            .collect();
        entries.push(Indexed {
            spec: spec.to_string(),
            release: release.clone(),
            mirror: mirror.to_string(),
            trust,
            time,
        });
        let mut text = String::from(
            "# vemu build: resolved Alpine releases (spec arch version branch file sha256 time mirror trust)\n",
        );
        for i in &entries {
            let r = &i.release;
            text.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                i.spec,
                r.arch,
                r.version,
                r.branch,
                r.file,
                r.sha256,
                i.time,
                i.mirror,
                i.trust.as_str()
            ));
        }
        let path = self.index_path();
        write_atomic(&path, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }
}

/// A mirror URL as the index stores it (no tabs or spaces).
fn is_index_mirror(m: &str) -> bool {
    (m.starts_with("https://") || m.starts_with("http://"))
        && m.bytes().all(|b| b.is_ascii_graphic())
}

/// Check that `dir` belongs to this user and only this user can write it.
fn check_private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(dir).map_err(|e| format!("cache directory {}: {e}", dir.display()))?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if m.uid() != me {
        return Err(format!(
            "refusing the cache directory {}: it belongs to uid {}, not to you (uid {me}); use --cache DIR",
            dir.display(),
            m.uid()
        ));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!(
            "refusing the cache directory {}: other users can write to it (mode {:04o}); chmod go-w it or use --cache DIR",
            dir.display(),
            m.mode() & 0o7777
        ));
    }
    Ok(())
}

fn parse_index_line(line: &str) -> Option<Indexed> {
    let f: Vec<&str> = line.split('\t').collect();
    // Lines of older vemu versions (no mirror, no trust) are ignored.
    let [
        spec,
        arch,
        version,
        branch,
        file,
        sha256,
        time,
        mirror,
        trust,
    ] = f.as_slice()
    else {
        return None;
    };
    let trust = Trust::parse(trust)?;
    let valid = is_version(version)
        && is_branch(branch)
        && matches!(*arch, "aarch64" | "x86_64")
        && *file == tarball_name(version, arch)
        && is_hex_digest(sha256)
        && !spec.is_empty()
        && is_index_mirror(mirror);
    valid.then(|| Indexed {
        spec: spec.to_string(),
        release: Release {
            version: version.to_string(),
            branch: branch.to_string(),
            arch: arch.to_string(),
            file: file.to_string(),
            sha256: sha256.to_string(),
            size: None,
        },
        mirror: mirror.to_string(),
        trust,
        time: time.parse().unwrap_or(0),
    })
}

/// Write `data` to `path` through a temporary file and a rename.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!("{TMP_PREFIX}{}-{}", std::process::id(), unique()));
    let r = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        let _guard = crate::cleanup::register_path(&tmp);
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("vemu-build-fetch-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn release(sha: &str) -> Release {
        Release {
            version: "3.24.4".into(),
            branch: "v3.24".into(),
            arch: "aarch64".into(),
            file: tarball_name("3.24.4", "aarch64"),
            sha256: sha.into(),
            size: None,
        }
    }

    #[test]
    fn urls_are_checked() {
        let c = Curl::new(false);
        assert!(c.check_url("https://dl-cdn.alpinelinux.org/x").is_ok());
        assert!(
            c.check_url("http://dl-cdn.alpinelinux.org/x")
                .unwrap_err()
                .contains("not an https")
        );
        assert!(c.check_url("file:///etc/passwd").is_err());
        assert!(
            c.check_url("https://a/b c")
                .unwrap_err()
                .contains("bad characters")
        );
        assert!(Curl::new(true).check_url("http://mirror/x").is_ok());
        assert!(Curl::new(true).check_url("ftp://mirror/x").is_err());
    }

    #[test]
    fn missing_curl_is_reported() {
        let d = temp_dir("nocurl");
        let c = Curl::with_program("/nonexistent/curl-xyz", false);
        let e = c.fetch("https://example.invalid/x", &d, 10, 5).unwrap_err();
        assert!(e.contains("not found") && e.contains("install curl"), "{e}");
        fs::remove_dir_all(&d).unwrap();
    }

    /// A failing curl's status and message reach the error, and the
    /// partial file is removed.
    #[test]
    fn curl_failure_is_reported() {
        let d = temp_dir("fail");
        let script = d.join("fake-curl");
        fs::write(
            &script,
            "#!/bin/sh\necho 'curl: (6) Could not resolve host: x' >&2\nexit 6\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let c = Curl::with_program(&script, false);
        let e = c.fetch("https://x/y", &d, 10, 5).unwrap_err();
        assert!(
            e.contains("exited with 6") && e.contains("offline") && e.contains("Could not resolve"),
            "{e}"
        );
        let left: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn cache_verifies_and_indexes() {
        let d = temp_dir("cache");
        let cache = Cache::open(&d).unwrap();
        let data = b"tarball bytes".to_vec();
        let sha = hex_digest(&data);
        assert_eq!(cache.load(&sha), None);
        cache.store(&sha, &data).unwrap();
        assert_eq!(cache.load(&sha), Some(data.clone()));
        // A corrupted cache file is dropped, not used.
        fs::write(cache.tarball_path(&sha), b"tampered").unwrap();
        assert_eq!(cache.load(&sha), None);
        assert!(!cache.tarball_path(&sha).exists());
        assert_eq!(cache.load("../../etc/passwd"), None);

        let r = release(&sha);
        let m = "https://dl-cdn.alpinelinux.org/alpine";
        cache
            .record("latest-stable", &r, m, Trust::Https, 100)
            .unwrap();
        cache.record("3.24.4", &r, m, Trust::Https, 200).unwrap();
        cache
            .record("latest-stable", &r, m, Trust::Https, 300)
            .unwrap(); // replaces the first
        // Another mirror, and its trust, is a separate entry.
        cache
            .record(
                "latest-stable",
                &r,
                "http://m.test/alpine",
                Trust::Pinned,
                50,
            )
            .unwrap();
        let idx = cache.index();
        assert_eq!(idx.len(), 3);
        let found = cache.find(|i| i.spec == "latest-stable").unwrap();
        assert_eq!(
            (
                found.time,
                found.release.clone(),
                found.mirror.as_str(),
                found.trust
            ),
            (300, r.clone(), m, Trust::Https)
        );
        let pinned = cache.find(|i| i.mirror.starts_with("http:")).unwrap();
        assert_eq!((pinned.time, pinned.trust), (50, Trust::Pinned));
        assert_eq!(cache.find(|i| i.release.sha256 == sha).unwrap().time, 300);
        assert!(cache.record("x", &r, "ftp://x", Trust::Https, 1).is_err());
        // Invalid lines are ignored, and so are the 7-field lines of older
        // versions (no mirror, no trust: they cannot be reused safely).
        let mut text = fs::read_to_string(cache.index_path()).unwrap();
        text.push_str("evil\tx86_64\t3.24.4\tv3.24\t../../x\tabc\t1\thttps://m\thttps\n");
        text.push_str(&format!(
            "3.24.4\taarch64\t3.24.4\tv3.24\t{}\t{sha}\t1\n",
            tarball_name("3.24.4", "aarch64")
        ));
        text.push_str(&format!(
            "3.24.4\taarch64\t3.24.4\tv3.24\t{}\t{sha}\t1\thttps://m\ttrusted\n",
            tarball_name("3.24.4", "aarch64")
        ));
        fs::write(cache.index_path(), text).unwrap();
        assert_eq!(cache.index().len(), 3);
        fs::remove_dir_all(&d).unwrap();
    }

    /// A cache another user could write to is refused; leftover temporary
    /// files are swept when old, kept when recent.
    #[test]
    fn cache_must_be_private_and_is_swept() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("private");
        let root = d.join("c");
        let cache = Cache::open(&root).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root.join("alpine")), 0o700);
        fs::set_permissions(root.join("alpine"), fs::Permissions::from_mode(0o777)).unwrap();
        let e = Cache::open(&root).unwrap_err();
        assert!(
            e.contains("other users can write to it") && e.contains("0777"),
            "{e}"
        );
        fs::set_permissions(root.join("alpine"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            Cache::open(&root)
                .unwrap_err()
                .contains("other users can write")
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        Cache::open(&root).unwrap();

        let dir = cache.dir();
        for n in [
            ".download-1-0",
            ".tmp-1-0",
            ".initrd-1-x.cpio",
            "keep.tar.gz",
        ] {
            fs::write(dir.join(n), "x").unwrap();
        }
        cache.sweep(SystemTime::now());
        assert!(dir.join(".download-1-0").exists(), "recent: kept");
        cache.sweep(SystemTime::now() + STALE + Duration::from_secs(60));
        assert!(!dir.join(".download-1-0").exists());
        assert!(!dir.join(".tmp-1-0").exists());
        assert!(!dir.join(".initrd-1-x.cpio").exists());
        assert!(dir.join("keep.tar.gz").exists(), "not a temporary file");
        let p = cache.temp_initrd_path("abc");
        assert!(
            p.starts_with(&dir)
                && p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".initrd-")
        );
        fs::remove_dir_all(&d).unwrap();
    }

    /// curl gets -q as its very first argument (no curlrc), https only.
    #[test]
    fn curl_ignores_curlrc() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("args");
        let script = d.join("fake-curl");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=$2; shift; done\necho ok > \"$out\"\n",
                d.join("args").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let got = Curl::with_program(&script, false)
            .fetch("https://x/y", &d, 10, 5)
            .unwrap();
        assert_eq!(got, b"ok\n");
        let args = fs::read_to_string(d.join("args")).unwrap();
        let args: Vec<&str> = args.lines().collect();
        assert_eq!(args[0], "-q", "{args:?}");
        assert!(
            args.windows(2).any(|w| w == ["--proto", "=https"]),
            "{args:?}"
        );
        assert!(
            args.windows(2).any(|w| w == ["--proto-redir", "=https"]),
            "{args:?}"
        );
        assert!(!args.iter().any(|a| *a == "-k" || *a == "--insecure"));
        // Nothing is left registered for cleanup after the download.
        assert!(
            !crate::cleanup::registered()
                .iter()
                .any(|p| p.starts_with(&d))
        );
        fs::remove_dir_all(&d).unwrap();
    }
}
