//! The output image's lifecycle.
//!
//! The builder writes `OUT.partial`, created exclusively and sparse at the
//! image size. Only a successful build turns it into `OUT`: synced,
//! renamed into place, then made read-only (0444: it is meant as a golden
//! image for overlays). Anything else removes `OUT.partial`: on drop (early
//! returns, unwinding panics) and through [`crate::cleanup`] (signals, and
//! a panic hook that exits without unwinding). An
//! existing `OUT` is refused unless `--force`; then the rename replaces it
//! atomically at the end of a successful build.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// `PATH` with `suffix` appended to its file name.
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// `OUT.partial`.
pub fn partial_path(out: &Path) -> PathBuf {
    with_suffix(out, ".partial")
}

/// `OUT.build.log`.
pub fn log_path(out: &Path) -> PathBuf {
    with_suffix(out, ".build.log")
}

/// Refuse an output that cannot be (re)built: an existing `OUT` without
/// `force`, a directory, a missing parent directory.
pub fn check(out: &Path, force: bool) -> Result<(), String> {
    if out.file_name().is_none() {
        return Err(format!("output {}: not a file name", out.display()));
    }
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(format!(
            "output {}: directory {} does not exist",
            out.display(),
            parent.display()
        ));
    }
    match fs::symlink_metadata(out) {
        Ok(m) if m.is_dir() => Err(format!("output {} is a directory", out.display())),
        Ok(_) if !force => Err(format!(
            "output {} already exists (use --force to replace it; overlays made on it will then be refused)",
            out.display()
        )),
        Ok(m) if !m.is_file() => Err(format!(
            "output {} exists and is not a regular file",
            out.display()
        )),
        _ => Ok(()),
    }
}

/// The image being built (`OUT.partial`).
#[derive(Debug)]
pub struct Target {
    out: PathBuf,
    partial: PathBuf,
    armed: bool,
    /// Registered once this process created `OUT.partial` (never before:
    /// it must not remove another build's).
    guard: Option<crate::cleanup::PathGuard>,
}

impl Target {
    /// Create `OUT.partial`, sparse, `size` bytes. A leftover
    /// `OUT.partial` is refused, or replaced with `force` unless a running
    /// build still holds it (its lock).
    pub fn create(out: &Path, size: u64, force: bool) -> Result<Target, String> {
        check(out, force)?;
        let partial = partial_path(out);
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&partial)
        };
        let file = match open() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if !force {
                    return Err(format!(
                        "{} exists: another vemu build is writing it, or one was interrupted \
                         (use --force to remove a leftover)",
                        partial.display()
                    ));
                }
                let f = File::open(&partial).map_err(|e| format!("{}: {e}", partial.display()))?;
                if f.try_lock().is_err() {
                    return Err(format!(
                        "{} is in use by a running vemu build",
                        partial.display()
                    ));
                }
                drop(f);
                fs::remove_file(&partial)
                    .map_err(|e| format!("cannot remove {}: {e}", partial.display()))?;
                open().map_err(|e| format!("cannot create {}: {e}", partial.display()))?
            }
            Err(e) => return Err(format!("cannot create {}: {e}", partial.display())),
        };
        let target = Target {
            out: out.to_path_buf(),
            guard: Some(crate::cleanup::register_path(&partial)),
            partial,
            armed: true,
        };
        file.set_len(size).map_err(|e| {
            format!(
                "cannot size {} to {size} bytes: {e}",
                target.partial.display()
            )
        })?;
        Ok(target)
    }

    pub fn partial(&self) -> &Path {
        &self.partial
    }

    pub fn out(&self) -> &Path {
        &self.out
    }

    /// The build succeeded: sync, rename to `OUT`, make it read-only.
    pub fn commit(mut self) -> Result<(), String> {
        let ctx = |what: &str, e: io::Error| format!("{what} {}: {e}", self.partial.display());
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.partial)
            .map_err(|e| ctx("cannot open", e))?;
        f.sync_all().map_err(|e| ctx("cannot sync", e))?;
        drop(f);
        // Unregistered first: once renamed, OUT.partial may be another
        // build's (a signal in between leaves this one behind at worst).
        self.guard = None;
        fs::rename(&self.partial, &self.out).map_err(|e| ctx("cannot rename", e))?;
        self.armed = false;
        set_mode(&self.out, 0o444)
            .map_err(|e| format!("cannot make {} read-only: {e}", self.out.display()))?;
        if let Some(dir) = self.out.parent().filter(|p| !p.as_os_str().is_empty()) {
            // The rename is durable once the directory is synced.
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.partial);
        }
    }
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vemu-build-out-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn success_renames_and_seals() {
        let d = dir("ok");
        let out = d.join("img.raw");
        let t = Target::create(&out, 64 << 20, false).unwrap();
        assert_eq!(t.partial(), d.join("img.raw.partial"));
        assert!(crate::cleanup::registered().contains(&d.join("img.raw.partial")));
        let m = fs::metadata(t.partial()).unwrap();
        assert_eq!(m.len(), 64 << 20);
        assert!(m.blocks() * 512 < 1 << 20, "sparse: {} blocks", m.blocks());
        // A second build of the same output meanwhile is refused.
        let e = Target::create(&out, 64 << 20, false).unwrap_err();
        assert!(e.contains("img.raw.partial exists"), "{e}");
        t.commit().unwrap();
        assert!(!d.join("img.raw.partial").exists());
        assert!(!crate::cleanup::registered().contains(&d.join("img.raw.partial")));
        let m = fs::metadata(&out).unwrap();
        assert_eq!((m.len(), m.permissions().mode() & 0o777), (64 << 20, 0o444));
        // Now OUT exists: refused without --force, replaced with it.
        let e = Target::create(&out, 64 << 20, false).unwrap_err();
        assert!(e.contains("already exists") && e.contains("--force"), "{e}");
        let t = Target::create(&out, 128 << 20, true).unwrap();
        assert_eq!(
            fs::metadata(&out).unwrap().len(),
            64 << 20,
            "OUT untouched until commit"
        );
        t.commit().unwrap();
        assert_eq!(fs::metadata(&out).unwrap().len(), 128 << 20);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failure_removes_the_partial() {
        let d = dir("fail");
        let out = d.join("img.raw");
        {
            let t = Target::create(&out, 1 << 20, false).unwrap();
            assert!(t.partial().exists());
        } // dropped without commit: a failed build
        assert!(!partial_path(&out).exists());
        assert!(!out.exists());
        // A leftover partial (an interrupted build): --force removes it.
        fs::write(partial_path(&out), b"junk").unwrap();
        assert!(
            Target::create(&out, 1 << 20, false)
                .unwrap_err()
                .contains("interrupted")
        );
        assert!(
            !crate::cleanup::registered().contains(&partial_path(&out)),
            "a refused build never registers another's partial"
        );
        let t = Target::create(&out, 1 << 20, true).unwrap();
        assert_eq!(fs::metadata(t.partial()).unwrap().len(), 1 << 20);
        // ... but not one a running build holds (its disk lock).
        let held = File::open(t.partial()).unwrap();
        held.lock().unwrap();
        let e = Target::create(&out, 1 << 20, true).unwrap_err();
        assert!(e.contains("in use"), "{e}");
        drop(held);
        drop(t);
        assert!(!partial_path(&out).exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn bad_outputs() {
        let d = dir("bad");
        assert!(check(&d, true).unwrap_err().contains("is a directory"));
        assert!(
            check(&d.join("nope/x.raw"), false)
                .unwrap_err()
                .contains("does not exist")
        );
        assert!(check(&d.join("x.raw"), false).is_ok());
        assert_eq!(
            log_path(Path::new("a/b.raw")),
            PathBuf::from("a/b.raw.build.log")
        );
        fs::remove_dir_all(&d).unwrap();
    }
}
