//! What to remove if a signal or a panic ends the process mid-build.
//!
//! A build creates temporary files (downloads, the builder initramfs,
//! `OUT.partial`) and runs curl. Their owners delete them on every normal
//! path, but a signal's default action or `process::exit` from a panic
//! hook runs no destructor. So each owner also registers the file (and
//! curl's pid) here while it exists, and the `vemu` binary's signal
//! handler and panic hook call [`run_now`], which kills the registered
//! children and unlinks the registered paths.
//!
//! [`run_now`] is async-signal-safe: it only reads atomics and calls
//! `kill(2)` and `unlink(2)`. A registered path's C string is never freed
//! (a few bytes per temporary file), so a handler running on another
//! thread can never see a dangling pointer.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

const PATH_SLOTS: usize = 32;
const PID_SLOTS: usize = 8;

static PATHS: [AtomicPtr<libc::c_char>; PATH_SLOTS] =
    [const { AtomicPtr::new(ptr::null_mut()) }; PATH_SLOTS];
static PIDS: [AtomicI32; PID_SLOTS] = [const { AtomicI32::new(0) }; PID_SLOTS];

/// A registered path: unregistered (not deleted) on drop.
#[derive(Debug)]
pub struct PathGuard {
    slot: Option<usize>,
}

/// Remove `path` if the process dies of a signal or a panic before the
/// returned guard is dropped. Register only a path this process created
/// (or is about to create under a name unique to it), never one that
/// another process might own. Best effort: with every slot taken, the
/// path is not registered.
pub fn register_path(path: &Path) -> PathGuard {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return PathGuard { slot: None };
    };
    let raw = c.into_raw();
    for (i, s) in PATHS.iter().enumerate() {
        if s.compare_exchange(ptr::null_mut(), raw, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return PathGuard { slot: Some(i) };
        }
    }
    // SAFETY: raw came from CString::into_raw above and was never shared.
    drop(unsafe { CString::from_raw(raw) });
    PathGuard { slot: None }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        if let Some(i) = self.slot {
            // The string is leaked on purpose (see the module comment).
            PATHS[i].store(ptr::null_mut(), Ordering::SeqCst);
        }
    }
}

/// A registered child process: unregistered on drop.
#[derive(Debug)]
pub struct ChildGuard {
    slot: Option<usize>,
}

/// Send SIGTERM to `pid` if the process dies of a signal or a panic
/// before the guard is dropped.
pub fn register_child(pid: u32) -> ChildGuard {
    let Ok(pid) = i32::try_from(pid) else {
        return ChildGuard { slot: None };
    };
    for (i, s) in PIDS.iter().enumerate() {
        if s.compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return ChildGuard { slot: Some(i) };
        }
    }
    ChildGuard { slot: None }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(i) = self.slot {
            PIDS[i].store(0, Ordering::SeqCst);
        }
    }
}

/// Kill the registered children and unlink the registered paths. Safe in
/// a signal handler.
pub fn run_now() {
    run_filtered(&|_| true, &|_| true);
}

/// [`run_now`] for the children and paths the filters accept (tests run
/// in one process, and must not clean up each other's files).
fn run_filtered(pid_ok: &dyn Fn(i32) -> bool, path_ok: &dyn Fn(&[u8]) -> bool) {
    for s in &PIDS {
        let pid = s.load(Ordering::SeqCst);
        if pid > 0
            && pid_ok(pid)
            && s.compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            // SAFETY: kill is async-signal-safe.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }
    for s in &PATHS {
        let p = s.load(Ordering::SeqCst);
        if p.is_null() {
            continue;
        }
        // SAFETY: p is a valid C string that is never freed (strlen only).
        let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
        if path_ok(bytes)
            && s.compare_exchange(p, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            // SAFETY: as above; unlink is async-signal-safe.
            unsafe { libc::unlink(p) };
        }
    }
}

/// The registered paths (for tests).
#[cfg(test)]
pub(crate) fn registered() -> Vec<std::path::PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    PATHS
        .iter()
        .filter_map(|s| {
            let p = s.load(Ordering::SeqCst);
            // SAFETY: registered strings are never freed.
            (!p.is_null()).then(|| {
                let b = unsafe { CStr::from_ptr(p) }.to_bytes();
                std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn paths_are_unlinked_and_children_killed() {
        let d = std::env::temp_dir().join(format!("vemu-build-cleanup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let (a, b) = (d.join("a"), d.join("b"));
        fs::write(&a, "a").unwrap();
        fs::write(&b, "b").unwrap();
        let ga = register_path(&a);
        let gb = register_path(&b);
        assert!(registered().contains(&a) && registered().contains(&b));
        drop(gb);
        assert!(!registered().contains(&b), "a dropped guard unregisters");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let gc = register_child(child.id());
        let prefix = d.as_os_str().as_bytes().to_vec();
        run_filtered(&|p| p == pid, &|b| b.starts_with(&prefix));
        assert!(!a.exists(), "registered: removed");
        assert!(b.exists(), "unregistered: kept");
        let st = child.wait().unwrap();
        assert!(!st.success(), "the child was killed");
        drop((ga, gc));
        fs::remove_dir_all(&d).unwrap();
    }
}
