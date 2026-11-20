//! Image locking with `flock(2)`.
//!
//! Every file a disk uses is locked for as long as the disk exists, without
//! waiting: `LOCK_EX` to write it, `LOCK_SH` to only read it. So any number
//! of VMs may read one golden image (overlay bases and read-only disks take
//! `LOCK_SH`), but nobody can open it read-write meanwhile (`LOCK_EX`
//! conflicts), and one writable disk or overlay belongs to one VM.
//!
//! `flock` cannot say who holds a lock, only whether a shared request would
//! succeed. When an exclusive request fails, a shared one is tried on the
//! same descriptor: if that works, every holder is a reader, so the message
//! names the reader roles (read-only disk, golden image of an overlay);
//! otherwise a writer holds it.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::io::is_unsupported;

/// What a file is to the disk being opened (for error messages).
#[derive(Clone, Copy)]
pub(crate) enum Role<'a> {
    /// A raw image used directly as a disk.
    Disk,
    /// The golden (base) image of an overlay or snapshot.
    Golden(&'a Path),
    /// An overlay file.
    Overlay,
}

/// A file with an advisory lock, released when dropped.
pub struct LockedFile {
    file: File,
    locked: bool,
}

impl LockedFile {
    /// Lock `file` (exclusively when `exclusive`) without waiting. A
    /// conflict is [`io::ErrorKind::WouldBlock`] with a message saying who
    /// holds it. A filesystem without `flock` support only warns.
    pub(crate) fn lock(file: File, exclusive: bool, role: Role<'_>) -> io::Result<LockedFile> {
        let op = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        match try_flock(&file, op) {
            Ok(true) => Ok(LockedFile { file, locked: true }),
            Ok(false) => {
                // Readers only? (Our own descriptor holds nothing, so this is
                // an independent request; it is dropped right away.)
                let readers_only = exclusive && try_flock(&file, libc::LOCK_SH)? && {
                    unlock(&file);
                    true
                };
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    conflict_message(role, exclusive, readers_only),
                ))
            }
            Err(e) if e.raw_os_error().is_some_and(is_unsupported) => {
                static WARNED: AtomicBool = AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    let _ = io::Write::write_fmt(
                        &mut io::stderr(),
                        format_args!(
                            "vemu-disk: the filesystem cannot lock disk images; using them unlocked\n"
                        ),
                    );
                }
                Ok(LockedFile {
                    file,
                    locked: false,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// `file` without a lock (for read-only inspection of a file a VM
    /// holds).
    pub(crate) fn unlocked(file: File) -> LockedFile {
        LockedFile {
            file,
            locked: false,
        }
    }

    pub fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for LockedFile {
    /// Release the lock now. Closing the file alone would not when a forked
    /// child (between fork and exec, or a test's child) still shares the
    /// open file description that holds the lock.
    fn drop(&mut self) {
        if self.locked {
            unlock(&self.file);
        }
    }
}

/// `flock(op | LOCK_NB)`: `Ok(false)` if another holder conflicts.
fn try_flock(file: &File, op: libc::c_int) -> io::Result<bool> {
    loop {
        // SAFETY: flock on a file descriptor `file` owns; no memory involved.
        if unsafe { libc::flock(file.as_raw_fd(), op | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EWOULDBLOCK) => return Ok(false),
            _ => return Err(e),
        }
    }
}

fn unlock(file: &File) {
    // SAFETY: flock on a file descriptor `file` owns; no memory involved.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

fn conflict_message(role: Role<'_>, exclusive: bool, readers_only: bool) -> String {
    const BY: &str = "by another vemu or process";
    match role {
        Role::Disk if readers_only => format!(
            "image is in use read-only {BY} (as a read-only disk, or as the golden image of \
             an overlay or snapshot), so it cannot be opened read-write"
        ),
        Role::Disk if exclusive => format!("image is in use {BY} (lock held)"),
        Role::Disk => format!("image is in use read-write {BY} (lock held)"),
        Role::Overlay if readers_only => format!(
            "overlay is in use read-only {BY} (a VM has it with ,ro), so it cannot be opened \
             read-write"
        ),
        Role::Overlay => format!("overlay is in use read-write {BY} (a running VM writes it)"),
        Role::Golden(path) => format!(
            "golden image {} is in use read-write {BY} (a VM writes it as a raw disk); \
             overlays need it unchanged",
            path.display()
        ),
    }
}
