//! File primitives: positioned reads and writes into [`ReadBuf`] /
//! [`WriteBuf`], durable syncs, and the [`Storage`] seam the overlay does
//! its I/O through (a real file, or an in-memory fault-injecting file in
//! the crash tests).

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};

use crate::buf::{ReadBuf, WriteBuf};
use crate::lock::LockedFile;

/// Read exactly `buf.len()` bytes at `off`. End of file is an error.
pub fn pread_all(fd: RawFd, buf: ReadBuf<'_>, mut off: u64) -> io::Result<()> {
    let mut ptr = buf.as_mut_ptr();
    let mut len = buf.len();
    while len > 0 {
        let file_off =
            libc::off_t::try_from(off).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `ptr` is valid for `len` bytes of writes (ReadBuf's
        // contract), for the whole call. The kernel writes into it; no Rust
        // reference aliases it.
        let r = unsafe { libc::pread(fd, ptr.cast(), len, file_off) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if r == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let r = r as usize;
        // SAFETY: r <= len, so the pointer stays inside the buffer.
        ptr = unsafe { ptr.add(r) };
        len -= r;
        off += r as u64;
    }
    Ok(())
}

/// Write all of `buf` at `off`.
pub fn pwrite_all(fd: RawFd, buf: WriteBuf<'_>, mut off: u64) -> io::Result<()> {
    let mut ptr = buf.as_ptr();
    let mut len = buf.len();
    while len > 0 {
        let file_off =
            libc::off_t::try_from(off).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `ptr` is valid for `len` bytes of reads (WriteBuf's
        // contract); the kernel only reads it.
        let r = unsafe { libc::pwrite(fd, ptr.cast(), len, file_off) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if r == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let r = r as usize;
        // SAFETY: r <= len, so the pointer stays inside the buffer.
        ptr = unsafe { ptr.add(r) };
        len -= r;
        off += r as u64;
    }
    Ok(())
}

/// Make written data durable. On macOS `fsync` only reaches the drive's cache;
/// `F_FULLFSYNC` flushes it (falling back to `fsync` where unsupported).
#[cfg(target_os = "macos")]
pub fn sync_fd(fd: RawFd) -> io::Result<()> {
    full_then_plain_sync(
        || {
            // SAFETY: fcntl on a file descriptor we own; F_FULLFSYNC takes
            // no argument.
            if unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        },
        || {
            // SAFETY: fsync on a file descriptor we own.
            if unsafe { libc::fsync(fd) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        },
    )
}

/// Make written data durable. On Linux `fdatasync` also flushes the drive's
/// write cache (the block layer issues a cache flush), and it writes the
/// metadata needed to read the data back (block allocation in a sparse
/// image); timestamps can wait.
#[cfg(not(target_os = "macos"))]
pub fn sync_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: fdatasync on a file descriptor we own.
    if unsafe { libc::fdatasync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Run `full` (`F_FULLFSYNC`); only if it reports "not supported here" fall
/// back to `plain` (`fsync`). Any other failure (EIO, ENOSPC...) is the
/// flush's result: a plain fsync succeeding afterwards proves nothing about
/// durability, so it must not turn the error into success.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn full_then_plain_sync(
    full: impl FnOnce() -> io::Result<()>,
    plain: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    match full() {
        Ok(()) => Ok(()),
        Err(e) => match e.raw_os_error() {
            Some(n) if is_unsupported(n) || n == libc::EINVAL || n == libc::ENOTTY => plain(),
            _ => Err(e),
        },
    }
}

/// "Operation not supported". `ENOTSUP` and `EOPNOTSUPP` are distinct on
/// macOS but the same number on Linux, so they cannot share a match pattern.
pub(crate) fn is_unsupported(errno: i32) -> bool {
    errno == libc::ENOTSUP || errno == libc::EOPNOTSUPP
}

/// Where an overlay keeps its bytes: the overlay file, or the golden image
/// (only read). The crash tests substitute an in-memory file that fails
/// from a chosen operation on and then loses unsynced writes.
pub(crate) trait Storage: Send + Sync {
    /// Read exactly `buf.len()` bytes at `off`.
    fn read_at(&self, buf: ReadBuf<'_>, off: u64) -> io::Result<()>;
    /// Write all of `buf` at `off`.
    fn write_at(&self, buf: WriteBuf<'_>, off: u64) -> io::Result<()>;
    /// Make every completed write durable (a barrier: no write issued after
    /// it becomes durable before the writes issued before it).
    fn sync(&self) -> io::Result<()>;
    /// Current length in bytes.
    fn len(&self) -> io::Result<u64>;
}

/// A locked host file as [`Storage`].
pub(crate) struct FileStorage(pub LockedFile);

impl FileStorage {
    pub fn file(&self) -> &File {
        self.0.file()
    }
}

impl Storage for FileStorage {
    fn read_at(&self, buf: ReadBuf<'_>, off: u64) -> io::Result<()> {
        pread_all(self.file().as_raw_fd(), buf, off)
    }

    fn write_at(&self, buf: WriteBuf<'_>, off: u64) -> io::Result<()> {
        pwrite_all(self.file().as_raw_fd(), buf, off)
    }

    fn sync(&self) -> io::Result<()> {
        sync_fd(self.file().as_raw_fd())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file().metadata()?.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_falls_back_only_when_unsupported() {
        let err = |n| move || -> io::Result<()> { Err(io::Error::from_raw_os_error(n)) };
        let ok = || -> io::Result<()> { Ok(()) };
        let never = || -> io::Result<()> { panic!("fsync must not run") };
        assert!(full_then_plain_sync(ok, never).is_ok());
        for n in [libc::ENOTSUP, libc::EOPNOTSUPP, libc::EINVAL, libc::ENOTTY] {
            assert!(full_then_plain_sync(err(n), ok).is_ok(), "errno {n}");
            assert_eq!(
                full_then_plain_sync(err(n), err(libc::EIO))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EIO)
            );
        }
        // A real I/O error is reported, not papered over by fsync.
        for n in [libc::EIO, libc::ENOSPC, libc::EBADF] {
            let r = full_then_plain_sync(err(n), never);
            assert_eq!(r.unwrap_err().raw_os_error(), Some(n));
        }
    }
}
