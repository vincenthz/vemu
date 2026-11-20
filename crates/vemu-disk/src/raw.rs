//! Raw disk images: the guest's disk is the file, byte for byte.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;

use crate::buf::{ReadBuf, WriteBuf};
use crate::format::MAGIC;
use crate::io::{pread_all, pwrite_all, sync_fd};
use crate::lock::{LockedFile, Role};
use crate::{BlockBackend, check_range};

/// A raw image file.
pub struct Raw {
    file: LockedFile,
    read_only: bool,
    size: u64,
    /// Refuse writes that would make the image start with the overlay
    /// magic (see [`Raw::guard_overlay_magic`]).
    guard: bool,
}

impl Raw {
    /// A disk backed by `file`. With `read_only` writes fail, even if the
    /// file is writable.
    ///
    /// Takes an advisory lock on `file` (shared if `read_only`, exclusive
    /// otherwise), held until the `Raw` is dropped. Fails with
    /// [`io::ErrorKind::WouldBlock`] if another open of the image (in this or
    /// another process) holds a conflicting lock.
    pub fn from_file(file: File, read_only: bool) -> io::Result<Raw> {
        let file = LockedFile::lock(file, !read_only, Role::Disk)?;
        // Seeking works for block devices too (their metadata length is 0).
        let size = file.file().seek(SeekFrom::End(0))?;
        Ok(Raw {
            file,
            read_only,
            size,
            guard: false,
        })
    }

    /// Refuse guest writes that would make the first bytes of the image the
    /// overlay magic. vemu recognizes overlays by that magic, so a guest
    /// could otherwise turn its raw disk into an "overlay" whose base is any
    /// file the host user can read, and read it on the next boot. Used for
    /// images whose format was detected (not given as `format=raw`).
    pub fn guard_overlay_magic(mut self) -> Raw {
        self.guard = true;
        self
    }

    pub fn file(&self) -> &File {
        self.file.file()
    }

    /// Would writing `buf` at `off` put the overlay magic at offset 0?
    fn writes_magic(&self, buf: WriteBuf<'_>, off: u64) -> io::Result<bool> {
        let n = MAGIC.len() as u64;
        if off >= n || buf.is_empty() || self.size < n {
            return Ok(false);
        }
        let mut head = [0u8; MAGIC.len()];
        pread_all(self.fd(), ReadBuf::new(&mut head), 0)?;
        let (s, e) = (off as usize, (off + buf.len() as u64).min(n) as usize);
        buf.sub(0, e - s).copy_to(&mut head[s..e]);
        Ok(head == MAGIC)
    }

    fn fd(&self) -> i32 {
        self.file().as_raw_fd()
    }
}

impl BlockBackend for Raw {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn read_at(&self, buf: ReadBuf<'_>, offset: u64) -> io::Result<()> {
        pread_all(self.fd(), buf, offset)
    }

    fn write_at(&self, buf: WriteBuf<'_>, offset: u64) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the disk is read-only",
            ));
        }
        if self.guard {
            check_range(offset, buf.len(), self.size)?;
            if self.writes_magic(buf, offset)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refused a write that would make this raw image start with the vemu \
                     overlay magic (give the disk as format=raw to allow it)",
                ));
            }
        }
        pwrite_all(self.fd(), buf, offset)
    }

    fn flush(&self) -> io::Result<()> {
        sync_fd(self.fd())
    }
}
