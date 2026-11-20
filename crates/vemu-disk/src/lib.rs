//! Disk backends for vemu's virtio-blk: what a guest disk's bytes are.
//!
//! - [`Raw`]: a raw image file, byte for byte (`--disk PATH`).
//! - [`Overlay`]: a vemu overlay, a sparse file holding the blocks a VM
//!   wrote on top of a read-only golden image (`--disk vm1.vov`), created by
//!   [`create`]; or a throwaway snapshot overlay in `$TMPDIR`, unlinked as
//!   soon as it is created ([`snapshot`], `--disk golden.raw,snapshot`).
//!
//! [`open`] picks the backend for a `--disk`. The file format is specified
//! in docs/overlay-format.md; [`overlay`]'s module documentation has the
//! I/O, concurrency and crash-consistency rules.
//!
//! Locking ([`lock`]): writable files take `flock(LOCK_EX)`, read-only ones
//! and golden images `LOCK_SH`, without waiting, so any number of VMs share
//! a golden image but none can write it meanwhile.

mod buf;
mod conflict;
mod format;
mod image;
mod io;
mod lock;
pub mod overlay;
mod raw;
#[cfg(test)]
mod tests_crash;
#[cfg(test)]
mod tests_model;
#[cfg(test)]
mod testutil;

use std::fs::OpenOptions;
use std::path::Path;
use std::sync::Arc;

pub use buf::{ReadBuf, WriteBuf};
pub use conflict::conflict_within;
pub use format::{
    DEFAULT_BLOCK_SIZE, Fingerprint, Header, MAGIC, MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, VERSION,
    check_block_size,
};
pub use image::{
    BaseStatus, OverlayInfo, create, fingerprint, fingerprint_changes, info, resolve_base,
    snapshot, temp_dir,
};
pub use io::sync_fd;
pub use overlay::Overlay;
pub use raw::Raw;

/// The bytes of a virtual disk.
///
/// Offsets and lengths are in bytes. Implementations are `Sync`: requests
/// may come from several threads at once (see [`overlay`] for what that
/// means for overlays).
pub trait BlockBackend: Send + Sync {
    /// Size of the virtual disk in bytes.
    fn size(&self) -> u64;
    /// Whether writes are refused.
    fn read_only(&self) -> bool;
    /// Read `buf.len()` bytes at `offset`.
    fn read_at(&self, buf: ReadBuf<'_>, offset: u64) -> std::io::Result<()>;
    /// Write `buf` at `offset`.
    fn write_at(&self, buf: WriteBuf<'_>, offset: u64) -> std::io::Result<()>;
    /// Make every completed write durable (virtio `FLUSH`).
    fn flush(&self) -> std::io::Result<()>;
    /// The VM stopped cleanly: persist what a clean exit keeps (an
    /// overlay's bitmap). Raw images need nothing.
    fn shutdown(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `[offset, offset + len)` must lie within a `size` byte disk.
pub(crate) fn check_range(offset: u64, len: usize, size: u64) -> std::io::Result<()> {
    if offset.checked_add(len as u64).is_some_and(|e| e <= size) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "request past the end of the disk",
        ))
    }
}

/// How `--disk` names the image's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// An overlay if the file starts with the overlay magic, else raw.
    #[default]
    Auto,
    /// Raw, whatever the content (no detection, no write guard).
    Raw,
    /// Must be an overlay.
    Overlay,
}

/// The `--disk` options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiskOptions {
    pub read_only: bool,
    /// Writes go to a throwaway overlay on the (raw) image.
    pub snapshot: bool,
    pub format: Format,
}

/// Open the disk at `path`.
///
/// - Without `snapshot`: an overlay (recognized by its magic, whatever the
///   file name) or a raw image. A raw image whose format was detected
///   refuses guest writes that would make it start with the overlay magic
///   ([`Raw::guard_overlay_magic`]); `Format::Raw` skips both.
/// - With `snapshot`: a throwaway overlay on the raw image `path`. Refused
///   with `read_only` (meaningless) and on an overlay (no chains).
///
/// Errors carry a message for the user that does not repeat `path`.
pub fn open(path: &Path, opts: DiskOptions) -> std::io::Result<Arc<dyn BlockBackend>> {
    use std::io::{Error, ErrorKind};
    let file = OpenOptions::new()
        .read(true)
        .write(!opts.read_only && !opts.snapshot)
        .open(path)
        .map_err(|e| image::context(e, "cannot open"))?;
    if opts.snapshot {
        if opts.read_only {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "snapshot and ro together make no sense (a snapshot disk is writable; its \
                 writes are discarded at exit)",
            ));
        }
        if opts.format == Format::Overlay
            || (opts.format == Format::Auto && image::has_overlay_magic(&file)?)
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "this is a vemu overlay: a snapshot on top of it would chain overlays, which is \
                 not supported (give the overlay without snapshot, or snapshot its raw golden \
                 image)",
            ));
        }
        drop(file);
        return Ok(Arc::new(image::snapshot(path)?));
    }
    let overlay = match opts.format {
        Format::Raw => false,
        Format::Auto => image::has_overlay_magic(&file)?,
        Format::Overlay => {
            if !image::has_overlay_magic(&file)? {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "not a vemu overlay (no VEMUOVL header)",
                ));
            }
            true
        }
    };
    if overlay {
        let hint = opts.format == Format::Auto;
        return Ok(Arc::new(image::open_overlay(
            file,
            path,
            opts.read_only,
            hint,
        )?));
    }
    let raw = Raw::from_file(file, opts.read_only)?;
    Ok(Arc::new(if opts.format == Format::Auto {
        raw.guard_overlay_magic()
    } else {
        raw
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, base_pattern};
    use std::fs;

    fn opts(read_only: bool, snapshot: bool, format: Format) -> DiskOptions {
        DiskOptions {
            read_only,
            snapshot,
            format,
        }
    }

    fn read(d: &dyn BlockBackend, off: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        d.read_at(ReadBuf::new(&mut v), off).unwrap();
        v
    }

    #[test]
    fn detects_overlays_by_magic_not_name() {
        let dir = TempDir::new("detect");
        let g = dir.join("golden.vov"); // a raw image, despite the name
        fs::write(&g, base_pattern(64 << 10)).unwrap();
        let ov = dir.join("disk.img"); // an overlay, despite the name
        create(&g, &ov, 4096).unwrap();
        let d = open(&ov, DiskOptions::default()).unwrap();
        d.write_at(WriteBuf::new(b"over"), 0).unwrap();
        assert_eq!(read(&*d, 0, 4), b"over");
        d.shutdown().unwrap();
        drop(d);
        assert_eq!(&fs::read(&g).unwrap()[..4], &base_pattern(4)[..]);
        // format=raw shows the overlay file itself.
        let d = open(&ov, opts(true, false, Format::Raw)).unwrap();
        assert_eq!(read(&*d, 0, 8), MAGIC);
        drop(d);
        let e = open(&g, opts(false, false, Format::Overlay)).err().unwrap();
        assert!(e.to_string().contains("not a vemu overlay"), "{e}");
    }

    #[test]
    fn snapshot_option_refusals() {
        let dir = TempDir::new("snapopts");
        let g = dir.join("golden.raw");
        fs::write(&g, base_pattern(64 << 10)).unwrap();
        let ov = dir.join("vm.vov");
        create(&g, &ov, 4096).unwrap();
        let e = open(&g, opts(true, true, Format::Auto)).err().unwrap();
        assert!(e.to_string().contains("make no sense"), "{e}");
        for f in [Format::Auto, Format::Overlay] {
            let e = open(&ov, opts(false, true, f)).err().unwrap();
            assert!(e.to_string().contains("chain"), "{e}");
        }
        let e = open(&dir.join("missing"), opts(false, true, Format::Auto))
            .err()
            .unwrap();
        assert!(e.to_string().starts_with("cannot open: "), "{e}");
    }

    /// A raw image with the magic but no valid header is refused with a
    /// hint; format=raw opens it.
    #[test]
    fn raw_image_starting_with_the_magic() {
        let dir = TempDir::new("magic");
        let p = dir.join("odd.raw");
        let mut data = base_pattern(8192);
        data[..8].copy_from_slice(&MAGIC);
        fs::write(&p, &data).unwrap();
        let e = open(&p, DiskOptions::default()).err().unwrap();
        assert!(e.to_string().contains("format=raw"), "{e}");
        let d = open(&p, opts(false, false, Format::Raw)).unwrap();
        assert_eq!(read(&*d, 0, 8192), data);
        // Explicitly raw: the guest may write anything.
        d.write_at(WriteBuf::new(&MAGIC), 0).unwrap();
    }

    /// A guest cannot turn its detected-raw disk into an overlay.
    #[test]
    fn guest_cannot_write_the_magic_into_a_detected_raw_image() {
        let dir = TempDir::new("guard");
        let p = dir.join("disk.raw");
        fs::write(&p, vec![0u8; 8192]).unwrap();
        let d = open(&p, DiskOptions::default()).unwrap();
        let e = d.write_at(WriteBuf::new(&MAGIC), 0).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        // Byte by byte, or split across two requests: still caught.
        d.write_at(WriteBuf::new(&MAGIC[..5]), 0).unwrap();
        assert!(d.write_at(WriteBuf::new(&MAGIC[5..]), 5).is_err());
        // Anything else at offset 0 is fine, as is the magic elsewhere.
        d.write_at(WriteBuf::new(b"VEMUOVL!"), 0).unwrap();
        d.write_at(WriteBuf::new(&MAGIC), 512).unwrap();
        let mut sector = vec![0u8; 512];
        sector[..8].copy_from_slice(&MAGIC);
        assert!(d.write_at(WriteBuf::new(&sector), 0).is_err());
        drop(d);
        assert_eq!(&fs::read(&p).unwrap()[..8], b"VEMUOVL!");
    }
}
