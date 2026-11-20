//! The vemu overlay file format, version 1 (docs/overlay-format.md is the
//! specification; keep the two in sync).
//!
//! ```text
//! 0                 header (fixed fields, then the base path), CRC-32C
//! bitmap_offset     allocation bitmap, 1 bit per block (page aligned)
//! data_offset       the virtual disk, sparse: guest byte X is at data_offset + X
//! ```

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

pub const MAGIC: [u8; 8] = *b"VEMUOVL\0";
pub const VERSION: u32 = 1;
/// Length of the fixed header fields; the base path follows.
pub const FIXED_LEN: usize = 88;
/// Longest base path stored.
pub const MAX_PATH: usize = 4096;
/// Bitmap I/O unit and the alignment of the bitmap.
pub const PAGE: u64 = 4096;
pub const MIN_BLOCK_SIZE: u32 = 512;
pub const MAX_BLOCK_SIZE: u32 = 2 << 20;
/// 4 KiB: the guest's filesystem block and page size, and the host's sparse
/// file granularity, so a guest's 4 KiB writes never copy up and the
/// overlay grows by what is written (see docs/overlay-format.md).
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;
/// Bitmaps larger than this (in bytes) are refused: 128 MiB of bitmap is
/// 4 TiB of disk at 4 KiB blocks. A larger block size covers larger disks.
pub const MAX_BITMAP_LEN: u64 = 128 << 20;

// Field offsets.
const O_VERSION: usize = 8;
const O_HEADER_LEN: usize = 12;
const O_BLOCK_SIZE: usize = 16;
const O_FLAGS: usize = 20;
const O_VIRTUAL_SIZE: usize = 24;
const O_BITMAP_OFFSET: usize = 32;
const O_BITMAP_LEN: usize = 40;
const O_DATA_OFFSET: usize = 48;
const O_BASE_SIZE: usize = 56;
const O_BASE_MTIME: usize = 64;
const O_BASE_DIGEST: usize = 72;
const O_PATH_LEN: usize = 80;
const O_RESERVED: usize = 82;
const O_CHECKSUM: usize = 84;

/// What identifies the golden image an overlay was made on. Every field
/// must match when the overlay is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    /// Size in bytes (also the overlay's virtual size).
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    /// FNV-1a 64 of sampled windows of the content ([`SAMPLES`] of
    /// [`SAMPLE_LEN`] bytes, evenly spaced, first and last included).
    pub digest: u64,
}

/// Number of sampled windows in [`Fingerprint::digest`].
pub const SAMPLES: u64 = 16;
/// Bytes per sampled window.
pub const SAMPLE_LEN: u64 = 64 << 10;

/// A decoded (and validated) overlay header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub block_size: u32,
    pub virtual_size: u64,
    pub bitmap_offset: u64,
    pub bitmap_len: u64,
    pub data_offset: u64,
    pub base: Fingerprint,
    /// The base reference as stored: relative to the overlay's directory,
    /// or absolute.
    pub base_path: PathBuf,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Check a block size: a power of two in `MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE`.
pub fn check_block_size(bs: u32) -> io::Result<()> {
    if bs.is_power_of_two() && (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bs) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "block size {bs} is not a power of two from {MIN_BLOCK_SIZE} to {} bytes",
                MAX_BLOCK_SIZE
            ),
        ))
    }
}

impl Header {
    /// The header of a new overlay of `base` (its fingerprint, and its path
    /// as it will be stored), with the version 1 layout.
    pub fn new(block_size: u32, base: Fingerprint, base_path: PathBuf) -> io::Result<Header> {
        check_block_size(block_size)?;
        if base.size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the golden image is empty",
            ));
        }
        let path_len = base_path.as_os_str().len();
        if path_len == 0 || path_len > MAX_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the golden image path is {path_len} bytes (at most {MAX_PATH})"),
            ));
        }
        let header_len = (FIXED_LEN + path_len) as u64;
        let bs = u64::from(block_size);
        let blocks = base.size.div_ceil(bs);
        let bitmap_len = blocks.div_ceil(8);
        if bitmap_len > MAX_BITMAP_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "a {} byte disk needs a {bitmap_len} byte bitmap at {block_size} byte blocks \
                     (at most {MAX_BITMAP_LEN}); use a larger block size",
                    base.size
                ),
            ));
        }
        let bitmap_offset = header_len.next_multiple_of(PAGE);
        let data_offset = (bitmap_offset + bitmap_len).next_multiple_of(bs.max(PAGE));
        Ok(Header {
            block_size,
            virtual_size: base.size,
            bitmap_offset,
            bitmap_len,
            data_offset,
            base,
            base_path,
        })
    }

    /// Number of blocks (the last one may be partial).
    pub fn blocks(&self) -> u64 {
        self.virtual_size.div_ceil(u64::from(self.block_size))
    }

    /// Length of the encoded header (fixed fields and path).
    pub fn header_len(&self) -> usize {
        FIXED_LEN + self.base_path.as_os_str().len()
    }

    /// Size of the overlay file: up to the end of the data region.
    pub fn file_len(&self) -> u64 {
        self.data_offset + self.virtual_size
    }

    pub fn encode(&self) -> Vec<u8> {
        let path = self.base_path.as_os_str().as_bytes();
        let mut h = vec![0u8; FIXED_LEN + path.len()];
        h[..8].copy_from_slice(&MAGIC);
        put32(&mut h, O_VERSION, VERSION);
        let len = h.len() as u32;
        put32(&mut h, O_HEADER_LEN, len);
        put32(&mut h, O_BLOCK_SIZE, self.block_size);
        put32(&mut h, O_FLAGS, 0);
        put64(&mut h, O_VIRTUAL_SIZE, self.virtual_size);
        put64(&mut h, O_BITMAP_OFFSET, self.bitmap_offset);
        put64(&mut h, O_BITMAP_LEN, self.bitmap_len);
        put64(&mut h, O_DATA_OFFSET, self.data_offset);
        put64(&mut h, O_BASE_SIZE, self.base.size);
        put64(&mut h, O_BASE_MTIME, self.base.mtime_ns as u64);
        put64(&mut h, O_BASE_DIGEST, self.base.digest);
        h[O_PATH_LEN..O_PATH_LEN + 2].copy_from_slice(&(path.len() as u16).to_le_bytes());
        h[O_RESERVED..O_RESERVED + 2].copy_from_slice(&[0, 0]);
        h[FIXED_LEN..].copy_from_slice(path);
        let crc = crc32c(&h);
        put32(&mut h, O_CHECKSUM, crc);
        h
    }

    /// The header length announced by the first [`FIXED_LEN`] bytes, after
    /// checking the magic and the version (so the caller knows how much to
    /// read for [`Header::decode`]).
    pub fn peek_len(fixed: &[u8]) -> io::Result<usize> {
        if fixed.len() < 8 || fixed[..8] != MAGIC {
            return Err(invalid("not a vemu overlay (bad magic)"));
        }
        if fixed.len() < FIXED_LEN {
            return Err(invalid("truncated overlay header"));
        }
        let version = get32(fixed, O_VERSION);
        if version != VERSION {
            return Err(invalid(format!(
                "unsupported overlay format version {version} (this vemu reads version {VERSION})"
            )));
        }
        let len = get32(fixed, O_HEADER_LEN) as usize;
        if !(FIXED_LEN + 1..=FIXED_LEN + MAX_PATH).contains(&len) {
            return Err(invalid(format!(
                "corrupt overlay header (header length {len})"
            )));
        }
        Ok(len)
    }

    /// Decode and validate a header; `bytes` holds at least its
    /// [`Header::peek_len`] bytes.
    pub fn decode(bytes: &[u8]) -> io::Result<Header> {
        let len = Header::peek_len(bytes)?;
        if bytes.len() < len {
            return Err(invalid("truncated overlay header"));
        }
        let mut h = bytes[..len].to_vec();
        let stored = get32(&h, O_CHECKSUM);
        put32(&mut h, O_CHECKSUM, 0);
        if crc32c(&h) != stored {
            return Err(invalid(
                "overlay header checksum mismatch: the header is corrupt",
            ));
        }
        let flags = get32(&h, O_FLAGS);
        if flags != 0 {
            return Err(invalid(format!(
                "the overlay uses unsupported features (flags {flags:#x})"
            )));
        }
        let path_len = usize::from(u16::from_le_bytes([h[O_PATH_LEN], h[O_PATH_LEN + 1]]));
        if FIXED_LEN + path_len != len || h[O_RESERVED..O_RESERVED + 2] != [0, 0] {
            return Err(invalid("corrupt overlay header (base path length)"));
        }
        let block_size = get32(&h, O_BLOCK_SIZE);
        check_block_size(block_size)
            .map_err(|e| invalid(format!("corrupt overlay header: {e}")))?;
        let hdr = Header {
            block_size,
            virtual_size: get64(&h, O_VIRTUAL_SIZE),
            bitmap_offset: get64(&h, O_BITMAP_OFFSET),
            bitmap_len: get64(&h, O_BITMAP_LEN),
            data_offset: get64(&h, O_DATA_OFFSET),
            base: Fingerprint {
                size: get64(&h, O_BASE_SIZE),
                mtime_ns: get64(&h, O_BASE_MTIME) as i64,
                digest: get64(&h, O_BASE_DIGEST),
            },
            base_path: PathBuf::from(OsStr::from_bytes(&h[FIXED_LEN..])),
        };
        hdr.check_layout(len as u64)?;
        Ok(hdr)
    }

    fn check_layout(&self, header_len: u64) -> io::Result<()> {
        let bad = |what: &str| invalid(format!("corrupt overlay header ({what})"));
        let bs = u64::from(self.block_size);
        if self.virtual_size == 0 || self.virtual_size != self.base.size {
            return Err(bad("virtual size"));
        }
        if self.bitmap_len != self.blocks().div_ceil(8) || self.bitmap_len > MAX_BITMAP_LEN {
            return Err(bad("bitmap length"));
        }
        if self.bitmap_offset < header_len || !self.bitmap_offset.is_multiple_of(PAGE) {
            return Err(bad("bitmap offset"));
        }
        // Checked: a crafted header (the CRC is no protection) must not
        // overflow. With bitmap_end <= data_offset <= i64::MAX below, every
        // later `bitmap_offset + pos` stays in range.
        let Some(bitmap_end) = self.bitmap_offset.checked_add(self.bitmap_len) else {
            return Err(bad("bitmap offset"));
        };
        if self.data_offset < bitmap_end
            || !self.data_offset.is_multiple_of(bs)
            || self
                .data_offset
                .checked_add(self.virtual_size)
                .is_none_or(|e| e > i64::MAX as u64)
        {
            return Err(bad("data offset"));
        }
        Ok(())
    }
}

fn put32(h: &mut [u8], at: usize, v: u32) {
    h[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(h: &mut [u8], at: usize, v: u64) {
    h[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn get32(h: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(h[at..at + 4].try_into().unwrap())
}

fn get64(h: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(h[at..at + 8].try_into().unwrap())
}

/// CRC-32C (Castagnoli, reflected polynomial 0x82F63B78; init and final
/// XOR 0xFFFFFFFF), as used by iSCSI, ext4 and btrfs.
pub fn crc32c(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0x82F6_3B78 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut c = !0u32;
    for &b in data {
        c = TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// FNV-1a 64-bit hash state.
pub struct Fnv64(u64);

impl Fnv64 {
    pub fn new() -> Fnv64 {
        Fnv64(0xcbf2_9ce4_8422_2325)
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    pub fn finish(&self) -> u64 {
        self.0
    }
}

impl Default for Fnv64 {
    fn default() -> Self {
        Fnv64::new()
    }
}

/// Offsets of the sampled windows of a `size` byte image (each window is
/// `SAMPLE_LEN` bytes or the rest of the image, whichever is shorter).
/// Small images are covered completely.
pub fn sample_offsets(size: u64) -> Vec<u64> {
    if size <= SAMPLES * SAMPLE_LEN {
        return (0..size.div_ceil(SAMPLE_LEN))
            .map(|i| i * SAMPLE_LEN)
            .collect();
    }
    let last = u128::from(size - SAMPLE_LEN);
    (0..SAMPLES)
        .map(|i| (last * u128::from(i) / u128::from(SAMPLES - 1)) as u64)
        .collect()
}

/// The path to store for `base` in an overlay living in directory
/// `overlay_dir` (both absolute and canonical): relative to `overlay_dir`
/// when they share more than the root directory, so the two can move
/// together; absolute otherwise.
pub fn stored_base_path(overlay_dir: &Path, base: &Path) -> PathBuf {
    let from: Vec<Component<'_>> = overlay_dir.components().collect();
    let to: Vec<Component<'_>> = base.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let only_root = from
        .iter()
        .zip(&to)
        .take(common)
        .all(|(c, _)| matches!(c, Component::RootDir | Component::Prefix(_)));
    if !overlay_dir.is_absolute() || !base.is_absolute() || only_root {
        return base.to_path_buf();
    }
    let mut rel = PathBuf::new();
    for _ in common..from.len() {
        rel.push("..");
    }
    for c in &to[common..] {
        rel.push(c.as_os_str());
    }
    rel
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        let fp = Fingerprint {
            size: 64 << 20,
            mtime_ns: 1_700_000_000_123_456_789,
            digest: 0x1234_5678_9abc_def0,
        };
        Header::new(4096, fp, PathBuf::from("../golden.raw")).unwrap()
    }

    #[test]
    fn crc32c_known_values() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn fnv_known_value() {
        let mut h = Fnv64::new();
        h.update(b"a");
        assert_eq!(h.finish(), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn layout() {
        let h = header();
        assert_eq!(h.blocks(), 16384);
        assert_eq!(h.bitmap_offset, 4096);
        assert_eq!(h.bitmap_len, 2048);
        assert_eq!(h.data_offset, 8192);
        assert_eq!(h.file_len(), 8192 + (64 << 20));
        // A partial last block, and a block size above the page size.
        let fp = Fingerprint {
            size: 1000 * 1024 + 7,
            ..h.base
        };
        let h = Header::new(64 << 10, fp, "/g".into()).unwrap();
        assert_eq!(h.blocks(), 16);
        assert_eq!(h.bitmap_len, 2);
        assert_eq!(h.data_offset, 64 << 10);
    }

    #[test]
    fn roundtrip() {
        let h = header();
        let bytes = h.encode();
        assert_eq!(bytes.len(), FIXED_LEN + "../golden.raw".len());
        assert_eq!(&bytes[..8], b"VEMUOVL\0");
        assert_eq!(Header::peek_len(&bytes[..FIXED_LEN]).unwrap(), bytes.len());
        assert_eq!(Header::decode(&bytes).unwrap(), h);
        // Trailing bytes (the rest of the header page) are ignored.
        let mut padded = bytes.clone();
        padded.resize(4096, 0xee);
        assert_eq!(Header::decode(&padded).unwrap(), h);
    }

    /// Re-checksum a modified header so that only the field under test is
    /// wrong.
    fn reseal(b: &mut [u8]) {
        put32(b, O_CHECKSUM, 0);
        let c = crc32c(b);
        put32(b, O_CHECKSUM, c);
    }

    #[test]
    fn refusals() {
        let good = header().encode();
        let err = |b: &[u8]| Header::decode(b).unwrap_err().to_string();
        let mut b = good.clone();
        b[0] = b'X';
        assert!(err(&b).contains("bad magic"));
        assert!(err(&good[..40]).contains("truncated"));
        assert!(err(&good[..FIXED_LEN + 3]).contains("truncated"));
        let mut b = good.clone();
        put32(&mut b, O_VERSION, 2);
        reseal(&mut b);
        assert!(
            err(&b).contains("unsupported overlay format version 2"),
            "{}",
            err(&b)
        );
        let mut b = good.clone();
        let last = b.len() - 1;
        b[last] ^= 1; // a path byte
        assert!(err(&b).contains("checksum"));
        let mut b = good.clone();
        b[O_VIRTUAL_SIZE] ^= 1;
        assert!(err(&b).contains("checksum"));
        let mut b = good.clone();
        put32(&mut b, O_FLAGS, 1);
        reseal(&mut b);
        assert!(err(&b).contains("unsupported features"));
        let mut b = good.clone();
        put32(&mut b, O_BLOCK_SIZE, 3000);
        reseal(&mut b);
        assert!(err(&b).contains("power of two"));
        for (at, v) in [
            (O_BITMAP_LEN, 7u64),
            (O_BITMAP_OFFSET, 100),
            (O_DATA_OFFSET, 4096),
            (O_DATA_OFFSET, 8192 + 512),
            (O_VIRTUAL_SIZE, 1 << 20),
        ] {
            let mut b = good.clone();
            put64(&mut b, at, v);
            reseal(&mut b);
            assert!(err(&b).contains("corrupt"), "field {at}: {}", err(&b));
        }
    }

    /// A crafted header whose bitmap end overflows u64 is refused as
    /// corrupt (it panicked in debug builds, and wrapped in release).
    #[test]
    fn bitmap_offset_overflow_is_refused() {
        let fp = Fingerprint {
            size: 16 << 20,
            ..header().base
        };
        let h = Header::new(512, fp, "g.raw".into()).unwrap();
        assert_eq!(h.bitmap_len, 4096);
        let mut b = h.encode();
        put64(&mut b, O_BITMAP_OFFSET, 0xFFFF_FFFF_FFFF_F000);
        put64(&mut b, O_DATA_OFFSET, 4096);
        reseal(&mut b);
        let e = Header::decode(&b).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(
            e.to_string()
                .contains("corrupt overlay header (bitmap offset)"),
            "{e}"
        );
        // Just below the overflow, the layout check still refuses it.
        put64(&mut b, O_BITMAP_OFFSET, 0xFFFF_FFFF_FFFF_E000);
        reseal(&mut b);
        assert!(
            Header::decode(&b)
                .unwrap_err()
                .to_string()
                .contains("corrupt")
        );
    }

    #[test]
    fn new_refusals() {
        let fp = header().base;
        assert!(Header::new(1000, fp, "/g".into()).is_err());
        assert!(Header::new(256, fp, "/g".into()).is_err());
        assert!(Header::new(4 << 20, fp, "/g".into()).is_err());
        assert!(Header::new(4096, Fingerprint { size: 0, ..fp }, "/g".into()).is_err());
        assert!(Header::new(4096, fp, "".into()).is_err());
        let huge = Fingerprint {
            size: 8 << 40,
            ..fp
        };
        let e = Header::new(4096, huge, "/g".into()).unwrap_err();
        assert!(e.to_string().contains("larger block size"), "{e}");
        assert!(Header::new(64 << 10, huge, "/g".into()).is_ok());
    }

    #[test]
    fn samples() {
        assert_eq!(sample_offsets(1), [0]);
        assert_eq!(
            sample_offsets(SAMPLE_LEN * 3),
            [0, SAMPLE_LEN, 2 * SAMPLE_LEN]
        );
        let size = 10 << 30;
        let s = sample_offsets(size);
        assert_eq!(s.len(), SAMPLES as usize);
        assert_eq!(s[0], 0);
        assert_eq!(*s.last().unwrap(), size - SAMPLE_LEN);
        assert!(s.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn base_paths() {
        let p = |d: &str, b: &str| stored_base_path(Path::new(d), Path::new(b));
        assert_eq!(p("/vm/a", "/vm/a/golden.raw"), Path::new("golden.raw"));
        assert_eq!(p("/vm/a", "/vm/golden.raw"), Path::new("../golden.raw"));
        assert_eq!(
            p("/home/u/vms/x", "/home/u/img/g.raw"),
            Path::new("../../img/g.raw")
        );
        // Nothing shared but the root: absolute.
        assert_eq!(
            p("/Users/u/vms", "/Volumes/ext/g.raw"),
            Path::new("/Volumes/ext/g.raw")
        );
    }
}
