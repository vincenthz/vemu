//! Test helpers: in-memory storage, a seeded PRNG and temporary directories.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::buf::{ReadBuf, WriteBuf};
use crate::io::Storage;

/// A file in memory. Clones share the contents (so an overlay can be
/// "reopened" on the same bytes). Reads and writes past the end fail.
#[derive(Clone)]
pub struct MemStorage(Arc<Mutex<Mem>>);

struct Mem {
    data: Vec<u8>,
    writes: u64,
    syncs: u64,
    fail_writes: bool,
}

impl MemStorage {
    pub fn new(data: Vec<u8>) -> MemStorage {
        MemStorage(Arc::new(Mutex::new(Mem {
            data,
            writes: 0,
            syncs: 0,
            fail_writes: false,
        })))
    }

    pub fn contents(&self) -> Vec<u8> {
        self.0.lock().unwrap().data.clone()
    }

    /// Write directly (test setup).
    pub fn poke(&self, off: usize, bytes: &[u8]) {
        self.0.lock().unwrap().data[off..off + bytes.len()].copy_from_slice(bytes);
    }

    /// (writes, syncs) since the last reset.
    pub fn counts(&self) -> (u64, u64) {
        let m = self.0.lock().unwrap();
        (m.writes, m.syncs)
    }

    pub fn reset_counts(&self) {
        let mut m = self.0.lock().unwrap();
        m.writes = 0;
        m.syncs = 0;
    }

    pub fn fail_writes(&self, fail: bool) {
        self.0.lock().unwrap().fail_writes = fail;
    }
}

fn range(len: usize, off: u64, n: usize) -> io::Result<std::ops::Range<usize>> {
    let start = usize::try_from(off).map_err(|_| io::ErrorKind::InvalidInput)?;
    match start.checked_add(n) {
        Some(end) if end <= len => Ok(start..end),
        _ => Err(io::ErrorKind::UnexpectedEof.into()),
    }
}

impl Storage for MemStorage {
    fn read_at(&self, mut buf: ReadBuf<'_>, off: u64) -> io::Result<()> {
        let m = self.0.lock().unwrap();
        let r = range(m.data.len(), off, buf.len())?;
        buf.copy_from(&m.data[r]);
        Ok(())
    }

    fn write_at(&self, buf: WriteBuf<'_>, off: u64) -> io::Result<()> {
        let mut m = self.0.lock().unwrap();
        if m.fail_writes {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let r = range(m.data.len(), off, buf.len())?;
        buf.copy_to(&mut m.data[r]);
        m.writes += 1;
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        self.0.lock().unwrap().syncs += 1;
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().data.len() as u64)
    }
}

/// Base image contents for tests: never zero (a hole reading as zeros is
/// then visible), varying per byte and per sector.
pub fn base_pattern(size: u64) -> Vec<u8> {
    (0..size)
        .map(|i| 0x80 | ((i / 512) as u8 & 0x3f) ^ ((i % 512) as u8 & 0x0f))
        .collect()
}

/// splitmix64: small, seeded, deterministic.
pub struct Prng(u64);

impl Prng {
    pub fn new(seed: u64) -> Prng {
        Prng(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// A directory removed (with its contents) on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(name: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vemu-disk-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Canonical, as the overlay code compares canonical paths.
        TempDir(std::fs::canonicalize(&dir).unwrap())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, p: &str) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
