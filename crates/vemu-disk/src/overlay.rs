//! The overlay backend: a sparse file holding the blocks a VM wrote, on top
//! of a read-only golden image (docs/overlay-format.md).
//!
//! # I/O
//!
//! The allocation bitmap lives in memory (`AtomicU64` words). A read is
//! split into runs of blocks with the same allocation state; each run is
//! one `pread`, from the overlay's data region for allocated blocks (the
//! base is never touched for them) and from the golden image otherwise. A
//! write whose blocks are all allocated is one `pwrite`, without a lock.
//! Otherwise the write takes the allocation lock and writes, in order: the
//! partial head block (copied up: base block read, merged, written whole,
//! if it was not allocated), the run of whole or already allocated blocks
//! (one `pwrite`), the partial tail block (copied up likewise). Each newly
//! allocated block's bit is set in memory only after its data write
//! returned.
//!
//! # Concurrency
//!
//! vemu's virtio-blk serves one queue on the notifying vCPU thread under
//! the transport lock, so requests to one disk never run concurrently
//! today. The backend does not rely on that (an I/O thread, multiqueue, or
//! the exit-time flush racing a vCPU that did not stop): it is `Sync`, and
//!
//! - bits are only set under `alloc`, after the data is written, and read
//!   with `Acquire`: a reader that sees a bit sees the block's data;
//! - two writes to the same unallocated block serialize on `alloc`, and the
//!   second re-checks the bit, so a copy-up never overwrites the other
//!   write's data with base bytes;
//! - writes to allocated blocks and all reads take no lock (racing a write,
//!   a read returns old or new data, as on any disk);
//! - flushes serialize on `flush_lock`: an older bitmap snapshot written
//!   after a newer one would clear bits that the newer flush made durable.
//!
//! # Crash consistency
//!
//! A flush (guest `FLUSH`, and the clean exit) does, holding `flush_lock`:
//!
//! 1. copy the dirty bitmap pages, under `alloc` (every bit in the copy
//!    belongs to a block whose data write has completed);
//! 2. sync the overlay file (`F_FULLFSYNC` on macOS, `fdatasync` on Linux):
//!    that data is now durable;
//! 3. write the copied pages;
//! 4. sync again.
//!
//! So an on-disk bit is never set before its block's data is durable, and
//! bits only ever go from 0 to 1: a torn bitmap page write mixes old and
//! new bytes, each of them valid. A crash loses at most the writes not
//! covered by a completed flush (allowed by virtio): a block whose bit did
//! not reach the disk reads from the base again, and the next write to it
//! copies it up again, overwriting the stale data. A block written and
//! flushed, then rewritten without a flush, reads as the old or the new
//! data (torn at sector granularity at worst, as a raw disk would), never
//! from the base. The header is written once, at creation, so no
//! clean-shutdown flag is kept: every crash leaves a consistent overlay,
//! and the flag could only report "unflushed writes may be lost", which
//! virtio allows anyway.
//!
//! # Failed flushes are final
//!
//! When any step of a flush fails, the overlay is `failed` for as long as
//! it is open: every later flush (and the exit-time `shutdown`) and every
//! write returns `EIO` without touching the file, and the bitmap on disk
//! stays as the last completed flush left it. A failed sync cannot be
//! retried: Linux reports a writeback error once and marks the failed
//! pages clean (and macOS gives no better promise), so a later sync
//! returning 0 says nothing about the data written before the failure. A
//! retried flush would then persist bits for blocks whose data never
//! reached the disk, which read back as zeros, neither the base nor the
//! guest's data. Failing instead loses only the writes since the last
//! completed flush, which virtio allows; reopening the overlay (the next
//! run) reads the on-disk bitmap, which is consistent.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::buf::{ReadBuf, WriteBuf};
use crate::format::{FIXED_LEN, Header, PAGE};
use crate::io::Storage;
use crate::{BlockBackend, check_range};

/// Blocks covered by one bitmap page.
const BITS_PER_PAGE: u64 = PAGE * 8;

/// A golden image plus an overlay file: persistent (`durable`), or a
/// throwaway snapshot whose file is already unlinked and is never synced.
pub struct Overlay {
    file: Box<dyn Storage>,
    base: Box<dyn Storage>,
    header: Header,
    shift: u32,
    read_only: bool,
    durable: bool,
    bits: Box<[AtomicU64]>,
    alloc: Mutex<AllocState>,
    flush_lock: Mutex<()>,
    /// A flush failed: no more writes or flushes (see the module docs).
    failed: AtomicBool,
    base_path: PathBuf,
}

/// What allocating writes and flushes share (under `Overlay::alloc`).
struct AllocState {
    /// Bitmap pages with bits not yet written to the file.
    dirty: Vec<bool>,
    dirty_list: Vec<usize>,
    /// Copy-up buffer (one block), allocated on first use.
    scratch: Vec<u8>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read and validate the header of an overlay file.
pub(crate) fn read_header(file: &dyn Storage) -> io::Result<Header> {
    let len = file.len()?;
    if len < FIXED_LEN as u64 {
        let mut head = vec![0; len as usize];
        file.read_at(ReadBuf::new(&mut head), 0)?;
        // Reports a bad magic, or a truncated header.
        Header::peek_len(&head)?;
    }
    let mut fixed = [0u8; FIXED_LEN];
    file.read_at(ReadBuf::new(&mut fixed), 0)?;
    let hlen = Header::peek_len(&fixed)?;
    if (hlen as u64) > len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated overlay header",
        ));
    }
    let mut bytes = vec![0; hlen];
    file.read_at(ReadBuf::new(&mut bytes), 0)?;
    let header = Header::decode(&bytes)?;
    if len < header.file_len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the overlay file is truncated ({len} bytes, its layout needs {})",
                header.file_len()
            ),
        ));
    }
    Ok(header)
}

/// Read the on-disk bitmap into words (bit `b` of the disk is bit `b % 64`
/// of word `b / 64`; bytes are little-endian, so this is the file's bit
/// order). Bits past the last block are ignored.
pub(crate) fn load_bitmap(file: &dyn Storage, header: &Header) -> io::Result<Vec<u64>> {
    let blocks = header.blocks();
    let mut words = vec![0u64; blocks.div_ceil(64) as usize];
    let mut chunk = vec![0u8; header.bitmap_len.min(1 << 20) as usize];
    let mut pos = 0u64;
    while pos < header.bitmap_len {
        let n = chunk.len().min((header.bitmap_len - pos) as usize);
        file.read_at(ReadBuf::new(&mut chunk[..n]), header.bitmap_offset + pos)?;
        for (i, &byte) in chunk[..n].iter().enumerate() {
            let at = pos + i as u64;
            words[(at / 8) as usize] |= u64::from(byte) << ((at % 8) * 8);
        }
        pos += n as u64;
    }
    if !blocks.is_multiple_of(64) {
        let last = words.len() - 1;
        words[last] &= (1u64 << (blocks % 64)) - 1;
    }
    Ok(words)
}

impl Overlay {
    /// An overlay over `file` (with its decoded `header`) and `base`. With
    /// `load`, the bitmap is read from the file; otherwise it starts empty
    /// (a fresh file).
    pub(crate) fn from_parts(
        file: Box<dyn Storage>,
        base: Box<dyn Storage>,
        header: Header,
        read_only: bool,
        durable: bool,
        base_path: PathBuf,
        load: bool,
    ) -> io::Result<Overlay> {
        let words = if load {
            load_bitmap(&*file, &header)?
        } else {
            vec![0; header.blocks().div_ceil(64) as usize]
        };
        let pages = header.bitmap_len.div_ceil(PAGE) as usize;
        Ok(Overlay {
            shift: header.block_size.trailing_zeros(),
            bits: words.into_iter().map(AtomicU64::new).collect(),
            alloc: Mutex::new(AllocState {
                dirty: vec![false; pages],
                dirty_list: Vec::new(),
                scratch: Vec::new(),
            }),
            flush_lock: Mutex::new(()),
            failed: AtomicBool::new(false),
            file,
            base,
            header,
            read_only,
            durable,
            base_path,
        })
    }

    /// Open an existing overlay from its storage (header and bitmap read
    /// from `file`); the caller checked the base's fingerprint.
    #[cfg(test)]
    pub(crate) fn from_storage(
        file: Box<dyn Storage>,
        base: Box<dyn Storage>,
        read_only: bool,
    ) -> io::Result<Overlay> {
        let header = read_header(&*file)?;
        Overlay::from_parts(file, base, header, read_only, true, PathBuf::new(), true)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The golden image, as resolved when the overlay was opened.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Whether this is a throwaway snapshot.
    pub fn is_snapshot(&self) -> bool {
        !self.durable
    }

    /// Blocks allocated in the overlay (in memory: flushed or not).
    pub fn allocated_blocks(&self) -> u64 {
        self.bits
            .iter()
            .map(|w| u64::from(w.load(Ordering::Relaxed).count_ones()))
            .sum()
    }

    pub fn is_allocated(&self, block: u64) -> bool {
        self.bits[(block / 64) as usize].load(Ordering::Acquire) & (1 << (block % 64)) != 0
    }

    /// Byte range `[start, end)` of `block` in the virtual disk.
    fn block_range(&self, block: u64) -> (u64, u64) {
        let start = block << self.shift;
        let end = (start + u64::from(self.header.block_size)).min(self.header.virtual_size);
        (start, end)
    }

    /// Mark `block` allocated (its data is written). Under `alloc`.
    fn mark(&self, st: &mut AllocState, block: u64) {
        self.bits[(block / 64) as usize].fetch_or(1 << (block % 64), Ordering::Release);
        let page = (block / BITS_PER_PAGE) as usize;
        if !st.dirty[page] {
            st.dirty[page] = true;
            st.dirty_list.push(page);
        }
    }

    /// Write `buf[from - off .. to - off]` at virtual `[from, to)` as is: each
    /// block there is allocated or wholly covered. Then mark the new ones.
    fn write_run(
        &self,
        st: &mut AllocState,
        buf: WriteBuf<'_>,
        off: u64,
        from: u64,
        to: u64,
    ) -> io::Result<()> {
        if from == to {
            return Ok(());
        }
        let part = buf.sub((from - off) as usize, (to - from) as usize);
        self.file.write_at(part, self.header.data_offset + from)?;
        for b in (from >> self.shift)..=((to - 1) >> self.shift) {
            if !self.is_allocated(b) {
                self.mark(st, b);
            }
        }
        Ok(())
    }

    /// Allocate `block` for a write of `part` at virtual offset `at` that
    /// covers only some of it: the base block, merged with `part`, written
    /// whole.
    fn copy_up(
        &self,
        st: &mut AllocState,
        block: u64,
        part: WriteBuf<'_>,
        at: u64,
    ) -> io::Result<()> {
        let (start, end) = self.block_range(block);
        let len = (end - start) as usize;
        if st.scratch.len() < len {
            st.scratch.resize(self.header.block_size as usize, 0);
        }
        let scratch = &mut st.scratch[..len];
        self.base.read_at(ReadBuf::new(scratch), start)?;
        let rel = (at - start) as usize;
        part.copy_to(&mut scratch[rel..rel + part.len()]);
        self.file
            .write_at(WriteBuf::new(scratch), self.header.data_offset + start)?;
        self.mark(st, block);
        Ok(())
    }

    /// The bytes of bitmap page `page` as they are in memory. Under `alloc`.
    fn page_bytes(&self, page: usize) -> Vec<u8> {
        let start = page as u64 * PAGE;
        let end = (start + PAGE).min(self.header.bitmap_len);
        let mut v = Vec::with_capacity((end - start) as usize + 8);
        for w in &self.bits[(start / 8) as usize..end.div_ceil(8) as usize] {
            v.extend_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
        }
        v.truncate((end - start) as usize);
        v
    }

    /// Step 1 of a flush: copy the dirty pages and mark them clean.
    fn take_dirty(&self) -> Vec<(usize, Vec<u8>)> {
        let mut st = lock(&self.alloc);
        let list = std::mem::take(&mut st.dirty_list);
        list.into_iter()
            .map(|p| {
                st.dirty[p] = false;
                (p, self.page_bytes(p))
            })
            .collect()
    }

    /// Whether a flush failed (the overlay refuses writes and flushes).
    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn failed_error() -> io::Error {
        io::Error::other(
            "an earlier flush of the overlay failed, so it takes no more writes or flushes: \
             the writes since the last completed flush are lost (the next run of the overlay \
             starts from that flush)",
        )
    }

    fn persist(&self) -> io::Result<()> {
        let _serial = lock(&self.flush_lock);
        if self.has_failed() {
            return Err(Overlay::failed_error());
        }
        let pages = self.take_dirty();
        let r = (|| {
            self.file.sync()?;
            for (p, bytes) in &pages {
                let off = self.header.bitmap_offset + *p as u64 * PAGE;
                self.file.write_at(WriteBuf::new(bytes), off)?;
            }
            if !pages.is_empty() {
                self.file.sync()?;
            }
            Ok(())
        })();
        if r.is_err() {
            // Never retried (module docs): the pages stay unwritten, and
            // the on-disk bitmap stays at the last completed flush.
            self.failed.store(true, Ordering::Release);
        }
        r
    }
}

impl BlockBackend for Overlay {
    fn size(&self) -> u64 {
        self.header.virtual_size
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn read_at(&self, mut buf: ReadBuf<'_>, offset: u64) -> io::Result<()> {
        check_range(offset, buf.len(), self.header.virtual_size)?;
        let end = offset + buf.len() as u64;
        let mut pos = offset;
        while pos < end {
            let b = pos >> self.shift;
            let allocated = self.is_allocated(b);
            let mut next = b + 1;
            while (next << self.shift) < end && self.is_allocated(next) == allocated {
                next += 1;
            }
            let run_end = (next << self.shift).min(end);
            let part = buf.sub((pos - offset) as usize, (run_end - pos) as usize);
            if allocated {
                self.file.read_at(part, self.header.data_offset + pos)?;
            } else {
                self.base.read_at(part, pos)?;
            }
            pos = run_end;
        }
        Ok(())
    }

    fn write_at(&self, buf: WriteBuf<'_>, offset: u64) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the disk is read-only",
            ));
        }
        check_range(offset, buf.len(), self.header.virtual_size)?;
        if self.has_failed() {
            return Err(Overlay::failed_error());
        }
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset + buf.len() as u64;
        let (first, last) = (offset >> self.shift, (end - 1) >> self.shift);
        if (first..=last).all(|b| self.is_allocated(b)) {
            return self.file.write_at(buf, self.header.data_offset + offset);
        }
        let mut st = lock(&self.alloc);
        // [run, s) is written as is; only the first and the last block can
        // be partially covered, and those copy up if not allocated.
        let mut run = offset;
        for b in first..=last {
            let (start, block_end) = self.block_range(b);
            let (s, e) = (start.max(offset), block_end.min(end));
            if self.is_allocated(b) || (s == start && e == block_end) {
                continue;
            }
            self.write_run(&mut st, buf, offset, run, s)?;
            let part = buf.sub((s - offset) as usize, (e - s) as usize);
            self.copy_up(&mut st, b, part, s)?;
            run = e;
        }
        self.write_run(&mut st, buf, offset, run, end)
    }

    fn flush(&self) -> io::Result<()> {
        if self.read_only || !self.durable {
            // Nothing to persist: a snapshot is discarded at exit.
            return Ok(());
        }
        self.persist()
    }

    fn shutdown(&self) -> io::Result<()> {
        self.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Fingerprint;
    use crate::testutil::{MemStorage, base_pattern};

    const BS: u32 = 4096;

    /// A fresh overlay on an in-memory base of `size` bytes; returns the
    /// overlay and its file.
    fn fresh(size: u64, bs: u32) -> (Overlay, MemStorage, MemStorage) {
        let base = MemStorage::new(base_pattern(size));
        let fp = Fingerprint {
            size,
            mtime_ns: 0,
            digest: 0,
        };
        let h = Header::new(bs, fp, "golden".into()).unwrap();
        let file = MemStorage::new(vec![0; h.file_len() as usize]);
        file.poke(0, &h.encode());
        let ov =
            Overlay::from_storage(Box::new(file.clone()), Box::new(base.clone()), false).unwrap();
        (ov, file, base)
    }

    fn read(ov: &Overlay, off: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        ov.read_at(ReadBuf::new(&mut v), off).unwrap();
        v
    }

    fn write(ov: &Overlay, off: u64, data: &[u8]) {
        ov.write_at(WriteBuf::new(data), off).unwrap();
    }

    fn allocated(ov: &Overlay) -> Vec<u64> {
        (0..ov.header.blocks())
            .filter(|&b| ov.is_allocated(b))
            .collect()
    }

    #[test]
    fn unwritten_blocks_read_from_the_base() {
        let (ov, _f, base) = fresh(10 * 4096, BS);
        assert_eq!(read(&ov, 0, 10 * 4096), base.contents());
        assert_eq!(read(&ov, 4000, 300), base.contents()[4000..4300]);
        assert!(allocated(&ov).is_empty());
    }

    #[test]
    fn copy_up_at_block_edges() {
        let (ov, f, base) = fresh(10 * 4096, BS);
        let b = base.contents();
        // The last byte of block 0 and the first of block 1.
        write(&ov, 4095, &[0xa1, 0xa2]);
        assert_eq!(allocated(&ov), [0, 1]);
        let mut want = b.clone();
        want[4095] = 0xa1;
        want[4096] = 0xa2;
        assert_eq!(read(&ov, 0, 10 * 4096), want);
        // Both blocks hold the merged base bytes in the file.
        let d = ov.header.data_offset as usize;
        assert_eq!(f.contents()[d..d + 8192], want[..8192]);
        // The last byte of the disk; the first byte.
        write(&ov, 10 * 4096 - 1, &[0xb1]);
        write(&ov, 0, &[0xb2]);
        want[10 * 4096 - 1] = 0xb1;
        want[0] = 0xb2;
        assert_eq!(allocated(&ov), [0, 1, 9]);
        assert_eq!(read(&ov, 0, 10 * 4096), want);
    }

    #[test]
    fn writes_spanning_blocks() {
        let (ov, f, base) = fresh(10 * 4096, BS);
        let mut want = base.contents();
        // Mid block 1 to mid block 4: head and tail copy up, 2 and 3 whole.
        let data: Vec<u8> = (0..3 * 4096).map(|i| (i % 251) as u8 ^ 0x5a).collect();
        write(&ov, 4096 + 2048, &data);
        want[4096 + 2048..4096 + 2048 + data.len()].copy_from_slice(&data);
        assert_eq!(allocated(&ov), [1, 2, 3, 4]);
        assert_eq!(read(&ov, 0, want.len()), want);
        // Exactly whole blocks: no base read needed, and the head of block
        // 6 / tail of block 7 come from the write.
        write(&ov, 6 * 4096, &vec![0x77; 2 * 4096]);
        want[6 * 4096..8 * 4096].fill(0x77);
        assert_eq!(allocated(&ov), [1, 2, 3, 4, 6, 7]);
        // Unallocated blocks were never written in the file.
        let d = ov.header.data_offset as usize;
        let c = f.contents();
        assert!(c[d..d + 4096].iter().all(|&x| x == 0));
        assert!(c[d + 5 * 4096..d + 6 * 4096].iter().all(|&x| x == 0));
        // A read mixing base and overlay runs.
        assert_eq!(read(&ov, 100, 9 * 4096), want[100..100 + 9 * 4096]);
        // Rewriting allocated blocks (the lock-free path), partially.
        write(&ov, 3 * 4096 + 10, &[1, 2, 3]);
        want[3 * 4096 + 10..3 * 4096 + 13].copy_from_slice(&[1, 2, 3]);
        assert_eq!(read(&ov, 0, want.len()), want);
    }

    #[test]
    fn partial_last_block() {
        let size = 3 * 4096 + 1000;
        let (ov, f, base) = fresh(size, BS);
        let mut want = base.contents();
        write(&ov, size - 10, &[9; 10]);
        want[size as usize - 10..].fill(9);
        assert_eq!(allocated(&ov), [3]);
        assert_eq!(read(&ov, 0, size as usize), want);
        // The copy-up wrote only the 1000 bytes that exist.
        assert_eq!(f.contents().len() as u64, ov.header.file_len());
        // Covering all of the partial block counts as whole.
        let (ov, _, _) = fresh(size, BS);
        write(&ov, 3 * 4096, &[4; 1000]);
        assert_eq!(allocated(&ov), [3]);
        assert!(ov.write_at(WriteBuf::new(&[0]), size).is_err());
        assert!(ov.read_at(ReadBuf::new(&mut [0; 2]), size - 1).is_err());
    }

    #[test]
    fn flush_persists_and_reopen_keeps_writes() {
        let (ov, f, base) = fresh(100 * 512, 512);
        write(&ov, 512 * 7 + 3, b"hello");
        write(&ov, 512 * 50, &[0xcc; 1024]);
        let want = read(&ov, 0, 100 * 512);
        ov.flush().unwrap();
        drop(ov);
        let ov = Overlay::from_storage(Box::new(f.clone()), Box::new(base.clone()), false).unwrap();
        assert_eq!(allocated(&ov), [7, 50, 51]);
        assert_eq!(read(&ov, 0, 100 * 512), want);
        // Without a flush the bitmap is not on disk: the writes are lost.
        write(&ov, 0, b"lost");
        drop(ov);
        let ov = Overlay::from_storage(Box::new(f), Box::new(base), true).unwrap();
        assert_eq!(read(&ov, 0, 100 * 512), want);
        // Read-only: writes refused, flush is fine.
        assert_eq!(
            ov.write_at(WriteBuf::new(b"x"), 0).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        ov.flush().unwrap();
    }

    #[test]
    fn flush_writes_only_dirty_pages() {
        // 4096 * 8 * 3 blocks of 512 bytes: 3 bitmap pages.
        let blocks = BITS_PER_PAGE * 3;
        let (ov, f, _) = fresh(blocks * 512, 512);
        write(&ov, (BITS_PER_PAGE * 2 + 5) * 512, &[1; 512]);
        f.reset_counts();
        ov.flush().unwrap();
        let (writes, syncs) = f.counts();
        assert_eq!((writes, syncs), (1, 2), "one page, data sync + bitmap sync");
        // Nothing dirty: a single data sync.
        f.reset_counts();
        ov.flush().unwrap();
        assert_eq!(f.counts(), (0, 1));
    }

    /// A failed flush is final: later flushes, the exit-time shutdown and
    /// writes all fail without touching the file, so no bit is ever
    /// persisted on the word of a sync that followed a failed one.
    #[test]
    fn a_failed_flush_is_never_retried() {
        let (ov, f, base) = fresh(64 * 512, 512);
        write(&ov, 3 * 512, &[1; 512]);
        ov.flush().unwrap();
        let flushed = read(&ov, 0, 64 * 512);
        // Block 9: allocated in memory; its flush fails (the bitmap write).
        write(&ov, 9 * 512, &[2; 512]);
        f.fail_writes(true);
        assert!(ov.flush().is_err());
        assert!(ov.has_failed());
        f.fail_writes(false);
        f.reset_counts();
        for r in [
            ov.flush(),
            ov.shutdown(),
            ov.write_at(WriteBuf::new(&[3; 512]), 0),
        ] {
            let e = r.unwrap_err();
            assert!(
                e.to_string()
                    .contains("an earlier flush of the overlay failed"),
                "{e}"
            );
        }
        assert_eq!(
            f.counts(),
            (0, 0),
            "nothing written or synced after the failure"
        );
        // Reads still work (the in-memory view).
        assert_eq!(read(&ov, 9 * 512, 512), [2; 512]);
        drop(ov);
        // Reopened: the overlay as of the last completed flush.
        let ov = Overlay::from_storage(Box::new(f), Box::new(base), false).unwrap();
        assert_eq!(allocated(&ov), [3]);
        assert_eq!(read(&ov, 0, 64 * 512), flushed);
        write(&ov, 9 * 512, &[4; 512]);
        ov.flush().unwrap();
    }

    /// Concurrent partial writes into the same unallocated blocks: each
    /// copy-up must keep the others' bytes.
    #[test]
    fn concurrent_copy_ups_keep_every_write() {
        for round in 0..20u8 {
            let (ov, _f, base) = fresh(4 * 4096, BS);
            let ov = std::sync::Arc::new(ov);
            let threads: Vec<_> = (0..4u64)
                .map(|t| {
                    let ov = ov.clone();
                    std::thread::spawn(move || {
                        // Thread t owns bytes [t*16, t*16+16) of every 512.
                        for i in 0..32u64 {
                            let off = i * 512 + t * 16;
                            ov.write_at(WriteBuf::new(&[round ^ (t as u8 + 1); 16]), off)
                                .unwrap();
                        }
                    })
                })
                .collect();
            for t in threads {
                t.join().unwrap();
            }
            let mut want = base.contents();
            for t in 0..4u64 {
                for i in 0..32u64 {
                    let off = (i * 512 + t * 16) as usize;
                    want[off..off + 16].fill(round ^ (t as u8 + 1));
                }
            }
            assert_eq!(read(&ov, 0, 4 * 4096), want, "round {round}");
        }
    }
}
