//! Split virtqueues (virtio 1.2 §2.7), device side.
//!
//! The driver owns the descriptor table and the available ring; the device
//! owns the used ring. Everything read from guest memory is untrusted: indices
//! are range-checked, chains are length-limited (so loops terminate), every
//! buffer must lie inside guest RAM, and errors are returned, never panicked
//! on.
//!
//! Memory ordering: the available `idx` is loaded with acquire semantics
//! before the ring entries and descriptors it publishes are read; used
//! elements are written before the used `idx` is stored with release
//! semantics. Around notification suppression a full fence orders our store
//! (used `idx` or `flags`) before the load of the driver's field (avail
//! `flags` or `idx`), which pairs with the driver's own full barrier.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{Ordering, fence};

use vemu_core::{GuestMemory, MemError};

/// Descriptor continues via `next`.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
/// Buffer is device-writable (otherwise device-readable).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
/// Buffer contains a table of indirect descriptors.
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;
/// Available ring flag: the driver does not want used-buffer interrupts.
pub const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Used ring flag: the device does not want available-buffer notifications.
pub const VIRTQ_USED_F_NO_NOTIFY: u16 = 1;

/// Largest split queue size (virtio 1.2 §2.7).
pub const MAX_QUEUE_SIZE: u16 = 32768;
/// Largest indirect descriptor table accepted, in descriptors.
pub const MAX_INDIRECT_DESCS: usize = 1024;

const DESC_SIZE: u64 = 16;

/// A driver error found while using a queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    /// Queue size is zero, not a power of two or too large.
    InvalidSize(u16),
    /// A ring address violates its alignment requirement.
    Misaligned { ring: &'static str, addr: u64 },
    /// A ring or buffer lies (partly) outside guest RAM.
    Memory(MemError),
    /// The driver advanced the available index by more than the queue size.
    AvailIndex { avail_idx: u16, next_avail: u16 },
    /// A descriptor index (head or `next`) is outside its table.
    DescIndex(u16),
    /// A chain has more descriptors than its table (a loop, or a driver bug).
    ChainTooLong,
    /// Indirect table length is zero, not a multiple of 16 or too large.
    IndirectLength(u32),
    /// An indirect table contains an indirect descriptor.
    NestedIndirect,
    /// A descriptor has both INDIRECT and NEXT set.
    IndirectWithNext,
    /// A device-readable descriptor follows a device-writable one.
    ReadableAfterWritable,
    /// The chain's buffers add up to more than 4 GiB - 1.
    ChainTooLarge,
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueError::InvalidSize(s) => write!(f, "invalid queue size {s}"),
            QueueError::Misaligned { ring, addr } => {
                write!(f, "misaligned {ring} ring at {addr:#x}")
            }
            QueueError::Memory(e) => e.fmt(f),
            QueueError::AvailIndex {
                avail_idx,
                next_avail,
            } => {
                write!(f, "available index jumped from {next_avail} to {avail_idx}")
            }
            QueueError::DescIndex(i) => write!(f, "descriptor index {i} out of range"),
            QueueError::ChainTooLong => f.write_str("descriptor chain too long (loop?)"),
            QueueError::IndirectLength(l) => write!(f, "invalid indirect table length {l}"),
            QueueError::NestedIndirect => f.write_str("nested indirect descriptor"),
            QueueError::IndirectWithNext => f.write_str("descriptor with both INDIRECT and NEXT"),
            QueueError::ReadableAfterWritable => {
                f.write_str("device-readable descriptor after a device-writable one")
            }
            QueueError::ChainTooLarge => f.write_str("descriptor chain larger than 4 GiB"),
        }
    }
}

impl std::error::Error for QueueError {}

impl From<MemError> for QueueError {
    fn from(e: MemError) -> QueueError {
        QueueError::Memory(e)
    }
}

/// One guest buffer of a chain (a non-empty descriptor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub addr: u64,
    pub len: u32,
}

/// A descriptor chain popped from the available ring, split into its
/// device-readable and device-writable parts. Every segment was checked to lie
/// inside guest RAM, and the total size fits in a `u32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescChain {
    head: u16,
    readable: Vec<Segment>,
    writable: Vec<Segment>,
    readable_len: u64,
    writable_len: u64,
}

impl DescChain {
    /// Head descriptor index (the id to put in the used ring).
    pub fn head(&self) -> u16 {
        self.head
    }

    pub fn readable(&self) -> &[Segment] {
        &self.readable
    }

    pub fn writable(&self) -> &[Segment] {
        &self.writable
    }

    /// Total bytes of the device-readable part.
    pub fn readable_len(&self) -> u64 {
        self.readable_len
    }

    /// Total bytes of the device-writable part.
    pub fn writable_len(&self) -> u64 {
        self.writable_len
    }

    /// Copy the readable part, starting `offset` bytes in, into `buf`.
    /// Returns the number of bytes copied (short at the end of the part).
    pub fn read_at(
        &self,
        mem: &GuestMemory,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, MemError> {
        let mut done = 0;
        for (gpa, len) in sub_ranges(&self.readable, offset, buf.len() as u64) {
            mem.read(gpa, &mut buf[done..done + len])?;
            done += len;
        }
        Ok(done)
    }

    /// Copy `buf` into the writable part, starting `offset` bytes in.
    /// Returns the number of bytes copied (short at the end of the part).
    pub fn write_at(&self, mem: &GuestMemory, offset: u64, buf: &[u8]) -> Result<usize, MemError> {
        let mut done = 0;
        for (gpa, len) in sub_ranges(&self.writable, offset, buf.len() as u64) {
            mem.write(gpa, &buf[done..done + len])?;
            done += len;
        }
        Ok(done)
    }

    fn push(&mut self, mem: &GuestMemory, d: &Descriptor) -> Result<(), QueueError> {
        let writable = d.flags & VIRTQ_DESC_F_WRITE != 0;
        if !writable && !self.writable.is_empty() {
            return Err(QueueError::ReadableAfterWritable);
        }
        if self.readable_len + self.writable_len + u64::from(d.len) > u64::from(u32::MAX) {
            return Err(QueueError::ChainTooLarge);
        }
        if d.len == 0 {
            return Ok(());
        }
        if !mem.contains(d.addr, d.len as usize) {
            return Err(MemError {
                gpa: d.addr,
                len: d.len as usize,
            }
            .into());
        }
        let seg = Segment {
            addr: d.addr,
            len: d.len,
        };
        if writable {
            self.writable.push(seg);
            self.writable_len += u64::from(d.len);
        } else {
            self.readable.push(seg);
            self.readable_len += u64::from(d.len);
        }
        Ok(())
    }
}

/// Split the byte range `[offset, offset+len)` of the concatenation of `segs`
/// into `(gpa, len)` pieces, clipped to the end of `segs`.
pub fn sub_ranges(segs: &[Segment], offset: u64, len: u64) -> SubRanges<'_> {
    SubRanges {
        segs,
        skip: offset,
        remaining: len,
    }
}

/// Iterator returned by [`sub_ranges`].
pub struct SubRanges<'a> {
    segs: &'a [Segment],
    skip: u64,
    remaining: u64,
}

impl Iterator for SubRanges<'_> {
    type Item = (u64, usize);

    fn next(&mut self) -> Option<(u64, usize)> {
        while self.remaining > 0 {
            let (seg, rest) = self.segs.split_first()?;
            self.segs = rest;
            let seg_len = u64::from(seg.len);
            if self.skip >= seg_len {
                self.skip -= seg_len;
                continue;
            }
            let n = (seg_len - self.skip).min(self.remaining);
            let gpa = seg.addr + self.skip;
            self.skip = 0;
            self.remaining -= n;
            return Some((gpa, n as usize));
        }
        None
    }
}

/// A raw descriptor as found in guest memory.
struct Descriptor {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

impl Descriptor {
    fn parse(b: &[u8]) -> Descriptor {
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let mut addr = [0; 8];
        addr.copy_from_slice(&b[0..8]);
        let mut len = [0; 4];
        len.copy_from_slice(&b[8..12]);
        Descriptor {
            addr: u64::from_le_bytes(addr),
            len: u32::from_le_bytes(len),
            flags: u16_at(12),
            next: u16_at(14),
        }
    }
}

/// The device side of one split virtqueue.
pub struct Queue {
    mem: Arc<GuestMemory>,
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    /// Next available ring entry to consume.
    next_avail: u16,
    /// Next used ring entry to fill (also the used `idx` we publish).
    next_used: u16,
}

impl Queue {
    /// Validate a ring layout the driver configured: `size` a power of two,
    /// the descriptor table 16-byte, available ring 2-byte and used ring
    /// 4-byte aligned, and all three inside guest RAM.
    pub fn new(
        mem: Arc<GuestMemory>,
        size: u16,
        desc: u64,
        avail: u64,
        used: u64,
    ) -> Result<Queue, QueueError> {
        if size == 0 || size > MAX_QUEUE_SIZE || !size.is_power_of_two() {
            return Err(QueueError::InvalidSize(size));
        }
        let n = usize::from(size);
        let rings = [
            ("descriptor", desc, 16, 16 * n),
            ("available", avail, 2, 6 + 2 * n),
            ("used", used, 4, 6 + 8 * n),
        ];
        for (ring, addr, align, len) in rings {
            if !addr.is_multiple_of(align) {
                return Err(QueueError::Misaligned { ring, addr });
            }
            if !mem.contains(addr, len) {
                return Err(MemError { gpa: addr, len }.into());
            }
        }
        Ok(Queue {
            mem,
            size,
            desc,
            avail,
            used,
            next_avail: 0,
            next_used: 0,
        })
    }

    pub fn size(&self) -> u16 {
        self.size
    }

    pub fn memory(&self) -> &Arc<GuestMemory> {
        &self.mem
    }

    /// Pop the next available descriptor chain, if any.
    ///
    /// On error the queue is unusable (the driver broke it) and should be
    /// dropped by the device.
    pub fn pop(&mut self) -> Result<Option<DescChain>, QueueError> {
        let avail_idx = self.mem.load_u16_acquire(self.avail + 2)?;
        let pending = avail_idx.wrapping_sub(self.next_avail);
        if pending == 0 {
            return Ok(None);
        }
        if pending > self.size {
            return Err(QueueError::AvailIndex {
                avail_idx,
                next_avail: self.next_avail,
            });
        }
        let slot = u64::from(self.next_avail % self.size);
        let head = self.mem.read_u16(self.avail + 4 + 2 * slot)?;
        let chain = self.walk(head)?;
        self.next_avail = self.next_avail.wrapping_add(1);
        Ok(Some(chain))
    }

    /// Give back the chain returned by the last [`Queue::pop`], unused; the
    /// next `pop` returns it again.
    pub fn undo_pop(&mut self) {
        self.next_avail = self.next_avail.wrapping_sub(1);
    }

    /// Whether the driver has published chains not popped yet.
    pub fn has_available(&self) -> Result<bool, QueueError> {
        Ok(self.mem.load_u16_acquire(self.avail + 2)? != self.next_avail)
    }

    /// Return chain `head` to the driver, with `len` bytes written to its
    /// device-writable part.
    pub fn add_used(&mut self, head: u16, len: u32) -> Result<(), QueueError> {
        let elem = self.used + 4 + 8 * u64::from(self.next_used % self.size);
        self.mem.write_u32(elem, u32::from(head))?;
        self.mem.write_u32(elem + 4, len)?;
        self.next_used = self.next_used.wrapping_add(1);
        // Release: the element is visible before the index that publishes it.
        self.mem.store_u16_release(self.used + 2, self.next_used)?;
        Ok(())
    }

    /// Whether the driver wants a used-buffer interrupt now (it did not set
    /// `VIRTQ_AVAIL_F_NO_INTERRUPT`). Call after [`Queue::add_used`].
    pub fn needs_interrupt(&self) -> bool {
        // Order the used idx store before the flags load; pairs with the
        // driver's barrier between clearing the flag and re-reading used idx.
        fence(Ordering::SeqCst);
        self.mem
            .load_u16_acquire(self.avail)
            .map_or(true, |flags| flags & VIRTQ_AVAIL_F_NO_INTERRUPT == 0)
    }

    /// Ask the driver to send (or not to send) available-buffer notifications.
    /// After enabling, re-check [`Queue::has_available`] to close the race with
    /// a driver that published while notifications were off.
    pub fn set_notification(&mut self, enable: bool) -> Result<(), QueueError> {
        let flags = if enable { 0 } else { VIRTQ_USED_F_NO_NOTIFY };
        self.mem.store_u16_release(self.used, flags)?;
        // Order the flags store before the following avail idx load.
        fence(Ordering::SeqCst);
        Ok(())
    }

    /// Process every available chain with `handle`, which returns the number
    /// of bytes it wrote to the chain's device-writable part. Notifications
    /// are suppressed while draining. Returns how many chains were used; the
    /// caller then signals the interrupt if [`Queue::needs_interrupt`].
    pub fn drain(
        &mut self,
        mut handle: impl FnMut(&DescChain) -> u32,
    ) -> Result<usize, QueueError> {
        let mut used = 0;
        loop {
            self.set_notification(false)?;
            while let Some(chain) = self.pop()? {
                let len = handle(&chain);
                self.add_used(chain.head(), len)?;
                used += 1;
            }
            self.set_notification(true)?;
            if !self.has_available()? {
                return Ok(used);
            }
        }
    }

    fn walk(&self, head: u16) -> Result<DescChain, QueueError> {
        let mut chain = DescChain {
            head,
            readable: Vec::new(),
            writable: Vec::new(),
            readable_len: 0,
            writable_len: 0,
        };
        let mut idx = head;
        let mut count = 0;
        loop {
            if idx >= self.size {
                return Err(QueueError::DescIndex(idx));
            }
            count += 1;
            if count > self.size {
                return Err(QueueError::ChainTooLong);
            }
            let mut raw = [0; DESC_SIZE as usize];
            self.mem
                .read(self.desc + DESC_SIZE * u64::from(idx), &mut raw)?;
            let d = Descriptor::parse(&raw);
            if d.flags & VIRTQ_DESC_F_INDIRECT != 0 {
                if d.flags & VIRTQ_DESC_F_NEXT != 0 {
                    return Err(QueueError::IndirectWithNext);
                }
                self.walk_indirect(&d, &mut chain)?;
                return Ok(chain);
            }
            chain.push(&self.mem, &d)?;
            if d.flags & VIRTQ_DESC_F_NEXT == 0 {
                return Ok(chain);
            }
            idx = d.next;
        }
    }

    fn walk_indirect(&self, table: &Descriptor, chain: &mut DescChain) -> Result<(), QueueError> {
        let len = table.len as usize;
        if len == 0
            || !len.is_multiple_of(DESC_SIZE as usize)
            || len / DESC_SIZE as usize > MAX_INDIRECT_DESCS
        {
            return Err(QueueError::IndirectLength(table.len));
        }
        let n = len / DESC_SIZE as usize;
        // Snapshot the whole table so the driver cannot change it under us.
        let mut raw = vec![0; len];
        self.mem.read(table.addr, &mut raw)?;
        let mut idx = 0usize;
        for _ in 0..n {
            let d = Descriptor::parse(&raw[idx * DESC_SIZE as usize..][..DESC_SIZE as usize]);
            if d.flags & VIRTQ_DESC_F_INDIRECT != 0 {
                return Err(QueueError::NestedIndirect);
            }
            chain.push(&self.mem, &d)?;
            if d.flags & VIRTQ_DESC_F_NEXT == 0 {
                return Ok(());
            }
            idx = usize::from(d.next);
            if idx >= n {
                return Err(QueueError::DescIndex(d.next));
            }
        }
        Err(QueueError::ChainTooLong)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{DriverQueue, MEM_BASE, test_memory};

    const W: bool = true;
    const R: bool = false;

    fn setup(size: u16) -> (Arc<GuestMemory>, DriverQueue, Queue) {
        let mem = test_memory();
        let dq = DriverQueue::new(MEM_BASE, size);
        let q = Queue::new(mem.clone(), size, dq.desc, dq.avail, dq.used).unwrap();
        (mem, dq, q)
    }

    const BUF: u64 = MEM_BASE + 0x10_0000;

    #[test]
    fn new_validates_layout() {
        let mem = test_memory();
        let ok = |size, d, a, u| Queue::new(mem.clone(), size, d, a, u).map(|_| ());
        assert_eq!(
            ok(0, BUF, BUF + 0x1000, BUF + 0x2000),
            Err(QueueError::InvalidSize(0))
        );
        assert_eq!(
            ok(3, BUF, BUF + 0x1000, BUF + 0x2000),
            Err(QueueError::InvalidSize(3))
        );
        assert_eq!(
            ok(65535, BUF, BUF + 0x1000, BUF + 0x2000),
            Err(QueueError::InvalidSize(65535))
        );
        assert!(matches!(
            ok(8, BUF + 8, BUF + 0x1000, BUF + 0x2000),
            Err(QueueError::Misaligned { .. })
        ));
        assert!(matches!(
            ok(8, BUF, BUF + 0x1001, BUF + 0x2000),
            Err(QueueError::Misaligned { .. })
        ));
        assert!(matches!(
            ok(8, BUF, BUF + 0x1000, BUF + 0x2002),
            Err(QueueError::Misaligned { .. })
        ));
        assert!(matches!(
            ok(8, 0x1000, BUF + 0x1000, BUF + 0x2000),
            Err(QueueError::Memory(_))
        ));
        let end = mem.gpa_end();
        assert!(matches!(
            ok(8, BUF, BUF + 0x1000, end - 16),
            Err(QueueError::Memory(_))
        ));
        assert!(ok(8, BUF, BUF + 0x1000, BUF + 0x2000).is_ok());
    }

    #[test]
    fn direct_chain_and_used_ring() {
        let (mem, mut dq, mut q) = setup(8);
        assert_eq!(q.pop().unwrap(), None);
        let head = dq.add(
            &mem,
            &[
                (BUF, 4, R),
                (BUF + 100, 0, R),
                (BUF + 200, 8, W),
                (BUF + 300, 2, W),
            ],
        );
        mem.write(BUF, b"abcd").unwrap();
        assert!(q.has_available().unwrap());
        let c = q.pop().unwrap().unwrap();
        assert_eq!(c.head(), head);
        assert_eq!(c.readable(), [Segment { addr: BUF, len: 4 }]);
        assert_eq!(c.writable().len(), 2);
        assert_eq!((c.readable_len(), c.writable_len()), (4, 10));
        let mut b = [0; 8];
        assert_eq!(c.read_at(&mem, 1, &mut b).unwrap(), 3);
        assert_eq!(&b[..3], b"bcd");
        assert_eq!(c.write_at(&mem, 6, b"0123456").unwrap(), 4);
        assert_eq!(mem.read_u16(BUF + 206).unwrap(), u16::from_le_bytes(*b"01"));
        assert_eq!(mem.read_u16(BUF + 300).unwrap(), u16::from_le_bytes(*b"23"));
        assert!(!q.has_available().unwrap());
        q.add_used(c.head(), 10).unwrap();
        assert_eq!(dq.pop_used(&mem), Some((u32::from(head), 10)));
        assert_eq!(dq.pop_used(&mem), None);
    }

    #[test]
    fn index_wraparound() {
        let (mem, mut dq, mut q) = setup(4);
        for i in 0..70_000u32 {
            let h = dq.add(&mem, &[(BUF, 1, W)]);
            let c = q.pop().unwrap().unwrap();
            assert_eq!(c.head(), h);
            q.add_used(c.head(), i).unwrap();
            assert_eq!(dq.pop_used(&mem), Some((u32::from(h), i)));
        }
    }

    #[test]
    fn undo_pop_returns_same_chain() {
        let (mem, mut dq, mut q) = setup(4);
        dq.add(&mem, &[(BUF, 1, W)]);
        let a = q.pop().unwrap().unwrap();
        q.undo_pop();
        assert_eq!(q.pop().unwrap().unwrap(), a);
        assert_eq!(q.pop().unwrap(), None);
    }

    #[test]
    fn indirect_chain() {
        let (mem, mut dq, mut q) = setup(4);
        let table = BUF + 0x8000;
        let head = dq.add_indirect(
            &mem,
            table,
            &[(BUF, 16, R), (BUF + 16, 512, W), (BUF + 600, 1, W)],
        );
        let c = q.pop().unwrap().unwrap();
        assert_eq!(c.head(), head);
        assert_eq!((c.readable_len(), c.writable_len()), (16, 513));
        assert_eq!(
            c.writable()[1],
            Segment {
                addr: BUF + 600,
                len: 1
            }
        );
    }

    #[test]
    fn indirect_after_direct_descriptors() {
        let (mem, mut dq, mut q) = setup(4);
        let table = BUF + 0x8000;
        DriverQueue::write_table(&mem, table, &[(BUF + 16, 32, W)]);
        dq.write_desc(&mem, 0, BUF, 16, VIRTQ_DESC_F_NEXT, 1);
        dq.write_desc(&mem, 1, table, 16, VIRTQ_DESC_F_INDIRECT, 0);
        dq.publish(&mem, 0);
        let c = q.pop().unwrap().unwrap();
        assert_eq!((c.readable_len(), c.writable_len()), (16, 32));
    }

    fn pop_err(size: u16, build: impl FnOnce(&GuestMemory, &mut DriverQueue)) -> QueueError {
        let (mem, mut dq, mut q) = setup(size);
        build(&mem, &mut dq);
        q.pop().unwrap_err()
    }

    #[test]
    fn malformed_chains_are_errors() {
        // Loop: 0 -> 1 -> 0.
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 0, BUF, 1, VIRTQ_DESC_F_NEXT, 1);
            dq.write_desc(m, 1, BUF, 1, VIRTQ_DESC_F_NEXT, 0);
            dq.publish(m, 0);
        });
        assert_eq!(e, QueueError::ChainTooLong);
        // Self loop.
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 2, BUF, 1, VIRTQ_DESC_F_NEXT, 2);
            dq.publish(m, 2);
        });
        assert_eq!(e, QueueError::ChainTooLong);
        // Head and next out of range.
        assert_eq!(
            pop_err(4, |m, dq| dq.publish(m, 4)),
            QueueError::DescIndex(4)
        );
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 0, BUF, 1, VIRTQ_DESC_F_NEXT, 0xffff);
            dq.publish(m, 0);
        });
        assert_eq!(e, QueueError::DescIndex(0xffff));
        // Buffer outside RAM, and overflowing the address space.
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 0, 0x1000, 1, 0, 0);
            dq.publish(m, 0);
        });
        assert!(matches!(e, QueueError::Memory(_)));
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 0, u64::MAX - 1, 16, VIRTQ_DESC_F_WRITE, 0);
            dq.publish(m, 0);
        });
        assert!(matches!(e, QueueError::Memory(_)));
        // Readable after writable.
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 0, BUF, 1, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 1);
            dq.write_desc(m, 1, BUF, 1, 0, 0);
            dq.publish(m, 0);
        });
        assert_eq!(e, QueueError::ReadableAfterWritable);
        // More than 4 GiB in total (checked before the buffer address).
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 0, BUF, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            dq.write_desc(m, 1, BUF, u32::MAX, 0, 0);
            dq.publish(m, 0);
        });
        assert_eq!(e, QueueError::ChainTooLarge);
        // Available index jumping past the queue size.
        let e = pop_err(4, |m, dq| m.store_u16_release(dq.avail + 2, 5).unwrap());
        assert_eq!(
            e,
            QueueError::AvailIndex {
                avail_idx: 5,
                next_avail: 0
            }
        );
    }

    #[test]
    fn malformed_indirect_tables_are_errors() {
        let table = BUF + 0x8000;
        let with_table = |len: u32, flags: u16, entries: &[(u64, u32, u16, u16)]| {
            pop_err(4, |m, dq| {
                for (i, &(addr, l, f, next)) in entries.iter().enumerate() {
                    DriverQueue::write_raw_desc(m, table + 16 * i as u64, addr, l, f, next);
                }
                dq.write_desc(m, 0, table, len, flags, 0);
                dq.publish(m, 0);
            })
        };
        assert_eq!(
            with_table(0, VIRTQ_DESC_F_INDIRECT, &[]),
            QueueError::IndirectLength(0)
        );
        assert_eq!(
            with_table(24, VIRTQ_DESC_F_INDIRECT, &[]),
            QueueError::IndirectLength(24)
        );
        let huge = 16 * (MAX_INDIRECT_DESCS as u32 + 1);
        assert_eq!(
            with_table(huge, VIRTQ_DESC_F_INDIRECT, &[]),
            QueueError::IndirectLength(huge)
        );
        assert_eq!(
            with_table(
                16,
                VIRTQ_DESC_F_INDIRECT | VIRTQ_DESC_F_NEXT,
                &[(BUF, 1, 0, 0)]
            ),
            QueueError::IndirectWithNext
        );
        assert_eq!(
            with_table(
                16,
                VIRTQ_DESC_F_INDIRECT,
                &[(table, 16, VIRTQ_DESC_F_INDIRECT, 0)]
            ),
            QueueError::NestedIndirect
        );
        assert_eq!(
            with_table(
                32,
                VIRTQ_DESC_F_INDIRECT,
                &[(BUF, 1, VIRTQ_DESC_F_NEXT, 2), (BUF, 1, 0, 0)]
            ),
            QueueError::DescIndex(2)
        );
        assert_eq!(
            with_table(
                32,
                VIRTQ_DESC_F_INDIRECT,
                &[
                    (BUF, 1, VIRTQ_DESC_F_NEXT, 1),
                    (BUF, 1, VIRTQ_DESC_F_NEXT, 0)
                ]
            ),
            QueueError::ChainTooLong
        );
        // Table itself outside RAM.
        let e = pop_err(4, |m, dq| {
            dq.write_desc(m, 0, 0x1000, 16, VIRTQ_DESC_F_INDIRECT, 0);
            dq.publish(m, 0);
        });
        assert!(matches!(e, QueueError::Memory(_)));
    }

    #[test]
    fn random_rings_never_panic() {
        // Fill the rings with pseudo-random garbage and pop until error/empty.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..500 {
            let (mem, dq, mut q) = setup(16);
            for i in 0..16 {
                let addr = if rnd() % 2 == 0 {
                    BUF + rnd() % 0x1000
                } else {
                    rnd()
                };
                let flags = (rnd() & 7) as u16;
                DriverQueue::write_raw_desc(
                    &mem,
                    dq.desc + 16 * i,
                    addr,
                    (rnd() % 0x2000) as u32,
                    flags,
                    (rnd() % 20) as u16,
                );
                mem.write_u16(dq.avail + 4 + 2 * i, (rnd() % 20) as u16)
                    .unwrap();
            }
            mem.store_u16_release(dq.avail + 2, (rnd() % 24) as u16)
                .unwrap();
            for _ in 0..32 {
                match q.pop() {
                    Ok(Some(c)) => q.add_used(c.head(), 0).unwrap(),
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }

    #[test]
    fn notification_flags() {
        let (mem, mut dq, mut q) = setup(4);
        q.set_notification(false).unwrap();
        assert_eq!(mem.read_u16(dq.used).unwrap(), VIRTQ_USED_F_NO_NOTIFY);
        q.set_notification(true).unwrap();
        assert_eq!(mem.read_u16(dq.used).unwrap(), 0);
        assert!(q.needs_interrupt());
        mem.write_u16(dq.avail, VIRTQ_AVAIL_F_NO_INTERRUPT).unwrap();
        assert!(!q.needs_interrupt());

        dq.add(&mem, &[(BUF, 1, W)]);
        dq.add(&mem, &[(BUF, 2, W)]);
        let mut seen = Vec::new();
        let n = q
            .drain(|c| {
                seen.push(c.writable_len());
                c.writable_len() as u32
            })
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(seen, [1, 2]);
        // Notifications re-enabled after draining.
        assert_eq!(mem.read_u16(dq.used).unwrap(), 0);
    }

    #[test]
    fn sub_range_splitting() {
        let segs = [
            Segment {
                addr: 0x100,
                len: 4,
            },
            Segment {
                addr: 0x200,
                len: 4,
            },
        ];
        let v: Vec<_> = sub_ranges(&segs, 2, 4).collect();
        assert_eq!(v, [(0x102, 2), (0x200, 2)]);
        let v: Vec<_> = sub_ranges(&segs, 4, 100).collect();
        assert_eq!(v, [(0x200, 4)]);
        assert_eq!(sub_ranges(&segs, 8, 1).count(), 0);
        assert_eq!(sub_ranges(&segs, 0, 0).count(), 0);
    }
}
