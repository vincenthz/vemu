//! Test helpers: guest memory, a recording IRQ line and a fake virtio driver
//! that lays out rings in guest memory and programs an [`MmioTransport`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use vemu_core::{GuestMemory, IrqLine, MmioDevice};

use crate::mmio::{reg, status};
use crate::queue::{VIRTQ_DESC_F_INDIRECT, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::{MmioTransport, VirtioDevice, features};

pub const MEM_BASE: u64 = 0x4000_0000;
pub const MEM_SIZE: usize = 4 << 20;

pub fn test_memory() -> Arc<GuestMemory> {
    GuestMemory::new(MEM_BASE, MEM_SIZE).unwrap()
}

/// An IRQ line recording its level transitions.
#[derive(Default)]
pub struct FakeIrq {
    level: AtomicBool,
    transitions: Mutex<Vec<bool>>,
}

impl FakeIrq {
    pub fn new() -> Arc<FakeIrq> {
        Arc::new(FakeIrq::default())
    }

    pub fn level(&self) -> bool {
        self.level.load(Ordering::SeqCst)
    }

    pub fn transitions(&self) -> Vec<bool> {
        self.transitions.lock().unwrap().clone()
    }
}

impl IrqLine for FakeIrq {
    fn set_level(&self, level: bool) {
        self.level.store(level, Ordering::SeqCst);
        self.transitions.lock().unwrap().push(level);
    }
}

/// Driver side of a split virtqueue living in guest memory.
pub struct DriverQueue {
    pub size: u16,
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
    next_desc: u16,
    avail_idx: u16,
    last_used: u16,
}

impl DriverQueue {
    /// Bytes needed for the rings of a queue of `size` at a 16-aligned base.
    pub fn footprint(size: u16) -> u64 {
        let n = u64::from(size);
        (16 * n + 6 + 2 * n).next_multiple_of(4) + 6 + 8 * n
    }

    /// Lay out the rings at `base` (16-byte aligned); memory must be zeroed.
    pub fn new(base: u64, size: u16) -> DriverQueue {
        let n = u64::from(size);
        let avail = base + 16 * n;
        DriverQueue {
            size,
            desc: base,
            avail,
            used: (avail + 6 + 2 * n).next_multiple_of(4),
            next_desc: 0,
            avail_idx: 0,
            last_used: 0,
        }
    }

    pub fn write_raw_desc(mem: &GuestMemory, gpa: u64, addr: u64, len: u32, flags: u16, next: u16) {
        mem.write_u64(gpa, addr).unwrap();
        mem.write_u32(gpa + 8, len).unwrap();
        mem.write_u16(gpa + 12, flags).unwrap();
        mem.write_u16(gpa + 14, next).unwrap();
    }

    pub fn write_desc(
        &self,
        mem: &GuestMemory,
        index: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        Self::write_raw_desc(
            mem,
            self.desc + 16 * u64::from(index),
            addr,
            len,
            flags,
            next,
        );
    }

    /// Write `bufs` as a linked chain into an indirect table at `table`.
    pub fn write_table(mem: &GuestMemory, table: u64, bufs: &[(u64, u32, bool)]) {
        for (i, &(addr, len, writable)) in bufs.iter().enumerate() {
            let mut flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
            if i + 1 < bufs.len() {
                flags |= VIRTQ_DESC_F_NEXT;
            }
            Self::write_raw_desc(mem, table + 16 * i as u64, addr, len, flags, i as u16 + 1);
        }
    }

    fn alloc_desc(&mut self) -> u16 {
        let i = self.next_desc;
        self.next_desc = (self.next_desc + 1) % self.size;
        i
    }

    /// Add a direct chain of `(addr, len, device_writable)` buffers and
    /// publish it. Returns the head index.
    pub fn add(&mut self, mem: &GuestMemory, bufs: &[(u64, u32, bool)]) -> u16 {
        let idx: Vec<u16> = bufs.iter().map(|_| self.alloc_desc()).collect();
        for (i, &(addr, len, writable)) in bufs.iter().enumerate() {
            let mut flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
            let next = idx.get(i + 1).copied();
            if next.is_some() {
                flags |= VIRTQ_DESC_F_NEXT;
            }
            self.write_desc(mem, idx[i], addr, len, flags, next.unwrap_or(0));
        }
        self.publish(mem, idx[0]);
        idx[0]
    }

    /// Add a chain through an indirect table at `table` and publish it.
    pub fn add_indirect(
        &mut self,
        mem: &GuestMemory,
        table: u64,
        bufs: &[(u64, u32, bool)],
    ) -> u16 {
        Self::write_table(mem, table, bufs);
        let head = self.alloc_desc();
        self.write_desc(
            mem,
            head,
            table,
            16 * bufs.len() as u32,
            VIRTQ_DESC_F_INDIRECT,
            0,
        );
        self.publish(mem, head);
        head
    }

    /// Put `head` in the available ring and bump the index.
    pub fn publish(&mut self, mem: &GuestMemory, head: u16) {
        let slot = u64::from(self.avail_idx % self.size);
        mem.write_u16(self.avail + 4 + 2 * slot, head).unwrap();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        mem.store_u16_release(self.avail + 2, self.avail_idx)
            .unwrap();
    }

    /// Next `(id, len)` from the used ring.
    pub fn pop_used(&mut self, mem: &GuestMemory) -> Option<(u32, u32)> {
        let idx = mem.load_u16_acquire(self.used + 2).unwrap();
        if idx == self.last_used {
            return None;
        }
        let elem = self.used + 4 + 8 * u64::from(self.last_used % self.size);
        self.last_used = self.last_used.wrapping_add(1);
        Some((mem.read_u32(elem).unwrap(), mem.read_u32(elem + 4).unwrap()))
    }

    /// Set or clear `VIRTQ_AVAIL_F_NO_INTERRUPT`.
    pub fn set_no_interrupt(&self, mem: &GuestMemory, on: bool) {
        mem.store_u16_release(self.avail, u16::from(on)).unwrap();
    }
}

/// A fake virtio-mmio driver talking to a transport.
pub struct Driver {
    pub t: MmioTransport,
    pub mem: Arc<GuestMemory>,
    pub irq: Arc<FakeIrq>,
    pub queues: Vec<Option<DriverQueue>>,
    next_free: u64,
}

impl Driver {
    pub fn new(dev: Box<dyn VirtioDevice>) -> Driver {
        let mem = test_memory();
        let irq = FakeIrq::new();
        Driver {
            t: MmioTransport::new(dev, mem.clone(), irq.clone()),
            mem,
            irq,
            queues: Vec::new(),
            next_free: MEM_BASE,
        }
    }

    /// Allocate `len` bytes of zeroed guest memory, 64-byte aligned.
    pub fn alloc(&mut self, len: u64) -> u64 {
        let a = self.next_free;
        self.next_free = (a + len).next_multiple_of(64);
        assert!(
            self.next_free <= self.mem.gpa_end(),
            "test memory exhausted"
        );
        a
    }

    pub fn read32(&mut self, off: u64) -> u32 {
        let mut b = [0; 4];
        self.t.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    pub fn write32(&mut self, off: u64, v: u32) {
        self.t.write(off, &v.to_le_bytes());
    }

    /// Write a 64-bit value to a low/high register pair.
    pub fn write64(&mut self, low: u64, v: u64) {
        self.write32(low, v as u32);
        self.write32(low + 4, (v >> 32) as u32);
    }

    pub fn read_config(&mut self, off: u64, data: &mut [u8]) {
        self.t.read(reg::CONFIG + off, data);
    }

    /// Reset, acknowledge, offer `features` and report whether the device
    /// accepted them (FEATURES_OK stuck).
    pub fn negotiate(&mut self, features: u64) -> bool {
        self.write32(reg::STATUS, 0);
        self.write32(reg::STATUS, status::ACKNOWLEDGE);
        self.write32(reg::STATUS, status::ACKNOWLEDGE | status::DRIVER);
        self.write32(reg::DRIVER_FEATURES_SEL, 0);
        self.write32(reg::DRIVER_FEATURES, features as u32);
        self.write32(reg::DRIVER_FEATURES_SEL, 1);
        self.write32(reg::DRIVER_FEATURES, (features >> 32) as u32);
        self.write32(
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        );
        self.read32(reg::STATUS) & status::FEATURES_OK != 0
    }

    /// The device's offered features.
    pub fn device_features(&mut self) -> u64 {
        self.write32(reg::DEVICE_FEATURES_SEL, 0);
        let lo = self.read32(reg::DEVICE_FEATURES);
        self.write32(reg::DEVICE_FEATURES_SEL, 1);
        let hi = self.read32(reg::DEVICE_FEATURES);
        u64::from(hi) << 32 | u64::from(lo)
    }

    /// Allocate rings for queue `index` and enable it.
    pub fn setup_queue(&mut self, index: u16, size: u16) {
        let base = self.alloc(DriverQueue::footprint(size));
        self.program_queue(index, DriverQueue::new(base, size));
    }

    /// Reset and re-initialise the device, reusing (zeroed) ring memory.
    pub fn restart(&mut self) {
        let f = self.device_features();
        assert!(self.negotiate(f));
        let layouts: Vec<_> = self
            .queues
            .iter()
            .map(|q| q.as_ref().map(|q| (q.desc, q.size)))
            .collect();
        for (i, layout) in layouts.into_iter().enumerate() {
            if let Some((base, size)) = layout {
                self.mem
                    .zero(base, DriverQueue::footprint(size) as usize)
                    .unwrap();
                self.program_queue(i as u16, DriverQueue::new(base, size));
            }
        }
        self.driver_ok();
    }

    fn program_queue(&mut self, index: u16, q: DriverQueue) {
        let size = q.size;
        self.write32(reg::QUEUE_SEL, u32::from(index));
        assert!(self.read32(reg::QUEUE_NUM_MAX) >= u32::from(size));
        assert_eq!(self.read32(reg::QUEUE_READY), 0);
        self.write32(reg::QUEUE_NUM, u32::from(size));
        self.write64(reg::QUEUE_DESC_LOW, q.desc);
        self.write64(reg::QUEUE_DRIVER_LOW, q.avail);
        self.write64(reg::QUEUE_DEVICE_LOW, q.used);
        self.write32(reg::QUEUE_READY, 1);
        assert_eq!(self.read32(reg::QUEUE_READY), 1);
        let i = usize::from(index);
        if self.queues.len() <= i {
            self.queues.resize_with(i + 1, || None);
        }
        self.queues[i] = Some(q);
    }

    pub fn driver_ok(&mut self) {
        let s = self.read32(reg::STATUS);
        self.write32(reg::STATUS, s | status::DRIVER_OK);
    }

    /// Full initialisation accepting every offered feature, with one queue
    /// per entry of `sizes`.
    pub fn start(&mut self, sizes: &[u16]) {
        let f = self.device_features();
        self.start_with(f, sizes);
    }

    /// Full initialisation accepting `features` (which must be offered), with
    /// one queue per entry of `sizes`.
    pub fn start_with(&mut self, features: u64, sizes: &[u16]) {
        assert_ne!(features & features::VERSION_1, 0);
        assert!(self.negotiate(features));
        for (i, &size) in sizes.iter().enumerate() {
            self.setup_queue(i as u16, size);
        }
        self.driver_ok();
        assert_eq!(self.read32(reg::STATUS) & status::DEVICE_NEEDS_RESET, 0);
    }

    pub fn q(&mut self, index: usize) -> &mut DriverQueue {
        self.queues[index].as_mut().unwrap()
    }

    /// Add a direct chain to queue `index` (without notifying).
    pub fn add(&mut self, index: usize, bufs: &[(u64, u32, bool)]) -> u16 {
        let mem = self.mem.clone();
        self.q(index).add(&mem, bufs)
    }

    pub fn pop_used(&mut self, index: usize) -> Option<(u32, u32)> {
        let mem = self.mem.clone();
        self.q(index).pop_used(&mem)
    }

    pub fn kick(&mut self, index: u16) {
        self.write32(reg::QUEUE_NOTIFY, u32::from(index));
    }

    pub fn interrupt_status(&mut self) -> u32 {
        self.read32(reg::INTERRUPT_STATUS)
    }

    /// Acknowledge every pending interrupt; returns what was pending.
    pub fn ack(&mut self) -> u32 {
        let s = self.interrupt_status();
        self.write32(reg::INTERRUPT_ACK, s);
        s
    }

    pub fn needs_reset(&mut self) -> bool {
        self.read32(reg::STATUS) & status::DEVICE_NEEDS_RESET != 0
    }

    pub fn reset(&mut self) {
        self.write32(reg::STATUS, 0);
    }
}
