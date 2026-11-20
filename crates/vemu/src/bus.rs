//! Device dispatch: guest-physical MMIO address → device ([`MmioBus`]), and
//! x86 I/O port → device ([`PortIoBus`]).
//!
//! A bus is built once before the vCPUs start and is then immutable and
//! shared. Each device sits behind its own `Mutex`, so accesses to one device
//! are serialised while different devices are used in parallel. Port-I/O
//! devices implement the same [`MmioDevice`] trait: `offset` is the port
//! minus the device's first port.
//!
//! An MMIO access must lie inside one device; anything else reads as zero
//! and is ignored on write. A port-I/O access that is not inside one device
//! is split into single-port accesses, as a PC chipset splits a wide I/O
//! cycle to byte-wide ISA devices: each port goes to the device that holds
//! it, and ports with no device read all ones (a floating bus) and ignore
//! writes. The first unhandled access in each 4 KiB page (MMIO) or each port
//! (port I/O) is logged, up to [`MAX_LOGGED_PAGES`] pages or ports; a port
//! access logs only its ports that hit no device.

use std::collections::HashSet;
use std::ops::Range;
use std::sync::{Arc, Mutex, PoisonError};

use vemu_core::MmioDevice;

/// Distinct pages (or ports) for which an unhandled access is reported
/// before going quiet.
pub const MAX_LOGGED_PAGES: usize = 16;

struct Region {
    name: String,
    base: u64,
    size: u64,
    dev: Arc<Mutex<dyn MmioDevice>>,
}

/// Range dispatch shared by both buses.
struct Ranges {
    /// "MMIO" or "port I/O", for messages.
    space: &'static str,
    /// Unhandled accesses are logged once per `granule`-aligned block.
    granule: u64,
    /// One past the highest address of the space.
    limit: u128,
    /// Each byte of an unhandled read.
    absent: u8,
    /// Split an access that is not inside one region into single-byte
    /// accesses (port I/O).
    split: bool,
    /// Sorted by `base`, non-overlapping.
    regions: Vec<Region>,
    unhandled: Mutex<HashSet<u64>>,
}

impl Ranges {
    fn new(space: &'static str, granule: u64, limit: u128, absent: u8, split: bool) -> Ranges {
        Ranges {
            space,
            granule,
            limit,
            absent,
            split,
            regions: Vec::new(),
            unhandled: Mutex::new(HashSet::new()),
        }
    }

    fn insert(
        &mut self,
        name: String,
        base: u64,
        size: u64,
        dev: Arc<Mutex<dyn MmioDevice>>,
    ) -> Result<(), String> {
        let space = self.space;
        let end = base
            .checked_add(size)
            .filter(|&e| size > 0 && u128::from(e) <= self.limit)
            .ok_or_else(|| {
                format!("{space} region {name} at {base:#x} has a bad size {size:#x}")
            })?;
        let pos = self.regions.partition_point(|r| r.base < base);
        let clash = |r: &Region| base < r.base + r.size && r.base < end;
        if let Some(r) = [pos.checked_sub(1), Some(pos)]
            .into_iter()
            .flatten()
            .filter_map(|i| self.regions.get(i))
            .find(|r| clash(r))
        {
            return Err(format!(
                "{space} region {name} [{base:#x}, {end:#x}) overlaps {} [{:#x}, {:#x})",
                r.name,
                r.base,
                r.base + r.size
            ));
        }
        self.regions.insert(
            pos,
            Region {
                name,
                base,
                size,
                dev,
            },
        );
        Ok(())
    }

    /// The region fully containing `[addr, addr + len)`.
    fn find(&self, addr: u64, len: usize) -> Option<&Region> {
        let i = self
            .regions
            .partition_point(|r| r.base <= addr)
            .checked_sub(1)?;
        let r = &self.regions[i];
        let off = addr - r.base;
        (off.checked_add(len as u64)? <= r.size).then_some(r)
    }

    /// Call `f` for the pieces of the access `[addr, addr + len)`: byte
    /// range within the access, and the region that handles it (`None`:
    /// no device). The whole access, unless it is not inside one region and
    /// this space splits: then each byte inside a region on its own, and
    /// each run of bytes outside every region as one piece.
    fn for_each_piece(
        &self,
        addr: u64,
        len: usize,
        mut f: impl FnMut(Range<usize>, Option<&Region>),
    ) {
        let whole = self.find(addr, len);
        if whole.is_some() || !self.split || len <= 1 {
            return f(0..len, whole);
        }
        let byte = |i: usize| self.find(addr.checked_add(i as u64)?, 1);
        let mut i = 0;
        while i < len {
            match byte(i) {
                Some(r) => f(i..i + 1, Some(r)),
                None => {
                    let start = i;
                    while i + 1 < len && byte(i + 1).is_none() {
                        i += 1;
                    }
                    f(start..i + 1, None);
                }
            }
            i += 1;
        }
    }

    /// Load of `len` (at most 8) bytes; the value, zero-extended.
    fn read(&self, addr: u64, len: usize) -> u64 {
        let mut buf = [0u8; 8];
        let len = len.min(8);
        self.for_each_piece(addr, len, |piece, r| {
            let at = addr + piece.start as u64;
            match r {
                Some(r) => lock(&r.dev).read(at - r.base, &mut buf[piece]),
                None => {
                    buf[piece.clone()].fill(self.absent);
                    self.unhandled("read", at, piece.len());
                }
            }
        });
        u64::from_le_bytes(buf)
    }

    /// Store of the low `len` bytes of `data`.
    fn write(&self, addr: u64, len: usize, data: u64) {
        let len = len.min(8);
        let bytes = data.to_le_bytes();
        self.for_each_piece(addr, len, |piece, r| {
            let at = addr + piece.start as u64;
            match r {
                Some(r) => lock(&r.dev).write(at - r.base, &bytes[piece]),
                None => self.unhandled("write", at, piece.len()),
            }
        });
    }

    fn unhandled(&self, what: &str, addr: u64, len: usize) {
        let block = addr & !(self.granule - 1);
        let mut seen = lock(&self.unhandled);
        if seen.len() > MAX_LOGGED_PAGES || seen.contains(&block) {
            return;
        }
        seen.insert(block);
        let space = self.space;
        let unit = if self.granule == 1 { "port" } else { "page" };
        let value = if self.absent == 0 { "0" } else { "all ones" };
        if seen.len() > MAX_LOGGED_PAGES {
            crate::log!(
                "unhandled {space} accesses in more than {MAX_LOGGED_PAGES} {unit}s; no longer logging them"
            );
        } else {
            crate::log!(
                "unhandled {space} {what} of {len} bytes at {addr:#x} (reads as {value}, writes ignored; \
                 further accesses to this {unit} not logged)"
            );
        }
    }
}

/// Guest-physical MMIO dispatch.
pub struct MmioBus(Ranges);

impl Default for MmioBus {
    fn default() -> MmioBus {
        MmioBus(Ranges::new("MMIO", 0x1000, 1 << 64, 0, false))
    }
}

impl MmioBus {
    pub fn new() -> MmioBus {
        MmioBus::default()
    }

    /// Register `dev` at `[base, base + size)`.
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        base: u64,
        size: u64,
        dev: Arc<Mutex<dyn MmioDevice>>,
    ) -> Result<(), String> {
        self.0.insert(name.into(), base, size, dev)
    }

    /// Guest load of `len` (1, 2, 4 or 8) bytes; the value, zero-extended.
    pub fn read(&self, addr: u64, len: usize) -> u64 {
        self.0.read(addr, len)
    }

    /// Guest store of the low `len` bytes of `data`.
    pub fn write(&self, addr: u64, len: usize, data: u64) {
        self.0.write(addr, len, data)
    }
}

/// x86 I/O port dispatch (ports 0..=0xffff). Empty on aarch64.
pub struct PortIoBus(Ranges);

impl Default for PortIoBus {
    fn default() -> PortIoBus {
        PortIoBus(Ranges::new("port I/O", 1, 1 << 16, 0xff, true))
    }
}

impl PortIoBus {
    pub fn new() -> PortIoBus {
        PortIoBus::default()
    }

    /// Register `dev` at ports `[base, base + count)`. Only the x86_64
    /// machine has port-I/O devices.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        base: u16,
        count: u16,
        dev: Arc<Mutex<dyn MmioDevice>>,
    ) -> Result<(), String> {
        self.0
            .insert(name.into(), u64::from(base), u64::from(count), dev)
    }

    /// Guest `IN` of `len` (1, 2 or 4) bytes from ports `port..port + len`;
    /// the value, zero-extended. Ports with no device read 0xff.
    pub fn read(&self, port: u16, len: usize) -> u32 {
        self.0.read(u64::from(port), len.min(4)) as u32
    }

    /// Guest `OUT` of the low `len` bytes of `data` to ports
    /// `port..port + len` (byte *i* to `port + i`).
    pub fn write(&self, port: u16, len: usize, data: u32) {
        self.0.write(u64::from(port), len.min(4), u64::from(data))
    }
}

/// Lock a device; a poisoned lock (a panicking device) is still usable, the
/// process exits on panics anyway.
fn lock<T: ?Sized>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records accesses; reads return the offset in every byte.
    #[derive(Default)]
    struct Probe {
        log: Vec<(bool, u64, Vec<u8>)>,
    }

    impl MmioDevice for Probe {
        fn read(&mut self, offset: u64, data: &mut [u8]) {
            data.fill(offset as u8);
            self.log.push((false, offset, data.to_vec()));
        }
        fn write(&mut self, offset: u64, data: &[u8]) {
            self.log.push((true, offset, data.to_vec()));
        }
    }

    #[test]
    fn dispatch_by_range() {
        let a = Arc::new(Mutex::new(Probe::default()));
        let b = Arc::new(Mutex::new(Probe::default()));
        let mut bus = MmioBus::new();
        bus.insert("b", 0x2000, 0x200, b.clone()).unwrap();
        bus.insert("a", 0x1000, 0x100, a.clone()).unwrap();

        assert_eq!(bus.read(0x1010, 4), 0x1010_1010);
        bus.write(0x2004, 2, 0xdead_beef);
        assert_eq!(bus.read(0x21f8, 8), 0xf8f8_f8f8_f8f8_f8f8);
        // Unmapped, past the end, or straddling the end of a region.
        assert_eq!(bus.read(0x1100, 4), 0);
        assert_eq!(bus.read(0x10fe, 4), 0);
        assert_eq!(bus.read(0x500, 1), 0);
        bus.write(0x3000, 4, 1);

        let a = a.lock().unwrap();
        assert_eq!(a.log, vec![(false, 0x10, vec![0x10; 4])]);
        let b = b.lock().unwrap();
        assert_eq!(
            b.log,
            vec![(true, 4, vec![0xef, 0xbe]), (false, 0x1f8, vec![0xf8; 8])]
        );
    }

    #[test]
    fn rejects_overlap() {
        let d = || Arc::new(Mutex::new(Probe::default()));
        let mut bus = MmioBus::new();
        bus.insert("a", 0x1000, 0x100, d()).unwrap();
        bus.insert("c", 0x1200, 0x100, d()).unwrap();
        assert!(
            bus.insert("x", 0x10ff, 2, d())
                .unwrap_err()
                .contains("overlaps a")
        );
        assert!(
            bus.insert("x", 0x1100, 0x101, d())
                .unwrap_err()
                .contains("overlaps c")
        );
        assert!(bus.insert("x", 0x0, 0x2000, d()).is_err());
        assert!(bus.insert("x", 0x5000, 0, d()).is_err());
        assert!(bus.insert("x", u64::MAX, 2, d()).is_err());
        bus.insert("b", 0x1100, 0x100, d()).unwrap();
    }

    #[test]
    fn unhandled_logging_is_bounded() {
        let bus = MmioBus::new();
        for i in 0..100u64 {
            assert_eq!(bus.read(i * 0x1000, 4), 0);
        }
        assert_eq!(bus.0.unhandled.lock().unwrap().len(), MAX_LOGGED_PAGES + 1);
    }

    #[test]
    fn port_io() {
        let com = Arc::new(Mutex::new(Probe::default()));
        let mut bus = PortIoBus::new();
        bus.insert("com1", 0x3f8, 8, com.clone()).unwrap();
        assert_eq!(bus.read(0x3fd, 1), 0x05);
        assert_eq!(bus.read(0x3f8, 4), 0);
        bus.write(0x3f8, 1, 0x4142);
        bus.write(0x3fe, 2, 0x1234);
        // Straddling the end (split per port; no port 0x400), unmapped
        // (all ones), and 8-byte accesses clamped to 4.
        assert_eq!(bus.read(0x3ff, 2), 0xff07);
        assert_eq!(bus.read(0x80, 1), 0xff);
        assert_eq!(bus.read(0x3f9, 8), 0x0101_0101);
        let com = com.lock().unwrap();
        assert_eq!(
            com.log,
            vec![
                (false, 5, vec![5]),
                (false, 0, vec![0; 4]),
                (true, 0, vec![0x42]),
                (true, 6, vec![0x34, 0x12]),
                (false, 7, vec![7]),
                (false, 1, vec![1; 4]),
            ]
        );
        drop(com);
        // Only the ports that hit no device were logged.
        assert_eq!(
            *bus.0.unhandled.lock().unwrap(),
            HashSet::from([0x400, 0x80])
        );
        // The port space ends at 0xffff.
        let d = Arc::new(Mutex::new(Probe::default()));
        assert!(bus.insert("x", 0xfffe, 2, d.clone()).is_ok());
        assert!(bus.insert("y", 0x3f0, 9, d.clone()).is_err(), "overlap");
        // Unhandled accesses are logged per port.
        bus.0.unhandled.lock().unwrap().clear();
        for p in 0..40u16 {
            bus.read(0x100 + p, 1);
        }
        assert_eq!(bus.0.unhandled.lock().unwrap().len(), MAX_LOGGED_PAGES + 1);
    }

    /// Port accesses that are not inside one device are split per port, as
    /// on a PC: each port reaches its own device, absent ports read 0xff
    /// and drop writes, and only the absent ports are logged.
    #[test]
    fn port_io_split_per_port() {
        let com = Arc::new(Mutex::new(Probe::default()));
        let next = Arc::new(Mutex::new(Probe::default()));
        let top = Arc::new(Mutex::new(Probe::default()));
        let mut bus = PortIoBus::new();
        bus.insert("com1", 0x3f8, 8, com.clone()).unwrap();
        bus.insert("next", 0x400, 2, next.clone()).unwrap();
        bus.insert("cmos", 0x70, 2, com.clone()).unwrap();
        bus.insert("top", 0xfffe, 2, top.clone()).unwrap();

        // inl(0x3fd): LSR, MSR, SCR from com1, then 0x400 from the next
        // device; nothing is unhandled.
        assert_eq!(bus.read(0x3fd, 4), 0x0007_0605);
        // outw(0x3ff): the low byte to com1's last port, the high to 0x400.
        bus.write(0x3ff, 2, 0xbbaa);
        // inl(0x401): one port of `next`, then three absent ports.
        assert_eq!(bus.read(0x401, 4), 0xffff_ff01);
        bus.write(0x401, 4, 0x4433_2211);
        // inw(0x71) runs past the CMOS pair; inl(0x6e) starts before it.
        assert_eq!(bus.read(0x71, 2), 0xff01);
        assert_eq!(bus.read(0x6e, 4), 0x0100_ffff);
        // The end of the port space: 0x10000 does not exist.
        assert_eq!(bus.read(0xffff, 4), 0xffff_ff01);
        // An access that hits no device at all reads all ones, logged once.
        assert_eq!(bus.read(0x500, 4), 0xffff_ffff);

        assert_eq!(
            com.lock().unwrap().log,
            vec![
                (false, 5, vec![5]),
                (false, 6, vec![6]),
                (false, 7, vec![7]),
                (true, 7, vec![0xaa]),
                (false, 1, vec![1]),
                (false, 0, vec![0]),
                (false, 1, vec![1]),
            ]
        );
        assert_eq!(
            next.lock().unwrap().log,
            vec![
                (false, 0, vec![0]),
                (true, 0, vec![0xbb]),
                (false, 1, vec![1]),
                (true, 1, vec![0x11]),
            ]
        );
        assert_eq!(top.lock().unwrap().log, vec![(false, 1, vec![1])]);
        assert_eq!(
            *bus.0.unhandled.lock().unwrap(),
            HashSet::from([0x402, 0x72, 0x6e, 0x10000, 0x500])
        );
    }

    /// MMIO is not split: an access straddling a region's end, or two
    /// regions, reads as zero and is dropped whole.
    #[test]
    fn mmio_not_split() {
        let a = Arc::new(Mutex::new(Probe::default()));
        let b = Arc::new(Mutex::new(Probe::default()));
        let mut bus = MmioBus::new();
        bus.insert("a", 0x1000, 0x100, a.clone()).unwrap();
        bus.insert("b", 0x1100, 0x100, b.clone()).unwrap();
        assert_eq!(bus.read(0x10fe, 4), 0);
        bus.write(0x10fe, 4, u64::MAX);
        assert!(a.lock().unwrap().log.is_empty());
        assert!(b.lock().unwrap().log.is_empty());
    }
}
