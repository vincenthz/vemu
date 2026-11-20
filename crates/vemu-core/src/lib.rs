//! Types shared by every vemu crate.
//!
//! - [`GuestMemory`]: the guest's RAM, one host mapping backing one or more
//!   guest-physical regions.
//! - [`MmioDevice`]: a device answering loads/stores in a guest-physical window.
//! - [`IrqLine`]: a level-triggered interrupt line into the guest's GIC.
//! - [`NetFrontend`] / [`NetBackend`]: the frame boundary between the
//!   virtio-net device and a network backend (user-mode NAT).
//!
//! This crate is deliberately small and stable: the other crates are written
//! against it in parallel.

use std::fmt;
use std::io;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

pub mod mem {
    pub use super::{GuestMemory, MemError, MemRegion};
}

/// An out-of-range or overflowing guest-physical access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemError {
    pub gpa: u64,
    pub len: usize,
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "guest memory access out of range: gpa={:#x} len={:#x}",
            self.gpa, self.len
        )
    }
}

impl std::error::Error for MemError {}

/// Guest RAM: a single anonymous host mapping placed at `gpa_base` in the
/// guest-physical address space, or split over several [`MemRegion`]s with
/// holes between them ([`GuestMemory::with_regions`]; x86_64 keeps 3-4 GiB
/// free for MMIO). Devices then reach all of RAM through one object.
///
/// Guest memory is concurrently accessed by vCPUs and device threads, so
/// methods take `&self` and copy bytes with plain `ptr::copy` (the usual VMM
/// convention; the guest is responsible for its own synchronisation, and
/// virtqueue index fields use the atomic accessors below).
pub struct GuestMemory {
    host: NonNull<u8>,
    /// Bytes mapped: the sum of the regions' sizes.
    size: usize,
    /// Sorted by `gpa`, separated by holes, packed back to back in the host
    /// mapping (`host_offset`).
    regions: Vec<MemRegion>,
}

/// One guest-physical range of a [`GuestMemory`] and where it starts in the
/// host mapping. A hypervisor maps each one separately (one HVF mapping or
/// one KVM memory slot per region).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    pub gpa: u64,
    pub size: usize,
    /// Offset of the region's first byte from [`GuestMemory::host_base`].
    pub host_offset: usize,
}

impl MemRegion {
    /// One past the region's last guest-physical address.
    pub fn gpa_end(&self) -> u64 {
        self.gpa + self.size as u64
    }
}

// The mapping is plain memory owned by this struct; sharing it across threads
// is the point.
unsafe impl Send for GuestMemory {}
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    /// Map `size` bytes of zeroed anonymous memory at guest-physical
    /// `gpa_base`. `size` and `gpa_base` must be multiples of the host page
    /// size ([`page_size`]: 16 KiB on Apple Silicon, 4 KiB on most Linux
    /// hosts, up to 64 KiB on some aarch64 Linux kernels).
    pub fn new(gpa_base: u64, size: usize) -> io::Result<Arc<GuestMemory>> {
        GuestMemory::with_regions(&[(gpa_base, size)])
    }

    /// Map zeroed anonymous memory for several guest-physical `(gpa, size)`
    /// ranges, in ascending order with a hole between neighbours (adjacent
    /// ranges are one region). Each base and size must be a non-zero
    /// multiple of the host page size. One host mapping backs all of them,
    /// in order.
    pub fn with_regions(ranges: &[(u64, usize)]) -> io::Result<Arc<GuestMemory>> {
        let page = page_size();
        let invalid = |msg: String| io::Error::new(io::ErrorKind::InvalidInput, msg);
        if ranges.is_empty() {
            return Err(invalid("guest memory needs at least one region".into()));
        }
        let mut regions = Vec::with_capacity(ranges.len());
        let mut size = 0usize;
        let mut prev_end: Option<u64> = None;
        for &(gpa, len) in ranges {
            if len == 0 || !len.is_multiple_of(page) || !gpa.is_multiple_of(page as u64) {
                return Err(invalid(format!(
                    "guest memory base/size must be non-zero multiples of {page:#x}"
                )));
            }
            let end = gpa.checked_add(len as u64).ok_or_else(|| {
                invalid(format!("guest memory region {gpa:#x}+{len:#x} overflows"))
            })?;
            if prev_end.is_some_and(|p| gpa <= p) {
                return Err(invalid(format!(
                    "guest memory region at {gpa:#x} must start above the previous one, after a hole"
                )));
            }
            regions.push(MemRegion {
                gpa,
                size: len,
                host_offset: size,
            });
            size = size
                .checked_add(len)
                .ok_or_else(|| invalid("guest memory size overflows".into()))?;
            prev_end = Some(end);
        }
        // SAFETY: anonymous private mapping, no file, checked for MAP_FAILED.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Arc::new(GuestMemory {
            host: NonNull::new(p.cast()).expect("mmap returned null"),
            size,
            regions,
        }))
    }

    /// Guest-physical address of the first region.
    pub fn gpa_base(&self) -> u64 {
        self.regions[0].gpa
    }

    /// Bytes of RAM, all regions together.
    pub fn size(&self) -> usize {
        self.size
    }

    /// One past the last guest-physical address of RAM (of the last region;
    /// with several regions, not everything below it is RAM).
    pub fn gpa_end(&self) -> u64 {
        self.regions[self.regions.len() - 1].gpa_end()
    }

    /// The guest-physical regions, in ascending order (one for
    /// [`GuestMemory::new`]). Hypervisor backends map each one.
    pub fn regions(&self) -> &[MemRegion] {
        &self.regions
    }

    /// Host address of the start of guest RAM (for `hv_vm_map` / KVM
    /// memslots): region `r` starts at `host_base() + r.host_offset`.
    pub fn host_base(&self) -> *mut u8 {
        self.host.as_ptr()
    }

    /// Offset of `[gpa, gpa+len)` inside the mapping, if it lies entirely in
    /// one region.
    fn offset(&self, gpa: u64, len: usize) -> Result<usize, MemError> {
        let err = MemError { gpa, len };
        for r in &self.regions {
            let Some(off) = gpa.checked_sub(r.gpa) else {
                break; // below this region, so above the previous one
            };
            if off >= r.size as u64 {
                continue;
            }
            let end = off.checked_add(len as u64).ok_or(err)?;
            if end > r.size as u64 {
                return Err(err);
            }
            return Ok(r.host_offset + off as usize);
        }
        Err(err)
    }

    /// Whether `[gpa, gpa+len)` lies entirely in guest RAM.
    pub fn contains(&self, gpa: u64, len: usize) -> bool {
        self.offset(gpa, len).is_ok()
    }

    /// Host pointer for `[gpa, gpa+len)`. The range is bounds-checked; the
    /// pointer is valid for `len` bytes for the lifetime of `self`. Use for
    /// zero-copy I/O (pread/pwrite/recv/send straight into guest buffers).
    pub fn host_ptr(&self, gpa: u64, len: usize) -> Result<*mut u8, MemError> {
        let off = self.offset(gpa, len)?;
        // SAFETY: off+len <= size, checked above.
        Ok(unsafe { self.host.as_ptr().add(off) })
    }

    /// Copy guest memory at `gpa` into `buf`.
    pub fn read(&self, gpa: u64, buf: &mut [u8]) -> Result<(), MemError> {
        let p = self.host_ptr(gpa, buf.len())?;
        // SAFETY: bounds-checked source; `buf` is a distinct host buffer.
        unsafe { std::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    /// Copy `buf` into guest memory at `gpa`.
    pub fn write(&self, gpa: u64, buf: &[u8]) -> Result<(), MemError> {
        let p = self.host_ptr(gpa, buf.len())?;
        // SAFETY: bounds-checked destination; `buf` is a distinct host buffer.
        unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), p, buf.len()) };
        Ok(())
    }

    /// Fill `[gpa, gpa+len)` with zeroes.
    pub fn zero(&self, gpa: u64, len: usize) -> Result<(), MemError> {
        let p = self.host_ptr(gpa, len)?;
        // SAFETY: bounds-checked.
        unsafe { std::ptr::write_bytes(p, 0, len) };
        Ok(())
    }

    pub fn read_u16(&self, gpa: u64) -> Result<u16, MemError> {
        let mut b = [0; 2];
        self.read(gpa, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    pub fn read_u32(&self, gpa: u64) -> Result<u32, MemError> {
        let mut b = [0; 4];
        self.read(gpa, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn read_u64(&self, gpa: u64) -> Result<u64, MemError> {
        let mut b = [0; 8];
        self.read(gpa, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn write_u16(&self, gpa: u64, v: u16) -> Result<(), MemError> {
        self.write(gpa, &v.to_le_bytes())
    }

    pub fn write_u32(&self, gpa: u64, v: u32) -> Result<(), MemError> {
        self.write(gpa, &v.to_le_bytes())
    }

    pub fn write_u64(&self, gpa: u64, v: u64) -> Result<(), MemError> {
        self.write(gpa, &v.to_le_bytes())
    }

    /// Atomic view of a naturally aligned little-endian u16 in guest memory
    /// (virtqueue `idx` fields). Errors if out of range or misaligned.
    pub fn atomic_u16(&self, gpa: u64) -> Result<&AtomicU16, MemError> {
        if !gpa.is_multiple_of(2) {
            return Err(MemError { gpa, len: 2 });
        }
        let p = self.host_ptr(gpa, 2)?;
        // SAFETY: in range, 2-byte aligned (every region's gpa and host
        // offset are page aligned), lives as long as self.
        Ok(unsafe { AtomicU16::from_ptr(p.cast()) })
    }

    /// `atomic_u16(gpa).load(Acquire)`; the host is little-endian like the guest.
    pub fn load_u16_acquire(&self, gpa: u64) -> Result<u16, MemError> {
        Ok(self.atomic_u16(gpa)?.load(Ordering::Acquire))
    }

    /// `atomic_u16(gpa).store(v, Release)`.
    pub fn store_u16_release(&self, gpa: u64, v: u16) -> Result<(), MemError> {
        self.atomic_u16(gpa)?.store(v, Ordering::Release);
        Ok(())
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        // SAFETY: we own the mapping created in `with_regions`.
        unsafe { libc::munmap(self.host.as_ptr().cast(), self.size) };
    }
}

impl fmt::Debug for GuestMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestMemory")
            .field("gpa_base", &format_args!("{:#x}", self.gpa_base()))
            .field("size", &format_args!("{:#x}", self.size))
            .field("regions", &self.regions.len())
            .finish()
    }
}

/// Host page size.
pub fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// A device occupying a window of guest-physical address space.
///
/// `offset` is relative to the start of the device's window. `data.len()` is
/// the access size (1, 2, 4 or 8). Values are little-endian. The MMIO bus
/// serialises calls per device (it holds the device behind a `Mutex`), and
/// calls come from vCPU threads.
pub trait MmioDevice: Send {
    fn read(&mut self, offset: u64, data: &mut [u8]);
    fn write(&mut self, offset: u64, data: &[u8]);
}

/// A level-triggered interrupt line wired to a GIC SPI.
///
/// Implementations must be callable from any thread and must wake a vCPU that
/// is idle in WFI so the interrupt is taken promptly.
pub trait IrqLine: Send + Sync {
    fn set_level(&self, level: bool);
}

/// Implemented by the virtio-net device so a backend can push frames to the
/// guest.
pub trait NetFrontend: Send + Sync {
    /// Deliver one Ethernet frame (no virtio-net header) to the guest.
    ///
    /// Returns `false` when the guest has no receive buffer posted right now.
    /// The frame was then *not* consumed: the backend keeps it and retries
    /// after [`NetBackend::rx_ready`].
    fn deliver(&self, frame: &[u8]) -> bool;
}

/// Implemented by network backends (user-mode NAT).
///
/// Locking rule (prevents deadlock): `transmit` and `rx_ready` are called by
/// the device possibly while it holds its own lock, so they must only enqueue
/// and wake the backend's own thread. They must never call
/// [`NetFrontend::deliver`] synchronously, and the backend must not hold any
/// lock that `transmit`/`rx_ready` take while it calls `deliver`.
pub trait NetBackend: Send + Sync {
    /// Connect the frontend. Called once, before the guest can transmit.
    fn attach(&self, frontend: Arc<dyn NetFrontend>);
    /// The guest transmitted one Ethernet frame (no virtio-net header).
    fn transmit(&self, frame: &[u8]);
    /// The guest posted new receive buffers; retry pending deliveries.
    fn rx_ready(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        let page = page_size();
        let m = GuestMemory::new(0x4000_0000, page * 4).unwrap();
        assert!(m.write_u32(0x4000_0000, 0xdead_beef).is_ok());
        assert_eq!(m.read_u32(0x4000_0000).unwrap(), 0xdead_beef);
        assert!(m.read_u32(0x3fff_fffe).is_err());
        assert!(m.read_u32(m.gpa_end() - 2).is_err());
        assert!(m.read_u32(m.gpa_end() - 4).is_ok());
        assert!(m.host_ptr(u64::MAX, 2).is_err());
        assert!(m.atomic_u16(0x4000_0001).is_err());
        m.store_u16_release(0x4000_0010, 7).unwrap();
        assert_eq!(m.load_u16_acquire(0x4000_0010).unwrap(), 7);
        assert_eq!(
            m.regions(),
            [MemRegion {
                gpa: 0x4000_0000,
                size: page * 4,
                host_offset: 0
            }]
        );
    }

    #[test]
    fn regions_with_a_hole() {
        let page = page_size();
        let (lo, hi) = (0u64, 0x1_0000_0000u64);
        let m = GuestMemory::with_regions(&[(lo, page * 2), (hi, page * 3)]).unwrap();
        assert_eq!(
            (m.gpa_base(), m.size(), m.gpa_end()),
            (lo, page * 5, hi + 3 * page as u64)
        );
        assert_eq!(m.regions()[1].host_offset, page * 2);
        // Both regions work and are distinct host memory.
        m.write_u32(lo + 8, 1).unwrap();
        m.write_u32(hi + 8, 2).unwrap();
        assert_eq!(
            (m.read_u32(lo + 8).unwrap(), m.read_u32(hi + 8).unwrap()),
            (1, 2)
        );
        let p_lo = m.host_ptr(lo, 1).unwrap() as usize;
        let p_hi = m.host_ptr(hi, 1).unwrap() as usize;
        assert_eq!(p_hi - p_lo, page * 2);
        // The hole, and accesses straddling a region's end, are refused.
        let lo_end = lo + 2 * page as u64;
        assert!(m.read_u32(lo_end).is_err());
        assert!(m.read_u32(lo_end - 2).is_err());
        assert!(m.read_u32(hi - 4).is_err());
        assert!(m.read_u32(m.gpa_end() - 4).is_ok());
        assert!(m.read_u32(m.gpa_end() - 2).is_err());
        assert!(m.atomic_u16(hi + 2).is_ok());
        assert!(m.contains(hi, 3 * page) && !m.contains(hi, 3 * page + 1));
        assert!(!m.contains(lo, 2 * page + 1));

        // Out of order, overlapping, adjacent, empty or unaligned: refused.
        let p = page as u64;
        for bad in [
            &[(hi, page), (lo, page)][..],
            &[(lo, 2 * page), (p, page)],
            &[(lo, page), (p, page)],
            &[(lo, 0)],
            &[(lo, page + 1)],
            &[(p / 2, page)],
            &[],
        ] {
            assert!(GuestMemory::with_regions(bad).is_err(), "{bad:x?}");
        }
    }
}
