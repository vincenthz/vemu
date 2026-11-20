//! virtio-blk (virtio 1.2 §5.2) over a [`vemu_disk::BlockBackend`]: a raw
//! image, an overlay on a golden image, or a throwaway snapshot.
//!
//! Requests are served synchronously on the notifying vCPU thread, one
//! queue, under the transport lock (so one disk's requests never run
//! concurrently). Each guest buffer segment goes to the backend as is: a
//! raw image `pread`s/`pwrite`s straight into guest memory (no bounce
//! buffer); an overlay does the same, plus a block-sized copy-up buffer for
//! partial writes to blocks it does not hold yet. The device offers
//! `VIRTIO_BLK_F_SEG_MAX`, `VIRTIO_BLK_F_BLK_SIZE` (512),
//! `VIRTIO_BLK_F_FLUSH` and, for read-only disks, `VIRTIO_BLK_F_RO`.
//!
//! The backend locks its files with `flock` for as long as it exists:
//! exclusively when writable, shared when read-only (and golden images
//! always shared). A second writer, or a writer alongside readers, is
//! refused (as QEMU's image locking does), so two guests never mount one
//! filesystem image independently.

use std::fs::File;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use vemu_core::GuestMemory;
use vemu_disk::{BlockBackend, Raw, ReadBuf, WriteBuf};

use crate::interrupt::Interrupt;
use crate::queue::{DescChain, Queue, Segment, sub_ranges};
use crate::{
    ActivateContext, ActivateError, VirtioDevice, device_id, queue_broken, read_config_bytes,
    warn_once,
};

pub const SECTOR_SIZE: u64 = 512;

/// Maximum segments per request.
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
/// Device is read-only.
pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
/// `blk_size` is valid.
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
/// Cache flush command support.
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Length of the `GET_ID` serial number.
pub const ID_LEN: usize = 20;

/// Request header: `le32 type, le32 reserved, le64 sector`.
const HEADER_LEN: u64 = 16;

const QUEUE_SIZE: u16 = 256;
/// Data segments per request: the queue size minus header and status.
const SEG_MAX: u32 = QUEUE_SIZE as u32 - 2;

/// Source of the default serial numbers "vemu-0", "vemu-1", ... (in creation
/// order, which matches the command line order).
static NEXT_SERIAL: AtomicU32 = AtomicU32::new(0);

/// virtio-blk device.
pub struct Block {
    backend: Arc<dyn BlockBackend>,
    read_only: bool,
    /// Size in 512-byte sectors (a trailing partial sector is not exposed).
    capacity: u64,
    id: [u8; ID_LEN],
    active: Option<Active>,
}

struct Active {
    mem: Arc<GuestMemory>,
    queue: Queue,
    interrupt: Arc<Interrupt>,
}

impl Block {
    /// A disk backed by the raw image `file`. With `read_only` the guest
    /// sees a read-only disk and writes fail, even if the file is writable.
    ///
    /// Takes an advisory lock on `file` (shared if `read_only`, exclusive
    /// otherwise), held until the `Block` is dropped. Fails with
    /// [`io::ErrorKind::WouldBlock`] if another open of the image (in this or
    /// another process) holds a conflicting lock.
    pub fn new(file: File, read_only: bool) -> io::Result<Block> {
        Ok(Block::with_backend(Arc::new(Raw::from_file(
            file, read_only,
        )?)))
    }

    /// A disk over `backend` (see [`vemu_disk::open`]); read-only if the
    /// backend is. The capacity is the backend's size in whole sectors.
    pub fn with_backend(backend: Arc<dyn BlockBackend>) -> Block {
        let mut block = Block {
            read_only: backend.read_only(),
            capacity: backend.size() / SECTOR_SIZE,
            backend,
            id: [0; ID_LEN],
            active: None,
        };
        block.set_serial(&format!(
            "vemu-{}",
            NEXT_SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        block
    }

    /// Set the serial number returned by `GET_ID` (truncated to 20 bytes).
    pub fn set_serial(&mut self, serial: &str) {
        let s = &serial.as_bytes()[..serial.len().min(ID_LEN)];
        self.id = [0; ID_LEN];
        self.id[..s.len()].copy_from_slice(s);
    }

    /// Capacity in 512-byte sectors.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    fn process(&mut self) {
        let Some(a) = self.active.as_mut() else {
            return;
        };
        let disk = Disk {
            backend: &*self.backend,
            read_only: self.read_only,
            capacity: self.capacity,
            id: &self.id,
        };
        let mem = a.mem.clone();
        match a.queue.drain(|chain| disk.handle(&mem, chain)) {
            Ok(0) => {}
            Ok(_) => {
                if a.queue.needs_interrupt() {
                    a.interrupt.signal_used();
                }
            }
            Err(e) => {
                queue_broken("block", "request", &e, &a.interrupt);
                a.interrupt.signal_used();
                self.active = None;
            }
        }
    }
}

/// What request handling needs, borrowed apart from the queue.
struct Disk<'a> {
    backend: &'a dyn BlockBackend,
    read_only: bool,
    capacity: u64,
    id: &'a [u8; ID_LEN],
}

impl Disk<'_> {
    /// Serve one request; returns the bytes written to its writable part.
    fn handle(&self, mem: &GuestMemory, chain: &DescChain) -> u32 {
        let mut header = [0; HEADER_LEN as usize];
        if chain.writable_len() == 0 {
            warn_once!("block: request without a status byte; dropped");
            return 0;
        }
        // The status byte is the last writable byte; data sits before it.
        let status_at = chain.writable_len() - 1;
        let (status, data_written) = if chain.read_at(mem, 0, &mut header) != Ok(header.len()) {
            warn_once!("block: request with a short header");
            (VIRTIO_BLK_S_IOERR, 0)
        } else {
            let ty = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let mut s = [0; 8];
            s.copy_from_slice(&header[8..16]);
            let sector = u64::from_le_bytes(s);
            self.request(mem, chain, ty, sector, status_at)
        };
        // Cannot fail: the segment was bounds-checked when popped.
        let _ = chain.write_at(mem, status_at, &[status]);
        // status_at < writable_len, which fits in a u32.
        (data_written + 1) as u32
    }

    /// Returns the status and the data bytes written to the guest.
    fn request(
        &self,
        mem: &GuestMemory,
        chain: &DescChain,
        ty: u32,
        sector: u64,
        data_len: u64,
    ) -> (u8, u64) {
        match ty {
            VIRTIO_BLK_T_IN => {
                match self.transfer(mem, chain.writable(), 0, data_len, sector, Dir::Read) {
                    Ok(()) => (VIRTIO_BLK_S_OK, data_len),
                    Err(_) => (VIRTIO_BLK_S_IOERR, 0),
                }
            }
            VIRTIO_BLK_T_OUT => {
                if self.read_only {
                    return (VIRTIO_BLK_S_IOERR, 0);
                }
                let len = chain.readable_len() - HEADER_LEN;
                match self.transfer(mem, chain.readable(), HEADER_LEN, len, sector, Dir::Write) {
                    Ok(()) => (VIRTIO_BLK_S_OK, 0),
                    Err(e) => {
                        if e.kind() != io::ErrorKind::InvalidInput {
                            warn_once!("block: write failed: {e}");
                        }
                        (VIRTIO_BLK_S_IOERR, 0)
                    }
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.backend.flush() {
                Ok(()) => (VIRTIO_BLK_S_OK, 0),
                Err(e) => {
                    warn_once!("block: flush failed: {e}");
                    (VIRTIO_BLK_S_IOERR, 0)
                }
            },
            VIRTIO_BLK_T_GET_ID => {
                let n = (data_len as usize).min(ID_LEN);
                match chain.write_at(mem, 0, &self.id[..n]) {
                    Ok(n) => (VIRTIO_BLK_S_OK, n as u64),
                    Err(_) => (VIRTIO_BLK_S_IOERR, 0),
                }
            }
            _ => (VIRTIO_BLK_S_UNSUPP, 0),
        }
    }

    /// Move `len` bytes between the image at `sector` and the guest buffers
    /// `segs` (starting `offset` bytes into them), checking the sector range.
    fn transfer(
        &self,
        mem: &GuestMemory,
        segs: &[Segment],
        offset: u64,
        len: u64,
        sector: u64,
        dir: Dir,
    ) -> io::Result<()> {
        let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
        if !len.is_multiple_of(SECTOR_SIZE) {
            warn_once!("block: request length {len} is not a multiple of {SECTOR_SIZE}");
            return Err(invalid());
        }
        let end = sector.checked_add(len / SECTOR_SIZE).ok_or_else(invalid)?;
        if end > self.capacity {
            warn_once!(
                "block: request past the end of the disk (sector {sector} + {})",
                len / SECTOR_SIZE
            );
            return Err(invalid());
        }
        let mut file_off = sector * SECTOR_SIZE;
        for (gpa, n) in sub_ranges(segs, offset, len) {
            let ptr = mem.host_ptr(gpa, n).map_err(|_| invalid())?;
            match dir {
                // SAFETY: `ptr` comes from GuestMemory::host_ptr for `n`
                // bytes of guest RAM, which outlives this call (the caller
                // holds the Arc); the backend only reaches it through raw
                // copies and system calls, never Rust references.
                Dir::Read => self
                    .backend
                    .read_at(unsafe { ReadBuf::from_raw(ptr, n) }, file_off)?,
                // SAFETY: as above; the backend only reads it.
                Dir::Write => self
                    .backend
                    .write_at(unsafe { WriteBuf::from_raw(ptr, n) }, file_off)?,
            }
            file_off += n as u64;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Dir {
    Read,
    Write,
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        device_id::BLOCK
    }

    fn device_features(&self) -> u64 {
        let ro = if self.read_only { VIRTIO_BLK_F_RO } else { 0 };
        VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_FLUSH | ro
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn queue_max_size(&self) -> u16 {
        QUEUE_SIZE
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // struct virtio_blk_config, up to and including blk_size; the rest
        // (topology, writeback, discard, ...) belongs to features not offered.
        let mut cfg = [0; 24];
        cfg[0..8].copy_from_slice(&self.capacity.to_le_bytes());
        // 8: size_max (no VIRTIO_BLK_F_SIZE_MAX).
        cfg[12..16].copy_from_slice(&SEG_MAX.to_le_bytes());
        // 16: geometry (no VIRTIO_BLK_F_GEOMETRY).
        cfg[20..24].copy_from_slice(&(SECTOR_SIZE as u32).to_le_bytes());
        read_config_bytes(&cfg, offset, data);
    }

    fn activate(&mut self, mut ctx: ActivateContext) -> Result<(), ActivateError> {
        let queue = ctx.take_queue(0)?;
        self.active = Some(Active {
            mem: ctx.mem,
            queue,
            interrupt: ctx.interrupt,
        });
        Ok(())
    }

    fn queue_notify(&mut self, index: u16) {
        if index == 0 {
            self.process();
        }
    }

    fn reset(&mut self) {
        self.active = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::INT_USED;
    use crate::testutil::Driver;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    const SECTORS: u64 = 64;

    struct TempFile(PathBuf);

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn image(name: &str) -> (TempFile, File) {
        let dir = std::env::temp_dir().join("vemu-virtio-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}-{}.img", std::process::id()));
        let mut f = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let data: Vec<u8> = (0..SECTORS * SECTOR_SIZE)
            .map(|i| (i / SECTOR_SIZE) as u8)
            .collect();
        f.write_all(&data).unwrap();
        // A trailing partial sector is not exposed.
        f.write_all(&[0xee; 100]).unwrap();
        (TempFile(path), f)
    }

    fn disk(name: &str, read_only: bool) -> (Driver, TempFile) {
        let (tmp, f) = image(name);
        let mut b = Block::new(f, read_only).unwrap();
        b.set_serial("test-serial");
        let mut d = Driver::new(Box::new(b));
        d.start(&[16]);
        (d, tmp)
    }

    /// Submit a request; returns (status, used len).
    fn submit(d: &mut Driver, ty: u32, sector: u64, out: &[u8], in_len: u32) -> (u8, u32, u64) {
        let hdr = d.alloc(16);
        d.mem.write_u32(hdr, ty).unwrap();
        d.mem.write_u64(hdr + 8, sector).unwrap();
        let status = d.alloc(1);
        d.mem.write(status, &[0xff]).unwrap();
        let mut bufs = vec![(hdr, 16, false)];
        if !out.is_empty() {
            let a = d.alloc(out.len() as u64);
            d.mem.write(a, out).unwrap();
            bufs.push((a, out.len() as u32, false));
        }
        let data = d.alloc(u64::from(in_len.max(1)));
        if in_len > 0 {
            bufs.push((data, in_len, true));
        }
        bufs.push((status, 1, true));
        let h = d.add(0, &bufs);
        d.kick(0);
        let (id, len) = d.pop_used(0).unwrap();
        assert_eq!(id, u32::from(h));
        let mut s = [0];
        d.mem.read(status, &mut s).unwrap();
        (s[0], len, data)
    }

    #[test]
    fn config_and_features() {
        let (mut d, _t) = disk("cfg", false);
        let f = d.device_features();
        assert_eq!(
            f & 0xffff_ffff,
            VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_FLUSH | (1 << 28)
        );
        let mut c = [0; 8];
        d.read_config(0, &mut c);
        assert_eq!(u64::from_le_bytes(c), SECTORS);
        let mut c = [0; 4];
        d.read_config(12, &mut c);
        assert_eq!(u32::from_le_bytes(c), SEG_MAX);
        d.read_config(20, &mut c);
        assert_eq!(u32::from_le_bytes(c), 512);
        let (mut d, _t) = disk("cfg-ro", true);
        assert_ne!(d.device_features() & VIRTIO_BLK_F_RO, 0);
    }

    #[test]
    fn read_write_roundtrip() {
        let (mut d, t) = disk("rw", false);
        let (s, len, data) = submit(&mut d, VIRTIO_BLK_T_IN, 3, &[], 1024);
        assert_eq!((s, len), (VIRTIO_BLK_S_OK, 1025));
        let mut buf = vec![0; 1024];
        d.mem.read(data, &mut buf).unwrap();
        assert!(buf[..512].iter().all(|&b| b == 3) && buf[512..].iter().all(|&b| b == 4));
        assert_eq!(d.ack(), INT_USED);

        let payload = vec![0xab; 1024];
        let (s, len, _) = submit(&mut d, VIRTIO_BLK_T_OUT, 10, &payload, 0);
        assert_eq!((s, len), (VIRTIO_BLK_S_OK, 1));
        let (s, _, data) = submit(&mut d, VIRTIO_BLK_T_IN, 10, &[], 1536);
        assert_eq!(s, VIRTIO_BLK_S_OK);
        let mut buf = vec![0; 1536];
        d.mem.read(data, &mut buf).unwrap();
        assert!(buf[..1024].iter().all(|&b| b == 0xab) && buf[1024..].iter().all(|&b| b == 12));
        let (s, len, _) = submit(&mut d, VIRTIO_BLK_T_FLUSH, 0, &[], 0);
        assert_eq!((s, len), (VIRTIO_BLK_S_OK, 1));
        // The file itself changed.
        let mut f = File::open(&t.0).unwrap();
        let mut all = Vec::new();
        f.read_to_end(&mut all).unwrap();
        assert!(all[10 * 512..12 * 512].iter().all(|&b| b == 0xab));
    }

    #[test]
    fn scattered_header_and_data() {
        // Header split across two descriptors, data across three, via an
        // indirect table.
        let (mut d, _t) = disk("sg", false);
        let hdr = d.alloc(16);
        d.mem.write_u32(hdr, VIRTIO_BLK_T_IN).unwrap();
        d.mem.write_u64(hdr + 8, 5).unwrap();
        let (a, b, c, st) = (d.alloc(100), d.alloc(400), d.alloc(12), d.alloc(1));
        let table = d.alloc(16 * 6);
        let mem = d.mem.clone();
        let h = d.q(0).add_indirect(
            &mem,
            table,
            &[
                (hdr, 5, false),
                (hdr + 5, 11, false),
                (a, 100, true),
                (b, 400, true),
                (c, 12, true),
                (st, 1, true),
            ],
        );
        d.kick(0);
        assert_eq!(d.pop_used(0), Some((h.into(), 513)));
        let mut s = [9];
        d.mem.read(st, &mut s).unwrap();
        assert_eq!(s[0], VIRTIO_BLK_S_OK);
        let mut v = [0; 12];
        d.mem.read(c, &mut v).unwrap();
        assert_eq!(v, [5; 12]);
    }

    #[test]
    fn errors() {
        let (mut d, _t) = disk("err", false);
        // Past the end, straddling the end, sector overflow.
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_IN, SECTORS, &[], 512).0,
            VIRTIO_BLK_S_IOERR
        );
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_IN, SECTORS - 1, &[], 1024).0,
            VIRTIO_BLK_S_IOERR
        );
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_OUT, u64::MAX, &[0; 512], 0).0,
            VIRTIO_BLK_S_IOERR
        );
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_IN, SECTORS - 1, &[], 512).0,
            VIRTIO_BLK_S_OK
        );
        // Not a multiple of the sector size.
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_IN, 0, &[], 100).0,
            VIRTIO_BLK_S_IOERR
        );
        // Unknown request type.
        let (s, len, _) = submit(&mut d, 0x1234, 0, &[], 0);
        assert_eq!((s, len), (VIRTIO_BLK_S_UNSUPP, 1));
        // Short header.
        let h = d.alloc(8);
        let st = d.alloc(1);
        d.add(0, &[(h, 8, false), (st, 1, true)]);
        d.kick(0);
        assert_eq!(d.pop_used(0).unwrap().1, 1);
        let mut s = [0];
        d.mem.read(st, &mut s).unwrap();
        assert_eq!(s[0], VIRTIO_BLK_S_IOERR);
        // No status byte at all: returned with len 0, device keeps working.
        d.add(0, &[(h, 8, false)]);
        d.kick(0);
        assert_eq!(d.pop_used(0).unwrap().1, 0);
        assert!(!d.needs_reset());
    }

    #[test]
    fn read_only_rejects_writes() {
        let (mut d, t) = disk("ro", true);
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_OUT, 0, &[0x55; 512], 0).0,
            VIRTIO_BLK_S_IOERR
        );
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_IN, 0, &[], 512).0,
            VIRTIO_BLK_S_OK
        );
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_FLUSH, 0, &[], 0).0,
            VIRTIO_BLK_S_OK
        );
        let mut first = [0; 512];
        File::open(&t.0).unwrap().read_exact(&mut first).unwrap();
        assert_eq!(first, [0; 512]);
    }

    #[test]
    fn get_id() {
        let (mut d, _t) = disk("id", false);
        let (s, len, data) = submit(&mut d, VIRTIO_BLK_T_GET_ID, 0, &[], 20);
        assert_eq!((s, len), (VIRTIO_BLK_S_OK, 21));
        let mut id = [0; 20];
        d.mem.read(data, &mut id).unwrap();
        assert_eq!(&id[..11], b"test-serial");
        assert_eq!(&id[11..], [0; 9]);
        // Short buffer gets a truncated id.
        let (s, len, data) = submit(&mut d, VIRTIO_BLK_T_GET_ID, 0, &[], 4);
        assert_eq!((s, len), (VIRTIO_BLK_S_OK, 5));
        let mut id = [0; 4];
        d.mem.read(data, &mut id).unwrap();
        assert_eq!(&id, b"test");
    }

    #[test]
    fn default_serial_and_capacity() {
        let (_t, f) = image("serial");
        let b = Block::new(f, false).unwrap();
        assert_eq!(b.capacity(), SECTORS);
        assert!(b.id.starts_with(b"vemu-"));
        let (_t2, f2) = image("serial2");
        let mut b2 = Block::new(f2, false).unwrap();
        assert_ne!(b.id, b2.id);
        b2.set_serial("a-very-long-serial-number-indeed");
        assert_eq!(&b2.id, b"a-very-long-serial-n");
    }

    #[test]
    fn flush_request_on_a_real_file() {
        let (mut d, _t) = disk("flush", false);
        let (s, len, _) = submit(&mut d, VIRTIO_BLK_T_FLUSH, 0, &[], 0);
        assert_eq!((s, len), (VIRTIO_BLK_S_OK, 1));
    }

    fn reopen(t: &TempFile, write: bool) -> File {
        File::options().read(true).write(write).open(&t.0).unwrap()
    }

    #[test]
    fn image_lock() {
        let (t, f) = image("lock");
        let rw = Block::new(f, false).unwrap();
        // A second writer, or a reader alongside the writer, is refused.
        for ro in [false, true] {
            let e = Block::new(reopen(&t, !ro), ro)
                .err()
                .expect("lock conflict");
            assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
            assert!(e.to_string().contains("in use"), "{e}");
        }
        drop(rw);
        // Released on drop. Readers share the image; a writer is refused.
        let r1 = Block::new(reopen(&t, false), true).unwrap();
        let r2 = Block::new(reopen(&t, false), true).unwrap();
        assert!(Block::new(reopen(&t, true), false).is_err());
        drop((r1, r2));
        Block::new(reopen(&t, true), false).unwrap();
    }

    /// Another process holding the image is refused too.
    #[test]
    fn image_lock_across_processes() {
        let (t, f) = image("lock-proc");
        let _rw = Block::new(f, false).unwrap();
        // Built before fork: the child must not allocate.
        let c = std::ffi::CString::new(t.0.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: fork in a test; the child only calls async-signal-safe
        // functions (open, flock, _exit) before exiting.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: valid NUL-terminated path; the descriptor is ours.
            let code = unsafe {
                let fd = libc::open(c.as_ptr(), libc::O_RDWR);
                if fd < 0 {
                    2
                } else if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0 {
                    1
                } else {
                    0
                }
            };
            // SAFETY: terminate the child without running parent cleanup.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0, "child got the lock");
    }

    /// The device over an overlay: guest writes land in the overlay (with
    /// copy-up of partial blocks), reads mix it with the golden image, and
    /// the golden image is never written.
    #[test]
    fn overlay_backend() {
        let (golden, _f) = image("golden");
        let ov = golden.0.with_extension("vov");
        let _ovt = TempFile(ov.clone());
        vemu_disk::create(&golden.0, &ov, 4096).unwrap();
        let opts = vemu_disk::DiskOptions::default();
        let mut d = Driver::new(Box::new(Block::with_backend(
            vemu_disk::open(&ov, opts).unwrap(),
        )));
        d.start(&[16]);
        assert_eq!(d.device_features() & VIRTIO_BLK_F_RO, 0);
        let mut c = [0; 8];
        d.read_config(0, &mut c);
        assert_eq!(u64::from_le_bytes(c), SECTORS);
        // One sector inside the first 4 KiB block: copy-up.
        let (s, _, _) = submit(&mut d, VIRTIO_BLK_T_OUT, 3, &[0xab; 512], 0);
        assert_eq!(s, VIRTIO_BLK_S_OK);
        let (s, _, data) = submit(&mut d, VIRTIO_BLK_T_IN, 0, &[], 8 * 512);
        assert_eq!(s, VIRTIO_BLK_S_OK);
        let mut buf = vec![0; 8 * 512];
        d.mem.read(data, &mut buf).unwrap();
        for (i, sector) in buf.chunks(512).enumerate() {
            let want = if i == 3 { 0xab } else { i as u8 };
            assert!(sector.iter().all(|&b| b == want), "sector {i}");
        }
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_FLUSH, 0, &[], 0).0,
            VIRTIO_BLK_S_OK
        );
        drop(d);
        let mut all = Vec::new();
        File::open(&golden.0)
            .unwrap()
            .read_to_end(&mut all)
            .unwrap();
        assert!(
            all[3 * 512..4 * 512].iter().all(|&b| b == 3),
            "golden image written"
        );
        // Read-only overlay: RO feature, writes rejected, the data is there.
        let ro = vemu_disk::DiskOptions {
            read_only: true,
            ..opts
        };
        let mut d = Driver::new(Box::new(Block::with_backend(
            vemu_disk::open(&ov, ro).unwrap(),
        )));
        d.start(&[16]);
        assert_ne!(d.device_features() & VIRTIO_BLK_F_RO, 0);
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_OUT, 0, &[0; 512], 0).0,
            VIRTIO_BLK_S_IOERR
        );
        let (_, _, data) = submit(&mut d, VIRTIO_BLK_T_IN, 3, &[], 512);
        let mut buf = vec![0; 512];
        d.mem.read(data, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xab));
    }

    #[test]
    fn malformed_chain_needs_reset() {
        let (mut d, _t) = disk("bad", false);
        let mem = d.mem.clone();
        let q = d.q(0);
        q.write_desc(&mem, 0, 0xdead_0000_0000, 16, 0, 0);
        q.publish(&mem, 0);
        d.kick(0);
        assert!(d.needs_reset());
        assert_eq!(d.pop_used(0), None);
        // Further notifies are ignored, and a reset brings it back.
        d.kick(0);
        d.reset();
        d.queues.clear();
        d.start(&[16]);
        assert_eq!(
            submit(&mut d, VIRTIO_BLK_T_IN, 0, &[], 512).0,
            VIRTIO_BLK_S_OK
        );
    }
}
