//! Decoding of `kvm_run` exits into [`VcpuExit`] and the completion protocol
//! for reads, over a raw `kvm_run` mapping ([`RunPtr`]). Pure code (no
//! system calls), unit-tested on every host against a fake `kvm_run`
//! buffer.
//!
//! KVM finishes an MMIO or port-I/O instruction only at the *next*
//! `KVM_RUN` (api.rst: "the corresponding operations are complete (and guest
//! state is consistent) only after userspace has re-entered the kernel with
//! KVM_RUN"); for a read, userspace first stores the value in `kvm_run`
//! (`mmio.data`, or the PIO data area at `io.data_offset`). [`Pending`]
//! tracks where a vCPU is in that protocol between two `KVM_RUN`s:
//!
//! - `MmioRead` / `Pio { awaiting_in }`: the VMM owes a value
//!   (`complete_mmio_read` / `complete_io_in`); `run()` refuses to continue.
//! - `Pio` with elements left: string I/O (`rep ins`/`outs`, `count > 1`)
//!   is handed to the VMM one element at a time, as separate
//!   `IoIn`/`IoOut` exits, before KVM is re-entered once for the whole
//!   instruction.
//! - `Complete`: the kernel will finish the instruction at the next
//!   `KVM_RUN`; register reads before that see the state *before* the
//!   instruction, so the backend flushes first (`KVM_RUN` with
//!   `immediate_exit = 1`, which completes it without running the guest).
//! - `Exit`: `kvm_run` holds an exit that `run()` has not returned yet (a
//!   flush that ended in a new exit, e.g. the second half of a 16-byte
//!   x86 MMIO access).

use std::ptr::{self, NonNull};
use std::sync::atomic::AtomicU8;

use super::abi::*;
use crate::{SystemEvent, VcpuExit};

/// Where a vCPU is in the exit/completion protocol (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Pending {
    /// Nothing outstanding.
    #[default]
    None,
    /// `MmioRead` was returned; waiting for `complete_mmio_read`.
    MmioRead { len: usize },
    /// A `KVM_EXIT_IO` being handed out element by element.
    Pio(Pio),
    /// An operation the kernel finishes at the next `KVM_RUN`.
    Complete,
    /// `kvm_run` holds an exit not yet returned by `run()`.
    Exit,
}

/// A port-I/O exit in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pio {
    pub out: bool,
    /// Bytes per element (1, 2 or 4).
    pub size: u8,
    pub port: u16,
    pub count: u32,
    /// Offset of element 0 from the start of `kvm_run`.
    pub data_offset: usize,
    /// Next element to hand out.
    pub next: u32,
    /// An `IoIn` for element `next - 1` was returned and is not completed.
    pub awaiting_in: bool,
}

impl Pio {
    fn done(&self) -> bool {
        self.next >= self.count && !self.awaiting_in
    }
}

/// What to do at the start of `run()`, before `KVM_RUN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Before {
    /// Return this exit without entering the kernel (next string-I/O
    /// element); the new state is given.
    Exit(VcpuExit, Pending),
    /// Decode the exit already in `kvm_run` ([`decode`]).
    Decode,
    /// Enter the kernel.
    Run,
}

/// Result of decoding a `kvm_run` exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// Return this exit to the VMM; the new state is given.
    Exit(VcpuExit, Pending),
    /// Nothing for the VMM: enter the guest again.
    Again,
    /// Not an exit the common layer handles: ask the arch hook.
    Arch(u32),
    /// The vCPU cannot continue; a description for the error.
    Fault(String),
}

/// A `kvm_run` mapping, accessed through raw pointers only: the kernel
/// writes it during `KVM_RUN` on the owning thread, and other threads store
/// `immediate_exit` (atomically) to kick the vCPU, so no Rust reference to
/// the whole struct may exist.
pub(crate) struct RunPtr {
    ptr: NonNull<KvmRun>,
    /// Bytes mapped (`KVM_GET_VCPU_MMAP_SIZE`), at least `size_of::<KvmRun>()`.
    size: usize,
}

impl RunPtr {
    /// # Safety
    ///
    /// `ptr` must be 8-byte aligned and valid for reads and writes of `size`
    /// bytes (with `size >= size_of::<KvmRun>()`) for the life of the
    /// `RunPtr`, and only accessed by others as described on [`RunPtr`].
    pub(crate) unsafe fn new(ptr: NonNull<KvmRun>, size: usize) -> RunPtr {
        debug_assert!(size >= std::mem::size_of::<KvmRun>());
        debug_assert!(ptr.as_ptr().is_aligned());
        RunPtr { ptr, size }
    }

    pub(crate) fn as_ptr(&self) -> *mut KvmRun {
        self.ptr.as_ptr()
    }

    /// Bytes mapped.
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// `kvm_run.immediate_exit`, shared with kicking threads.
    pub(crate) fn immediate_exit(&self) -> &AtomicU8 {
        // SAFETY: the field is valid for the life of `self` (RunPtr::new);
        // every userspace access to it goes through this atomic, and the
        // kernel only reads it (READ_ONCE).
        unsafe { AtomicU8::from_ptr(ptr::addr_of_mut!((*self.as_ptr()).immediate_exit)) }
    }

    pub(crate) fn exit_reason(&self) -> u32 {
        // SAFETY: valid for reads (RunPtr::new); the kernel does not write
        // it while userspace runs.
        unsafe { ptr::addr_of!((*self.as_ptr()).exit_reason).read() }
    }

    /// A copy of the exit-specific union.
    pub(crate) fn exit_data(&self) -> KvmRunUnion {
        // SAFETY: as for exit_reason; the union is plain data.
        unsafe { ptr::addr_of!((*self.as_ptr()).u).read() }
    }

    fn set_mmio_data(&self, data: [u8; 8]) {
        // SAFETY: valid for writes (RunPtr::new); only this thread writes
        // the union, and only outside KVM_RUN.
        unsafe { ptr::addr_of_mut!((*self.as_ptr()).u.mmio.data).write(data) }
    }

    /// Bytes `[off, off + len)` of the mapping, which `decode` validated.
    fn read_bytes(&self, off: usize, len: usize) -> u32 {
        assert!(len <= 4 && off + len <= self.size);
        let mut b = [0u8; 4];
        // SAFETY: in bounds (checked); the data area is plain bytes outside
        // the immediate_exit field (data_offset >= size_of::<KvmRun>()).
        unsafe {
            ptr::copy_nonoverlapping(self.as_ptr().cast::<u8>().add(off), b.as_mut_ptr(), len)
        }
        u32::from_le_bytes(b)
    }

    fn write_bytes(&self, off: usize, len: usize, value: u32) {
        assert!(len <= 4 && off + len <= self.size);
        let b = value.to_le_bytes();
        // SAFETY: as for read_bytes.
        unsafe { ptr::copy_nonoverlapping(b.as_ptr(), self.as_ptr().cast::<u8>().add(off), len) }
    }
}

/// Errors for a `run()` that would drop a value the VMM still owes.
pub(crate) fn check_completed(p: Pending) -> Result<(), &'static str> {
    match p {
        Pending::MmioRead { .. } => Err("previous MmioRead was not completed"),
        Pending::Pio(p) if p.awaiting_in => Err("previous IoIn was not completed"),
        _ => Ok(()),
    }
}

/// Start of `run()`, after [`check_completed`] and the kick check.
pub(crate) fn before_run(p: Pending, run: &RunPtr) -> Before {
    match p {
        Pending::Pio(pio) if pio.next < pio.count => {
            let (exit, next) = pio_element(pio, run);
            Before::Exit(exit, Pending::Pio(next))
        }
        Pending::Exit => Before::Decode,
        _ => Before::Run,
    }
}

/// Whether the kernel holds a half-done instruction that a flush
/// (`KVM_RUN` with `immediate_exit`) would finish: guest registers are not
/// consistent until then.
pub(crate) fn needs_flush(p: Pending) -> bool {
    match p {
        Pending::Complete => true,
        Pending::Pio(pio) => pio.done(),
        _ => false,
    }
}

/// Give up on an outstanding exit (the vCPU is being reset): reads complete
/// with zeros, string I/O elements not yet handed out are dropped. Returns
/// the state to flush (the kernel still finishes the instruction at the next
/// `KVM_RUN`, so it must happen *before* new register state is written).
///
/// `Exit` (an exit in `kvm_run` that `run()` has not returned, e.g. the
/// second fragment of a page-crossing x86 MMIO access) is decoded first and
/// abandoned like the state it decodes to: the kernel still holds that
/// instruction (x86 `complete_userspace_io`), so it is not "nothing pending".
pub(crate) fn abandon(p: Pending, run: &RunPtr) -> Pending {
    match p {
        Pending::None => Pending::None,
        Pending::Exit => match decode(run) {
            // `decode` never yields `Exit`, so this recursion ends.
            Decoded::Exit(_, p) => abandon(p, run),
            // Nothing the kernel finishes at the next KVM_RUN.
            Decoded::Again | Decoded::Arch(_) | Decoded::Fault(_) => Pending::None,
        },
        Pending::MmioRead { .. } => {
            run.set_mmio_data([0; 8]);
            Pending::Complete
        }
        Pending::Pio(pio) => {
            if !pio.out {
                // Zero every element not completed (the awaited one and the
                // rest).
                let first = if pio.awaiting_in {
                    pio.next - 1
                } else {
                    pio.next
                };
                for i in first..pio.count {
                    let off = pio.data_offset + i as usize * pio.size as usize;
                    run.write_bytes(off, pio.size as usize, 0);
                }
            }
            Pending::Complete
        }
        Pending::Complete => Pending::Complete,
    }
}

/// `complete_mmio_read`: store the low `len` bytes of `value`.
pub(crate) fn complete_mmio_read(
    p: Pending,
    run: &RunPtr,
    value: u64,
) -> Result<Pending, &'static str> {
    let Pending::MmioRead { len } = p else {
        return Err("no MmioRead pending");
    };
    let mut data = [0u8; 8];
    data[..len].copy_from_slice(&value.to_le_bytes()[..len]);
    run.set_mmio_data(data);
    Ok(Pending::Complete)
}

/// `complete_io_in`: store the low `size` bytes of `value` as the awaited
/// element.
pub(crate) fn complete_io_in(
    p: Pending,
    run: &RunPtr,
    value: u32,
) -> Result<Pending, &'static str> {
    let Pending::Pio(mut pio) = p else {
        return Err("no IoIn pending");
    };
    if !pio.awaiting_in {
        return Err("no IoIn pending");
    }
    let off = pio.data_offset + (pio.next - 1) as usize * pio.size as usize;
    run.write_bytes(off, pio.size as usize, value);
    pio.awaiting_in = false;
    Ok(Pending::Pio(pio))
}

/// The exit for element `pio.next` and the state after it.
fn pio_element(mut pio: Pio, run: &RunPtr) -> (VcpuExit, Pio) {
    let len = pio.size as usize;
    let off = pio.data_offset + pio.next as usize * len;
    pio.next += 1;
    let exit = if pio.out {
        VcpuExit::IoOut {
            port: pio.port,
            len,
            data: run.read_bytes(off, len),
        }
    } else {
        pio.awaiting_in = true;
        VcpuExit::IoIn {
            port: pio.port,
            len,
        }
    };
    (exit, pio)
}

/// Decode the exit `KVM_RUN` just reported (it returned 0).
pub(crate) fn decode(run: &RunPtr) -> Decoded {
    let reason = run.exit_reason();
    let u = run.exit_data();
    // SAFETY (union reads below): every member is plain data, any bit
    // pattern is valid; `reason` says which one KVM filled.
    match reason {
        KVM_EXIT_MMIO => {
            // SAFETY: plain-data union member filled for this exit reason.
            let m = unsafe { u.mmio };
            let len = m.len as usize;
            if !(1..=8).contains(&len) {
                return Decoded::Fault(format!(
                    "KVM_EXIT_MMIO with unsupported length {len} at {:#x}",
                    m.phys_addr
                ));
            }
            if m.is_write != 0 {
                let mut b = [0u8; 8];
                b[..len].copy_from_slice(&m.data[..len]);
                Decoded::Exit(
                    VcpuExit::MmioWrite {
                        addr: m.phys_addr,
                        len,
                        data: u64::from_le_bytes(b),
                    },
                    Pending::Complete,
                )
            } else {
                Decoded::Exit(
                    VcpuExit::MmioRead {
                        addr: m.phys_addr,
                        len,
                    },
                    Pending::MmioRead { len },
                )
            }
        }
        KVM_EXIT_IO => {
            // SAFETY: plain-data union member filled for this exit reason.
            let io = unsafe { u.io };
            match decode_io(io, run.size()) {
                Ok(pio) => {
                    let (exit, next) = pio_element(pio, run);
                    Decoded::Exit(exit, Pending::Pio(next))
                }
                Err(msg) => Decoded::Fault(msg),
            }
        }
        KVM_EXIT_SYSTEM_EVENT => {
            // SAFETY: plain-data union member filled for this exit reason.
            let e = unsafe { u.system_event };
            match e.type_ {
                KVM_SYSTEM_EVENT_SHUTDOWN => {
                    Decoded::Exit(VcpuExit::SystemEvent(SystemEvent::Shutdown), Pending::None)
                }
                KVM_SYSTEM_EVENT_RESET => {
                    Decoded::Exit(VcpuExit::SystemEvent(SystemEvent::Reset), Pending::None)
                }
                // Only reported for a vCPU suspended with
                // KVM_CAP_ARM_SYSTEM_SUSPEND; KVM_RUN again keeps waiting.
                KVM_SYSTEM_EVENT_WAKEUP => Decoded::Again,
                t => Decoded::Fault(format!(
                    "guest system event {} (type {t}, data {:x?})",
                    system_event_name(t),
                    &e.data[..(e.ndata as usize).min(16)]
                )),
            }
        }
        // x86 triple fault (or an INIT the VMM must emulate): the machine
        // resets.
        KVM_EXIT_SHUTDOWN => {
            Decoded::Exit(VcpuExit::SystemEvent(SystemEvent::Reset), Pending::None)
        }
        // Normally reported with KVM_RUN failing with EINTR; harmless.
        KVM_EXIT_INTR => Decoded::Again,
        KVM_EXIT_INTERNAL_ERROR => {
            // SAFETY: plain-data union member filled for this exit reason.
            let i = unsafe { u.internal };
            Decoded::Fault(format!(
                "KVM internal error: {} (suberror {}), data {:x?}",
                internal_error_name(i.suberror),
                i.suberror,
                &i.data[..(i.ndata as usize).min(16)]
            ))
        }
        KVM_EXIT_FAIL_ENTRY => {
            // SAFETY: plain-data union member filled for this exit reason.
            let f = unsafe { u.fail_entry };
            Decoded::Fault(format!(
                "KVM could not enter the guest (KVM_EXIT_FAIL_ENTRY): hardware entry failure reason {:#x} on host CPU {}",
                f.hardware_entry_failure_reason, f.cpu
            ))
        }
        KVM_EXIT_UNKNOWN => {
            // SAFETY: plain-data union member filled for this exit reason.
            let h = unsafe { u.hw };
            Decoded::Fault(format!(
                "unknown exit (KVM_EXIT_UNKNOWN): hardware exit reason {:#x}",
                h.hardware_exit_reason
            ))
        }
        KVM_EXIT_EXCEPTION => {
            // SAFETY: plain-data union member filled for this exit reason.
            let e = unsafe { u.ex };
            Decoded::Fault(format!(
                "guest exception {} (error code {:#x})",
                e.exception, e.error_code
            ))
        }
        r => Decoded::Arch(r),
    }
}

/// Validate a `KVM_EXIT_IO` against the mapping size.
fn decode_io(io: KvmRunIo, mapped: usize) -> Result<Pio, String> {
    let out = match io.direction {
        KVM_EXIT_IO_IN => false,
        KVM_EXIT_IO_OUT => true,
        d => return Err(format!("KVM_EXIT_IO with direction {d}")),
    };
    if !matches!(io.size, 1 | 2 | 4) {
        return Err(format!(
            "KVM_EXIT_IO of {} bytes at port {:#x}",
            io.size, io.port
        ));
    }
    let bytes = u64::from(io.count) * u64::from(io.size);
    let end = io.data_offset.checked_add(bytes);
    if io.count == 0
        || io.data_offset < std::mem::size_of::<KvmRun>() as u64
        || end.is_none_or(|e| e > mapped as u64)
    {
        return Err(format!(
            "KVM_EXIT_IO data outside the kvm_run mapping (port {:#x}, {} x {} bytes at offset {:#x}, {mapped:#x} mapped)",
            io.port, io.count, io.size, io.data_offset
        ));
    }
    Ok(Pio {
        out,
        size: io.size,
        port: io.port,
        count: io.count,
        data_offset: io.data_offset as usize,
        next: 0,
        awaiting_in: false,
    })
}

fn system_event_name(t: u32) -> &'static str {
    match t {
        KVM_SYSTEM_EVENT_SHUTDOWN => "SHUTDOWN",
        KVM_SYSTEM_EVENT_RESET => "RESET",
        KVM_SYSTEM_EVENT_CRASH => "CRASH",
        KVM_SYSTEM_EVENT_WAKEUP => "WAKEUP",
        KVM_SYSTEM_EVENT_SUSPEND => "SUSPEND",
        KVM_SYSTEM_EVENT_SEV_TERM => "SEV_TERM",
        KVM_SYSTEM_EVENT_TDX_FATAL => "TDX_FATAL",
        _ => "unknown",
    }
}

fn internal_error_name(s: u32) -> &'static str {
    match s {
        KVM_INTERNAL_ERROR_EMULATION => "instruction emulation failed",
        KVM_INTERNAL_ERROR_SIMUL_EX => "simultaneous exceptions",
        KVM_INTERNAL_ERROR_DELIVERY_EV => "exit during event delivery",
        KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON => "unexpected hardware exit reason",
        _ => "unknown suberror",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    /// A fake vCPU mapping: kvm_run plus a PIO data page at 4096, as on x86.
    struct Fake {
        buf: Box<[u64]>,
    }

    const MAPPED: usize = 3 * 4096;
    const PIO_OFF: usize = 4096;

    impl Fake {
        fn new() -> Fake {
            Fake {
                buf: vec![0u64; MAPPED / 8].into_boxed_slice(),
            }
        }
        fn run(&mut self) -> RunPtr {
            let p = NonNull::new(self.buf.as_mut_ptr().cast::<KvmRun>()).unwrap();
            // SAFETY: the buffer is 8-aligned, MAPPED bytes, outlives the
            // RunPtr in each test.
            unsafe { RunPtr::new(p, MAPPED) }
        }
        fn bytes(&mut self) -> &mut [u8] {
            // SAFETY: plain u64 storage viewed as bytes.
            unsafe { std::slice::from_raw_parts_mut(self.buf.as_mut_ptr().cast::<u8>(), MAPPED) }
        }
        fn put(&mut self, off: usize, b: &[u8]) {
            self.bytes()[off..off + b.len()].copy_from_slice(b);
        }
        fn set_reason(&mut self, r: u32) {
            self.put(offset_of!(KvmRun, exit_reason), &r.to_ne_bytes());
        }
        fn set_union<T: Copy>(&mut self, v: T) {
            let off = offset_of!(KvmRun, u);
            // SAFETY: T is a plain #[repr(C)] union member.
            let b = unsafe {
                std::slice::from_raw_parts((&v as *const T).cast::<u8>(), size_of::<T>())
            };
            self.put(off, b);
        }
        fn mmio_data(&mut self) -> [u8; 8] {
            let off = offset_of!(KvmRun, u) + offset_of!(KvmRunMmio, data);
            self.bytes()[off..off + 8].try_into().unwrap()
        }
    }

    fn mmio(f: &mut Fake, addr: u64, len: u32, write: Option<u64>) {
        f.set_reason(KVM_EXIT_MMIO);
        f.set_union(KvmRunMmio {
            phys_addr: addr,
            data: write.unwrap_or(0xeeee_eeee_eeee_eeee).to_le_bytes(),
            len,
            is_write: write.is_some() as u8,
        });
    }

    fn io(f: &mut Fake, out: bool, size: u8, port: u16, count: u32, data_offset: u64) {
        f.set_reason(KVM_EXIT_IO);
        f.set_union(KvmRunIo {
            direction: if out { KVM_EXIT_IO_OUT } else { KVM_EXIT_IO_IN },
            size,
            port,
            count,
            data_offset,
        });
    }

    #[test]
    fn mmio_write() {
        let mut f = Fake::new();
        mmio(&mut f, 0x0900_0000, 4, Some(0xffff_ffff_1234_5678));
        let d = decode(&f.run());
        assert_eq!(
            d,
            Decoded::Exit(
                VcpuExit::MmioWrite {
                    addr: 0x0900_0000,
                    len: 4,
                    data: 0x1234_5678
                },
                Pending::Complete
            )
        );
        assert!(needs_flush(Pending::Complete));
        assert_eq!(check_completed(Pending::Complete), Ok(()));
        assert_eq!(before_run(Pending::Complete, &f.run()), Before::Run);
    }

    #[test]
    fn mmio_read_completion() {
        let mut f = Fake::new();
        mmio(&mut f, 0x1000, 2, None);
        let Decoded::Exit(exit, p) = decode(&f.run()) else {
            panic!()
        };
        assert_eq!(
            exit,
            VcpuExit::MmioRead {
                addr: 0x1000,
                len: 2
            }
        );
        assert_eq!(p, Pending::MmioRead { len: 2 });
        assert!(check_completed(p).is_err());
        assert!(!needs_flush(p));
        assert!(complete_io_in(p, &f.run(), 1).is_err());
        let p = complete_mmio_read(p, &f.run(), 0xaaaa_bbcc).unwrap();
        assert_eq!(p, Pending::Complete);
        // Only the access size is stored, little-endian, rest zero.
        assert_eq!(f.mmio_data(), [0xcc, 0xbb, 0, 0, 0, 0, 0, 0]);
        assert!(complete_mmio_read(p, &f.run(), 0).is_err());
    }

    #[test]
    fn mmio_bad_len() {
        let mut f = Fake::new();
        mmio(&mut f, 0x1000, 0, None);
        assert!(matches!(decode(&f.run()), Decoded::Fault(_)));
        mmio(&mut f, 0x1000, 16, None);
        assert!(matches!(decode(&f.run()), Decoded::Fault(_)));
        // Odd fragment sizes from x86 emulation are passed through.
        mmio(&mut f, 0x1000, 6, Some(0x0000_6655_4433_2211));
        assert!(matches!(
            decode(&f.run()),
            Decoded::Exit(
                VcpuExit::MmioWrite {
                    len: 6,
                    data: 0x6655_4433_2211,
                    ..
                },
                _
            )
        ));
    }

    #[test]
    fn pio_out_single() {
        let mut f = Fake::new();
        io(&mut f, true, 1, 0x3f8, 1, PIO_OFF as u64);
        f.put(PIO_OFF, &[b'A', 0xff, 0xff, 0xff]);
        let Decoded::Exit(exit, p) = decode(&f.run()) else {
            panic!()
        };
        assert_eq!(
            exit,
            VcpuExit::IoOut {
                port: 0x3f8,
                len: 1,
                data: 0x41
            }
        );
        assert_eq!(check_completed(p), Ok(()));
        assert!(needs_flush(p));
        assert_eq!(before_run(p, &f.run()), Before::Run);
    }

    #[test]
    fn pio_in_single() {
        let mut f = Fake::new();
        io(&mut f, false, 2, 0x71, 1, PIO_OFF as u64);
        f.put(PIO_OFF, &[0xee; 4]);
        let Decoded::Exit(exit, p) = decode(&f.run()) else {
            panic!()
        };
        assert_eq!(exit, VcpuExit::IoIn { port: 0x71, len: 2 });
        assert!(check_completed(p).is_err());
        assert!(!needs_flush(p));
        assert!(complete_mmio_read(p, &f.run(), 0).is_err());
        let p = complete_io_in(p, &f.run(), 0x1234_5678).unwrap();
        assert_eq!(f.bytes()[PIO_OFF..PIO_OFF + 4], [0x78, 0x56, 0xee, 0xee]);
        assert!(complete_io_in(p, &f.run(), 0).is_err());
        assert_eq!(check_completed(p), Ok(()));
        assert!(needs_flush(p));
        assert_eq!(before_run(p, &f.run()), Before::Run);
    }

    #[test]
    fn pio_string_out() {
        let mut f = Fake::new();
        io(&mut f, true, 2, 0x1f0, 3, PIO_OFF as u64);
        f.put(PIO_OFF, &[1, 0, 2, 0, 3, 0]);
        let Decoded::Exit(exit, mut p) = decode(&f.run()) else {
            panic!()
        };
        assert_eq!(
            exit,
            VcpuExit::IoOut {
                port: 0x1f0,
                len: 2,
                data: 1
            }
        );
        let mut seen = vec![];
        loop {
            assert_eq!(check_completed(p), Ok(()));
            match before_run(p, &f.run()) {
                Before::Exit(e, n) => {
                    assert!(!needs_flush(p));
                    seen.push(e);
                    p = n;
                }
                Before::Run => break,
                Before::Decode => panic!(),
            }
        }
        assert_eq!(
            seen,
            [
                VcpuExit::IoOut {
                    port: 0x1f0,
                    len: 2,
                    data: 2
                },
                VcpuExit::IoOut {
                    port: 0x1f0,
                    len: 2,
                    data: 3
                }
            ]
        );
        assert!(needs_flush(p));
    }

    #[test]
    fn pio_string_in() {
        let mut f = Fake::new();
        io(&mut f, false, 1, 0x60, 3, PIO_OFF as u64);
        let Decoded::Exit(exit, mut p) = decode(&f.run()) else {
            panic!()
        };
        assert_eq!(exit, VcpuExit::IoIn { port: 0x60, len: 1 });
        p = complete_io_in(p, &f.run(), 0x10).unwrap();
        for v in [0x11, 0x12] {
            let Before::Exit(e, n) = before_run(p, &f.run()) else {
                panic!()
            };
            assert_eq!(e, VcpuExit::IoIn { port: 0x60, len: 1 });
            // Not completed yet: run() must refuse.
            assert!(check_completed(n).is_err());
            p = complete_io_in(n, &f.run(), v).unwrap();
        }
        assert_eq!(before_run(p, &f.run()), Before::Run);
        assert_eq!(f.bytes()[PIO_OFF..PIO_OFF + 4], [0x10, 0x11, 0x12, 0]);
    }

    #[test]
    fn pio_rejects_bad_exits() {
        let mut f = Fake::new();
        for (size, count, off) in [
            (3u8, 1u32, PIO_OFF as u64),
            (1, 0, PIO_OFF as u64),
            (4, 2, (MAPPED - 4) as u64),
            (1, 1, 0),
            (4, u32::MAX, PIO_OFF as u64),
            (1, 1, u64::MAX),
        ] {
            io(&mut f, true, size, 0x80, count, off);
            assert!(
                matches!(decode(&f.run()), Decoded::Fault(_)),
                "{size} {count} {off}"
            );
        }
        f.set_union(KvmRunIo {
            direction: 7,
            size: 1,
            port: 0x80,
            count: 1,
            data_offset: PIO_OFF as u64,
        });
        assert!(matches!(decode(&f.run()), Decoded::Fault(_)));
        // The last element may end exactly at the end of the mapping.
        io(&mut f, true, 4, 0x80, 2, (MAPPED - 8) as u64);
        assert!(matches!(decode(&f.run()), Decoded::Exit(..)));
    }

    #[test]
    fn abandon_zeroes_reads() {
        let mut f = Fake::new();
        mmio(&mut f, 0x1000, 8, None);
        f.put(
            offset_of!(KvmRun, u) + offset_of!(KvmRunMmio, data),
            &[0xff; 8],
        );
        let p = abandon(Pending::MmioRead { len: 8 }, &f.run());
        assert_eq!(p, Pending::Complete);
        assert_eq!(f.mmio_data(), [0; 8]);

        io(&mut f, false, 1, 0x60, 3, PIO_OFF as u64);
        f.put(PIO_OFF, &[0xff; 3]);
        let Decoded::Exit(_, p) = decode(&f.run()) else {
            panic!()
        };
        let p = complete_io_in(p, &f.run(), 0x42).unwrap();
        let Before::Exit(_, p) = before_run(p, &f.run()) else {
            panic!()
        };
        assert_eq!(abandon(p, &f.run()), Pending::Complete);
        assert_eq!(f.bytes()[PIO_OFF..PIO_OFF + 3], [0x42, 0, 0]);

        assert_eq!(abandon(Pending::None, &f.run()), Pending::None);
    }

    /// An exit not yet returned by run() (a flush produced it) is abandoned
    /// like the state it decodes to, not dropped: the kernel still holds the
    /// instruction and would finish it on top of a new boot state.
    #[test]
    fn abandon_decodes_an_unreturned_exit() {
        let mut f = Fake::new();
        // Second fragment of a split MMIO read: zeroed, then flushed.
        mmio(&mut f, 0x2_1000, 2, None);
        f.put(
            offset_of!(KvmRun, u) + offset_of!(KvmRunMmio, data),
            &[0xff; 8],
        );
        assert_eq!(abandon(Pending::Exit, &f.run()), Pending::Complete);
        assert_eq!(f.mmio_data(), [0; 8]);
        // An MMIO write: the kernel still finishes it.
        mmio(&mut f, 0x2_1000, 4, Some(0x1234));
        assert_eq!(abandon(Pending::Exit, &f.run()), Pending::Complete);
        // A port read (string I/O too): every element zeroed.
        io(&mut f, false, 1, 0x60, 3, PIO_OFF as u64);
        f.put(PIO_OFF, &[0xff; 3]);
        assert_eq!(abandon(Pending::Exit, &f.run()), Pending::Complete);
        assert_eq!(f.bytes()[PIO_OFF..PIO_OFF + 3], [0, 0, 0]);
        // Exits that leave nothing in the kernel.
        f.set_reason(KVM_EXIT_SHUTDOWN);
        assert_eq!(abandon(Pending::Exit, &f.run()), Pending::None);
        f.set_reason(KVM_EXIT_INTR);
        assert_eq!(abandon(Pending::Exit, &f.run()), Pending::None);
        f.set_reason(KVM_EXIT_HLT);
        assert_eq!(abandon(Pending::Exit, &f.run()), Pending::None);
    }

    #[test]
    fn system_events() {
        let mut f = Fake::new();
        let mut ev = |t: u32| {
            f.set_reason(KVM_EXIT_SYSTEM_EVENT);
            f.set_union(KvmRunSystemEvent {
                type_: t,
                ndata: 1,
                data: [0; 16],
            });
            decode(&f.run())
        };
        assert_eq!(
            ev(KVM_SYSTEM_EVENT_SHUTDOWN),
            Decoded::Exit(VcpuExit::SystemEvent(SystemEvent::Shutdown), Pending::None)
        );
        assert_eq!(
            ev(KVM_SYSTEM_EVENT_RESET),
            Decoded::Exit(VcpuExit::SystemEvent(SystemEvent::Reset), Pending::None)
        );
        assert_eq!(ev(KVM_SYSTEM_EVENT_WAKEUP), Decoded::Again);
        let Decoded::Fault(m) = ev(KVM_SYSTEM_EVENT_CRASH) else {
            panic!()
        };
        assert!(m.contains("CRASH"), "{m}");
        assert!(matches!(ev(99), Decoded::Fault(_)));
    }

    #[test]
    fn other_exits() {
        let mut f = Fake::new();
        f.set_reason(KVM_EXIT_SHUTDOWN);
        assert_eq!(
            decode(&f.run()),
            Decoded::Exit(VcpuExit::SystemEvent(SystemEvent::Reset), Pending::None)
        );
        f.set_reason(KVM_EXIT_INTR);
        assert_eq!(decode(&f.run()), Decoded::Again);
        f.set_reason(KVM_EXIT_INTERNAL_ERROR);
        f.set_union(KvmRunInternal {
            suberror: KVM_INTERNAL_ERROR_EMULATION,
            ndata: 2,
            data: [0xab, 0xcd, 0xee, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });
        let Decoded::Fault(m) = decode(&f.run()) else {
            panic!()
        };
        assert!(
            m.contains("emulation failed") && m.contains("[ab, cd]"),
            "{m}"
        );
        f.set_reason(KVM_EXIT_FAIL_ENTRY);
        f.set_union(KvmRunFailEntry {
            hardware_entry_failure_reason: 0x21,
            cpu: 3,
        });
        let Decoded::Fault(m) = decode(&f.run()) else {
            panic!()
        };
        assert!(m.contains("0x21") && m.contains("CPU 3"), "{m}");
        f.set_reason(KVM_EXIT_UNKNOWN);
        assert!(matches!(decode(&f.run()), Decoded::Fault(_)));
        f.set_reason(KVM_EXIT_DEBUG);
        assert_eq!(decode(&f.run()), Decoded::Arch(KVM_EXIT_DEBUG));
        f.set_reason(KVM_EXIT_HLT);
        assert_eq!(decode(&f.run()), Decoded::Arch(KVM_EXIT_HLT));
        assert_eq!(before_run(Pending::Exit, &f.run()), Before::Decode);
    }

    #[test]
    fn immediate_exit_is_the_right_byte() {
        let mut f = Fake::new();
        f.run()
            .immediate_exit()
            .store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(f.bytes()[offset_of!(KvmRun, immediate_exit)], 1);
        assert_eq!(f.bytes().iter().map(|&b| b as usize).sum::<usize>(), 1);
    }
}
