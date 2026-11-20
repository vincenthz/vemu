//! virtio 1.x devices for vemu.
//!
//! - [`queue`]: split virtqueues (virtio 1.2 §2.7), including indirect
//!   descriptors, hardened against malicious or buggy drivers.
//! - [`MmioTransport`]: the virtio-mmio transport, version 2 (non-legacy,
//!   virtio 1.2 §4.2), implementing [`vemu_core::MmioDevice`].
//! - [`console`], [`block`], [`net`]: the devices.
//!
//! # Threading and locking
//!
//! The MMIO bus holds each [`MmioTransport`] behind a `Mutex` and calls it from
//! vCPU threads, so register accesses, `QueueNotify` and therefore
//! [`VirtioDevice::queue_notify`] run with that lock held. Some requests are
//! completed from other threads (console input, net receive), so the
//! device-side state those threads touch lives behind the device's own
//! `Arc<Mutex<..>>`. Interrupt state lives in [`Interrupt`], which has its own
//! small lock. The only lock order is
//!
//! ```text
//! transport (bus) lock  ->  device lock  ->  Interrupt lock  ->  IrqLine::set_level
//! ```
//!
//! and no thread ever takes them in another order, so there is no deadlock.
//! Interrupt status bits and the line level are updated together under the
//! `Interrupt` lock, so a used-buffer notification racing with the driver's
//! `InterruptACK` is never lost.
//!
//! # Guest errors
//!
//! Nothing a driver writes into rings or registers can panic the VMM. A
//! malformed descriptor chain (bad index, loop, out-of-RAM buffer, ...) breaks
//! the queue: the device stops using it and sets `DEVICE_NEEDS_RESET` (with a
//! configuration-change interrupt). A well-formed chain carrying a
//! semantically bad request is completed with an error status or dropped.

mod interrupt;
mod mmio;
pub mod queue;

pub mod block;
pub mod console;
pub mod net;

#[cfg(test)]
mod testutil;

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use vemu_core::GuestMemory;

pub use interrupt::{INT_CONFIG, INT_USED, Interrupt};
pub use mmio::{MMIO_SIZE, MmioTransport, VENDOR_ID, status};
pub use queue::{DescChain, Queue, QueueError, Segment};

/// virtio device IDs (virtio 1.2 §5).
pub mod device_id {
    pub const NET: u32 = 1;
    pub const BLOCK: u32 = 2;
    pub const CONSOLE: u32 = 3;
}

/// Device-independent feature bits (virtio 1.2 §6).
pub mod features {
    /// Descriptors may point to indirect descriptor tables.
    pub const RING_INDIRECT_DESC: u64 = 1 << 28;
    /// `used_event` / `avail_event` notification suppression (not offered).
    pub const RING_EVENT_IDX: u64 = 1 << 29;
    /// virtio 1.x (non-legacy) device. Required by this implementation.
    pub const VERSION_1: u64 = 1 << 32;
}

/// A virtio device model, independent of the transport.
pub trait VirtioDevice: Send {
    /// virtio device ID (see [`device_id`]).
    fn device_type(&self) -> u32;
    /// Device-specific feature bits. The transport adds
    /// [`features::VERSION_1`] and [`features::RING_INDIRECT_DESC`].
    fn device_features(&self) -> u64;
    fn num_queues(&self) -> usize;
    /// Largest queue size the driver may pick (a power of two).
    fn queue_max_size(&self) -> u16 {
        256
    }
    /// Read device configuration space at `offset` (relative to its start).
    /// Bytes past the end of the configuration structure read as zero.
    fn read_config(&self, offset: u64, data: &mut [u8]);
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    /// Driver set DRIVER_OK. `ctx.queues[i]` holds queue `i` if the driver
    /// enabled it; `ctx.interrupt` signals used-buffer / config-change.
    fn activate(&mut self, ctx: ActivateContext) -> Result<(), ActivateError>;
    /// Driver wrote `QueueNotify` for queue `index` (only delivered after a
    /// successful activation, and only for enabled queues).
    fn queue_notify(&mut self, index: u16);
    /// Driver reset the device (status = 0). Drop rings and stop every use of
    /// them (including from other threads) before returning.
    fn reset(&mut self);
}

/// What a device gets when the driver sets DRIVER_OK.
pub struct ActivateContext {
    pub mem: Arc<GuestMemory>,
    /// One entry per queue the device has; `None` for queues the driver did
    /// not enable.
    pub queues: Vec<Option<Queue>>,
    pub interrupt: Arc<Interrupt>,
    /// Features the driver accepted (device-specific and transport bits).
    pub features: u64,
}

impl ActivateContext {
    /// Take queue `index`, failing if the driver did not enable it.
    pub fn take_queue(&mut self, index: usize) -> Result<Queue, ActivateError> {
        self.queues
            .get_mut(index)
            .and_then(Option::take)
            .ok_or_else(|| ActivateError::new(format!("queue {index} not enabled by the driver")))
    }
}

/// The device cannot start with what the driver configured. The transport
/// reports it to the driver as `DEVICE_NEEDS_RESET`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateError {
    msg: String,
}

impl ActivateError {
    pub fn new(msg: impl Into<String>) -> ActivateError {
        ActivateError { msg: msg.into() }
    }
}

impl fmt::Display for ActivateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for ActivateError {}

/// Print a warning on stderr the first time this call site is reached.
///
/// Guest-triggered conditions use this so a misbehaving guest cannot flood
/// the host terminal.
macro_rules! warn_once {
    ($($arg:tt)*) => {{
        static ONCE: ::std::sync::atomic::AtomicBool = ::std::sync::atomic::AtomicBool::new(false);
        if !ONCE.swap(true, ::std::sync::atomic::Ordering::Relaxed) {
            // Not eprintln!: it panics when stderr is a closed pipe, and the
            // guest decides when this runs.
            let _ = ::std::io::Write::write_fmt(
                &mut ::std::io::stderr(),
                format_args!("vemu-virtio: {}\n", format_args!($($arg)*)),
            );
        }
    }};
}
pub(crate) use warn_once;

/// Lock `m`, ignoring poisoning: device state stays usable (and the VMM keeps
/// running) even if another thread panicked while holding the lock.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Copy the part of configuration structure `cfg` that `[offset, offset+len)`
/// overlaps into `data`; bytes outside `cfg` read as zero.
pub(crate) fn read_config_bytes(cfg: &[u8], offset: u64, data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b = usize::try_from(offset)
            .ok()
            .and_then(|o| o.checked_add(i))
            .and_then(|o| cfg.get(o))
            .copied()
            .unwrap_or(0);
    }
}

/// A queue hit a malformed chain: log it and ask the driver for a reset. The
/// caller then drops the queue.
pub(crate) fn queue_broken(device: &str, queue: &str, err: &QueueError, interrupt: &Interrupt) {
    warn_once!("{device}: {queue} queue broken by the driver ({err}); device needs reset");
    interrupt.set_needs_reset();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Driver, MEM_BASE};
    use vemu_core::{MmioDevice, NetBackend, NetFrontend};

    struct NullBackend(Mutex<Option<Arc<dyn NetFrontend>>>);

    impl NetBackend for NullBackend {
        fn attach(&self, frontend: Arc<dyn NetFrontend>) {
            *self.0.lock().unwrap() = Some(frontend);
        }
        fn transmit(&self, _frame: &[u8]) {}
        fn rx_ready(&self) {}
    }

    /// Random register accesses, ring garbage and host-side input against
    /// every device: the VMM must never panic.
    #[test]
    fn fuzz_devices_never_panic() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let path =
            std::env::temp_dir().join(format!("vemu-virtio-fuzz-{}.img", std::process::id()));
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(64 * 1024).unwrap();

        let (console, input) = console::Console::new(Box::new(std::io::sink()));
        let backend = Arc::new(NullBackend(Mutex::new(None)));
        let devices: Vec<Box<dyn VirtioDevice>> = vec![
            Box::new(console),
            Box::new(block::Block::new(file, false).unwrap()),
            Box::new(net::Net::new([2, 0, 0, 0, 0, 1], backend.clone())),
        ];
        for dev in devices {
            let n = dev.num_queues();
            let mut d = Driver::new(dev);
            d.start(&vec![16; n]);
            let buf = d.alloc(0x1000);
            for i in 0..20_000 {
                if i % 500 == 0 {
                    d.restart();
                }
                match rnd() % 10 {
                    0 | 1 => {
                        // Garbage into the rings (allocated first, at MEM_BASE).
                        let gpa = (MEM_BASE + rnd() % 0x800) & !7;
                        let v = rnd();
                        let _ = d.mem.write_u16(gpa, v as u16);
                        let addr = if v & 1 == 0 { buf + v % 0x1000 } else { v };
                        let _ = d.mem.write_u64(gpa, addr);
                    }
                    2 => {
                        // A well-formed chain with random contents.
                        let q = (rnd() as usize) % n;
                        let _ = d.mem.write_u64(buf, rnd() % 16);
                        let split = (rnd() % 0x800) as u32;
                        d.add(
                            q,
                            &[
                                (buf, split, false),
                                (buf + 0x800, (rnd() % 0x800) as u32, true),
                            ],
                        );
                    }
                    3 | 4 => d.kick((rnd() % 3) as u16),
                    5 => {
                        let off = rnd() % 0x200;
                        let len = [1, 2, 4, 8][(rnd() % 4) as usize];
                        let val = rnd().to_le_bytes();
                        d.t.write(off, &val[..len]);
                    }
                    6 => {
                        let mut b = [0; 8];
                        let len = [1, 2, 4, 8][(rnd() % 4) as usize];
                        d.t.read(rnd() % 0x200, &mut b[..len]);
                    }
                    7 => {
                        input.push(&rnd().to_le_bytes());
                        if let Some(f) = backend.0.lock().unwrap().clone() {
                            f.deliver(&[0; 60]);
                        }
                    }
                    _ => {
                        d.ack();
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_bytes_window() {
        let cfg = [1u8, 2, 3, 4];
        let mut d = [0xff; 4];
        read_config_bytes(&cfg, 2, &mut d);
        assert_eq!(d, [3, 4, 0, 0]);
        read_config_bytes(&cfg, u64::MAX, &mut d);
        assert_eq!(d, [0; 4]);
    }
}
