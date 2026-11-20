//! virtio-net (virtio 1.2 §5.1): one receive queue (0) and one transmit queue
//! (1), `VIRTIO_NET_F_MAC` and `VIRTIO_NET_F_STATUS` (link always up), no
//! offloads and no mergeable receive buffers. Every buffer starts with a
//! 12-byte `virtio_net_hdr_v1`.
//!
//! Transmit runs on the notifying vCPU thread: the header is stripped and the
//! frame handed to [`NetBackend::transmit`]. Receive runs on the backend's
//! thread through [`NetFrontend::deliver`]; the receive queue therefore lives
//! behind its own lock, shared by the device and the frontend. Per the
//! `NetBackend` locking rule, `transmit` and `rx_ready` are only ever called
//! without that lock held.

use std::sync::{Arc, Mutex};

use vemu_core::{NetBackend, NetFrontend};

use crate::interrupt::Interrupt;
use crate::queue::Queue;
use crate::{
    ActivateContext, ActivateError, VirtioDevice, device_id, lock, queue_broken, read_config_bytes,
    warn_once,
};

/// `mac` config field is valid.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// `status` config field is valid.
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
/// `status` bit: link is up.
pub const VIRTIO_NET_S_LINK_UP: u16 = 1;

/// Size of `struct virtio_net_hdr_v1` (with `num_buffers`).
pub const NET_HDR_LEN: usize = 12;
/// Largest frame accepted from the guest (without the virtio-net header).
pub const MAX_FRAME_LEN: usize = 65535;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

/// virtio-net device.
pub struct Net {
    mac: [u8; 6],
    backend: Arc<dyn NetBackend>,
    rx: Arc<RxShared>,
    tx: Option<TxState>,
    frame: Vec<u8>,
}

struct TxState {
    queue: Queue,
    interrupt: Arc<Interrupt>,
}

/// Receive side; this is what the backend sees as its [`NetFrontend`].
struct RxShared {
    state: Mutex<Option<RxState>>,
}

struct RxState {
    queue: Queue,
    interrupt: Arc<Interrupt>,
}

impl Net {
    /// A NIC with address `mac`, attached to `backend` (registers itself as
    /// the backend's frontend).
    pub fn new(mac: [u8; 6], backend: Arc<dyn NetBackend>) -> Net {
        let rx = Arc::new(RxShared {
            state: Mutex::new(None),
        });
        backend.attach(rx.clone());
        Net {
            mac,
            backend,
            rx,
            tx: None,
            frame: Vec::new(),
        }
    }

    fn process_tx(&mut self) {
        let Some(tx) = self.tx.as_mut() else { return };
        let (backend, frame) = (&self.backend, &mut self.frame);
        let mem = tx.queue.memory().clone();
        let result = tx.queue.drain(|chain| {
            let len = chain.readable_len();
            if len < NET_HDR_LEN as u64 || len - NET_HDR_LEN as u64 > MAX_FRAME_LEN as u64 {
                warn_once!("net: dropping transmit buffer of {len} bytes");
                return 0;
            }
            frame.resize(len as usize - NET_HDR_LEN, 0);
            // Segments were bounds-checked when the chain was popped.
            if chain.read_at(&mem, NET_HDR_LEN as u64, frame) == Ok(frame.len()) {
                backend.transmit(frame);
            }
            0
        });
        match result {
            Ok(0) => {}
            Ok(_) => {
                if tx.queue.needs_interrupt() {
                    tx.interrupt.signal_used();
                }
            }
            Err(e) => {
                queue_broken("net", "transmit", &e, &tx.interrupt);
                tx.interrupt.signal_used();
                self.tx = None;
            }
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        device_id::NET
    }

    fn device_features(&self) -> u64 {
        VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // struct virtio_net_config { u8 mac[6]; le16 status; ... }
        let mut cfg = [0; 8];
        cfg[..6].copy_from_slice(&self.mac);
        cfg[6..8].copy_from_slice(&VIRTIO_NET_S_LINK_UP.to_le_bytes());
        read_config_bytes(&cfg, offset, data);
    }

    fn activate(&mut self, mut ctx: ActivateContext) -> Result<(), ActivateError> {
        let rxq = ctx.take_queue(RX_QUEUE.into())?;
        let txq = ctx.take_queue(TX_QUEUE.into())?;
        self.tx = Some(TxState {
            queue: txq,
            interrupt: ctx.interrupt.clone(),
        });
        *lock(&self.rx.state) = Some(RxState {
            queue: rxq,
            interrupt: ctx.interrupt,
        });
        // Frames the backend held back can go now (the guest usually posted
        // receive buffers before DRIVER_OK).
        self.backend.rx_ready();
        Ok(())
    }

    fn queue_notify(&mut self, index: u16) {
        match index {
            RX_QUEUE => self.backend.rx_ready(),
            TX_QUEUE => self.process_tx(),
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.tx = None;
        // Under the lock: once this returns, `deliver` cannot touch the rings.
        *lock(&self.rx.state) = None;
    }
}

impl NetFrontend for RxShared {
    fn deliver(&self, frame: &[u8]) -> bool {
        let mut guard = lock(&self.state);
        let Some(rx) = guard.as_mut() else {
            return false;
        };
        let chain = match rx.queue.pop() {
            Ok(Some(chain)) => chain,
            Ok(None) => return false,
            Err(e) => {
                queue_broken("net", "receive", &e, &rx.interrupt);
                *guard = None;
                return false;
            }
        };
        let total = NET_HDR_LEN + frame.len();
        if chain.writable_len() < total as u64 {
            // Without mergeable buffers the frame cannot be split: drop it
            // and keep the buffer for the next one.
            warn_once!(
                "net: receive buffer of {} bytes too small for a {total}-byte frame; dropped",
                chain.writable_len()
            );
            rx.queue.undo_pop();
            return true;
        }
        let mem = rx.queue.memory().clone();
        let mut hdr = [0; NET_HDR_LEN];
        // num_buffers = 1; flags, gso_type and the rest are zero.
        hdr[10..12].copy_from_slice(&1u16.to_le_bytes());
        // Segments were bounds-checked when the chain was popped.
        let ok = chain.write_at(&mem, 0, &hdr).is_ok()
            && chain.write_at(&mem, NET_HDR_LEN as u64, frame).is_ok();
        if !ok {
            rx.queue.undo_pop();
            return true;
        }
        // total <= writable_len, which fits in a u32.
        match rx.queue.add_used(chain.head(), total as u32) {
            Ok(()) => {
                if rx.queue.needs_interrupt() {
                    rx.interrupt.signal_used();
                }
            }
            Err(e) => {
                queue_broken("net", "receive", &e, &rx.interrupt);
                *guard = None;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::INT_USED;
    use crate::testutil::Driver;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeBackend {
        frontend: Mutex<Option<Arc<dyn NetFrontend>>>,
        sent: Mutex<Vec<Vec<u8>>>,
        rx_ready: AtomicUsize,
    }

    impl NetBackend for FakeBackend {
        fn attach(&self, frontend: Arc<dyn NetFrontend>) {
            *self.frontend.lock().unwrap() = Some(frontend);
        }
        fn transmit(&self, frame: &[u8]) {
            self.sent.lock().unwrap().push(frame.to_vec());
        }
        fn rx_ready(&self) {
            self.rx_ready.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl FakeBackend {
        fn deliver(&self, frame: &[u8]) -> bool {
            let f = self.frontend.lock().unwrap().clone().unwrap();
            f.deliver(frame)
        }
    }

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

    fn nic() -> (Driver, Arc<FakeBackend>) {
        let backend = Arc::new(FakeBackend::default());
        let net = Net::new(MAC, backend.clone());
        assert!(backend.frontend.lock().unwrap().is_some());
        let d = Driver::new(Box::new(net));
        (d, backend)
    }

    #[test]
    fn config_and_features() {
        let (mut d, _) = nic();
        assert_eq!(d.read32(0x008), 1);
        assert_eq!(
            d.device_features(),
            VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | (1 << 28) | (1 << 32)
        );
        let mut c = [0; 8];
        d.read_config(0, &mut c);
        assert_eq!(&c[..6], &MAC);
        assert_eq!(u16::from_le_bytes([c[6], c[7]]), VIRTIO_NET_S_LINK_UP);
        let mut b = [0; 1];
        d.read_config(5, &mut b);
        assert_eq!(b[0], 0x56);
    }

    #[test]
    fn deliver_before_activation_is_refused() {
        let (mut d, backend) = nic();
        assert!(!backend.deliver(b"frame"));
        d.start(&[16, 16]);
        assert_eq!(backend.rx_ready.load(Ordering::SeqCst), 1);
        // Activated but no buffers posted.
        assert!(!backend.deliver(b"frame"));
    }

    #[test]
    fn transmit() {
        let (mut d, backend) = nic();
        d.start(&[16, 16]);
        let a = d.alloc(64);
        // Header and frame in one buffer.
        d.mem.write(a + 12, b"frame-one").unwrap();
        let h1 = d.add(1, &[(a, 21, false)]);
        // Header and frame split, frame itself split.
        let (h, f1, f2) = (d.alloc(12), d.alloc(4), d.alloc(4));
        d.mem.write(f1, b"fram").unwrap();
        d.mem.write(f2, b"e-2").unwrap();
        let h2 = d.add(1, &[(h, 12, false), (f1, 4, false), (f2, 3, false)]);
        // Too short to hold a header: dropped but returned.
        let h3 = d.add(1, &[(a, 4, false)]);
        d.kick(1);
        assert_eq!(
            *backend.sent.lock().unwrap(),
            [b"frame-one".to_vec(), b"frame-2".to_vec()]
        );
        assert_eq!(d.pop_used(1), Some((h1.into(), 0)));
        assert_eq!(d.pop_used(1), Some((h2.into(), 0)));
        assert_eq!(d.pop_used(1), Some((h3.into(), 0)));
        assert_eq!(d.ack(), INT_USED);
    }

    #[test]
    fn receive_and_backpressure() {
        let (mut d, backend) = nic();
        d.start(&[16, 16]);
        let buf = d.alloc(1526);
        let h = d.add(0, &[(buf, 1526, true)]);
        d.kick(0);
        assert_eq!(backend.rx_ready.load(Ordering::SeqCst), 2);
        let frame: Vec<u8> = (0..100).collect();
        assert!(backend.deliver(&frame));
        assert_eq!(d.pop_used(0), Some((h.into(), 112)));
        let mut got = vec![0; 112];
        d.mem.read(buf, &mut got).unwrap();
        assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(&got[12..], &frame[..]);
        assert_eq!(d.ack(), INT_USED);
        // No buffer left: refused, and not consumed.
        assert!(!backend.deliver(&frame));
        assert_eq!(d.pop_used(0), None);
        assert!(!d.irq.level());
        // Header and frame scattered over two buffers.
        let (b1, b2) = (d.alloc(10), d.alloc(1516));
        let h = d.add(0, &[(b1, 10, true), (b2, 1516, true)]);
        d.kick(0);
        assert_eq!(backend.rx_ready.load(Ordering::SeqCst), 3);
        assert!(backend.deliver(b"abc"));
        assert_eq!(d.pop_used(0), Some((h.into(), 15)));
        let mut got = [0; 5];
        d.mem.read(b2, &mut got).unwrap();
        assert_eq!(&got, &[1, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn oversized_frame_is_dropped_buffer_kept() {
        let (mut d, backend) = nic();
        d.start(&[16, 16]);
        let buf = d.alloc(64);
        let h = d.add(0, &[(buf, 64, true)]);
        assert!(backend.deliver(&[0; 100]));
        assert_eq!(d.pop_used(0), None);
        assert!(backend.deliver(&[7; 52]));
        assert_eq!(d.pop_used(0), Some((h.into(), 64)));
    }

    #[test]
    fn receive_from_another_thread() {
        let (mut d, backend) = nic();
        d.start(&[16, 16]);
        let n = 2000usize;
        let t = {
            let backend = backend.clone();
            std::thread::spawn(move || {
                let mut i = 0usize;
                while i < n {
                    let frame = (i as u32).to_le_bytes();
                    if backend.deliver(&frame) {
                        i += 1;
                    } else {
                        std::thread::yield_now();
                    }
                }
            })
        };
        let bufs: Vec<u64> = (0..8).map(|_| d.alloc(64)).collect();
        let mut by_head = std::collections::HashMap::new();
        for &b in &bufs {
            by_head.insert(u32::from(d.add(0, &[(b, 64, true)])), b);
        }
        d.kick(0);
        let mut next = 0u32;
        while (next as usize) < n {
            if !d.irq.level() {
                std::thread::yield_now();
                continue;
            }
            d.ack();
            while let Some((h, len)) = d.pop_used(0) {
                assert_eq!(len, 16);
                let b = by_head[&h];
                assert_eq!(d.mem.read_u32(b + 12).unwrap(), next);
                next += 1;
                by_head.insert(u32::from(d.add(0, &[(b, 64, true)])), b);
                d.kick(0);
            }
        }
        t.join().unwrap();
    }

    #[test]
    fn reset_detaches_receive() {
        let (mut d, backend) = nic();
        d.start(&[16, 16]);
        let buf = d.alloc(64);
        d.add(0, &[(buf, 64, true)]);
        d.reset();
        assert!(!backend.deliver(b"x"));
        assert_eq!(d.pop_used(0), None);
    }

    #[test]
    fn malformed_rx_chain_needs_reset() {
        let (mut d, backend) = nic();
        d.start(&[16, 16]);
        let mem = d.mem.clone();
        let q = d.q(0);
        q.write_desc(&mem, 0, 0x10, 64, crate::queue::VIRTQ_DESC_F_WRITE, 0);
        q.publish(&mem, 0);
        assert!(!backend.deliver(b"x"));
        assert!(d.needs_reset());
        assert!(!backend.deliver(b"x"));
        // Transmit still works until the driver resets.
        let a = d.alloc(16);
        d.add(1, &[(a, 13, false)]);
        d.kick(1);
        assert_eq!(backend.sent.lock().unwrap().len(), 1);
    }
}
