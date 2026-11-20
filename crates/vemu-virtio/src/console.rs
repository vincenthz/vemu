//! virtio-console (virtio 1.2 §5.3) with one port, `hvc0` in Linux.
//!
//! The device offers `VIRTIO_CONSOLE_F_MULTIPORT` with `max_nr_ports = 1`,
//! only to learn when the guest has the port open: Linux's driver posts its
//! receive buffers before it marks the console port connected, and throws
//! away input that arrives in between. With MULTIPORT the control queues
//! tell the device exactly when that is (the `PORT_OPEN` message), so input
//! is held here until then. The handshake (§5.3.6.2):
//!
//! | driver → device | device → driver |
//! |---|---|
//! | `DEVICE_READY(1)` | `DEVICE_ADD` port 0 |
//! | `PORT_READY` port 0 | `CONSOLE_PORT` port 0 |
//! | `PORT_OPEN(1)` port 0: input flows | |
//!
//! Queues: 0 receiveq and 1 transmitq of port 0, then (MULTIPORT only) 2
//! control receiveq (device → driver) and 3 control transmitq. A driver that
//! does not accept MULTIPORT gets the plain single-port device, whose input
//! is delivered as soon as receive buffers are posted.
//!
//! Output is written synchronously to the host writer when the driver
//! notifies transmitq. Input pushed through [`ConsoleInput`] (from any
//! thread) is buffered and copied into receive buffers once the port is open
//! and as the driver posts them; it is kept across device resets and before
//! the driver is up, so nothing typed early is lost.
//!
//! Buffered input is bounded by [`INPUT_CAPACITY`]. When the buffer is full,
//! [`ConsoleInput::push`] blocks the pushing thread until the guest has read
//! enough (backpressure: a piped file reaches the guest whole), until
//! [`ConsoleInput::close`] is called, or until the [`Console`] is dropped.
//! [`ConsoleInput::try_push`] never blocks and drops what does not fit (like
//! a UART FIFO overrun), for interactive input that must stay responsive.
//!
//! Host memory per device is bounded whatever the guest does: output is
//! copied through a fixed [`TX_CHUNK`]-byte buffer, and at most one
//! `DEVICE_ADD` and one `CONSOLE_PORT` reply wait for control receive buffers.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crate::interrupt::Interrupt;
use crate::queue::{Queue, sub_ranges};
use crate::{
    ActivateContext, ActivateError, VirtioDevice, device_id, lock, queue_broken, read_config_bytes,
    warn_once,
};

/// Maximum bytes of input buffered while the guest has no receive buffers.
pub const INPUT_CAPACITY: usize = 1 << 20;

/// Size of the bounce buffer guest output is copied through.
pub const TX_CHUNK: usize = 16 << 10;

/// Device feature: control queues and multiple ports (we use one port).
pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const CONTROL_RX_QUEUE: u16 = 2;
const CONTROL_TX_QUEUE: u16 = 3;
const QUEUE_SIZE: u16 = 64;

/// The only port.
const PORT: u32 = 0;

/// Control message events (`struct virtio_console_control.event`).
mod event {
    pub const DEVICE_READY: u16 = 0;
    pub const DEVICE_ADD: u16 = 1;
    pub const PORT_READY: u16 = 3;
    pub const CONSOLE_PORT: u16 = 4;
    pub const PORT_OPEN: u16 = 6;
}

/// `struct virtio_console_control { le32 id; le16 event; le16 value; }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ControlMsg {
    id: u32,
    event: u16,
    value: u16,
}

impl ControlMsg {
    const SIZE: usize = 8;

    fn parse(b: &[u8; Self::SIZE]) -> ControlMsg {
        ControlMsg {
            id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            event: u16::from_le_bytes([b[4], b[5]]),
            value: u16::from_le_bytes([b[6], b[7]]),
        }
    }

    fn bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0; Self::SIZE];
        b[..4].copy_from_slice(&self.id.to_le_bytes());
        b[4..6].copy_from_slice(&self.event.to_le_bytes());
        b[6..].copy_from_slice(&self.value.to_le_bytes());
        b
    }
}

/// virtio-console device.
pub struct Console {
    rx: Arc<Rx>,
    tx: Option<Queue>,
    /// Present when the driver accepted MULTIPORT.
    control: Option<Control>,
    interrupt: Option<Arc<Interrupt>>,
    output: Box<dyn Write + Send>,
    /// Bounce buffer for output, [`TX_CHUNK`] bytes; never grows.
    buf: Box<[u8]>,
}

/// The control queues and the replies waiting for control receive buffers.
struct Control {
    rx: Queue,
    tx: Queue,
    outbox: Outbox,
}

/// Replies waiting for control receive buffers. The replies are idempotent,
/// so each is pending at most once whatever the driver sends (a queue of
/// them would let a driver that never posts control receive buffers grow
/// host memory without limit).
#[derive(Default)]
struct Outbox {
    device_add: bool,
    console_port: bool,
}

impl Outbox {
    /// The next reply to deliver: `DEVICE_ADD` before `CONSOLE_PORT`.
    fn front(&self) -> Option<u16> {
        if self.device_add {
            Some(event::DEVICE_ADD)
        } else if self.console_port {
            Some(event::CONSOLE_PORT)
        } else {
            None
        }
    }

    fn pop_front(&mut self) {
        if self.device_add {
            self.device_add = false;
        } else {
            self.console_port = false;
        }
    }
}

/// Feeds host input to a [`Console`]. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct ConsoleInput {
    rx: Arc<Rx>,
}

/// Receive side, shared between the device (vCPU threads) and input threads.
struct Rx {
    state: Mutex<RxState>,
    /// Signalled when `pending` shrinks or input is closed.
    room: Condvar,
}

impl Rx {
    fn lock(&self) -> MutexGuard<'_, RxState> {
        lock(&self.state)
    }

    /// Deliver pending input and wake pushers blocked on a full buffer.
    fn fill(&self, rx: &mut RxState) {
        if rx.fill() {
            self.room.notify_all();
        }
    }
}

struct RxState {
    pending: VecDeque<u8>,
    queue: Option<Queue>,
    interrupt: Option<Arc<Interrupt>>,
    /// The guest has the port open: input may be delivered.
    open: bool,
    /// No more blocking on a full buffer ([`ConsoleInput::close`]).
    closed: bool,
}

impl Console {
    /// A console writing guest output to `output`, and the handle feeding it
    /// input.
    pub fn new(output: Box<dyn Write + Send>) -> (Console, ConsoleInput) {
        let rx = Arc::new(Rx {
            state: Mutex::new(RxState {
                pending: VecDeque::new(),
                queue: None,
                interrupt: None,
                open: false,
                closed: false,
            }),
            room: Condvar::new(),
        });
        let console = Console {
            rx: rx.clone(),
            tx: None,
            control: None,
            interrupt: None,
            output,
            buf: vec![0; TX_CHUNK].into_boxed_slice(),
        };
        (console, ConsoleInput { rx })
    }

    fn process_tx(&mut self) {
        let (Some(q), Some(interrupt)) = (self.tx.as_mut(), self.interrupt.as_ref()) else {
            return;
        };
        let (output, buf) = (&mut self.output, &mut self.buf);
        let mem = q.memory().clone();
        let mut write_failed = false;
        let result = q.drain(|chain| {
            // A segment can be as large as guest RAM: copy it through the
            // fixed-size buffer, never a host buffer as large as the segment.
            for (gpa, n) in sub_ranges(chain.readable(), 0, chain.readable_len()) {
                let mut off = 0;
                while off < n {
                    let len = (n - off).min(buf.len());
                    let chunk = &mut buf[..len];
                    // Segments were bounds-checked when the chain was popped.
                    if mem.read(gpa + off as u64, chunk).is_ok() && !write_failed {
                        write_failed = output.write_all(chunk).is_err();
                    }
                    off += len;
                }
            }
            0
        });
        if output.flush().is_err() || write_failed {
            warn_once!("console: writing guest output failed; output dropped");
        }
        match result {
            Ok(0) => {}
            Ok(_) => {
                if q.needs_interrupt() {
                    interrupt.signal_used();
                }
            }
            Err(e) => {
                queue_broken("console", "transmit", &e, interrupt);
                interrupt.signal_used();
                self.tx = None;
            }
        }
    }

    /// Handle the driver's control messages, each as it is taken off the
    /// queue (collecting them first would need memory without bound while
    /// other vCPUs keep refilling the queue).
    fn process_control_tx(&mut self) {
        let (Some(c), Some(interrupt)) = (self.control.as_mut(), self.interrupt.as_ref()) else {
            return;
        };
        let rx = &self.rx;
        let mem = c.tx.memory().clone();
        let Control { tx, outbox, .. } = c;
        let result = tx.drain(|chain| {
            let mut b = [0; ControlMsg::SIZE];
            match chain.read_at(&mem, 0, &mut b) {
                Ok(ControlMsg::SIZE) => control_message(ControlMsg::parse(&b), outbox, rx),
                _ => warn_once!("console: short control message ignored"),
            }
            0
        });
        match result {
            Ok(0) => {}
            Ok(_) => {
                if c.tx.needs_interrupt() {
                    interrupt.signal_used();
                }
            }
            Err(e) => {
                queue_broken("console", "control transmit", &e, interrupt);
                interrupt.signal_used();
                self.control = None;
                return;
            }
        }
        self.flush_control();
    }

    /// Deliver queued control messages into the control receive buffers.
    fn flush_control(&mut self) {
        let (Some(c), Some(interrupt)) = (self.control.as_mut(), self.interrupt.as_ref()) else {
            return;
        };
        let mem = c.rx.memory().clone();
        let mut used = false;
        let mut result = Ok(());
        while let Some(event) = c.outbox.front() {
            let chain = match c.rx.pop() {
                Ok(Some(chain)) => chain,
                Ok(None) => break,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            // Segments were bounds-checked when the chain was popped.
            let m = ControlMsg {
                id: PORT,
                event,
                value: 1,
            };
            let n = chain.write_at(&mem, 0, &m.bytes()).unwrap_or(0);
            if n < ControlMsg::SIZE {
                warn_once!("console: control receive buffer too small");
            }
            c.outbox.pop_front();
            // n <= 8.
            if let Err(e) = c.rx.add_used(chain.head(), n as u32) {
                result = Err(e);
                break;
            }
            used = true;
        }
        match result {
            Ok(()) => {
                if used && c.rx.needs_interrupt() {
                    interrupt.signal_used();
                }
            }
            Err(e) => {
                queue_broken("console", "control receive", &e, interrupt);
                interrupt.signal_used();
                self.control = None;
            }
        }
    }
}

/// Handle one control message from the driver.
fn control_message(m: ControlMsg, outbox: &mut Outbox, rx: &Rx) {
    match m.event {
        event::DEVICE_READY if m.value == 1 => outbox.device_add = true,
        event::DEVICE_READY => warn_once!("console: the driver failed to initialise"),
        event::PORT_READY if m.id == PORT && m.value == 1 => outbox.console_port = true,
        event::PORT_READY if m.id == PORT => {
            warn_once!("console: the driver failed to set up the port")
        }
        event::PORT_OPEN if m.id == PORT => {
            let mut state = rx.lock();
            state.open = m.value == 1;
            rx.fill(&mut state);
        }
        _ => warn_once!(
            "console: unexpected control message (port {}, event {}, value {}) ignored",
            m.id,
            m.event,
            m.value
        ),
    }
}

impl Drop for Console {
    /// Nothing will read the buffered input any more: release blocked pushers.
    fn drop(&mut self) {
        ConsoleInput {
            rx: self.rx.clone(),
        }
        .close();
    }
}

impl VirtioDevice for Console {
    fn device_type(&self) -> u32 {
        device_id::CONSOLE
    }

    fn device_features(&self) -> u64 {
        VIRTIO_CONSOLE_F_MULTIPORT
    }

    fn num_queues(&self) -> usize {
        4
    }

    fn queue_max_size(&self) -> u16 {
        QUEUE_SIZE
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // struct virtio_console_config { le16 cols; le16 rows;
        // le32 max_nr_ports; le32 emerg_wr; }: one port; no SIZE or
        // EMERG_WRITE, so the other fields mean nothing.
        let mut cfg = [0; 12];
        cfg[4..8].copy_from_slice(&1u32.to_le_bytes());
        read_config_bytes(&cfg, offset, data);
    }

    fn activate(&mut self, mut ctx: ActivateContext) -> Result<(), ActivateError> {
        let rxq = ctx.take_queue(RX_QUEUE.into())?;
        let txq = ctx.take_queue(TX_QUEUE.into())?;
        let multiport = ctx.features & VIRTIO_CONSOLE_F_MULTIPORT != 0;
        self.control = if multiport {
            Some(Control {
                rx: ctx.take_queue(CONTROL_RX_QUEUE.into())?,
                tx: ctx.take_queue(CONTROL_TX_QUEUE.into())?,
                outbox: Outbox::default(),
            })
        } else {
            None
        };
        self.tx = Some(txq);
        self.interrupt = Some(ctx.interrupt.clone());
        let mut rx = self.rx.lock();
        rx.queue = Some(rxq);
        rx.interrupt = Some(ctx.interrupt);
        // Without control queues there is no PORT_OPEN to wait for.
        rx.open = !multiport;
        self.rx.fill(&mut rx);
        Ok(())
    }

    fn queue_notify(&mut self, index: u16) {
        match index {
            RX_QUEUE => self.rx.fill(&mut self.rx.lock()),
            TX_QUEUE => self.process_tx(),
            CONTROL_RX_QUEUE => self.flush_control(),
            CONTROL_TX_QUEUE => self.process_control_tx(),
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.tx = None;
        self.control = None;
        self.interrupt = None;
        let mut rx = self.rx.lock();
        rx.queue = None;
        rx.interrupt = None;
        rx.open = false;
    }
}

impl ConsoleInput {
    /// Queue `bytes` for the guest; delivered once the guest has the port
    /// open and as receive buffers allow. While [`INPUT_CAPACITY`] bytes are
    /// already waiting, this blocks until the guest reads some (device resets
    /// keep the backlog, so they do not unblock it). After [`close`] (or once
    /// the [`Console`] is dropped) it no longer blocks and drops what does
    /// not fit, with a warning.
    ///
    /// [`close`]: ConsoleInput::close
    pub fn push(&self, bytes: &[u8]) {
        let mut rx = self.rx.lock();
        let mut rest = bytes;
        loop {
            let n = rest.len().min(INPUT_CAPACITY - rx.pending.len());
            rx.pending.extend(&rest[..n]);
            rest = &rest[n..];
            self.rx.fill(&mut rx);
            if rest.is_empty() {
                return;
            }
            if rx.closed {
                warn_once!("console: input closed with the buffer full; dropping input");
                return;
            }
            if rx.pending.len() == INPUT_CAPACITY {
                rx = self
                    .rx
                    .room
                    .wait(rx)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
    }

    /// Like [`push`](ConsoleInput::push) but never blocks: bytes beyond
    /// [`INPUT_CAPACITY`] of backlog are dropped (with a warning). Returns the
    /// number of bytes accepted.
    pub fn try_push(&self, bytes: &[u8]) -> usize {
        let mut rx = self.rx.lock();
        let n = bytes.len().min(INPUT_CAPACITY - rx.pending.len());
        if n < bytes.len() {
            warn_once!("console: input buffer full, dropping input");
        }
        rx.pending.extend(&bytes[..n]);
        self.rx.fill(&mut rx);
        n
    }

    /// Stop blocking: wake every thread blocked in
    /// [`push`](ConsoleInput::push), and make later pushes drop what does not
    /// fit instead of waiting. Used at shutdown so an input thread blocked on
    /// a guest that stopped reading cannot hang it.
    pub fn close(&self) {
        self.rx.lock().closed = true;
        self.rx.room.notify_all();
    }

    /// Bytes buffered and not yet delivered to the guest.
    pub fn pending(&self) -> usize {
        self.rx.lock().pending.len()
    }
}

impl RxState {
    /// Move pending input into posted receive buffers (once the port is open).
    /// Returns whether any input was delivered.
    fn fill(&mut self) -> bool {
        if !self.open {
            return false;
        }
        let (Some(q), Some(interrupt)) = (self.queue.as_mut(), self.interrupt.as_ref()) else {
            return false;
        };
        let mem = q.memory().clone();
        let before = self.pending.len();
        let mut used = false;
        let mut result = Ok(());
        while !self.pending.is_empty() {
            let chain = match q.pop() {
                Ok(Some(chain)) => chain,
                Ok(None) => break,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            let (a, b) = self.pending.as_slices();
            // Segments were bounds-checked when the chain was popped.
            let n = chain.write_at(&mem, 0, a).unwrap_or(0);
            let m = if n == a.len() {
                chain.write_at(&mem, n as u64, b).unwrap_or(0)
            } else {
                0
            };
            self.pending.drain(..n + m);
            // n + m <= writable_len, which fits in a u32.
            if let Err(e) = q.add_used(chain.head(), (n + m) as u32) {
                result = Err(e);
                break;
            }
            used = true;
        }
        match result {
            Ok(()) => {
                if used && q.needs_interrupt() {
                    interrupt.signal_used();
                }
            }
            Err(e) => {
                queue_broken("console", "receive", &e, interrupt);
                interrupt.signal_used();
                self.queue = None;
            }
        }
        self.pending.len() < before
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::INT_USED;
    use crate::testutil::Driver;

    /// A `Write` sink the test can inspect.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Start the device as a driver without MULTIPORT does: two queues, and
    /// input flows as soon as receive buffers are posted.
    fn start_single_port(d: &mut Driver) {
        let f = d.device_features() & !VIRTIO_CONSOLE_F_MULTIPORT;
        d.start_with(f, &[64, 64]);
    }

    fn console() -> (Driver, ConsoleInput, Sink) {
        let sink = Sink::default();
        let (dev, input) = Console::new(Box::new(sink.clone()));
        let mut d = Driver::new(Box::new(dev));
        assert_eq!(d.read32(0x008), 3);
        assert_eq!(
            d.device_features() & 0xffff_ffff & !(1 << 28),
            VIRTIO_CONSOLE_F_MULTIPORT
        );
        start_single_port(&mut d);
        (d, input, sink)
    }

    /// Send control message `(id, event, value)` on the control transmitq.
    fn send_control(d: &mut Driver, id: u32, event: u16, value: u16) {
        let buf = d.alloc(8);
        d.mem
            .write(buf, &ControlMsg { id, event, value }.bytes())
            .unwrap();
        d.add(3, &[(buf, 8, false)]);
        d.kick(3);
    }

    /// Control messages the device has written into posted control receive
    /// buffers (in `bufs`, by head).
    fn received_control(
        d: &mut Driver,
        bufs: &std::collections::HashMap<u32, u64>,
    ) -> Vec<(u32, u16, u16)> {
        let mut out = Vec::new();
        while let Some((head, len)) = d.pop_used(2) {
            assert_eq!(len, 8);
            let mut b = [0; 8];
            d.mem.read(bufs[&head], &mut b).unwrap();
            let m = ControlMsg::parse(&b);
            out.push((m.id, m.event, m.value));
        }
        out
    }

    #[test]
    fn config_reports_one_port() {
        let (mut d, _, _) = console();
        let mut b = [0; 4];
        d.read_config(4, &mut b);
        assert_eq!(u32::from_le_bytes(b), 1, "max_nr_ports");
    }

    #[test]
    fn multiport_holds_input_until_port_open() {
        let sink = Sink::default();
        let (dev, input) = Console::new(Box::new(sink.clone()));
        let mut d = Driver::new(Box::new(dev));
        d.start(&[64, 64, 16, 16]);
        input.push(b"typed early\n");

        // The port's receive buffers come first (as Linux's add_port does):
        // input must not go into them yet.
        let data = d.alloc(64);
        let data_head = d.add(0, &[(data, 64, true)]);
        d.kick(0);
        assert_eq!(d.pop_used(0), None);

        // DEVICE_READY before any control receive buffer: the reply waits.
        send_control(&mut d, u32::MAX, event::DEVICE_READY, 1);
        let mut bufs = std::collections::HashMap::new();
        for _ in 0..4 {
            let b = d.alloc(8);
            bufs.insert(u32::from(d.add(2, &[(b, 8, true)])), b);
        }
        assert!(received_control(&mut d, &bufs).is_empty());
        d.kick(2);
        assert_eq!(received_control(&mut d, &bufs), [(0, event::DEVICE_ADD, 1)]);

        send_control(&mut d, 0, event::PORT_READY, 1);
        assert_eq!(
            received_control(&mut d, &bufs),
            [(0, event::CONSOLE_PORT, 1)]
        );
        assert_eq!(d.pop_used(0), None, "port not open yet");
        assert_eq!(input.pending(), 12);

        // PORT_OPEN: the held input is delivered.
        send_control(&mut d, 0, event::PORT_OPEN, 1);
        assert_eq!(d.pop_used(0), Some((data_head.into(), 12)));
        let mut got = [0; 12];
        d.mem.read(data, &mut got).unwrap();
        assert_eq!(&got, b"typed early\n");
        assert!(d.irq.level());

        // Unknown ports and events are ignored; output works throughout.
        send_control(&mut d, 7, event::PORT_OPEN, 1);
        send_control(&mut d, 0, 99, 1);
        let out = d.alloc(4);
        d.mem.write(out, b"ok\r\n").unwrap();
        d.add(1, &[(out, 4, false)]);
        d.kick(1);
        assert_eq!(&*sink.0.lock().unwrap(), b"ok\r\n");

        // Closing the port holds input again.
        send_control(&mut d, 0, event::PORT_OPEN, 0);
        let h = d.add(0, &[(data, 64, true)]);
        input.push(b"x");
        assert_eq!(d.pop_used(0), None);
        send_control(&mut d, 0, event::PORT_OPEN, 1);
        assert_eq!(d.pop_used(0), Some((h.into(), 1)));
        assert!(!d.needs_reset());
    }

    #[test]
    fn reset_closes_the_port() {
        let (dev, input) = Console::new(Box::new(Sink::default()));
        let mut d = Driver::new(Box::new(dev));
        d.start(&[64, 64, 16, 16]);
        send_control(&mut d, 0, event::PORT_OPEN, 1);
        d.reset();
        d.queues.clear();
        d.start(&[64, 64, 16, 16]);
        let buf = d.alloc(8);
        let h = d.add(0, &[(buf, 8, true)]);
        input.push(b"held");
        d.kick(0);
        assert_eq!(d.pop_used(0), None, "a new driver must open the port again");
        send_control(&mut d, 0, event::PORT_OPEN, 1);
        assert_eq!(d.pop_used(0), Some((h.into(), 4)));
    }

    #[test]
    fn multiport_needs_control_queues() {
        let (dev, _) = Console::new(Box::new(Sink::default()));
        let mut d = Driver::new(Box::new(dev));
        // MULTIPORT accepted but only the port queues enabled.
        let f = d.device_features();
        assert!(d.negotiate(f));
        d.setup_queue(0, 64);
        d.setup_queue(1, 64);
        d.driver_ok();
        assert!(d.needs_reset());
    }

    #[test]
    fn output() {
        let (mut d, _input, sink) = console();
        let a = d.alloc(16);
        let b = d.alloc(16);
        d.mem.write(a, b"hello, ").unwrap();
        d.mem.write(b, b"world\n").unwrap();
        let h1 = d.add(1, &[(a, 7, false)]);
        let h2 = d.add(1, &[(a, 3, false), (b, 6, false)]);
        d.kick(1);
        assert_eq!(&*sink.0.lock().unwrap(), b"hello, helworld\n");
        assert_eq!(d.pop_used(1), Some((h1.into(), 0)));
        assert_eq!(d.pop_used(1), Some((h2.into(), 0)));
        assert_eq!(d.ack(), INT_USED);
        assert!(!d.irq.level());
    }

    #[test]
    fn input_before_buffers_is_kept() {
        let (dev, input) = Console::new(Box::new(Sink::default()));
        // Typed before the driver even exists.
        input.push(b"early ");
        let mut d = Driver::new(Box::new(dev));
        start_single_port(&mut d);
        input.push(b"input");
        assert_eq!(input.pending(), 11);
        assert_eq!(d.interrupt_status(), 0);
        let buf = d.alloc(8);
        let h = d.add(0, &[(buf, 8, true)]);
        d.kick(0);
        assert_eq!(d.pop_used(0), Some((h.into(), 8)));
        let mut got = [0; 8];
        d.mem.read(buf, &mut got).unwrap();
        assert_eq!(&got, b"early in");
        assert_eq!(d.ack(), INT_USED);
        assert_eq!(input.pending(), 3);
        // Second buffer, split in two segments, gets the rest.
        let b1 = d.alloc(2);
        let b2 = d.alloc(8);
        let h = d.add(0, &[(b1, 2, true), (b2, 8, true)]);
        d.kick(0);
        assert_eq!(d.pop_used(0), Some((h.into(), 3)));
        let mut got = [0; 3];
        d.mem.read(b1, &mut got[..2]).unwrap();
        d.mem.read(b2, &mut got[2..]).unwrap();
        assert_eq!(&got, b"put");
        assert_eq!(input.pending(), 0);
    }

    #[test]
    fn input_into_posted_buffers() {
        let (mut d, input, _) = console();
        let buf = d.alloc(64);
        let h = d.add(0, &[(buf, 64, true)]);
        d.kick(0);
        // Posted buffers are not consumed without input.
        assert_eq!(d.pop_used(0), None);
        input.push(b"ls\n");
        assert_eq!(d.pop_used(0), Some((h.into(), 3)));
        assert!(d.irq.level());
        // Interrupt suppressed by the driver.
        d.ack();
        let mem = d.mem.clone();
        d.q(0).set_no_interrupt(&mem, true);
        let h = d.add(0, &[(buf, 64, true)]);
        input.push(b"x");
        assert_eq!(d.pop_used(0), Some((h.into(), 1)));
        assert!(!d.irq.level());
    }

    #[test]
    fn input_wraps_ring_buffer() {
        let (mut d, input, _) = console();
        let buf = d.alloc(4);
        let mut out = Vec::new();
        for i in 0..50u8 {
            input.push(&[i, i, i]);
            d.add(0, &[(buf, 4, true)]);
            d.kick(0);
            let (_, len) = d.pop_used(0).unwrap();
            let mut b = vec![0; len as usize];
            d.mem.read(buf, &mut b).unwrap();
            out.extend(b);
        }
        while input.pending() > 0 {
            d.add(0, &[(buf, 4, true)]);
            d.kick(0);
            let (_, len) = d.pop_used(0).unwrap();
            let mut b = vec![0; len as usize];
            d.mem.read(buf, &mut b).unwrap();
            out.extend(b);
        }
        let want: Vec<u8> = (0..50u8).flat_map(|i| [i, i, i]).collect();
        assert_eq!(out, want);
    }

    #[test]
    fn try_push_overflow_drops_newest() {
        let (dev, input) = Console::new(Box::new(Sink::default()));
        assert_eq!(
            input.try_push(&vec![1; INPUT_CAPACITY - 1]),
            INPUT_CAPACITY - 1
        );
        assert_eq!(input.try_push(&[2, 3, 4]), 1);
        assert_eq!(input.pending(), INPUT_CAPACITY);
        let rx = input.rx.lock();
        assert_eq!(rx.pending.back(), Some(&2));
        drop(rx);
        drop(dev);
    }

    /// Wait (bounded) until `cond` holds.
    fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// A push larger than the buffer (piped stdin) blocks until the guest
    /// reads, and every byte arrives, in order.
    #[test]
    fn push_applies_backpressure_and_loses_nothing() {
        let (mut d, input, _) = console();
        let total = 2 * INPUT_CAPACITY + 123;
        let want: Vec<u8> = (0..total).map(|i| (i % 253) as u8).collect();
        let t = {
            let (input, data) = (input.clone(), want.clone());
            std::thread::spawn(move || {
                // In odd-sized pieces, as reads from a pipe come.
                data.chunks(70_001).for_each(|c| input.push(c));
            })
        };
        // No receive buffers yet: the pusher fills the buffer and blocks.
        wait_until("buffer full", || input.pending() == INPUT_CAPACITY);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!t.is_finished(), "push must block on a full buffer");
        assert_eq!(input.pending(), INPUT_CAPACITY, "nothing dropped");

        let buf = d.alloc(64 << 10);
        let mut out = Vec::with_capacity(total);
        while out.len() < total {
            let h = d.add(0, &[(buf, 64 << 10, true)]);
            d.kick(0);
            // The pusher may be between pushes: wait for some input.
            let used = loop {
                if let Some(u) = d.pop_used(0) {
                    break u;
                }
                std::thread::yield_now();
            };
            assert_eq!(used.0, u32::from(h));
            let mut v = vec![0; used.1 as usize];
            d.mem.read(buf, &mut v).unwrap();
            out.extend(v);
        }
        t.join().unwrap();
        assert!(out == want, "input corrupted");
        assert_eq!(input.pending(), 0);
    }

    /// `close` releases a pusher blocked on a guest that never reads, and
    /// later pushes no longer block.
    #[test]
    fn close_unblocks_push() {
        let (_d, input, _) = console();
        let t = {
            let input = input.clone();
            std::thread::spawn(move || input.push(&vec![7; INPUT_CAPACITY + 10]))
        };
        wait_until("buffer full", || input.pending() == INPUT_CAPACITY);
        assert!(!t.is_finished());
        input.close();
        t.join().unwrap();
        input.push(b"more");
        assert_eq!(input.pending(), INPUT_CAPACITY);
    }

    /// Dropping the device (VM shutdown) releases a blocked pusher.
    #[test]
    fn dropping_the_console_unblocks_push() {
        let (dev, input) = Console::new(Box::new(Sink::default()));
        let t = {
            let input = input.clone();
            std::thread::spawn(move || input.push(&vec![7; INPUT_CAPACITY + 10]))
        };
        wait_until("buffer full", || input.pending() == INPUT_CAPACITY);
        assert!(!t.is_finished());
        drop(dev);
        t.join().unwrap();
        assert_eq!(input.pending(), INPUT_CAPACITY);
    }

    /// A driver repeating DEVICE_READY/PORT_READY without ever posting
    /// control receive buffers gets one reply of each, not one per message.
    #[test]
    fn control_replies_are_bounded() {
        let (dev, _input) = Console::new(Box::new(Sink::default()));
        let mut d = Driver::new(Box::new(dev));
        d.start(&[64, 64, 16, 16]);
        let msg = d.alloc(8);
        for i in 0..5_000u32 {
            let (id, event) = if i % 2 == 0 {
                (u32::MAX, event::DEVICE_READY)
            } else {
                (PORT, event::PORT_READY)
            };
            d.mem
                .write(
                    msg,
                    &ControlMsg {
                        id,
                        event,
                        value: 1,
                    }
                    .bytes(),
                )
                .unwrap();
            d.add(3, &[(msg, 8, false)]);
            d.kick(3);
            assert!(d.pop_used(3).is_some());
        }
        let mut bufs = std::collections::HashMap::new();
        for _ in 0..8 {
            let b = d.alloc(8);
            bufs.insert(u32::from(d.add(2, &[(b, 8, true)])), b);
        }
        d.kick(2);
        assert_eq!(
            received_control(&mut d, &bufs),
            [(0, event::DEVICE_ADD, 1), (0, event::CONSOLE_PORT, 1)]
        );
        assert!(!d.needs_reset());
    }

    /// Several messages handled in one notify, in order; a reply already
    /// delivered is sent again if the driver asks again.
    #[test]
    fn control_messages_in_one_notify() {
        let (dev, input) = Console::new(Box::new(Sink::default()));
        let mut d = Driver::new(Box::new(dev));
        d.start(&[64, 64, 16, 16]);
        let mut bufs = std::collections::HashMap::new();
        for _ in 0..4 {
            let b = d.alloc(8);
            bufs.insert(u32::from(d.add(2, &[(b, 8, true)])), b);
        }
        let data = d.alloc(8);
        let h = d.add(0, &[(data, 8, true)]);
        input.push(b"hi");
        for (id, event) in [
            (u32::MAX, event::DEVICE_READY),
            (PORT, event::PORT_READY),
            (PORT, event::PORT_OPEN),
        ] {
            let b = d.alloc(8);
            d.mem
                .write(
                    b,
                    &ControlMsg {
                        id,
                        event,
                        value: 1,
                    }
                    .bytes(),
                )
                .unwrap();
            d.add(3, &[(b, 8, false)]);
        }
        d.kick(3);
        assert_eq!(
            received_control(&mut d, &bufs),
            [(0, event::DEVICE_ADD, 1), (0, event::CONSOLE_PORT, 1)]
        );
        assert_eq!(d.pop_used(0), Some((h.into(), 2)));
        send_control(&mut d, u32::MAX, event::DEVICE_READY, 1);
        assert_eq!(received_control(&mut d, &bufs), [(0, event::DEVICE_ADD, 1)]);
    }

    /// Largest single heap allocation made by the current thread while
    /// [`track_allocations`] is on.
    mod alloc_track {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        thread_local! {
            static TRACK: Cell<bool> = const { Cell::new(false) };
            static MAX: Cell<usize> = const { Cell::new(0) };
        }

        pub struct Tracking;

        // SAFETY: forwards to the system allocator unchanged; the
        // bookkeeping only touches const-initialised thread locals, which
        // never allocate.
        unsafe impl GlobalAlloc for Tracking {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                note(layout.size());
                // SAFETY: same contract as our caller's.
                unsafe { System.alloc(layout) }
            }
            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                note(layout.size());
                // SAFETY: same contract as our caller's.
                unsafe { System.alloc_zeroed(layout) }
            }
            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                note(new_size);
                // SAFETY: same contract as our caller's.
                unsafe { System.realloc(ptr, layout, new_size) }
            }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                // SAFETY: same contract as our caller's.
                unsafe { System.dealloc(ptr, layout) }
            }
        }

        fn note(size: usize) {
            let _ = TRACK.try_with(|t| {
                if t.get() {
                    let _ = MAX.try_with(|m| m.set(m.get().max(size)));
                }
            });
        }

        /// Run `f` and return the largest allocation it made on this thread.
        pub fn largest_allocation(f: impl FnOnce()) -> usize {
            MAX.with(|m| m.set(0));
            TRACK.with(|t| t.set(true));
            f();
            TRACK.with(|t| t.set(false));
            MAX.with(|m| m.get())
        }
    }

    #[global_allocator]
    static ALLOC: alloc_track::Tracking = alloc_track::Tracking;

    /// A sink that checks output against an expected pattern without
    /// storing it, and records the largest single write.
    #[derive(Clone, Default)]
    struct CheckSink(Arc<Mutex<(usize, usize, bool)>>);

    impl Write for CheckSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let mut s = self.0.lock().unwrap();
            for (i, &x) in b.iter().enumerate() {
                s.2 &= x == ((s.0 + i) % 251) as u8;
            }
            s.0 += b.len();
            s.1 = s.1.max(b.len());
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// One huge transmit descriptor is copied through the fixed buffer: no
    /// host allocation scales with the descriptor's length.
    #[test]
    fn large_output_is_written_in_bounded_chunks() {
        let sink = CheckSink(Arc::new(Mutex::new((0, 0, true))));
        let (dev, _input) = Console::new(Box::new(sink.clone()));
        let mut d = Driver::new(Box::new(dev));
        start_single_port(&mut d);
        let len = 3 << 20;
        let a = d.alloc(len as u64);
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        d.mem.write(a, &data).unwrap();
        drop(data);
        let largest = alloc_track::largest_allocation(|| {
            d.add(
                1,
                &[(a, len as u32 - 5, false), (a + len as u64 - 5, 5, false)],
            );
            d.kick(1);
        });
        assert!(largest < 64 << 10, "{largest}-byte allocation for output");
        let s = *sink.0.lock().unwrap();
        assert_eq!(s.0, len, "bytes written");
        assert!(s.1 <= TX_CHUNK, "{}-byte write", s.1);
        assert!(s.2, "output corrupted");
        assert!(d.pop_used(1).is_some());
    }

    #[test]
    fn input_from_another_thread() {
        let (mut d, input, _) = console();
        let total = 20_000usize;
        let t = {
            let input = input.clone();
            std::thread::spawn(move || {
                for i in 0..total {
                    input.push(&[(i % 251) as u8]);
                }
            })
        };
        let bufs: Vec<u64> = (0..32).map(|_| d.alloc(64)).collect();
        let mut by_head = std::collections::HashMap::new();
        for &b in &bufs {
            let h = d.add(0, &[(b, 64, true)]);
            by_head.insert(u32::from(h), b);
        }
        d.kick(0);
        let mut out = Vec::new();
        while out.len() < total {
            // Interrupt-driven: wait for the line, ACK, then reap.
            if !d.irq.level() {
                std::thread::yield_now();
                continue;
            }
            d.ack();
            while let Some((h, len)) = d.pop_used(0) {
                let b = by_head[&h];
                let mut v = vec![0; len as usize];
                d.mem.read(b, &mut v).unwrap();
                out.extend(v);
                let h2 = d.add(0, &[(b, 64, true)]);
                by_head.insert(u32::from(h2), b);
                d.kick(0);
            }
        }
        t.join().unwrap();
        let want: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        assert_eq!(out, want);
    }

    #[test]
    fn broken_queue_needs_reset_and_reset_recovers() {
        let (mut d, input, sink) = console();
        // Loop in the transmit queue.
        let mem = d.mem.clone();
        let q = d.q(1);
        q.write_desc(&mem, 0, 0x4000_0000, 1, crate::queue::VIRTQ_DESC_F_NEXT, 0);
        q.publish(&mem, 0);
        d.kick(1);
        assert!(d.needs_reset());
        d.kick(1);
        assert!(sink.0.lock().unwrap().is_empty());
        // Reset; input pushed meanwhile is kept.
        d.reset();
        input.push(b"z");
        assert!(!d.needs_reset());
        d.queues.clear();
        start_single_port(&mut d);
        let buf = d.alloc(4);
        d.add(0, &[(buf, 4, true)]);
        d.kick(0);
        assert_eq!(d.pop_used(0).map(|u| u.1), Some(1));
    }

    #[test]
    fn zero_sized_rx_buffer_is_returned() {
        let (mut d, input, _) = console();
        let buf = d.alloc(4);
        let h = d.add(0, &[(buf, 0, true)]);
        input.push(b"a");
        assert_eq!(d.pop_used(0), Some((h.into(), 0)));
        // The byte is still pending.
        assert_eq!(input.pending(), 1);
    }
}
