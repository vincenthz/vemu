//! virtio-mmio transport, version 2 (virtio 1.2 §4.2.2).

use std::sync::Arc;

use vemu_core::{GuestMemory, IrqLine, MmioDevice};

use crate::interrupt::Interrupt;
use crate::queue::Queue;
use crate::{ActivateContext, VirtioDevice, features, warn_once};

/// Size of one virtio-mmio register window.
pub const MMIO_SIZE: u64 = 0x200;

/// `VendorID`: "vemu" as little-endian bytes (like QEMU's "QEMU").
pub const VENDOR_ID: u32 = u32::from_le_bytes(*b"vemu");

const MAGIC_VALUE: u32 = 0x7472_6976; // "virt"
const VERSION: u32 = 2;

pub(crate) mod reg {
    pub const MAGIC_VALUE: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00c;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
    pub const SHM_SEL: u64 = 0x0ac;
    pub const SHM_LEN_LOW: u64 = 0x0b0;
    pub const SHM_LEN_HIGH: u64 = 0x0b4;
    pub const SHM_BASE_LOW: u64 = 0x0b8;
    pub const SHM_BASE_HIGH: u64 = 0x0bc;
    pub const CONFIG_GENERATION: u64 = 0x0fc;
    pub const CONFIG: u64 = 0x100;
}

/// Device status bits (virtio 1.2 §2.1).
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const DEVICE_NEEDS_RESET: u32 = 64;
    pub const FAILED: u32 = 128;
}

/// Features every device gets from the transport and queue implementation.
const TRANSPORT_FEATURES: u64 = features::VERSION_1 | features::RING_INDIRECT_DESC;

/// Driver-side configuration of one queue, as written to the registers.
#[derive(Clone, Copy)]
struct QueueConfig {
    size: u16,
    ready: bool,
    desc: u64,
    avail: u64,
    used: u64,
}

/// A virtio device behind a virtio-mmio v2 register window.
pub struct MmioTransport {
    dev: Box<dyn VirtioDevice>,
    mem: Arc<GuestMemory>,
    interrupt: Arc<Interrupt>,
    device_id: u32,
    device_features: u64,
    queue_max: u16,
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u32,
    queues: Vec<QueueConfig>,
    activated: bool,
}

impl MmioTransport {
    pub fn new(
        dev: Box<dyn VirtioDevice>,
        mem: Arc<GuestMemory>,
        irq: Arc<dyn IrqLine>,
    ) -> MmioTransport {
        let queue_max = dev.queue_max_size();
        let num_queues = dev.num_queues();
        MmioTransport {
            device_id: dev.device_type(),
            device_features: dev.device_features() | TRANSPORT_FEATURES,
            queue_max,
            dev,
            mem,
            interrupt: Arc::new(Interrupt::new(irq)),
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            queues: vec![QueueConfig::new(queue_max); num_queues],
            activated: false,
        }
    }

    /// The device's virtio ID (for building the device tree).
    pub fn device_type(&self) -> u32 {
        self.device_id
    }

    fn selected_queue(&mut self) -> Option<&mut QueueConfig> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    /// Selected queue, if its configuration may still be changed: it exists,
    /// is not enabled, and the driver has not set DRIVER_OK.
    fn configurable_queue(&mut self) -> Option<&mut QueueConfig> {
        if self.status & status::DRIVER_OK != 0 {
            warn_once!("driver changed queue configuration after DRIVER_OK; ignored");
            return None;
        }
        self.selected_queue().filter(|q| !q.ready)
    }

    fn read_reg(&self, offset: u64) -> u32 {
        match offset {
            reg::MAGIC_VALUE => MAGIC_VALUE,
            reg::VERSION => VERSION,
            reg::DEVICE_ID => self.device_id,
            reg::VENDOR_ID => VENDOR_ID,
            reg::DEVICE_FEATURES => match self.device_features_sel {
                0 => self.device_features as u32,
                1 => (self.device_features >> 32) as u32,
                _ => 0,
            },
            reg::QUEUE_NUM_MAX => self
                .queues
                .get(self.queue_sel as usize)
                .map_or(0, |_| u32::from(self.queue_max)),
            reg::QUEUE_READY => self
                .queues
                .get(self.queue_sel as usize)
                .map_or(0, |q| u32::from(q.ready)),
            reg::INTERRUPT_STATUS => self.interrupt.status(),
            reg::STATUS => {
                let needs_reset = if self.interrupt.needs_reset() {
                    status::DEVICE_NEEDS_RESET
                } else {
                    0
                };
                self.status | needs_reset
            }
            // No shared memory regions: length and base read as all ones.
            reg::SHM_LEN_LOW | reg::SHM_LEN_HIGH | reg::SHM_BASE_LOW | reg::SHM_BASE_HIGH => {
                u32::MAX
            }
            reg::CONFIG_GENERATION => self.interrupt.config_generation(),
            _ => 0,
        }
    }

    fn write_reg(&mut self, offset: u64, val: u32) {
        match offset {
            reg::DEVICE_FEATURES_SEL => self.device_features_sel = val,
            reg::DRIVER_FEATURES_SEL => self.driver_features_sel = val,
            reg::DRIVER_FEATURES => self.write_driver_features(val),
            reg::QUEUE_SEL => self.queue_sel = val,
            reg::QUEUE_NUM => {
                if let Some(q) = self.configurable_queue() {
                    // Clamped; an invalid size is refused when the queue is enabled.
                    q.size = val.min(u32::from(u16::MAX)) as u16;
                }
            }
            reg::QUEUE_READY => self.write_queue_ready(val),
            reg::QUEUE_DESC_LOW => self.set_queue_addr(|q| &mut q.desc, false, val),
            reg::QUEUE_DESC_HIGH => self.set_queue_addr(|q| &mut q.desc, true, val),
            reg::QUEUE_DRIVER_LOW => self.set_queue_addr(|q| &mut q.avail, false, val),
            reg::QUEUE_DRIVER_HIGH => self.set_queue_addr(|q| &mut q.avail, true, val),
            reg::QUEUE_DEVICE_LOW => self.set_queue_addr(|q| &mut q.used, false, val),
            reg::QUEUE_DEVICE_HIGH => self.set_queue_addr(|q| &mut q.used, true, val),
            reg::QUEUE_NOTIFY => self.notify(val),
            reg::INTERRUPT_ACK => self.interrupt.ack(val),
            reg::STATUS => self.write_status(val),
            reg::SHM_SEL => {}
            _ => warn_once!("driver wrote read-only or unknown register {offset:#x}"),
        }
    }

    fn write_driver_features(&mut self, val: u32) {
        if self.status & status::FEATURES_OK != 0 {
            warn_once!("driver changed features after FEATURES_OK; ignored");
            return;
        }
        let shift = match self.driver_features_sel {
            0 => 0,
            1 => 32,
            _ => return,
        };
        self.driver_features =
            (self.driver_features & !(0xffff_ffff << shift)) | (u64::from(val) << shift);
    }

    fn set_queue_addr(&mut self, field: fn(&mut QueueConfig) -> &mut u64, high: bool, val: u32) {
        if let Some(q) = self.configurable_queue() {
            let a = field(q);
            *a = if high {
                (*a & 0xffff_ffff) | (u64::from(val) << 32)
            } else {
                (*a & !0xffff_ffff) | u64::from(val)
            };
        }
    }

    fn write_queue_ready(&mut self, val: u32) {
        if self.status & status::DRIVER_OK != 0 {
            warn_once!("driver changed QueueReady after DRIVER_OK; ignored");
            return;
        }
        let (mem, max) = (self.mem.clone(), self.queue_max);
        let Some(q) = self.selected_queue() else {
            return;
        };
        if val & 1 == 0 {
            q.ready = false;
            return;
        }
        // Refused layouts leave QueueReady at 0; DRIVER_OK then fails activation.
        match q.validate(mem, max) {
            Ok(()) => q.ready = true,
            Err(e) => warn_once!("driver enabled a queue with an invalid layout: {e}"),
        }
    }

    fn notify(&mut self, val: u32) {
        // Without VIRTIO_F_NOTIFICATION_DATA the value is just the queue index.
        let Ok(index) = u16::try_from(val) else {
            return;
        };
        if self.activated && self.queues.get(usize::from(index)).is_some_and(|q| q.ready) {
            self.dev.queue_notify(index);
        }
    }

    fn write_status(&mut self, val: u32) {
        if val == 0 {
            self.reset();
            return;
        }
        // Bits only ever get set (the driver must not clear them); NEEDS_RESET
        // is owned by the device.
        let newly_set = val & !self.status & !status::DEVICE_NEEDS_RESET;
        let mut new_status = self.status | newly_set;
        if newly_set & status::FEATURES_OK != 0 && !self.features_acceptable() {
            new_status &= !status::FEATURES_OK;
        }
        if newly_set & status::DRIVER_OK != 0 {
            if new_status & status::FEATURES_OK == 0 {
                warn_once!("driver set DRIVER_OK without FEATURES_OK");
                new_status &= !status::DRIVER_OK;
            } else {
                self.status = new_status;
                self.activate();
                return;
            }
        }
        self.status = new_status;
    }

    /// The driver accepted only offered features, and virtio 1.x.
    fn features_acceptable(&self) -> bool {
        let unknown = self.driver_features & !self.device_features;
        if unknown != 0 {
            warn_once!("driver accepted features {unknown:#x} that were not offered");
            return false;
        }
        if self.driver_features & features::VERSION_1 == 0 {
            warn_once!("driver did not accept VIRTIO_F_VERSION_1 (legacy drivers are unsupported)");
            return false;
        }
        true
    }

    fn activate(&mut self) {
        let queues = self
            .queues
            .iter()
            .map(|c| {
                c.ready
                    .then(|| Queue::new(self.mem.clone(), c.size, c.desc, c.avail, c.used).ok())
                    .flatten()
            })
            .collect();
        let ctx = ActivateContext {
            mem: self.mem.clone(),
            queues,
            interrupt: self.interrupt.clone(),
            features: self.driver_features,
        };
        match self.dev.activate(ctx) {
            Ok(()) => self.activated = true,
            Err(e) => {
                warn_once!("device {} failed to activate: {e}", self.device_id);
                self.interrupt.set_needs_reset();
            }
        }
    }

    fn reset(&mut self) {
        // The device stops (and drops its interrupt users) before the
        // interrupt state is cleared, so nothing re-raises it afterwards.
        self.dev.reset();
        self.interrupt.reset();
        self.activated = false;
        self.status = 0;
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = 0;
        self.queue_sel = 0;
        self.queues.fill(QueueConfig::new(self.queue_max));
    }
}

impl QueueConfig {
    fn new(max: u16) -> QueueConfig {
        QueueConfig {
            size: max,
            ready: false,
            desc: 0,
            avail: 0,
            used: 0,
        }
    }

    fn validate(&self, mem: Arc<GuestMemory>, max: u16) -> Result<(), String> {
        if self.size > max {
            return Err(format!("queue size {} > QueueNumMax {max}", self.size));
        }
        Queue::new(mem, self.size, self.desc, self.avail, self.used)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

impl MmioDevice for MmioTransport {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if offset >= reg::CONFIG {
            self.dev.read_config(offset - reg::CONFIG, data);
            return;
        }
        // Control registers: 32-bit aligned accesses only (virtio 1.2 §4.2.2.2).
        if data.len() != 4 || !offset.is_multiple_of(4) {
            warn_once!(
                "driver read register {offset:#x} with a {}-byte access; reads as 0",
                data.len()
            );
            data.fill(0);
            return;
        }
        data.copy_from_slice(&self.read_reg(offset).to_le_bytes());
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if offset >= reg::CONFIG {
            self.dev.write_config(offset - reg::CONFIG, data);
            return;
        }
        let Ok(bytes) = <[u8; 4]>::try_from(data) else {
            warn_once!(
                "driver wrote register {offset:#x} with a {}-byte access; ignored",
                data.len()
            );
            return;
        };
        if !offset.is_multiple_of(4) {
            warn_once!("driver wrote unaligned register offset {offset:#x}; ignored");
            return;
        }
        self.write_reg(offset, u32::from_le_bytes(bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Driver, MEM_BASE};
    use crate::{ActivateError, INT_CONFIG, INT_USED, read_config_bytes};
    use std::sync::Mutex;

    /// Records what the transport asks of it.
    #[derive(Default)]
    struct Log {
        activations: Vec<Vec<bool>>,
        features: u64,
        notifies: Vec<u16>,
        resets: usize,
        config_writes: Vec<(u64, Vec<u8>)>,
        interrupt: Option<Arc<Interrupt>>,
    }

    struct TestDev {
        log: Arc<Mutex<Log>>,
        fail_activate: bool,
    }

    impl VirtioDevice for TestDev {
        fn device_type(&self) -> u32 {
            42
        }
        fn device_features(&self) -> u64 {
            0b101
        }
        fn num_queues(&self) -> usize {
            2
        }
        fn queue_max_size(&self) -> u16 {
            16
        }
        fn read_config(&self, offset: u64, data: &mut [u8]) {
            read_config_bytes(
                &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                offset,
                data,
            );
        }
        fn write_config(&mut self, offset: u64, data: &[u8]) {
            self.log
                .lock()
                .unwrap()
                .config_writes
                .push((offset, data.to_vec()));
        }
        fn activate(&mut self, ctx: ActivateContext) -> Result<(), ActivateError> {
            let mut log = self.log.lock().unwrap();
            log.activations
                .push(ctx.queues.iter().map(Option::is_some).collect());
            log.features = ctx.features;
            log.interrupt = Some(ctx.interrupt);
            if self.fail_activate {
                Err(ActivateError::new("nope"))
            } else {
                Ok(())
            }
        }
        fn queue_notify(&mut self, index: u16) {
            self.log.lock().unwrap().notifies.push(index);
        }
        fn reset(&mut self) {
            let mut log = self.log.lock().unwrap();
            log.resets += 1;
            log.interrupt = None;
        }
    }

    fn test_driver(fail_activate: bool) -> (Driver, Arc<Mutex<Log>>) {
        let log = Arc::new(Mutex::new(Log::default()));
        let dev = TestDev {
            log: log.clone(),
            fail_activate,
        };
        (Driver::new(Box::new(dev)), log)
    }

    #[test]
    fn identification_registers() {
        let (mut d, _) = test_driver(false);
        assert_eq!(d.read32(reg::MAGIC_VALUE), 0x7472_6976);
        assert_eq!(d.read32(reg::VERSION), 2);
        assert_eq!(d.read32(reg::DEVICE_ID), 42);
        assert_eq!(d.read32(reg::VENDOR_ID), VENDOR_ID);
        assert_eq!(&VENDOR_ID.to_le_bytes(), b"vemu");
        assert_eq!(d.read32(reg::DEVICE_FEATURES), 0b101 | (1 << 28));
        d.write32(reg::DEVICE_FEATURES_SEL, 1);
        assert_eq!(d.read32(reg::DEVICE_FEATURES), 1);
        d.write32(reg::DEVICE_FEATURES_SEL, 2);
        assert_eq!(d.read32(reg::DEVICE_FEATURES), 0);
        assert_eq!(d.read32(reg::SHM_LEN_LOW), u32::MAX);
        assert_eq!(d.read32(reg::SHM_LEN_HIGH), u32::MAX);
        assert_eq!(d.read32(reg::QUEUE_NUM_MAX), 16);
        d.write32(reg::QUEUE_SEL, 2);
        assert_eq!(d.read32(reg::QUEUE_NUM_MAX), 0);
    }

    #[test]
    fn odd_register_accesses() {
        let (mut d, log) = test_driver(false);
        // Narrow or unaligned register reads return zero.
        let mut b = [0xff; 2];
        d.t.read(reg::MAGIC_VALUE, &mut b);
        assert_eq!(b, [0, 0]);
        let mut b = [0xff; 4];
        d.t.read(reg::MAGIC_VALUE + 1, &mut b);
        assert_eq!(b, [0; 4]);
        let mut b = [0xff; 8];
        d.t.read(reg::MAGIC_VALUE, &mut b);
        assert_eq!(b, [0; 8]);
        // Narrow and unaligned writes are ignored.
        d.t.write(reg::STATUS, &[1]);
        d.t.write(reg::STATUS + 1, &[1, 0, 0, 0]);
        d.t.write(reg::STATUS, &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d.read32(reg::STATUS), 0);
        // Writes to read-only registers are ignored.
        d.write32(reg::MAGIC_VALUE, 0);
        assert_eq!(d.read32(reg::MAGIC_VALUE), 0x7472_6976);
        // Config space: any width, any alignment; zero past the end.
        let mut b = [0; 1];
        d.t.read(reg::CONFIG + 3, &mut b);
        assert_eq!(b, [0x44]);
        let mut b = [0; 2];
        d.t.read(reg::CONFIG + 7, &mut b);
        assert_eq!(b, [0x88, 0]);
        let mut b = [0; 8];
        d.t.read(reg::CONFIG, &mut b);
        assert_eq!(u64::from_le_bytes(b), 0x8877_6655_4433_2211);
        d.t.write(reg::CONFIG + 5, &[9]);
        assert_eq!(log.lock().unwrap().config_writes, [(5, vec![9])]);
    }

    #[test]
    fn full_handshake_and_notify() {
        let (mut d, log) = test_driver(false);
        assert!(d.negotiate(features::VERSION_1 | 0b100));
        assert_eq!(
            d.read32(reg::STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK
        );
        d.setup_queue(0, 16);
        d.setup_queue(1, 8);
        // QueueNotify before DRIVER_OK is not forwarded.
        d.write32(reg::QUEUE_NOTIFY, 0);
        d.driver_ok();
        assert_eq!(d.read32(reg::STATUS) & status::DRIVER_OK, status::DRIVER_OK);
        {
            let log = log.lock().unwrap();
            assert_eq!(log.activations, [vec![true, true]]);
            assert_eq!(log.features, features::VERSION_1 | 0b100);
            assert!(log.notifies.is_empty());
        }
        d.write32(reg::QUEUE_SEL, 1);
        assert_eq!(d.read32(reg::QUEUE_READY), 1);
        d.write32(reg::QUEUE_NOTIFY, 1);
        d.write32(reg::QUEUE_NOTIFY, 0);
        d.write32(reg::QUEUE_NOTIFY, 2); // no such queue
        d.write32(reg::QUEUE_NOTIFY, 0x1_0000);
        assert_eq!(log.lock().unwrap().notifies, [1, 0]);
        // Queue configuration is frozen after DRIVER_OK.
        d.write32(reg::QUEUE_SEL, 0);
        d.write32(reg::QUEUE_READY, 0);
        assert_eq!(d.read32(reg::QUEUE_READY), 1);
    }

    #[test]
    fn only_enabled_queues_are_passed() {
        let (mut d, log) = test_driver(false);
        assert!(d.negotiate(features::VERSION_1));
        d.setup_queue(1, 4);
        d.driver_ok();
        assert_eq!(log.lock().unwrap().activations, [vec![false, true]]);
        d.write32(reg::QUEUE_NOTIFY, 0);
        d.write32(reg::QUEUE_NOTIFY, 1);
        assert_eq!(log.lock().unwrap().notifies, [1]);
    }

    #[test]
    fn rejects_driver_without_version_1() {
        let (mut d, log) = test_driver(false);
        assert!(!d.negotiate(0b1));
        assert_eq!(d.read32(reg::STATUS) & status::FEATURES_OK, 0);
        // DRIVER_OK without FEATURES_OK does not activate.
        d.setup_queue(0, 4);
        d.driver_ok();
        assert_eq!(d.read32(reg::STATUS) & status::DRIVER_OK, 0);
        assert!(log.lock().unwrap().activations.is_empty());
        // The driver may retry with acceptable features.
        assert!(d.negotiate(features::VERSION_1));
    }

    #[test]
    fn rejects_unoffered_features() {
        let (mut d, _) = test_driver(false);
        assert!(!d.negotiate(features::VERSION_1 | 0b10));
        assert!(!d.negotiate(features::VERSION_1 | features::RING_EVENT_IDX));
        assert!(d.negotiate(features::VERSION_1 | features::RING_INDIRECT_DESC | 1));
        // Feature writes after FEATURES_OK are ignored.
        d.write32(reg::DRIVER_FEATURES_SEL, 1);
        d.write32(reg::DRIVER_FEATURES, 0);
        assert_eq!(
            d.t.driver_features & features::VERSION_1,
            features::VERSION_1
        );
    }

    #[test]
    fn invalid_queue_layouts_are_refused() {
        let (mut d, log) = test_driver(false);
        assert!(d.negotiate(features::VERSION_1));
        let q = |d: &mut Driver, size: u32, desc: u64| {
            d.write32(reg::QUEUE_SEL, 0);
            d.write32(reg::QUEUE_NUM, size);
            d.write64(reg::QUEUE_DESC_LOW, desc);
            d.write64(reg::QUEUE_DRIVER_LOW, MEM_BASE + 0x1000);
            d.write64(reg::QUEUE_DEVICE_LOW, MEM_BASE + 0x2000);
            d.write32(reg::QUEUE_READY, 1);
            d.read32(reg::QUEUE_READY)
        };
        assert_eq!(q(&mut d, 32, MEM_BASE), 0); // > QueueNumMax
        assert_eq!(q(&mut d, 6, MEM_BASE), 0); // not a power of two
        assert_eq!(q(&mut d, 0, MEM_BASE), 0);
        assert_eq!(q(&mut d, 0x1_0010, MEM_BASE), 0); // clamped to 65535, refused
        assert_eq!(q(&mut d, 8, MEM_BASE + 8), 0); // misaligned
        assert_eq!(q(&mut d, 8, 0x10), 0); // outside RAM
        assert_eq!(q(&mut d, 8, MEM_BASE), 1);
        // Once enabled, the configuration is locked until QueueReady = 0.
        d.write32(reg::QUEUE_NUM, 4);
        assert_eq!(d.t.queues[0].size, 8);
        d.write32(reg::QUEUE_READY, 0);
        d.write32(reg::QUEUE_NUM, 4);
        assert_eq!(d.t.queues[0].size, 4);
        // The refused layouts never reached the device.
        d.write32(reg::QUEUE_READY, 0);
        d.driver_ok();
        assert_eq!(log.lock().unwrap().activations, [vec![false, false]]);
    }

    #[test]
    fn activation_failure_sets_needs_reset() {
        let (mut d, log) = test_driver(true);
        assert!(d.negotiate(features::VERSION_1));
        d.setup_queue(0, 4);
        d.driver_ok();
        assert_eq!(log.lock().unwrap().activations.len(), 1);
        assert_eq!(
            d.read32(reg::STATUS) & status::DEVICE_NEEDS_RESET,
            status::DEVICE_NEEDS_RESET
        );
        assert_eq!(d.read32(reg::INTERRUPT_STATUS), INT_CONFIG);
        assert!(d.irq.level());
        d.write32(reg::QUEUE_NOTIFY, 0);
        assert!(log.lock().unwrap().notifies.is_empty());
    }

    #[test]
    fn interrupt_status_and_ack() {
        let (mut d, log) = test_driver(false);
        d.start(&[4, 4]);
        let int = log.lock().unwrap().interrupt.clone().unwrap();
        assert_eq!(d.read32(reg::INTERRUPT_STATUS), 0);
        assert!(!d.irq.level());
        int.signal_used();
        assert_eq!(d.read32(reg::INTERRUPT_STATUS), INT_USED);
        assert!(d.irq.level());
        int.signal_config();
        assert_eq!(d.read32(reg::CONFIG_GENERATION), 1);
        assert_eq!(d.read32(reg::INTERRUPT_STATUS), INT_USED | INT_CONFIG);
        d.write32(reg::INTERRUPT_ACK, INT_USED);
        assert!(d.irq.level());
        d.write32(reg::INTERRUPT_ACK, INT_CONFIG);
        assert!(!d.irq.level());
        assert_eq!(d.irq.transitions(), [true, false]);
    }

    #[test]
    fn reset_clears_everything() {
        let (mut d, log) = test_driver(false);
        d.start(&[4, 4]);
        let int = log.lock().unwrap().interrupt.clone().unwrap();
        let resets = log.lock().unwrap().resets;
        int.signal_used();
        int.set_needs_reset();
        assert_ne!(d.read32(reg::STATUS) & status::DEVICE_NEEDS_RESET, 0);
        // The driver cannot set NEEDS_RESET or clear bits other than by reset.
        d.write32(reg::STATUS, status::ACKNOWLEDGE);
        assert_ne!(d.read32(reg::STATUS) & status::DRIVER_OK, 0);
        d.write32(reg::STATUS, 0);
        assert_eq!(d.read32(reg::STATUS), 0);
        assert_eq!(d.read32(reg::INTERRUPT_STATUS), 0);
        assert!(!d.irq.level());
        assert_eq!(log.lock().unwrap().resets, resets + 1);
        d.write32(reg::QUEUE_SEL, 0);
        assert_eq!(d.read32(reg::QUEUE_READY), 0);
        assert_eq!(d.t.driver_features, 0);
        d.write32(reg::QUEUE_NOTIFY, 0);
        assert!(log.lock().unwrap().notifies.is_empty());
        d.write32(
            reg::STATUS,
            status::DEVICE_NEEDS_RESET | status::ACKNOWLEDGE,
        );
        assert_eq!(d.read32(reg::STATUS), status::ACKNOWLEDGE);
        // Re-initialisation works.
        d.write32(reg::STATUS, 0);
        d.start(&[4, 4]);
        assert_eq!(log.lock().unwrap().activations.len(), 2);
    }

    #[test]
    fn failed_status_bit_is_kept() {
        let (mut d, _) = test_driver(false);
        d.write32(reg::STATUS, status::ACKNOWLEDGE);
        d.write32(reg::STATUS, status::ACKNOWLEDGE | status::FAILED);
        assert_eq!(d.read32(reg::STATUS), status::ACKNOWLEDGE | status::FAILED);
    }
}
