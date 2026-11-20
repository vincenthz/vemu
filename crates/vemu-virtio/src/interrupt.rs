//! Interrupt state shared by a transport and its device.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vemu_core::IrqLine;

use crate::lock;

/// `InterruptStatus` bit: the device used a buffer.
pub const INT_USED: u32 = 1 << 0;
/// `InterruptStatus` bit: the device configuration changed.
pub const INT_CONFIG: u32 = 1 << 1;

/// A virtio device's interrupt: the `InterruptStatus` register, the
/// `DEVICE_NEEDS_RESET` flag, the configuration generation counter and the
/// level-triggered line they drive (level = status != 0).
///
/// Shared (`Arc`) between the transport and its device; callable from any
/// thread.
pub struct Interrupt {
    irq: Arc<dyn IrqLine>,
    /// `InterruptStatus`. The line level only changes while this is held, so
    /// status and level never disagree.
    status: Mutex<u32>,
    needs_reset: AtomicBool,
    config_generation: AtomicU32,
}

impl Interrupt {
    pub fn new(irq: Arc<dyn IrqLine>) -> Interrupt {
        Interrupt {
            irq,
            status: Mutex::new(0),
            needs_reset: AtomicBool::new(false),
            config_generation: AtomicU32::new(0),
        }
    }

    /// Used-buffer notification. Devices call it after adding used elements
    /// when [`crate::Queue::needs_interrupt`] says the driver wants one.
    pub fn signal_used(&self) {
        self.raise(INT_USED);
    }

    /// Configuration-change notification after the device changed its
    /// configuration space (bumps `ConfigGeneration`).
    pub fn signal_config(&self) {
        self.config_generation.fetch_add(1, Ordering::AcqRel);
        self.raise(INT_CONFIG);
    }

    /// Set `DEVICE_NEEDS_RESET` and notify the driver (virtio 1.2 §2.1.2).
    pub fn set_needs_reset(&self) {
        if !self.needs_reset.swap(true, Ordering::AcqRel) {
            self.raise(INT_CONFIG);
        }
    }

    pub fn needs_reset(&self) -> bool {
        self.needs_reset.load(Ordering::Acquire)
    }

    pub(crate) fn status(&self) -> u32 {
        *lock(&self.status)
    }

    pub(crate) fn config_generation(&self) -> u32 {
        self.config_generation.load(Ordering::Acquire)
    }

    /// `InterruptACK`: clear `bits`, lowering the line once nothing is pending.
    pub(crate) fn ack(&self, bits: u32) {
        let mut status = lock(&self.status);
        let was = *status;
        *status &= !bits;
        if was != 0 && *status == 0 {
            self.irq.set_level(false);
        }
    }

    /// Device reset: clear everything and lower the line.
    pub(crate) fn reset(&self) {
        let mut status = lock(&self.status);
        self.needs_reset.store(false, Ordering::Release);
        if *status != 0 {
            *status = 0;
            self.irq.set_level(false);
        }
    }

    fn raise(&self, bits: u32) {
        let mut status = lock(&self.status);
        let was = *status;
        *status |= bits;
        if was == 0 {
            self.irq.set_level(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeIrq;

    #[test]
    fn level_follows_status() {
        let irq = FakeIrq::new();
        let int = Interrupt::new(irq.clone());
        int.signal_used();
        int.signal_used();
        assert_eq!(int.status(), INT_USED);
        assert_eq!(irq.transitions(), [true]);
        int.signal_config();
        assert_eq!(int.status(), INT_USED | INT_CONFIG);
        assert_eq!(int.config_generation(), 1);
        int.ack(INT_USED);
        assert!(irq.level());
        int.ack(INT_CONFIG);
        assert!(!irq.level());
        assert_eq!(irq.transitions(), [true, false]);
        // ACK of nothing pending does not touch the line.
        int.ack(INT_USED);
        assert_eq!(irq.transitions(), [true, false]);

        int.set_needs_reset();
        int.set_needs_reset();
        assert!(int.needs_reset());
        assert_eq!(int.status(), INT_CONFIG);
        int.reset();
        assert!(!int.needs_reset());
        assert_eq!(int.status(), 0);
        assert_eq!(irq.transitions(), [true, false, true, false]);
    }
}
