//! Interrupt lines into the VM's in-kernel interrupt controller.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use vemu_core::IrqLine;
use vemu_hv::Vm;

/// A level-triggered line wired to interrupt `irq` of the VM (aarch64: a GIC
/// SPI INTID; x86_64: an IOAPIC GSI).
///
/// `Vm::set_irq_line` may be called from any thread and wakes an idle vCPU,
/// which is exactly the `IrqLine` contract.
pub struct VmIrqLine {
    vm: Arc<dyn Vm>,
    irq: u32,
    warned: AtomicBool,
}

impl VmIrqLine {
    pub fn new(vm: Arc<dyn Vm>, irq: u32) -> VmIrqLine {
        VmIrqLine {
            vm,
            irq,
            warned: AtomicBool::new(false),
        }
    }
}

impl IrqLine for VmIrqLine {
    fn set_level(&self, level: bool) {
        if let Err(e) = self.vm.set_irq_line(self.irq, level)
            && !self.warned.swap(true, Ordering::Relaxed)
        {
            crate::log!("cannot set interrupt {}: {e}", self.irq);
        }
    }
}
