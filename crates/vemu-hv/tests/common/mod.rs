//! Harness shared by the integration tests: a small machine (VM + 2 MiB of
//! RAM at 0x4000_0000) running hand-written guest code assembled into the
//! test binary (`tests/guest/*.s`).
//!
//! HVF allows one VM per process, so each test binary has a single `#[test]`
//! that runs its scenarios in sequence.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use vemu_core::GuestMemory;
use vemu_hv::{BootState, Reg, Vcpu, VcpuExit, Vm, VmConfig};

pub const RAM_BASE: u64 = 0x4000_0000;
pub const RAM_SIZE: usize = 2 << 20;
/// Per-vCPU record areas (see `x20` in `guest/common.s`): vCPU i at
/// `RECORDS + i * 0x100`.
pub const RECORDS: u64 = RAM_BASE + 0x10_0000;
/// HVC immediate of the guest's "unexpected exception" vectors.
pub const HVC_GUEST_EXCEPTION: u16 = 0xdead;

unsafe extern "C" {
    static vemu_guest_start: u8;
    static vemu_guest_end: u8;
}

pub struct Machine {
    pub vm: Arc<dyn Vm>,
    pub mem: Arc<GuestMemory>,
}

impl Machine {
    /// Create the VM, map RAM and load the guest blob at `RAM_BASE`.
    pub fn new(cpus: usize) -> Machine {
        let vm = vemu_hv::create_vm(&VmConfig {
            cpus,
            ..VmConfig::default()
        })
        .expect("create_vm");
        let mem = GuestMemory::new(RAM_BASE, RAM_SIZE).expect("guest memory");
        vm.map_memory(&mem).expect("map_memory");
        // The VM keeps the memory it maps alive (its own reference).
        assert_eq!(Arc::strong_count(&mem), 2, "map_memory keeps a reference");
        mem.write(RAM_BASE, guest_blob()).expect("load guest code");
        Machine { vm, mem }
    }

    /// Guest-physical address of a guest code label.
    pub fn gpa(&self, label: *const u8) -> u64 {
        RAM_BASE + (label as u64 - guest_start() as u64)
    }

    pub fn record(&self, cpu: usize) -> u64 {
        RECORDS + cpu as u64 * 0x100
    }

    /// Last IRQ INTID and IRQ count recorded by vCPU `cpu`'s handler.
    pub fn irq_record(&self, cpu: usize) -> (u64, u64) {
        let r = self.record(cpu);
        (
            self.mem.read_u64(r).unwrap(),
            self.mem.read_u64(r + 8).unwrap(),
        )
    }

    pub fn clear_irq_record(&self, cpu: usize) {
        self.mem.zero(self.record(cpu), 16).unwrap();
    }

    /// Create vCPU `index` on the calling thread and point its x20 at its
    /// record area.
    pub fn vcpu(&self, index: usize) -> Box<dyn Vcpu> {
        let mut v = self.vm.create_vcpu(index).expect("create_vcpu");
        v.set_reg(Reg::X(20), self.record(index)).unwrap();
        v
    }
}

fn guest_start() -> *const u8 {
    &raw const vemu_guest_start
}

fn guest_blob() -> &'static [u8] {
    let start = guest_start();
    // SAFETY: both labels delimit one contiguous range of the test binary's
    // __text section (start < end, same section), readable for its lifetime.
    unsafe {
        let end = &raw const vemu_guest_end;
        std::slice::from_raw_parts(start, end as usize - start as usize)
    }
}

/// Address of a guest label, for `Machine::gpa`.
#[macro_export]
macro_rules! label {
    ($sym:ident) => {{
        unsafe extern "C" {
            static $sym: u8;
        }
        &raw const $sym
    }};
}

/// Point `vcpu` at `entry` (EL1h, all exceptions masked).
pub fn start_at(vcpu: &mut dyn Vcpu, entry: u64) {
    vcpu.set_reg(Reg::Pc, entry).unwrap();
    vcpu.set_reg(Reg::Cpsr, 0x3c5).unwrap();
}

/// Power `vcpu` on at `entry` with X0 = `x0`, as the VMM does for the boot
/// CPU (secondaries otherwise wait for PSCI CPU_ON in `run()`).
pub fn boot_at(vcpu: &mut dyn Vcpu, entry: u64, x0: u64) {
    vcpu.set_boot_state(&BootState { pc: entry, x0 }).unwrap();
}

/// Run until the next exit and require it to be `HVC #imm`. Returns X1.
pub fn expect_hvc(vcpu: &mut dyn Vcpu, imm: u16) -> u64 {
    let exit = vcpu.run().expect("run");
    check_guest_exception(vcpu, exit);
    assert_eq!(
        exit,
        VcpuExit::Hvc { imm },
        "vCPU {}: unexpected exit",
        vcpu.index()
    );
    vcpu.get_reg(Reg::X(1)).unwrap()
}

/// Fail with the guest's ESR/ELR if `exit` is the guest's own exception report.
pub fn check_guest_exception(vcpu: &dyn Vcpu, exit: VcpuExit) {
    if exit
        == (VcpuExit::Hvc {
            imm: HVC_GUEST_EXCEPTION,
        })
    {
        panic!(
            "vCPU {}: guest took an unexpected exception: ESR_EL1={:#x} ELR_EL1={:#x}",
            vcpu.index(),
            vcpu.get_reg(Reg::X(1)).unwrap(),
            vcpu.get_reg(Reg::X(2)).unwrap()
        );
    }
}

/// Abort the whole test process if it is still running after `limit` (a hung
/// vCPU would otherwise hang the test run).
pub fn watchdog(limit: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        eprintln!("watchdog: test still running after {limit:?}, aborting");
        std::process::abort();
    });
}
