//! The arch-independent part of the Linux KVM userspace ABI that vemu uses:
//! ioctl request numbers, `#[repr(C)]` mirrors of the `linux/kvm.h` structs,
//! capability / exit / event numbers. Pure definitions, no system calls, so
//! they compile and are unit-tested on every host.
//!
//! Source of truth: `include/uapi/linux/kvm.h` (KVM_API_VERSION 12) and
//! `include/uapi/asm-generic/ioctl.h`. aarch64 and x86_64 both use the
//! generic ioctl encoding (`asm/ioctl.h` is `asm-generic/ioctl.h` on both).
//!
//! Verification: the `const` block at the end pins every struct's size and
//! field offsets on each target this crate is built for (both Linux targets
//! are checked by `scripts/check-linux.sh`), and `scripts/kvm-abi/check.sh`
//! compiles a C probe against the real kernel headers (bundled with zig) for
//! aarch64-linux and x86_64-linux that `_Static_assert`s every value in the
//! table built by [`tests::abi_table`]: sizes, offsets, ioctl numbers and
//! constants. Add new definitions to both.
//!
//! Arch-specific structs (`kvm_regs`, `kvm_vcpu_init`, ...) belong to
//! `kvm/aarch64.rs` / `kvm/x86_64.rs`; build their ioctl numbers with
//! [`ior`] / [`iow`] / [`iowr`] and check them in
//! `scripts/kvm-abi/probe-<arch>.h` (see `scripts/kvm-abi/probe.c`).

// Not every definition is used on every arch (some are for the arch modules).
#![allow(dead_code)]

use std::mem::size_of;

/// `KVM_API_VERSION`: what `KVM_GET_API_VERSION` must return.
pub(crate) const KVM_API_VERSION: i32 = 12;

/// The KVM ioctl type byte (`KVMIO`).
pub(crate) const KVMIO: u32 = 0xAE;

// --- ioctl encoding (asm-generic/ioctl.h) --------------------------------

pub(crate) const IOC_NRBITS: u32 = 8;
pub(crate) const IOC_TYPEBITS: u32 = 8;
pub(crate) const IOC_SIZEBITS: u32 = 14;
pub(crate) const IOC_NRSHIFT: u32 = 0;
pub(crate) const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
pub(crate) const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
pub(crate) const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
pub(crate) const IOC_NONE: u32 = 0;
/// Userspace writes, the kernel reads (`_IOW`).
pub(crate) const IOC_WRITE: u32 = 1;
/// The kernel writes, userspace reads (`_IOR`).
pub(crate) const IOC_READ: u32 = 2;

/// `_IOC(dir, type, nr, size)`. Fails to compile (in const context) if
/// `size` does not fit the 14-bit size field.
pub(crate) const fn ioc(dir: u32, ty: u32, nr: u32, size: usize) -> u32 {
    assert!(size < 1 << IOC_SIZEBITS, "ioctl argument too large");
    assert!(ty < 1 << IOC_TYPEBITS && nr < 1 << IOC_NRBITS);
    (dir << IOC_DIRSHIFT) | ((size as u32) << IOC_SIZESHIFT) | (ty << IOC_TYPESHIFT) | nr
}

/// `_IO(KVMIO, nr)`: no argument struct (an integer argument or none).
pub(crate) const fn io(nr: u32) -> u32 {
    ioc(IOC_NONE, KVMIO, nr, 0)
}

/// `_IOR(KVMIO, nr, T)`: the kernel fills a `T`.
pub(crate) const fn ior<T>(nr: u32) -> u32 {
    ioc(IOC_READ, KVMIO, nr, size_of::<T>())
}

/// `_IOW(KVMIO, nr, T)`: the kernel reads a `T`.
pub(crate) const fn iow<T>(nr: u32) -> u32 {
    ioc(IOC_WRITE, KVMIO, nr, size_of::<T>())
}

/// `_IOWR(KVMIO, nr, T)`: both directions.
pub(crate) const fn iowr<T>(nr: u32) -> u32 {
    ioc(IOC_READ | IOC_WRITE, KVMIO, nr, size_of::<T>())
}

/// `_IOC_SIZE(req)`: the argument size encoded in a request number.
pub(crate) const fn ioc_size(req: u32) -> usize {
    ((req >> IOC_SIZESHIFT) & ((1 << IOC_SIZEBITS) - 1)) as usize
}

/// `_IOC_DIR(req)`.
pub(crate) const fn ioc_dir(req: u32) -> u32 {
    (req >> IOC_DIRSHIFT) & 3
}

// --- structs -------------------------------------------------------------

/// `struct kvm_userspace_memory_region` (KVM_SET_USER_MEMORY_REGION).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmUserspaceMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    /// Bytes; 0 deletes the slot.
    pub memory_size: u64,
    pub userspace_addr: u64,
}

/// `struct kvm_irq_level` (KVM_IRQ_LINE). `irq` is a union with
/// `__s32 status` (KVM_IRQ_LINE_STATUS only, unused here).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmIrqLevel {
    /// x86: GSI. arm64: `type << 24 | vcpu_index << 16 | irq_id` (see api.rst
    /// KVM_IRQ_LINE; encoded by kvm/aarch64.rs).
    pub irq: u32,
    pub level: u32,
}

/// `struct kvm_mp_state` (KVM_GET/SET_MP_STATE).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmMpState {
    pub mp_state: u32,
}

/// `struct kvm_one_reg` (KVM_GET/SET_ONE_REG). `addr` points at a buffer of
/// the size encoded in `id` ([`KVM_REG_SIZE_MASK`]).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmOneReg {
    pub id: u64,
    pub addr: u64,
}

/// `struct kvm_enable_cap` (KVM_ENABLE_CAP on a VM or vCPU fd).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KvmEnableCap {
    pub cap: u32,
    pub flags: u32,
    pub args: [u64; 4],
    pub pad: [u8; 64],
}

impl Default for KvmEnableCap {
    fn default() -> KvmEnableCap {
        KvmEnableCap {
            cap: 0,
            flags: 0,
            args: [0; 4],
            pad: [0; 64],
        }
    }
}

/// `struct kvm_create_device` (KVM_CREATE_DEVICE; `fd` is an output).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmCreateDevice {
    /// `enum kvm_device_type`, e.g. KVM_DEV_TYPE_ARM_VGIC_V3.
    pub type_: u32,
    pub fd: u32,
    /// KVM_CREATE_DEVICE_TEST probes without creating.
    pub flags: u32,
}

/// `struct kvm_device_attr` (KVM_SET/GET/HAS_DEVICE_ATTR, on a device or
/// vCPU fd). `addr` is a userspace pointer to the attribute's value.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmDeviceAttr {
    pub flags: u32,
    pub group: u32,
    pub attr: u64,
    pub addr: u64,
}

/// `kvm_run.hw` (KVM_EXIT_UNKNOWN).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunHw {
    pub hardware_exit_reason: u64,
}

/// `kvm_run.fail_entry` (KVM_EXIT_FAIL_ENTRY).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunFailEntry {
    pub hardware_entry_failure_reason: u64,
    pub cpu: u32,
}

/// `kvm_run.ex` (KVM_EXIT_EXCEPTION).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunEx {
    pub exception: u32,
    pub error_code: u32,
}

/// `kvm_run.io` (KVM_EXIT_IO, x86 port I/O).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunIo {
    /// [`KVM_EXIT_IO_IN`] or [`KVM_EXIT_IO_OUT`].
    pub direction: u8,
    /// Bytes per element: 1, 2 or 4.
    pub size: u8,
    pub port: u16,
    /// Elements (> 1 for string I/O, `rep ins`/`outs`).
    pub count: u32,
    /// Offset of the packed data array from the start of `kvm_run`.
    pub data_offset: u64,
}

/// `kvm_run.mmio` (KVM_EXIT_MMIO).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunMmio {
    pub phys_addr: u64,
    /// Little-endian value: written by the guest (`is_write`), or to be
    /// filled by userspace before the next KVM_RUN (read).
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

/// `kvm_run.internal` (KVM_EXIT_INTERNAL_ERROR).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunInternal {
    pub suberror: u32,
    /// Valid words in `data` (KVM_CAP_INTERNAL_ERROR_DATA).
    pub ndata: u32,
    pub data: [u64; 16],
}

/// `kvm_run.system_event` (KVM_EXIT_SYSTEM_EVENT). `data[0]` is the
/// legacy `flags` (a union in C).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunSystemEvent {
    pub type_: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

/// `kvm_run.arm_nisv` (KVM_EXIT_ARM_NISV, only with
/// KVM_CAP_ARM_NISV_TO_USER enabled).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunArmNisv {
    pub esr_iss: u64,
    pub fault_ipa: u64,
}

/// `kvm_run.memory_fault` (KVM_EXIT_MEMORY_FAULT, reported with KVM_RUN
/// failing with EFAULT/EHWPOISON).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRunMemoryFault {
    pub flags: u64,
    pub gpa: u64,
    pub size: u64,
}

/// The exit-specific union of `struct kvm_run` (256 bytes). Every member is
/// plain data, so reading any of them is sound; which one is meaningful
/// depends on `exit_reason`. Arch code reads its own members (e.g.
/// `debug.arch`) through [`KvmRunUnion::padding`].
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union KvmRunUnion {
    pub hw: KvmRunHw,
    pub fail_entry: KvmRunFailEntry,
    pub ex: KvmRunEx,
    pub io: KvmRunIo,
    pub mmio: KvmRunMmio,
    pub internal: KvmRunInternal,
    pub system_event: KvmRunSystemEvent,
    pub arm_nisv: KvmRunArmNisv,
    pub memory_fault: KvmRunMemoryFault,
    pub padding: [u8; 256],
}

/// `struct kvm_run`, the per-vCPU page shared with the kernel (mmap of the
/// vCPU fd at offset 0, `KVM_GET_VCPU_MMAP_SIZE` bytes; on x86 the PIO data
/// page follows it). Accessed through raw pointers only (see
/// `kvm/exit.rs`, `RunPtr`): another thread writes `immediate_exit`.
#[repr(C)]
pub(crate) struct KvmRun {
    // in
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub padding1: [u8; 6],
    // out
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,
    // in (pre_kvm_run), out (post_kvm_run)
    pub cr8: u64,
    pub apic_base: u64,
    pub u: KvmRunUnion,
    pub kvm_valid_regs: u64,
    pub kvm_dirty_regs: u64,
    /// `union { struct kvm_sync_regs regs; char padding[2048]; } s`.
    pub s: [u8; SYNC_REGS_SIZE_BYTES],
}

/// `SYNC_REGS_SIZE_BYTES`.
pub(crate) const SYNC_REGS_SIZE_BYTES: usize = 2048;

// --- ioctl numbers ---------------------------------------------------------

// System ioctls (/dev/kvm).
pub(crate) const KVM_GET_API_VERSION: u32 = io(0x00);
pub(crate) const KVM_CREATE_VM: u32 = io(0x01);
pub(crate) const KVM_CHECK_EXTENSION: u32 = io(0x03);
pub(crate) const KVM_GET_VCPU_MMAP_SIZE: u32 = io(0x04);

// VM ioctls.
pub(crate) const KVM_CREATE_VCPU: u32 = io(0x41);
pub(crate) const KVM_SET_USER_MEMORY_REGION: u32 = iow::<KvmUserspaceMemoryRegion>(0x46);
pub(crate) const KVM_SET_TSS_ADDR: u32 = io(0x47);
pub(crate) const KVM_SET_IDENTITY_MAP_ADDR: u32 = iow::<u64>(0x48);
pub(crate) const KVM_CREATE_IRQCHIP: u32 = io(0x60);
pub(crate) const KVM_IRQ_LINE: u32 = iow::<KvmIrqLevel>(0x61);
pub(crate) const KVM_ENABLE_CAP: u32 = iow::<KvmEnableCap>(0xa3);
pub(crate) const KVM_CREATE_DEVICE: u32 = iowr::<KvmCreateDevice>(0xe0);
pub(crate) const KVM_SET_DEVICE_ATTR: u32 = iow::<KvmDeviceAttr>(0xe1);
pub(crate) const KVM_GET_DEVICE_ATTR: u32 = iow::<KvmDeviceAttr>(0xe2);
pub(crate) const KVM_HAS_DEVICE_ATTR: u32 = iow::<KvmDeviceAttr>(0xe3);

// vCPU ioctls.
pub(crate) const KVM_RUN: u32 = io(0x80);
pub(crate) const KVM_GET_MP_STATE: u32 = ior::<KvmMpState>(0x98);
pub(crate) const KVM_SET_MP_STATE: u32 = iow::<KvmMpState>(0x99);
pub(crate) const KVM_GET_ONE_REG: u32 = iow::<KvmOneReg>(0xab);
pub(crate) const KVM_SET_ONE_REG: u32 = iow::<KvmOneReg>(0xac);

// --- capabilities (KVM_CHECK_EXTENSION) --------------------------------------

pub(crate) const KVM_CAP_IRQCHIP: u32 = 0;
pub(crate) const KVM_CAP_USER_MEMORY: u32 = 3;
pub(crate) const KVM_CAP_NR_VCPUS: u32 = 9;
pub(crate) const KVM_CAP_NR_MEMSLOTS: u32 = 10;
pub(crate) const KVM_CAP_MAX_VCPUS: u32 = 66;
pub(crate) const KVM_CAP_CHECK_EXTENSION_VM: u32 = 105;
pub(crate) const KVM_CAP_MAX_VCPU_ID: u32 = 128;
pub(crate) const KVM_CAP_IMMEDIATE_EXIT: u32 = 136;
pub(crate) const KVM_CAP_ARM_VM_IPA_SIZE: u32 = 165;

// --- exit reasons (kvm_run.exit_reason) ----------------------------------

pub(crate) const KVM_EXIT_UNKNOWN: u32 = 0;
pub(crate) const KVM_EXIT_EXCEPTION: u32 = 1;
pub(crate) const KVM_EXIT_IO: u32 = 2;
pub(crate) const KVM_EXIT_HYPERCALL: u32 = 3;
pub(crate) const KVM_EXIT_DEBUG: u32 = 4;
pub(crate) const KVM_EXIT_HLT: u32 = 5;
pub(crate) const KVM_EXIT_MMIO: u32 = 6;
pub(crate) const KVM_EXIT_IRQ_WINDOW_OPEN: u32 = 7;
pub(crate) const KVM_EXIT_SHUTDOWN: u32 = 8;
pub(crate) const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub(crate) const KVM_EXIT_INTR: u32 = 10;
pub(crate) const KVM_EXIT_NMI: u32 = 16;
pub(crate) const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
pub(crate) const KVM_EXIT_SYSTEM_EVENT: u32 = 24;
pub(crate) const KVM_EXIT_IOAPIC_EOI: u32 = 26;
pub(crate) const KVM_EXIT_ARM_NISV: u32 = 28;
pub(crate) const KVM_EXIT_X86_RDMSR: u32 = 29;
pub(crate) const KVM_EXIT_X86_WRMSR: u32 = 30;
pub(crate) const KVM_EXIT_X86_BUS_LOCK: u32 = 33;
pub(crate) const KVM_EXIT_NOTIFY: u32 = 37;
pub(crate) const KVM_EXIT_MEMORY_FAULT: u32 = 39;

/// `kvm_run.io.direction`.
pub(crate) const KVM_EXIT_IO_IN: u8 = 0;
pub(crate) const KVM_EXIT_IO_OUT: u8 = 1;

/// `kvm_run.internal.suberror`.
pub(crate) const KVM_INTERNAL_ERROR_EMULATION: u32 = 1;
pub(crate) const KVM_INTERNAL_ERROR_SIMUL_EX: u32 = 2;
pub(crate) const KVM_INTERNAL_ERROR_DELIVERY_EV: u32 = 3;
pub(crate) const KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON: u32 = 4;

/// `kvm_run.system_event.type`.
pub(crate) const KVM_SYSTEM_EVENT_SHUTDOWN: u32 = 1;
pub(crate) const KVM_SYSTEM_EVENT_RESET: u32 = 2;
pub(crate) const KVM_SYSTEM_EVENT_CRASH: u32 = 3;
pub(crate) const KVM_SYSTEM_EVENT_WAKEUP: u32 = 4;
pub(crate) const KVM_SYSTEM_EVENT_SUSPEND: u32 = 5;
pub(crate) const KVM_SYSTEM_EVENT_SEV_TERM: u32 = 6;
pub(crate) const KVM_SYSTEM_EVENT_TDX_FATAL: u32 = 7;

/// `kvm_mp_state.mp_state` values used by vemu.
pub(crate) const KVM_MP_STATE_RUNNABLE: u32 = 0;
pub(crate) const KVM_MP_STATE_UNINITIALIZED: u32 = 1;
pub(crate) const KVM_MP_STATE_HALTED: u32 = 3;
pub(crate) const KVM_MP_STATE_STOPPED: u32 = 5;

/// KVM_GET/SET_ONE_REG id: size field (`KVM_REG_SIZE_MASK`, log2 of the
/// byte count at bit 52).
pub(crate) const KVM_REG_SIZE_SHIFT: u32 = 52;
pub(crate) const KVM_REG_SIZE_MASK: u64 = 0x00f0_0000_0000_0000;
pub(crate) const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;

/// Bytes of the register named by a ONE_REG id.
pub(crate) const fn one_reg_size(id: u64) -> usize {
    1 << ((id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT)
}

/// `kvm_userspace_memory_region.flags`.
pub(crate) const KVM_MEM_LOG_DIRTY_PAGES: u32 = 1 << 0;
pub(crate) const KVM_MEM_READONLY: u32 = 1 << 1;

/// Name of an exit reason, for error messages.
pub(crate) fn exit_reason_name(reason: u32) -> &'static str {
    match reason {
        KVM_EXIT_UNKNOWN => "KVM_EXIT_UNKNOWN",
        KVM_EXIT_EXCEPTION => "KVM_EXIT_EXCEPTION",
        KVM_EXIT_IO => "KVM_EXIT_IO",
        KVM_EXIT_HYPERCALL => "KVM_EXIT_HYPERCALL",
        KVM_EXIT_DEBUG => "KVM_EXIT_DEBUG",
        KVM_EXIT_HLT => "KVM_EXIT_HLT",
        KVM_EXIT_MMIO => "KVM_EXIT_MMIO",
        KVM_EXIT_IRQ_WINDOW_OPEN => "KVM_EXIT_IRQ_WINDOW_OPEN",
        KVM_EXIT_SHUTDOWN => "KVM_EXIT_SHUTDOWN",
        KVM_EXIT_FAIL_ENTRY => "KVM_EXIT_FAIL_ENTRY",
        KVM_EXIT_INTR => "KVM_EXIT_INTR",
        KVM_EXIT_NMI => "KVM_EXIT_NMI",
        KVM_EXIT_INTERNAL_ERROR => "KVM_EXIT_INTERNAL_ERROR",
        KVM_EXIT_SYSTEM_EVENT => "KVM_EXIT_SYSTEM_EVENT",
        KVM_EXIT_IOAPIC_EOI => "KVM_EXIT_IOAPIC_EOI",
        KVM_EXIT_ARM_NISV => "KVM_EXIT_ARM_NISV",
        KVM_EXIT_X86_RDMSR => "KVM_EXIT_X86_RDMSR",
        KVM_EXIT_X86_WRMSR => "KVM_EXIT_X86_WRMSR",
        KVM_EXIT_X86_BUS_LOCK => "KVM_EXIT_X86_BUS_LOCK",
        KVM_EXIT_NOTIFY => "KVM_EXIT_NOTIFY",
        KVM_EXIT_MEMORY_FAULT => "KVM_EXIT_MEMORY_FAULT",
        _ => "unknown exit reason",
    }
}

// --- layout pins (checked at compile time on every target) ----------------
//
// The same values are checked against the kernel headers by
// scripts/kvm-abi/check.sh (the C probe gets them from tests::abi_table, run
// on the build host); pinning them here makes sure every target computes
// the same layout as that host.
const _: () = {
    use std::mem::{align_of, offset_of};
    assert!(size_of::<KvmUserspaceMemoryRegion>() == 32);
    assert!(offset_of!(KvmUserspaceMemoryRegion, guest_phys_addr) == 8);
    assert!(offset_of!(KvmUserspaceMemoryRegion, memory_size) == 16);
    assert!(offset_of!(KvmUserspaceMemoryRegion, userspace_addr) == 24);
    assert!(size_of::<KvmIrqLevel>() == 8);
    assert!(size_of::<KvmMpState>() == 4);
    assert!(size_of::<KvmOneReg>() == 16);
    assert!(size_of::<KvmEnableCap>() == 104);
    assert!(offset_of!(KvmEnableCap, args) == 8);
    assert!(offset_of!(KvmEnableCap, pad) == 40);
    assert!(size_of::<KvmCreateDevice>() == 12);
    assert!(size_of::<KvmDeviceAttr>() == 24);
    assert!(offset_of!(KvmDeviceAttr, attr) == 8);
    assert!(offset_of!(KvmDeviceAttr, addr) == 16);

    assert!(size_of::<KvmRunUnion>() == 256 && align_of::<KvmRunUnion>() == 8);
    assert!(size_of::<KvmRunFailEntry>() == 16);
    assert!(size_of::<KvmRunIo>() == 16);
    assert!(offset_of!(KvmRunIo, size) == 1);
    assert!(offset_of!(KvmRunIo, port) == 2);
    assert!(offset_of!(KvmRunIo, count) == 4);
    assert!(offset_of!(KvmRunIo, data_offset) == 8);
    assert!(size_of::<KvmRunMmio>() == 24);
    assert!(offset_of!(KvmRunMmio, data) == 8);
    assert!(offset_of!(KvmRunMmio, len) == 16);
    assert!(offset_of!(KvmRunMmio, is_write) == 20);
    assert!(size_of::<KvmRunInternal>() == 136);
    assert!(offset_of!(KvmRunInternal, data) == 8);
    assert!(size_of::<KvmRunSystemEvent>() == 136);
    assert!(offset_of!(KvmRunSystemEvent, data) == 8);

    assert!(size_of::<KvmRun>() == 2352 && align_of::<KvmRun>() == 8);
    assert!(offset_of!(KvmRun, immediate_exit) == 1);
    assert!(offset_of!(KvmRun, exit_reason) == 8);
    assert!(offset_of!(KvmRun, ready_for_interrupt_injection) == 12);
    assert!(offset_of!(KvmRun, if_flag) == 13);
    assert!(offset_of!(KvmRun, flags) == 14);
    assert!(offset_of!(KvmRun, cr8) == 16);
    assert!(offset_of!(KvmRun, apic_base) == 24);
    assert!(offset_of!(KvmRun, u) == 32);
    assert!(offset_of!(KvmRun, kvm_valid_regs) == 288);
    assert!(offset_of!(KvmRun, kvm_dirty_regs) == 296);
    assert!(offset_of!(KvmRun, s) == 304);

    // Request numbers follow from the sizes above; spot-check the encoding.
    assert!(KVM_RUN == 0xae80);
    assert!(KVM_SET_USER_MEMORY_REGION == 0x4020_ae46);
    assert!(KVM_IRQ_LINE == 0x4008_ae61);
    assert!(KVM_CREATE_DEVICE == 0xc00c_aee0);
    assert!(KVM_GET_MP_STATE == 0x8004_ae98);
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::mem::offset_of;

    /// Every value the C probe checks: `(C expression, Rust value)`. The C
    /// side evaluates the expression against `<linux/kvm.h>` for each Linux
    /// target and `_Static_assert`s equality.
    pub(crate) fn abi_table() -> Vec<(String, u64)> {
        let mut t: Vec<(String, u64)> = Vec::new();
        let mut v = |e: &str, x: u64| t.push((e.to_string(), x));
        macro_rules! size {
            ($c:literal, $t:ty) => {
                v(concat!("sizeof(", $c, ")"), size_of::<$t>() as u64)
            };
        }
        macro_rules! off {
            ($c:literal, $t:ty, $f:ident) => {
                v(
                    concat!("offsetof(", $c, ", ", stringify!($f), ")"),
                    offset_of!($t, $f) as u64,
                )
            };
        }
        macro_rules! run_off {
            ($c:literal, $t:ty, $f:ident) => {
                v(
                    concat!("offsetof(struct kvm_run, ", $c, ".", stringify!($f), ")"),
                    (offset_of!(KvmRun, u) + offset_of!($t, $f)) as u64,
                )
            };
        }
        macro_rules! val {
            ($($c:ident),* $(,)?) => { $( v(stringify!($c), $c as u64); )* };
        }

        size!(
            "struct kvm_userspace_memory_region",
            KvmUserspaceMemoryRegion
        );
        off!(
            "struct kvm_userspace_memory_region",
            KvmUserspaceMemoryRegion,
            slot
        );
        off!(
            "struct kvm_userspace_memory_region",
            KvmUserspaceMemoryRegion,
            flags
        );
        off!(
            "struct kvm_userspace_memory_region",
            KvmUserspaceMemoryRegion,
            guest_phys_addr
        );
        off!(
            "struct kvm_userspace_memory_region",
            KvmUserspaceMemoryRegion,
            memory_size
        );
        off!(
            "struct kvm_userspace_memory_region",
            KvmUserspaceMemoryRegion,
            userspace_addr
        );
        size!("struct kvm_irq_level", KvmIrqLevel);
        off!("struct kvm_irq_level", KvmIrqLevel, irq);
        off!("struct kvm_irq_level", KvmIrqLevel, level);
        size!("struct kvm_mp_state", KvmMpState);
        size!("struct kvm_one_reg", KvmOneReg);
        off!("struct kvm_one_reg", KvmOneReg, id);
        off!("struct kvm_one_reg", KvmOneReg, addr);
        size!("struct kvm_enable_cap", KvmEnableCap);
        off!("struct kvm_enable_cap", KvmEnableCap, cap);
        off!("struct kvm_enable_cap", KvmEnableCap, flags);
        off!("struct kvm_enable_cap", KvmEnableCap, args);
        off!("struct kvm_enable_cap", KvmEnableCap, pad);
        size!("struct kvm_create_device", KvmCreateDevice);
        v(
            "offsetof(struct kvm_create_device, type)",
            offset_of!(KvmCreateDevice, type_) as u64,
        );
        off!("struct kvm_create_device", KvmCreateDevice, fd);
        off!("struct kvm_create_device", KvmCreateDevice, flags);
        size!("struct kvm_device_attr", KvmDeviceAttr);
        off!("struct kvm_device_attr", KvmDeviceAttr, flags);
        off!("struct kvm_device_attr", KvmDeviceAttr, group);
        off!("struct kvm_device_attr", KvmDeviceAttr, attr);
        off!("struct kvm_device_attr", KvmDeviceAttr, addr);

        size!("struct kvm_run", KvmRun);
        off!("struct kvm_run", KvmRun, request_interrupt_window);
        off!("struct kvm_run", KvmRun, immediate_exit);
        off!("struct kvm_run", KvmRun, padding1);
        off!("struct kvm_run", KvmRun, exit_reason);
        off!("struct kvm_run", KvmRun, ready_for_interrupt_injection);
        off!("struct kvm_run", KvmRun, if_flag);
        off!("struct kvm_run", KvmRun, flags);
        off!("struct kvm_run", KvmRun, cr8);
        off!("struct kvm_run", KvmRun, apic_base);
        // The anonymous union starts at its first member.
        v("offsetof(struct kvm_run, hw)", offset_of!(KvmRun, u) as u64);
        v("sizeof(((struct kvm_run *)0)->padding)", 256);
        off!("struct kvm_run", KvmRun, kvm_valid_regs);
        off!("struct kvm_run", KvmRun, kvm_dirty_regs);
        off!("struct kvm_run", KvmRun, s);
        v(
            "sizeof(((struct kvm_run *)0)->s)",
            SYNC_REGS_SIZE_BYTES as u64,
        );
        run_off!("hw", KvmRunHw, hardware_exit_reason);
        run_off!("fail_entry", KvmRunFailEntry, hardware_entry_failure_reason);
        run_off!("fail_entry", KvmRunFailEntry, cpu);
        run_off!("ex", KvmRunEx, exception);
        run_off!("ex", KvmRunEx, error_code);
        run_off!("io", KvmRunIo, direction);
        run_off!("io", KvmRunIo, size);
        run_off!("io", KvmRunIo, port);
        run_off!("io", KvmRunIo, count);
        run_off!("io", KvmRunIo, data_offset);
        run_off!("mmio", KvmRunMmio, phys_addr);
        run_off!("mmio", KvmRunMmio, data);
        run_off!("mmio", KvmRunMmio, len);
        run_off!("mmio", KvmRunMmio, is_write);
        run_off!("internal", KvmRunInternal, suberror);
        run_off!("internal", KvmRunInternal, ndata);
        run_off!("internal", KvmRunInternal, data);
        v(
            "offsetof(struct kvm_run, system_event.type)",
            (offset_of!(KvmRun, u) + offset_of!(KvmRunSystemEvent, type_)) as u64,
        );
        run_off!("system_event", KvmRunSystemEvent, ndata);
        run_off!("system_event", KvmRunSystemEvent, data);
        v(
            "offsetof(struct kvm_run, system_event.flags)",
            (offset_of!(KvmRun, u) + offset_of!(KvmRunSystemEvent, data)) as u64,
        );
        run_off!("arm_nisv", KvmRunArmNisv, esr_iss);
        run_off!("arm_nisv", KvmRunArmNisv, fault_ipa);
        run_off!("memory_fault", KvmRunMemoryFault, flags);
        run_off!("memory_fault", KvmRunMemoryFault, gpa);
        run_off!("memory_fault", KvmRunMemoryFault, size);

        val!(
            KVM_API_VERSION,
            KVMIO,
            KVM_GET_API_VERSION,
            KVM_CREATE_VM,
            KVM_CHECK_EXTENSION,
            KVM_GET_VCPU_MMAP_SIZE,
            KVM_CREATE_VCPU,
            KVM_SET_USER_MEMORY_REGION,
            KVM_SET_TSS_ADDR,
            KVM_SET_IDENTITY_MAP_ADDR,
            KVM_CREATE_IRQCHIP,
            KVM_IRQ_LINE,
            KVM_ENABLE_CAP,
            KVM_CREATE_DEVICE,
            KVM_SET_DEVICE_ATTR,
            KVM_GET_DEVICE_ATTR,
            KVM_HAS_DEVICE_ATTR,
            KVM_RUN,
            KVM_GET_MP_STATE,
            KVM_SET_MP_STATE,
            KVM_GET_ONE_REG,
            KVM_SET_ONE_REG,
            KVM_CAP_IRQCHIP,
            KVM_CAP_USER_MEMORY,
            KVM_CAP_NR_VCPUS,
            KVM_CAP_NR_MEMSLOTS,
            KVM_CAP_MAX_VCPUS,
            KVM_CAP_CHECK_EXTENSION_VM,
            KVM_CAP_MAX_VCPU_ID,
            KVM_CAP_IMMEDIATE_EXIT,
            KVM_CAP_ARM_VM_IPA_SIZE,
            KVM_EXIT_UNKNOWN,
            KVM_EXIT_EXCEPTION,
            KVM_EXIT_IO,
            KVM_EXIT_HYPERCALL,
            KVM_EXIT_DEBUG,
            KVM_EXIT_HLT,
            KVM_EXIT_MMIO,
            KVM_EXIT_IRQ_WINDOW_OPEN,
            KVM_EXIT_SHUTDOWN,
            KVM_EXIT_FAIL_ENTRY,
            KVM_EXIT_INTR,
            KVM_EXIT_NMI,
            KVM_EXIT_INTERNAL_ERROR,
            KVM_EXIT_SYSTEM_EVENT,
            KVM_EXIT_IOAPIC_EOI,
            KVM_EXIT_ARM_NISV,
            KVM_EXIT_X86_RDMSR,
            KVM_EXIT_X86_WRMSR,
            KVM_EXIT_X86_BUS_LOCK,
            KVM_EXIT_NOTIFY,
            KVM_EXIT_MEMORY_FAULT,
            KVM_EXIT_IO_IN,
            KVM_EXIT_IO_OUT,
            KVM_INTERNAL_ERROR_EMULATION,
            KVM_INTERNAL_ERROR_SIMUL_EX,
            KVM_INTERNAL_ERROR_DELIVERY_EV,
            KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON,
            KVM_SYSTEM_EVENT_SHUTDOWN,
            KVM_SYSTEM_EVENT_RESET,
            KVM_SYSTEM_EVENT_CRASH,
            KVM_SYSTEM_EVENT_WAKEUP,
            KVM_SYSTEM_EVENT_SUSPEND,
            KVM_SYSTEM_EVENT_SEV_TERM,
            KVM_SYSTEM_EVENT_TDX_FATAL,
            KVM_MP_STATE_RUNNABLE,
            KVM_MP_STATE_UNINITIALIZED,
            KVM_MP_STATE_HALTED,
            KVM_MP_STATE_STOPPED,
            KVM_REG_SIZE_SHIFT,
            KVM_REG_SIZE_MASK,
            KVM_REG_SIZE_U64,
            KVM_MEM_LOG_DIRTY_PAGES,
            KVM_MEM_READONLY,
            SYNC_REGS_SIZE_BYTES,
        );
        // The generic encoding itself, through the C macros.
        v(
            "_IOC(_IOC_READ|_IOC_WRITE, 0x12, 0x34, 0x567)",
            u64::from(ioc(3, 0x12, 0x34, 0x567)),
        );
        v(
            "_IOC_SIZE(KVM_SET_USER_MEMORY_REGION)",
            ioc_size(KVM_SET_USER_MEMORY_REGION) as u64,
        );
        v(
            "_IOC_DIR(KVM_CREATE_DEVICE)",
            u64::from(ioc_dir(KVM_CREATE_DEVICE)),
        );
        t
    }

    /// Writes the C probe's input header to `$VEMU_KVM_ABI_HEADER` (used by
    /// scripts/kvm-abi/check.sh); without the variable it only checks that
    /// the table is well formed.
    #[test]
    fn c_header() {
        let table = abi_table();
        let mut seen = std::collections::HashSet::new();
        let mut out =
            String::from("/* Generated by vemu-hv kvm::abi::tests::c_header -- do not edit. */\n");
        for (expr, val) in &table {
            assert!(seen.insert(expr.clone()), "duplicate entry {expr}");
            out.push_str(&format!("VEMU_CHECK({expr}, {val:#x}ULL)\n"));
        }
        if let Some(path) = std::env::var_os("VEMU_KVM_ABI_HEADER") {
            std::fs::write(&path, out).expect("write VEMU_KVM_ABI_HEADER");
        }
    }

    #[test]
    fn ioctl_encoding() {
        // Values from the Linux headers (also checked by the C probe).
        assert_eq!(KVM_GET_API_VERSION, 0xae00);
        assert_eq!(KVM_CREATE_VM, 0xae01);
        assert_eq!(KVM_CHECK_EXTENSION, 0xae03);
        assert_eq!(KVM_GET_VCPU_MMAP_SIZE, 0xae04);
        assert_eq!(KVM_CREATE_VCPU, 0xae41);
        assert_eq!(KVM_SET_USER_MEMORY_REGION, 0x4020_ae46);
        assert_eq!(KVM_SET_IDENTITY_MAP_ADDR, 0x4008_ae48);
        assert_eq!(KVM_IRQ_LINE, 0x4008_ae61);
        assert_eq!(KVM_RUN, 0xae80);
        assert_eq!(KVM_GET_MP_STATE, 0x8004_ae98);
        assert_eq!(KVM_SET_MP_STATE, 0x4004_ae99);
        assert_eq!(KVM_ENABLE_CAP, 0x4068_aea3);
        assert_eq!(KVM_GET_ONE_REG, 0x4010_aeab);
        assert_eq!(KVM_SET_ONE_REG, 0x4010_aeac);
        assert_eq!(KVM_CREATE_DEVICE, 0xc00c_aee0);
        assert_eq!(KVM_SET_DEVICE_ATTR, 0x4018_aee1);
        assert_eq!(KVM_HAS_DEVICE_ATTR, 0x4018_aee3);
        // Arch structs go through the same helpers: kvm_regs is 144 bytes
        // on x86_64 (KVM_GET_REGS = 0x8090ae81), kvm_vcpu_init 32 bytes on
        // arm64 (KVM_ARM_VCPU_INIT = 0x4020aeae).
        assert_eq!(ior::<[u64; 18]>(0x81), 0x8090_ae81);
        assert_eq!(iow::<[u32; 8]>(0xae), 0x4020_aeae);
        assert_eq!(ioc_size(0x8090_ae81), 144);
        assert_eq!(ioc_dir(KVM_CREATE_DEVICE), IOC_READ | IOC_WRITE);
        assert_eq!(ioc_dir(KVM_RUN), IOC_NONE);
    }

    #[test]
    fn one_reg_sizes() {
        assert_eq!(one_reg_size(KVM_REG_SIZE_U64 | 0x6000_0000_0010_0000), 8);
        // arm64 core register X0: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | CORE | 0.
        assert_eq!(one_reg_size(0x6030_0000_0010_0000), 8);
        // A 128-bit FP register (KVM_REG_SIZE_U128).
        assert_eq!(one_reg_size(0x6040_0000_0010_0054), 16);
        assert_eq!(one_reg_size(0x6020_0000_0000_0000), 4);
    }

    #[test]
    fn exit_names() {
        assert_eq!(exit_reason_name(KVM_EXIT_MMIO), "KVM_EXIT_MMIO");
        assert_eq!(exit_reason_name(9999), "unknown exit reason");
    }
}
