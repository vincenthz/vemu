//! The x86 half of the KVM backend that needs no `/dev/kvm`: `#[repr(C)]`
//! mirrors of the x86 KVM UAPI structs (`asm/kvm.h`, `linux/kvm.h`) and the
//! pure vCPU / VM setup logic (CPUID fixups, boot MSRs, FPU, LAPIC LVTs,
//! long-mode boot sregs, GSI routing, register access, fault description).
//!
//! It compiles on every host so the logic is unit-tested on the Mac; the
//! ioctls that use it live in `kvm/x86_64.rs` (Linux/x86_64 only). Struct
//! layouts are pinned by the const block at the end and checked against
//! the kernel headers by `scripts/kvm-abi/probe-x86_64.h` (same literals).
//!
//! References: Documentation/virt/kvm/api.rst; Firecracker
//! (`arch/x86_64/{regs,msr,interrupts}.rs`, `cpu_config/x86_64/cpuid`),
//! QEMU (`kvm_pc_setup_irq_routing`), Intel SDM vol. 2A (CPUID) and 3C
//! (VM-entry checks on guest segment state).

use super::{
    BOOT_CR0, BOOT_CR4, BOOT_CS, BOOT_DS, BOOT_EFER, BOOT_GDT, BOOT_GDT_LIMIT, BOOT_RFLAGS,
    BootState, Reg, Segment,
};

// --- UAPI structs -------------------------------------------------------------

/// `struct kvm_regs` (KVM_GET/SET_REGS).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// `struct kvm_segment`: a segment register (selector + hidden part).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmSegment {
    pub base: u64,
    /// Byte limit (already scaled by `g`).
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

/// `struct kvm_dtable` (GDTR / IDTR).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

/// `struct kvm_sregs` (KVM_GET/SET_SREGS).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    /// IA32_APIC_BASE: KVM_SET_SREGS applies it, so always read-modify-write.
    pub apic_base: u64,
    /// Pending external interrupts (KVM_NR_INTERRUPTS bits); a set bit on
    /// KVM_SET_SREGS queues that vector.
    pub interrupt_bitmap: [u64; 4],
}

/// `struct kvm_fpu` (KVM_GET/SET_FPU), FXSAVE-like.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmFpu {
    pub fpr: [[u8; 16]; 8],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16]; 16],
    pub mxcsr: u32,
    pub pad2: u32,
}

/// `struct kvm_msr_entry`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmMsrEntry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}

/// `struct kvm_msrs` with room for `N` entries (KVM_GET/SET_MSRS; the ioctl
/// number is built from `KvmMsrs<0>`, the C struct without its flexible
/// array).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KvmMsrs<const N: usize> {
    pub nmsrs: u32,
    pub pad: u32,
    pub entries: [KvmMsrEntry; N],
}

/// `struct kvm_cpuid_entry2`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    /// [`KVM_CPUID_FLAG_SIGNIFCANT_INDEX`] when `index` selects a subleaf.
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

/// `struct kvm_cpuid2` with room for `N` entries (KVM_GET_SUPPORTED_CPUID,
/// KVM_SET_CPUID2; ioctl numbers from `KvmCpuid2<0>`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KvmCpuid2<const N: usize> {
    pub nent: u32,
    pub padding: u32,
    pub entries: [KvmCpuidEntry2; N],
}

/// `struct kvm_lapic_state` (KVM_GET/SET_LAPIC): the xAPIC register page.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KvmLapicState {
    pub regs: [u8; KVM_APIC_REG_SIZE],
}

impl Default for KvmLapicState {
    fn default() -> KvmLapicState {
        KvmLapicState {
            regs: [0; KVM_APIC_REG_SIZE],
        }
    }
}

/// `struct kvm_pit_config` (KVM_CREATE_PIT2).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmPitConfig {
    pub flags: u32,
    pub pad: [u32; 15],
}

/// `struct kvm_irq_routing_entry`. The C union `u` (8-byte aligned because
/// of its s390 member) is kept as words: for [`KVM_IRQ_ROUTING_IRQCHIP`],
/// `u[0]` is `irqchip.irqchip` and `u[1]` is `irqchip.pin`.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmIrqRoutingEntry {
    pub gsi: u32,
    pub type_: u32,
    pub flags: u32,
    pub pad: u32,
    pub u: [u32; 8],
}

/// `struct kvm_irq_routing` with room for `N` entries (KVM_SET_GSI_ROUTING;
/// ioctl number from `KvmIrqRouting<0>`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KvmIrqRouting<const N: usize> {
    pub nr: u32,
    pub flags: u32,
    pub entries: [KvmIrqRoutingEntry; N],
}

// --- constants -------------------------------------------------------------------

/// `KVM_APIC_REG_SIZE`.
pub(crate) const KVM_APIC_REG_SIZE: usize = 0x400;
/// `KVM_CPUID_FLAG_SIGNIFCANT_INDEX` (sic).
pub(crate) const KVM_CPUID_FLAG_SIGNIFCANT_INDEX: u32 = 1;
/// The kernel's `KVM_MAX_CPUID_ENTRIES` (arch/x86/include/asm/kvm_host.h):
/// KVM_SET_CPUID2 refuses more, KVM_GET_SUPPORTED_CPUID clamps to it.
pub(crate) const KVM_MAX_CPUID_ENTRIES: usize = 256;
/// `kvm_pit_config.flags`: KVM emulates port 0x61 (speaker / PIT gate 2).
pub(crate) const KVM_PIT_SPEAKER_DUMMY: u32 = 1;
/// `kvm_irq_routing_entry.type_`.
pub(crate) const KVM_IRQ_ROUTING_IRQCHIP: u32 = 1;
pub(crate) const KVM_IRQCHIP_PIC_MASTER: u32 = 0;
pub(crate) const KVM_IRQCHIP_PIC_SLAVE: u32 = 1;
pub(crate) const KVM_IRQCHIP_IOAPIC: u32 = 2;
/// `KVM_IOAPIC_NUM_PINS`.
pub(crate) const KVM_IOAPIC_NUM_PINS: u32 = 24;

/// KVM's real-mode helpers, in the 3 GiB-4 GiB hole (must be reserved in
/// the guest's e820, never RAM): the EPT identity-map page
/// (KVM_SET_IDENTITY_MAP_ADDR, one page) and the TSS (KVM_SET_TSS_ADDR,
/// three pages). Same values as Firecracker / cloud-hypervisor.
pub const KVM_IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;
pub const KVM_TSS_ADDR: u64 = 0xfffb_d000;
/// End of the range KVM uses at [`KVM_IDENTITY_MAP_ADDR`]..
pub const KVM_RESERVED_END: u64 = KVM_TSS_ADDR + 3 * 0x1000;

// MSRs (arch/x86/include/asm/msr-index.h).
pub(crate) const MSR_IA32_TSC: u32 = 0x10;
pub(crate) const MSR_IA32_SYSENTER_CS: u32 = 0x174;
pub(crate) const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
pub(crate) const MSR_IA32_SYSENTER_EIP: u32 = 0x176;
pub(crate) const MSR_IA32_MISC_ENABLE: u32 = 0x1a0;
pub(crate) const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 1 << 0;
/// Branch Trace Storage unavailable (read-only to the guest).
pub(crate) const MSR_IA32_MISC_ENABLE_BTS_UNAVAIL: u64 = 1 << 11;
/// Processor Event Based Sampling unavailable (read-only to the guest).
pub(crate) const MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL: u64 = 1 << 12;
/// The MISC_ENABLE value vemu writes: KVM's own vCPU reset value
/// (`kvm_vcpu_reset`: BTS and PEBS unavailable, since KVM does not
/// virtualize BTS) plus fast strings. A host-initiated KVM_SET_MSRS stores
/// the value as given, so writing FAST_STRING alone would clear the two
/// UNAVAIL bits; a guest seeing CPUID DS (which KVM offers on PEBS-via-EPT
/// hosts) would then enable BTS and take a #GP on its DEBUGCTL write.
pub(crate) const MISC_ENABLE_BOOT: u64 = MSR_IA32_MISC_ENABLE_FAST_STRING
    | MSR_IA32_MISC_ENABLE_BTS_UNAVAIL
    | MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL;
pub(crate) const MSR_MTRR_DEF_TYPE: u32 = 0x2ff;
/// MTRRdefType: MTRRs enabled (bit 11), default type write-back (6).
pub(crate) const MTRR_DEF_TYPE_ENABLE_WB: u64 = (1 << 11) | 6;
pub(crate) const MSR_STAR: u32 = 0xc000_0081;
pub(crate) const MSR_LSTAR: u32 = 0xc000_0082;
pub(crate) const MSR_CSTAR: u32 = 0xc000_0083;
pub(crate) const MSR_SYSCALL_MASK: u32 = 0xc000_0084;
pub(crate) const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

// Local APIC register offsets / LVT delivery modes.
pub(crate) const APIC_LVT0: usize = 0x350;
pub(crate) const APIC_LVT1: usize = 0x360;
pub(crate) const APIC_MODE_NMI: u32 = 0x4;
pub(crate) const APIC_MODE_EXTINT: u32 = 0x7;

// CPUID bits.
const CPUID_1_ECX_X2APIC: u32 = 1 << 21;
const CPUID_1_ECX_TSC_DEADLINE: u32 = 1 << 24;
const CPUID_1_ECX_HYPERVISOR: u32 = 1 << 31;
const CPUID_1_EDX_HTT: u32 = 1 << 28;
/// Leaf 0xB / 0x1F level types (ECX[15:8]).
const TOPO_LEVEL_SMT: u32 = 1;
const TOPO_LEVEL_CORE: u32 = 2;

/// The flat GDT descriptors the boot vCPU starts with (BOOT_GDT).
const BOOT_CODE: u64 = BOOT_GDT[BOOT_CS as usize / 8];
const BOOT_DATA: u64 = BOOT_GDT[BOOT_DS as usize / 8];

// --- CPUID -----------------------------------------------------------------------

/// CPU vendor from leaf 0's signature (EBX, EDX, ECX).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vendor {
    Intel,
    /// AMD or Hygon (same topology leaves).
    Amd,
    Other,
}

pub(crate) fn vendor(entries: &[KvmCpuidEntry2]) -> Vendor {
    let Some(e) = find(entries, 0, 0) else {
        return Vendor::Other;
    };
    let mut sig = [0u8; 12];
    sig[0..4].copy_from_slice(&e.ebx.to_le_bytes());
    sig[4..8].copy_from_slice(&e.edx.to_le_bytes());
    sig[8..12].copy_from_slice(&e.ecx.to_le_bytes());
    match &sig {
        b"GenuineIntel" => Vendor::Intel,
        b"AuthenticAMD" | b"HygonGenuine" => Vendor::Amd,
        _ => Vendor::Other,
    }
}

fn find(entries: &[KvmCpuidEntry2], function: u32, index: u32) -> Option<&KvmCpuidEntry2> {
    entries.iter().find(|e| {
        e.function == function
            && (e.index == index || e.flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX == 0)
    })
}

/// Bits needed to number `n` items 0..n (ceil(log2(n))).
pub(crate) const fn id_bits(n: u32) -> u32 {
    if n <= 1 {
        0
    } else {
        32 - (n - 1).leading_zeros()
    }
}

/// Replace bits `lo..=hi` of `v` with `x`.
const fn set_bits(v: u32, lo: u32, hi: u32, x: u32) -> u32 {
    let mask = (u32::MAX >> (31 - (hi - lo))) << lo;
    (v & !mask) | ((x << lo) & mask)
}

/// The CPUID table of vCPU `index` out of `cpus`, from KVM_GET_SUPPORTED_CPUID's
/// `supported`. The topology is one package of `cpus` single-thread cores
/// with APIC id = x2APIC id = `index` (what the MADT describes):
///
/// - leaf 1: initial APIC id (EBX[31:24]), logical processor count
///   (EBX[23:16]) with HTT iff `cpus > 1`, CLFLUSH size 64 bytes if
///   unreported, the hypervisor bit, x2APIC (the in-kernel LAPIC emulates
///   it), TSC deadline iff `tsc_deadline` (KVM_CAP_TSC_DEADLINE_TIMER;
///   older kernels do not report it in the supported table, newer ones
///   do);
/// - leaves 0xB and 0x1F (present when the host has them): rebuilt, SMT
///   level (1 thread) + core level (`cpus`), x2APIC id in EDX;
/// - Intel leaf 4 / AMD leaf 0x8000_001D: cache sharing (L1/L2 per core,
///   L3 by all) and, on Intel, cores per package;
/// - AMD leaves 0x8000_0008 (ECX core count / APIC id size) and
///   0x8000_001E (extended APIC id, core id);
/// - everything else, including KVM's 0x4000_0000 leaves, unchanged.
pub(crate) fn cpuid_for_vcpu(
    supported: &[KvmCpuidEntry2],
    index: u32,
    cpus: u32,
    tsc_deadline: bool,
) -> Result<Vec<KvmCpuidEntry2>, String> {
    if cpus == 0 || index >= cpus {
        return Err(format!("vCPU {index} out of {cpus}"));
    }
    if cpus > 255 {
        // Leaf 1 EBX[31:24] holds the initial (xAPIC) id.
        return Err(format!("{cpus} vCPUs: at most 255 have an xAPIC id"));
    }
    let vendor = vendor(supported);
    let core_bits = id_bits(cpus);
    let mut out = Vec::with_capacity(supported.len() + 6);
    let mut topo_leaves = Vec::new();
    for e in supported {
        let mut e = *e;
        match e.function {
            1 => {
                e.ebx = set_bits(e.ebx, 24, 31, index);
                e.ebx = set_bits(e.ebx, 16, 23, cpus);
                if (e.ebx >> 8) & 0xff == 0 {
                    e.ebx = set_bits(e.ebx, 8, 15, 8); // 8 * 8 = 64-byte lines
                }
                e.ecx |= CPUID_1_ECX_HYPERVISOR | CPUID_1_ECX_X2APIC;
                if tsc_deadline {
                    e.ecx |= CPUID_1_ECX_TSC_DEADLINE;
                } else {
                    e.ecx &= !CPUID_1_ECX_TSC_DEADLINE;
                }
                if cpus > 1 {
                    e.edx |= CPUID_1_EDX_HTT;
                } else {
                    e.edx &= !CPUID_1_EDX_HTT;
                }
            }
            4 if vendor == Vendor::Intel && e.eax & 0x1f != 0 => {
                e.eax = cache_sharing(e.eax, cpus);
                e.eax = set_bits(e.eax, 26, 31, (cpus - 1).min(63));
            }
            0x8000_001d if vendor == Vendor::Amd && e.eax & 0x1f != 0 => {
                e.eax = cache_sharing(e.eax, cpus);
            }
            0xb | 0x1f => {
                if !topo_leaves.contains(&e.function) {
                    topo_leaves.push(e.function);
                }
                continue;
            }
            0x8000_0008 if vendor == Vendor::Amd => {
                e.ecx = set_bits(e.ecx, 0, 7, cpus - 1);
                e.ecx = set_bits(e.ecx, 12, 15, core_bits);
            }
            0x8000_001e if vendor == Vendor::Amd => {
                e.eax = index; // extended APIC id
                e.ebx = index & 0xff; // core id; threads per core - 1 = 0
                e.ecx = 0; // node 0, one node per package
                e.edx = 0;
            }
            _ => {}
        }
        out.push(e);
    }
    for function in topo_leaves {
        let level = |subleaf: u32, shift: u32, count: u32, kind: u32| KvmCpuidEntry2 {
            function,
            index: subleaf,
            flags: KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
            eax: shift,
            ebx: count,
            ecx: (kind << 8) | subleaf,
            edx: index,
            padding: [0; 3],
        };
        out.push(level(0, 0, 1, TOPO_LEVEL_SMT));
        out.push(level(1, core_bits, cpus, TOPO_LEVEL_CORE));
        out.push(level(2, 0, 0, 0)); // invalid level: end of the list
    }
    if out.len() > KVM_MAX_CPUID_ENTRIES {
        return Err(format!(
            "{} CPUID entries, KVM accepts at most {KVM_MAX_CPUID_ENTRIES}",
            out.len()
        ));
    }
    Ok(out)
}

/// Deterministic cache parameters (Intel leaf 4 / AMD 0x8000_001D) EAX:
/// logical processors sharing the cache - 1 in bits 25:14 (L1/L2 private
/// to the single-thread core, L3 shared by the package).
fn cache_sharing(eax: u32, cpus: u32) -> u32 {
    let level = (eax >> 5) & 7;
    match level {
        1 | 2 => set_bits(eax, 14, 25, 0),
        3 => set_bits(eax, 14, 25, (cpus - 1).min(0xfff)),
        _ => eax,
    }
}

// --- MSRs, FPU, LAPIC -----------------------------------------------------------

/// MSRs set on every vCPU at creation (as Firecracker): syscall/sysenter
/// state zero, TSC 0 (KVM treats a 0 write as "synchronize with the other
/// vCPUs"), fast strings on with KVM's BTS/PEBS-unavailable bits kept
/// ([`MISC_ENABLE_BOOT`]), MTRRs enabled with write-back default.
pub(crate) const BOOT_MSRS: [KvmMsrEntry; 11] = {
    const fn msr(index: u32, data: u64) -> KvmMsrEntry {
        KvmMsrEntry {
            index,
            reserved: 0,
            data,
        }
    }
    [
        msr(MSR_IA32_SYSENTER_CS, 0),
        msr(MSR_IA32_SYSENTER_ESP, 0),
        msr(MSR_IA32_SYSENTER_EIP, 0),
        msr(MSR_STAR, 0),
        msr(MSR_CSTAR, 0),
        msr(MSR_KERNEL_GS_BASE, 0),
        msr(MSR_SYSCALL_MASK, 0),
        msr(MSR_LSTAR, 0),
        msr(MSR_IA32_TSC, 0),
        msr(MSR_IA32_MISC_ENABLE, MISC_ENABLE_BOOT),
        msr(MSR_MTRR_DEF_TYPE, MTRR_DEF_TYPE_ENABLE_WB),
    ]
};

/// FPU state at creation: FCW 0x37f (all exceptions masked, extended
/// precision), MXCSR 0x1f80 (the reset values).
pub(crate) fn boot_fpu() -> KvmFpu {
    KvmFpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..KvmFpu::default()
    }
}

fn lapic_reg(l: &KvmLapicState, off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&l.regs[off..off + 4]);
    u32::from_le_bytes(b)
}

fn set_lapic_reg(l: &mut KvmLapicState, off: usize, v: u32) {
    l.regs[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// LVT LINT0 = ExtINT (the 8259 PIC's output) and LINT1 = NMI, keeping
/// the other LVT bits (mask, trigger) as KVM set them; the virtual-wire
/// setup of a PC, as Firecracker does.
pub(crate) fn set_lint(l: &mut KvmLapicState) {
    for (off, mode) in [(APIC_LVT0, APIC_MODE_EXTINT), (APIC_LVT1, APIC_MODE_NMI)] {
        let v = lapic_reg(l, off);
        set_lapic_reg(l, off, (v & !0x700) | (mode << 8));
    }
}

// --- boot state -------------------------------------------------------------------

/// A `kvm_segment` for GDT descriptor `desc` loaded with `selector`.
pub(crate) fn kvm_segment(desc: u64, selector: u16) -> KvmSegment {
    let s = Segment::decode(desc);
    KvmSegment {
        base: u64::from(s.base),
        limit: s.limit,
        selector,
        type_: s.type_,
        present: s.present as u8,
        dpl: s.dpl,
        db: s.db as u8,
        s: s.s as u8,
        l: s.l as u8,
        g: s.g as u8,
        avl: s.avl as u8,
        unusable: 0,
        padding: 0,
    }
}

/// The boot vCPU's special registers (see [`BootState`]): `cur` is what
/// KVM_GET_SREGS returned (only `apic_base` is kept: KVM_SET_SREGS applies
/// it). Segment state satisfies the VMX guest-state checks (SDM 3C 28.3.1.2)
/// without unrestricted guest: CS 64-bit code (L=1, D=0), data segments
/// flat read/write, TR a usable busy 64-bit TSS (type 11; selector 0 as the
/// BOOT_GDT has no TSS descriptor, the hidden part is what matters), LDTR
/// usable type 2 (KVM's reset value).
pub(crate) fn boot_sregs(cur: &KvmSregs, s: &BootState) -> KvmSregs {
    let code = kvm_segment(BOOT_CODE, BOOT_CS);
    let data = kvm_segment(BOOT_DATA, BOOT_DS);
    KvmSregs {
        cs: code,
        ds: data,
        es: data,
        fs: data,
        gs: data,
        ss: data,
        tr: KvmSegment {
            base: 0,
            limit: 0x67, // sizeof(struct x86_hw_tss) - 1
            selector: 0,
            type_: 11,
            present: 1,
            ..KvmSegment::default()
        },
        ldt: KvmSegment {
            base: 0,
            limit: 0xffff,
            selector: 0,
            type_: 2,
            present: 1,
            ..KvmSegment::default()
        },
        gdt: KvmDtable {
            base: s.gdt_base,
            limit: BOOT_GDT_LIMIT,
            padding: [0; 3],
        },
        idt: KvmDtable::default(),
        cr0: BOOT_CR0,
        cr2: 0,
        cr3: s.cr3,
        cr4: BOOT_CR4,
        cr8: 0,
        efer: BOOT_EFER,
        apic_base: cur.apic_base,
        interrupt_bitmap: [0; 4],
    }
}

/// The boot vCPU's general registers: RIP, RSI (boot_params), RSP, RFLAGS
/// 0x2, everything else 0.
pub(crate) fn boot_regs(s: &BootState) -> KvmRegs {
    KvmRegs {
        rip: s.rip,
        rsi: s.rsi,
        rsp: s.rsp,
        rflags: BOOT_RFLAGS,
        ..KvmRegs::default()
    }
}

// --- registers -------------------------------------------------------------------

/// Whether `reg` lives in `kvm_sregs` (else in `kvm_regs`).
pub(crate) fn is_sreg(reg: Reg) -> bool {
    matches!(reg, Reg::Cr0 | Reg::Cr2 | Reg::Cr3 | Reg::Cr4 | Reg::Efer)
}

/// `reg` in `kvm_regs`; `None` for a special register.
pub(crate) fn reg_mut(r: &mut KvmRegs, reg: Reg) -> Option<&mut u64> {
    Some(match reg {
        Reg::Rax => &mut r.rax,
        Reg::Rbx => &mut r.rbx,
        Reg::Rcx => &mut r.rcx,
        Reg::Rdx => &mut r.rdx,
        Reg::Rsi => &mut r.rsi,
        Reg::Rdi => &mut r.rdi,
        Reg::Rsp => &mut r.rsp,
        Reg::Rbp => &mut r.rbp,
        Reg::R8 => &mut r.r8,
        Reg::R9 => &mut r.r9,
        Reg::R10 => &mut r.r10,
        Reg::R11 => &mut r.r11,
        Reg::R12 => &mut r.r12,
        Reg::R13 => &mut r.r13,
        Reg::R14 => &mut r.r14,
        Reg::R15 => &mut r.r15,
        Reg::Rip => &mut r.rip,
        Reg::Rflags => &mut r.rflags,
        Reg::Cr0 | Reg::Cr2 | Reg::Cr3 | Reg::Cr4 | Reg::Efer => return None,
    })
}

/// `reg` in `kvm_sregs`; `None` for a general register.
pub(crate) fn sreg_mut(s: &mut KvmSregs, reg: Reg) -> Option<&mut u64> {
    Some(match reg {
        Reg::Cr0 => &mut s.cr0,
        Reg::Cr2 => &mut s.cr2,
        Reg::Cr3 => &mut s.cr3,
        Reg::Cr4 => &mut s.cr4,
        Reg::Efer => &mut s.efer,
        _ => return None,
    })
}

/// Guest state for a fatal-exit message.
pub(crate) fn describe(r: &KvmRegs, s: &KvmSregs) -> String {
    format!(
        " (RIP={:#x} RSP={:#x} RFLAGS={:#x} CS={:#x}{} CR0={:#x} CR2={:#x} CR3={:#x} CR4={:#x} EFER={:#x})",
        r.rip,
        r.rsp,
        r.rflags,
        s.cs.selector,
        if s.cs.l != 0 {
            "/64"
        } else if s.cs.db != 0 {
            "/32"
        } else {
            "/16"
        },
        s.cr0,
        s.cr2,
        s.cr3,
        s.cr4,
        s.efer
    )
}

// --- interrupts -------------------------------------------------------------------

/// KVM GSI routing in the PC layout QEMU uses (`kvm_pc_setup_irq_routing`),
/// matching an ACPI MADT with the override "ISA IRQ 0 -> GSI 2": KVM GSI 0
/// (where the in-kernel PIT raises its interrupt) goes to PIC IRQ 0 and
/// IOAPIC pin 2; KVM GSI n (n = 1, 3..15) to PIC IRQ n and IOAPIC pin n;
/// KVM GSI 16..23 to IOAPIC pin n only. KVM GSI 2 has no route (the PIC
/// cascade). So for every ACPI GSI g other than 0 and 2, KVM GSI g raises
/// IOAPIC pin g ([`gsi_to_kvm`]).
pub(crate) fn gsi_routes() -> Vec<KvmIrqRoutingEntry> {
    let route = |gsi: u32, chip: u32, pin: u32| {
        let mut u = [0u32; 8];
        u[0] = chip;
        u[1] = pin;
        KvmIrqRoutingEntry {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            flags: 0,
            pad: 0,
            u,
        }
    };
    let mut v = Vec::new();
    for i in (0..8).filter(|&i| i != 2) {
        v.push(route(i, KVM_IRQCHIP_PIC_MASTER, i));
    }
    for i in 8..16 {
        v.push(route(i, KVM_IRQCHIP_PIC_SLAVE, i - 8));
    }
    for i in (0..KVM_IOAPIC_NUM_PINS).filter(|&i| i != 2) {
        v.push(route(i, KVM_IRQCHIP_IOAPIC, if i == 0 { 2 } else { i }));
    }
    v
}

/// The KVM GSI ([`gsi_routes`]) for a [`Vm::set_irq_line`](crate::Vm::set_irq_line)
/// number, which is an ACPI GSI = IOAPIC pin. Pins 0 and 2 belong to the
/// in-kernel PIT and are refused.
pub(crate) fn gsi_to_kvm(gsi: u32) -> Result<u32, String> {
    match gsi {
        0 | 2 => Err(format!("GSI {gsi} is the in-kernel PIT's")),
        g if g < KVM_IOAPIC_NUM_PINS => Ok(g),
        g => Err(format!(
            "GSI {g} out of range: the IOAPIC has {KVM_IOAPIC_NUM_PINS} pins"
        )),
    }
}

// --- layout pins (same literals in scripts/kvm-abi/probe-x86_64.h) -----------------

const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<KvmRegs>() == 144);
    assert!(offset_of!(KvmRegs, rsi) == 32);
    assert!(offset_of!(KvmRegs, r8) == 64);
    assert!(offset_of!(KvmRegs, rip) == 128);
    assert!(offset_of!(KvmRegs, rflags) == 136);
    assert!(size_of::<KvmSegment>() == 24);
    assert!(offset_of!(KvmSegment, limit) == 8);
    assert!(offset_of!(KvmSegment, selector) == 12);
    assert!(offset_of!(KvmSegment, type_) == 14);
    assert!(offset_of!(KvmSegment, present) == 15);
    assert!(offset_of!(KvmSegment, dpl) == 16);
    assert!(offset_of!(KvmSegment, db) == 17);
    assert!(offset_of!(KvmSegment, s) == 18);
    assert!(offset_of!(KvmSegment, l) == 19);
    assert!(offset_of!(KvmSegment, g) == 20);
    assert!(offset_of!(KvmSegment, avl) == 21);
    assert!(offset_of!(KvmSegment, unusable) == 22);
    assert!(offset_of!(KvmSegment, padding) == 23);
    assert!(size_of::<KvmDtable>() == 16);
    assert!(offset_of!(KvmDtable, limit) == 8);
    assert!(offset_of!(KvmDtable, padding) == 10);
    assert!(size_of::<KvmSregs>() == 312);
    assert!(offset_of!(KvmSregs, ss) == 120);
    assert!(offset_of!(KvmSregs, tr) == 144);
    assert!(offset_of!(KvmSregs, ldt) == 168);
    assert!(offset_of!(KvmSregs, gdt) == 192);
    assert!(offset_of!(KvmSregs, idt) == 208);
    assert!(offset_of!(KvmSregs, cr0) == 224);
    assert!(offset_of!(KvmSregs, cr3) == 240);
    assert!(offset_of!(KvmSregs, cr4) == 248);
    assert!(offset_of!(KvmSregs, cr8) == 256);
    assert!(offset_of!(KvmSregs, efer) == 264);
    assert!(offset_of!(KvmSregs, apic_base) == 272);
    assert!(offset_of!(KvmSregs, interrupt_bitmap) == 280);
    assert!(offset_of!(KvmSregs, ds) == 24 && offset_of!(KvmSregs, es) == 48);
    assert!(offset_of!(KvmSregs, fs) == 72 && offset_of!(KvmSregs, gs) == 96);
    assert!(offset_of!(KvmSregs, cr2) == 232);
    assert!(size_of::<[u64; 4]>() * 8 == 256); // KVM_NR_INTERRUPTS bits
    assert!(size_of::<KvmFpu>() == 416);
    assert!(offset_of!(KvmFpu, fcw) == 128);
    assert!(offset_of!(KvmFpu, fsw) == 130);
    assert!(offset_of!(KvmFpu, ftwx) == 132);
    assert!(offset_of!(KvmFpu, pad1) == 133);
    assert!(offset_of!(KvmFpu, last_opcode) == 134);
    assert!(offset_of!(KvmFpu, last_ip) == 136);
    assert!(offset_of!(KvmFpu, last_dp) == 144);
    assert!(offset_of!(KvmFpu, xmm) == 152);
    assert!(offset_of!(KvmFpu, mxcsr) == 408);
    assert!(offset_of!(KvmFpu, pad2) == 412);
    assert!(size_of::<KvmMsrEntry>() == 16);
    assert!(offset_of!(KvmMsrEntry, data) == 8);
    assert!(size_of::<KvmMsrs<0>>() == 8);
    assert!(offset_of!(KvmMsrs<1>, entries) == 8);
    assert!(offset_of!(KvmMsrs<1>, pad) == 4);
    assert!(offset_of!(KvmMsrEntry, reserved) == 4);
    assert!(size_of::<KvmCpuidEntry2>() == 40);
    assert!(offset_of!(KvmCpuidEntry2, index) == 4);
    assert!(offset_of!(KvmCpuidEntry2, flags) == 8);
    assert!(offset_of!(KvmCpuidEntry2, eax) == 12);
    assert!(offset_of!(KvmCpuidEntry2, ebx) == 16 && offset_of!(KvmCpuidEntry2, ecx) == 20);
    assert!(offset_of!(KvmCpuid2<1>, padding) == 4);
    assert!(offset_of!(KvmCpuidEntry2, edx) == 24);
    assert!(offset_of!(KvmCpuidEntry2, padding) == 28);
    assert!(size_of::<KvmCpuid2<0>>() == 8);
    assert!(offset_of!(KvmCpuid2<1>, entries) == 8);
    assert!(size_of::<KvmLapicState>() == 1024);
    assert!(size_of::<KvmPitConfig>() == 64);
    assert!(size_of::<KvmIrqRoutingEntry>() == 48 && align_of::<KvmIrqRoutingEntry>() == 8);
    assert!(offset_of!(KvmIrqRoutingEntry, type_) == 4);
    assert!(offset_of!(KvmIrqRoutingEntry, flags) == 8);
    assert!(offset_of!(KvmIrqRoutingEntry, u) == 16);
    assert!(offset_of!(KvmIrqRoutingEntry, pad) == 12);
    assert!(size_of::<[u32; 8]>() == 32);
    assert!(size_of::<KvmIrqRouting<0>>() == 8);
    assert!(offset_of!(KvmIrqRouting<1>, entries) == 8);
    // The TSS pages and the identity-map page do not overlap and stay
    // below the LAPIC/IOAPIC-free top of the 4 GiB hole.
    assert!(KVM_IDENTITY_MAP_ADDR + 0x1000 <= KVM_TSS_ADDR);
    assert!(KVM_RESERVED_END == 0xfffc_0000);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(function: u32, index: u32, regs: [u32; 4]) -> KvmCpuidEntry2 {
        KvmCpuidEntry2 {
            function,
            index,
            flags: 0,
            eax: regs[0],
            ebx: regs[1],
            ecx: regs[2],
            edx: regs[3],
            padding: [0; 3],
        }
    }

    fn indexed(function: u32, index: u32, regs: [u32; 4]) -> KvmCpuidEntry2 {
        KvmCpuidEntry2 {
            flags: KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
            ..leaf(function, index, regs)
        }
    }

    fn sig(s: &[u8; 12]) -> [u32; 3] {
        let w = |i: usize| u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]);
        [w(0), w(4), w(8)] // EBX, EDX, ECX
    }

    /// A trimmed KVM_GET_SUPPORTED_CPUID of an Intel host (i7-8550U-like,
    /// max basic leaf 0x16 so no 0x1F), as a 6.x kernel returns it: 0xB
    /// subleaf 0 zeroed, KVM leaves at 0x4000_0000.
    fn intel_table() -> Vec<KvmCpuidEntry2> {
        let [b, d, c] = sig(b"GenuineIntel");
        vec![
            leaf(0, 0, [0x16, b, c, d]),
            // Host: APIC id 6, 16 logical, CLFLUSH 8, HTT; ECX lacks hypervisor.
            leaf(1, 0, [0x806ea, 0x0610_0800, 0x77fa_3223, 0x0f8b_fbff]),
            indexed(4, 0, [0x1c00_4121, 0x01c0_003f, 0x3f, 0]),
            indexed(4, 1, [0x1c00_4122, 0x01c0_003f, 0x3f, 0]),
            indexed(4, 2, [0x1c00_4143, 0x00c0_003f, 0x3ff, 0]),
            indexed(4, 3, [0x1c03_c163, 0x02c0_003f, 0x1fff, 6]),
            indexed(4, 4, [0, 0, 0, 0]),
            indexed(7, 0, [0, 0x029c_67af, 0, 0xbc00_0400]),
            indexed(0xb, 0, [0, 0, 0, 0]),
            indexed(0xd, 0, [0x1f, 0x440, 0x440, 0]),
            leaf(
                0x4000_0000,
                0,
                [0x4000_0001, 0x4b4d_564b, 0x564b_4d56, 0x4d],
            ),
            leaf(0x4000_0001, 0, [0x0100_7afb, 0, 0, 0]),
            leaf(0x8000_0000, 0, [0x8000_0008, 0, 0, 0]),
            leaf(0x8000_0008, 0, [0x3027, 0, 0, 0]),
        ]
    }

    fn get(t: &[KvmCpuidEntry2], f: u32, i: u32) -> KvmCpuidEntry2 {
        *t.iter()
            .find(|e| e.function == f && e.index == i)
            .unwrap_or_else(|| panic!("leaf {f:#x}.{i}"))
    }

    #[test]
    fn vendor_from_leaf_0() {
        assert_eq!(vendor(&intel_table()), Vendor::Intel);
        let [b, d, c] = sig(b"AuthenticAMD");
        assert_eq!(vendor(&[leaf(0, 0, [0x10, b, c, d])]), Vendor::Amd);
        assert_eq!(vendor(&[]), Vendor::Other);
    }

    #[test]
    fn id_bits_values() {
        assert_eq!(
            [1, 2, 3, 4, 5, 8, 9, 255].map(id_bits),
            [0, 1, 2, 2, 3, 3, 4, 8]
        );
    }

    #[test]
    fn leaf_1_fixups() {
        let t = intel_table();
        let v = cpuid_for_vcpu(&t, 2, 4, true).unwrap();
        let e = get(&v, 1, 0);
        assert_eq!(e.ebx >> 24, 2, "initial APIC id");
        assert_eq!((e.ebx >> 16) & 0xff, 4, "logical processors");
        assert_eq!((e.ebx >> 8) & 0xff, 8, "CLFLUSH line size kept");
        assert_eq!(e.ebx & 0xff, 0, "brand index kept");
        assert_ne!(e.ecx & CPUID_1_ECX_HYPERVISOR, 0);
        assert_ne!(e.ecx & CPUID_1_ECX_X2APIC, 0);
        assert_ne!(e.ecx & CPUID_1_ECX_TSC_DEADLINE, 0);
        assert_ne!(e.edx & CPUID_1_EDX_HTT, 0);
        assert_eq!(e.eax, 0x806ea, "signature kept");

        let v = cpuid_for_vcpu(&t, 0, 1, false).unwrap();
        let e = get(&v, 1, 0);
        assert_eq!(e.ebx >> 24, 0);
        assert_eq!((e.ebx >> 16) & 0xff, 1);
        assert_eq!(e.edx & CPUID_1_EDX_HTT, 0, "no HTT for one vCPU");
        assert_eq!(e.ecx & CPUID_1_ECX_TSC_DEADLINE, 0);
        // CLFLUSH filled in when the host reports 0.
        let mut t2 = t.clone();
        t2[1].ebx = 0;
        let e = get(&cpuid_for_vcpu(&t2, 0, 1, false).unwrap(), 1, 0);
        assert_eq!((e.ebx >> 8) & 0xff, 8);
    }

    #[test]
    fn extended_topology_leaf_b() {
        let t = intel_table();
        for (index, cpus) in [(0, 1), (1, 2), (2, 3), (3, 4)] {
            let v = cpuid_for_vcpu(&t, index, cpus, false).unwrap();
            let subs: Vec<_> = v.iter().filter(|e| e.function == 0xb).copied().collect();
            assert_eq!(subs.len(), 3);
            for (i, e) in subs.iter().enumerate() {
                assert_eq!(e.index, i as u32);
                assert_eq!(e.flags, KVM_CPUID_FLAG_SIGNIFCANT_INDEX);
                assert_eq!(e.edx, index, "x2APIC id");
                assert_eq!(e.ecx & 0xff, i as u32, "level number");
            }
            // SMT: shift 0, 1 thread.
            assert_eq!((subs[0].eax, subs[0].ebx, subs[0].ecx >> 8), (0, 1, 1));
            // Core: shift = bits for `cpus` ids, `cpus` logical processors.
            assert_eq!(
                (subs[1].eax, subs[1].ebx, subs[1].ecx >> 8),
                (id_bits(cpus), cpus, 2)
            );
            // Terminator: invalid level type.
            assert_eq!((subs[2].eax, subs[2].ebx, subs[2].ecx >> 8), (0, 0, 0));
            // The package id (x2APIC id >> core shift) is 0 for every vCPU.
            assert_eq!(index >> subs[1].eax, 0);
            // No 0x1F invented when the host lacks it.
            assert!(!v.iter().any(|e| e.function == 0x1f));
        }
    }

    #[test]
    fn leaf_1f_rebuilt_when_present() {
        let mut t = intel_table();
        t[0].eax = 0x1f;
        t.push(indexed(0x1f, 0, [1, 2, 0x100, 6]));
        t.push(indexed(0x1f, 1, [4, 16, 0x201, 6]));
        t.push(indexed(0x1f, 2, [0, 0, 2, 6]));
        let v = cpuid_for_vcpu(&t, 1, 2, false).unwrap();
        let subs: Vec<_> = v.iter().filter(|e| e.function == 0x1f).collect();
        assert_eq!(subs.len(), 3, "host subleaves replaced, not kept");
        assert!(subs.iter().all(|e| e.edx == 1));
        assert_eq!((subs[1].eax, subs[1].ebx), (1, 2));
    }

    #[test]
    fn deterministic_cache_leaf_4() {
        let t = intel_table();
        let v = cpuid_for_vcpu(&t, 0, 3, false).unwrap();
        let sharing = |e: KvmCpuidEntry2| (e.eax >> 14) & 0xfff;
        let cores = |e: KvmCpuidEntry2| e.eax >> 26;
        for i in 0..3 {
            let e = get(&v, 4, i);
            assert_eq!(sharing(e), 0, "L1/L2 subleaf {i} per core");
            assert_eq!(cores(e), 2);
            assert_eq!(
                e.eax & 0x3fff,
                get(&t, 4, i).eax & 0x3fff,
                "cache type/level kept"
            );
            assert_eq!((e.ebx, e.ecx), (get(&t, 4, i).ebx, get(&t, 4, i).ecx));
        }
        let l3 = get(&v, 4, 3);
        assert_eq!(sharing(l3), 2, "L3 shared by the 3 vCPUs");
        assert_eq!(cores(l3), 2);
        assert_eq!(get(&v, 4, 4), get(&t, 4, 4), "terminator untouched");
    }

    #[test]
    fn other_leaves_kept() {
        let t = intel_table();
        let v = cpuid_for_vcpu(&t, 1, 2, true).unwrap();
        for f in [
            0,
            7,
            0xd,
            0x4000_0000,
            0x4000_0001,
            0x8000_0000,
            0x8000_0008,
        ] {
            assert_eq!(get(&v, f, 0), get(&t, f, 0), "leaf {f:#x}");
        }
        // One 0xB entry replaced by three.
        assert_eq!(v.len(), t.len() + 2);
    }

    #[test]
    fn amd_topology_leaves() {
        let [b, d, c] = sig(b"AuthenticAMD");
        let t = vec![
            leaf(0, 0, [0x10, b, c, d]),
            leaf(1, 0, [0x00a2_0f12, 0x0c10_0800, 0x7ef8_320b, 0x178b_fbff]),
            indexed(4, 0, [0x1c00_4121, 0, 0, 0]), // reserved on AMD: untouched
            leaf(0x8000_0008, 0, [0x3030, 0, 0x0000_700f, 0]),
            indexed(0x8000_001d, 0, [0x0000_4121, 0x01c0_003f, 0x3f, 0]),
            indexed(0x8000_001d, 1, [0x0000_4143, 0x01c0_003f, 0x3ff, 2]),
            indexed(0x8000_001d, 2, [0x0003_c163, 0x03c0_003f, 0x7fff, 1]),
            leaf(0x8000_001e, 0, [0, 0, 0, 0]),
        ];
        let v = cpuid_for_vcpu(&t, 3, 5, false).unwrap();
        assert_eq!(get(&v, 4, 0), t[2]);
        let e = get(&v, 0x8000_0008, 0);
        assert_eq!(e.ecx & 0xff, 4, "NC = cpus - 1");
        assert_eq!((e.ecx >> 12) & 0xf, 3, "ApicIdSize");
        assert_eq!(e.eax, 0x3030);
        let e = get(&v, 0x8000_001e, 0);
        assert_eq!((e.eax, e.ebx, e.ecx), (3, 3, 0));
        assert_eq!((get(&v, 0x8000_001d, 0).eax >> 14) & 0xfff, 0);
        assert_eq!((get(&v, 0x8000_001d, 2).eax >> 14) & 0xfff, 4);
        assert!(!v.iter().any(|e| e.function == 0xb));
    }

    #[test]
    fn cpuid_errors() {
        let t = intel_table();
        assert!(cpuid_for_vcpu(&t, 2, 2, false).is_err());
        assert!(cpuid_for_vcpu(&t, 0, 0, false).is_err());
        assert!(cpuid_for_vcpu(&t, 0, 256, false).is_err());
        let big = vec![leaf(0x8000_0000, 0, [0; 4]); KVM_MAX_CPUID_ENTRIES + 1];
        assert!(cpuid_for_vcpu(&big, 0, 1, false).is_err());
    }

    #[test]
    fn boot_msr_list() {
        let idx: Vec<u32> = BOOT_MSRS.iter().map(|m| m.index).collect();
        let mut dedup = idx.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), idx.len(), "no MSR twice");
        let get = |i: u32| BOOT_MSRS.iter().find(|m| m.index == i).unwrap().data;
        // Fast strings, and KVM's reset bits BTS_UNAVAIL (11) and
        // PEBS_UNAVAIL (12) kept rather than cleared.
        assert_eq!(get(MSR_IA32_MISC_ENABLE), 0x1801);
        assert_eq!(get(MSR_MTRR_DEF_TYPE), 0x806);
        for i in [
            MSR_IA32_SYSENTER_CS,
            MSR_IA32_SYSENTER_ESP,
            MSR_IA32_SYSENTER_EIP,
            MSR_STAR,
            MSR_LSTAR,
            MSR_CSTAR,
            MSR_SYSCALL_MASK,
            MSR_KERNEL_GS_BASE,
            MSR_IA32_TSC,
        ] {
            assert_eq!(get(i), 0, "MSR {i:#x}");
        }
        assert!(BOOT_MSRS.iter().all(|m| m.reserved == 0));
    }

    #[test]
    fn fpu_reset_values() {
        let f = boot_fpu();
        assert_eq!((f.fcw, f.mxcsr), (0x37f, 0x1f80));
        assert_eq!(f.fsw, 0);
    }

    #[test]
    fn lint_delivery_modes() {
        let mut l = KvmLapicState::default();
        // KVM's reset: LVT0 masked (BSP: ExtINT unmasked), LVT1 masked.
        set_lapic_reg(&mut l, APIC_LVT0, 0x0001_0000);
        set_lapic_reg(&mut l, APIC_LVT1, 0x0001_0000);
        set_lapic_reg(&mut l, 0x370, 0xdead_beef);
        set_lint(&mut l);
        assert_eq!(lapic_reg(&l, APIC_LVT0), 0x0001_0700);
        assert_eq!(lapic_reg(&l, APIC_LVT1), 0x0001_0400);
        assert_eq!(lapic_reg(&l, 0x370), 0xdead_beef, "other registers kept");
        // Idempotent, and replaces a previous mode.
        set_lapic_reg(&mut l, APIC_LVT1, 0x0000_0700);
        set_lint(&mut l);
        set_lint(&mut l);
        assert_eq!(lapic_reg(&l, APIC_LVT1), 0x0000_0400);
        // Little-endian byte layout of the register page.
        assert_eq!(&l.regs[APIC_LVT0..APIC_LVT0 + 4], &[0, 7, 1, 0]);
    }

    fn boot() -> BootState {
        BootState {
            rip: 0x10_0200,
            rsi: 0x7000,
            rsp: 0x8ff0,
            cr3: 0x9000,
            gdt_base: 0x500,
        }
    }

    #[test]
    fn boot_segments() {
        let cur = KvmSregs {
            apic_base: 0xfee0_0900,
            cr0: 0x6000_0010,
            interrupt_bitmap: [1, 0, 0, 0],
            ..KvmSregs::default()
        };
        let s = boot_sregs(&cur, &boot());
        let cs = s.cs;
        assert_eq!((cs.selector, cs.base, cs.limit), (0x10, 0, 0xffff_ffff));
        assert_eq!((cs.type_, cs.s, cs.present, cs.dpl), (0xb, 1, 1, 0));
        assert_eq!((cs.l, cs.db, cs.g, cs.unusable), (1, 0, 1, 0));
        for d in [s.ds, s.es, s.fs, s.gs, s.ss] {
            assert_eq!((d.selector, d.base, d.limit), (0x18, 0, 0xffff_ffff));
            assert_eq!((d.type_, d.s, d.present, d.dpl), (3, 1, 1, 0));
            assert_eq!((d.l, d.db, d.g, d.unusable), (0, 1, 1, 0));
        }
        // TR: usable busy 64-bit TSS, system segment, limit consistent with G=0.
        assert_eq!(
            (s.tr.type_, s.tr.s, s.tr.present, s.tr.unusable),
            (11, 0, 1, 0)
        );
        assert_eq!((s.tr.g, s.tr.limit, s.tr.selector & 4), (0, 0x67, 0));
        // LDTR: usable LDT descriptor type (KVM's reset value).
        assert_eq!((s.ldt.type_, s.ldt.s, s.ldt.present), (2, 0, 1));
        assert_eq!((s.gdt.base, s.gdt.limit), (0x500, 31));
        assert_eq!((s.idt.base, s.idt.limit), (0, 0));
        assert_eq!(
            (s.cr0, s.cr3, s.cr4, s.efer),
            (0x8005_0033, 0x9000, 0x20, 0x500)
        );
        assert_eq!((s.cr2, s.cr8), (0, 0));
        assert_eq!(s.apic_base, 0xfee0_0900, "APIC base kept");
        assert_eq!(s.interrupt_bitmap, [0; 4], "no pending interrupt");
    }

    #[test]
    fn boot_general_registers() {
        let r = boot_regs(&boot());
        assert_eq!(
            r,
            KvmRegs {
                rip: 0x10_0200,
                rsi: 0x7000,
                rsp: 0x8ff0,
                rflags: 2,
                ..KvmRegs::default()
            }
        );
    }

    #[test]
    fn segment_from_descriptor_matches_decode() {
        let s = kvm_segment(gdt_entry_for_test(), 0x28);
        assert_eq!((s.base, s.limit, s.selector), (0x1234_5678, 0xabcde, 0x28));
        assert_eq!((s.type_, s.db, s.g, s.avl), (3, 1, 0, 1));
    }

    fn gdt_entry_for_test() -> u64 {
        super::super::gdt_entry(0x5093, 0x1234_5678, 0xabcde)
    }

    #[test]
    fn register_access() {
        let all = [
            Reg::Rax,
            Reg::Rbx,
            Reg::Rcx,
            Reg::Rdx,
            Reg::Rsi,
            Reg::Rdi,
            Reg::Rsp,
            Reg::Rbp,
            Reg::R8,
            Reg::R9,
            Reg::R10,
            Reg::R11,
            Reg::R12,
            Reg::R13,
            Reg::R14,
            Reg::R15,
            Reg::Rip,
            Reg::Rflags,
            Reg::Cr0,
            Reg::Cr2,
            Reg::Cr3,
            Reg::Cr4,
            Reg::Efer,
        ];
        let mut r = KvmRegs::default();
        let mut s = KvmSregs::default();
        for (i, &reg) in all.iter().enumerate() {
            let v = 0x100 + i as u64;
            match (is_sreg(reg), reg_mut(&mut r, reg), sreg_mut(&mut s, reg)) {
                (false, Some(p), None) | (true, None, Some(p)) => *p = v,
                other => panic!(
                    "{reg:?}: {:?}",
                    (other.0, other.1.is_some(), other.2.is_some())
                ),
            }
        }
        // Every register landed in its own field, in struct order.
        assert_eq!((r.rax, r.r8, r.rip, r.rflags), (0x100, 0x108, 0x110, 0x111));
        assert_eq!(
            (s.cr0, s.cr2, s.cr3, s.cr4, s.efer),
            (0x112, 0x113, 0x114, 0x115, 0x116)
        );
        // The 18 general registers are distinct fields.
        let words: [u64; 18] = [
            r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rsp, r.rbp, r.r8, r.r9, r.r10, r.r11,
            r.r12, r.r13, r.r14, r.r15, r.rip, r.rflags,
        ];
        assert_eq!(words.to_vec(), (0x100..0x112).collect::<Vec<u64>>());
    }

    #[test]
    fn describe_state() {
        let r = boot_regs(&boot());
        let s = boot_sregs(&KvmSregs::default(), &boot());
        let d = describe(&r, &s);
        assert!(
            d.starts_with(" (RIP=0x100200 RSP=0x8ff0 RFLAGS=0x2 CS=0x10/64"),
            "{d}"
        );
        assert!(
            d.contains("CR3=0x9000") && d.ends_with("EFER=0x500)"),
            "{d}"
        );
    }

    #[test]
    fn gsi_routing_like_qemu() {
        let routes = gsi_routes();
        let targets = |gsi: u32| -> Vec<(u32, u32)> {
            routes
                .iter()
                .filter(|e| e.gsi == gsi)
                .map(|e| (e.u[0], e.u[1]))
                .collect()
        };
        assert!(
            routes
                .iter()
                .all(|e| e.type_ == KVM_IRQ_ROUTING_IRQCHIP && e.flags == 0)
        );
        // The PIT's GSI 0: PIC IRQ 0 and IOAPIC pin 2 (MADT override 0 -> 2).
        assert_eq!(
            targets(0),
            [(KVM_IRQCHIP_PIC_MASTER, 0), (KVM_IRQCHIP_IOAPIC, 2)]
        );
        assert_eq!(targets(2), [], "cascade: no route");
        assert_eq!(
            targets(4),
            [(KVM_IRQCHIP_PIC_MASTER, 4), (KVM_IRQCHIP_IOAPIC, 4)]
        );
        assert_eq!(
            targets(9),
            [(KVM_IRQCHIP_PIC_SLAVE, 1), (KVM_IRQCHIP_IOAPIC, 9)]
        );
        assert_eq!(targets(23), [(KVM_IRQCHIP_IOAPIC, 23)]);
        assert_eq!(routes.len(), 15 + 23);
        // Every IOAPIC pin but 0 is reachable, through gsi_to_kvm.
        for pin in 1..KVM_IOAPIC_NUM_PINS {
            let reached: Vec<u32> = routes
                .iter()
                .filter(|e| e.u[0] == KVM_IRQCHIP_IOAPIC && e.u[1] == pin)
                .map(|e| e.gsi)
                .collect();
            assert_eq!(reached.len(), 1, "pin {pin}");
            if pin != 2 {
                assert_eq!(gsi_to_kvm(pin), Ok(reached[0]));
            }
        }
        assert!(gsi_to_kvm(0).is_err());
        assert!(gsi_to_kvm(2).is_err());
        assert!(gsi_to_kvm(24).is_err());
    }
}
