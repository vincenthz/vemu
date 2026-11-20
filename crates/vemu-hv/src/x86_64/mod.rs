//! x86_64 guest types of the [`Vm`](crate::Vm)/[`Vcpu`](crate::Vcpu)
//! interface: [`Reg`], [`BootState`], [`ArchVmInfo`] and the boot GDT shared
//! between the VMM (which writes [`BOOT_GDT`] into guest memory) and the
//! backend (which loads the matching segment registers). Pure code, no
//! hypervisor calls: it compiles (and is tested) on every host.
//!
//! The boot state follows the Linux 64-bit boot protocol
//! (Documentation/arch/x86/boot.rst, "64-bit BOOT PROTOCOL"): long mode with
//! paging on and an identity map covering the kernel, boot_params and the
//! command line; `__BOOT_CS` (0x10) a flat 64-bit code segment and
//! `__BOOT_DS` (0x18) a flat data segment; RSI = boot_params; interrupts
//! disabled. See docs/kvm-design.md, "x86_64 BootState and GDT".

/// x86 KVM UAPI mirrors and the pure part of the KVM backend's vCPU / VM
/// setup (used by `kvm/x86_64.rs`; compiled everywhere for its tests).
#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(dead_code)
)]
pub(crate) mod kvm;

pub use kvm::{KVM_IDENTITY_MAP_ADDR, KVM_RESERVED_END, KVM_TSS_ADDR};

/// A guest register reachable through [`Vcpu::get_reg`](crate::Vcpu::get_reg)
/// / [`Vcpu::set_reg`](crate::Vcpu::set_reg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rsp,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Rflags,
    Cr0,
    Cr2,
    Cr3,
    Cr4,
    Efer,
}

/// Entry state of the boot vCPU, see
/// [`Vcpu::set_boot_state`](crate::Vcpu::set_boot_state). The VMM has
/// written [`BOOT_GDT`] at `gdt_base` and identity-mapping page tables
/// (PML4 at `cr3`) into guest RAM. The backend loads GDTR = (`gdt_base`,
/// [`BOOT_GDT_LIMIT`]), CS = [`BOOT_CS`] (64-bit), DS/ES/FS/GS/SS =
/// [`BOOT_DS`], a busy 64-bit TSS in TR, IDT limit 0, CR0 = [`BOOT_CR0`],
/// CR3 = `cr3`, CR4 = [`BOOT_CR4`], EFER = [`BOOT_EFER`], RFLAGS =
/// [`BOOT_RFLAGS`], RIP = `rip`, RSI = `rsi`, RSP = `rsp`, other GPRs 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootState {
    /// 64-bit entry point (bzImage protected-mode part load address +
    /// 0x200).
    pub rip: u64,
    /// Guest-physical address of `struct boot_params` (the zero page).
    pub rsi: u64,
    /// Initial stack pointer.
    pub rsp: u64,
    /// Guest-physical address of the PML4.
    pub cr3: u64,
    /// Guest-physical address of the GDT ([`BOOT_GDT`]).
    pub gdt_base: u64,
}

/// What [`Vm::arch_info`](crate::Vm::arch_info) reports on x86_64: nothing
/// yet (the in-kernel IOAPIC/LAPIC addresses are architectural).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArchVmInfo {}

/// The boot GDT: null, unused, 64-bit flat code at selector 0x10, flat data
/// at 0x18 (the selectors Linux's 64-bit boot protocol names `__BOOT_CS` and
/// `__BOOT_DS`).
pub const BOOT_GDT: [u64; 4] = [
    0,
    0,
    0x00af_9b00_0000_ffff, // 0x10: code, base 0, limit 4 GiB (G), L=1, P, DPL 0, type 0xb
    0x00cf_9300_0000_ffff, // 0x18: data, base 0, limit 4 GiB (G), D/B=1, P, DPL 0, type 0x3
];
/// GDTR limit for [`BOOT_GDT`] (size in bytes - 1).
pub const BOOT_GDT_LIMIT: u16 = (BOOT_GDT.len() * 8 - 1) as u16;
/// Code segment selector (`__BOOT_CS`).
pub const BOOT_CS: u16 = 0x10;
/// Data segment selector (`__BOOT_DS`), for DS, ES, FS, GS and SS.
pub const BOOT_DS: u16 = 0x18;

/// CR0 at entry: PE | MP | ET | NE | WP | AM | PG.
pub const BOOT_CR0: u64 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
/// CR4 at entry: PAE (required for long mode).
pub const BOOT_CR4: u64 = CR4_PAE;
/// EFER at entry: LME | LMA.
pub const BOOT_EFER: u64 = EFER_LME | EFER_LMA;
/// RFLAGS at entry: only the reserved bit 1 (interrupts disabled).
pub const BOOT_RFLAGS: u64 = 0x2;

pub const CR0_PE: u64 = 1 << 0;
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_ET: u64 = 1 << 4;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_AM: u64 = 1 << 18;
pub const CR0_PG: u64 = 1 << 31;
pub const CR4_PAE: u64 = 1 << 5;
pub const CR4_OSFXSR: u64 = 1 << 9;
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub const EFER_SCE: u64 = 1 << 0;
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;

/// A decoded segment descriptor: the fields of a segment register's hidden
/// part (and of KVM's `struct kvm_segment`, minus the selector).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub base: u32,
    /// Limit in bytes - 1, i.e. already scaled by the granularity bit.
    pub limit: u32,
    /// Type field (access byte bits 3:0).
    pub type_: u8,
    /// S: code/data (1) rather than system (0) descriptor.
    pub s: bool,
    pub dpl: u8,
    pub present: bool,
    pub avl: bool,
    /// L: 64-bit code segment.
    pub l: bool,
    /// D/B: 32-bit default operand size / big.
    pub db: bool,
    /// G: limit in 4 KiB units.
    pub g: bool,
}

impl Segment {
    /// Decode an 8-byte code/data segment descriptor.
    pub const fn decode(d: u64) -> Segment {
        let raw_limit = ((d & 0xffff) | ((d >> 32) & 0xf_0000)) as u32;
        let base = (((d >> 16) & 0xff_ffff) | ((d >> 32) & 0xff00_0000)) as u32;
        let access = (d >> 40) as u8;
        let flags = ((d >> 52) & 0xf) as u8;
        let g = flags & 0x8 != 0;
        Segment {
            base,
            limit: if g {
                (raw_limit << 12) | 0xfff
            } else {
                raw_limit
            },
            type_: access & 0xf,
            s: access & 0x10 != 0,
            dpl: (access >> 5) & 3,
            present: access & 0x80 != 0,
            avl: flags & 0x1 != 0,
            l: flags & 0x2 != 0,
            db: flags & 0x4 != 0,
            g,
        }
    }
}

/// Encode a descriptor from `flags` (access byte in bits 7:0, the G/DB/L/AVL
/// nibble in bits 15:12, as in the Linux kernel's `GDT_ENTRY()`), `base` and
/// a 20-bit raw `limit`.
pub const fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    let (flags, base, limit) = (flags as u64, base as u64, limit as u64);
    ((base & 0xff00_0000) << 32)
        | ((base & 0x00ff_ffff) << 16)
        | (limit & 0x0000_ffff)
        | ((limit & 0x000f_0000) << 32)
        | ((flags & 0xf0ff) << 40)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdt_matches_the_kernel_boot_descriptors() {
        // arch/x86/boot/pm.c / head_64.S: GDT_ENTRY(0xa09b, 0, 0xfffff) and
        // GDT_ENTRY(0xc093, 0, 0xfffff).
        assert_eq!(BOOT_GDT[2], gdt_entry(0xa09b, 0, 0xfffff));
        assert_eq!(BOOT_GDT[3], gdt_entry(0xc093, 0, 0xfffff));
        assert_eq!(BOOT_GDT[0], 0);
        assert_eq!(BOOT_GDT[1], 0);
        assert_eq!(BOOT_GDT_LIMIT, 31);
        assert_eq!(usize::from(BOOT_CS) / 8, 2);
        assert_eq!(usize::from(BOOT_DS) / 8, 3);
    }

    #[test]
    fn code_descriptor() {
        let c = Segment::decode(BOOT_GDT[BOOT_CS as usize / 8]);
        assert_eq!(
            c,
            Segment {
                base: 0,
                limit: 0xffff_ffff,
                type_: 0xb, // execute/read, accessed
                s: true,
                dpl: 0,
                present: true,
                avl: false,
                l: true,
                db: false, // must be 0 when L=1
                g: true,
            }
        );
    }

    #[test]
    fn data_descriptor() {
        let d = Segment::decode(BOOT_GDT[BOOT_DS as usize / 8]);
        assert_eq!(
            d,
            Segment {
                base: 0,
                limit: 0xffff_ffff,
                type_: 0x3, // read/write, accessed
                s: true,
                dpl: 0,
                present: true,
                avl: false,
                l: false,
                db: true,
                g: true,
            }
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        let e = gdt_entry(0x4093, 0x1234_5678, 0xabcde);
        let s = Segment::decode(e);
        assert_eq!(s.base, 0x1234_5678);
        assert_eq!(s.limit, 0xabcde, "byte granular: not scaled");
        assert!(s.db && !s.g && !s.l && s.present && s.s);
        assert_eq!(s.type_, 3);
        let s = Segment::decode(gdt_entry(0x00e9, 0, 0x67)); // DPL 3 TSS-like
        assert_eq!((s.dpl, s.type_, s.s, s.limit), (3, 9, false, 0x67));
    }

    #[test]
    fn control_register_values() {
        assert_eq!(BOOT_CR0, 0x8005_0033);
        assert_eq!(BOOT_CR4, 0x20);
        assert_eq!(BOOT_EFER, 0x500);
    }
}
