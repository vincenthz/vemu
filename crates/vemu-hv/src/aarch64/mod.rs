//! AArch64 guest types of the [`Vm`](crate::Vm)/[`Vcpu`](crate::Vcpu)
//! interface ([`Reg`], [`BootState`], [`GicRequest`], [`GicInfo`],
//! [`ArchVmInfo`]) and helpers shared by backends: exception syndrome (ESR)
//! decoding, MMIO register semantics and PSCI firmware emulation
//! ([`psci`]). Pure code, no hypervisor calls: it compiles (and is tested) on
//! every host.

pub mod psci;

/// A guest register reachable through [`Vcpu::get_reg`](crate::Vcpu::get_reg)
/// / [`Vcpu::set_reg`](crate::Vcpu::set_reg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    /// General-purpose register X0..=X30.
    X(u8),
    /// SP_EL1.
    Sp,
    Pc,
    /// PSTATE as saved in SPSR format.
    Cpsr,
}

/// Entry state of a vCPU, see
/// [`Vcpu::set_boot_state`](crate::Vcpu::set_boot_state): the arm64 Linux
/// boot protocol (Documentation/arch/arm64/booting.rst) and PSCI `CPU_ON`
/// both enter at `pc` with X0 = `x0` (the DTB address for the boot CPU), X1..X3
/// = 0, EL1h with D/A/I/F masked, MMU and caches off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootState {
    pub pc: u64,
    pub x0: u64,
}

/// Where the VMM wants the interrupt controller in the guest-physical map
/// (part of [`VmConfig`](crate::VmConfig)). The backend creates a GICv3 at
/// `dist_base` / `redist_base` when it can; a backend that can only offer a
/// GICv2 (KVM on hosts without a GICv3-capable vGIC) puts the distributor at
/// `dist_base` and the CPU interface at `v2_cpu_base`. HVF always creates a
/// GICv3 and ignores `v2_cpu_base`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicRequest {
    pub dist_base: u64,
    pub redist_base: u64,
    pub v2_cpu_base: u64,
}

impl Default for GicRequest {
    /// The QEMU `virt` addresses: distributor 0x0800_0000, GICv2 CPU
    /// interface 0x0801_0000, GICv3 redistributors 0x080A_0000.
    fn default() -> GicRequest {
        GicRequest {
            dist_base: 0x0800_0000,
            redist_base: 0x080A_0000,
            v2_cpu_base: 0x0801_0000,
        }
    }
}

/// Architecture version of the VM's in-kernel GIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    V2,
    V3,
}

/// Geometry of the VM's in-kernel GIC, for the device tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicInfo {
    pub version: GicVersion,
    pub dist_base: u64,
    pub dist_size: u64,
    /// GICv3 only (0 for a GICv2): redistributor region base.
    pub redist_base: u64,
    /// GICv3 only: size of the redistributor region *used by this VM*:
    /// `cpus * redist_stride`. The DT `reg` entry should use this. (HVF's
    /// maximal region is larger, but frames past the last vCPU are not
    /// claimed by the GIC: accesses there are ordinary MMIO exits.)
    pub redist_region_size: u64,
    /// GICv3 only: size of one vCPU's redistributor (RD_base + SGI_base
    /// frames).
    pub redist_stride: u64,
    /// GICv2 only (0 for a GICv3): CPU interface base.
    pub cpu_base: u64,
    /// GICv2 only: CPU interface size.
    pub cpu_size: u64,
    /// First SPI INTID (32).
    pub spi_base: u32,
    /// Number of SPIs, starting at `spi_base`.
    pub spi_count: u32,
}

impl GicInfo {
    /// Whether `intid` is one of this GIC's SPIs, i.e. a valid
    /// [`Vm::set_irq_line`](crate::Vm::set_irq_line) argument.
    pub fn is_spi(&self, intid: u32) -> bool {
        (self.spi_base..self.spi_base.saturating_add(self.spi_count)).contains(&intid)
    }
}

/// What [`Vm::arch_info`](crate::Vm::arch_info) reports on aarch64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchVmInfo {
    /// The GIC the backend actually created.
    pub gic: GicInfo,
    /// How many vCPUs share one Aff1 value in MPIDR_EL1 (a power of two,
    /// at most 256): see [`ArchVmInfo::mpidr`]. HVF: 256 (Aff0 = index);
    /// KVM: 16, the kernel's own assignment, which keeps every Aff0 below
    /// 16 so that GICv3 SGIs (16-bit target lists) can reach each vCPU.
    pub mpidr_aff0_cpus: u32,
}

impl ArchVmInfo {
    /// MPIDR_EL1 affinity of vCPU `index` (Aff2/Aff1/Aff0 in bits 23:0,
    /// without the RES1 bit 31): Aff0 = `index % mpidr_aff0_cpus`, then Aff1
    /// and Aff2 count the groups. This is the device tree `cpu` node `reg`
    /// and the PSCI `CPU_ON` target of that vCPU.
    pub fn mpidr(&self, index: usize) -> u64 {
        let per = u64::from(self.mpidr_aff0_cpus.clamp(1, 256));
        let (i, group) = (index as u64 % per, index as u64 / per);
        i | (group & 0xff) << 8 | (group >> 8 & 0xff) << 16
    }
}

/// Exception syndrome register (ESR_ELx) fields.
pub mod esr {
    /// Unknown reason.
    pub const EC_UNKNOWN: u8 = 0x00;
    /// Trapped WFI/WFE.
    pub const EC_WFX: u8 = 0x01;
    /// HVC from AArch64 state.
    pub const EC_HVC64: u8 = 0x16;
    /// SMC from AArch64 state.
    pub const EC_SMC64: u8 = 0x17;
    /// Trapped MSR/MRS/system instruction.
    pub const EC_SYSREG: u8 = 0x18;
    /// Instruction abort from a lower exception level.
    pub const EC_IABT_LOWER: u8 = 0x20;
    /// Data abort from a lower exception level.
    pub const EC_DABT_LOWER: u8 = 0x24;

    /// Exception class, ESR\[31:26\].
    pub fn ec(esr: u64) -> u8 {
        ((esr >> 26) & 0x3f) as u8
    }

    /// Length in bytes of the trapped instruction (IL, ESR\[25\]).
    pub fn insn_len(esr: u64) -> u64 {
        if esr & (1 << 25) != 0 { 4 } else { 2 }
    }

    /// Immediate of a trapped HVC/SMC, ISS\[15:0\].
    pub fn imm16(esr: u64) -> u16 {
        esr as u16
    }

    /// Decoded ISS of a data abort (EC 0x24).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DataAbort {
        /// ISS\[24\]: the fields below (SAS..AR) are valid.
        pub isv: bool,
        /// Access size in bytes (from SAS, ISS\[23:22\]).
        pub len: usize,
        /// ISS\[21\]: the load sign-extends.
        pub sign_extend: bool,
        /// ISS\[20:16\]: transfer register; 31 means XZR/WZR.
        pub srt: u8,
        /// ISS\[15\]: the transfer register is 64-bit (Xn), else 32-bit (Wn).
        pub sf: bool,
        /// ISS\[8\]: cache maintenance / address translation instruction.
        pub cm: bool,
        /// ISS\[7\]: fault on a stage-1 translation table walk.
        pub s1ptw: bool,
        /// ISS\[6\]: write (store) rather than read.
        pub write: bool,
    }

    impl DataAbort {
        pub fn decode(esr: u64) -> DataAbort {
            DataAbort {
                isv: esr & (1 << 24) != 0,
                len: 1 << ((esr >> 22) & 3),
                sign_extend: esr & (1 << 21) != 0,
                srt: ((esr >> 16) & 0x1f) as u8,
                sf: esr & (1 << 15) != 0,
                cm: esr & (1 << 8) != 0,
                s1ptw: esr & (1 << 7) != 0,
                write: esr & (1 << 6) != 0,
            }
        }
    }

    /// Decoded ISS of a trapped MSR/MRS (EC 0x18).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SysRegAccess {
        /// The register, see [`SysReg`].
        pub reg: SysReg,
        /// ISS\[9:5\]: general-purpose register; 31 means XZR.
        pub rt: u8,
        /// ISS\[0\]: MRS (read) rather than MSR (write).
        pub read: bool,
    }

    impl SysRegAccess {
        pub fn decode(esr: u64) -> SysRegAccess {
            let f = |shift: u32, bits: u32| ((esr >> shift) & ((1 << bits) - 1)) as u8;
            SysRegAccess {
                reg: SysReg {
                    op0: f(20, 2),
                    op2: f(17, 3),
                    op1: f(14, 3),
                    crn: f(10, 4),
                    crm: f(1, 4),
                },
                rt: f(5, 5),
                read: esr & 1 != 0,
            }
        }
    }

    /// A system register encoding `S<op0>_<op1>_C<crn>_C<crm>_<op2>`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SysReg {
        pub op0: u8,
        pub op1: u8,
        pub crn: u8,
        pub crm: u8,
        pub op2: u8,
    }

    impl SysReg {
        pub const fn new(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> SysReg {
            SysReg {
                op0,
                op1,
                crn,
                crm,
                op2,
            }
        }
    }

    impl std::fmt::Display for SysReg {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "S{}_{}_C{}_C{}_{}",
                self.op0, self.op1, self.crn, self.crm, self.op2
            )
        }
    }
}

/// Value an MMIO store of `len` bytes writes, given the source register value.
pub fn store_value(reg: u64, len: usize) -> u64 {
    reg & size_mask(len)
}

/// Value an MMIO load writes into its destination register: the device value
/// truncated to `len` bytes, sign-extended if the instruction asked (LDRS*),
/// and limited to 32 bits for a W destination (writing Wn zeroes the top half
/// of Xn).
pub fn load_value(device: u64, len: usize, sign_extend: bool, sf: bool) -> u64 {
    let mut v = device & size_mask(len);
    if sign_extend && len < 8 {
        let shift = 64 - 8 * len as u32;
        v = (((v << shift) as i64) >> shift) as u64;
    }
    if !sf {
        v &= 0xffff_ffff;
    }
    v
}

/// PSTATE.SS, CPSR\[21\]: software step, "active-not-pending" while set.
pub const PSTATE_SS: u64 = 1 << 21;
/// PSTATE.BTYPE, CPSR\[11:10\]: branch type of the last indirect branch
/// (FEAT_BTI).
pub const PSTATE_BTYPE: u64 = 0b11 << 10;

/// PSTATE after the hypervisor has emulated the trapped instruction and moved
/// the PC past it: the instruction counts as executed, so a pending software
/// step must be taken right after re-entry (SS cleared, as the hardware does
/// when an instruction completes) and the branch-target check no longer
/// applies (BTYPE cleared). Mirrors Linux KVM's `kvm_skip_instr`.
pub fn pstate_after_skip(cpsr: u64) -> u64 {
    cpsr & !(PSTATE_SS | PSTATE_BTYPE)
}

fn size_mask(len: usize) -> u64 {
    if len >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * len)) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::esr::*;
    use super::*;

    #[test]
    fn decode_data_abort() {
        // `str w0, [x1]` to unmapped IPA, captured on HVF.
        let d = DataAbort::decode(0x9380_0046);
        assert_eq!(ec(0x9380_0046), EC_DABT_LOWER);
        assert!(d.isv && d.write && !d.sign_extend && !d.sf && !d.s1ptw && !d.cm);
        assert_eq!((d.len, d.srt), (4, 0));
        // `ldrsh x9, [x20]`: SAS=1, SSE, SRT=9, SF, read.
        let esr =
            (0x24 << 26) | (1 << 25) | (1 << 24) | (1 << 22) | (1 << 21) | (9 << 16) | (1 << 15);
        let d = DataAbort::decode(esr);
        assert!(d.isv && d.sign_extend && d.sf && !d.write);
        assert_eq!((d.len, d.srt), (2, 9));
        assert_eq!(insn_len(esr), 4);
    }

    #[test]
    fn decode_sysreg() {
        // `msr oslar_el1, xzr`: S2_0_C1_C0_4, write, rt=31.
        let esr = (0x18u64 << 26) | (1 << 25) | (2 << 20) | (4 << 17) | (1 << 10) | (31 << 5);
        let b = SysRegAccess::decode(esr);
        assert_eq!(b.reg, SysReg::new(2, 0, 1, 0, 4));
        assert_eq!((b.rt, b.read), (31, false));
        assert_eq!(b.reg.to_string(), "S2_0_C1_C0_4");
        // `mrs x5, mdccsr_el0`: S2_3_C0_C1_0, read.
        let esr = (0x18u64 << 26) | (2 << 20) | (3 << 14) | (5 << 5) | (1 << 1) | 1;
        let c = SysRegAccess::decode(esr);
        assert_eq!(c.reg, SysReg::new(2, 3, 0, 1, 0));
        assert_eq!((c.rt, c.read), (5, true));
    }

    #[test]
    fn skip_clears_ss_and_btype() {
        // EL1h, DAIF clear, SS set, BTYPE=0b10 (after a BLR), NZCV set.
        let cpsr = 0xf000_0000 | PSTATE_SS | (0b10 << 10) | 0x5;
        assert_eq!(pstate_after_skip(cpsr), 0xf000_0005);
        assert_eq!(pstate_after_skip(0x3c5), 0x3c5, "nothing else changes");
        assert_eq!(pstate_after_skip(u64::MAX), !(0x3u64 << 10 | 1 << 21));
    }

    #[test]
    fn mpidr_affinity() {
        let gic = GicInfo {
            version: GicVersion::V3,
            dist_base: 0,
            dist_size: 0,
            redist_base: 0,
            redist_region_size: 0,
            redist_stride: 0,
            cpu_base: 0,
            cpu_size: 0,
            spi_base: 32,
            spi_count: 256,
        };
        // Linux KVM's kvm_calculate_mpidr (arch/arm64/kvm/sys_regs.h):
        // Aff0 = id & 0xf, Aff1 = (id >> 4) & 0xff, Aff2 = (id >> 12) & 0xff.
        let kvm = ArchVmInfo {
            gic,
            mpidr_aff0_cpus: 16,
        };
        for id in [0usize, 1, 15, 16, 17, 63, 255, 4095, 4096, 0x12345] {
            let want = (id & 0xf) | ((id >> 4) & 0xff) << 8 | ((id >> 12) & 0xff) << 16;
            assert_eq!(kvm.mpidr(id), want as u64, "vCPU {id}");
        }
        assert_eq!(kvm.mpidr(16), 0x100);
        // HVF: Aff0 = index.
        let hvf = ArchVmInfo {
            gic,
            mpidr_aff0_cpus: 256,
        };
        assert_eq!(hvf.mpidr(5), 5);
        assert_eq!(hvf.mpidr(63), 63);
        assert_eq!(hvf.mpidr(256), 0x100);
    }

    #[test]
    fn mmio_values() {
        assert_eq!(store_value(0x1122_3344_5566_7788, 1), 0x88);
        assert_eq!(store_value(0x1122_3344_5566_7788, 2), 0x7788);
        assert_eq!(store_value(0x1122_3344_5566_7788, 4), 0x5566_7788);
        assert_eq!(store_value(0x1122_3344_5566_7788, 8), 0x1122_3344_5566_7788);
        // zero-extension, extra device bits dropped
        assert_eq!(load_value(0x1ff, 1, false, false), 0xff);
        assert_eq!(
            load_value(0xffff_ffff_8000_0001, 4, false, false),
            0x8000_0001
        );
        assert_eq!(
            load_value(0xffff_ffff_8000_0001, 8, false, true),
            0xffff_ffff_8000_0001
        );
        // sign extension into X and W
        assert_eq!(load_value(0x80, 1, true, true), 0xffff_ffff_ffff_ff80);
        assert_eq!(load_value(0x80, 1, true, false), 0xffff_ff80);
        assert_eq!(load_value(0x7f, 1, true, true), 0x7f);
        assert_eq!(load_value(0x8000, 2, true, true), 0xffff_ffff_ffff_8000);
        assert_eq!(load_value(0x8000, 2, true, false), 0xffff_8000);
        assert_eq!(
            load_value(0x8000_0000, 4, true, true),
            0xffff_ffff_8000_0000
        );
    }
}
