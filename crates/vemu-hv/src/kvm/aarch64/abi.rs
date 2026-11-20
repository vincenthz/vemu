//! arm64 KVM UAPI mirrors and the pure logic of the aarch64 KVM backend
//! (`kvm/aarch64.rs`): `struct kvm_vcpu_init`, the arm64 ioctls,
//! `KVM_REG_ARM64` register ids, vGIC device attributes, the `KVM_IRQ_LINE`
//! encoding, the IPA size choice and the vGIC geometry.
//!
//! No system calls here: this file is also compiled for `cfg(test)` on
//! macOS (lib.rs) so its tests run on every host. Sources:
//! `arch/arm64/include/uapi/asm/kvm.h`, `include/uapi/linux/kvm.h`,
//! Documentation/virt/kvm/api.rst and devices/arm-vgic{,-v3}.rst. Every
//! value below is pinned by a const assert and listed in [`abi_table`],
//! which a test compares with `scripts/kvm-abi/probe-aarch64.h`, the file
//! `scripts/kvm-abi/check.sh` compiles against the real headers.

use std::mem::{offset_of, size_of};

use crate::aarch64::{GicInfo, GicRequest, GicVersion, Reg};
use crate::kvm::abi::{KVM_REG_SIZE_U64, ior, iow};

// --- vCPU init ------------------------------------------------------------------

/// `struct kvm_vcpu_init`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmVcpuInit {
    pub target: u32,
    pub features: [u32; 7],
}

/// VM ioctl: the target to pass to `KVM_ARM_VCPU_INIT`.
pub(crate) const KVM_ARM_PREFERRED_TARGET: u32 = ior::<KvmVcpuInit>(0xaf);
/// vCPU ioctl: initialise (or reset) the vCPU.
pub(crate) const KVM_ARM_VCPU_INIT: u32 = iow::<KvmVcpuInit>(0xae);

/// `kvm_vcpu_init.features[0]` bits.
pub(crate) const KVM_ARM_VCPU_POWER_OFF: u32 = 0;
pub(crate) const KVM_ARM_VCPU_PSCI_0_2: u32 = 2;
/// Not requested: vemu describes no PMU (dtb.rs).
#[allow(dead_code)]
pub(crate) const KVM_ARM_VCPU_PMU_V3: u32 = 3;

/// Features of every vemu vCPU: in-kernel PSCI 0.2+ (KVM implements the
/// newest PSCI it knows, 1.x, behind this flag), nothing else (no PMU, SVE,
/// pointer authentication, nested virtualisation, AArch32). The boot vCPU
/// (index 0) starts powered on; the others start with POWER_OFF and wait
/// for PSCI `CPU_ON`.
pub(crate) fn vcpu_features(index: usize, power_off_secondaries: bool) -> [u32; 7] {
    let mut f = [0u32; 7];
    f[0] = 1 << KVM_ARM_VCPU_PSCI_0_2;
    if index > 0 && power_off_secondaries {
        f[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
    }
    f
}

// --- capabilities, VM type ----------------------------------------------------------

pub(crate) const KVM_CAP_ARM_PSCI_0_2: u32 = 102;
pub(crate) const KVM_CAP_ARM_NISV_TO_USER: u32 = 177;

/// `KVM_VM_TYPE_ARM_IPA_SIZE(x) = x & KVM_VM_TYPE_ARM_IPA_SIZE_MASK`.
pub(crate) const KVM_VM_TYPE_ARM_IPA_SIZE_MASK: u64 = 0xff;
/// IPA size of VM type 0 (and of kernels without KVM_CAP_ARM_VM_IPA_SIZE).
pub(crate) const DEFAULT_IPA_BITS: u32 = 40;
/// Smallest IPA size KVM accepts.
pub(crate) const MIN_IPA_BITS: u32 = 32;

/// Address bits needed to reach every byte below `end` (exclusive).
pub(crate) fn bits_for(end: u64) -> u32 {
    if end <= 1 {
        0
    } else {
        64 - (end - 1).leading_zeros()
    }
}

/// `KVM_CREATE_VM` machine type: the IPA (guest-physical address) size.
///
/// `host_limit` is `KVM_CHECK_EXTENSION(KVM_CAP_ARM_VM_IPA_SIZE)`: the
/// largest IPA size the host supports, or 0 when the kernel predates the
/// capability (Linux < 4.20; then only type 0, 40 bits, exists). `need_end`
/// is the end of the guest-physical space the backend itself must place
/// (the GIC).
///
/// The choice is `min(host_limit, 40)`, raised to what `need_end` needs: 40
/// bits is KVM's default and covers vemu's whole machine layout (RAM ends
/// below 2^36, `layout::IPA_LIMIT` in the binary) with room to spare, while
/// a larger IPA would only add stage-2 table levels. On a host with fewer
/// than 40 IPA bits the VM gets the host's limit, so RAM is limited to
/// `2^bits - 1 GiB` there (mapping more fails in `map_memory`).
pub(crate) fn vm_type(host_limit: i32, need_end: u64) -> Result<u64, String> {
    let need = bits_for(need_end).max(MIN_IPA_BITS);
    if host_limit <= 0 {
        return if need <= DEFAULT_IPA_BITS {
            Ok(0)
        } else {
            Err(format!(
                "the GIC needs {need} address bits, but this kernel only offers \
                 {DEFAULT_IPA_BITS}-bit VMs"
            ))
        };
    }
    let host = host_limit as u32;
    if need > host {
        return Err(format!(
            "the GIC needs {need} address bits, but the host supports {host}-bit guests"
        ));
    }
    let bits = host.min(DEFAULT_IPA_BITS).max(need);
    Ok(u64::from(bits) & KVM_VM_TYPE_ARM_IPA_SIZE_MASK)
}

// --- registers ----------------------------------------------------------------------

/// `KVM_REG_ARM64`: arch field of a ONE_REG id.
pub(crate) const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
/// Coprocessor field: core registers (`struct kvm_regs`, by u32 offset).
pub(crate) const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;
/// Coprocessor field: system registers (op0/op1/CRn/CRm/op2).
pub(crate) const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << 16;

/// `struct user_pt_regs`.
#[repr(C)]
pub(crate) struct UserPtRegs {
    pub regs: [u64; 31],
    /// SP_EL0.
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// The start of `struct kvm_regs` (`fp_regs`, a `user_fpsimd_state`,
/// follows; vemu never accesses it, so it is left out). Only used for
/// offsets: core register ids are `offsetof(struct kvm_regs, field) / 4`.
#[repr(C)]
pub(crate) struct KvmRegsCore {
    pub regs: UserPtRegs,
    pub sp_el1: u64,
    pub elr_el1: u64,
    pub spsr: [u64; 5],
}

/// ONE_REG id of the 64-bit core register at byte `offset` of `struct
/// kvm_regs` (`KVM_REG_ARM_CORE_REG`).
pub(crate) const fn core_reg(offset: usize) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (offset / 4) as u64
}

/// ONE_REG id of `Xn` (n <= 30).
pub(crate) const fn x_reg(n: u8) -> u64 {
    core_reg(offset_of!(KvmRegsCore, regs) + n as usize * 8)
}

pub(crate) const REG_PC: u64 = core_reg(offset_of!(KvmRegsCore, regs) + offset_of!(UserPtRegs, pc));
pub(crate) const REG_PSTATE: u64 =
    core_reg(offset_of!(KvmRegsCore, regs) + offset_of!(UserPtRegs, pstate));
pub(crate) const REG_SP_EL1: u64 = core_reg(offset_of!(KvmRegsCore, sp_el1));

/// `ARM64_SYS_REG(op0, op1, crn, crm, op2)`.
pub(crate) const fn sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG
        | (op0 << 14 & 0xc000)
        | (op1 << 11 & 0x3800)
        | (crn << 7 & 0x0780)
        | (crm << 3 & 0x0078)
        | (op2 & 0x7)
}

/// MPIDR_EL1 = S3_0_C0_C0_5.
pub(crate) const REG_MPIDR_EL1: u64 = sys_reg(3, 0, 0, 0, 5);
/// MPIDR_EL1 bit 31 is RES1.
pub(crate) const MPIDR_RES1: u64 = 1 << 31;
/// MPIDR_EL1 affinity fields (Aff3 39:32, Aff2 23:16, Aff1 15:8, Aff0 7:0).
pub(crate) const MPIDR_AFFINITY_MASK: u64 = 0xff_00ff_ffff;

/// The vCPUs per Aff1 group KVM assigns (`kvm_calculate_mpidr`: Aff0 =
/// vcpu_id & 0xf, Aff1 = (vcpu_id >> 4) & 0xff, Aff2 = (vcpu_id >> 12) &
/// 0xff) and vemu keeps: GICv3 SGIs (ICC_SGI1R_EL1 16-bit target lists)
/// cannot reach Aff0 >= 16 without the range selector, which KVM's vGIC
/// does not offer.
pub(crate) const KVM_MPIDR_AFF0_CPUS: u32 = 16;

/// PSTATE at entry (arm64 boot protocol, PSCI CPU_ON, and KVM's own reset
/// value): EL1h with D, A, I, F masked.
pub(crate) const PSTATE_EL1H_DAIF: u64 = 0x3c5;

/// ONE_REG id of a [`Reg`].
pub(crate) fn reg_id(reg: Reg) -> Result<u64, String> {
    match reg {
        Reg::X(n @ 0..=30) => Ok(x_reg(n)),
        Reg::X(n) => Err(format!("X{n} does not exist (X0..X30)")),
        Reg::Sp => Ok(REG_SP_EL1),
        Reg::Pc => Ok(REG_PC),
        Reg::Cpsr => Ok(REG_PSTATE),
    }
}

// --- vGIC ----------------------------------------------------------------------------

/// `enum kvm_device_type`.
pub(crate) const KVM_DEV_TYPE_ARM_VGIC_V2: u32 = 5;
pub(crate) const KVM_DEV_TYPE_ARM_VGIC_V3: u32 = 7;

/// vGIC device attribute groups (`kvm_device_attr.group`).
pub(crate) const KVM_DEV_ARM_VGIC_GRP_ADDR: u32 = 0;
pub(crate) const KVM_DEV_ARM_VGIC_GRP_NR_IRQS: u32 = 3;
pub(crate) const KVM_DEV_ARM_VGIC_GRP_CTRL: u32 = 4;
/// `KVM_DEV_ARM_VGIC_GRP_CTRL` attribute: initialise the vGIC.
pub(crate) const KVM_DEV_ARM_VGIC_CTRL_INIT: u64 = 0;

/// `KVM_DEV_ARM_VGIC_GRP_ADDR` attributes.
pub(crate) const KVM_VGIC_V2_ADDR_TYPE_DIST: u64 = 0;
pub(crate) const KVM_VGIC_V2_ADDR_TYPE_CPU: u64 = 1;
pub(crate) const KVM_VGIC_V3_ADDR_TYPE_DIST: u64 = 2;
/// The legacy single redistributor region: one frame per vCPU, in vCPU
/// creation order, as many as there are vCPUs.
pub(crate) const KVM_VGIC_V3_ADDR_TYPE_REDIST: u64 = 3;

/// Region sizes the kernel emulates.
pub(crate) const KVM_VGIC_V2_DIST_SIZE: u64 = 0x1000;
pub(crate) const KVM_VGIC_V2_CPU_SIZE: u64 = 0x2000;
pub(crate) const KVM_VGIC_V3_DIST_SIZE: u64 = 0x1_0000;
/// One vCPU's redistributor: RD_base + SGI_base frames.
pub(crate) const KVM_VGIC_V3_REDIST_SIZE: u64 = 0x2_0000;

/// Base alignment the kernel requires (vgic-kvm-device.c, kvm_vgic_addr).
const VGIC_V2_ALIGN: u64 = 0x1000;
const VGIC_V3_ALIGN: u64 = 0x1_0000;
/// GICv2 CPU interfaces: at most 8 vCPUs (VGIC_V2_MAX_CPUS).
pub(crate) const VGIC_V2_MAX_CPUS: usize = 8;

/// First SPI INTID.
pub(crate) const SPI_BASE: u32 = 32;
/// SPIs vemu asks for: 256 (QEMU `virt`'s count), INTIDs 32..288. The
/// machine uses 33 (debug UART) and 48..80 (virtio).
pub(crate) const SPI_COUNT: u32 = 256;
/// `KVM_DEV_ARM_VGIC_GRP_NR_IRQS` value: every INTID including the 32
/// private ones; the kernel wants a multiple of 32 in 64..=1023.
pub(crate) const NR_IRQS: u32 = SPI_BASE + SPI_COUNT;
const _: () = assert!(NR_IRQS.is_multiple_of(32) && NR_IRQS >= 64 && NR_IRQS <= 1023);

fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.0.saturating_add(b.1) && b.0 < a.0.saturating_add(a.1)
}

fn check_base(what: &str, base: u64, align: u64) -> Result<(), String> {
    if base.is_multiple_of(align) {
        Ok(())
    } else {
        Err(format!(
            "GIC {what} base {base:#x} is not {align:#x}-aligned"
        ))
    }
}

/// The GICv3 KVM creates for `cpus` vCPUs at the requested addresses.
pub(crate) fn gic_v3_info(req: &GicRequest, cpus: usize) -> Result<GicInfo, String> {
    check_base("distributor", req.dist_base, VGIC_V3_ALIGN)?;
    check_base("redistributor", req.redist_base, VGIC_V3_ALIGN)?;
    let redist_size = (cpus as u64)
        .checked_mul(KVM_VGIC_V3_REDIST_SIZE)
        .ok_or("too many vCPUs")?;
    let dist = (req.dist_base, KVM_VGIC_V3_DIST_SIZE);
    let redist = (req.redist_base, redist_size);
    if overlaps(dist, redist) {
        return Err(format!(
            "GICv3 redistributors {:#x}+{redist_size:#x} overlap the distributor at {:#x}",
            req.redist_base, req.dist_base
        ));
    }
    Ok(GicInfo {
        version: GicVersion::V3,
        dist_base: req.dist_base,
        dist_size: KVM_VGIC_V3_DIST_SIZE,
        redist_base: req.redist_base,
        redist_region_size: redist_size,
        redist_stride: KVM_VGIC_V3_REDIST_SIZE,
        cpu_base: 0,
        cpu_size: 0,
        spi_base: SPI_BASE,
        spi_count: SPI_COUNT,
    })
}

/// The GICv2 KVM creates (hosts without GICv3 emulation).
pub(crate) fn gic_v2_info(req: &GicRequest, cpus: usize) -> Result<GicInfo, String> {
    if cpus > VGIC_V2_MAX_CPUS {
        return Err(format!(
            "{cpus} vCPUs requested, but this host only emulates a GICv2, which \
             supports at most {VGIC_V2_MAX_CPUS}"
        ));
    }
    check_base("distributor", req.dist_base, VGIC_V2_ALIGN)?;
    check_base("CPU interface", req.v2_cpu_base, VGIC_V2_ALIGN)?;
    if overlaps(
        (req.dist_base, KVM_VGIC_V2_DIST_SIZE),
        (req.v2_cpu_base, KVM_VGIC_V2_CPU_SIZE),
    ) {
        return Err(format!(
            "GICv2 CPU interface at {:#x} overlaps the distributor at {:#x}",
            req.v2_cpu_base, req.dist_base
        ));
    }
    Ok(GicInfo {
        version: GicVersion::V2,
        dist_base: req.dist_base,
        dist_size: KVM_VGIC_V2_DIST_SIZE,
        redist_base: 0,
        redist_region_size: 0,
        redist_stride: 0,
        cpu_base: req.v2_cpu_base,
        cpu_size: KVM_VGIC_V2_CPU_SIZE,
        spi_base: SPI_BASE,
        spi_count: SPI_COUNT,
    })
}

/// End of the guest-physical space the GIC (v3, else v2) needs, for the
/// IPA size: the highest end of either variant, since the version is only
/// known after the VM exists.
pub(crate) fn gic_end(req: &GicRequest, cpus: usize) -> u64 {
    let redist = (cpus as u64).saturating_mul(KVM_VGIC_V3_REDIST_SIZE);
    [
        req.dist_base.saturating_add(KVM_VGIC_V3_DIST_SIZE),
        req.redist_base.saturating_add(redist),
        req.v2_cpu_base.saturating_add(KVM_VGIC_V2_CPU_SIZE),
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
}

// --- KVM_IRQ_LINE --------------------------------------------------------------------

/// `kvm_irq_level.irq` fields on arm64 (api.rst, KVM_IRQ_LINE): vcpu2_index
/// 31:28, irq_type 27:24, vcpu_index 23:16, irq_id 15:0.
pub(crate) const KVM_ARM_IRQ_TYPE_SHIFT: u32 = 24;
pub(crate) const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;
pub(crate) const KVM_ARM_IRQ_NUM_MASK: u32 = 0xffff;

/// `kvm_irq_level.irq` for SPI `intid` (the absolute INTID, >= 32; the
/// vCPU fields are ignored for SPIs).
pub(crate) fn spi_irq_line(gic: &GicInfo, intid: u32) -> Result<u32, String> {
    if !gic.is_spi(intid) || intid > KVM_ARM_IRQ_NUM_MASK {
        return Err(format!(
            "interrupt {intid} is not one of the GIC's SPIs ({}..{})",
            gic.spi_base,
            gic.spi_base + gic.spi_count
        ));
    }
    Ok(KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT | intid)
}

// --- layout pins ---------------------------------------------------------------------

const _: () = {
    assert!(size_of::<KvmVcpuInit>() == 32);
    assert!(offset_of!(KvmVcpuInit, features) == 4);
    assert!(size_of::<UserPtRegs>() == 272);
    assert!(offset_of!(UserPtRegs, sp) == 248);
    assert!(offset_of!(UserPtRegs, pc) == 256);
    assert!(offset_of!(UserPtRegs, pstate) == 264);
    assert!(offset_of!(KvmRegsCore, sp_el1) == 272);
    assert!(offset_of!(KvmRegsCore, elr_el1) == 280);
    assert!(offset_of!(KvmRegsCore, spsr) == 288);
    assert!(KVM_ARM_PREFERRED_TARGET == 0x8020_aeaf);
    assert!(KVM_ARM_VCPU_INIT == 0x4020_aeae);
    assert!(x_reg(0) == 0x6030_0000_0010_0000);
    assert!(x_reg(30) == 0x6030_0000_0010_003c);
    assert!(REG_PC == 0x6030_0000_0010_0040);
    assert!(REG_PSTATE == 0x6030_0000_0010_0042);
    assert!(REG_SP_EL1 == 0x6030_0000_0010_0044);
    assert!(REG_MPIDR_EL1 == 0x6030_0000_0013_c005);
    // KVM_DEV_ARM_VGIC_GRP_NR_IRQS is read by the kernel as a u32 through
    // the attribute's pointer; vemu passes a u64, whose first 4 bytes are
    // its low half on little-endian hosts only.
    assert!(cfg!(target_endian = "little"));
};

/// Every arm64 value checked against the C headers: `(C expression,
/// value)`, exactly the `VEMU_CHECK` lines of
/// `scripts/kvm-abi/probe-aarch64.h` (test `probe_header_matches`).
#[cfg(test)]
pub(crate) fn abi_table() -> Vec<(&'static str, u64)> {
    let pt = |off: usize| (offset_of!(KvmRegsCore, regs) + off) as u64;
    vec![
        (
            "sizeof(struct kvm_vcpu_init)",
            size_of::<KvmVcpuInit>() as u64,
        ),
        (
            "offsetof(struct kvm_vcpu_init, features)",
            offset_of!(KvmVcpuInit, features) as u64,
        ),
        (
            "KVM_ARM_PREFERRED_TARGET",
            u64::from(KVM_ARM_PREFERRED_TARGET),
        ),
        ("KVM_ARM_VCPU_INIT", u64::from(KVM_ARM_VCPU_INIT)),
        ("KVM_ARM_VCPU_POWER_OFF", u64::from(KVM_ARM_VCPU_POWER_OFF)),
        ("KVM_ARM_VCPU_PSCI_0_2", u64::from(KVM_ARM_VCPU_PSCI_0_2)),
        ("KVM_ARM_VCPU_PMU_V3", u64::from(KVM_ARM_VCPU_PMU_V3)),
        ("KVM_CAP_ARM_PSCI_0_2", u64::from(KVM_CAP_ARM_PSCI_0_2)),
        (
            "KVM_CAP_ARM_NISV_TO_USER",
            u64::from(KVM_CAP_ARM_NISV_TO_USER),
        ),
        (
            "KVM_VM_TYPE_ARM_IPA_SIZE_MASK",
            KVM_VM_TYPE_ARM_IPA_SIZE_MASK,
        ),
        ("KVM_VM_TYPE_ARM_IPA_SIZE(36)", 36),
        ("KVM_REG_ARM64", KVM_REG_ARM64),
        ("KVM_REG_ARM_CORE", KVM_REG_ARM_CORE),
        ("KVM_REG_ARM64_SYSREG", KVM_REG_ARM64_SYSREG),
        ("offsetof(struct kvm_regs, regs.regs[0])", pt(0)),
        ("offsetof(struct kvm_regs, regs.regs[30])", pt(30 * 8)),
        (
            "offsetof(struct kvm_regs, regs.sp)",
            pt(offset_of!(UserPtRegs, sp)),
        ),
        (
            "offsetof(struct kvm_regs, regs.pc)",
            pt(offset_of!(UserPtRegs, pc)),
        ),
        (
            "offsetof(struct kvm_regs, regs.pstate)",
            pt(offset_of!(UserPtRegs, pstate)),
        ),
        (
            "offsetof(struct kvm_regs, sp_el1)",
            offset_of!(KvmRegsCore, sp_el1) as u64,
        ),
        (
            "offsetof(struct kvm_regs, elr_el1)",
            offset_of!(KvmRegsCore, elr_el1) as u64,
        ),
        (
            "offsetof(struct kvm_regs, spsr)",
            offset_of!(KvmRegsCore, spsr) as u64,
        ),
        (
            "KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(regs.regs[0])",
            x_reg(0),
        ),
        (
            "KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(regs.regs[1])",
            x_reg(1),
        ),
        (
            "KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(regs.regs[30])",
            x_reg(30),
        ),
        (
            "KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(regs.pc)",
            REG_PC,
        ),
        (
            "KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(regs.pstate)",
            REG_PSTATE,
        ),
        (
            "KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(sp_el1)",
            REG_SP_EL1,
        ),
        ("ARM64_SYS_REG(3, 0, 0, 0, 5)", REG_MPIDR_EL1),
        // A system register id with every field non-zero: S3_3_C14_C3_2
        // (the header's KVM_REG_ARM_TIMER_CNT).
        ("KVM_REG_ARM_TIMER_CNT", sys_reg(3, 3, 14, 3, 2)),
        (
            "KVM_DEV_TYPE_ARM_VGIC_V2",
            u64::from(KVM_DEV_TYPE_ARM_VGIC_V2),
        ),
        (
            "KVM_DEV_TYPE_ARM_VGIC_V3",
            u64::from(KVM_DEV_TYPE_ARM_VGIC_V3),
        ),
        (
            "KVM_DEV_ARM_VGIC_GRP_ADDR",
            u64::from(KVM_DEV_ARM_VGIC_GRP_ADDR),
        ),
        (
            "KVM_DEV_ARM_VGIC_GRP_NR_IRQS",
            u64::from(KVM_DEV_ARM_VGIC_GRP_NR_IRQS),
        ),
        (
            "KVM_DEV_ARM_VGIC_GRP_CTRL",
            u64::from(KVM_DEV_ARM_VGIC_GRP_CTRL),
        ),
        ("KVM_DEV_ARM_VGIC_CTRL_INIT", KVM_DEV_ARM_VGIC_CTRL_INIT),
        ("KVM_VGIC_V2_ADDR_TYPE_DIST", KVM_VGIC_V2_ADDR_TYPE_DIST),
        ("KVM_VGIC_V2_ADDR_TYPE_CPU", KVM_VGIC_V2_ADDR_TYPE_CPU),
        ("KVM_VGIC_V3_ADDR_TYPE_DIST", KVM_VGIC_V3_ADDR_TYPE_DIST),
        ("KVM_VGIC_V3_ADDR_TYPE_REDIST", KVM_VGIC_V3_ADDR_TYPE_REDIST),
        ("KVM_VGIC_V2_DIST_SIZE", KVM_VGIC_V2_DIST_SIZE),
        ("KVM_VGIC_V2_CPU_SIZE", KVM_VGIC_V2_CPU_SIZE),
        ("KVM_VGIC_V3_DIST_SIZE", KVM_VGIC_V3_DIST_SIZE),
        ("KVM_VGIC_V3_REDIST_SIZE", KVM_VGIC_V3_REDIST_SIZE),
        ("KVM_ARM_IRQ_TYPE_SHIFT", u64::from(KVM_ARM_IRQ_TYPE_SHIFT)),
        ("KVM_ARM_IRQ_TYPE_SPI", u64::from(KVM_ARM_IRQ_TYPE_SPI)),
        ("KVM_ARM_IRQ_NUM_MASK", u64::from(KVM_ARM_IRQ_NUM_MASK)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> GicRequest {
        GicRequest::default()
    }

    /// The `VEMU_CHECK(expr, value)` lines of probe-aarch64.h are exactly
    /// [`abi_table`]: so what check.sh proves about the C headers holds for
    /// the Rust values.
    #[test]
    fn probe_header_matches() {
        // Embedded at build time: the test binary also runs in a Linux guest
        // without the source tree.
        let text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/kvm-abi/probe-aarch64.h"
        ));
        let mut probe = Vec::new();
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("VEMU_CHECK(") else {
                continue;
            };
            let body = rest.strip_suffix(')').expect("VEMU_CHECK(...) on one line");
            let (expr, val) = body.rsplit_once(',').expect("VEMU_CHECK(expr, value)");
            let val = val.trim().trim_end_matches("ULL");
            let n = match val.strip_prefix("0x") {
                Some(h) => u64::from_str_radix(h, 16),
                None => val.parse(),
            }
            .unwrap_or_else(|e| panic!("bad value {val:?}: {e}"));
            probe.push((expr.trim().to_string(), n));
        }
        let table: Vec<(String, u64)> = abi_table()
            .into_iter()
            .map(|(e, v)| (e.to_string(), v))
            .collect();
        for (e, v) in &table {
            let found: Vec<_> = probe.iter().filter(|(pe, _)| pe == e).collect();
            assert_eq!(found.len(), 1, "probe-aarch64.h must check {e} once");
            assert_eq!(
                found[0].1, *v,
                "{e}: probe says {:#x}, Rust {v:#x}",
                found[0].1
            );
        }
        for (e, _) in &probe {
            assert!(
                table.iter().any(|(te, _)| te == e),
                "probe-aarch64.h checks {e}, which abi_table() lacks"
            );
        }
    }

    #[test]
    fn register_ids() {
        // KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | offset/4.
        assert_eq!(reg_id(Reg::X(0)), Ok(0x6030_0000_0010_0000));
        assert_eq!(reg_id(Reg::X(1)), Ok(0x6030_0000_0010_0002));
        assert_eq!(reg_id(Reg::X(30)), Ok(0x6030_0000_0010_003c));
        assert_eq!(reg_id(Reg::Pc), Ok(0x6030_0000_0010_0040));
        assert_eq!(reg_id(Reg::Cpsr), Ok(0x6030_0000_0010_0042));
        // vemu's Sp is SP_EL1 (as on HVF), not user_pt_regs.sp (SP_EL0).
        assert_eq!(reg_id(Reg::Sp), Ok(0x6030_0000_0010_0044));
        assert!(reg_id(Reg::X(31)).is_err());
        // Same encoding as HVF's HV_SYS_REG_MPIDR_EL1 (0xc005) in the low bits.
        assert_eq!(REG_MPIDR_EL1 & 0xffff, 0xc005);
        assert_eq!(
            crate::kvm::abi::one_reg_size(REG_MPIDR_EL1),
            8,
            "64-bit ids only"
        );
        for id in [x_reg(7), REG_PC, REG_PSTATE, REG_SP_EL1] {
            assert_eq!(crate::kvm::abi::one_reg_size(id), 8);
        }
    }

    #[test]
    fn features() {
        assert_eq!(vcpu_features(0, true), [4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(vcpu_features(1, true), [5, 0, 0, 0, 0, 0, 0]);
        assert_eq!(vcpu_features(7, false), [4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(vcpu_features(3, true)[0] & (1 << KVM_ARM_VCPU_PMU_V3), 0);
    }

    #[test]
    fn ipa_size() {
        let gic = gic_end(&req(), 64);
        assert_eq!(gic, 0x080A_0000 + 64 * 0x20000);
        assert_eq!(bits_for(gic), 28);
        assert_eq!(bits_for(1 << 36), 36);
        assert_eq!(bits_for((1 << 36) + 1), 37);
        assert_eq!(bits_for(0), 0);
        // Old kernel: type 0 (40 bits).
        assert_eq!(vm_type(0, gic), Ok(0));
        assert!(vm_type(0, 1 << 41).is_err());
        // Capped at the 40-bit default; the host's limit below that.
        assert_eq!(vm_type(48, gic), Ok(40));
        assert_eq!(vm_type(40, gic), Ok(40));
        assert_eq!(vm_type(36, gic), Ok(36));
        assert_eq!(vm_type(32, gic), Ok(32));
        // Never below KVM's minimum; never above the host.
        assert_eq!(vm_type(44, 0x1000), Ok(40));
        assert_eq!(vm_type(48, 1 << 44), Ok(44));
        assert!(vm_type(36, 1 << 40).is_err());
    }

    #[test]
    fn gic_v3_geometry() {
        let g = gic_v3_info(&req(), 4).unwrap();
        assert_eq!(g.version, GicVersion::V3);
        assert_eq!((g.dist_base, g.dist_size), (0x0800_0000, 0x10000));
        assert_eq!(
            (g.redist_base, g.redist_region_size, g.redist_stride),
            (0x080A_0000, 4 * 0x20000, 0x20000)
        );
        assert_eq!((g.cpu_base, g.cpu_size), (0, 0));
        assert_eq!((g.spi_base, g.spi_count), (32, 256));
        assert!(g.is_spi(33) && g.is_spi(79) && g.is_spi(287));
        assert!(!g.is_spi(288) && !g.is_spi(31));
        let bad = GicRequest {
            redist_base: 0x0800_8000,
            ..req()
        };
        assert!(gic_v3_info(&bad, 1).unwrap_err().contains("aligned"));
        let bad = GicRequest {
            redist_base: 0x0800_0000,
            ..req()
        };
        assert!(gic_v3_info(&bad, 1).unwrap_err().contains("overlap"));
        // Redistributors below the distributor must not run into it.
        let low = GicRequest {
            dist_base: 0x0810_0000,
            redist_base: 0x0800_0000,
            v2_cpu_base: 0,
        };
        assert!(gic_v3_info(&low, 8).is_ok());
        assert!(gic_v3_info(&low, 9).is_err());
    }

    #[test]
    fn gic_v2_geometry() {
        let g = gic_v2_info(&req(), 8).unwrap();
        assert_eq!(g.version, GicVersion::V2);
        assert_eq!((g.dist_base, g.dist_size), (0x0800_0000, 0x1000));
        assert_eq!((g.cpu_base, g.cpu_size), (0x0801_0000, 0x2000));
        assert_eq!(
            (g.redist_base, g.redist_region_size, g.redist_stride),
            (0, 0, 0)
        );
        assert_eq!((g.spi_base, g.spi_count), (32, 256));
        assert!(gic_v2_info(&req(), 9).unwrap_err().contains("at most 8"));
        let bad = GicRequest {
            v2_cpu_base: 0x0800_0800,
            ..req()
        };
        assert!(gic_v2_info(&bad, 1).unwrap_err().contains("aligned"));
        let bad = GicRequest {
            v2_cpu_base: 0x0800_0000,
            ..req()
        };
        assert!(gic_v2_info(&bad, 1).unwrap_err().contains("overlaps"));
    }

    #[test]
    fn irq_line_encoding() {
        let g = gic_v3_info(&req(), 1).unwrap();
        // irq_type SPI (1) in bits 27:24, the absolute INTID in 15:0.
        assert_eq!(spi_irq_line(&g, 32), Ok(0x0100_0020));
        assert_eq!(spi_irq_line(&g, 48), Ok(0x0100_0030));
        assert_eq!(spi_irq_line(&g, 287), Ok(0x0100_011f));
        assert!(spi_irq_line(&g, 31).is_err(), "PPIs are not lines");
        assert!(spi_irq_line(&g, 288).is_err());
        assert!(spi_irq_line(&g, 0).is_err());
    }
}
