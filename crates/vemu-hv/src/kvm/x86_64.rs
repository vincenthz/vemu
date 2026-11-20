//! KVM hooks for x86_64 hosts (x86_64 guests), see docs/kvm-design.md.
//!
//! VM ([`Arch::new`], right after `KVM_CREATE_VM`, before memory and
//! vCPUs): `KVM_SET_IDENTITY_MAP_ADDR` / `KVM_SET_TSS_ADDR` (KVM's real-mode
//! helpers on hosts without unrestricted guest, at
//! [`KVM_IDENTITY_MAP_ADDR`] / [`KVM_TSS_ADDR`], which the VMM keeps out of
//! RAM), `KVM_CREATE_IRQCHIP` (in-kernel 8259 PICs, IOAPIC and per-vCPU
//! LAPICs), `KVM_SET_GSI_ROUTING` in QEMU's PC layout (PIT on IOAPIC pin 2,
//! matching an MADT override IRQ 0 -> GSI 2; see
//! [`gsi_routes`](crate::x86_64::kvm::gsi_routes)), `KVM_CREATE_PIT2` with
//! the dummy speaker port, and one `KVM_GET_SUPPORTED_CPUID`.
//!
//! vCPU ([`ArchVm::create_vcpu`]): `KVM_SET_CPUID2` (the supported table
//! with per-vCPU topology fixups), boot MSRs, FPU (FCW / MXCSR reset
//! values), LAPIC LINT0 = ExtINT and LINT1 = NMI. KVM itself starts vCPU 0
//! runnable and the others in the wait-for-SIPI state (in-kernel LAPIC):
//! the guest starts them with INIT/SIPI, so `run()` of a secondary blocks
//! in the kernel until then (a kick still gets it out).
//!
//! Boot ([`ArchVcpu::set_boot_state`]): the Linux 64-bit boot protocol state
//! of [`BootState`] (long mode, paging, flat BOOT_GDT segments), then
//! `KVM_MP_STATE_RUNNABLE`.
//!
//! Exits: the common layer decodes port I/O, MMIO, SHUTDOWN (triple fault
//! -> `SystemEvent(Reset)`) and SYSTEM_EVENT; here only `KVM_EXIT_HLT` /
//! `KVM_EXIT_IRQ_WINDOW_OPEN` (not expected with the in-kernel irqchip:
//! re-enter) and errors for the rest.
//!
//! The struct mirrors and the pure logic are in `crate::x86_64::kvm`
//! (unit-tested on every host); the ioctl numbers below are pinned to the
//! kernel headers by `scripts/kvm-abi/probe-x86_64.h`.

use super::abi::{
    KVM_CAP_IRQCHIP, KVM_CREATE_IRQCHIP, KVM_EXIT_HLT, KVM_EXIT_IRQ_WINDOW_OPEN,
    KVM_MP_STATE_RUNNABLE, KVM_SET_IDENTITY_MAP_ADDR, KVM_SET_TSS_ADDR, KvmRunUnion,
    exit_reason_name, io, ior, iow, iowr,
};
use super::{ArchVcpu, ArchVm, Kvm, VcpuFd, VmFd};
use crate::x86_64::kvm::*;
use crate::{ArchVmInfo, BootState, Error, Reg, Result, VcpuExit, VmConfig};

// --- ioctls (asm/kvm.h structs; numbers checked in probe-x86_64.h) ------------

/// System ioctl: the CPUID features KVM can expose (flexible array).
pub(crate) const KVM_GET_SUPPORTED_CPUID: u32 = iowr::<KvmCpuid2<0>>(0x05);
pub(crate) const KVM_SET_GSI_ROUTING: u32 = iow::<KvmIrqRouting<0>>(0x6a);
pub(crate) const KVM_CREATE_PIT2: u32 = iow::<KvmPitConfig>(0x77);
pub(crate) const KVM_GET_REGS: u32 = ior::<KvmRegs>(0x81);
pub(crate) const KVM_SET_REGS: u32 = iow::<KvmRegs>(0x82);
pub(crate) const KVM_GET_SREGS: u32 = ior::<KvmSregs>(0x83);
pub(crate) const KVM_SET_SREGS: u32 = iow::<KvmSregs>(0x84);
pub(crate) const KVM_GET_MSRS: u32 = iowr::<KvmMsrs<0>>(0x88);
pub(crate) const KVM_SET_MSRS: u32 = iow::<KvmMsrs<0>>(0x89);
pub(crate) const KVM_GET_FPU: u32 = ior::<KvmFpu>(0x8c);
pub(crate) const KVM_SET_FPU: u32 = iow::<KvmFpu>(0x8d);
pub(crate) const KVM_GET_LAPIC: u32 = ior::<KvmLapicState>(0x8e);
pub(crate) const KVM_SET_LAPIC: u32 = iow::<KvmLapicState>(0x8f);
pub(crate) const KVM_SET_CPUID2: u32 = iow::<KvmCpuid2<0>>(0x90);
/// `KVM_CREATE_PIT` (the old one): only to pin `io()` in the probe.
const KVM_CREATE_PIT: u32 = io(0x64);

// Capabilities.
pub(crate) const KVM_CAP_SET_TSS_ADDR: u32 = 4;
pub(crate) const KVM_CAP_EXT_CPUID: u32 = 7;
pub(crate) const KVM_CAP_MP_STATE: u32 = 14;
pub(crate) const KVM_CAP_IRQ_ROUTING: u32 = 25;
pub(crate) const KVM_CAP_PIT2: u32 = 33;
pub(crate) const KVM_CAP_SET_IDENTITY_MAP_ADDR: u32 = 37;
pub(crate) const KVM_CAP_TSC_DEADLINE_TIMER: u32 = 72;

const _: () = {
    assert!(KVM_GET_SUPPORTED_CPUID == 0xc008_ae05);
    assert!(KVM_SET_GSI_ROUTING == 0x4008_ae6a);
    assert!(KVM_CREATE_PIT2 == 0x4040_ae77);
    assert!(KVM_CREATE_PIT == 0xae64);
    assert!(KVM_GET_REGS == 0x8090_ae81);
    assert!(KVM_SET_REGS == 0x4090_ae82);
    assert!(KVM_GET_SREGS == 0x8138_ae83);
    assert!(KVM_SET_SREGS == 0x4138_ae84);
    assert!(KVM_GET_MSRS == 0xc008_ae88);
    assert!(KVM_SET_MSRS == 0x4008_ae89);
    assert!(KVM_GET_FPU == 0x81a0_ae8c);
    assert!(KVM_SET_FPU == 0x41a0_ae8d);
    assert!(KVM_GET_LAPIC == 0x8400_ae8e);
    assert!(KVM_SET_LAPIC == 0x4400_ae8f);
    assert!(KVM_SET_CPUID2 == 0x4008_ae90);
};

/// Routes for `KVM_SET_GSI_ROUTING` (gsi_routes() has 38).
const MAX_ROUTES: usize = 64;

// --- VM ------------------------------------------------------------------------

pub(super) struct Arch {
    /// KVM_GET_SUPPORTED_CPUID, fixed up per vCPU.
    cpuid: Vec<KvmCpuidEntry2>,
    cpus: u32,
    tsc_deadline: bool,
}

/// Per-vCPU state: just its index (KVM holds the rest).
pub(super) struct ArchCpu {
    index: usize,
}

fn supported_cpuid(kvm: &Kvm) -> Result<Vec<KvmCpuidEntry2>> {
    const OP: &str = "KVM_GET_SUPPORTED_CPUID";
    let mut buf = Box::new(KvmCpuid2::<KVM_MAX_CPUID_ENTRIES> {
        nent: KVM_MAX_CPUID_ENTRIES as u32,
        padding: 0,
        entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
    });
    // SAFETY: the kernel writes at most `nent` (= the array length)
    // entries after the 8-byte header, all plain integers, and updates
    // `nent`; the buffer is exactly that big.
    unsafe { kvm.fd().ioctl_ptr(OP, KVM_GET_SUPPORTED_CPUID, &mut *buf) }.map_err(|e| {
        if e.code() == Some(libc::E2BIG) {
            Error::invalid(
                OP,
                format!("the host has more than {KVM_MAX_CPUID_ENTRIES} CPUID entries"),
            )
        } else {
            e
        }
    })?;
    let n = buf.nent as usize;
    if n == 0 || n > KVM_MAX_CPUID_ENTRIES {
        return Err(Error::invalid(OP, format!("KVM returned {n} entries")));
    }
    Ok(buf.entries[..n].to_vec())
}

fn set_gsi_routing(vm: &VmFd, routes: &[KvmIrqRoutingEntry]) -> Result<()> {
    let mut buf = Box::new(KvmIrqRouting::<MAX_ROUTES> {
        nr: routes.len() as u32,
        flags: 0,
        entries: [KvmIrqRoutingEntry::default(); MAX_ROUTES],
    });
    if routes.len() > MAX_ROUTES {
        return Err(Error::invalid("KVM_SET_GSI_ROUTING", "too many routes"));
    }
    buf.entries[..routes.len()].copy_from_slice(routes);
    // SAFETY: the kernel reads the header and `nr` entries, all inside
    // `buf` (nr <= MAX_ROUTES checked above).
    unsafe {
        vm.fd()
            .ioctl_ptr("KVM_SET_GSI_ROUTING", KVM_SET_GSI_ROUTING, &mut *buf)
    }
    .map(drop)
}

impl ArchVm for Arch {
    type Vcpu = ArchCpu;

    fn vm_type(_kvm: &Kvm, _cfg: &VmConfig) -> Result<u64> {
        Ok(0) // KVM_X86_DEFAULT_VM
    }

    fn new(kvm: &Kvm, vm: &VmFd, cfg: &VmConfig) -> Result<Arch> {
        for (cap, name) in [
            (KVM_CAP_IRQCHIP, "KVM_CAP_IRQCHIP"),
            (KVM_CAP_IRQ_ROUTING, "KVM_CAP_IRQ_ROUTING"),
            (KVM_CAP_PIT2, "KVM_CAP_PIT2"),
            (KVM_CAP_SET_TSS_ADDR, "KVM_CAP_SET_TSS_ADDR"),
            (
                KVM_CAP_SET_IDENTITY_MAP_ADDR,
                "KVM_CAP_SET_IDENTITY_MAP_ADDR",
            ),
            (KVM_CAP_EXT_CPUID, "KVM_CAP_EXT_CPUID"),
            (KVM_CAP_MP_STATE, "KVM_CAP_MP_STATE"),
        ] {
            if kvm.check_extension(cap) <= 0 {
                return Err(Error::invalid("create_vm", format!("KVM lacks {name}")));
            }
        }
        let cpus = u32::try_from(cfg.cpus).unwrap_or(u32::MAX);
        let cpuid = supported_cpuid(kvm)?;
        let tsc_deadline = kvm.check_extension(KVM_CAP_TSC_DEADLINE_TIMER) > 0;
        // Fail here, not on a vCPU thread, if the table cannot be built.
        cpuid_for_vcpu(&cpuid, 0, cpus, tsc_deadline)
            .map_err(|m| Error::invalid("create_vm", m))?;

        // Both must precede the first vCPU (api.rst).
        let mut map = KVM_IDENTITY_MAP_ADDR;
        // SAFETY: KVM_SET_IDENTITY_MAP_ADDR reads one u64.
        unsafe {
            vm.fd().ioctl_ptr(
                "KVM_SET_IDENTITY_MAP_ADDR",
                KVM_SET_IDENTITY_MAP_ADDR,
                &mut map,
            )
        }?;
        vm.fd()
            .ioctl_val("KVM_SET_TSS_ADDR", KVM_SET_TSS_ADDR, KVM_TSS_ADDR)?;
        vm.fd()
            .ioctl_val("KVM_CREATE_IRQCHIP", KVM_CREATE_IRQCHIP, 0)?;
        // After CREATE_IRQCHIP, which installs the default routing.
        set_gsi_routing(vm, &gsi_routes())?;
        let mut pit = KvmPitConfig {
            flags: KVM_PIT_SPEAKER_DUMMY,
            pad: [0; 15],
        };
        // SAFETY: fixed-size kvm_pit_config, read by the kernel.
        unsafe {
            vm.fd()
                .ioctl_ptr("KVM_CREATE_PIT2", KVM_CREATE_PIT2, &mut pit)
        }?;
        Ok(Arch {
            cpuid,
            cpus,
            tsc_deadline,
        })
    }

    fn arch_info(&self) -> ArchVmInfo {
        ArchVmInfo::default()
    }

    fn irq_line(&self, irq: u32) -> Result<u32> {
        gsi_to_kvm(irq).map_err(|m| Error::invalid("set_irq_line", m))
    }

    fn create_vcpu(&self, _kvm: &Kvm, _vm: &VmFd, vcpu: &VcpuFd, index: usize) -> Result<ArchCpu> {
        let entries = cpuid_for_vcpu(&self.cpuid, index as u32, self.cpus, self.tsc_deadline)
            .map_err(|m| Error::invalid("create_vcpu", m))?;
        set_cpuid(vcpu, &entries)?;
        set_msrs(vcpu, &BOOT_MSRS)?;
        let mut fpu = boot_fpu();
        // SAFETY: fixed-size kvm_fpu, read by the kernel.
        unsafe { vcpu.fd().ioctl_ptr("KVM_SET_FPU", KVM_SET_FPU, &mut fpu) }?;
        let mut lapic = KvmLapicState::default();
        // SAFETY: fixed-size kvm_lapic_state (plain bytes), written by the
        // kernel.
        unsafe {
            vcpu.fd()
                .ioctl_ptr("KVM_GET_LAPIC", KVM_GET_LAPIC, &mut lapic)
        }?;
        set_lint(&mut lapic);
        // SAFETY: as above, read by the kernel.
        unsafe {
            vcpu.fd()
                .ioctl_ptr("KVM_SET_LAPIC", KVM_SET_LAPIC, &mut lapic)
        }?;
        Ok(ArchCpu { index })
    }

    fn finalize(&self, _vm: &VmFd) -> Result<()> {
        Ok(())
    }
}

fn set_cpuid(vcpu: &VcpuFd, entries: &[KvmCpuidEntry2]) -> Result<()> {
    if entries.len() > KVM_MAX_CPUID_ENTRIES {
        return Err(Error::invalid("KVM_SET_CPUID2", "too many entries"));
    }
    let mut buf = Box::new(KvmCpuid2::<KVM_MAX_CPUID_ENTRIES> {
        nent: entries.len() as u32,
        padding: 0,
        entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
    });
    buf.entries[..entries.len()].copy_from_slice(entries);
    // SAFETY: the kernel reads the header and `nent` entries, all inside
    // `buf` (checked above).
    unsafe {
        vcpu.fd()
            .ioctl_ptr("KVM_SET_CPUID2", KVM_SET_CPUID2, &mut *buf)
    }
    .map(drop)
}

fn set_msrs<const N: usize>(vcpu: &VcpuFd, entries: &[KvmMsrEntry; N]) -> Result<()> {
    const OP: &str = "KVM_SET_MSRS";
    let mut buf = KvmMsrs::<N> {
        nmsrs: N as u32,
        pad: 0,
        entries: *entries,
    };
    // SAFETY: the kernel reads the header and `nmsrs` = N entries, exactly
    // `buf`.
    let n = unsafe { vcpu.fd().ioctl_ptr(OP, KVM_SET_MSRS, &mut buf) }? as usize;
    // KVM stops at the first MSR it refuses and returns how many it set.
    if n != N {
        return Err(Error::invalid(
            OP,
            format!(
                "KVM refused MSR {:#x}",
                entries.get(n).map_or(0, |e| e.index)
            ),
        ));
    }
    Ok(())
}

impl ArchCpu {
    fn regs(vcpu: &VcpuFd) -> Result<KvmRegs> {
        let mut r = KvmRegs::default();
        // SAFETY: fixed-size kvm_regs (integers), written by the kernel.
        unsafe { vcpu.fd().ioctl_ptr("KVM_GET_REGS", KVM_GET_REGS, &mut r) }?;
        Ok(r)
    }

    fn set_regs(vcpu: &VcpuFd, mut r: KvmRegs) -> Result<()> {
        // SAFETY: fixed-size kvm_regs, read by the kernel.
        unsafe { vcpu.fd().ioctl_ptr("KVM_SET_REGS", KVM_SET_REGS, &mut r) }.map(drop)
    }

    fn sregs(vcpu: &VcpuFd) -> Result<KvmSregs> {
        let mut s = KvmSregs::default();
        // SAFETY: fixed-size kvm_sregs (integers), written by the kernel.
        unsafe { vcpu.fd().ioctl_ptr("KVM_GET_SREGS", KVM_GET_SREGS, &mut s) }?;
        Ok(s)
    }

    fn set_sregs(vcpu: &VcpuFd, mut s: KvmSregs) -> Result<()> {
        // SAFETY: fixed-size kvm_sregs, read by the kernel.
        unsafe { vcpu.fd().ioctl_ptr("KVM_SET_SREGS", KVM_SET_SREGS, &mut s) }.map(drop)
    }
}

impl ArchVcpu for ArchCpu {
    fn set_boot_state(&mut self, vcpu: &VcpuFd, s: &BootState) -> Result<()> {
        // Read-modify-write: KVM_SET_SREGS also applies apic_base.
        let cur = Self::sregs(vcpu)?;
        Self::set_sregs(vcpu, boot_sregs(&cur, s))?;
        Self::set_regs(vcpu, boot_regs(s))?;
        // Power on: a secondary is still waiting for SIPI (and a halted
        // boot vCPU must run again).
        vcpu.set_mp_state(KVM_MP_STATE_RUNNABLE)
            .map_err(|e| Error::invalid("set_boot_state", format!("vCPU {}: {e}", self.index)))
    }

    fn get_reg(&self, vcpu: &VcpuFd, reg: Reg) -> Result<u64> {
        if is_sreg(reg) {
            let mut s = Self::sregs(vcpu)?;
            Ok(sreg_mut(&mut s, reg).map_or(0, |v| *v))
        } else {
            let mut r = Self::regs(vcpu)?;
            Ok(reg_mut(&mut r, reg).map_or(0, |v| *v))
        }
    }

    fn set_reg(&mut self, vcpu: &VcpuFd, reg: Reg, val: u64) -> Result<()> {
        if is_sreg(reg) {
            let mut s = Self::sregs(vcpu)?;
            if let Some(v) = sreg_mut(&mut s, reg) {
                *v = val;
            }
            Self::set_sregs(vcpu, s)
        } else {
            let mut r = Self::regs(vcpu)?;
            if let Some(v) = reg_mut(&mut r, reg) {
                *v = val;
            }
            Self::set_regs(vcpu, r)
        }
    }

    fn handle_exit(
        &mut self,
        vcpu: &VcpuFd,
        reason: u32,
        _data: &KvmRunUnion,
    ) -> Result<Option<VcpuExit>> {
        match reason {
            // Only without an in-kernel irqchip / when requested: nothing to
            // do but continue (HLT has completed).
            KVM_EXIT_HLT | KVM_EXIT_IRQ_WINDOW_OPEN => Ok(None),
            _ => Err(Error::invalid(
                "run",
                format!(
                    "vCPU {}: unhandled KVM exit {} ({reason}){}",
                    self.index,
                    exit_reason_name(reason),
                    self.fault_context(vcpu)
                ),
            )),
        }
    }

    fn fault_context(&self, vcpu: &VcpuFd) -> String {
        match (Self::regs(vcpu), Self::sregs(vcpu)) {
            (Ok(r), Ok(s)) => describe(&r, &s),
            (Err(e), _) | (_, Err(e)) => format!(" (registers unavailable: {e})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vcpu, Vm};
    use std::sync::Arc;
    use vemu_core::GuestMemory;

    /// Real-KVM test of the x86 backend (skipped without /dev/kvm): boots a
    /// tiny 64-bit guest through `set_boot_state` with the BOOT_GDT /
    /// identity-mapped page tables the VMM writes, checks long mode, the
    /// CPUID topology, MSRs, I/O and MMIO, the GSI routing, and that a
    /// secondary vCPU waits for SIPI until kicked.
    #[test]
    fn real_kvm_long_mode_boot() {
        if std::fs::metadata("/dev/kvm").is_err() {
            eprintln!("skipped: no /dev/kvm");
            return;
        }
        use crate::x86_64::BOOT_GDT;
        const GDT: u64 = 0x500;
        const PML4: u64 = 0x9000;
        const CODE: u64 = 0x10_0000;
        let vm = crate::create_vm(&VmConfig { cpus: 2 }).unwrap();
        let mem = GuestMemory::new(0, 4 << 20).unwrap();
        for (i, d) in BOOT_GDT.iter().enumerate() {
            mem.write(GDT + 8 * i as u64, &d.to_le_bytes()).unwrap();
        }
        // PML4[0] -> PDPT[0] -> PD[0] = 2 MiB page at 0, PD[1] at 2 MiB.
        mem.write(PML4, &(0xa000u64 | 3).to_le_bytes()).unwrap();
        mem.write(0xa000, &(0xb000u64 | 3).to_le_bytes()).unwrap();
        mem.write(0xb000, &(0x83u64).to_le_bytes()).unwrap();
        mem.write(0xb008, &(0x20_0000u64 | 0x83).to_le_bytes())
            .unwrap();
        // PDPT[3] -> PD at 0xc000, whose entry 128 maps 0xd000_0000 (MMIO).
        mem.write(0xa018, &(0xc000u64 | 3).to_le_bytes()).unwrap();
        mem.write(0xc400, &(0xd000_0000u64 | 0x83).to_le_bytes())
            .unwrap();
        // ... and entry 503 the LAPIC page at 0xfee0_0000 (uncached).
        mem.write(0xcfb8, &(0xfee0_0000u64 | 0x9b).to_le_bytes())
            .unwrap();
        // The AP's real-mode SIPI target (vector 8 = 0x8000).
        #[rustfmt::skip]
        mem.write(0x8000, &[
            0x66, 0xb8, 0x01, 0, 0, 0,    // mov eax, 1
            0x0f, 0xa2,                   // cpuid
            0x66, 0x89, 0xd8,             // mov eax, ebx
            0x66, 0xe7, 0x21,             // out 0x21, eax       (AP leaf 1 EBX)
            0xf4,                         // hlt
            0xeb, 0xfd,                   // jmp hlt
        ]).unwrap();
        // Triple fault: #UD with an empty IDT.
        mem.write(CODE + 0x100, &[0x0f, 0x0b]).unwrap(); // ud2
        #[rustfmt::skip]
        let code: &[u8] = &[
            0x48, 0x89, 0xf0,             // mov rax, rsi
            0xe7, 0x10,                   // out 0x10, eax       (low half of RSI)
            0x31, 0xc0,                   // xor eax, eax
            0x0f, 0xa2,                   // cpuid (leaf 0)
            0xb8, 0x01, 0, 0, 0,          // mov eax, 1
            0x0f, 0xa2,                   // cpuid
            0x89, 0xd8,                   // mov eax, ebx
            0xe7, 0x11,                   // out 0x11, eax       (leaf 1 EBX)
            0x89, 0xc8,                   // mov eax, ecx
            0xe7, 0x12,                   // out 0x12, eax       (leaf 1 ECX)
            0xb9, 0xa0, 0x01, 0, 0,       // mov ecx, 0x1a0
            0x0f, 0x32,                   // rdmsr (MISC_ENABLE)
            0xe7, 0x13,                   // out 0x13, eax
            0x48, 0xb8, 0, 0, 0, 0xd0, 0, 0, 0, 0, // mov rax, 0xd0000000
            0x8b, 0x18,                   // mov ebx, [rax]      (MMIO read)
            0x89, 0x58, 0x04,             // mov [rax+4], ebx    (MMIO write)
            0xe4, 0x61,                   // in al, 0x61         (PIT speaker port: in-kernel)
            0xe6, 0x14,                   // out 0x14, al
            // Start the AP: INIT, then SIPI with vector 8, through the
            // in-kernel LAPIC's ICR (no exits).
            0x48, 0xb8, 0x00, 0x03, 0xe0, 0xfe, 0, 0, 0, 0, // mov rax, 0xfee00300
            0xc7, 0x40, 0x10, 0, 0, 0, 0x01, // mov dword [rax+0x10], 1 << 24 (ICR high: APIC id 1)
            0xc7, 0x00, 0x00, 0x45, 0, 0, // mov dword [rax], 0x4500 (INIT)
            0xc7, 0x00, 0x08, 0x46, 0, 0, // mov dword [rax], 0x4608 (SIPI, vector 8)
            0xf4,                         // hlt (interrupts off: in-kernel wait)
        ];
        mem.write(CODE, code).unwrap();
        vm.map_memory(&mem).unwrap();
        assert!(vm.set_irq_line(0, true).is_err());
        assert!(vm.set_irq_line(24, true).is_err());
        vm.set_irq_line(5, true).unwrap();
        vm.set_irq_line(5, false).unwrap();

        // vCPUs are created in index order (KVM's vcpu_idx == vcpu_id).
        assert!(vm.create_vcpu(1).is_err(), "vCPU 1 before vCPU 0");
        let mut v = vm.create_vcpu(0).unwrap();
        let vm2: Arc<dyn Vm> = vm.clone();
        let (created_tx, created_rx) = std::sync::mpsc::channel();
        let (ap_tx, ap_rx) = std::sync::mpsc::channel();
        let ap = std::thread::spawn(move || {
            let mut v = vm2.create_vcpu(1).unwrap();
            created_tx.send(()).unwrap();
            // Waits for INIT/SIPI in the kernel: only a kick gets it out.
            let first = v.run().unwrap();
            ap_tx.send(v.run().unwrap()).unwrap(); // after SIPI
            (first, v.run().unwrap()) // hlt: until kicked
        });
        created_rx.recv().unwrap();
        vm.finalize().unwrap();
        assert!(vm.finalize().is_err(), "finalize twice");
        std::thread::sleep(std::time::Duration::from_millis(50));
        vm.kick(1);
        v.set_boot_state(&BootState {
            rip: CODE,
            rsi: 0x1234_5678_7000,
            rsp: 0x8ff0,
            cr3: PML4,
            gdt_base: GDT,
        })
        .unwrap();
        assert_eq!(v.get_reg(Reg::Rip).unwrap(), CODE);
        assert_eq!(v.get_reg(Reg::Efer).unwrap() & 0x500, 0x500);
        let out = |v: &mut Box<dyn Vcpu>| match v.run().unwrap() {
            VcpuExit::IoOut { port, data, .. } => (port, data),
            e => panic!("{e:?}"),
        };
        assert_eq!(out(&mut v), (0x10, 0x5678_7000));
        let (_, ebx) = out(&mut v);
        assert_eq!(ebx >> 24, 0, "APIC id");
        assert_eq!((ebx >> 16) & 0xff, 2, "logical processors");
        let (_, ecx) = out(&mut v);
        assert_ne!(ecx & (1 << 31), 0, "hypervisor bit");
        assert_ne!(ecx & (1 << 21), 0, "x2APIC");
        let (_, misc) = out(&mut v);
        assert_ne!(misc & 1, 0, "fast strings");
        assert_eq!(u64::from(misc), MISC_ENABLE_BOOT, "BTS/PEBS_UNAVAIL kept");
        assert_eq!(
            v.run().unwrap(),
            VcpuExit::MmioRead {
                addr: 0xd000_0000,
                len: 4
            }
        );
        v.complete_mmio_read(0xabcd).unwrap();
        assert_eq!(
            v.run().unwrap(),
            VcpuExit::MmioWrite {
                addr: 0xd000_0004,
                len: 4,
                data: 0xabcd
            }
        );
        let (port, _) = out(&mut v);
        assert_eq!(port, 0x14, "port 0x61 handled in the kernel");
        // The BSP starts the AP, then HLTs with IF=0 (sleeps in the
        // kernel); the AP reports its APIC id, then HLTs too.
        let vm3 = vm.clone();
        let k = std::thread::spawn(move || {
            let r = ap_rx.recv_timeout(std::time::Duration::from_secs(10));
            std::thread::sleep(std::time::Duration::from_millis(50));
            vm3.kick(0);
            vm3.kick(1);
            r
        });
        assert_eq!(v.run().unwrap(), VcpuExit::Kicked);
        let ap_out = k.join().unwrap().expect("the AP never ran after SIPI");
        match ap_out {
            VcpuExit::IoOut {
                port: 0x21, data, ..
            } => {
                assert_eq!(data >> 24, 1, "AP initial APIC id")
            }
            e => panic!("AP: {e:?}"),
        }
        assert_eq!(ap.join().unwrap(), (VcpuExit::Kicked, VcpuExit::Kicked));
        assert!(v.get_reg(Reg::Rip).unwrap() > CODE);
        assert_eq!(v.get_reg(Reg::Cr3).unwrap(), PML4);
        v.set_reg(Reg::Rbx, 0x55).unwrap();
        assert_eq!(v.get_reg(Reg::Rbx).unwrap(), 0x55);
        // set_boot_state again (the halted BSP runs again): a triple fault
        // is a reset.
        v.set_boot_state(&BootState {
            rip: CODE + 0x100,
            rsi: 0,
            rsp: 0x8ff0,
            cr3: PML4,
            gdt_base: GDT,
        })
        .unwrap();
        assert_eq!(v.get_reg(Reg::Rbx).unwrap(), 0);
        assert_eq!(
            v.run().unwrap(),
            VcpuExit::SystemEvent(crate::SystemEvent::Reset)
        );
        // The guest memory outlives the VM's memory slot.
        drop(v);
        drop(vm);
        drop(mem);
    }
}
