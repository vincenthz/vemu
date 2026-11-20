//! KVM hooks for aarch64 hosts (docs/kvm-design.md, "aarch64 on KVM"): the
//! same machine as on HVF, with the kernel doing what the HVF backend
//! emulates.
//!
//! - **VM type**: the IPA size, `min(host limit, 40)` bits
//!   (`KVM_CAP_ARM_VM_IPA_SIZE`), see [`abi::vm_type`].
//! - **vGIC**: `KVM_CREATE_DEVICE` of a GICv3 at `GicRequest::{dist_base,
//!   redist_base}` (legacy single redistributor region: one 128 KiB frame per
//!   vCPU), else a GICv2 at `{dist_base, v2_cpu_base}` (at most 8 vCPUs).
//!   256 SPIs (INTIDs 32..288). Created right after the VM, before any vCPU
//!   (as kvmtool does); `finalize` sends `KVM_DEV_ARM_VGIC_CTRL_INIT` once
//!   every vCPU exists. The architected timer is in-kernel (PPIs 27 virtual,
//!   30 physical: what the device tree says).
//! - **vCPUs**: created in index order (common layer), so KVM's vcpu_idx
//!   equals the vcpu_id the vGICv2 targets by. `KVM_ARM_VCPU_INIT` with the
//!   VM's preferred target and feature PSCI_0_2 (in-kernel PSCI 1.x over
//!   HVC, also answering SMC) runs in `init_vcpu`, i.e. at `finalize` once
//!   every vCPU exists (api.rst: "all vcpus should be created before this
//!   ioctl is invoked") and before the vGIC `CTRL_INIT`, as QEMU and
//!   kvmtool order it; secondaries also get POWER_OFF, so `run()` blocks in
//!   the kernel until the guest's PSCI `CPU_ON` (or a kick). No PMU, SVE,
//!   pointer authentication or nested virtualisation.
//! - **MPIDR**: KVM's own assignment (16 vCPUs per Aff1, see
//!   [`abi::KVM_MPIDR_AFF0_CPUS`]), published as
//!   `ArchVmInfo::mpidr_aff0_cpus` so the device tree's `cpu` `reg` values
//!   (and so PSCI `CPU_ON` targets) match; every `KVM_ARM_VCPU_INIT` is
//!   followed by reading MPIDR_EL1 back and writing the expected value if a
//!   kernel ever differs.
//! - **Boot state**: `KVM_ARM_VCPU_INIT` again (a full architectural reset:
//!   PSTATE EL1h with DAIF masked, SCTLR_EL1 MMU/caches off, ...), then PC,
//!   X0..X3 and PSTATE via `KVM_SET_ONE_REG`, and `KVM_SET_MP_STATE`
//!   RUNNABLE for a secondary (powered on without CPU_ON, as the trait
//!   requires).
//! - **Exits**: MMIO with a valid syndrome is decoded by KVM (register,
//!   size, sign extension) and handled by the common layer; PSCI
//!   SYSTEM_OFF / SYSTEM_RESET arrive as `KVM_EXIT_SYSTEM_EVENT` (common
//!   layer). A data abort outside RAM *without* a valid syndrome (load/store
//!   pair, writeback, ...) is fatal: with `KVM_CAP_ARM_NISV_TO_USER`
//!   (enabled when available) it arrives as `KVM_EXIT_ARM_NISV` and is
//!   reported with its IPA here; otherwise `KVM_RUN` fails with ENOSYS
//!   (common layer hint). `run()` never returns `VcpuExit::Hvc` on KVM.
//!
//! The pure parts (UAPI mirrors, register ids, vGIC geometry, IPA choice,
//! `KVM_IRQ_LINE` encoding) live in `aarch64/abi.rs`, unit-tested on every
//! host and checked against the kernel headers by `scripts/kvm-abi/`.

mod abi;

use abi::*;

use super::abi::{KVM_CAP_ARM_VM_IPA_SIZE, KVM_EXIT_ARM_NISV, KVM_MP_STATE_RUNNABLE, KvmRunUnion};
use super::{ArchVcpu, ArchVm, Fd, Kvm, VcpuFd, VmFd};
use crate::{ArchVmInfo, BootState, Error, GicInfo, GicVersion, Reg, Result, VcpuExit, VmConfig};

/// VM-level state: the vGIC device and what was created.
pub(super) struct Arch {
    /// The vGIC device fd (kept for `finalize`; the device itself lives as
    /// long as the VM).
    gic: Fd,
    info: GicInfo,
    /// `KVM_ARM_PREFERRED_TARGET`.
    target: u32,
}

/// Per-vCPU state.
pub(super) struct ArchCpu {
    index: usize,
    /// The `KVM_ARM_VCPU_INIT` argument of the vCPU's first init
    /// ([`Arch::vcpu_init_arg`]); reused unchanged for resets (kernels
    /// before the POWER_OFF bit became "ephemeral" refuse a re-init with
    /// different features).
    init: KvmVcpuInit,
    /// MPIDR_EL1 affinity the device tree gives this vCPU.
    mpidr: u64,
}

fn arch_info(gic: GicInfo) -> ArchVmInfo {
    ArchVmInfo {
        gic,
        mpidr_aff0_cpus: KVM_MPIDR_AFF0_CPUS,
    }
}

/// `KVM_SET_DEVICE_ATTR` of a vGIC setting.
fn gic_attr(gic: &Fd, op: &'static str, group: u32, attr: u64, val: u64) -> Result<()> {
    gic.set_device_attr(op, group, attr, Some(&val))
}

/// Create the vGIC: v3 if the host emulates one, else v2.
fn create_gic(vm: &VmFd, cfg: &VmConfig) -> Result<(Fd, GicInfo)> {
    const OP: &str = "create_vm";
    let v3 = match vm.create_device(KVM_DEV_TYPE_ARM_VGIC_V3) {
        Ok(fd) => {
            let info = gic_v3_info(&cfg.gic, cfg.cpus).map_err(|m| Error::invalid(OP, m))?;
            // NR_IRQS is read as a u32 (little-endian low half, see abi.rs).
            gic_attr(
                &fd,
                "vGICv3 NR_IRQS",
                KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
                0,
                u64::from(NR_IRQS),
            )?;
            gic_attr(
                &fd,
                "vGICv3 distributor address",
                KVM_DEV_ARM_VGIC_GRP_ADDR,
                KVM_VGIC_V3_ADDR_TYPE_DIST,
                info.dist_base,
            )?;
            gic_attr(
                &fd,
                "vGICv3 redistributor address",
                KVM_DEV_ARM_VGIC_GRP_ADDR,
                KVM_VGIC_V3_ADDR_TYPE_REDIST,
                info.redist_base,
            )?;
            return Ok((fd, info));
        }
        Err(e) => e,
    };
    let fd = vm.create_device(KVM_DEV_TYPE_ARM_VGIC_V2).map_err(|v2| {
        Error::invalid(
            OP,
            format!("KVM cannot create a GICv3 ({v3}) nor a GICv2 ({v2})"),
        )
    })?;
    let info = gic_v2_info(&cfg.gic, cfg.cpus).map_err(|m| Error::invalid(OP, m))?;
    gic_attr(
        &fd,
        "vGICv2 NR_IRQS",
        KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
        0,
        u64::from(NR_IRQS),
    )?;
    gic_attr(
        &fd,
        "vGICv2 distributor address",
        KVM_DEV_ARM_VGIC_GRP_ADDR,
        KVM_VGIC_V2_ADDR_TYPE_DIST,
        info.dist_base,
    )?;
    gic_attr(
        &fd,
        "vGICv2 CPU interface address",
        KVM_DEV_ARM_VGIC_GRP_ADDR,
        KVM_VGIC_V2_ADDR_TYPE_CPU,
        info.cpu_base,
    )?;
    Ok((fd, info))
}

/// `KVM_ARM_VCPU_INIT`: (re)initialise the vCPU to its reset state, then
/// make MPIDR_EL1's affinity `mpidr` (the published layout) if the kernel's
/// reset value differs (never on current kernels; a reset restores KVM's
/// value, so this follows every init).
fn vcpu_init(vcpu: &VcpuFd, init: &KvmVcpuInit, mpidr: u64) -> Result<()> {
    let mut arg = *init;
    // SAFETY: fixed-size struct kvm_vcpu_init (size encoded in the request,
    // checked by ioctl_ptr), read by the kernel.
    unsafe {
        vcpu.fd()
            .ioctl_ptr("KVM_ARM_VCPU_INIT", KVM_ARM_VCPU_INIT, &mut arg)
    }?;
    let got = vcpu.get_one_reg(REG_MPIDR_EL1)?;
    if got & MPIDR_AFFINITY_MASK != mpidr {
        let fixed = (got & !MPIDR_AFFINITY_MASK) | MPIDR_RES1 | mpidr;
        vcpu.set_one_reg(REG_MPIDR_EL1, fixed)?;
    }
    Ok(())
}

impl Arch {
    /// The `KVM_ARM_VCPU_INIT` argument of vCPU `index`.
    fn vcpu_init_arg(&self, index: usize) -> KvmVcpuInit {
        KvmVcpuInit {
            target: self.target,
            features: vcpu_features(index, true),
        }
    }
}

impl ArchVm for Arch {
    type Vcpu = ArchCpu;

    fn vm_type(kvm: &Kvm, cfg: &VmConfig) -> Result<u64> {
        vm_type(
            kvm.check_extension(KVM_CAP_ARM_VM_IPA_SIZE),
            gic_end(&cfg.gic, cfg.cpus),
        )
        .map_err(|m| Error::invalid("create_vm", m))
    }

    fn new(kvm: &Kvm, vm: &VmFd, cfg: &VmConfig) -> Result<Arch> {
        if kvm.check_extension(KVM_CAP_ARM_PSCI_0_2) <= 0 {
            return Err(Error::invalid(
                "create_vm",
                "KVM lacks KVM_CAP_ARM_PSCI_0_2 (in-kernel PSCI 0.2+, Linux 3.16+)",
            ));
        }
        let mut pref = KvmVcpuInit::default();
        // SAFETY: fixed-size struct kvm_vcpu_init, written by the kernel.
        unsafe {
            vm.fd().ioctl_ptr(
                "KVM_ARM_PREFERRED_TARGET",
                KVM_ARM_PREFERRED_TARGET,
                &mut pref,
            )
        }?;
        let (gic, info) = create_gic(vm, cfg)?;
        // Better diagnostics only (the guest still cannot continue): report
        // syndrome-less MMIO aborts as KVM_EXIT_ARM_NISV with the IPA.
        if kvm.check_extension(KVM_CAP_ARM_NISV_TO_USER) > 0 {
            let _ = vm.enable_cap(KVM_CAP_ARM_NISV_TO_USER, [0; 4]);
        }
        Ok(Arch {
            gic,
            info,
            target: pref.target,
        })
    }

    fn arch_info(&self) -> ArchVmInfo {
        arch_info(self.info)
    }

    fn irq_line(&self, irq: u32) -> Result<u32> {
        spi_irq_line(&self.info, irq).map_err(|m| Error::invalid("set_irq_line", m))
    }

    fn create_vcpu(&self, _kvm: &Kvm, _vm: &VmFd, _vcpu: &VcpuFd, index: usize) -> Result<ArchCpu> {
        // Nothing in the kernel yet: KVM_ARM_VCPU_INIT waits for every vCPU
        // to exist (init_vcpu).
        Ok(ArchCpu {
            index,
            init: self.vcpu_init_arg(index),
            // The device tree describes this vCPU as arch_info().mpidr(index).
            mpidr: arch_info(self.info).mpidr(index),
        })
    }

    fn init_vcpu(&self, vcpu: &VcpuFd, index: usize) -> Result<()> {
        vcpu_init(
            vcpu,
            &self.vcpu_init_arg(index),
            arch_info(self.info).mpidr(index),
        )
    }

    fn finalize(&self, _vm: &VmFd) -> Result<()> {
        let ctrl = (KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_CTRL_INIT);
        if self.gic.has_device_attr(ctrl.0, ctrl.1) {
            self.gic
                .set_device_attr("vGIC CTRL_INIT", ctrl.0, ctrl.1, None)
        } else if self.info.version == GicVersion::V2 {
            // Kernels before 4.6 initialise a GICv2 at the first KVM_RUN.
            Ok(())
        } else {
            Err(Error::invalid(
                "finalize",
                "the vGICv3 has no KVM_DEV_ARM_VGIC_CTRL_INIT",
            ))
        }
    }
}

impl ArchCpu {
    /// " (PC=... PSTATE=...)" for errors; never fails.
    fn context(&self, vcpu: &VcpuFd) -> String {
        let reg = |id| {
            vcpu.get_one_reg(id)
                .map_or_else(|_| "?".to_string(), |v| format!("{v:#x}"))
        };
        format!(" (PC={} PSTATE={})", reg(REG_PC), reg(REG_PSTATE))
    }
}

impl ArchVcpu for ArchCpu {
    fn set_boot_state(&mut self, vcpu: &VcpuFd, s: &BootState) -> Result<()> {
        // A re-init is KVM's vCPU reset (api.rst, KVM_ARM_VCPU_INIT): every
        // register back to its reset value, including SCTLR_EL1 (MMU and
        // caches off) and PSTATE 0x3c5.
        vcpu_init(vcpu, &self.init, self.mpidr)?;
        vcpu.set_one_reg(REG_PSTATE, PSTATE_EL1H_DAIF)?;
        vcpu.set_one_reg(REG_PC, s.pc)?;
        vcpu.set_one_reg(x_reg(0), s.x0)?;
        for n in 1..=3 {
            vcpu.set_one_reg(x_reg(n), 0)?;
        }
        if self.index > 0 {
            // Its init has POWER_OFF (STOPPED); power it on without CPU_ON.
            vcpu.set_mp_state(KVM_MP_STATE_RUNNABLE)?;
        }
        Ok(())
    }

    fn get_reg(&self, vcpu: &VcpuFd, reg: Reg) -> Result<u64> {
        let id = reg_id(reg).map_err(|m| Error::invalid("get_reg", m))?;
        vcpu.get_one_reg(id)
    }

    fn set_reg(&mut self, vcpu: &VcpuFd, reg: Reg, val: u64) -> Result<()> {
        let id = reg_id(reg).map_err(|m| Error::invalid("set_reg", m))?;
        vcpu.set_one_reg(id, val)
    }

    fn handle_exit(
        &mut self,
        vcpu: &VcpuFd,
        reason: u32,
        data: &KvmRunUnion,
    ) -> Result<Option<VcpuExit>> {
        let msg = match reason {
            KVM_EXIT_ARM_NISV => {
                // SAFETY: plain-data union member, the one KVM fills for
                // this exit reason.
                let n = unsafe { data.arm_nisv };
                format!(
                    "data abort at IPA {:#x}, outside RAM, without a valid syndrome (ESR ISS \
                     {:#x}): the guest used an MMIO access KVM cannot decode (load/store \
                     pair, writeback, SIMD, ...)",
                    n.fault_ipa, n.esr_iss
                )
            }
            r => format!(
                "unhandled KVM exit {} ({r})",
                super::abi::exit_reason_name(r)
            ),
        };
        Err(Error::invalid(
            "run",
            format!("vCPU {}: {msg}{}", self.index, self.context(vcpu)),
        ))
    }

    fn fault_context(&self, vcpu: &VcpuFd) -> String {
        self.context(vcpu)
    }
}

/// Real-KVM test of the aarch64 hooks. Runs only on an aarch64 Linux host
/// with a usable `/dev/kvm` (skips otherwise, e.g. in vemu's own Linux
/// guest): vGIC creation and `KVM_IRQ_LINE`, boot state, MMIO write / read
/// with KVM's sign extension, in-kernel PSCI `CPU_ON` of a powered-off
/// secondary (context id, MPIDR as published, EL1), `SYSTEM_OFF` as
/// `SystemEvent(Shutdown)`, powering a secondary on with `set_boot_state`,
/// and kicking a vCPU out of WFI / the post-SYSTEM_OFF sleep.
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;
    use std::time::Instant;

    use crate::{GicRequest, SystemEvent, Vcpu, VcpuExit, Vm, VmConfig};

    const RAM: u64 = 0x4000_0000;
    const DEV: u64 = 0x0900_0000;
    const SECONDARY: u64 = RAM + 0x100;

    /// Guest code (assembled with clang for arm64; `.p2align 8` before
    /// the secondary entry).
    const BOOT: [u32; 16] = [
        0xd2a1_2001, // mov   x1, #0x9000000
        0x5280_0222, // mov   w2, #0x11
        0xb900_0022, // str   w2, [x1]            MmioWrite 0x0900_0000/4 = 0x11
        0x3980_2023, // ldrsb x3, [x1, #8]        MmioRead 0x0900_0008/1
        0xf900_0823, // str   x3, [x1, #16]       MmioWrite 0x0900_0010/8 = sext
        0xd280_0060, // mov   x0, #0x3
        0xf2b8_8000, // movk  x0, #0xc400, lsl #16  PSCI CPU_ON (64-bit)
        0xd280_0021, // mov   x1, #1              target MPIDR 1
        0xd280_2002, // mov   x2, #0x100
        0xf2a8_0002, // movk  x2, #0x4000, lsl #16  entry SECONDARY
        0xd280_0aa3, // mov   x3, #0x55           context id
        0xd400_0002, // hvc   #0
        0xd2a1_2001, // mov   x1, #0x9000000
        0xf900_0c20, // str   x0, [x1, #0x18]     MmioWrite 0x0900_0018 = result
        0xd503_207f, // 1: wfi
        0x17ff_ffff, // b     1b
    ];
    const SECOND: [u32; 10] = [
        0xd2a1_2001, // mov   x1, #0x9000000
        0xf900_1020, // str   x0, [x1, #0x20]     context id
        0xd538_00a2, // mrs   x2, mpidr_el1
        0xf900_1422, // str   x2, [x1, #0x28]
        0xd538_4242, // mrs   x2, currentel
        0xf900_1822, // str   x2, [x1, #0x30]
        0xd280_0100, // mov   x0, #0x8
        0xf2b0_8000, // movk  x0, #0x8400, lsl #16  PSCI SYSTEM_OFF
        0xd400_0002, // hvc   #0
        0x1400_0000, // 2: b  2b
    ];

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// Run until an exit other than an MMIO read (answered with `read`),
    /// returning the writes seen on the way.
    /// `on_write` runs while the vCPU is stopped at each write.
    fn run_until(
        v: &mut dyn Vcpu,
        read: u64,
        mut on_write: impl FnMut(u64),
    ) -> (Vec<(u64, usize, u64)>, VcpuExit) {
        let mut writes = Vec::new();
        loop {
            match v.run().expect("run") {
                VcpuExit::MmioWrite { addr, len, data } => {
                    on_write(addr);
                    writes.push((addr, len, data));
                }
                VcpuExit::MmioRead { addr, len } => {
                    assert_eq!((addr, len), (DEV + 8, 1));
                    v.complete_mmio_read(read).expect("complete_mmio_read");
                }
                e => return (writes, e),
            }
        }
    }

    #[test]
    fn real_kvm_aarch64() {
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_err()
        {
            eprintln!("skipping: no usable /dev/kvm");
            return;
        }
        let vm: Arc<dyn Vm> = crate::create_vm(&VmConfig {
            cpus: 2,
            gic: GicRequest::default(),
        })
        .expect("create_vm");
        let info = vm.arch_info();
        eprintln!("vGIC: {:?}", info.gic);
        assert_eq!(info.gic.dist_base, 0x0800_0000);
        assert_eq!((info.gic.spi_base, info.gic.spi_count), (32, 256));
        assert_eq!(info.mpidr(1), 1);
        let mem = vemu_core::GuestMemory::new(RAM, 0x1_0000).expect("memory");
        mem.write(RAM, &code(&BOOT)).unwrap();
        mem.write(SECONDARY, &code(&SECOND)).unwrap();
        vm.map_memory(&mem).expect("map_memory");

        let ready = Arc::new(Barrier::new(3));
        // A vCPU that is missing makes finalize fail.
        {
            let short: Arc<dyn Vm> = crate::create_vm(&VmConfig {
                cpus: 2,
                gic: GicRequest::default(),
            })
            .expect("create_vm");
            let _v0 = short.create_vcpu(0).expect("create_vcpu");
            assert!(short.finalize().is_err(), "finalize without vCPU 1");
        }
        let (tx, rx) = mpsc::channel();
        let reported = Arc::new(AtomicBool::new(false));
        // vCPUs are created in index order: thread 1 starts once vCPU 0
        // exists (out of order is refused, see the common layer).
        assert!(vm.create_vcpu(1).is_err(), "vCPU 1 before vCPU 0");
        let (created_tx, created_rx) = mpsc::channel();
        let threads: Vec<_> = (0..2)
            .map(|i| {
                let (vm, ready, tx) = (vm.clone(), ready.clone(), tx.clone());
                let reported = reported.clone();
                let created_tx = created_tx.clone();
                let t = std::thread::spawn(move || {
                    let mut v = vm.create_vcpu(i).expect("create_vcpu");
                    created_tx.send(()).unwrap();
                    ready.wait(); // finalized
                    if i == 0 {
                        v.set_boot_state(&crate::BootState { pc: RAM, x0: 0 })
                            .expect("set_boot_state");
                        assert_eq!(v.get_reg(crate::Reg::Pc).unwrap(), RAM);
                        assert_eq!(v.get_reg(crate::Reg::Cpsr).unwrap(), 0x3c5);
                        v.set_reg(crate::Reg::X(9), 0x1234).unwrap();
                        assert_eq!(v.get_reg(crate::Reg::X(9)).unwrap(), 0x1234);
                        let r = run_until(&mut *v, 0x80, |addr| {
                            if addr == DEV + 0x18 {
                                reported.store(true, SeqCst);
                            }
                        });
                        tx.send((0, r)).unwrap();
                        // Kicked out of WFI: the PC is in the wfi loop.
                        let pc = v.get_reg(crate::Reg::Pc).unwrap();
                        assert!((RAM + 0x38..=RAM + 0x3c).contains(&pc), "PC {pc:#x}");
                    } else {
                        // Powered off until CPU_ON. Its SYSTEM_OFF stops
                        // vCPU 0 too: hold it until vCPU 0 has reported
                        // the CPU_ON result.
                        let r = run_until(&mut *v, 0, |_| {
                            let t = Instant::now();
                            while !reported.load(SeqCst) && t.elapsed() < Duration::from_secs(10) {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                        });
                        tx.send((1, r)).unwrap();
                        // Powered on without CPU_ON (after SYSTEM_OFF stopped it).
                        v.set_boot_state(&crate::BootState {
                            pc: SECONDARY,
                            x0: 0x66,
                        })
                        .expect("set_boot_state on a secondary");
                        let r = run_until(&mut *v, 0, |_| {});
                        tx.send((2, r)).unwrap();
                    }
                });
                created_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("vCPU created");
                t
            })
            .collect();
        drop(tx);
        // Every vCPU exists but none is initialised yet: that is finalize.
        vm.finalize().expect("finalize");
        assert!(vm.finalize().is_err(), "finalize twice");
        vm.set_irq_line(48, true).expect("SPI 48 up");
        vm.set_irq_line(48, false).expect("SPI 48 down");
        assert!(vm.set_irq_line(31, true).is_err(), "a PPI is not a line");
        ready.wait();

        let mut got = std::collections::HashMap::new();
        let mut kicked = false;
        while got.len() < 3 {
            match rx.recv_timeout(Duration::from_secs(10)) {
                Ok((k, r)) => {
                    got.insert(k, r);
                    if got.contains_key(&2) && !kicked {
                        vm.kick(0);
                        kicked = true;
                    }
                }
                Err(e) => {
                    vm.kick(0);
                    vm.kick(1);
                    panic!("guest stuck ({e}); seen so far: {got:?}");
                }
            }
        }
        for t in threads {
            t.join().expect("vCPU thread");
        }
        let mpidr = |v: u64| v & 0xff_00ff_ffff;
        let (w, e) = &got[&1];
        assert_eq!(*e, VcpuExit::SystemEvent(SystemEvent::Shutdown));
        assert_eq!(w[0], (DEV + 0x20, 8, 0x55), "CPU_ON context id");
        assert_eq!((w[1].0, mpidr(w[1].2)), (DEV + 0x28, 1), "MPIDR of vCPU 1");
        assert_ne!(w[1].2 & 1 << 31, 0, "MPIDR RES1");
        assert_eq!(w[2], (DEV + 0x30, 8, 1 << 2), "EL1");
        let (w, e) = &got[&2];
        assert_eq!(*e, VcpuExit::SystemEvent(SystemEvent::Shutdown));
        assert_eq!(w[0], (DEV + 0x20, 8, 0x66), "X0 from set_boot_state");
        let (w, e) = &got[&0];
        assert_eq!(*e, VcpuExit::Kicked);
        assert_eq!(
            w[..],
            [
                (DEV, 4, 0x11),
                (DEV + 0x10, 8, 0xffff_ffff_ffff_ff80), // ldrsb sign-extended by KVM
                (DEV + 0x18, 8, 0),                     // CPU_ON: PSCI SUCCESS
            ]
        );
    }
}
