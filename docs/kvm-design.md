# Multi-arch + Linux/KVM design (v2)

Adds Linux/KVM hosts on **aarch64 and x86_64** next to macOS/HVF (aarch64).
The guest architecture always equals the host architecture (no emulation).

| Host | Backend | Guest machine |
|---|---|---|
| macOS aarch64 | HVF + hv_gic (existing) | aarch64 `virt`-like: DTB, GICv3, PSCI/hvc, virtio-mmio |
| Linux aarch64 | KVM + in-kernel vGIC v3 (fallback v2) + in-kernel PSCI | same aarch64 machine (DTB gains a GICv2 variant) |
| Linux x86_64 | KVM + in-kernel irqchip (PIC/IOAPIC/LAPIC) + PIT2 | new x86_64 machine: 64-bit Linux boot protocol, e820, ACPI (HW-reduced), virtio-mmio described in the DSDT |

Test situation: the author's Mac (M2 Max) has no nested virtualization, so KVM
code cannot run locally. Quality gates are: cross-compilation + clippy for
`aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl`; struct layout /
ioctl number checks against the real Linux UAPI headers bundled with zig
(`/opt/homebrew/Cellar/zig/0.17.0/lib/zig/libc/include/any-linux-any/linux/kvm.h`
plus the per-arch `asm/kvm.h` under `aarch64-linux-any` / `x86-linux-any` or
equivalents); pure-logic unit tests of every machine-model structure run on the
Mac; aarch64-linux test binaries (everything not needing /dev/kvm) run inside a
vemu guest on the Mac; adversarial review against `Documentation/virt/kvm/api.rst`
and reference VMMs (kvmtool, firecracker, cloud-hypervisor, crosvm). The user
runs the real KVM e2e later on Linux hosts.

### UPDATE: a real x86_64 KVM host is available (supersedes "compile-only" for x86_64)

The user added a Linux x86_64 KVM host, so **x86_64 KVM work must be tested for
real**: run the kvm/x86_64 backend, the x86_64 machine and the x86_64 e2e there.
aarch64 KVM stays compile-only (there is no aarch64 Linux host).

- Host `10.10.0.31` (ssh as the current user, key auth works): Fedora 45, kernel
  7.3, Intel i7-8550U (4 cores / 8 threads, VT-x), 15 GiB RAM, `/dev/kvm` usable
  by the user, qemu-system-x86_64 installed (useful as a *reference only*, e.g.
  to compare what a working x86 guest sees; never as vemu's backend). Its Rust
  (1.59) is too old: **build on the Mac** with
  `cargo build --release --target x86_64-unknown-linux-musl ...` (static
  binaries; `.cargo/config.toml` already sets up linking) and copy them over.
  Test binaries: `cargo test --target x86_64-unknown-linux-musl --no-run
  --message-format=json` to locate them, then copy and run.
- Use `scripts/remote-kvm.sh` only: `sync NAME FILE...` copies into
  `~/vemu-remote/NAME/` on the host; `run NAME SECS 'CMD'` runs CMD there under a
  host-wide flock (one VM at a time across all agents) and `timeout SECS` (≤ 300);
  `shell 'CMD'` for read-only diagnostics (dmesg is fine if readable, `cat
  /proc/cpuinfo`, ...). Use a distinct NAME per agent.
- It is the user's real workstation. HOST SAFETY applies there too: ≤ 4 vCPUs,
  ≤ 1 GiB guest RAM, always under the lock + timeout, never leave processes
  running, write only under `~/vemu-remote/`, no sudo, no package installs, no
  system configuration changes. Bind host forwards to 127.0.0.1 only (never
  0.0.0.0) on that machine.
- x86_64 fixtures: `testdata/x86_64/` (made by `VEMU_ARCH=x86_64
  scripts/mk-testdata.sh` on the Mac), synced to the host.
- Goal for integration: `scripts/e2e.sh` runs on that host against a prebuilt
  binary (add e.g. `--vemu PATH` / `--no-build` so it doesn't need cargo there,
  and makes no host-wide changes), with all 23 scenarios passing for x86_64 guests.
- ABI gotcha seen there: musl's variadic `ioctl` must be given an explicit third
  argument (pass 0 for argument-less ioctls such as KVM_GET_API_VERSION),
  otherwise the result is garbage.

## vemu-hv: arch-neutral interface

```rust
pub fn create_vm(cfg: &VmConfig) -> Result<Arc<dyn Vm>>;   // HVF on macOS/aarch64, KVM on Linux; error elsewhere

pub struct VmConfig {
    pub cpus: usize,
    #[cfg(target_arch = "aarch64")] pub gic: GicRequest,   // { dist_base, redist_base, v2_cpu_base } — VMM layout; backend picks v3, else v2 (KVM only)
}

pub trait Vm: Send + Sync {
    /// aarch64: the GIC actually created (version, bases, sizes, SPI range). x86_64: unit/empty info.
    fn arch_info(&self) -> ArchVmInfo;
    fn map_memory(&self, mem: &Arc<GuestMemory>) -> Result<()>;   // may be called for several regions (x86: below/above 4 GiB); the VM keeps `mem` alive
    /// Level-triggered interrupt line. aarch64: absolute GIC INTID of an SPI (>= 32).
    /// x86_64: IOAPIC GSI. Callable from any thread.
    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()>;
    /// On the calling thread, which then owns it (HVF requirement; KVM: the thread that runs it).
    /// In index order: index i only after i-1 returned (KVM refuses otherwise, never waits).
    fn create_vcpu(&self, index: usize) -> Result<Box<dyn Vcpu>>;
    /// After every vCPU exists, before the first run, once (KVM: arm64 VCPU_INIT of
    /// every vCPU, then vGIC CTRL_INIT; HVF no-op).
    fn finalize(&self) -> Result<()>;
    /// Sticky kick (unchanged semantics). KVM: immediate_exit + signal to the vCPU thread.
    fn kick(&self, index: usize);
}

pub trait Vcpu {
    fn index(&self) -> usize;
    /// Boot CPU only. aarch64: PC + X0 (DTB); CPSR EL1h masked. x86_64: see x86_64::BootState.
    fn set_boot_state(&mut self, s: &BootState) -> Result<()>;
    /// Secondary CPUs: aarch64 start powered off and are started by the guest via PSCI
    /// CPU_ON (handled INSIDE the backend: KVM in-kernel PSCI; HVF backend emulates it and
    /// run() of a powered-off vCPU blocks until CPU_ON or kick). x86_64: in-kernel LAPIC
    /// INIT/SIPI (KVM). So the VMM starts every vCPU thread and just calls run() in a loop.
    fn run(&mut self) -> Result<VcpuExit>;
    fn complete_mmio_read(&mut self, value: u64) -> Result<()>;
    /// x86_64 port I/O read completion (no-op/error on aarch64).
    fn complete_io_in(&mut self, value: u32) -> Result<()>;
    // arch-specific debugging/tests:
    fn get_reg(&self, reg: Reg) -> Result<u64>;            // Reg is per-arch (aarch64: X/Sp/Pc/Cpsr; x86_64: Rax..R15/Rip/Rflags/...)
    fn set_reg(&mut self, reg: Reg, val: u64) -> Result<()>;
}

pub enum VcpuExit {
    MmioRead { addr: u64, len: usize },
    MmioWrite { addr: u64, len: usize, data: u64 },
    IoIn { port: u16, len: usize },                // x86_64 only
    IoOut { port: u16, len: usize, data: u32 },    // x86_64 only
    /// Guest asked for power off / reset (aarch64: PSCI SYSTEM_OFF/RESET — HVF backend
    /// or KVM_SYSTEM_EVENT; x86_64: triple fault = Reset). x86 ACPI poweroff arrives as
    /// IoOut/MmioWrite to the VMM's ACPI sleep register instead.
    SystemEvent(SystemEvent),
    /// aarch64 HVF only (test hook): HVC with imm != 0 (not SMCCC); already answered
    /// X0 = NOT_SUPPORTED, PC past it — VMMs ignore it. KVM never reports it.
    Hvc { imm: u16 },
    Kicked,
}
pub enum SystemEvent { Shutdown, Reset }
```

As implemented (phase 1; `crates/vemu-hv/src/lib.rs` is authoritative):

- Per-arch types are re-exported at the crate root for the host arch:
  aarch64 `{Reg, BootState { pc, x0 }, GicRequest, GicVersion { V2, V3 }, GicInfo,
  ArchVmInfo { gic: GicInfo }}`; x86_64 `{Reg, BootState, ArchVmInfo {}}`. Both
  modules (`vemu_hv::aarch64`, `vemu_hv::x86_64`) compile on every host.
- `GicInfo { version, dist_base, dist_size, redist_base, redist_region_size,
  redist_stride, cpu_base, cpu_size, spi_base, spi_count }` (redist_* are 0 for a
  v2, cpu_* are 0 for a v3) + `GicInfo::is_spi(intid)`. `GicRequest::default()` =
  QEMU virt (0x0800_0000 / 0x080A_0000 / v2 CPU 0x0801_0000).
- `set_boot_state` resets to the entry state (aarch64: CPSR 0x3c5, SCTLR_EL1
  MMU/caches off, X1..X3 = 0, pending MMIO read dropped) **and powers the vCPU on**;
  on a secondary that bypasses CPU_ON (tests use it; KVM: `KVM_SET_MP_STATE`
  RUNNABLE after VCPU_INIT with POWER_OFF). vCPU 0 is created powered on.
- `Vcpu::reset` is gone (CPU_ON does it inside the backend). SMC is answered
  NOT_SUPPORTED inside `run()` (as KVM does); there is no `Smc` exit.
- `Vm::kick` also wakes a vCPU blocked in a powered-off `run()`.
- PSCI emulation: `vemu_hv::aarch64::psci` (`PowerTable`, `dispatch`, constants),
  pure std, used by HVF only.
- `vemu-hv/src/kvm/mod.rs` is a stub whose `create_vm` returns
  `Invalid("KVM backend not built yet ...")`; the kvm agent replaces it.
  `Error::{backend, invalid, guest}` are `pub(crate)` constructors for backends;
  `GuestFault` carries aarch64 fields (esr/far/ipa/pc) — an x86 backend may add
  its own variant/fields.
- x86_64 module also provides `BOOT_GDT_LIMIT`, `BOOT_CS`, `BOOT_DS`,
  `BOOT_CR0/CR4/EFER/RFLAGS`, CR/EFER bit constants, `gdt_entry(flags, base,
  limit)` and `Segment::decode(u64)` (the `kvm_segment` fields), unit-tested
  against the kernel's `GDT_ENTRY(0xa09b/0xc093, 0, 0xfffff)`.

Module layout:

```
vemu-hv/src/lib.rs            arch-neutral traits/types, create_vm dispatch
vemu-hv/src/aarch64/          ESR decode (existing aarch64.rs), PSCI logic (moved from the binary; used by HVF), Reg, BootState, GicRequest/GicInfo
vemu-hv/src/x86_64/           Reg, BootState, boot GDT definition — PURE, compiles on every host (unit-tested on the Mac)
vemu-hv/src/hvf/              macOS aarch64 (cfg(all(target_os="macos", target_arch="aarch64")))
vemu-hv/src/kvm/mod.rs        Linux common: /dev/kvm, ioctl numbers + #[repr(C)] structs, VM/vCPU fds, kvm_run mmap, memory slots, kick (signal + immediate_exit), exit decoding of MMIO/IO
vemu-hv/src/kvm/aarch64.rs    VM type with IPA size, KVM_ARM_PREFERRED_TARGET / VCPU_INIT (PSCI_0_2, POWER_OFF for secondaries), MPIDR, vGIC v3/v2 device, IRQ_LINE encoding, SYSTEM_EVENT
vemu-hv/src/kvm/x86_64.rs     IRQCHIP, PIT2, TSS/identity-map addrs, CPUID (GET_SUPPORTED_CPUID + fixups), MSRs, FPU, sregs (long mode), LAPIC LINT0/1, IRQ_LINE GSI, SHUTDOWN
```

Kick on KVM: per-vCPU thread gets a real-time signal (e.g. SIGRTMIN) with a no-op
handler installed WITHOUT SA_RESTART; `kick()` sets the sticky flag, sets
`kvm_run.immediate_exit = 1`, and `pthread_kill`s the thread. KVM_RUN returning
EINTR (or immediate exit) → `Kicked`.

### As implemented (phase 2a, kvm common; `kvm/mod.rs` docs are authoritative)

Files: `kvm/mod.rs` (Linux runtime), `kvm/abi.rs` (UAPI mirrors: generic
`io/ior/iow/iowr`, common structs incl. `KvmRun` + `KvmRunUnion`, ioctl / cap /
exit / event numbers; layout pinned by const asserts), `kvm/exit.rs` (pure exit
decoding + completion state machine over a raw `kvm_run`, `RunPtr`). `abi.rs` and
`exit.rs` also compile for `cfg(test)` on macOS (inline `mod kvm` in lib.rs), so
their unit tests run on the Mac. `scripts/kvm-abi/check.sh` compiles a C probe
with `zig cc` for aarch64-linux and x86_64-linux that `_Static_assert`s every
Rust value (generated by test `kvm::abi::tests::c_header`) against
`<linux/kvm.h>`; arch agents add literal checks to
`scripts/kvm-abi/probe-<arch>.h` (+ matching Rust const asserts).

Arch hooks (each arch file defines `pub(super) struct Arch: ArchVm`):

```rust
pub(crate) trait ArchVm: Send + Sync + Sized + 'static {
    type Vcpu: ArchVcpu;
    fn vm_type(kvm: &Kvm, cfg: &VmConfig) -> Result<u64>;          // before KVM_CREATE_VM
    fn new(kvm: &Kvm, vm: &VmFd, cfg: &VmConfig) -> Result<Self>;    // right after it (irqchip, vGIC, TSS...)
    fn arch_info(&self) -> ArchVmInfo;
    fn irq_line(&self, irq: u32) -> Result<u32>;                      // -> kvm_irq_level.irq
    fn create_vcpu(&self, kvm: &Kvm, vm: &VmFd, vcpu: &VcpuFd, index: usize) -> Result<Self::Vcpu>; // vCPU thread, after CREATE_VCPU + mmap
    fn init_vcpu(&self, vcpu: &VcpuFd, index: usize) -> Result<()>; // Vm::finalize's thread, all vCPUs exist, index order (default: nothing)
    fn finalize(&self, vm: &VmFd) -> Result<()>;                      // after every init_vcpu
}
pub(crate) trait ArchVcpu: 'static {
    fn set_boot_state(&mut self, vcpu: &VcpuFd, s: &BootState) -> Result<()>;
    fn get_reg(&self, vcpu: &VcpuFd, reg: Reg) -> Result<u64>;
    fn set_reg(&mut self, vcpu: &VcpuFd, reg: Reg, val: u64) -> Result<()>;
    fn handle_exit(&mut self, vcpu: &VcpuFd, reason: u32, data: &KvmRunUnion) -> Result<Option<VcpuExit>>; // default: error
    fn fault_context(&self, vcpu: &VcpuFd) -> String;                 // default: ""
}
```

Helpers: `Kvm::{check_extension, fd}`, `VmFd::{check_extension (VM-level, Err if
unsupported), enable_cap, create_device, irq_line, fd}`, `VcpuFd::{get_one_reg,
set_one_reg (64-bit ids only), get_mp_state, set_mp_state, fd}`, `Fd::{ioctl_val
(_IO only), unsafe ioctl_ptr<T> (rejects size/dir mismatch), set_device_attr,
has_device_attr}`. Errors from ioctls are `Error::backend(op, errno)`; on Linux
`Display` of a backend error shows the errno text (lib.rs).

Behaviour of the common layer:

- `create_vm`: cpus >= 1, kick handler, `/dev/kvm` (O_CLOEXEC, hints for ENOENT /
  EACCES), API 12, requires KVM_CAP_USER_MEMORY + KVM_CAP_IMMEDIATE_EXIT, cpus <=
  min(MAX_VCPUS (else NR_VCPUS, else 4), MAX_VCPU_ID), mmap size >= sizeof(kvm_run),
  `vm_type` → KVM_CREATE_VM (EINTR retried) → NR_MEMSLOTS (VM, else system, else 32)
  → `ArchVm::new`.
- `map_memory`: one slot per `GuestMemory::regions()` entry (slot ids 0..), overlap
  and slot-count checked first. The VM keeps a clone of the `Arc<GuestMemory>`
  (vCPUs hold the VM), so the memory outlives every slot and every KVM_RUN (HVF
  likewise keeps it until after `hv_vm_destroy`). A safe caller dropping its own
  reference early cannot leave KVM a dangling host address.
- `create_vcpu`: vCPU id = index, and vCPUs are created **in index order**: KVM's
  `vcpu_idx` is its creation counter, and the arm64 vGICv2 targets private IRQs by
  `vcpu_id` (vgic-init.c) but delivers SGIs/SPIs by `vcpu_idx` (vgic-mmio-v2.c), so
  the two must be equal. `create_vcpu(i)` fails at once (never waits) unless
  vCPUs `0..i` exist; a counter held across `KVM_CREATE_VCPU` advances when the
  ioctl succeeds (a failed ioctl can be retried; a failure after it uses the id up
  and the next index still matches KVM's count). The binary starts vCPU thread
  `i + 1` only after vCPU `i` reported (`machine::start_vcpus`).
- `finalize`: once; every vCPU must exist; `ArchVm::init_vcpu` for each in index
  order from the calling thread (KVM accepts vCPU ioctls from any thread of the
  process), then `ArchVm::finalize`.
- Exits: MMIO (len 1..=8, passed through; read completion written to
  `mmio.data`), IO (direction/size 1,2,4/count/data_offset validated against the
  mapping; **string I/O is handed out one element per `IoIn`/`IoOut` exit**, KVM
  re-entered once after the last), SYSTEM_EVENT SHUTDOWN/RESET → `SystemEvent`,
  WAKEUP → re-enter, CRASH/others → error; KVM_EXIT_SHUTDOWN → `SystemEvent(Reset)`;
  INTERNAL_ERROR / FAIL_ENTRY / UNKNOWN / EXCEPTION → error with the data words and
  `fault_context`; KVM_RUN errno: EINTR/EAGAIN retried, EFAULT+MEMORY_FAULT shows
  the GPA, ENOEXEC/ENOSYS(arm64 NISV) get hints; anything else → `handle_exit`.
- `run()` refuses to continue with an uncompleted `MmioRead`/`IoIn` (as HVF).
- `get_reg`/`set_reg`/`set_boot_state` first *flush* a completed-but-unconsumed
  MMIO/IO (`KVM_RUN` with immediate_exit = 1, completes without running guest code),
  so registers are consistent as on HVF; `set_boot_state` first abandons a pending
  read (completes as 0). A flush that yields a new exit (x86 MMIO fragments) is
  returned by the next `run()`; `set_boot_state` decodes such an unreturned exit
  and abandons it too (flushing until nothing is left), since the kernel still
  holds that instruction and would otherwise finish it over the new registers
  (test `kvm::tests::x86::set_boot_state_after_a_split_mmio_fragment`).
- Kick: `kick()` = flag, `immediate_exit = 1`, then `pthread_kill(SIGRTMIN)` only
  if the vCPU is in/near KVM_RUN (`in_run`); `run()` = `in_run`, clear
  immediate_exit, test flag, KVM_RUN (all SeqCst). No lost or doubled kicks (proof
  in `kvm/mod.rs`); verified on the x86_64 KVM host (220 kicks incl. racing ones,
  sticky + collapse) by test `kvm::tests::x86::real_kvm_common_layer`, which runs
  a real-mode guest through IO out/in, MMIO write/read, `rep insb` (KVM batches it:
  count 3), `rep outsb`, flush, abandon, kicks.

### As implemented (phase 2b, kvm x86_64; `kvm/x86_64.rs` + `x86_64/kvm.rs` docs are authoritative)

Files: `vemu-hv/src/kvm/x86_64.rs` (Linux/x86_64: the ioctls, ioctl numbers and
caps) and `vemu-hv/src/x86_64/kvm.rs` (pure, every host: `asm/kvm.h` struct
mirrors + setup logic, unit-tested on the Mac). Layouts and numbers are pinned by
const asserts and by the same literals in `scripts/kvm-abi/probe-x86_64.h` (125
checks against zig's kernel headers).

- VM (`Arch::new`): requires KVM_CAP_{IRQCHIP, IRQ_ROUTING, PIT2, SET_TSS_ADDR,
  SET_IDENTITY_MAP_ADDR, EXT_CPUID, MP_STATE}; KVM_GET_SUPPORTED_CPUID (256
  entries) once; `KVM_SET_IDENTITY_MAP_ADDR 0xfffb_c000`, `KVM_SET_TSS_ADDR
  0xfffb_d000` (exported as `vemu_hv::x86_64::{KVM_IDENTITY_MAP_ADDR,
  KVM_TSS_ADDR, KVM_RESERVED_END = 0xfffc_0000}`: keep out of RAM / e820-reserved),
  `KVM_CREATE_IRQCHIP`, then **`KVM_SET_GSI_ROUTING` in QEMU's PC layout**
  (`kvm_pc_setup_irq_routing`): KVM GSI 0 (the in-kernel PIT) → PIC IRQ 0 +
  IOAPIC pin 2; KVM GSI n (1, 3..15) → PIC IRQ n + IOAPIC pin n; 16..23 → IOAPIC
  pin n; no GSI 2. This is what makes the MADT override "ISA IRQ 0 → GSI 2" true
  (KVM's default routing would put the PIT on pin 0). Then `KVM_CREATE_PIT2` with
  `KVM_PIT_SPEAKER_DUMMY` (port 0x61 is emulated by KVM).
- `set_irq_line(gsi)`: gsi = ACPI GSI = IOAPIC pin, accepted for 1 and 3..=23
  (0 and 2 are the PIT's, ≥ 24 out of range), passed to KVM_IRQ_LINE unchanged.
- In-kernel, never seen by the VMM: PIC ports 0x20/0x21/0xa0/0xa1 and ELCR
  0x4d0/0x4d1, PIT 0x40–0x43 and 0x61, IOAPIC MMIO 0xfec0_0000, LAPIC MMIO
  0xfee0_0000 (incl. x2APIC MSRs).
- vCPU (`create_vcpu`, every vCPU): KVM_SET_CPUID2 with per-vCPU fixups — one
  package of `cpus` single-thread cores, **APIC id = x2APIC id = vCPU index**
  (the MADT must list Local APIC ids 0..cpus-1): leaf 1 EBX[31:24] = index,
  EBX[23:16] = cpus, HTT iff cpus > 1, CLFLUSH 64 B if 0, hypervisor + x2APIC
  bits set, TSC-deadline iff KVM_CAP_TSC_DEADLINE_TIMER; leaves 0xB (and 0x1F
  when the host has it) rebuilt (SMT 1 thread, core level `cpus` with shift
  ceil(log2 cpus), EDX = index); Intel leaf 4 / AMD 0x8000_001D cache sharing
  (L1/L2 per core, L3 all) and leaf 4 cores = cpus; AMD 0x8000_0008 ECX
  NC/ApicIdSize and 0x8000_001E ids; everything else (incl. KVM's 0x4000_0000
  leaves) as KVM reports. MSRs (all must be accepted): SYSENTER_CS/ESP/EIP, STAR,
  LSTAR, CSTAR, SYSCALL_MASK, KERNEL_GS_BASE = 0, TSC = 0 (KVM syncs 0 writes),
  MISC_ENABLE = fast strings, MTRRdefType = enabled + WB. FPU FCW 0x37f, MXCSR
  0x1f80. LAPIC LVT LINT0 = ExtINT, LINT1 = NMI (mask bit kept). APIC_BASE is
  KVM's (BSP flag on vCPU 0).
- vCPU 0 starts runnable; secondaries are left in KVM's wait-for-SIPI state:
  their `run()` blocks in the kernel until the guest's INIT/SIPI (or a kick).
- `set_boot_state`: GET_SREGS (keeps apic_base) → BootState sregs exactly as in
  the next section (TR: selector 0, base 0, limit 0x67, type 11, P; LDTR:
  selector 0, limit 0xffff, type 2, P; pending-interrupt bitmap cleared) →
  SET_REGS (RIP/RSI/RSP, RFLAGS 2, rest 0) → `KVM_SET_MP_STATE` RUNNABLE (any
  vCPU, also a halted one). CR4 = PAE only.
- `get_reg`/`set_reg`: GPRs/RIP/RFLAGS via KVM_GET/SET_REGS, CR0/2/3/4/EFER via
  KVM_GET/SET_SREGS (read-modify-write). `fault_context` = " (RIP= RSP= RFLAGS=
  CS=sel/64|32|16 CR0= CR2= CR3= CR4= EFER=)".
- Exits beyond the common layer: KVM_EXIT_HLT / IRQ_WINDOW_OPEN re-enter (not
  expected with the in-kernel irqchip); others are errors with `fault_context`.
- Verified on the x86_64 KVM host by `kvm::x86_64::tests::real_kvm_long_mode_boot`:
  2 vCPUs, long-mode entry through `set_boot_state` with BOOT_GDT + identity page
  tables, CPUID/MSR values seen by the guest, MMIO read/write, port 0x61 in-kernel,
  AP blocked until kicked, then started by INIT/SIPI through the in-kernel LAPIC
  (AP reads APIC id 1), HLT with IF=0 kicked out, re-`set_boot_state` of a halted
  vCPU, triple fault → `SystemEvent(Reset)`.

## x86_64 BootState and GDT (shared contract between vemu-hv and the binary)

```rust
pub struct BootState { pub rip: u64, pub rsi: u64 /* boot_params GPA */, pub rsp: u64, pub cr3: u64 /* PML4 GPA */, pub gdt_base: u64 }
pub const BOOT_GDT: [u64; 4] = [0, 0, 0x00af_9b00_0000_ffff /* 0x10: 64-bit code */, 0x00cf_9300_0000_ffff /* 0x18: data */];
```

The binary writes `BOOT_GDT` at `gdt_base` and identity page tables at `cr3`; the
backend loads GDTR = (gdt_base, 4*8-1), CS = 0x10 (L=1), DS/ES/FS/GS/SS = 0x18,
a valid busy TSS in TR (selector 0, as other VMMs do for KVM's checks), IDT
limit 0, CR0 = PE|MP|ET|NE|WP|AM|PG, CR4 = PAE (+ OSFXSR/OSXMMEXCPT if needed),
EFER = LME|LMA (+SCE not needed), RFLAGS = 0x2, per the Linux 64-bit boot protocol
(Documentation/arch/x86/boot.rst "64-bit BOOT PROTOCOL").

## x86_64 machine (binary, crates/vemu/src/arch/x86_64/)

- Memory: RAM at 0 up to `min(size, 0xC000_0000)`; the rest at `0x1_0000_0000`.
  MMIO hole 3 GiB–4 GiB: virtio-mmio slots at `0xD000_0000 + n*0x200`; IOAPIC
  `0xFEC0_0000`; LAPIC `0xFEE0_0000`; KVM TSS at `0xFFFB_D000` (3 pages) and
  identity map page `0xFFFB_C000` (backend sets these, must stay reserved in e820).
- Low memory: GDT 0x500, boot_params (zero page) 0x7000, cmdline 0x2_0000, PML4/PDPT/PDs
  at 0x9000.., stack top 0x8ff0, ACPI tables at 0xE_0000 (RSDP in 0xE0000–0xFFFFF so
  Linux finds it by scan; also set boot_params.acpi_rsdp_addr), kernel at 1 MiB
  (bzImage protected-mode part, 64-bit entry = load addr + 0x200; require boot
  protocol ≥ 2.12 and XLF_KERNEL_64), initrd high below 3 GiB / `initrd_addr_max`.
- e820: RAM 0–0x9_FC00, reserved 0x9_FC00–0x10_0000, RAM 1 MiB–end of low RAM,
  reserved hole, high RAM.
- ACPI, HW-reduced (FADT flag HW_REDUCED_ACPI): RSDP(rev 2) → XSDT → FADT (+ DSDT),
  MADT (one Processor Local APIC per vCPU, IOAPIC id 0 at 0xFEC00000 GSI base 0,
  ISA interrupt source override for IRQ0→GSI2 like qemu), optionally MCFG none.
  FADT sleep control/status registers (I/O port, e.g. 0x600/0x601) + DSDT `\_S5` package
  → Linux poweroff writes SLP_TYP|SLP_EN → VMM shuts down. FADT RESET_REG (I/O port
  0x604? or 0xCF9) value → VMM reset. DSDT describes each virtio-mmio device as
  `Device (VRxx) { _HID "LNRO0005", _UID n, _CRS { Memory32Fixed(RW, base, 0x200),
  Interrupt(ResourceConsumer, Level, ActiveHigh, Exclusive) { gsi } } }`.
  A small AML byte-code encoder lives in the binary (or a tiny crate) with unit tests.
- Interrupts: virtio slot n → GSI 5+n... (choose a set avoiding ISA conflicts:
  0/2 timer, 1 kbd, 4 COM1 (debug UART), 8 RTC, 9 ACPI SCI), max 16 virtio slots on x86.
- Port I/O bus: debug 16550 at 0x3F8 (with `--debug-uart`, `console=ttyS0`/earlyprintk),
  i8042 at 0x60/0x64 (command 0xFE = reset), ACPI sleep/reset regs, PCI config 0xCF8/0xCFC
  → reads all-ones (no PCI devices), everything else reads all-ones, writes ignored, logged once.
- Kernel cmdline additions: none required (ACPI describes virtio); default `console=hvc0`.

As implemented (phase 2, x86_64 machine; `crates/vemu/src/arch/x86_64/` is
authoritative): a relocatable kernel is loaded at its `pref_address` (16 MiB
for the test kernel), not at 1 MiB; only the KVM identity-map + TSS pages
are e820-reserved inside the 3–4 GiB hole (the rest of the hole is a gap, as
with QEMU / firecracker); `MAX_CPUS` 64, 16 virtio slots on GSIs
`[5,6,7,10..=22]`, `CMDLINE_MAX` 2048 and also the kernel's `cmdline_size`;
RAM 32 MiB–64 GiB in 2 MiB steps (3 GiB cap lifted in phase 3); FADT revision
6.5, hardware-reduced, `IAPC_BOOT_ARCH` = no VGA / no MSI / no CMOS RTC /
ASPM controls, no FACS; MADT LAPIC NMI on LINT1; DSDT `\_SB.COM1`
(PNP0501) only with `--debug-uart`. Port devices: ACPI 0x600 (S5 = 0x34),
0x604 reset (1), i8042 0x60–0x64, absent-hardware ranges (all-ones, not
logged) for 0xCF8–0xCFF, COM2–4 (and COM1 without `--debug-uart`),
0x70–0x71, 0x80–0x8F; 16550 TX only (no receive path).
Because the FADT is hardware-reduced, Linux installs a null legacy PIC, so
the IOAPIC is the only device-interrupt route: `nosmp`, `maxcpus=0`,
`noapic` and `nolapic` leave the guest without device interrupts (virtio
probes fail, hvc0 is silent). Unsupported; `prepare` warns on stderr.

## aarch64 on KVM

Same machine as HVF. Differences: in-kernel PSCI (VCPU_INIT feature PSCI_0_2,
secondaries with POWER_OFF), vGIC v3 via `KVM_CREATE_DEVICE` (dist + redist
addrs, `KVM_DEV_ARM_VGIC_GRP_NR_IRQS`, `CTRL_INIT` in `finalize`), fallback to
vGIC v2 (dist + cpu interface at fixed addresses; ≤ 8 vCPUs; the DTB emits
`arm,cortex-a15-gic` and PPI cpu masks). Timer PPIs are the same INTIDs. IPA size
from `KVM_CAP_ARM_VM_IPA_SIZE`.

### As implemented (phase 2b, kvm aarch64; `kvm/aarch64.rs` docs are authoritative)

Files: `vemu-hv/src/kvm/aarch64.rs` (runtime hooks, Linux aarch64 only) and
`vemu-hv/src/kvm/aarch64/abi.rs` (pure: `kvm_vcpu_init`, arm64 ioctls,
ONE_REG ids, vGIC attributes/geometry, IPA choice, IRQ_LINE encoding). `abi.rs`
is also compiled for `cfg(test)` on macOS (lib.rs inline `mod kvm { mod aarch64
{ mod abi; } }`). Its `abi_table()` must equal the `VEMU_CHECK` lines of
`scripts/kvm-abi/probe-aarch64.h` (test `probe_header_matches`, header embedded
with `include_str!`), and check.sh compiles those against the real arm64
headers, so every Rust value is the kernel's.

- **VM type**: `min(KVM_CAP_ARM_VM_IPA_SIZE, 40)` bits, raised to what the GIC
  needs (≥ 32), error if the host can't reach that; type 0 on kernels without
  the cap. `VmConfig` has no RAM size, so RAM must fit the chosen IPA (vemu's
  layout ends below 2^36; on a host limited to < 36 bits, `map_memory` fails
  for RAM beyond `2^bits`).
- **vGIC** (`ArchVm::new`, before any vCPU, like kvmtool): `KVM_CREATE_DEVICE`
  V3; `NR_IRQS` = 288 (256 SPIs, INTIDs 32..288: `GicInfo::spi_count = 256`);
  DIST at `dist_base` (64 KiB); legacy `ADDR_TYPE_REDIST` at `redist_base` (one
  128 KiB frame per vCPU, `redist_region_size = cpus * 0x20000`). If V3 can't be
  created: V2 with DIST (4 KiB) at `dist_base` and CPU (8 KiB) at `v2_cpu_base`,
  ≤ 8 vCPUs (else `create_vm` fails with a clear message). Alignment and overlap
  are checked first. `finalize` = `KVM_ARM_VCPU_INIT` of every vCPU (below), then
  `KVM_DEV_ARM_VGIC_CTRL_INIT` (skipped for a v2 on kernels without it, which
  initialise lazily). `KVM_CAP_ARM_NISV_TO_USER`
  is enabled when available (diagnostics only).
- **IRQ_LINE**: `KVM_ARM_IRQ_TYPE_SPI << 24 | intid`, only for the GIC's SPIs.
  (A GICv3 rejects lines before `finalize`; the binary only raises lines after.)
- **vCPU** (`create_vcpu` creates, in index order; `init_vcpu`, i.e. `finalize`,
  initialises once every vCPU exists, as api.rst asks for KVM_ARM_VCPU_INIT, and
  before CTRL_INIT, the QEMU/kvmtool order): `KVM_ARM_PREFERRED_TARGET` (read
  once in `new`) + `KVM_ARM_VCPU_INIT` with PSCI_0_2, plus POWER_OFF for index >
  0. No PMU / SVE / PAuth / NV. MPIDR_EL1 is read back after every VCPU_INIT and
  must equal the published layout (below); if a kernel ever assigns something
  else, the expected value is written with `KVM_SET_ONE_REG`. Registers are only
  accessible after `finalize`.
- **MPIDR (interface change)**: aarch64 `ArchVmInfo` gained `mpidr_aff0_cpus:
  u32` and `ArchVmInfo::mpidr(index) -> u64` (affinity bits 23:0). HVF reports
  256 (Aff0 = index, unchanged); KVM reports 16, which is the kernel's own
  `kvm_calculate_mpidr` (Aff0 = id & 0xf, Aff1 = id >> 4 ...). That keeps Aff0 < 16, which
  GICv3 SGIs need (ICC_SGI1R target lists cover 16 Aff0 values and KVM's vGIC
  has no range selector). The DTB's `cpu@<mpidr>` nodes and `reg` use
  `info.mpidr(i)`, so PSCI `CPU_ON` targets match KVM's in-kernel PSCI. For ≤ 16
  vCPUs both schemes give `reg = i`.
- **Boot state**: `KVM_ARM_VCPU_INIT` again with the vCPU's original init
  (KVM's architectural reset: PSTATE 0x3c5, SCTLR_EL1 MMU/caches off; same
  features so kernels from before POWER_OFF became "ephemeral" accept it),
  MPIDR checked and re-applied if needed, then ONE_REG PSTATE = 0x3c5, PC, X0,
  X1..X3 = 0, and for index > 0 `KVM_SET_MP_STATE` RUNNABLE.
- **Registers**: core ONE_REG ids `KVM_REG_ARM64 | U64 | CORE | offsetof(kvm_regs)/4`:
  `X(n)` = `0x6030_0000_0010_0000 + 2n`, `Pc` 0x…40, `Cpsr` (pstate) 0x…42, `Sp`
  = **SP_EL1** 0x…44 (as on HVF, not `regs.sp` = SP_EL0).
- **Exits**: `KVM_EXIT_ARM_NISV` → error with fault IPA + ESR ISS + PC/PSTATE;
  anything else unknown → error. `fault_context` = ` (PC=… PSTATE=…)`.
- **Binary**: `dtb.rs` has the GICv2 variant (`arm,cortex-a15-gic`, `reg` = dist
  + cpu with KVM's sizes, timer PPI flags `IRQ_TYPE_LEVEL_HIGH |
  GIC_CPU_MASK_SIMPLE(cpus)`, which matches QEMU `virt,gic-version=2` (0xf04 for 4 CPUs));
  `MachineDesc.gic` became `MachineDesc.info: ArchVmInfo`; the "GICv2 not
  described yet" refusal in `arch/aarch64/mod.rs` is gone. On HVF the DTB is
  unchanged.
- **Real-KVM test** `kvm::aarch64::tests::real_kvm_aarch64` (skips without
  `/dev/kvm`): 2 vCPUs, vGIC + IRQ_LINE, boot state, MMIO write / read with
  KVM's `ldrsb` sign extension, PSCI CPU_ON (context id, MPIDR, EL1), SYSTEM_OFF
  → `SystemEvent(Shutdown)`, `set_boot_state` powering a stopped secondary on,
  and kicking a vCPU out of WFI / the post-SYSTEM_OFF sleep. Run it on an
  aarch64 KVM host with `cargo test -p vemu-hv --lib kvm::aarch64` (or the
  musl test binary).

## Binary arch interface (crates/vemu/src/arch/)

The binary is split into common code and one machine model per guest arch;
`arch/mod.rs` compiles only the host arch's module and names it `arch::Machine`
(`aarch64::Aarch64`, `x86_64::X86_64`). Common modules: `cli` (help text from
`Machine::HELP`, `--cpus` limit `arch::MAX_CPUS`), `machine` (orchestration),
`vcpu` (thread loop), `bus` (`MmioBus`, `PortIoBus`), `irq::VmIrqLine` (an
`IrqLine` over `Vm::set_irq_line`), `power` (`Control`/`Exit`: shutdown only),
`bootfile` (`regular_file_len`, `Initrd { open, size, load }`), `serial`,
`terminal`. aarch64-only: `arch/aarch64/{layout, loader, dtb, pl011, pl031}.rs`.

```rust
pub trait ArchMachine: Sized {
    const MAX_CPUS: usize;        // --cpus 1..=MAX_CPUS
    const CMDLINE_MAX: usize;     // incl. NUL; common code refuses longer cmdlines
    const VIRTIO_SLOTS: usize;    // more virtio devices → "too many devices" error
    const HELP: ArchHelp;         // { guest, kernel, initrd, debug_uart } lines of --help
    /// Before the VM exists: parse the kernel, open/size the initrd, check RAM size,
    /// place the boot images. Errors are user-facing strings.
    fn prepare(cfg: &Config) -> Result<Self, String>;
    fn vm_config(&self, cfg: &Config) -> VmConfig;
    /// RAM regions (ascending, page-aligned, holes between); the common code
    /// allocates ONE GuestMemory::with_regions for all of them and maps it
    /// (phase 3; was one GuestMemory per region with DMA on ram[0]).
    fn ram_regions(&self, cfg: &Config) -> Vec<RamRegion /* { gpa, size } */>;
    /// Slot n < VIRTIO_SLOTS: { base, size, irq } (irq = set_irq_line number);
    /// Err if the VM cannot raise that irq.
    fn virtio_slot(&self, info: &ArchVmInfo, n: usize) -> Result<VirtioSlot, String>;
    /// Load images into RAM, add arch devices to ctx.mmio / ctx.pio, write the
    /// firmware tables (DTB / ACPI + e820 + boot_params), return the boot vCPU state.
    fn build(self, ctx: BuildCtx<'_>) -> Result<ArchSetup /* { boot: BootState } */, String>;
}
pub struct BuildCtx<'a> {
    pub cfg: &'a Config, pub cmdline: &'a str,          // cmdline = cfg.cmdline(), length-checked
    pub vm: &'a Arc<dyn Vm>, pub info: &'a ArchVmInfo,
    pub ram: &'a Arc<GuestMemory>,                      // all RAM, mapped (one region per ram_regions() entry); also the virtio DMA memory
    pub virtio: &'a [VirtioSlot],                       // populated slots (console, disks, net)
    pub mmio: &'a mut MmioBus,                          // already holds the virtio transports
    pub pio: &'a mut PortIoBus,                         // empty; x86 devices go here
    pub control: &'a Arc<Control>,                      // devices that end the machine:
}                                                       //   control.request_exit(Exit::PowerOff | Exit::Reset)
```

Order in `machine::run`: `prepare` → cmdline check → disks / net / serial →
`create_vm(vm_config)` → `arch_info` → `ram_regions` (one `GuestMemory::with_regions`
+ one `map_memory`) → virtio devices (console, disks, net), each `virtio_slot(n)` →
`MmioTransport` on that memory with a `VmIrqLine(slot.irq)` inserted at `slot.base` → `build` → spawn
one thread per vCPU in index order, each after the previous one created its vCPU
(`start_vcpus`; stops at the first failure) → `Vm::finalize` → console input →
release the threads (vCPU 0 applies `ArchSetup::boot` via `set_boot_state`) →
wait for `Exit` → kick all.

`PortIoBus`: `insert(name, base: u16, count: u16, Arc<Mutex<dyn MmioDevice>>)`
(device `offset` = port − base), `read(port, len) -> u32`, `write(port, len,
data: u32)`; unmapped ports read all-ones, writes ignored, logged once per port (≤ 16);
an access not inside one device is split per port.
A device that must read all-ones (PCI config 0xCFC) registers itself.

For the x86_64 machine agent: replace `arch/x86_64/machine.rs` (placeholder
`impl ArchMachine for X86_64` whose `prepare` fails with "x86_64 machine not
implemented yet") and drop the temporary `allow(dead_code)`s marked
"Placeholder x86_64 machine" in `arch/mod.rs` (`BuildCtx`), `bootfile.rs` and
`bus.rs` (`PortIoBus` impl). `arch/x86_64/mod.rs` is compiled on x86_64 *and*
for `cfg(test)` on every host; only `machine.rs` (the trait impl, which uses the
host's `vemu_hv::{VmConfig, ArchVmInfo, BootState}`) is gated on x86_64. So pure
submodules declared in `x86_64/mod.rs` (bzImage parser, e820, ACPI/AML, page
tables; using `vemu_hv::x86_64::*` explicitly, never the root re-exports) are
unit-tested on the Mac with plain `cargo test -p vemu`; on the Mac they are
otherwise unused, so mark them `#[cfg_attr(not(target_arch = "x86_64"),
allow(dead_code))]`.
Resolved in phase 3: all of RAM is one multi-region `GuestMemory`, so virtio
DMA reaches RAM above the 3 GiB hole; x86 RAM is no longer capped at 3 GiB.

## As implemented (phase 3, integration)

Verification state (details in docs/linux-testing.md):

- Builds + `clippy --all-targets -D warnings` clean for aarch64-apple-darwin,
  aarch64/x86_64-unknown-linux-musl (with test links) and
  aarch64/x86_64-unknown-linux-gnu (check + clippy); `cargo fmt` clean.
- macOS: `cargo test --workspace`, e2e 23/23 (twice).
- aarch64 Linux test executables of all six crates pass inside a vemu guest
  (`scripts/linux-guest-test.sh`, now the default crate set); the aarch64
  Linux vemu binary there fails cleanly: exit 1, `cannot create the VM: open
  /dev/kvm: No such file or directory (os error 2) (KVM is not available: no
  kvm module, or no virtualization support)`, and with a driverless
  `/dev/kvm` node `No such device (os error 19) (no kvm driver behind
  /dev/kvm: ...)`.
- C ABI probes: aarch64 147 common + 47 arch checks, x86_64 147 + 125.
- **x86_64 on the real KVM host** (i7-8550U, kernel 7.3): every test
  executable (incl. `real_kvm_*` and `vemu/tests/boot.rs`), e2e 23/23 three
  times (twice with the cross-built static binary, once with a native glibc
  build: `cargo build/test` and `scripts/e2e.sh --release` on the host), all
  Linux `reboot=` methods (default/bios, acpi, kbd, triple, pci) end vemu
  with status 0, `--debug-uart` earlyprintk/earlycon recipes.
- **aarch64 KVM: still never run** (no host).

Changes made during integration:

- Binary: `BuildCtx.ram` is one `&Arc<GuestMemory>` holding all RAM
  (`GuestMemory::with_regions`, one `map_memory`), the virtio DMA memory too;
  x86 `MAX_RAM` raised from 3 GiB to 64 GiB (RAM beyond 3 GiB at 4 GiB).
  HVF `map_memory` maps each region (was: assumed one contiguous region).
- x86 machine: a real-mode **reset-vector stub** at `0xF_FFF0` (`mov dx,
  0x604; mov al, 1; out dx, al; cli; hlt`). Linux on a hardware-reduced ACPI
  machine picks `BOOT_EFI` (`reboot_init`: `efi_reboot_required()`), and
  without EFI falls back to `BOOT_BIOS`, which jumps to F000:FFF0: the
  default `reboot` used to hang executing zeroed RAM. ACPI tables are capped
  at 64 KiB (`0xE_0000..0xF_0000`) to keep clear of it.
- x86 machine: ports 0x80–0x8F (POST + 8237 DMA page registers) read 0xFF
  quietly: Linux's `i8237A_init_ops` reads 0x87, and the "unhandled port"
  line on stderr failed e2e's `expect_quiet`.
- x86 machine: `layout::KVM_{IDENTITY_MAP_ADDR, TSS_ADDR, RESERVED_END}` are
  re-exports of `vemu_hv::x86_64`'s, so the e820 reservation cannot drift
  from what the backend gives KVM.
- KVM common: hint for ENODEV/ENXIO when opening `/dev/kvm`; the kick
  handler test no longer compares function addresses (an optimised build
  gave a different address for the empty handler: Rust does not guarantee
  unique function addresses).
- vemu `serial` EMFILE test accepts EMFILE at `try_clone` (what Linux/musl
  hit) as well as at `accept` (macOS).
- `vemu/tests/boot.rs` runs on Linux KVM hosts (skips without a usable
  `/dev/kvm`), uses the host arch's fixtures, `VEMU_TEST_BIN` /
  `VEMU_TESTDATA` overrides for cross-built test executables; boot
  command lines use `loglevel=4` (the x86 test kernel's
  CONFIG_DEBUG_STACK_USAGE info lines interleaved with init's output).
- `scripts/e2e.sh`: `--vemu PATH` (prebuilt binary, no cargo); `script(1)`
  optional (python3 `pty` fallback); `timing-idle` measures idle CPU as the
  difference to a 0-second idle run (< 0.25 s), because an x86 bzImage boot
  alone costs ~0.7 s of CPU; `boot-cpus*` use `loglevel=4`.
- zig wrappers drop `-Wl,-O1` (zig warned on every release link);
  `kvm-abi/check.sh` no longer leaves `probe.o` in the current directory and
  reports the arch check counts; `check-linux.sh` also checks + lints the
  `*-linux-gnu` targets when installed; `testdata/x86_64/initramfs.cpio.gz`
  regenerated with the current `mkinitramfs.py` (the old one needed
  `cttyhack`).

## Ownership during parallel work

| Area | Files |
|---|---|
| hv refactor (phase 1) | vemu-hv/src/lib.rs, aarch64/, x86_64/ (types only), hvf/, crates/vemu/** |
| portability + tooling (phase 1) | vemu-core, vemu-virtio, vemu-net, vemu-fdt, .cargo/config.toml, scripts/** (not e2e scenarios' semantics), testdata recipes |
| kvm common (phase 2a) | vemu-hv/src/kvm/mod.rs (+ kvm/layout probes) |
| kvm aarch64 (phase 2b) | vemu-hv/src/kvm/aarch64.rs, crates/vemu/src/arch/aarch64/dtb.rs (GICv2 variant) |
| kvm x86_64 (phase 2b) | vemu-hv/src/kvm/x86_64.rs, vemu-hv/src/x86_64/ |
| x86_64 machine (phase 2) | crates/vemu/src/arch/x86_64/** |
| integration (phase 3) | anything |
