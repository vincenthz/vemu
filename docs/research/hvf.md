# Hypervisor.framework (arm64) behaviour, as used by vemu-hv

Host: macOS 27.2 (Darwin 27.2.0), Apple Silicon, SDK headers from
`$(xcrun --show-sdk-path)/System/Library/Frameworks/Hypervisor.framework/Headers`.
Sources read: the SDK headers (`hv_vm*.h`, `hv_vcpu*.h`, `hv_gic*.h`,
`arm64/hv/hv_kern_types.h`), QEMU `target/arm/hvf/hvf.c` (master, Nov 2026,
including its `kernel-irqchip` / `hv_gic` path), libkrun `src/hvf/src/lib.rs`
(userspace GIC, used for comparison only).

Every claim marked **measured** was observed on this machine, either with
throw-away C probes (scratch, not kept) or with the integration tests in
`crates/vemu-hv/tests/` (kept; they re-verify the behaviour on every run), or
by booting the `testdata/Image` Linux 7.2 kernel on vemu-hv with a scratch
harness (2 and 4 vCPUs, minimal PL011 + PSCI).

## Summary for the VMM

- Create the VM, then the GIC (`hv_gic_create`), then the vCPUs. The GIC
  handles the timers, SGIs, SPIs and **WFI entirely in the kernel**: with
  `hv_gic` the VMM never sees WFI, vtimer or ICC_* exits.
- WFI wake-ups for guest timers are delayed by XNU timer coalescing (25-50%,
  up to ~5 ms). vemu-hv sets QoS USER_INTERACTIVE on vCPU threads. A
  real-time policy would make them exact but let a spinning guest starve and
  **panic the host** (observed), so it is not used (§4).
- `hv_vcpus_exit` is sticky for a vCPU outside `hv_vcpu_run`; vemu-hv adds its
  own flag so a kick is never lost or reported twice.
- HVC exits come with PC already past the HVC; SMC/sysreg/data-abort exits
  point at the instruction (advance by 4).
- A Linux boot traps only OSLAR_EL1 and OSDLR_EL1 writes (once per CPU).
- Redistributor frames are assigned in **vCPU creation order**, not by
  MPIDR. Linux finds them by affinity, so this is fine, but every vCPU should
  be created before any runs. DT redistributor size = `cpus * 0x20000`.

## 1. VM config, IPA size, GIC creation order, geometry

**Measured** (`hv_vm_config_*`, `hv_gic_get_*` probe):

| Query | Value |
|---|---|
| `hv_vm_config_get_max_ipa_size` | 40 bits |
| `hv_vm_config_get_default_ipa_size` | 36 bits (64 GiB) |
| `hv_vm_config_get_default_ipa_granule` | 16 KiB |
| `hv_vm_get_max_vcpu_count` | 64 |
| `hv_vm_config_get_el2_supported` | false |
| distributor size / base alignment | 0x10000 / 0x10000 |
| redistributor region size (max) | 0x2000000 (32 MiB) |
| one redistributor (RD + SGI frame) | 0x20000 |
| redistributor base alignment | 0x10000 |
| MSI region size / alignment | 0x10000 / 0x10000 (unused) |
| SPI range | base 32, count 988 (INTID 32..=1019) |
| reserved INTIDs (`hv_gic_get_intid`) | vtimer 27, EL1 ptimer 30, PMU 23, maintenance 25 |
| GICD_TYPER / GICD_CTLR at reset | 0x0478001f / 0x50 (ARE, DS=1: single security state) |
| ICC_SRE_EL1 / ICC_CTLR_EL1 | 0x7 / 0x40400 (RSS=1) |
| CNTFRQ_EL0, mach timebase | 24 MHz, 125/3 (one mach tick = one counter tick) |

The geometry queries work before `hv_vm_create`. Ordering (**measured**):

- `hv_gic_create` before `hv_vm_create` → `HV_NO_DEVICE` (0xfae94006).
- `hv_gic_config_create` → set bases → `hv_gic_create` after `hv_vm_create`
  succeeds; a second `hv_gic_create` → `HV_BUSY`.
- A misaligned distributor base (0x08001000) is rejected by
  `hv_gic_config_set_distributor_base` → `HV_BAD_ARGUMENT`.
- The header requires the GIC before any vCPU ("so that GIC CPU system
  resources can be allocated"). Creating an *extra* vCPU after others have
  already run still succeeded (and got the next redistributor frame), but the
  header calls the topology final once vCPUs run, so vemu creates them all
  first.
- `hv_vm_destroy` then `hv_vm_create` + `hv_gic_create` again in the same
  process works (tests/mmio.rs does it).

DESIGN's fixed bases fit: 0x0800_0000 (dist) and 0x080A_0000 (redist) satisfy
the 64 KiB alignments, and the SPI range covers 48..80.

**The GIC only claims the frames it uses** (**measured**): with one vCPU,
loads from 0x080E_0008 (redistributor frame 2), 0x0809_0000 and 0x0801_0000
come back as ordinary data-abort exits, as do 0x0900_0000 and 0x0A00_0000. So
the 32 MiB maximal region does not swallow the PL011/virtio windows, and
`GicInfo::redist_region_size` reports `cpus * stride` for the DT.

vemu-hv uses the default IPA size (36 bits) and clamps
ID_AA64MMFR0_EL1.PARange (host value 2 = 40 bits) to 1 (36 bits) so the guest
does not believe in physical addresses the VM cannot map (QEMU does the same).

## 2. Exits and ESR decoding; when to advance the PC

`hv_vcpu_run` returns with `hv_vcpu_exit_t { reason, exception { syndrome
(ESR_EL2), virtual_address (FAR), physical_address (IPA) } }`.

Data abort (EC 0x24), **measured** examples:

- `str w0, [x1]` to 0x0900_0000: ESR 0x93800046 → ISV=1, SAS=2 (4 bytes),
  SSE=0, SRT=0, SF=0, WnR=1, DFSC=6. `physical_address` is the full IPA
  including the page offset (0x080e0008 for a load at offset 8).
- ISS fields used: ISV[24], SAS[23:22] (len = 1 << SAS), SSE[21], SRT[20:16]
  (31 = XZR/WZR), SF[15] (Xn vs Wn destination), CM[8], S1PTW[7], WnR[6].
- `ldp` and pre/post-index writeback stores (`str x1, [x19, #8]!`) give ISV=0
  (ESR 0x92000046) — no syndrome; vemu-hv returns an error with ESR/FAR/IPA/PC.
  Linux's MMIO accessors use plain `ldr/str` (ISV=1).
- Store data: register value truncated to `len` (XZR → 0). Load completion:
  truncate to `len`, sign-extend if SSE, then truncate to 32 bits if SF=0
  (writing Wn zeroes the top of Xn). All variants (x/w/h/b stores incl. XZR/WZR,
  ldr x/w/h/b, ldrsb/ldrsh to x and w, ldrsw, ldr xzr) are covered by
  tests/mmio.rs.

PC rules (**measured**, tests/mmio.rs):

| Exit | PC reported | VMM action |
|---|---|---|
| HVC (EC 0x16, ESR 0x5a00iiii) | **after** the HVC (`hvc` at 0x400001e0 → PC 0x400001e4) | do not advance |
| SMC (EC 0x17, ESR 0x5e00iiii) | **at** the SMC | advance by 4 |
| Data abort (EC 0x24) | at the access | advance by 4 (IL=1) after emulating |
| Sysreg trap (EC 0x18) | at the MSR/MRS | advance by 4 |

HVC is an exception-generating instruction (preferred return = next
instruction); a trapped SMC returns to the SMC itself. QEMU agrees ("Do NOT
advance $pc for HVC", advance for SMC). The HVC/SMC immediate is ISS[15:0].

## 3. Virtual timer with hv_gic

**Measured**: with the in-kernel GIC, `HV_EXIT_REASON_VTIMER_ACTIVATED` is
never returned. A guest that enables CNTV (CVAL = now + 10 ms), unmasks IRQs
and sits in WFI takes INTID 27 through its GIC CPU interface (ICC_IAR1_EL1)
with no exit to userspace at all. The kernel injects PPI 27 from the timer
state; userspace does nothing — no `hv_vcpu_set_vtimer_mask`, no EOI
tracking. QEMU's in-kernel path asserts the same
(`assert(!hvf_irqchip_in_kernel())` on VTIMER_ACTIVATED).

`hv_vcpu_set_vtimer_offset`: `CNTVCT_EL0 = mach_absolute_time() - offset`.
The default offset is 0 (guest counter = host uptime). vemu-hv sets every vCPU
to the same offset, captured at VM creation, so the guest counter starts near
0 and is identical on all vCPUs (tested: CNTVCT < 30 s worth of ticks).

Physical timer registers (CNTP_*) are also handled in-kernel when the GIC
exists (reads/writes produce no exit, CNTP_CTL reads 0x4).

## 4. WFI/WFE, sleeping, and waking on IPIs

**Measured**:

- WFI does **not** exit to userspace when the VM has an `hv_gic`.
  `hv_vcpu_run` blocks in the kernel; `hv_vcpu_get_wait_for_interrupt_time`
  (macOS 27 header: "returns HV_UNSUPPORTED if the VM was created without a GIC")
  is the framework's accounting of exactly that.
- A WFI with DAIF fully masked and nothing pending stays blocked inside
  `hv_vcpu_run` until `hv_vcpus_exit` (returned `CANCELED` after 301 ms when
  kicked at 300 ms; the PC was already past the WFI, i.e. the cancel ends the
  WFI).
- WFE: no exit either (completes in-kernel).
- **SGIs**: a write to ICC_SGI1R_EL1 does *not* trap (no exit on the sender)
  and the target vCPU, blocked in WFI inside `hv_vcpu_run`, takes the SGI
  ~80 µs after the sender was resumed (tests/smp.rs: SGI 5 to Aff0=1).
  ICC_SGI0R/ICC_ASGI1R likewise do not trap.
- `hv_gic_set_spi` from another thread wakes a vCPU in WFI within ~20-50 µs
  (tests/irq.rs SPI 48, tests/smp.rs SPI 49 routed via GICD_IROUTER to vCPU 1).

So the wake mechanism question disappears: SGIs, SPIs, timer and kicks all
wake the in-kernel WFI. vemu-hv has **no userspace WFI emulation**: `run()`
simply re-enters `hv_vcpu_run`. No CNTV_CVAL deadline computation, SGI
trapping or polling is needed. If the framework ever did trap a WFx (EC 0x01),
vemu-hv steps over it, which is architecturally a spurious wake-up (guests
loop around WFI) — a defensive fallback, not a path Linux exercises.

### Timer slack in the in-kernel WFI (important)

**Measured** (guest arms CNTV at now+Δ, sleeps in WFI, handler records CNTVCT):

| Δ | default thread | QoS USER_INTERACTIVE | QoS UTILITY | time-constraint (RT) policy | guest spinning (no WFI) |
|---|---|---|---|---|---|
| 1 ms | +0.52 ms | +0.3-0.5 ms | +8 ms | +0.02 ms | +0 |
| 4 ms | +2.0 ms | +2.0 ms | +26 ms | +0.02 ms | +0 |
| 10 ms | +0.5..5 ms | | | +0.02 ms | +0 |
| 20 ms | +5.0 ms | +3.2 ms | +147 ms | +0.02 ms | +0 |

The in-kernel WFI sleep is a coalescable kernel timer whose leeway depends on
the calling thread's QoS tier; only real-time threads get ~no leeway.

vemu-hv sets **QoS USER_INTERACTIVE** on vCPU threads (`create_vcpu`), the same
trade-off QEMU makes: short guest timers fire a few hundred µs to ~3 ms late.

**Do not use `THREAD_TIME_CONSTRAINT_POLICY` for vCPU threads.** An earlier
version did (period 0, computation 5 ms, constraint 10 ms). A short test
(16 RT spinning vCPUs on a 12-core host for a few seconds) looked fine because
XNU's fail-safe demotes some RT hogs. But a ~130 s run of the same shape
(review experiment, 2026-11-18) starved `watchdogd` for 91 s and the host
**kernel-panicked** ("watchdog timeout: no checkins from watchdogd in 91
seconds"): the fail-safe only demoted about half of the RT threads, and the rest
kept every core busy at priority 97. A guest controls whether its vCPUs spin,
so an RT policy hands the guest a host DoS.

## 5. System registers that trap to userspace

**Measured** with the in-kernel GIC and EL2 disabled (probe executing each
access, then a Linux boot with tracing):

| Access | Result |
|---|---|
| OSLAR_EL1 w, OSLSR_EL1 r, OSDLR_EL1 r/w | **trap** (EC 0x18) |
| DBGPRCR_EL1 w | **trap** |
| MDCCSR_EL0 r, MDCCINT_EL1 w | **trap** |
| LORC_EL1 (S3_0_C10_C4_3) r | **trap** (MMFR1.LO=1 is advertised) |
| MDSCR_EL1, DBGB/W{C,V}Rn_EL1, DBGCLAIM*, DBGAUTHSTATUS | in-kernel (no exit; `hv_vcpu_get_trap_debug_reg_accesses` defaults to false) |
| ICC_* (PMR, IAR1, EOIR1, DIR, SGI1R, SGI0R, ASGI1R, CTLR, SRE, BPR1, AP1R0, RPR, HPPIR1, IGRPEN0/1) | in-kernel |
| CNTV_*, CNTP_*, CNTPCT, CNTVCT, CNTKCTL, CNTFRQ | in-kernel |
| ID_AA64*, MIDR, MPIDR, REVIDR, AIDR, CTR, CLIDR, CCSIDR, ACTLR | in-kernel |
| ERRIDR_EL1, DISR_EL1 (RAS) | in-kernel |
| PMCR_EL0, PMUSERENR_EL0, PMCCNTR_EL0, PMINTENCLR_EL1, AMUSERENR_EL0, TRFCR_EL1, SCXTNUM_EL1 | UNDEF injected into the guest by the framework (no exit) |
| DC CIVAC, IC IALLU, TLBI VMALLE1IS, SEV, YIELD | no exit |

A full Linux 7.2 boot (4 vCPUs, to `vemu-init: done` and PSCI SYSTEM_OFF)
trapped exactly: `msr oslar_el1` and `msr osdlr_el1`, once per CPU
(`clear_os_lock` in arch/arm64/kernel/debug-monitors.c). Nothing else.

vemu-hv emulation (`src/hvf/sysreg.rs`): OSLAR_EL1 writes set OSLSR_EL1.OSLK;
OSLSR_EL1 reads `0b1000 | OSLK << 1` (OSLM = 0b10, lock implemented);
OSDLR_EL1, DBGPRCR_EL1 RAZ/WI; MDCCSR_EL0 RAZ; MDCCINT_EL1 forwarded to the
framework's `HV_SYS_REG_MDCCINT_EL1`. Anything else: RAZ/WI and one log line
per register per VM. ID_AA64DFR0_EL1.PMUVer = 0, so Linux does not touch PMU
registers (`armv8-pmu: failed to probe PMU!` if the DT has a pmu node — the
vemu DT should not have one).

## 6. Kicking

`hv_vcpus_exit(&ids, n)` — callable from any thread. **Measured**:

- On a vCPU inside `hv_vcpu_run` (including blocked in WFI): the run returns
  `HV_EXIT_REASON_CANCELED` within ~30 µs.
- On a vCPU *not* in `hv_vcpu_run`: the next `hv_vcpu_run` returns `CANCELED`
  immediately (as the header says). Two calls before the run collapse into
  one `CANCELED`.

The header does not say what happens to a cancel that races with another exit
(e.g. the vCPU exits for MMIO just as the cancel arrives); it could be consumed
by that exit. vemu-hv makes kicks reliable on its own: `kick()` sets a per-vCPU
`AtomicBool` and then calls `hv_vcpus_exit`; `run()` checks-and-clears the flag
before every `hv_vcpu_run` and treats `CANCELED` as "loop": if the flag was set
the loop top returns `Kicked`, otherwise it was the leftover cancel of a kick
already reported (re-enter silently). So a kick is never lost (the flag
survives any exit) and never reported twice (tests/irq.rs `sticky_kick`:
two pre-run kicks → one `Kicked`; the next run then only returns on a later
kick ≥150 ms after). `kick()` holds the slot lock while calling
`hv_vcpus_exit`, so a vCPU being destroyed concurrently cannot be targeted.

## 7. MPIDR, initial state, ID registers

**Measured** defaults of a fresh vCPU: MPIDR_EL1 = 0, CPSR = 0 (EL0t!),
SCTLR_EL1 = 0, CPACR = 0, CNTV_CTL = 0, vtimer offset 0, vtimer not masked.

- `hv_vcpu_set_sys_reg(HV_SYS_REG_MPIDR_EL1, 1<<31 | index)` before the first
  run. GICv3 routes by affinity: `hv_gic_get_redistributor_base` fails
  (`HV_BAD_ARGUMENT`) while MPIDR is still 0, and works once set.
- GICR_TYPER.Affinity follows MPIDR; GICR_TYPER.Last is dynamic (set on the
  most recently *created* vCPU's frame and cleared when another is created).
  Frames are handed out in creation order: in tests/smp.rs vCPU 1 may sit at
  0x080A_0000 and vCPU 0 at 0x080C_0000. The guest-side scan (walk frames until
  TYPER.Affinity == MPIDR, stop at Last — what Linux does) is exercised by the
  tests and by the Linux boots ("CPU1: found redistributor 1 region
  0:0x00000000080c0000").
- vemu-hv sets CPSR = 0x3c5 (EL1h, DAIF masked) and SCTLR_EL1 = 0x30d00800
  (Linux's `INIT_SCTLR_EL1_MMU_OFF`; reads back 0x30d00980, the CPU adds the
  RES1 ITD/SED bits). Linux's booting.rst only needs MMU/D-cache off, which
  the zero default also satisfies; the RES1 bits keep it architecturally tidy.
- ID registers as the guest sees them: MIDR 0x610f0000 (implementer 0x61,
  Apple), ID_AA64PFR0 0x1101000011110011 (EL0/EL1 AArch64 only, no EL2/EL3,
  FP/AdvSIMD, **GIC = 1** system-register interface, RAS, CSV2/CSV3),
  ID_AA64PFR1 0x1 (BTI; no SME/MTE), ID_AA64DFR0 0x10305006 (PMUVer 0,
  6 breakpoints / 4 watchpoints), ID_AA64MMFR0 0x10000f100002 (PARange 40 bits
  → clamped to 36), ID_AA64MMFR1 0x11212000 (LO=1), CTR 0x8444c004,
  CLIDR 0x81000023. Linux boots with these unchanged ("CPU features: detected:
  GICv3 CPU interface", "hw-breakpoint: found 6 breakpoint and 4 watchpoint
  registers", "arch_timer: cp15 timer running at 24.00MHz (virt)").

## Other notes

- `hv_vcpu_create` binds the vCPU to the calling thread (one per thread; a
  second one on the same thread fails). All `hv_vcpu_*` calls on it must come
  from that thread; `hv_vcpus_exit` and `hv_gic_set_spi` may come from any
  thread.
- `hv_vcpu_set_pending_interrupt` / `get_pending_interrupt` return
  `HV_UNSUPPORTED` with an `hv_gic` (header); interrupts go only through the
  GIC.
- Writeback MMIO and pair loads/stores are rare in practice but would need an
  instruction decoder to support; v1 reports them as errors.
