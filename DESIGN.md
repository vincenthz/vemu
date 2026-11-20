# vemu design

vemu is a small Rust VMM in the spirit of `qemu-system-aarch64 -M virt -accel hvf`,
but with **no CPU emulation**: guest code only runs on hardware virtualization
(Hypervisor.framework on macOS, KVM on Linux). The goal is booting a simple
Linux guest with a console, a disk and NAT networking with port forwards.

Scope (v2): the guest architecture always equals the host's.

| Host | Backend | Guest machine |
|---|---|---|
| macOS aarch64 | HVF + hv_gic | aarch64 `virt`-like: DTB, GICv3, PSCI over HVC, virtio-mmio |
| Linux aarch64 | KVM + in-kernel vGICv3 (fallback vGICv2) + in-kernel PSCI | the same aarch64 machine (the DTB has a GICv2 variant) |
| Linux x86_64 | KVM + in-kernel irqchip (PIC/IOAPIC/LAPIC) + PIT2 | x86_64 machine: 64-bit boot protocol, e820, hardware-reduced ACPI, virtio-mmio in the DSDT |

docs/kvm-design.md is the detailed reference for the KVM backend and the
x86_64 machine (decisions, kernel interfaces, what each phase implemented);
this file has the essentials.

## Decisions

| Topic | Decision |
|---|---|
| Hypervisor | macOS: `Hypervisor.framework` (low-level `hv_*` API), not Virtualization.framework. Linux: `/dev/kvm` ioctls, hand-written UAPI mirrors |
| Guest arch | The host's: aarch64 (HVF, KVM) or x86_64 (KVM) |
| Interrupt controller | In-kernel only, no userspace emulation: Apple GICv3 (`hv_gic_*`, macOS 15+); KVM vGICv3 or vGICv2; KVM PIC + IOAPIC + LAPIC |
| Boot | Direct kernel boot, no firmware. aarch64: `Image` + generated DTB. x86_64: `bzImage` (64-bit entry), zero page, e820, identity page tables, ACPI |
| CPU bring-up | In the backend: PSCI CPU_ON (HVF: emulated in vemu-hv; KVM: in-kernel); x86 INIT/SIPI through KVM's LAPIC. The VMM just runs every vCPU thread |
| Devices | virtio 1.x over **virtio-mmio** (v2, non-legacy): console, block, net |
| Serial | **virtio-console** (`hvc0`) on stdio (raw mode) or a unix socket |
| Network | User-mode NAT (slirp-like), hand-written; host port forwards (`hostfwd`) |
| Root fs | initramfs and/or virtio-blk disk: a raw image, or a vemu overlay on a read-only golden image (docs/overlay-format.md) |
| Disk images | Raw, or the vemu-native overlay format (sparse data region at the virtual layout + 1-bit-per-block bitmap, no qcow2); persistent overlays and throwaway `,snapshot` overlays; `flock` locking (`LOCK_EX` to write, `LOCK_SH` to read, golden images always `LOCK_SH`) |
| Dependencies | `std` + `libc` only. Everything else is written here (HVF FFI, KVM ABI, FDT, ACPI/AML, virtio, TCP/IP NAT) |
| Clock | aarch64: PL031 RTC at 0x0901_0000 (QEMU `virt`'s address) counting the host's UTC seconds; the load register shifts it for the VM's lifetime only; the match interrupt is served by one sleeping thread started on the first alarm. x86_64: no RTC; kvmclock's wall clock |
| Debug aid | Optional write-only UART (`--debug-uart`) on stderr for early boot messages: PL011 at 0x0900_0000 (aarch64), 16550 at port 0x3f8, GSI 4 (x86_64); not the product serial device |

## Workspace

```
crates/vemu-core    GuestMemory, MmioDevice, IrqLine, NetFrontend/NetBackend (shared, stable)
crates/vemu-hv      Arch-neutral hypervisor interface (aarch64/ + x86_64/ guest types, PSCI emulation),
                    HVF backend (hvf/, FFI hand-written), KVM backend (kvm/: common layer + aarch64.rs, x86_64.rs)
crates/vemu-fdt     DTB writer
crates/vemu-disk    disk backends (BlockBackend): raw images, overlays on golden images, snapshots; image locking
crates/vemu-virtio  split virtqueue, virtio-mmio transport, console/block/net devices
crates/vemu-net     user-mode NAT backend (implements vemu_core::NetBackend)
crates/vemu-build   `vemu build` (Alpine images): config parser, release resolution + curl downloads + cache,
                    SHA-256, inflate, tar reader, cpio writer, builder initramfs, the guest /init script,
                    OUT.partial lifecycle (no VM code: the binary runs the builder VM)
crates/vemu         binary: common CLI, machine orchestration, vCPU threads, MMIO + port-I/O buses, stdio;
                    src/arch/<arch>/ machine models (aarch64: layout, Image loader, DTB, PL011, PL031;
                    x86_64: layout/e820, bzImage, boot params + page tables, ACPI/AML, port-I/O devices, 16550)
scripts/            run-signed.sh (cargo runner: ad-hoc codesign w/ hypervisor entitlement), test fixtures,
                    e2e.sh + e2e/ (end-to-end tests booting real guests), zig linker wrappers for the
                    Linux musl targets, check-linux.sh, linux-guest-test.sh, kvm-abi/ (C ABI probe),
                    remote-kvm.sh (run on a remote x86_64 KVM host)
examples/           alpine.conf (commented vemu build config)
testdata/           (gitignored) Image, initramfs.cpio.gz, disk.img; x86_64/{bzImage,...} — scripts/mk-testdata.sh
```

On macOS, binaries need the `com.apple.security.hypervisor` entitlement. `.cargo/config.toml`
sets `scripts/run-signed.sh` as the runner, so `cargo run` / `cargo test` sign
automatically. A binary run directly must be signed first:
`codesign -f -s - --entitlements vemu.entitlements target/debug/vemu`.
On Linux nothing is needed besides read-write access to `/dev/kvm`.

## aarch64 machine layout (guest-physical)

Mirrors QEMU `virt` so guest kernels/configs behave familiarly.

| Range | What |
|---|---|
| `0x0800_0000` | GICv3 distributor (size from `hv_gic_get_distributor_size`) |
| `0x0801_0000` | GICv2 CPU interface (KVM hosts without a GICv3 vGIC only) |
| `0x080A_0000` | GICv3 redistributor region (`GicInfo.redist_region_size` = cpus × per-CPU stride from `hv_gic_get_redistributor_size`; frames past the last vCPU are not claimed by the GIC) |
| `0x0900_0000` | debug PL011 (only with `--debug-uart`), 4 KiB |
| `0x0901_0000` | PL031 real-time clock (host UTC time; alarm on GIC SPI 2 = INTID 34), 4 KiB |
| `0x0A00_0000` | virtio-mmio slots, `0x200` bytes each, slot *n* at `0x0A00_0000 + n*0x200`, 32 slots |
| `0x4000_0000` | RAM (default 1 GiB) |

Alignments must satisfy `hv_gic_get_*_base_alignment`; if the fixed bases above
don't, the backend reports an error (adjust the constants, don't silently move).

Interrupts (GIC INTIDs): virtio slot *n* → SPI INTID `48 + n` (DT `GIC_SPI 16+n`),
level-high. Debug UART → INTID 33 (`GIC_SPI 1`). Arch timer PPIs: secure phys 29,
non-secure phys 30, virtual 27, hyp 26 (DT `GIC_PPI 13/14/11/10`, level-high as in
QEMU `virt` with GICv3).
Check `hv_gic_get_spi_interrupt_range` covers 48..80.

Boot: kernel `Image` loaded at `RAM_BASE + text_offset` (header field; 2 MiB aligned
base). DTB placed in the last 2 MiB of RAM (8-byte aligned, ≤ 2 MiB); initrd right
below the DTB, page aligned. Boot CPU: `PC = kernel entry`, `X0 = DTB GPA`,
`X1..X3 = 0`, `CPSR = 0x3c5` (EL1h, DAIF masked). Secondary CPUs start powered off
and are released by PSCI `CPU_ON` (method `hvc`), which the hypervisor backend
implements (HVF: emulated in vemu-hv; KVM: in-kernel). `MPIDR_EL1` affinity of vCPU *i*
is `arch_info().mpidr(i)` (HVF: Aff0 = *i*; KVM: the kernel's 16 vCPUs per Aff1), which
the DT `cpu@<mpidr>` `reg` uses. The GIC is a GICv3, or on KVM hosts without GICv3
emulation a GICv2 (`arm,cortex-a15-gic`, ≤ 8 vCPUs).

## x86_64 machine layout (guest-physical)

`crates/vemu/src/arch/x86_64/layout.rs` is authoritative.

| Range | What |
|---|---|
| `0x0500` | boot GDT (`vemu_hv::x86_64::BOOT_GDT`: 0x10 64-bit code, 0x18 data) |
| `0x7000` | `boot_params` (zero page); stack top `0x8ff0` |
| `0x9000..0xF000` | identity page tables: PML4, PDPT, 4 PDs of 2 MiB pages (0–4 GiB) |
| `0x2_0000` | kernel command line (≤ 2047 bytes) |
| `0x9_FC00..0x10_0000` | reserved (EBDA/VGA/BIOS area): ACPI tables at `0xE_0000` (RSDP first), a reset-vector stub at `0xF_FFF0` |
| `pref_address` (16 MiB) | kernel (bzImage protected-mode part); a non-relocatable kernel at 1 MiB |
| top of low RAM | initrd (below `initrd_addr_max`) |
| `0xC000_0000..0x1_0000_0000` | MMIO hole: virtio-mmio slot *n* at `0xD000_0000 + n*0x200` (16 slots), IOAPIC `0xFEC0_0000`, LAPIC `0xFEE0_0000`, KVM identity-map page `0xFFFB_C000` + TSS `0xFFFB_D000` (reserved in e820) |
| `0x1_0000_0000` | RAM beyond 3 GiB (up to 64 GiB of RAM in total) |

Boot: 64-bit boot protocol (boot.rst), protocol ≥ 2.12 with XLF_KERNEL_64.
vCPU 0 starts in long mode at `load address + 0x200` with RSI = zero page,
CR3 = 0x9000, GDTR = (0x500, 31), CS 0x10, DS/ES/FS/GS/SS 0x18, a busy TSS
in TR, CR0 = PE|MP|ET|NE|WP|AM|PG, CR4 = PAE, EFER = LME|LMA. The other
vCPUs wait for INIT/SIPI in KVM's LAPIC.

Firmware tables: hardware-reduced ACPI (RSDP rev 2 → XSDT → FADT, MADT,
DSDT). The MADT lists one LAPIC per vCPU (APIC id = vCPU index), IOAPIC id 0
with GSIs 0–23, ISA IRQ0 → GSI 2, LINT1 = NMI. The DSDT has `\_S5`, one
`LNRO0005` device per virtio slot, and `COM1` with `--debug-uart`.

Interrupts (IOAPIC GSIs, through `Vm::set_irq_line`): virtio slot *n* →
`[5, 6, 7, 10..=22][n]`, level-high; the debug 16550 → GSI 4. KVM's GSI
routing is QEMU's PC layout: the in-kernel PIT on IOAPIC pin 2, GSI 0 and 2
not available to the VMM.

Port I/O: ACPI sleep control/status at 0x600/0x601 (S5 = power off), reset
register 0x604 (value 1), i8042 at 0x60/0x64 (0xFE = reset), the 16550 at
0x3F8 with `--debug-uart`. Ports Linux probes on a PC read all-ones without
being logged: PCI config 0xCF8–0xCFF, the other COM ports, CMOS 0x70/0x71,
POST and DMA page registers 0x80–0x8F. PIC, PIT, port 0x61, IOAPIC and LAPIC
are in KVM. Linux's default reboot on this machine (no EFI, so BOOT_BIOS)
jumps to the reset vector, whose stub writes the ACPI reset register.

## Crate interfaces

These signatures are the contract between crates written in parallel. A crate may
add things, but must not change these without updating this file.

### vemu-core (done, frozen)

See `crates/vemu-core/src/lib.rs`: `GuestMemory` (`Arc`, `&self` accessors,
`host_ptr`, `load_u16_acquire`/`store_u16_release`), `MmioDevice`, `IrqLine`,
`NetFrontend`, `NetBackend` (+ its locking rule).

### vemu-hv

Arch-neutral interface for aarch64 and x86_64 guests (the guest arch is the
host's); the full contract is in docs/kvm-design.md ("vemu-hv: arch-neutral
interface") and `crates/vemu-hv/src/lib.rs`. In short:

```rust
pub fn create_vm(cfg: &VmConfig) -> Result<Arc<dyn Vm>>;  // HVF on macOS/aarch64, KVM on Linux; error elsewhere
pub struct VmConfig { pub cpus: usize, #[cfg(aarch64)] pub gic: GicRequest }
pub trait Vm: Send + Sync {
    fn arch_info(&self) -> ArchVmInfo;                 // aarch64: { gic: GicInfo, mpidr_aff0_cpus } (GIC version, bases, sizes, SPIs; MPIDR layout)
    fn map_memory(&self, mem: &Arc<GuestMemory>) -> Result<()>; // every mem.regions() entry (x86: below/above 4 GiB); the VM keeps a clone
    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()>;  // aarch64 SPI INTID / x86 GSI; any thread
    fn create_vcpu(&self, index: usize) -> Result<Box<dyn Vcpu>>; // on the thread that will run it; KVM: in index order
    fn finalize(&self) -> Result<()>;                  // after all vCPUs exist, before the first run
    fn kick(&self, index: usize);                      // sticky; also ends a powered-off wait
}
pub trait Vcpu {                                       // !Send
    fn index(&self) -> usize;
    fn set_boot_state(&mut self, s: &BootState) -> Result<()>;  // aarch64 { pc, x0 } / x86 { rip, rsi, rsp, cr3, gdt_base }: reset state + power on
    fn run(&mut self) -> Result<VcpuExit>;
    fn complete_mmio_read(&mut self, value: u64) -> Result<()>;
    fn complete_io_in(&mut self, value: u32) -> Result<()>;     // x86 only
    fn get_reg(&self, reg: Reg) -> Result<u64>;        // per-arch Reg (aarch64: X(n)/Sp/Pc/Cpsr; x86: GPRs/Rip/Rflags/CRs/Efer)
    fn set_reg(&mut self, reg: Reg, val: u64) -> Result<()>;
}
pub enum VcpuExit { MmioRead{..}, MmioWrite{..}, IoIn{..}, IoOut{..},
                    SystemEvent(SystemEvent /* Shutdown | Reset */), Hvc { imm: u16 }, Kicked }
```

PSCI lives in the backend: the HVF backend emulates PSCI 1.0 over `HVC #0`
(`vemu-hv/src/aarch64/psci.rs`: VERSION, FEATURES, CPU_ON (also after CPU_OFF: CPU
hotplug), CPU_OFF, AFFINITY_INFO, MIGRATE_INFO_TYPE (=2), SYSTEM_OFF, SYSTEM_RESET;
SMCCC_VERSION / CPU_SUSPEND → NOT_SUPPORTED). vCPU 0 starts powered on, the
others off: `run()` of a powered-off vCPU blocks until CPU_ON (which resets it:
CPSR 0x3c5, SCTLR_EL1 MMU/caches off, PC = entry, X0 = context, X1..X3 = 0) or a
kick. SYSTEM_OFF/RESET return `VcpuExit::SystemEvent`. SMC is answered
NOT_SUPPORTED inside `run()`; `HVC #imm` with imm ≠ 0 (not SMCCC) is answered
NOT_SUPPORTED and reported as `VcpuExit::Hvc` (HVF only, a test hook; VMMs ignore it).

KVM backend (`vemu-hv/src/kvm/`, Linux only). The common layer opens
`/dev/kvm` (API 12, `KVM_CAP_USER_MEMORY`, `KVM_CAP_IMMEDIATE_EXIT`), creates
the VM, maps one memory slot per RAM region, creates each vCPU on its own
thread, decodes exits (MMIO, port I/O including string I/O one element per
exit, `KVM_EXIT_SYSTEM_EVENT` → `SystemEvent`, `KVM_EXIT_SHUTDOWN` (x86
triple fault) → `SystemEvent(Reset)`) and implements the kick: sticky flag,
`kvm_run.immediate_exit = 1`, and `SIGRTMIN` (no-op handler without
SA_RESTART) to the vCPU thread while it is in `KVM_RUN`. aarch64 hooks:
IPA-sized VM type, vGICv3 (else v2) device with 256 SPIs and `CTRL_INIT` in
`finalize`, `KVM_ARM_VCPU_INIT` with PSCI 0.2 (POWER_OFF for secondaries; in
`finalize`, once every vCPU exists, before `CTRL_INIT`),
MPIDR as published by `ArchVmInfo::mpidr`, `KVM_IRQ_LINE` = SPI type | INTID.
x86_64 hooks: identity map + TSS addresses, in-kernel irqchip with QEMU's GSI
routing, PIT2, per-vCPU CPUID (APIC id = index), boot MSRs, FPU, LAPIC
LINT0/LINT1, long-mode sregs. Struct layouts and ioctl numbers are pinned by
const asserts and checked against the kernel headers by
`scripts/kvm-abi/check.sh`. Details: docs/kvm-design.md.

The HVF backend advances the PC past emulated MMIO instructions (data-abort exits with
ESR.ISV=1), trapped system registers, SMC and WFx. Each time it also clears
PSTATE.SS and PSTATE.BTYPE, the way KVM's `kvm_skip_instr` does, so a guest
single-stepping over one of these instructions takes the step exception right
after it. A data abort with ISV=0, or one outside RAM that the VMM can't decode,
is an error from `run()` carrying the ESR/FAR/PC.

### vemu-fdt

```rust
pub struct FdtWriter { .. }
impl FdtWriter {
    pub fn new() -> FdtWriter;
    pub fn begin_node(&mut self, name: &str) -> Result<NodeHandle>;   // "" for root
    pub fn end_node(&mut self, h: NodeHandle) -> Result<()>;
    pub fn property(&mut self, name: &str, value: &[u8]) -> Result<()>;
    pub fn property_null(&mut self, name: &str) -> Result<()>;
    pub fn property_string(&mut self, name: &str, s: &str) -> Result<()>;
    pub fn property_string_list(&mut self, name: &str, l: &[&str]) -> Result<()>;
    pub fn property_u32(&mut self, name: &str, v: u32) -> Result<()>;
    pub fn property_u64(&mut self, name: &str, v: u64) -> Result<()>;
    pub fn property_array_u32(&mut self, name: &str, v: &[u32]) -> Result<()>;
    pub fn property_array_u64(&mut self, name: &str, v: &[u64]) -> Result<()>;
    pub fn add_mem_reserve(&mut self, addr: u64, size: u64) -> Result<()>;
    pub fn finish(self) -> Result<Vec<u8>>;    // errors on unbalanced nodes etc.
}
```

### vemu-virtio

```rust
pub trait VirtioDevice: Send {
    fn device_type(&self) -> u32;                  // 1 net, 2 block, 3 console
    fn device_features(&self) -> u64;              // VERSION_1 and RING_INDIRECT_DESC are added by the transport
    fn num_queues(&self) -> usize;
    fn queue_max_size(&self) -> u16 { 256 }
    fn read_config(&self, offset: u64, data: &mut [u8]);
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    /// Driver set DRIVER_OK. `queues[i]` are ready-to-use rings (only those the
    /// driver enabled); `interrupt` signals used-buffer / config-change.
    fn activate(&mut self, ctx: ActivateContext) -> Result<(), ActivateError>;
    /// Driver wrote QueueNotify for queue `index`.
    fn queue_notify(&mut self, index: u16);
    /// Driver reset the device (status = 0). Drop rings, stop backends' use of them.
    fn reset(&mut self);
}

pub struct MmioTransport { .. }                    // impl vemu_core::MmioDevice
impl MmioTransport {
    pub fn new(dev: Box<dyn VirtioDevice>, mem: Arc<GuestMemory>, irq: Arc<dyn IrqLine>) -> MmioTransport;
}

pub mod console {
    /// virtio-console, one port (hvc0). Offers MULTIPORT (max_nr_ports = 1) only
    /// for the control queues' PORT_OPEN: input is held until the guest opens
    /// the port (Linux discards input that arrives before). Without MULTIPORT
    /// negotiated it is the plain 2-queue device.
    pub struct Console;                            // impl VirtioDevice
    #[derive(Clone)] pub struct ConsoleInput;      // Send + Sync
    impl Console { pub fn new(output: Box<dyn std::io::Write + Send>) -> (Console, ConsoleInput); }
    impl ConsoleInput {
        pub fn push(&self, bytes: &[u8]);          // buffered (1 MiB); blocks while full, until close()
        pub fn try_push(&self, bytes: &[u8]) -> usize; // never blocks; drops what does not fit (tty)
        pub fn close(&self);                       // release blocked pushers (also on Console drop)
    }
}
pub mod block {
    pub struct Block;                              // impl VirtioDevice
    impl Block {
        pub fn new(file: std::fs::File, read_only: bool) -> std::io::Result<Block>; // raw image; flock: SH if ro, else EX (NB)
        pub fn with_backend(backend: Arc<dyn vemu_disk::BlockBackend>) -> Block;    // any backend (vemu_disk::open)
    }
}
pub mod net {
    pub struct Net;                                // impl VirtioDevice; registers itself as NetFrontend
    impl Net { pub fn new(mac: [u8; 6], backend: Arc<dyn vemu_core::NetBackend>) -> Net; }
}
```

Interrupt: transport keeps `InterruptStatus`; bit 0 used-buffer, bit 1 config change;
line level = `status != 0`; `InterruptACK` clears bits and lowers the line when zero.
Devices may complete requests from non-vCPU threads (console input, net rx), so
the device-side state touched from those threads lives behind its own `Arc<Mutex<..>>`.

### vemu-disk

What a guest disk's bytes are. Used by vemu-virtio's `Block` (one segment of
guest memory per call, no bounce buffer) and by the binary (`--disk`,
`vemu overlay`).

```rust
pub trait BlockBackend: Send + Sync {
    fn size(&self) -> u64;                          // virtual disk bytes
    fn read_only(&self) -> bool;
    fn read_at(&self, buf: ReadBuf<'_>, offset: u64) -> io::Result<()>;   // ReadBuf/WriteBuf: raw pointers
    fn write_at(&self, buf: WriteBuf<'_>, offset: u64) -> io::Result<()>; //   into guest RAM, never &[u8]
    fn flush(&self) -> io::Result<()>;              // virtio FLUSH
    fn shutdown(&self) -> io::Result<()> { Ok(()) } // clean exit: an overlay persists its bitmap
}
pub struct Raw;      // impl BlockBackend; Raw::from_file(file, read_only), .guard_overlay_magic()
pub struct Overlay;  // impl BlockBackend: golden image + overlay file, or a snapshot
pub enum Format { Auto, Raw, Overlay }
pub struct DiskOptions { pub read_only: bool, pub snapshot: bool, pub format: Format }
pub fn open(path: &Path, opts: DiskOptions) -> io::Result<Arc<dyn BlockBackend>>;
pub fn create(base: &Path, overlay: &Path, block_size: u32) -> io::Result<Header>;
pub fn snapshot(base: &Path) -> io::Result<Overlay>;   // file in temp_dir(): O_TMPFILE on Linux, else unlinked at once; never synced
pub fn info(overlay: &Path) -> io::Result<OverlayInfo>;
```

Overlay rules (details: docs/overlay-format.md and `overlay.rs`): the bitmap
lives in memory; reads of allocated blocks never touch the golden image;
writes to allocated blocks take no lock; allocating writes (copy-up of
partial blocks) serialize on one lock and set a block's bit only after its
data is written; a flush copies the dirty bitmap pages, syncs the data
(`F_FULLFSYNC` / `fdatasync`), writes the pages, syncs again, one flush at a
time. Bits only go 0 → 1 and the header is written once, so every crash
leaves a consistent overlay without a journal. A failed flush is final for
the open overlay (later writes and flushes fail): a sync after a failed one
proves nothing on Linux, so retrying could persist bits for lost data. Golden images are fingerprinted
(size, mtime ns, FNV-1a of 16 × 64 KiB samples) and a mismatch is refused;
an overlay as a golden image (a chain) is refused. Detected-raw read-write
disks refuse guest writes that would put the overlay magic at offset 0.

### vemu-net

```rust
pub struct UserNetConfig {
    pub net: Ipv4Addr,          // 10.0.2.0/24
    pub gateway: Ipv4Addr,      // 10.0.2.2  (host, ARP/ICMP/TCP/UDP to it reach host 127.0.0.1)
    pub dns: Ipv4Addr,          // 10.0.2.3  (relays to the host resolver from /etc/resolv.conf)
    pub guest: Ipv4Addr,        // 10.0.2.15 (handed out by DHCP)
    pub guest_mac: [u8; 6],     // 52:54:00:12:34:56
    pub hostfwd: Vec<HostFwd>,
}
impl Default for UserNetConfig;
pub enum Proto { Tcp, Udp }
pub struct HostFwd { pub proto: Proto, pub host_addr: Ipv4Addr, pub host_port: u16, pub guest_port: u16 }
impl std::str::FromStr for HostFwd;  // qemu syntax: "tcp:127.0.0.1:2222-:22", "tcp::8080-:80", "udp::5353-:53"
pub struct UserNet;                  // impl vemu_core::NetBackend; runs its own poll() thread
impl UserNet { pub fn new(cfg: UserNetConfig) -> std::io::Result<Arc<UserNet>>; }
```

Architecture: a sans-IO core (`Stack`: frames in → frames out + socket ops,
time passed explicitly) driven by one thread doing `poll(2)` over host sockets and
a self-pipe woken by `transmit`/`rx_ready`. Unit tests drive the core with
synthetic frames; integration tests use real loopback sockets.

NAT semantics (qemu-compatible): UDP is endpoint-independent (one unconnected
host socket per guest source port; replies from any source, 127.0.0.0/8 shown
as 10.0.2.2; 240 s idle timeout), DNS to 10.0.2.3 uses a socket per guest port
connected to the host resolver (10 s idle). Packets for the guest above the
1500-byte MTU are IPv4-fragmented (DF cleared); guest fragments are dropped.
A host TCP reset is passed on only after the data the peer sent before it
has reached the guest. Every flow costs a host fd: `UserNet::new` raises the
soft `RLIMIT_NOFILE` toward 4096 (hard limit permitting) and scales the caps
(256 guest TCP, 128 hostfwd TCP, 256 UDP sockets) to the limit minus a
reserve of 64; hostfwd clients beyond their cap stay in the listen backlog.
EMFILE on a guest connect answers RST and is logged once.

### vemu (binary)

```
vemu --kernel PATH [--initrd PATH] [--append CMDLINE] [--memory 1G] [--cpus N]
     [--disk PATH[,ro|,snapshot][,format=raw|overlay]]... [--net user[,hostfwd=SPEC]...|none]
     [-p [HOSTADDR:]HOSTPORT:GUESTPORT[/tcp|/udp]]... [--serial stdio|unix:PATH|none] [--debug-uart]
vemu overlay create BASE OVERLAY [--block-size N]     # default 4K, 512..=2M
vemu overlay info OVERLAY                             # exit 1 if the golden image is unusable
vemu build CONFIG [-o OUT] [--force] [--cache DIR] [--kernel PATH] [--timeout SECS] [-v]
```

- `build` (docs/image-builder.md): `vemu_build::prepare` does the host side
  (config, release, verified minirootfs, initramfs (0600, in the 0700
  cache directory: it carries the [files] data), `OUT.partial`);
  `src/build.rs` runs the builder VM with `machine::run`
  in-process: 2 vCPUs, 1 GiB, `--net user` without forwards, the disk raw,
  the console captured (`SerialConfig::Capture`) into `OUT.build.log`, and
  `Config.timeout` (the machine stops with `Exit::Timeout`). Success is the
  nonce marker followed by a guest power-off. Temporary files (downloads,
  the initramfs, `OUT.partial`) and curl's pid are registered in
  `vemu_build::cleanup` while they exist; the signal handlers (installed
  before anything is downloaded) and the panic hook call its
  async-signal-safe `run_now` (kill curl, unlink the files). Build
  messages ignore stderr/stdout write errors (no panic on a closed pipe).
  The cache index records the mirror and how each digest was trusted
  (`https`, or `pinned` for an insecure mirror with a matching pin); an
  unpinned insecure resolution is never recorded, and an entry is reused
  only by a config with the same mirror (and the same pin, for `pinned`).

- `overlay` is a subcommand only as the first argument (a VM's command line
  always starts with an option).
- `--disk`: opened by `vemu_disk::open` before the VM exists (locks taken
  then); an overlay is recognized by its magic. `snapshot,ro` and
  `snapshot,format=overlay` are usage errors. When the machine stops, every
  disk's `BlockBackend::shutdown` runs (overlays persist their bitmap); a
  failure turns a clean exit into an error exit.

- If `--append` contains no `console=`, `console=hvc0` is appended.
- `--serial stdio` (default): host terminal in raw mode when it is a TTY, restored on exit;
  `Ctrl-A x` quits, `Ctrl-A Ctrl-A` sends a literal Ctrl-A. `unix:PATH` listens on a
  unix socket, one client at a time (output dropped while none connected). An existing
  socket file is replaced only if a connect() to it is refused (stale); a live one is an
  "in use" startup error. At exit the file is removed only if it is still ours (same
  dev/ino). Transient accept() errors (EMFILE, ECONNABORTED, ...) are retried with a
  backoff of 10 ms to 1 s.
- Default `--net user` (one virtio-net device, MAC 52:54:00:12:34:56) unless
  `--net none`. `hostfwd=` specs are parsed at the command line (usage error on a
  bad spec); a forward that cannot be bound is a startup error. At exit, guest data
  already acknowledged by the NAT gets up to 1 s to drain to host sockets.
- Device slot order: console (slot 0), disks, net.
- Threads: one per vCPU (HVF binds vCPUs to threads; KVM runs each on its creating thread), console input thread, net thread
  (inside vemu-net), main thread waits for shutdown. All vCPUs are created, then
  `Vm::finalize`, then every thread runs; vCPU 0 first gets the arch's `BootState`.
  The loop only dispatches MMIO / port I/O and turns `SystemEvent` into the exit
  (guest reset = exit, like `-no-reboot`); PSCI is the backend's. x86 ACPI S5,
  the ACPI reset register and the i8042 reset end the machine from their
  port-I/O devices (`Control::request_exit`).
- All of RAM is one `GuestMemory` (one region per `ArchMachine::ram_regions`
  entry, holes between them), mapped with one `map_memory` call; virtio DMA
  uses it, so it reaches RAM above the x86 PCI hole too.
- Common code vs `src/arch/<arch>/`: see docs/kvm-design.md, "Binary arch interface".
- Exit status: 0 on guest poweroff/reset, non-zero on VMM error.

## Testing

- `cargo test --workspace`: unit tests everywhere; real-hypervisor tests run
  where they can (HVF integration tests on macOS; `kvm::*::real_kvm_*` and
  `vemu/tests/boot.rs` on Linux with `/dev/kvm`) and skip otherwise.
- `scripts/e2e.sh`: 31 scenarios booting real guests (macOS, Linux aarch64,
  Linux x86_64; `--vemu PATH` for a prebuilt binary), 4 of them for
  overlays (`disk-overlay-*`) and 4 for `vemu build` (`build-*`; they need
  internet and SKIP without it).
- vemu-build: SHA-256 against NIST vectors, inflate against zlib vectors,
  corruptions, truncations, a bomb bound (global across gzip members) and
  a system gzip round trip; tar
  (GNU/pax long names, refusals); cpio round trip; config errors with
  file:line; release index parsing; resolution against a fake curl
  (pins, cache, offline fallback, trust-aware cache reuse: an insecure
  entry never reaches an https build); the cleanup registry; the
  generated script's contents.
- vemu-disk: a model-based randomized test against an in-memory disk, and a
  crash test that cuts the power at every write and sync of an overlay
  (keeping any subset of the unsynced writes, torn per sector) and checks
  the crash guarantees after reopening.
- From macOS for Linux: `scripts/check-linux.sh` (cross check/clippy/test
  build), `scripts/kvm-abi/check.sh` (KVM ABI vs kernel headers),
  `scripts/linux-guest-test.sh` (aarch64 Linux tests in a vemu guest).
- Real Linux hosts: docs/linux-testing.md. State: x86_64 KVM passes
  everything on an Intel host; aarch64 KVM has never run.

## Rules for contributors (and agents)

- Dependencies: `std` + `libc` only. No new crates.
- `unsafe` blocks carry a `// SAFETY:` comment.
- Build/test only your crate while others are in flux: `cargo test -p <crate>`.
- Don't edit another crate during parallel work; record needed interface changes
  in your report instead.
- Never `git commit`; leave changes in the working tree.
