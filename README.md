# vemu

vemu boots Linux virtual machines using the host's hardware virtualization and
nothing else. It works like `qemu-system-aarch64 -M virt -accel hvf` (or
`-accel kvm`), but it has no CPU emulator and no TCG fallback, and the only
device models are the few a Linux guest needs. Guest code always runs on the
real CPU, so the guest has the host's architecture.

| Host | Hypervisor | Guest |
|---|---|---|
| macOS 15+ on Apple silicon | Hypervisor.framework (`hv_*`) + in-kernel GICv3 | aarch64 Linux `Image` |
| Linux on aarch64 | KVM + in-kernel vGICv3 (or vGICv2) and PSCI | aarch64 Linux `Image` |
| Linux on x86_64 | KVM + in-kernel PIC/IOAPIC/LAPIC and PIT | x86_64 Linux `bzImage` |

- **Boot:** directly from a kernel plus an optional initramfs. No firmware
  or bootloader is involved: aarch64 guests get a device tree; x86_64 guests
  the 64-bit Linux boot protocol, an e820 map and hardware-reduced ACPI
  tables.
- **Devices:** virtio-mmio console (`hvc0`), block disks (raw images, or
  sparse copy-on-write overlays on a shared read-only golden image) and
  network. aarch64 guests also get a PL031 real-time clock, so the clock
  is right from boot (x86_64 guests read it from kvmclock). A
  write-only debug UART is available for early boot messages (a PL011 on
  aarch64, a 16550 at I/O port 0x3f8 on x86_64).
- **Network:** user-mode NAT (like qemu's `-netdev user`) with DHCP, a DNS
  relay and host port forwards. It needs no root and no host configuration.
- **Code:** written in Rust with only `std` and `libc`. The HVF and KVM
  bindings, the device tree and ACPI writers, virtio and the TCP/IP NAT are
  all written in this repository.

The aarch64 machine copies QEMU `virt`'s memory map, so kernels and
configurations that boot under QEMU boot here too. [DESIGN.md](DESIGN.md)
covers the architecture, the memory maps and the interfaces between crates;
[docs/kvm-design.md](docs/kvm-design.md) has the details of the KVM backend
and the x86_64 machine.

## Requirements

- Rust 1.90 or later.
- **macOS:** a Mac with Apple silicon, on macOS 15 or later (needed for the
  in-kernel GIC, `hv_gic_*`). Development and testing used macOS 27.
- **Linux:** an aarch64 or x86_64 machine with KVM, and read-write access to
  `/dev/kvm`. That usually means being in the `kvm` group
  (`sudo usermod -aG kvm $USER`, then log in again); vemu needs no root.
  x86_64 needs VT-x or AMD-V (`kvm_intel` or `kvm_amd` loaded). aarch64
  needs a kernel booted at EL2 with KVM, and a GICv3, or a GICv2 that KVM
  can emulate (then at most 8 vCPUs). A virtual machine without nested
  virtualization has no `/dev/kvm`. vemu's error message says which of these
  is missing.

### Guest kernel

The kernel needs `CONFIG_VIRTIO_MMIO`, `CONFIG_VIRTIO_CONSOLE`,
`CONFIG_VIRTIO_BLK` and `CONFIG_VIRTIO_NET`, built in or as modules in your
initramfs.

- **aarch64:** an uncompressed arm64 `Image` (`arch/arm64/boot/Image`),
  with `CONFIG_ARM_GIC_V3` (and `CONFIG_ARM_GIC` for KVM hosts with a GICv2),
  `CONFIG_ARM_PSCI_FW` and the architected timer, which every arm64
  defconfig has. Compressed (`Image.gz`) and EFI zboot (`vmlinuz.efi`)
  kernels are rejected with a hint. For `--debug-uart`:
  `CONFIG_SERIAL_AMBA_PL011_CONSOLE`.
- **x86_64:** a `bzImage` (`arch/x86/boot/bzImage`) with boot protocol 2.12
  or later and a 64-bit entry point (Linux 3.8 or later), and `CONFIG_ACPI`:
  vemu describes the CPUs, the interrupt controller and the virtio devices
  in ACPI tables, and virtio-mmio finds its devices there (`LNRO0005`). No
  PCI is needed. Recommended: `CONFIG_KVM_GUEST` (kvmclock and
  paravirtual IPIs) and `CONFIG_X86_X2APIC`. For `--debug-uart`:
  `CONFIG_SERIAL_8250_CONSOLE` (and `CONFIG_EARLY_PRINTK`). ELF `vmlinux`
  and PE/EFI-only images are rejected with a hint.

## Build

### macOS

```sh
cargo build --release
codesign -f -s - --entitlements vemu.entitlements target/release/vemu
```

Hypervisor.framework refuses to create a VM unless the binary carries the
`com.apple.security.hypervisor` entitlement, so a freshly built binary has to
be signed (ad hoc, as shown) before you run it. `cargo run` and `cargo test`
take care of this: `.cargo/config.toml` sets `scripts/run-signed.sh` as the
runner, and it signs each binary before running it.

```sh
cargo run --release -- --kernel Image --initrd initramfs.cpio.gz
```

### Linux

```sh
cargo build --release
./target/release/vemu --kernel bzImage --initrd initramfs.cpio.gz   # x86_64
./target/release/vemu --kernel Image --initrd initramfs.cpio.gz     # aarch64
```

Nothing else is needed: no signing, no capabilities.

### Cross-building Linux binaries on macOS

Static Linux binaries can be built on a Mac with
[zig](https://ziglang.org) as the linker (`brew install zig`);
`.cargo/config.toml` already points the musl targets at the wrappers in
`scripts/`:

```sh
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p vemu
# -> target/x86_64-unknown-linux-musl/release/vemu, runs on any x86_64 Linux
```

`scripts/check-linux.sh` runs check, clippy and a test build for both Linux
targets (and check plus clippy for the `*-linux-gnu` targets if they are
installed).

## Usage

```
vemu --kernel PATH [--initrd PATH] [--append CMDLINE] [--memory 1G] [--cpus N]
     [--disk PATH[,ro|,snapshot][,format=raw|overlay]]...
     [--net user[,hostfwd=SPEC]...|none] [-p [HOSTADDR:]HOSTPORT:GUESTPORT[/udp]]...
     [--serial stdio|unix:PATH|none] [--debug-uart]
vemu overlay create BASE OVERLAY [--block-size N]
vemu overlay info OVERLAY
vemu build CONFIG [-o OUT] [--force] [--cache DIR] [--kernel PATH] [--timeout SECS] [-v]
```

`vemu --help` describes every option (`vemu overlay --help` the overlay
commands, `vemu build --help` the image builder). If the command line has no `console=`,
vemu adds `console=hvc0`. vemu exits with status 0 when the guest powers off
or reboots, 1 on a VMM error, and 2 on a usage error.

The options are the same on every host; the kernel is the host
architecture's (`Image` on aarch64, `bzImage` on x86_64). Limits:

| | aarch64 | x86_64 |
|---|---|---|
| `--cpus` | 1 to 64 (8 on a KVM host with a GICv2) | 1 to 64 |
| `--memory` | 2 MiB multiples, up to 63 GiB (RAM starts at 1 GiB) | 32 MiB to 64 GiB, 2 MiB multiples (above 3 GiB, the rest goes above 4 GiB) |
| virtio devices (console + disks + net) | 32 | 16 |
| power off / reboot | PSCI `SYSTEM_OFF` / `SYSTEM_RESET` | ACPI S5 / every Linux `reboot=` method (ACPI reset register, keyboard controller, triple fault, BIOS reset vector) |

### Examples

A shell from an initramfs, with 2 vCPUs and 2 GiB of RAM:

```sh
vemu --kernel Image --initrd initramfs.cpio.gz --cpus 2 --memory 2G
```

A root filesystem on a raw disk image, plus a second disk that is read-only:

```sh
vemu --kernel Image --disk rootfs.img --disk data.img,ro \
     --append "root=/dev/vda rw"
```

Disks appear as `/dev/vda`, `/dev/vdb`, ... in command-line order. A raw image
can be created with `mkfile -n 4g rootfs.img` or `truncate -s 4G rootfs.img`.
Each image is locked while vemu runs (`flock`: exclusive when read-write,
shared with `ro`), so a second VM, or the same image given twice, cannot write
it at the same time; vemu refuses to start with "image is in use".

### Golden images and overlays

A **golden image** is a raw image that you prepare once (install and
configure a system) and then never modify. An **overlay** is a small,
sparse file that holds one VM's writes on top of it: blocks the VM has
written come from the overlay, everything else from the golden image. Any
number of VMs can run on one golden image at once, each with its own
overlay, and an overlay keeps its writes from one run to the next.

```sh
# Prepare the golden image once, then stop writing it.
truncate -s 8G golden.raw
vemu --kernel Image --initrd installer.cpio.gz --disk golden.raw
chmod a-w golden.raw                         # optional, but a good idea

# One overlay per VM: it starts at a few KiB and grows with the VM's writes.
vemu overlay create golden.raw vm1.vov
vemu overlay create golden.raw vm2.vov

# Run them (at the same time if you like). Each VM keeps its own changes.
vemu --kernel Image --disk vm1.vov --append "root=/dev/vda rw"
vemu --kernel Image --disk vm2.vov --append "root=/dev/vda rw" --net none

# A throwaway run: writes go to a temporary overlay that is deleted when
# vemu exits, like qemu's snapshot=on.
vemu --kernel Image --disk golden.raw,snapshot --append "root=/dev/vda rw"

vemu overlay info vm1.vov                    # golden image, status, usage
```

`vemu overlay info vm1.vov` prints something like:

```
overlay:        vm1.vov
format:         vemu overlay, version 1
virtual size:   8 GiB (8589934592 bytes)
block size:     4 KiB
golden image:   /home/me/vms/golden.raw (stored relative to the overlay's directory: golden.raw)
fingerprint:    size 8589934592, modified 1795011509.780744097, sample digest 4128ed30895abf05
golden status:  ok (unchanged)
allocated:      51213 of 2097152 blocks, 200.1 MiB (2.4%)
file:           200.3 MiB on disk (8.0 GiB apparent, sparse)
```

- `--disk PATH` recognizes an overlay by its header, whatever the file is
  called (`.vov` is only a convention). `--disk vm1.vov,ro` uses an overlay
  read-only.
- The overlay records where its golden image is (relative to the overlay's
  directory when the two share a parent directory other than `/`, so a
  directory holding both can be moved), plus its size, modification time
  and a digest of 1 MiB of samples. If the golden image has changed, vemu
  refuses the overlay rather than show the guest a corrupted disk. While
  any VM uses a golden image (through an overlay or a snapshot), vemu
  refuses to open it read-write.
- What the guest flushed (`sync`, `fsync`, a clean unmount) survives a
  crash of the host or of vemu; unflushed writes may be lost, as with a
  real disk. A clean exit (guest power-off, Ctrl-A x) keeps everything.
  If the host fails a flush (an I/O error, a full or over-quota
  filesystem), the overlay takes no more writes until vemu is restarted,
  and vemu exits with an error: the writes since the last completed flush
  are lost, but the overlay stays consistent.
- `--block-size` (default 4K) sets the allocation unit: a power of two
  from 512 to 2M. Larger blocks shrink the in-memory bitmap (32 KiB per GiB
  of disk at 4K) but make small writes to fresh blocks cost a whole block.
- Snapshot overlays live in `$TMPDIR` (or the system's temporary directory
  if it is unset or empty). On Linux the file never has a name
  (`O_TMPFILE`); elsewhere it is unlinked as soon as it is created, so
  nothing is left behind even if vemu is killed. `snapshot` on
  an overlay, and `snapshot,ro`, are refused.
- A raw image that happens to start with the overlay magic `VEMUOVL` can be
  given as `--disk PATH,format=raw`. For raw images whose format was
  detected, vemu refuses guest writes that would put that magic at the
  start of the disk, so a guest cannot turn its raw disk into an overlay
  pointing at a host file.
- Overlays cannot be chained (the golden image is always raw), and writes
  are never merged back into the golden image.

[docs/overlay-format.md](docs/overlay-format.md) specifies the file format
and its crash-consistency rules.

### Building images

`vemu build` makes a golden image that behaves like a normal Alpine Linux
install (OpenRC, apk, a getty on the console) from a small config file,
with these optional features:

- an ssh server (OpenSSH or dropbear) with your keys;
- networking: DHCP, DNS, the hostname, NTP;
- extra packages;
- host files copied in;
- a setup script.

```sh
vemu build examples/alpine.conf -o alpine.raw     # ~5 s with a fast mirror
vemu overlay create alpine.raw vm1.vov
vemu --kernel testdata/Image --disk vm1.vov --append "root=/dev/vda rw" -p 2222:22
ssh -p 2222 root@127.0.0.1
```

A minimal config:

```ini
kernel = ../testdata/Image
hostname = web1

[ssh]
enable = true
authorized_keys = ~/.ssh/id_ed25519.pub

[packages]
list = curl nginx

[files]
/etc/nginx/http.d/default.conf = site.conf 0644

[run]
# setup.sh: rc-update add nginx default   (packages do not enable their
# services by themselves, as on any Alpine)
script = setup.sh
```

How it works:
- vemu boots a builder VM (the Alpine minirootfs as its initramfs, on the
  same kernel), which formats the image and installs Alpine into it with
  apk. The host needs no root, no `mkfs` and no loop devices, and the
  same path works on macOS and Linux.
- The image must be the host's architecture: build x86_64 images on an
  x86_64 KVM host.
- Downloads use the system `curl`, over https only. vemu verifies them
  by SHA-256 and caches them, and apk verifies the packages' signatures.
- The image is a sparse raw ext4 filesystem (`/dev/vda`, no partitions),
  read-only once built. A 1 GiB image takes ~50 MiB on disk.
- Root logs in on the console without a password (Alpine's default), and
  over ssh with keys only.
- Each VM generates its own ssh host keys on its first boot.

[docs/image-builder.md](docs/image-builder.md) is the reference: every
config key, the trust chain, caching, reproducibility and troubleshooting.

### Networking

`--net user` is the default. The guest sees qemu's usual user-mode network:

| Address   | What it is                                                         |
|-----------|--------------------------------------------------------------------|
| 10.0.2.15 | the guest (handed out by the built-in DHCP server)                 |
| 10.0.2.2  | gateway, and also the host: connecting to it reaches the host's `127.0.0.1` |
| 10.0.2.3  | DNS relay to the host's resolver (`/etc/resolv.conf`)              |

TCP, UDP and ping (ICMP echo) to the outside world go through ordinary
unprivileged host sockets. In the guest, `udhcpc -i eth0`, `dhclient` or
systemd-networkd configure the interface. The interface's MAC address is
`52:54:00:12:34:56`.

As in qemu, UDP mappings are "full cone": replies may come from any address
and port (a TFTP server answering from a new port works), and a mapping stays
open for 240 s after its last datagram. Datagrams larger than the 1500-byte
MTU reach the guest as IP fragments. Each NAT connection or UDP mapping uses
a host file descriptor, so vemu raises its soft open-file limit to 4096 (or to
the hard limit, if that is lower) and sizes its connection limits to fit.

To reach a service in the guest from the host, publish a host port with
`-p` (repeatable): vemu listens on that port and forwards each connection
(or, with `/udp`, each datagram) to the guest's port:

```
-p [HOSTADDR:]HOSTPORT:GUESTPORT[/tcp|/udp]
```

The host address defaults to `127.0.0.1`, so a forward is reachable from
this host only; write `0.0.0.0` (all interfaces) or one of the host's
addresses to open it to the network. Unlike docker, `-p 8080:80` does not
listen on all interfaces.

An ssh-style setup: forward host port 2222 to the guest's sshd and 8080 to
its web server, then connect from the host:

```sh
vemu --kernel Image --disk rootfs.img --append "root=/dev/vda rw" -p 2222:22 -p 8080:80

ssh -p 2222 root@127.0.0.1                    # the guest's sshd
curl http://127.0.0.1:8080/                   # the guest's web server
```

`-p` is a shorthand for qemu's `hostfwd` rules, which `--net user` also
takes (both may be given; they add up):

```
--net user,hostfwd=[tcp|udp]:[HOSTADDR]:HOSTPORT-[GUESTADDR]:GUESTPORT
```

As in qemu, an empty `hostfwd` host address means all interfaces
(`0.0.0.0`): `--net user,hostfwd=tcp::2222-:22` is `-p 0.0.0.0:2222:22`.
A host port forwarded twice (same protocol, overlapping addresses) is a
usage error.

To the guest, forwarded connections come from 10.0.2.2. At most 128 forwarded
TCP connections are open at once (a budget separate from the guest's own
connections); further clients wait in the host's listen backlog. If a forward
cannot be bound (for example, the port is already in use), vemu refuses to
start.
`--net none` removes the network device.

### Serial console

The guest console is a virtio-console port (`hvc0` in Linux).

- `--serial stdio` (the default) connects the console to vemu's standard input
  and output. When stdin is a terminal, vemu puts it in raw mode, so keys like
  Ctrl-C go to the guest, and restores it on exit, including on signals and
  panics. Escape keys:

  | Keys            | Effect                  |
  |-----------------|-------------------------|
  | `Ctrl-A x`      | quit vemu               |
  | `Ctrl-A h`      | help                    |
  | `Ctrl-A Ctrl-A` | send a literal Ctrl-A   |

  When stdin is a pipe or a file, its bytes reach the guest untouched, which
  makes scripting easy. Input sent before the guest console is up is kept and
  delivered once the guest opens the port. Input of any size arrives whole:
  vemu stops reading the pipe while 1 MiB is waiting for the guest.

  ```sh
  printf 'uname -a\npoweroff -f\n' | vemu --kernel Image --initrd initramfs.cpio.gz
  ```

- `--serial unix:PATH` listens on a unix socket and serves one client at a
  time. While no client is connected, output is dropped (the guest never
  waits for a client). Input is kept until the guest reads it. A socket file
  left behind by a vemu that was killed is replaced, but vemu refuses a
  socket that another running process listens on ("in use"), and anything
  that is not a socket. At exit vemu removes the socket file, unless another
  process has replaced it. If accepting a client fails, for example while
  vemu is out of file descriptors, vemu keeps retrying, so the console
  comes back. Connect with any socket client, for example:

  ```sh
  vemu --kernel Image --initrd initramfs.cpio.gz --serial unix:/tmp/vemu.sock &
  nc -U /tmp/vemu.sock          # or: socat -,raw,echo=0 UNIX-CONNECT:/tmp/vemu.sock
  ```

- `--serial none` throws output away and sends no input.

hvc0 only shows kernel messages from the point the console driver registers.
For the earliest boot messages, add the debug UART. It prints on stderr:

- aarch64 (a PL011 at 0x09000000): `--debug-uart --append "earlycon
  console=hvc0"`.
- x86_64 (a 16550 at I/O port 0x3f8): `--debug-uart --append
  "earlyprintk=serial,ttyS0,115200 console=ttyS0 console=hvc0"`. The 16550
  cannot receive, so keep `console=hvc0` last, so that the shell runs on
  hvc0.

[docs/linux-testing.md](docs/linux-testing.md), section 8, has the full
recipes for diagnosing a guest that hangs early.

## Testing

```sh
cargo test --workspace          # unit + integration tests (real VMs: HVF or KVM)
scripts/e2e.sh                  # end-to-end: boots real Linux guests
scripts/e2e.sh --release net-hostfwd-http timing-idle   # selected scenarios
scripts/e2e.sh --vemu ./vemu    # test a prebuilt binary (no cargo needed)
```

The guest matches the host. The fixtures are `testdata/{Image,
initramfs.cpio.gz,disk.img}` for aarch64 and `testdata/x86_64/{bzImage,
initramfs.cpio.gz,disk.img}` for x86_64, made by `scripts/mk-testdata.sh`
(`VEMU_ARCH=x86_64` for the second set; see the script for where the
kernel and busybox come from). `scripts/e2e.sh` builds vemu (and signs it on
macOS), makes a test initramfs from the fixtures, then runs each scenario
under `timeout` and prints PASS, FAIL or SKIP:

- **Boot and SMP:** 1, 2 and 4 vCPUs; parallel work on every CPU; CPU hotplug
  (taking CPUs offline and back online through PSCI).
- **Console:** commands piped on stdin; a `unix:` socket client; a
  pseudo-terminal in raw mode, with `Ctrl-A x`.
- **Disk:** reading the image's marker; guest writes that are checked in the
  host file, including 16 MiB checked by md5; a read-only disk that refuses
  writes.
- **Overlays:** writes to an overlay kept across two runs while the golden
  image stays unchanged; a snapshot disk that reads back its writes, leaves
  no file in `$TMPDIR` (not even while running) and shows the golden image
  again on the next run; two overlays on one golden image that do not see
  each other's writes; the refusals (the golden image read-write while an
  overlay uses it, an overlay in use, a snapshot of an overlay, a changed
  golden image, `snapshot,ro`, overwriting an overlay).
- **Network:**
  - DHCP lease 10.0.2.15; ping 10.0.2.2; DNS through 10.0.2.3.
  - A 32 MiB download from a host HTTP server, also as 4 parallel downloads,
    and a 32 MiB upload. Every transfer is checked by md5.
  - TCP hostfwd: the host fetches 32 MiB from a server in the guest, and
    drives a guest shell (ssh-style).
  - UDP hostfwd.
  - Guest to internet over HTTP. This scenario and DNS are SKIPped when the
    host is offline.
- **Timing:** `sleep 2` in the guest takes 2 s by the host's clock; an idle
  4-vCPU guest uses almost no host CPU.
- **Image builder (`vemu build`):**
  - Building a 1 GiB Alpine image with ssh, a package, two files and a
    [run] script. It must end read-only, with no `.partial` left and with
    its inode tables initialized at mkfs.
  - Booting it on a snapshot with these checks: the login prompt on hvc0,
    ssh with the test key, no failed services, the DHCP lease, DNS, a
    chrony sync, the clock within 60 s of the host's, the package, the
    file modes, the [run] marker and inittab. Poweroff then ends vemu
    with 0.
  - Two overlays of the image get different ssh host keys and random
    seeds.
  - The refusals: the wrong arch, a bad config line (with `file:line`),
    a bad value, an existing output, and a sha256 pin mismatch.

  These SKIP when the host is offline. `VEMU_E2E_BUILD_CACHE` sets the
  download cache.

Ctrl-C or SIGTERM stops the script at once, together with the VM and the
helper servers it started.

Linux-specific checks, all runnable on the Mac:

- `scripts/check-linux.sh`: cross check, clippy and test build for the Linux
  targets.
- `scripts/kvm-abi/check.sh`: compiles a C probe against the kernel's
  `<linux/kvm.h>` and `<asm/kvm.h>` (shipped with zig) for both
  architectures, and checks every KVM struct layout, ioctl number and
  constant vemu uses.
- `scripts/linux-guest-test.sh`: runs the aarch64 Linux test executables
  inside a Linux guest booted by vemu. The tests that need `/dev/kvm` skip
  themselves there.

[docs/linux-testing.md](docs/linux-testing.md) is the checklist for running
everything on real aarch64 and x86_64 Linux hosts and collecting the
results.

## Limitations

- **Hosts and guests:** macOS on Apple silicon and Linux on aarch64 or
  x86_64; the guest has the host's architecture. HVF allows one VM per
  process. The KVM aarch64 backend has only been checked at compile time
  (no aarch64 Linux host was available): see
  [docs/linux-testing.md](docs/linux-testing.md).
- **Boot:** direct kernel boot only (no UEFI or bootloader). An aarch64
  kernel must be uncompressed.
- **Reboot:** a guest reboot ends vemu (exit status 0), like QEMU's
  `-no-reboot`.
- **Devices:**
  - virtio only: no PCI, no graphics, no USB, no sound.
  - The debug UARTs (PL011, 16550) are write-only.
  - x86_64: no legacy PC devices besides what Linux needs to boot and shut
    down: no RTC/CMOS, no HPET, no keyboard. The in-kernel PIT and PIC exist;
    the timer is the TSC-deadline LAPIC timer and kvmclock.
  - x86_64: the machine is hardware-reduced ACPI, so Linux uses no legacy
    PIC and every device interrupt goes through the IOAPIC. The kernel
    options `nosmp`, `maxcpus=0`, `noapic` and `nolapic` turn that off and
    leave the guest with no device interrupts: virtio devices fail to probe
    and the hvc0 console is silent. vemu prints a warning when the command
    line has one of them. Remove the option; to run one vCPU, use
    `--cpus 1` instead (it keeps the IOAPIC).
  - virtio features not offered: EVENT_IDX, mergeable receive buffers,
    checksum/GSO offloads, multiqueue, block discard and write-zeroes, console
    resize.
- **Overlays:** no chains (the golden image of an overlay is a raw image),
  no commit back to the golden image, and no discard: a block the guest
  wrote stays in the overlay. On APFS, the host filesystem itself fills
  holes of up to ~16 MiB ahead of a file's last extent, so an overlay can
  take more space on a Mac than the blocks it holds.
- **Disk I/O:** disk requests are served synchronously on the vCPU thread
  that submitted them.
- **Network:** IPv4 only. No reassembly of IP fragments sent by the guest,
  no TCP SACK or timestamps. One guest per NAT. As with qemu's user-mode
  network, the NAT itself answers the guest's TCP keepalive probes, so
  keepalives never detect a remote host that went away, and UDP sent to a
  closed port gets no ICMP "port unreachable".
- **MMIO (aarch64):** device registers must be accessed with plain loads
  and stores, as Linux's `readl`/`writel` do. Accesses without an
  instruction syndrome (`ldp`/`stp`, writeback addressing) stop the VM with
  an error.

## Roadmap

- Running the KVM aarch64 backend on real hardware
  ([docs/linux-testing.md](docs/linux-testing.md)).
- Reboot by rebuilding the VM in place (`hv_vm_destroy` followed by a new VM
  works in the same process).
- A virtio I/O thread for block devices, and EVENT_IDX and mergeable receive
  buffers for throughput.
- virtio-rng, virtio-vsock and virtiofs.
