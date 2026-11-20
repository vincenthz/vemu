# Testing vemu on Linux/KVM hosts

A checklist for running vemu's tests on a real **aarch64** Linux host and a
real **x86_64** Linux host, and for sending the results back. Each step gives
the exact commands and the output to expect.

What has already been verified, and where:

| | aarch64 Linux/KVM | x86_64 Linux/KVM |
|---|---|---|
| builds, clippy `-D warnings` (musl + glibc targets) | yes (cross, from macOS) | yes (cross, and natively on the host) |
| KVM ABI (struct layouts, ioctl numbers) against kernel headers | yes (`scripts/kvm-abi/check.sh`) | yes |
| unit tests that need no `/dev/kvm` | yes (in an aarch64 Linux guest under vemu on macOS) | yes (on the host) |
| real-KVM backend test | **never run** | yes (Intel i7-8550U, Fedora 45, kernel 7.3) |
| `cargo test --workspace`, `scripts/e2e.sh` | **never run** | yes, 23/23, three times; 27/27 with the overlay scenarios (`disk-overlay-*`); 31/31 with the image builder (`build-*`; `timing-rtc` skips: no RTC on x86_64) |

The **aarch64 host is the important one**: none of the KVM aarch64 code
(vGIC creation, `KVM_ARM_VCPU_INIT`, in-kernel PSCI, MPIDR, `KVM_IRQ_LINE`,
kicks) has ever run. On x86_64, the open questions are an AMD CPU, other
kernels, and RAM above 3 GiB.

## 0. Host requirements

Both hosts:

- Linux with KVM: `/dev/kvm` exists. x86_64 needs VT-x or AMD-V enabled in
  the firmware, with `kvm_intel` or `kvm_amd` loaded. aarch64 needs a kernel
  with `CONFIG_KVM` that was booted at EL2: in `dmesg`, look for
  "kvm [1]: Hyp mode initialized successfully" (or "VHE mode
  initialized"). A VM without nested virtualization has no `/dev/kvm`.
- Your user can open `/dev/kvm` read-write. Usually that means membership of
  the `kvm` group: `sudo usermod -aG kvm $USER`, then log in again, and check
  with `id`. vemu needs no root, no capabilities and no network setup.
- Rust 1.90 or later (rustup), a C toolchain for linking (`cc`), `python3`,
  `curl`, `perl`, `cpio` and coreutils `timeout`. `script` (util-linux) and
  `/usr/bin/time` are optional: e2e.sh falls back to Python for both.
- Optional: `sysctl net.ipv4.ping_group_range` should include your group, as
  in Fedora's default `0 2147483647`. Without it, ping from the guest
  reaches only the gateway 10.0.2.2, which e2e's `net-ping` uses, so the
  scenario still passes.
- aarch64 only: the host must have a GICv3, or a GICv2 with KVM emulation
  (for example a Raspberry Pi 4 or 5). vemu picks a vGICv3 and falls back to
  a vGICv2, which allows at most 8 vCPUs.

## 1. Get the tree and the fixtures onto the host

The working tree has no commits yet, so copy it from the Mac (`HOST` is the
Linux machine):

```sh
# on the Mac, in the repository
rsync -a --exclude /target ./ HOST:vemu/
```

That also copies `testdata/`, which holds the kernels, initramfs images and
disk images the tests boot:

- aarch64 host: `testdata/{Image,initramfs.cpio.gz,disk.img}`
- x86_64 host: `testdata/x86_64/{bzImage,initramfs.cpio.gz,disk.img}`

To make them on the host instead:
`VEMU_KERNEL=/path/to/kernel VEMU_BUSYBOX=/path/to/static-busybox scripts/mk-testdata.sh`.
On x86_64, `VEMU_BUSYBOX` may be left out: the script then downloads
Alpine's busybox-static.

## 2. Record the host

Run this in `~/vemu` and keep `host-info.txt`:

```sh
{
  echo "== uname";      uname -a
  echo "== os";         grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
  echo "== cpu";        grep -m1 -E 'model name|^CPU part|^Hardware' /proc/cpuinfo; nproc
  grep -m1 -oE '\b(vmx|svm)\b' /proc/cpuinfo || true
  echo "== kvm";        ls -l /dev/kvm; id
  ls /sys/module | grep -E '^kvm' || echo "(kvm built in or absent)"
  for p in /sys/module/kvm*/parameters/{nx_huge_pages,ept,npt,enable_apicv,nested}; do
    [ -r "$p" ] && echo "$p=$(cat "$p")"; done
  echo "== dmesg kvm"
  k=$(dmesg 2>/dev/null || sudo -n dmesg 2>/dev/null)
  if [ -n "$k" ]; then printf '%s\n' "$k" | grep -iE 'kvm|vgic|gic|hyp mode|IPA' | tail -20
  else echo "(dmesg not readable: paste the output of 'sudo dmesg | grep -iE \"kvm|gic\"')"; fi
  echo "== sysctl";     sysctl net.ipv4.ping_group_range 2>/dev/null
  echo "== ulimit -n";  ulimit -n; ulimit -Hn
  echo "== tools";      for t in cargo rustc cc python3 curl perl cpio script timeout; do printf '%s: ' "$t"; command -v "$t" || echo MISSING; done
  rustc --version 2>/dev/null
} > host-info.txt 2>&1
```

On aarch64 the dmesg lines name the vGIC ("vgic-v3" or "vgic-v2") and the
"IPA Size Limit".

## 3. Build

```sh
cd ~/vemu
cargo build --release 2>&1 | tee build.log
./target/release/vemu --help | head -3
```

Expected: no warnings. The help text says "Boot an arm64 Linux kernel ..."
on aarch64 and "Boot an x86_64 Linux kernel ..." on x86_64.

## 4. The backend test first (fastest signal)

```sh
# aarch64
cargo test --release -p vemu-hv --lib kvm::aarch64 -- --nocapture 2>&1 | tee kvm-test.log
# x86_64
cargo test --release -p vemu-hv --lib real_kvm -- --nocapture --test-threads=1 2>&1 | tee kvm-test.log
```

Expected on aarch64: a line `vGIC: GicInfo { version: V3, dist_base:
134217728, ... }` (`V2` on a GICv2 host), then
`test kvm::aarch64::tests::real_kvm_aarch64 ... ok`, along with the pure
`kvm::aarch64::abi` tests. It boots 2 vCPUs through vGIC setup, an MMIO
write and read, PSCI CPU_ON, SYSTEM_OFF, powering a secondary vCPU on and
kicks. If it says `skipping: no usable /dev/kvm`, step 0 is not done.

Expected on x86_64: `kvm::tests::x86::real_kvm_common_layer ... ok` and
`kvm::x86_64::tests::real_kvm_long_mode_boot ... ok`.

If the test fails or hangs (it gives up on its own after about 10 s), keep
`kvm-test.log` and stop here: the rest depends on it.

## 5. All tests

```sh
cargo test --release --workspace 2>&1 | tee cargo-test.log
grep -E 'test result|FAILED|panicked|skipping' cargo-test.log
```

Expected: every `test result: ok`. On Linux, `vemu-hv/tests/{irq,mmio,psci,singlestep,smp}.rs`
are HVF-only and report 0 tests. `vemu/tests/boot.rs` boots the real guest
(4 tests, a few seconds), and on Linux it skips only without `/dev/kvm` or
fixtures. `vemu-fdt`'s `qemu_reference` compares against QEMU only on aarch64
with `qemu-system-aarch64` installed, otherwise it prints a skip message.
`vemu-net`'s internet test is `#[ignore]`d.

## 6. End-to-end

```sh
scripts/e2e.sh --release -k 2>&1 | tee e2e.log
```

Expected: 31 lines `PASS  <scenario>` and
`e2e: 31 passed, 0 failed, 0 skipped`, taking 40 to 90 s. `net-dns`,
`net-internet` and the four `build-*` scenarios SKIP when the host is
offline, which is fine. The `build-*` scenarios also need `ssh` and
`ssh-keygen`; `VEMU_E2E_BUILD_CACHE=DIR` keeps the Alpine download between
runs. With `-k`, the
last line names the kept work directory (`/tmp/vemu-e2e.XXXXXX`), which
holds every scenario's console log (`<scenario>.log`) and vemu stderr
(`<scenario>.err`). `timing-idle` reports the boot's CPU time separately:
x86_64 is about 0.7 s, because the bzImage decompresses itself; the check
is only on the idle part.

To test a binary built elsewhere, for example cross-built on the Mac
(section 9), use `scripts/e2e.sh --vemu ./vemu`. cargo is then not needed.

## 7. Manual smoke test

```sh
K=testdata/Image; [ "$(uname -m)" = x86_64 ] && K=testdata/x86_64/bzImage
I=$(dirname $K)/initramfs.cpio.gz
./target/release/vemu --kernel $K --initrd $I --cpus 4 --memory 1G
#   in the guest:  cat /proc/cpuinfo | grep -c processor   -> 4
#                  cat /proc/interrupts                    (virtio, timer)
#                  poweroff -f                             -> vemu exits 0
#   or Ctrl-A x to quit
```

On x86_64 also try `reboot -f`: vemu should print "guest requested a reset;
exiting" and exit 0.

## 8. Diagnosing early-boot hangs: `--debug-uart` earlycon recipes

The guest console (hvc0) only starts late in the boot. For everything
before that, add the debug UART: its output goes to vemu's **stderr**, so
redirect it to a file. Use `--cpus 1` first, to rule out SMP bring-up.

aarch64 (write-only PL011 at 0x0900_0000):

```sh
./target/release/vemu --kernel testdata/Image --initrd testdata/initramfs.cpio.gz \
  --cpus 1 --net none --debug-uart \
  --append "earlycon=pl011,mmio32,0x09000000 console=hvc0 loglevel=8" 2> uart.log
```

A bare `earlycon` also works (the device tree's `stdout-path` names the
UART). The first line in `uart.log` should be
`Booting Linux on physical CPU 0x0000000000`.

x86_64 (transmit-only 16550 at I/O port 0x3f8, IRQ 4):

```sh
./target/release/vemu --kernel testdata/x86_64/bzImage --initrd testdata/x86_64/initramfs.cpio.gz \
  --cpus 1 --net none --debug-uart \
  --append "earlyprintk=serial,ttyS0,115200 console=ttyS0 console=hvc0 loglevel=8" 2> uart.log
```

`earlyprintk` starts in the kernel's decompressor: the first lines are
"early console in extract_kernel". `earlycon=uart8250,io,0x3f8,115200`
starts later, in `setup_arch`. Keep `console=hvc0` last: the 16550 cannot
receive, so the shell has to be on hvc0.

A guest that hangs after its last line is usually a hypervisor problem. Run
it again under `timeout 60` and keep `uart.log`, vemu's other stderr lines
(they start with `vemu:`) and the host's `sudo dmesg | tail -50`.

## 9. Without Rust on the host: cross-build on the Mac

On the Mac (`brew install zig`, and
`rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl`):

```sh
T=aarch64-unknown-linux-musl          # or x86_64-unknown-linux-musl
cargo build --release --target $T -p vemu
# test executables (their paths):
cargo test --release --target $T --workspace --no-run --message-format=json \
  | python3 -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
        print(m["target"]["name"], m["executable"])'
```

Copy `target/$T/release/vemu`, the test executables, `scripts/` and
`testdata/` to the host, then run each test executable there with
`--test-threads=1`. The boot tests need
`VEMU_TEST_BIN=$PWD/vemu VEMU_TESTDATA=$PWD/testdata`, because their
compiled-in paths are the Mac's. Run e2e with `scripts/e2e.sh --vemu ./vemu`.
The binaries are static, so they run on any Linux of that architecture.

## 10. What to send back

```sh
W=$(sed -n 's/^e2e: work directory kept: //p' e2e.log)
mkdir -p results/e2e-work
cp host-info.txt build.log kvm-test.log cargo-test.log e2e.log uart.log results/ 2>/dev/null
[ -n "$W" ] && cp "$W"/*.log "$W"/*.err results/e2e-work/ 2>/dev/null
tar czf vemu-results-$(uname -m).tgz results && ls -l vemu-results-*.tgz
```

The archive holds only text logs: the work directory's disk images and
32 MiB transfer files are left out.

Include any `uart.log` from section 8 and a note about anything that looked
wrong, even when the tests passed: slow boots, odd `vemu:` lines on stderr,
or kernel warnings.
