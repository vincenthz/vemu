#!/usr/bin/env bash
# Run the Linux builds of the host-independent crates' tests inside a Linux
# guest booted by vemu, so their Linux code paths (sockets, ICMP, flock,
# fdatasync, rlimits...) run on a Mac with no Linux machine at hand.
#
# usage: scripts/linux-guest-test.sh [-k|--keep] [-i|--ignored] [CRATE...]
#
#   CRATE          crates whose test executables to run (default: vemu-core
#                  vemu-fdt vemu-virtio vemu-net vemu-hv vemu; the KVM and
#                  boot tests skip themselves, the guest has no /dev/kvm)
#   -k, --keep     keep the work directory (initramfs, console log)
#   -i, --ignored  also run #[ignore]d tests (they need Internet access,
#                  which the guest reaches through vemu's NAT)
#
# Steps: cargo test --no-run for aarch64-unknown-linux-musl (linked by zig,
# see .cargo/config.toml); pack the test executables into a busybox
# initramfs at /tests (scripts/mkinitramfs.py, guest side in
# scripts/linux-guest/guest.sh); boot it with the host's vemu (2 vCPUs,
# 1 GiB, --net user so the NAT's loopback tests have a network) under
# timeout; report PASS/FAIL per test executable from the guest console.
# Tests needing what the guest lacks (Internet, /dev/kvm, qemu, dtc) skip
# themselves or are #[ignore]d.
#
# Environment: VEMU_BIN (vemu to boot with; default: build target/release/vemu),
# VEMU_BUSYBOX (static aarch64 busybox; default: the one in
# testdata/initramfs.cpio.gz), VEMU_KERNEL (default: testdata/Image),
# VEMU_GUEST_TIMEOUT (seconds, default 120, at most 120).
#
# Needs an aarch64 host (the guest runs at native speed; no emulation).

set -u
set -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=aarch64-unknown-linux-musl
KEEP=0
IGNORED=""
CRATES=()
while [ $# -gt 0 ]; do
  case $1 in
    -k | --keep) KEEP=1 ;;
    -i | --ignored) IGNORED=" vemu.ignored=1" ;;
    -h | --help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "linux-guest-test: unknown option $1" >&2; exit 2 ;;
    *) CRATES+=("$1") ;;
  esac
  shift
done
[ ${#CRATES[@]} -gt 0 ] || CRATES=(vemu-core vemu-fdt vemu-virtio vemu-net vemu-hv vemu)

say() { printf 'linux-guest-test: %s\n' "$*"; }
die() { say "$*" >&2; exit 1; }

case "$(uname -m)" in
  arm64 | aarch64) ;;
  *) die "needs an aarch64 host (the guest is aarch64 Linux)" ;;
esac
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || die "needs timeout(1) (coreutils)"
VM_TIMEOUT="${VEMU_GUEST_TIMEOUT:-120}"
[ "$VM_TIMEOUT" -le 120 ] 2> /dev/null || VM_TIMEOUT=120
command -v python3 > /dev/null || die "needs python3"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vemu-linux-guest.XXXXXX")"
VM_PID=""
cleanup() {
  [ -n "$VM_PID" ] && kill "$VM_PID" 2> /dev/null
  if [ "$KEEP" = 1 ]; then say "work directory kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# ------------------------------------------------------------ the VMM ----

VEMU="${VEMU_BIN:-}"
if [ -z "$VEMU" ]; then
  say "building vemu (release)"
  (cd "$ROOT" && cargo build -q --release -p vemu) || die "cannot build vemu (set VEMU_BIN to use another binary)"
  VEMU="$ROOT/target/release/vemu"
  if [ "$(uname -s)" = Darwin ]; then
    codesign -f -s - --entitlements "$ROOT/vemu.entitlements" "$VEMU" 2> /dev/null || die "codesign failed"
  fi
fi
[ -x "$VEMU" ] || die "no vemu binary at $VEMU"

KERNEL="${VEMU_KERNEL:-$ROOT/testdata/Image}"
if [ -z "${VEMU_KERNEL:-}" ] && { [ ! -f "$KERNEL" ] || [ ! -f "$ROOT/testdata/initramfs.cpio.gz" ]; }; then
  say "testdata incomplete; running scripts/mk-testdata.sh"
  VEMU_ARCH=aarch64 "$ROOT/scripts/mk-testdata.sh" > /dev/null || die "cannot build testdata"
fi
[ -f "$KERNEL" ] || die "no kernel at $KERNEL"

BUSYBOX="${VEMU_BUSYBOX:-}"
if [ -z "$BUSYBOX" ]; then
  mkdir -p "$WORK/bb"
  (cd "$WORK/bb" && gzip -dc "$ROOT/testdata/initramfs.cpio.gz" | cpio -id --quiet bin/busybox 2> /dev/null)
  BUSYBOX="$WORK/bb/bin/busybox"
fi
[ -s "$BUSYBOX" ] || die "no busybox (set VEMU_BUSYBOX)"

# ------------------------------------------------------ test binaries ----

say "building test executables for $TARGET: ${CRATES[*]}"
pkg_args=()
for c in "${CRATES[@]}"; do pkg_args+=(-p "$c"); done
(cd "$ROOT" && cargo test -q --no-run --message-format=json --target "$TARGET" "${pkg_args[@]}") \
  > "$WORK/build.json" 2> "$WORK/build.err" || {
  cat "$WORK/build.err" >&2
  die "cargo test --no-run failed"
}
# One "NAME=PATH" per test executable; NAME is crate.target (crate.lib for
# unit tests), which is also the file name in the guest's /tests.
python3 -I - "$WORK/build.json" > "$WORK/tests.list" << 'PY' || die "cannot read cargo's output"
import json, os, sys
for line in open(sys.argv[1]):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact" or not m.get("executable") or not m["profile"]["test"]:
        continue
    crate = os.path.basename(os.path.dirname(m["manifest_path"]))
    kind = m["target"]["kind"]
    name = "lib" if "lib" in kind else m["target"]["name"]
    print(f"{crate}.{name}={m['executable']}")
PY
[ -s "$WORK/tests.list" ] || die "no test executables found"
EXPECTED=()
files=()
while IFS== read -r name path; do
  EXPECTED+=("$name")
  files+=("tests/$name=$path")
done < "$WORK/tests.list"
say "${#EXPECTED[@]} test executables: ${EXPECTED[*]}"

INITRD="$WORK/tests.cpio.gz"
VEMU_TEST_SCRIPT="$ROOT/scripts/linux-guest/guest.sh" \
  python3 -I "$ROOT/scripts/mkinitramfs.py" "$BUSYBOX" "$INITRD" "${files[@]}" ||
  die "cannot build the test initramfs"

# ---------------------------------------------------------------- run ----

say "booting the guest (2 vCPUs, 1 GiB, timeout ${VM_TIMEOUT}s)"
CONSOLE="$WORK/console.log"
START=$SECONDS
# In the background so Ctrl-C and SIGTERM reach the trap while it runs.
"$TIMEOUT_BIN" "$VM_TIMEOUT" "$VEMU" --kernel "$KERNEL" --initrd "$INITRD" \
  --cpus 2 --memory 1G --net user --append "quiet console=hvc0 vemu.test=1$IGNORED" \
  < /dev/null > "$WORK/console.raw" 2> "$WORK/vemu.err" &
VM_PID=$!
wait "$VM_PID"
RC=$?
VM_PID=""
tr -d '\r' < "$WORK/console.raw" > "$CONSOLE"
say "guest finished in $((SECONDS - START)) s (vemu status $RC)"
if [ "$RC" != 0 ]; then
  [ "$RC" = 124 ] && say "the guest timed out"
  [ -s "$WORK/vemu.err" ] && sed 's/^/  vemu: /' "$WORK/vemu.err" | tail -n 20
fi

# --------------------------------------------------------------- report ----

python3 -I - "$CONSOLE" "${EXPECTED[@]}" << 'PY'
import re, sys
log, expected = sys.argv[1], sys.argv[2:]
sections, cur, out = {}, None, []
for line in open(log, errors="replace"):
    line = line.rstrip("\n")
    m = re.match(r"vemu-test: begin (\S+)$", line)
    if m:
        cur, out = m.group(1), []
        sections[cur] = {"rc": None, "out": out}
        continue
    m = re.match(r"vemu-test: end (\S+) rc=(\d+)$", line)
    if m and m.group(1) in sections:
        sections[m.group(1)]["rc"] = int(m.group(2))
        cur = None
        continue
    if cur:
        out.append(line)
failed = 0
for name in expected:
    s = sections.get(name)
    counts = ""
    if s:
        res = [l for l in s["out"] if l.startswith("test result:")]
        if res:
            nums = re.findall(r"(\d+) (passed|failed|ignored)", " ".join(res))
            tot = {}
            for n, k in nums:
                tot[k] = tot.get(k, 0) + int(n)
            counts = "  (" + ", ".join(f"{tot.get(k, 0)} {k}" for k in ("passed", "failed", "ignored")) + ")"
    if s and s["rc"] == 0:
        print(f"PASS  {name}{counts}")
        continue
    failed += 1
    why = "did not run" if not s else "no exit status (crashed or timed out)" if s["rc"] is None else f"exit status {s['rc']}"
    print(f"FAIL  {name}  {why}{counts}")
    if s:
        keep = [l for l in s["out"] if not re.match(r"test .* \.\.\. ok$", l)]
        for l in keep[-40:]:
            print(f"      {l}")
done = any(l.startswith("vemu-test: all done") for l in open(log, errors="replace"))
if not done:
    print("linux-guest-test: the guest did not finish the run; console tail:")
    for l in open(log, errors="replace").read().splitlines()[-15:]:
        print(f"      {l}")
print(f"\nlinux-guest-test: {len(expected) - failed} passed, {failed} failed")
sys.exit(1 if failed or not done else 0)
PY
