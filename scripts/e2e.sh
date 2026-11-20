#!/usr/bin/env bash
# End-to-end tests: boot real Linux guests with vemu and check the console,
# disks, network and timers from both sides.
#
# usage: scripts/e2e.sh [-r|--release] [-k|--keep] [--vemu PATH] [SCENARIO...]
#
#   -r, --release   test a release build (default: debug)
#   -k, --keep      keep the work directory (logs, images) afterwards
#   --vemu PATH     test this prebuilt vemu binary; nothing is built, so cargo
#                   is not needed (on macOS PATH must already be signed with
#                   vemu.entitlements)
#   SCENARIO        run only the named scenarios (default: all; -l lists them)
#
# Every VM runs under `timeout`. Each scenario prints PASS, FAIL or SKIP
# (SKIP only for reasons outside vemu, such as no internet access on the
# host); the script exits non-zero if any scenario failed.
#
# Environment: VEMU_E2E_TIMEOUT (seconds per VM, default 60), plus
# VEMU_KERNEL / VEMU_BUSYBOX, used by scripts/mk-testdata.sh when testdata/
# is incomplete. The build-* scenarios (vemu build) need internet access
# (they SKIP without it), ssh and ssh-keygen; VEMU_E2E_BUILD_CACHE is the
# builder's download cache (default: vemu's own), VEMU_E2E_BUILD_TIMEOUT
# the build's time limit (default 600 s).
#
# Hosts: macOS on Apple silicon (HVF; the binary is ad-hoc signed first) and
# Linux on aarch64 or x86_64 (KVM; needs access to /dev/kvm). The guest
# matches the host: testdata/{Image,initramfs.cpio.gz,disk.img} on aarch64,
# testdata/x86_64/{bzImage,initramfs.cpio.gz,disk.img} on x86_64
# (VEMU_ARCH=x86_64 scripts/mk-testdata.sh).

set -u
set -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E="$ROOT/scripts/e2e"
HOST_OS="$(uname -s)"
case "$(uname -m)" in
  arm64 | aarch64) GUEST_ARCH=aarch64 TD="$ROOT/testdata" KERNEL_NAME=Image ;;
  x86_64 | amd64) GUEST_ARCH=x86_64 TD="$ROOT/testdata/x86_64" KERNEL_NAME=bzImage ;;
  *) echo "e2e: unsupported host architecture $(uname -m)" >&2; exit 2 ;;
esac
VM_TIMEOUT="${VEMU_E2E_TIMEOUT:-60}"
BIG_MIB=32  # size of the bulk network transfers
PROFILE=debug
KEEP=0
PREBUILT=""
ONLY=()

ALL_SCENARIOS=(
  boot-cpus1 boot-cpus2 boot-cpus4 smp-workers smp-hotplug
  console-stdin console-unix console-tty
  disk-read disk-write disk-ro
  disk-overlay-persist disk-overlay-snapshot disk-overlay-shared-base disk-overlay-refusals
  net-dhcp net-ping net-dns net-http-get net-http-parallel net-http-post
  net-hostfwd-http net-hostfwd-shell net-hostfwd-udp net-internet
  timing-sleep timing-idle timing-rtc
  build-image build-boot build-hostkeys build-refusals
)

while [ $# -gt 0 ]; do
  case $1 in
    -r | --release) PROFILE=release ;;
    -k | --keep) KEEP=1 ;;
    --vemu)
      [ $# -ge 2 ] || { echo "e2e: --vemu needs a path" >&2; exit 2; }
      PREBUILT="$2"; shift ;;
    --vemu=*) PREBUILT="${1#--vemu=}" ;;
    -l | --list) printf '%s\n' "${ALL_SCENARIOS[@]}"; exit 0 ;;
    -h | --help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "e2e: unknown option $1" >&2; exit 2 ;;
    *) ONLY+=("$1") ;;
  esac
  shift
done
for s in ${ONLY[@]+"${ONLY[@]}"}; do
  case " ${ALL_SCENARIOS[*]} " in *" $s "*) ;; *) echo "e2e: unknown scenario $s" >&2; exit 2 ;; esac
done

TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "e2e: needs timeout(1) (coreutils)" >&2; exit 2; }
# script(1) is optional: in_pty falls back to python3's pty module.
tools=(python3 curl perl cpio)
[ "$HOST_OS" = Darwin ] && [ -z "$PREBUILT" ] && tools+=(codesign)
[ -z "$PREBUILT" ] && tools+=(cargo)
for tool in "${tools[@]}"; do
  command -v "$tool" > /dev/null || { echo "e2e: needs $tool" >&2; exit 2; }
done
if [ "$HOST_OS" = Linux ] && { [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; }; then
  echo "e2e: needs read-write access to /dev/kvm" >&2
  exit 2
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vemu-e2e.XXXXXX")"
# Every VM runs as $WORK/bin/vemu and every helper server gets a $WORK path
# argument, so cleanup can find them all by command line: `timeout` moves
# itself and vemu into their own process group, out of reach of the
# terminal's Ctrl-C and of the subshell pids in $BG_PIDS.
BG_PIDS=()
# Signal $1 to (or with -0, only look for) every process whose command line
# names $WORK; succeeds if there was one.
kill_ours() {
  local pat
  pat="$(printf '%s' "$WORK/" | sed 's/[][\.*^$+?(){}|]/\\&/g')"
  if [ "$1" = -0 ]; then
    pgrep -U "$(id -u)" -f -- "$pat" > /dev/null
  else
    pkill "$1" -U "$(id -u)" -f -- "$pat" 2> /dev/null
  fi
}
cleanup() {
  trap '' INT TERM HUP
  for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do kill "$p" 2> /dev/null; done
  if kill_ours -TERM; then
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do kill_ours -0 || break; sleep 0.2; done
    kill_ours -KILL
  fi
  for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do wait "$p" 2> /dev/null; done
  if [ "$KEEP" = 1 ]; then echo "e2e: work directory kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

say() { printf 'e2e: %s\n' "$*"; }

# ---------------------------------------------------------------- setup ----

if [ -n "$PREBUILT" ]; then
  [ -x "$PREBUILT" ] || { say "--vemu $PREBUILT: not an executable file"; exit 2; }
  VEMU="$(cd "$(dirname "$PREBUILT")" && pwd)/$(basename "$PREBUILT")"
  say "testing prebuilt $VEMU"
else
  say "building vemu ($PROFILE)"
  build_flags=(-p vemu)
  [ "$PROFILE" = release ] && build_flags+=(--release)
  (cd "$ROOT" && cargo build -q "${build_flags[@]}") || { say "build failed"; exit 1; }
  VEMU="$ROOT/target/$PROFILE/vemu"
  # Hypervisor.framework needs the entitlement; KVM needs nothing like it.
  if [ "$HOST_OS" = Darwin ]; then
    codesign -f -s - --entitlements "$ROOT/vemu.entitlements" "$VEMU" 2> /dev/null ||
      { say "codesign failed"; exit 1; }
  fi
fi
mkdir -p "$WORK/bin"
ln -s "$VEMU" "$WORK/bin/vemu"
VEMU="$WORK/bin/vemu"

if [ ! -f "$TD/$KERNEL_NAME" ] || [ ! -f "$TD/initramfs.cpio.gz" ] || [ ! -f "$TD/disk.img" ]; then
  say "testdata incomplete; running scripts/mk-testdata.sh"
  VEMU_ARCH="$GUEST_ARCH" "$ROOT/scripts/mk-testdata.sh" > /dev/null || { say "cannot build testdata"; exit 1; }
fi
KERNEL="$TD/$KERNEL_NAME"

# The e2e initramfs: the test fixture's busybox plus scripts/e2e/guest.sh as
# /etc/vemu-test.sh.
BUSYBOX="${VEMU_BUSYBOX:-}"
if [ -z "$BUSYBOX" ]; then
  mkdir -p "$WORK/bb"
  (cd "$WORK/bb" && gzip -dc "$TD/initramfs.cpio.gz" | cpio -id --quiet bin/busybox 2> /dev/null)
  BUSYBOX="$WORK/bb/bin/busybox"
fi
[ -s "$BUSYBOX" ] || { say "no busybox (set VEMU_BUSYBOX)"; exit 1; }
INITRD="$WORK/e2e.cpio.gz"
VEMU_TEST_SCRIPT="$E2E/guest.sh" python3 -I "$ROOT/scripts/mkinitramfs.py" "$BUSYBOX" "$INITRD" ||
  { say "cannot build the e2e initramfs"; exit 1; }

# ------------------------------------------------------------- helpers ----

PASSED=() FAILED=() SKIPPED=()
CUR=""      # current scenario
LOG=""      # its guest console log
ERR=""      # its vemu stderr
RC=0        # vemu exit status
REASON=""   # first failed check
NOTE=""     # extra detail shown after PASS
SKIPPED_CUR=0

begin() {
  CUR=$1
  LOG="$WORK/$CUR.log"
  ERR="$WORK/$CUR.err"
  REASON=""
  NOTE=""
  SKIPPED_CUR=0
  : > "$LOG"
  : > "$ERR"
}

# Record a failed check (the first one is the reason shown).
fail() { [ -n "$REASON" ] || REASON="$*"; }

finish() {
  if [ -z "$REASON" ]; then
    PASSED+=("$CUR")
    printf 'PASS  %s%s\n' "$CUR" "${1:+  ($1)}"
  else
    FAILED+=("$CUR")
    printf 'FAIL  %s  %s\n' "$CUR" "$REASON"
    for f in "$LOG" "$ERR"; do
      [ -s "$f" ] && { echo "      --- ${f##*/} (last 15 lines)"; tail -n 15 "$f" | sed 's/^/      /'; }
    done
  fi
}

skip() {
  SKIPPED_CUR=1
  SKIPPED+=("$CUR")
  printf 'SKIP  %s  %s\n' "$CUR" "$*"
}

# vemu under timeout with the test kernel and $VM_INITRD (default: the e2e
# initramfs); arguments are passed through. The guest console's \r\n line
# endings become \n.
VM_INITRD=""
vemu() {
  "$TIMEOUT_BIN" "$VM_TIMEOUT" "$VEMU" --kernel "$KERNEL" --initrd "${VM_INITRD:-$INITRD}" "$@"
}
crlf() { tr -d '\r'; }

# Run "$@" in the background and wait for it, status in $RC. bash defers
# signal traps until a foreground command ends, but interrupts `wait`, so
# this keeps Ctrl-C and SIGTERM effective while a VM runs.
run_bg() {
  "$@" &
  VM_PID=$!
  BG_PIDS+=("$VM_PID")
  wait "$VM_PID"
  RC=$?
}

# Run a VM to completion, console to $LOG, stderr to $ERR, status in $RC.
run_vm() {
  start_vm "$@"
  wait_vm
}

# Start a VM in the background; its pid is in $VM_PID. The console goes to
# $LOG.raw, which wait_for and wait_vm turn into $LOG.
start_vm() {
  : > "$LOG.raw"
  vemu "$@" < /dev/null > "$LOG.raw" 2> "$ERR" &
  VM_PID=$!
  BG_PIDS+=("$VM_PID")
}

# Wait for the background VM and set $RC.
wait_vm() {
  wait "$VM_PID"
  RC=$?
  crlf < "$LOG.raw" > "$LOG"
}

# Wait until $LOG matches the extended regex $1 (up to $2 seconds, default
# the VM timeout).
wait_for() {
  local deadline=$((SECONDS + ${2:-$VM_TIMEOUT}))
  while [ $SECONDS -lt $deadline ]; do
    crlf < "$LOG.raw" > "$LOG"
    grep -Eq -- "$1" "$LOG" && return 0
    sleep 0.1
  done
  return 1
}

# Checks on the scenario's output.
expect() { grep -Eq -- "$1" "$LOG" || fail "missing output: $1"; }
expect_rc() { [ "$RC" = "${1:-0}" ] || fail "vemu exited with $RC (expected ${1:-0})"; }
expect_quiet() { [ -s "$ERR" ] && fail "unexpected vemu stderr: $(head -n 1 "$ERR")"; return 0; }
expect_done() { expect '^vemu-init: done'; expect_rc 0; }
# The value of "e2e: $1<value>" in the log (first match, rest of the line).
field() { sed -n "s/^e2e: $1//p" "$LOG" | head -n 1 | tr -d '\r'; }

# Run "$@" in a pseudo-terminal, with its exit status: BSD script(1) takes
# the command as arguments, util-linux's as one -c string (and needs -e to
# pass the status on). Without script(1), python3's pty module does the same
# (stdin copied to the terminal, the terminal's output to stdout).
in_pty() {
  if ! command -v script > /dev/null; then
    python3 -I -c '
import os, pty, sys
sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' "$@"
  elif script -V 2>&1 | grep -q util-linux; then
    script -q -e -c "$(printf '%q ' "$@")" /dev/null
  else
    script -q /dev/null "$@"
  fi
}

# Run "$@" and append its CPU time (itself and the children it waited for)
# to stderr as POSIX `time -p` lines ("user S", "sys S"). /usr/bin/time is
# not installed everywhere on Linux.
cpu_time() {
  if [ -x /usr/bin/time ]; then
    /usr/bin/time -p "$@"
  else
    python3 -I -c '
import os, subprocess, sys
r = subprocess.run(sys.argv[1:]).returncode
u = os.times()
print(f"user {u.children_user:.2f}\nsys {u.children_system:.2f}", file=sys.stderr)
sys.exit(r if r >= 0 else 128 - r)' "$@"
  fi
}

md5_of() { python3 -I -c 'import hashlib,sys; print(hashlib.md5(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
# Bytes [$2, $2+$3) of file $1.
slice() { python3 -I -c 'import sys; f=open(sys.argv[1],"rb"); f.seek(int(sys.argv[2])); sys.stdout.buffer.write(f.read(int(sys.argv[3])))' "$@"; }
host_online() { curl -s -m 5 -o /dev/null "http://$1/"; }

HTTPD_PORT=""
start_httpd() {
  [ -n "$HTTPD_PORT" ] && return 0
  mkdir -p "$WORK/www"
  head -c $((BIG_MIB << 20)) /dev/urandom > "$WORK/www/big.bin"
  python3 -I "$E2E/httpd.py" "$WORK/www" "$WORK/httpd.port" &
  BG_PIDS+=($!)
  local i
  for i in $(seq 50); do [ -s "$WORK/httpd.port" ] && break; sleep 0.1; done
  HTTPD_PORT="$(cat "$WORK/httpd.port" 2> /dev/null)"
  [ -n "$HTTPD_PORT" ]
}

fresh_disk() { cp "$TD/disk.img" "$WORK/$1"; echo "$WORK/$1"; }
# md5 of the $3 bytes at offset $2 of file $1.
slice_md5() { python3 -I -c 'import hashlib,sys; f=open(sys.argv[1],"rb"); f.seek(int(sys.argv[2])); print(hashlib.md5(f.read(int(sys.argv[3]))).hexdigest())' "$@"; }
# md5 of a sector holding the string $1, zero-padded (what dd conv=sync writes).
marker_md5() { python3 -I -c 'import hashlib,sys; b=sys.argv[1].encode(); print(hashlib.md5(b+bytes(512-len(b))).hexdigest())' "$1"; }
# vemu overlay create BASE OVERLAY, output in $WORK/$CUR.create.
overlay_create() {
  "$TIMEOUT_BIN" 30 "$VEMU" overlay create "$@" > "$WORK/$CUR.create" 2>&1 ||
    { fail "overlay create $*: $(tail -n 1 "$WORK/$CUR.create")"; return 1; }
}

# ----------------------------------------------------------- scenarios ----

boot_cpus() {
  local n=$1
  # The stock test initramfs, default (user) networking. loglevel=4 keeps
  # kernel warnings but stops info messages (the x86 test kernel's stack
  # depth reports) from landing in the middle of init's lines.
  VM_INITRD="$TD/initramfs.cpio.gz" run_vm --cpus "$n" --disk "$TD/disk.img,ro" \
    --append "console=hvc0 loglevel=4 vemu.test=1"
  expect "^vemu-init: up .* cpus=$n\$"
  expect '^vemu-init: eth0 10\.0\.2\.15/24'
  expect '^vemu-init: disk /dev/vda 131072 sectors'
  expect_done
  expect_quiet
}
t_boot-cpus1() { boot_cpus 1; }
t_boot-cpus2() { boot_cpus 2; }
t_boot-cpus4() { boot_cpus 4; }

t_smp-workers() {
  local zeros
  zeros=$(head -c $((64 << 20)) /dev/zero | md5 -q 2> /dev/null || python3 -I -c 'import hashlib; print(hashlib.md5(bytes(64<<20)).hexdigest())')
  run_vm --cpus 4 --net none --append "quiet vemu.test=1 e2e.scenario=smp"
  local got; got=$(field 'smp ')
  [ "$got" = "$zeros " ] || fail "4 parallel md5 workers gave '$got', expected '$zeros'"
  expect_done
}

t_smp-hotplug() {
  run_vm --cpus 4 --net none --append "quiet vemu.test=1 e2e.scenario=hotplug"
  expect '^e2e: hotplug rounds ok=3 online=0-3$'
  expect_done
  expect_quiet
}

t_console-stdin() {
  piped() {
    printf 'echo $((6*7))-piped\nhead -c 16 /dev/vda; echo\npoweroff -f\n' |
      vemu --net none --disk "$TD/disk.img,ro" --append "quiet vemu.test=1 vemu.run=sh" 2> "$ERR" | crlf > "$LOG"
    return "${PIPESTATUS[1]}"
  }
  run_bg piped
  expect '42-piped'
  expect 'VEMU-DISK-MARKER'
  expect_rc 0
}

t_console-unix() {
  local sock="$WORK/console.sock"
  start_vm --net none --serial "unix:$sock" --append "quiet vemu.test=1 vemu.run=sh"
  python3 -I "$E2E/client.py" unix "$sock" 'echo $((6*7))-unix\npoweroff -f\n' '42-unix' 30 > "$WORK/$CUR.client" ||
    fail "client did not see the command's output"
  wait_vm
  expect_rc 0
  [ -e "$sock" ] && fail "socket file left behind"
  crlf < "$WORK/$CUR.client" > "$LOG"
}

t_console-tty() {
  # In a pseudo-terminal (script(1)): raw mode, a typed command runs in the
  # guest shell, then Ctrl-A x quits vemu (the shell would wait forever).
  local start=$SECONDS
  typed() {
    (sleep 1; printf 'echo $((6*7))-tty\r'; sleep 1; printf '\001x') |
      in_pty "$TIMEOUT_BIN" "$VM_TIMEOUT" "$VEMU" --kernel "$KERNEL" --initrd "$INITRD" \
        --net none --append "quiet vemu.test=1 vemu.run=sh" 2> "$ERR" | crlf > "$LOG"
    return "${PIPESTATUS[1]}"
  }
  run_bg typed
  expect '^42-tty'
  expect_rc 0
  [ $((SECONDS - start)) -lt 15 ] || fail "Ctrl-A x did not quit (took $((SECONDS - start)) s)"
}

t_disk-read() {
  run_vm --net none --disk "$(fresh_disk read.img),ro" --append "quiet vemu.test=1 e2e.scenario=disk-read"
  expect '^e2e: marker VEMU-DISK-MARKER'
  expect_done
}

t_disk-write() {
  local img marker
  img=$(fresh_disk write.img)
  marker="VEMU-E2E-$$-$RANDOM"
  run_vm --net none --disk "$img" --append "quiet vemu.test=1 e2e.scenario=disk-write e2e.marker=$marker"
  expect_done
  expect '^e2e: marker written'
  [ "$(slice "$img" $((2048 * 512)) ${#marker})" = "$marker" ] || fail "marker not found in the host image"
  local wrote back host
  wrote=$(field 'bulk written md5=')
  back=$(field 'bulk readback md5=')
  slice "$img" $((8 << 20)) $((16 << 20)) > "$WORK/bulk.bin"
  host=$(md5_of "$WORK/bulk.bin")
  [ -n "$wrote" ] && [ "$wrote" = "$host" ] || fail "16 MiB written by the guest ($wrote) differs on the host ($host)"
  [ "$back" = "$wrote" ] || fail "guest read back $back, wrote $wrote"
}

t_disk-ro() {
  local img before
  img=$(fresh_disk ro.img)
  before=$(md5_of "$img")
  run_vm --net none --disk "$img,ro" --append "quiet vemu.test=1 e2e.scenario=disk-ro"
  expect '^e2e: ro=1 write=rejected'
  expect_done
  [ "$(md5_of "$img")" = "$before" ] || fail "read-only image was modified"
}

t_disk-overlay-persist() {
  # A golden image, an overlay on it, and two boots ("reboot" = a new vemu
  # on the same overlay): the second sees what the first wrote.
  local golden ov before marker wrote
  golden=$(fresh_disk golden-persist.img)
  before=$(md5_of "$golden")
  ov="$WORK/persist.vov"
  overlay_create "$golden" "$ov" || return
  marker="VEMU-OVL-$$-$RANDOM"
  run_vm --net none --disk "$ov" --append "quiet vemu.test=1 e2e.scenario=disk-write e2e.marker=$marker"
  expect_done
  expect_quiet
  expect '^e2e: marker written'
  wrote=$(field 'bulk written md5=')
  [ -n "$wrote" ] && [ "$(field 'bulk readback md5=')" = "$wrote" ] ||
    fail "first boot read back $(field 'bulk readback md5='), wrote $wrote"
  cp "$LOG" "$WORK/$CUR.boot1.log"
  run_vm --net none --disk "$ov" --append "quiet vemu.test=1 e2e.scenario=disk-show"
  expect_done
  expect_quiet
  expect '^e2e: head VEMU-DISK-MARKER'
  [ "$(field 'sector md5=')" = "$(marker_md5 "$marker")" ] ||
    fail "second boot: sector 2048 has md5 $(field 'sector md5='), not the marker's"
  [ "$(field 'bulk md5=')" = "$wrote" ] ||
    fail "second boot: 16 MiB at 8 MiB have md5 $(field 'bulk md5='), the first boot wrote $wrote"
  [ "$(md5_of "$golden")" = "$before" ] || fail "the golden image changed"
  "$TIMEOUT_BIN" 30 "$VEMU" overlay info "$ov" > "$WORK/$CUR.info" 2>&1 || fail "overlay info exited with $?"
  grep -q '^golden status:  ok' "$WORK/$CUR.info" || fail "overlay info: $(grep '^golden status' "$WORK/$CUR.info")"
  NOTE="overlay: $(sed -n 's/^allocated: *//p' "$WORK/$CUR.info")"
}

t_disk-overlay-snapshot() {
  # --disk golden,snapshot: the guest writes, and reads its writes back;
  # the snapshot file is unlinked while vemu runs, and a fresh run sees
  # the golden image again.
  local golden before snapdir marker wrote left
  golden=$(fresh_disk golden-snap.img)
  before=$(md5_of "$golden")
  snapdir="$WORK/snaptmp"
  mkdir -p "$snapdir"
  marker="VEMU-SNAP-$$-$RANDOM"
  TMPDIR="$snapdir" start_vm --net none --disk "$golden,snapshot" \
    --append "quiet vemu.test=1 e2e.scenario=disk-write e2e.marker=$marker"
  if wait_for '^e2e: marker written'; then
    left=$(ls -A "$snapdir")
    [ -z "$left" ] || fail "snapshot file visible in TMPDIR while vemu runs: $left"
  else
    fail "the guest did not write its marker"
  fi
  wait_vm
  expect_done
  expect_quiet
  wrote=$(field 'bulk written md5=')
  [ -n "$wrote" ] && [ "$(field 'bulk readback md5=')" = "$wrote" ] ||
    fail "snapshot disk read back $(field 'bulk readback md5='), wrote $wrote"
  [ -z "$(ls -A "$snapdir")" ] || fail "file left in TMPDIR: $(ls -A "$snapdir")"
  [ "$(md5_of "$golden")" = "$before" ] || fail "the golden image changed"
  TMPDIR="$snapdir" run_vm --net none --disk "$golden,snapshot" --append "quiet vemu.test=1 e2e.scenario=disk-show"
  expect_done
  expect '^e2e: head VEMU-DISK-MARKER'
  [ "$(field 'sector md5=')" = "$(slice_md5 "$golden" $((2048 * 512)) 512)" ] ||
    fail "fresh run: sector 2048 is not the golden image's"
  [ "$(field 'bulk md5=')" = "$(slice_md5 "$golden" $((8 << 20)) $((16 << 20)))" ] ||
    fail "fresh run: the 16 MiB at 8 MiB are not the golden image's"
  [ -z "$(ls -A "$snapdir")" ] || fail "file left in TMPDIR: $(ls -A "$snapdir")"
}

t_disk-overlay-shared-base() {
  # Two overlays on one golden image, booted one after the other: each
  # sees the golden image and its own writes only.
  local golden before a b ma mb gsec
  golden=$(fresh_disk golden-shared.img)
  before=$(md5_of "$golden")
  a="$WORK/shared-a.vov"
  b="$WORK/shared-b.vov"
  overlay_create "$golden" "$a" || return
  overlay_create --block-size 64K "$golden" "$b" || return
  gsec=$(slice_md5 "$golden" $((2048 * 512)) 512)
  ma="VEMU-A-$$-$RANDOM"
  mb="VEMU-B-$$-$RANDOM"
  run_vm --net none --disk "$a" --append "quiet vemu.test=1 e2e.scenario=disk-mark e2e.marker=$ma"
  expect_done
  expect '^e2e: marker written'
  [ "$(field 'sector md5=')" = "$gsec" ] || fail "new overlay A does not show the golden image"
  run_vm --net none --disk "$b" --append "quiet vemu.test=1 e2e.scenario=disk-mark e2e.marker=$mb"
  expect_done
  expect '^e2e: marker written'
  [ "$(field 'sector md5=')" = "$gsec" ] || fail "overlay B sees overlay A's write"
  run_vm --net none --disk "$a" --append "quiet vemu.test=1 e2e.scenario=disk-show"
  expect_done
  expect_quiet
  [ "$(field 'sector md5=')" = "$(marker_md5 "$ma")" ] || fail "overlay A lost its marker, or sees B's"
  [ "$(md5_of "$golden")" = "$before" ] || fail "the golden image changed"
}

t_disk-overlay-refusals() {
  # Host-side checks, each a second vemu that must stop at its disks. It
  # also gets a --serial that is not a socket, so even one whose disks did
  # open stops right after, before any VM exists.
  local golden ov nosock p="$WORK/$CUR.probe"
  golden=$(fresh_disk golden-refuse.img)
  ov="$WORK/refuse.vov"
  overlay_create "$golden" "$ov" || return
  nosock="$WORK/not-a-socket"
  : > "$nosock"
  probe() {
    "$TIMEOUT_BIN" 20 "$VEMU" --kernel "$KERNEL" --initrd "$INITRD" --net none \
      --serial "unix:$nosock" "$@" < /dev/null > /dev/null 2> "$p"
  }
  start_vm --net none --disk "$ov" --append "quiet vemu.test=1 e2e.scenario=idle e2e.seconds=6"
  if wait_for '^vemu-init: disk /dev/vda'; then
    # The golden image read-write while an overlay uses it.
    probe --disk "$golden" && fail "the golden image opened read-write while an overlay uses it"
    grep -q 'in use read-only.*golden image of an overlay' "$p" ||
      fail "golden image read-write: $(head -n 1 "$p")"
    # The same overlay in a second VM.
    probe --disk "$ov" && fail "an overlay in use opened a second time"
    grep -q 'overlay is in use read-write' "$p" || fail "overlay in use: $(head -n 1 "$p")"
    # Sharing the golden image (here with a snapshot) is fine: this one
    # gets past its disks and stops at the serial port.
    probe --disk "$golden,snapshot"
    grep -q 'is not a socket' "$p" || fail "snapshot of a golden image in use: $(head -n 1 "$p")"
  else
    fail "the VM using the overlay did not start"
  fi
  wait_vm
  expect_done
  expect_quiet
  # No chains: a snapshot of an overlay.
  probe --disk "$ov,snapshot" && fail "a snapshot of an overlay was accepted"
  grep -q 'chain' "$p" || fail "snapshot of an overlay: $(head -n 1 "$p")"
  # The golden image changed (one byte, in place).
  python3 -I -c 'import sys; f=open(sys.argv[1],"r+b"); f.seek(4096); f.write(b"X"); f.close()' "$golden"
  probe --disk "$ov" && fail "an overlay on a changed golden image was used"
  grep -q 'has changed since the overlay was created' "$p" || fail "changed golden image: $(head -n 1 "$p")"
  "$TIMEOUT_BIN" 30 "$VEMU" overlay info "$ov" > "$WORK/$CUR.info" 2>&1 &&
    fail "overlay info exited 0 for a changed golden image"
  grep -q '^golden status:  UNUSABLE: changed' "$WORK/$CUR.info" || fail "overlay info: $(grep '^golden status' "$WORK/$CUR.info")"
  # An existing overlay is never overwritten.
  "$TIMEOUT_BIN" 30 "$VEMU" overlay create "$golden" "$ov" > "$p" 2>&1 && fail "overlay create overwrote $ov"
  grep -q 'already exists' "$p" || fail "overlay create on an existing file: $(head -n 1 "$p")"
  # The usage errors.
  probe --disk "$golden,snapshot,ro" && fail "snapshot,ro was accepted"
  grep -q 'make no sense' "$p" || fail "snapshot,ro: $(head -n 1 "$p")"
}

t_net-dhcp() {
  run_vm --append "quiet vemu.test=1"
  expect '^vemu-init: eth0 10\.0\.2\.15/24$'
  expect_done
  expect_quiet
}

t_net-ping() {
  run_vm --append "quiet vemu.test=1 e2e.scenario=ping"
  expect '^e2e: ping 3 packets received'
  expect_done
}

t_net-dns() {
  local name=example.com
  python3 -I -c 'import socket,sys; socket.gethostbyname(sys.argv[1])' "$name" 2> /dev/null ||
    { skip "host cannot resolve $name"; return; }
  run_vm --append "quiet vemu.test=1 e2e.scenario=dns e2e.name=$name"
  expect '^e2e: dns [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
  expect_done
}

t_net-http-get() {
  start_httpd || { fail "host HTTP server did not start"; return; }
  run_vm --append "quiet vemu.test=1 e2e.scenario=http-get e2e.port=$HTTPD_PORT e2e.file=big.bin"
  local want; want="$(md5_of "$WORK/www/big.bin") size=$((BIG_MIB << 20))"
  [ "$(field 'get md5=')" = "$want" ] || fail "guest got '$(field 'get ')', expected md5=$want"
  expect_done
  NOTE="$BIG_MIB MiB"
}

t_net-http-parallel() {
  start_httpd || { fail "host HTTP server did not start"; return; }
  run_vm --cpus 4 --append "quiet vemu.test=1 e2e.scenario=http-parallel e2e.port=$HTTPD_PORT e2e.file=big.bin e2e.n=4"
  local want; want=$(md5_of "$WORK/www/big.bin")
  [ "$(field 'parallel ')" = "4 $want " ] || fail "4 downloads gave '$(field 'parallel ')', expected 4 x $want"
  expect_done
  NOTE="4 x $BIG_MIB MiB on 4 vCPUs"
}

t_net-http-post() {
  start_httpd || { fail "host HTTP server did not start"; return; }
  run_vm --append "quiet vemu.test=1 e2e.scenario=http-post e2e.port=$HTTPD_PORT e2e.mib=$BIG_MIB"
  local sent; sent=$(field 'post local md5=')
  [ -n "$sent" ] && [ "$(field 'post remote ')" = "md5=$sent size=$(field 'post local size=')" ] ||
    fail "host received '$(field 'post remote ')', guest sent md5=$sent"
  expect_done
}

t_net-hostfwd-http() {
  local port; port=$(free_port)
  start_vm --append "quiet vemu.test=1 e2e.scenario=hostfwd-http e2e.mib=$BIG_MIB" \
    --net "user,hostfwd=tcp:127.0.0.1:$port-:8080"
  if wait_for '^e2e: serving md5='; then
    sleep 0.3 # nc is about to listen
    curl -s -m 30 -o "$WORK/fwd.bin" "http://127.0.0.1:$port/" || fail "curl through the forward failed"
    local want; want=$(field 'serving md5=')
    [ "$(md5_of "$WORK/fwd.bin")" = "$want" ] || fail "host got md5 $(md5_of "$WORK/fwd.bin"), guest served $want"
  else
    fail "guest server did not start"
  fi
  wait_vm
  expect '^e2e: served'
  expect_done
}

t_net-hostfwd-shell() {
  # The ssh-style use: a host client reaches a guest service through a
  # forwarded port (here a shell behind nc -e).
  local port; port=$(free_port)
  start_vm --append "quiet vemu.test=1 e2e.scenario=hostfwd-shell" \
    -p "$port:2323"
  if wait_for '^e2e: shell listening'; then
    sleep 0.3
    python3 -I "$E2E/client.py" tcp 127.0.0.1 "$port" 'echo $((6*7))-remote; uname -m\nexit\n' '42-remote' 30 \
      > "$WORK/$CUR.client" || fail "no reply from the guest shell"
    grep -q "$GUEST_ARCH" "$WORK/$CUR.client" || fail "uname output missing"
  else
    fail "guest did not start listening"
  fi
  wait_vm
  expect '^e2e: shell closed'
  expect_done
}

t_net-hostfwd-udp() {
  local port; port=$(free_port)
  start_vm --append "quiet vemu.test=1 e2e.scenario=hostfwd-udp" -p "$port:5353/udp"
  if wait_for '^e2e: udp listening'; then
    sleep 0.3
    python3 -I -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"hello-udp-fwd\n",("127.0.0.1",int(sys.argv[1])))' "$port"
  else
    fail "guest did not start listening"
  fi
  wait_vm
  expect '^e2e: udp got hello-udp-fwd$'
  expect_done
}

t_net-internet() {
  local host=example.com
  host_online "$host" || { skip "host cannot reach http://$host/"; return; }
  run_vm --append "quiet vemu.test=1 e2e.scenario=internet e2e.host=$host"
  expect '^e2e: internet [1-9][0-9]* matches'
  expect_done
}

t_timing-sleep() {
  # Timestamp console lines on the host as they arrive.
  stamped() {
    vemu --net none --append "quiet vemu.test=1 e2e.scenario=sleep" < /dev/null 2> "$ERR" |
      perl -MTime::HiRes=time -ne 'BEGIN { $| = 1 } s/\r//g; printf "%.3f %s", time, $_' > "$WORK/$CUR.ts"
    return "${PIPESTATUS[0]}"
  }
  run_bg stamped
  sed 's/^[0-9.]* //' "$WORK/$CUR.ts" > "$LOG"
  expect_done
  local host guest
  host=$(awk '/e2e: t0/ { a = $1 } /e2e: t1/ { b = $1 } END { if (a && b) printf "%.3f", b - a }' "$WORK/$CUR.ts")
  guest=$(field 't1 uptime ' | awk '{ printf "%.3f", $2 - $1 }')
  awk -v h="${host:-0}" -v g="${guest:-0}" 'BEGIN { exit !(h >= 1.95 && h <= 2.3 && g >= 1.95 && g <= 2.3) }' ||
    fail "sleep 2 took host ${host:-?} s, guest ${guest:-?} s"
  NOTE="host ${host}s, guest ${guest}s"
}

t_timing-idle() {
  # 4 vCPUs idle for 5 s. The CPU time of a whole run includes the boot,
  # which costs more for a compressed x86 bzImage (~0.6 s) than for an arm64
  # Image, so the idle cost is the difference to a run that idles 0 s.
  timed() { # seconds
    cpu_time "$TIMEOUT_BIN" "$VM_TIMEOUT" "$VEMU" --kernel "$KERNEL" --initrd "$INITRD" --cpus 4 \
      --append "quiet vemu.test=1 e2e.scenario=idle e2e.seconds=$1" < /dev/null 2> "$ERR" | crlf > "$LOG"
    return "${PIPESTATUS[0]}"
  }
  cpu_of() { awk '/^(user|sys) / { t += $2 } END { printf "%.2f", t }' "$ERR"; }
  local base cpu idle
  run_bg timed 0
  expect '^e2e: idle done'
  expect_done
  base=$(cpu_of)
  run_bg timed 5
  expect '^e2e: idle done'
  expect_done
  cpu=$(cpu_of)
  idle=$(awk -v a="$cpu" -v b="$base" 'BEGIN { printf "%.2f", a - b }')
  awk -v c="$idle" 'BEGIN { exit !(c < 0.25) }' ||
    fail "idle VM used $idle s of CPU in 5 s (run $cpu s, boot-only run $base s)"
  NOTE="${idle}s CPU over 5s idle, 4 vCPUs (boot ${base}s)"
}

t_timing-rtc() {
  # aarch64: the PL031. x86_64 guests have no RTC device; they read the
  # wall clock from kvmclock instead.
  [ "$GUEST_ARCH" = aarch64 ] || { skip "no RTC device on $GUEST_ARCH guests (kvmclock gives the time)"; return; }
  local host host_end
  host=$(date +%s)
  run_vm --net none --append "quiet vemu.test=1 e2e.scenario=rtc"
  host_end=$(date +%s)
  expect_done
  expect '^e2e: rtc name .*pl031'
  local rtc sys
  rtc=$(field 'rtc time ' | awk '{ print $1 }')
  sys=$(field 'rtc time ' | awk '{ print $3 }')
  # Read during the run: between the host's time at start and at the end.
  awk -v h="$host" -v e="$host_end" -v r="${rtc:-0}" -v s="${sys:-0}" 'BEGIN { exit !(r >= h - 1 && r <= e + 1 && s >= h - 1 && s <= e + 1) }' ||
    fail "guest clock off: host $host..$host_end, rtc ${rtc:-?}, system ${sys:-?}"
  local before after early
  before=$(field 'rtc alarm irqs ' | awk '{ print $1 }')
  after=$(field 'rtc alarm irqs ' | awk '{ print $2 }')
  early=$(field 'rtc alarm irqs ' | awk '{ sub(/^early=/, "", $3); print $3 }')
  # Exactly one interrupt, and none in the first second.
  awk -v a="${before:-x}" -v b="${after:-x}" -v e="${early:-x}" 'BEGIN { exit !(a ~ /^[0-9]+$/ && b ~ /^[0-9]+$/ && e ~ /^[0-9]+$/ && b == a + 1 && e == a) }' ||
    fail "the RTC alarm should raise one interrupt after 2 s (irqs ${before:-?} -> ${after:-?}, ${early:-?} after 1 s)"
  expect '^e2e: rtc alarm .* pending=\[\]'
  NOTE="rtc $((rtc - host)) s, system $((sys - host)) s off the host; alarm irqs $before -> $after"
}

# ---------------------------------------------------- vemu build (images) ----

BUILD_DIR="$WORK/build"
BUILD_IMG="$BUILD_DIR/e2e.raw"
BUILD_TIMEOUT="${VEMU_E2E_BUILD_TIMEOUT:-600}"
BUILD_STATUS=""   # "" (not tried yet), ok, "failed: <why>", "skip: <why>"
BUILD_SECS=""
RUN_TOKEN="run-$$-$RANDOM"
build_cache_args=()
[ -n "${VEMU_E2E_BUILD_CACHE:-}" ] && build_cache_args=(--cache "$VEMU_E2E_BUILD_CACHE")

# Why the build scenarios cannot run on this host, if they cannot.
build_unavailable() {
  local t
  for t in ssh ssh-keygen; do
    command -v "$t" > /dev/null || { echo "needs $t"; return; }
  done
  curl -s -m 10 -o /dev/null https://dl-cdn.alpinelinux.org/alpine/ ||
    echo "host cannot reach https://dl-cdn.alpinelinux.org/"
}

# The test config: ssh with a key made here, the network defaults (DHCP,
# NTP), a package, two [files] (an explicit mode and the host file's) and
# a [run] script.
build_inputs() {
  [ -f "$BUILD_DIR/e2e.conf" ] && return 0
  mkdir -p "$BUILD_DIR"
  ssh-keygen -q -t ed25519 -N '' -C vemu-e2e -f "$BUILD_DIR/id" < /dev/null || return 1
  printf 'hello from the host\n' > "$BUILD_DIR/hello.txt"
  printf '#!/bin/sh\necho e2e-tool\n' > "$BUILD_DIR/tool"
  chmod 0751 "$BUILD_DIR/tool"
  printf '%s\n' '# [run] script: runs in the image, with the network, ptys and shm.' 'set -e' \
    "echo $RUN_TOKEN > /etc/e2e-run-marker" 'apk info -e curl > /dev/null' \
    'grep -q " /dev/pts devpts " /proc/mounts' '( exec 3<> /dev/ptmx )' \
    '[ -k /dev/shm ] && [ -w /dev/shm ]' > "$BUILD_DIR/run.sh"
  printf '%s\n' '# vemu e2e test image' "kernel = $KERNEL" 'size = 1G' 'hostname = e2e-build' '' \
    '[network]' 'dhcp = true' 'ntp = true' '' \
    '[ssh]' 'enable = true' 'authorized_keys = id.pub' '' \
    '[packages]' 'list = curl' '' \
    '[files]' '/etc/e2e/hello.txt = hello.txt 0640' '/usr/local/bin/e2e-tool = tool' '' \
    '[run]' 'script = run.sh' > "$BUILD_DIR/e2e.conf"
}

# Build $BUILD_IMG once; the scenarios after build-image reuse it.
ensure_image() {
  case "$BUILD_STATUS" in
    ok) return 0 ;;
    skip:*) skip "${BUILD_STATUS#skip: }"; return 1 ;;
    failed:*) fail "the image build failed: ${BUILD_STATUS#failed: }"; return 1 ;;
  esac
  local why; why=$(build_unavailable)
  if [ -n "$why" ]; then BUILD_STATUS="skip: $why"; skip "$why"; return 1; fi
  build_inputs || { BUILD_STATUS="failed: cannot make the test inputs"; fail "cannot make the test inputs"; return 1; }
  local t0=$SECONDS
  run_bg "$TIMEOUT_BIN" "$BUILD_TIMEOUT" "$VEMU" build "$BUILD_DIR/e2e.conf" -o "$BUILD_IMG" \
    ${build_cache_args[@]+"${build_cache_args[@]}"} > "$WORK/build.out" 2> "$WORK/build.err"
  BUILD_SECS=$((SECONDS - t0))
  cat "$WORK/build.out" "$WORK/build.err" > "$LOG"
  if [ "$RC" = 0 ] && [ -f "$BUILD_IMG" ]; then
    BUILD_STATUS=ok
  else
    BUILD_STATUS="failed: vemu build exited with $RC: $(grep -m 1 'error:' "$WORK/build.err")"
    fail "${BUILD_STATUS#failed: }"
    [ -f "$BUILD_IMG.build.log" ] && tail -n 20 "$BUILD_IMG.build.log" > "$ERR"
    return 1
  fi
}

mode_of() { python3 -I -c 'import os,sys; print("%o" % (os.stat(sys.argv[1]).st_mode & 0o7777))' "$1"; }
size_of() { python3 -I -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$1"; }
alloc_mib() { python3 -I -c 'import os,sys; print(os.stat(sys.argv[1]).st_blocks * 512 >> 20)' "$1"; }
now_ms() { python3 -I -c 'import time; print(int(time.time() * 1000))'; }

# ssh to the guest behind host port $1, as root with the test key.
guest_ssh() {
  local port=$1; shift
  "$TIMEOUT_BIN" 60 ssh -q -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$BUILD_DIR/id" -p "$port" root@127.0.0.1 "$@" < /dev/null
}

# Boot the image ("$@": its --disk) with sshd forwarded from 127.0.0.1:
# $SSH_PORT, in the background ($VM_PID), and wait for the login prompt and
# for ssh. Sets BOOT_LOGIN and BOOT_SSH (ms after vemu started), or fails
# (the VM is then stopped).
boot_image() {
  SSH_PORT=$(free_port)
  BOOT_LOGIN="" BOOT_SSH=""
  local t0 i; t0=$(now_ms)
  : > "$LOG.raw"
  "$TIMEOUT_BIN" "$VM_TIMEOUT" "$VEMU" --kernel "$KERNEL" --cpus 2 --memory 1G "$@" \
    -p "$SSH_PORT:22" --append "root=/dev/vda rw" \
    < /dev/null > "$LOG.raw" 2> "$ERR" &
  VM_PID=$!
  BG_PIDS+=("$VM_PID")
  if wait_for 'login: ' 45; then
    BOOT_LOGIN=$(( $(now_ms) - t0 ))
    for i in $(seq 100); do
      if guest_ssh "$SSH_PORT" true 2> /dev/null; then
        BOOT_SSH=$(( $(now_ms) - t0 ))
        return 0
      fi
      kill -0 "$VM_PID" 2> /dev/null || break
      sleep 0.3
    done
    fail "ssh to the guest failed"
  else
    fail "no login prompt on hvc0"
  fi
  kill "$VM_PID" 2> /dev/null
  wait_vm
  return 1
}

# Power the guest off from the inside; vemu must exit 0.
poweroff_image() {
  guest_ssh "$SSH_PORT" poweroff 2> /dev/null
  wait_vm
  expect_rc 0
}

t_build-image() {
  ensure_image || return
  [ "$(mode_of "$BUILD_IMG")" = 444 ] || fail "the image has mode $(mode_of "$BUILD_IMG"), not 444"
  [ ! -e "$BUILD_IMG.partial" ] || fail "$BUILD_IMG.partial left behind"
  [ "$(size_of "$BUILD_IMG")" = $((1 << 30)) ] || fail "the image is not 1 GiB"
  grep -Eq '^VEMU-BUILD-OK [0-9a-f]{32}$' "$BUILD_IMG.build.log" || fail "no success marker in the build log"
  grep -q 'inode tables initialized' "$BUILD_IMG.build.log" || fail "inode tables not initialized by mkfs"
  # The [run] script leaves resolv.conf alone: the builder's copy is removed.
  ! grep -q 'keeping the /etc/resolv.conf' "$BUILD_IMG.build.log" || fail "the builder's resolv.conf was kept"
  grep -q '^vemu build: built ' "$WORK/build.err" || fail "no 'built' message"
  grep -qF "vemu overlay create $BUILD_IMG vm1.vov" "$WORK/build.out" || fail "no usage hint"
  NOTE="built in ${BUILD_SECS}s, $(alloc_mib "$BUILD_IMG") MiB allocated of 1 GiB"
}

t_build-boot() {
  ensure_image || return
  boot_image --disk "$BUILD_IMG,snapshot" || return
  local out="$WORK/$CUR.ssh"
  guest_ssh "$SSH_PORT" '
    echo "release=$(cat /etc/alpine-release)"
    echo "hostname=$(hostname)"
    echo "runlevel=$(rc-status -r)"
    echo "failed=$(rc-status -a | grep -cE "failed|crashed")"
    echo "crashed=$(rc-status --crashed | wc -l)"
    for l in sysinit boot default; do rc-status "$l"; done | grep -vE "Runlevel:|\[ +started" | sed "s/^/notstarted: /"
    echo "curl=$(command -v curl)"
    echo "hello=$(stat -c "%a %U" /etc/e2e/hello.txt) $(cat /etc/e2e/hello.txt)"
    echo "tool=$(stat -c %a /usr/local/bin/e2e-tool) $(/usr/local/bin/e2e-tool)"
    echo "run=$(cat /etc/e2e-run-marker)"
    echo "eth0=$(ip -4 -o addr show eth0 | awk "{print \$4}")"
    echo "dns=$(nslookup dl-cdn.alpinelinux.org 2> /dev/null | grep -c "^Address")"
    chronyc waitsync 30 1 0 1 > /dev/null 2>&1 && echo synced=yes
    echo "date=$(date +%s)"
    echo "inittab=$(grep -c "^hvc0::respawn:/sbin/getty" /etc/inittab) $(grep -c "^tty[0-9]" /etc/inittab)"
  ' > "$out" 2>&1 || fail "commands over ssh failed"
  local host_now; host_now=$(date +%s)
  f() { sed -n "s/^$1=//p" "$out" | head -n 1; }
  [ -n "$(f release)" ] || fail "no /etc/alpine-release"
  [ "$(f hostname)" = e2e-build ] || fail "hostname is '$(f hostname)'"
  [ "$(f runlevel)" = default ] || fail "runlevel '$(f runlevel)', not default"
  [ "$(f failed)" = 0 ] && [ "$(f crashed)" = 0 ] || fail "failed or crashed services: $(f failed)/$(f crashed)"
  # OpenRC lists a service that failed to start as "stopped", not failed:
  # every service of the image's runlevels must be started.
  grep -q '^notstarted: ' "$out" && fail "services not started: $(sed -n 's/^notstarted: *//p' "$out" | tr -s ' ' | paste -sd ';' -)"
  [ -n "$(f curl)" ] || fail "curl is not installed"
  [ "$(f hello)" = "640 root hello from the host" ] || fail "hello.txt: '$(f hello)'"
  [ "$(f tool)" = "751 e2e-tool" ] || fail "e2e-tool: '$(f tool)'"
  [ "$(f run)" = "$RUN_TOKEN" ] || fail "[run] marker: '$(f run)', expected $RUN_TOKEN"
  [ "$(f eth0)" = 10.0.2.15/24 ] || fail "eth0 '$(f eth0)'"
  [ "$(f dns)" -ge 1 ] 2> /dev/null || fail "DNS lookup failed in the guest"
  [ "$(f synced)" = yes ] || fail "chrony did not synchronize"
  local d=$(( host_now - $(f date || echo 0) ))
  [ "${d#-}" -le 60 ] || fail "the guest clock is ${d} s off the host's"
  [ "$(f inittab)" = "1 0" ] || fail "inittab: hvc0 gettys / tty gettys = $(f inittab)"
  poweroff_image
  expect 'login: '
  # No OpenRC failure on the console, at boot or at shutdown ("[ !! ]",
  # "ERROR: ... failed to start"), and no modprobe complaints.
  local bad; bad=$(tr -d '\033' < "$LOG.raw" | grep -E '!!( |\[[0-9;]*m)*\]|ERROR: |modprobe: ' | head -n 3)
  [ -z "$bad" ] || fail "console errors: $bad"
  NOTE="login prompt ${BOOT_LOGIN} ms, ssh ${BOOT_SSH} ms, clock off by ${d#-} s"
}

t_build-hostkeys() {
  ensure_image || return
  local a="$WORK/hk-a.vov" b="$WORK/hk-b.vov" ov ka kb
  overlay_create "$BUILD_IMG" "$a" || return
  overlay_create "$BUILD_IMG" "$b" || return
  for ov in "$a" "$b"; do
    boot_image --disk "$ov" || return
    guest_ssh "$SSH_PORT" 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub; cat /var/lib/seedrng/seed.* | md5sum' \
      > "$ov.keys" 2>&1 || fail "ssh to the VM on $(basename "$ov") failed"
    poweroff_image
  done
  ka=$(awk 'NR == 1 {print $2}' "$a.keys")
  kb=$(awk 'NR == 1 {print $2}' "$b.keys")
  [ -n "$ka" ] && [ -n "$kb" ] || fail "no host key fingerprints ('$ka', '$kb')"
  [ "$ka" != "$kb" ] || fail "two overlays of one image have the same host key $ka"
  [ "$(sed -n 2p "$a.keys")" != "$(sed -n 2p "$b.keys")" ] || fail "two overlays of one image have the same seedrng seed"
  NOTE="$ka vs $kb"
}

t_build-refusals() {
  # Host-side refusals: no VM boots, and nothing is left behind.
  local d="$WORK/refuse" other=x86_64 before
  [ "$GUEST_ARCH" = x86_64 ] && other=aarch64
  mkdir -p "$d"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGUyZTJlMmUyZTJlMmUyZTJlMmUyZTJlMmUyZTJlMmUy e2e\n' > "$d/k.pub"
  refuse() { # NAME WANT CONFIG-LINE...
    local name=$1 want=$2; shift 2
    printf '%s\n' "$@" > "$d/$name.conf"
    "$TIMEOUT_BIN" 120 "$VEMU" build "$d/$name.conf" -o "$d/$name.raw" \
      ${build_cache_args[@]+"${build_cache_args[@]}"} > "$d/$name.out" 2>&1 && fail "$name: vemu build succeeded"
    grep -qF -- "$want" "$d/$name.out" || fail "$name: no '$want' in: $(grep -m 1 error "$d/$name.out")"
    [ ! -e "$d/$name.raw.partial" ] || fail "$name: $name.raw.partial left behind"
    cat "$d/$name.out" >> "$LOG"
  }
  refuse arch "arch.conf:2: arch = $other, but this host is $GUEST_ARCH" "kernel = $KERNEL" "arch = $other"
  grep -q 'no CPU emulation' "$d/arch.out" || fail "arch: the message does not say why"
  refuse badkey 'badkey.conf:3: unknown top-level key "siez"' "kernel = $KERNEL" 'size = 1G' 'siez = 2G'
  refuse badvalue 'badvalue.conf:5: [ssh] server: expected openssh or dropbear' "kernel = $KERNEL" \
    '[ssh]' 'enable = true' 'authorized_keys = k.pub' 'server = telnet'
  printf 'not an image\n' > "$d/exists.raw"
  before=$(md5_of "$d/exists.raw")
  refuse exists "output $d/exists.raw already exists (use --force" "kernel = $KERNEL"
  [ "$(md5_of "$d/exists.raw")" = "$before" ] || fail "exists: the existing output was modified"
  if [ -z "$(build_unavailable)" ]; then
    refuse pin 'sha256 pin mismatch: the config pins 0000000000' "kernel = $KERNEL" \
      "sha256 = 0000000000000000000000000000000000000000000000000000000000000000"
  else
    NOTE="offline: the sha256 pin check was skipped"
  fi
  for f in arch badkey badvalue pin; do
    [ ! -e "$d/$f.raw" ] || fail "$f: an output was created"
  done
}

# ----------------------------------------------------------------- main ----

say "work directory: $WORK"
SELECTED=("${ALL_SCENARIOS[@]}")
[ ${#ONLY[@]} -gt 0 ] && SELECTED=("${ONLY[@]}")
START=$SECONDS
for s in "${SELECTED[@]}"; do
  begin "$s"
  "t_$s"
  [ "$SKIPPED_CUR" = 1 ] || finish "$NOTE"
done

echo
printf 'e2e: %d passed, %d failed, %d skipped (%d s)\n' \
  "${#PASSED[@]}" "${#FAILED[@]}" "${#SKIPPED[@]}" $((SECONDS - START))
[ ${#FAILED[@]} -eq 0 ]
