#!/bin/sh
# Check vemu-hv's KVM ABI definitions (crates/vemu-hv/src/kvm/abi.rs, plus
# the arch checks in probe-<arch>.h) against the Linux UAPI headers, for
# aarch64-linux and x86_64-linux, at compile time:
#
#   1. cargo test (host) writes the Rust values as a C header
#      (VEMU_KVM_ABI_HEADER, test kvm::abi::tests::c_header);
#   2. probe.c is compiled with `zig cc -target <arch>-linux-musl`, whose
#      bundled kernel headers provide <linux/kvm.h>; every value is a
#      _Static_assert;
#   3. a deliberately wrong copy of the header must FAIL to compile (proves
#      the checks are live).
#
#   scripts/kvm-abi/check.sh [TARGET...]   default: aarch64-linux-musl x86_64-linux-musl
#
# Environment: ZIG (default zig). Exit status 1 on any mismatch.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
zig="${ZIG:-zig}"
[ $# -gt 0 ] || set -- aarch64-linux-musl x86_64-linux-musl
command -v "$zig" > /dev/null 2>&1 || { echo "kvm-abi: zig not found (set ZIG)" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/vemu-kvm-abi.XXXXXX")"
trap 'rm -rf "$work"' EXIT INT TERM
hdr="$work/abi.h"

(cd "$root" && VEMU_KVM_ABI_HEADER="$hdr" cargo test -q -p vemu-hv --lib -- --exact kvm::abi::tests::c_header > "$work/cargo.log" 2>&1) || {
  cat "$work/cargo.log" >&2
  echo "kvm-abi: generating the header failed" >&2
  exit 1
}
[ -s "$hdr" ] || { echo "kvm-abi: the test wrote no header" >&2; exit 1; }
n="$(grep -c '^VEMU_CHECK' "$hdr")"

# The first check with its value changed by one.
sed '2s/ULL)$/ ^ 1ULL)/' "$hdr" > "$work/bad.h"
cmp -s "$hdr" "$work/bad.h" && { echo "kvm-abi: could not make the negative header" >&2; exit 1; }

probe() { # target header
  # Object into $work: with -o /dev/null zig still leaves probe.o in the
  # current directory.
  (cd "$work" && "$zig" cc -target "$1" -std=c11 -Wall -Werror -c -o "$work/probe-$1.o" \
    -DVEMU_ABI_HEADER="\"$2\"" -I "$here" "$here/probe.c")
}

status=0
for t in "$@"; do
  arch_hdr="$here/probe-${t%%-*}.h"
  na=0
  [ -f "$arch_hdr" ] && na="$(grep -c '^VEMU_CHECK' "$arch_hdr")"
  if probe "$t" "$hdr" > "$work/$t.log" 2>&1; then
    echo "kvm-abi: $t: $n common + $na arch checks OK"
  else
    echo "kvm-abi: $t: MISMATCH" >&2
    grep -E 'error' "$work/$t.log" | head -40 >&2
    status=1
  fi
  if probe "$t" "$work/bad.h" > /dev/null 2>&1; then
    echo "kvm-abi: $t: a wrong value was NOT detected (probe broken)" >&2
    status=1
  fi
done
exit "$status"
