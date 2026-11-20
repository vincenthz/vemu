#!/bin/sh
# Cross-check the workspace for the Linux (KVM) targets from any host:
#   cargo check, cargo clippy -D warnings (--workspace --all-targets) and
#   cargo test --no-run (links every test executable with zig, see
#   .cargo/config.toml) for aarch64- and x86_64-unknown-linux-musl.
# Nothing runs: scripts/linux-guest-test.sh runs the aarch64 tests in a guest.
#
#   scripts/check-linux.sh [TARGET...]    default: both Linux musl targets,
#                                         plus check + clippy (no linking)
#                                         of the *-linux-gnu targets that
#                                         rustup has installed (what a native
#                                         Linux build uses)
# Every step runs even after a failure; the summary lists each one, and the
# exit status is 1 if any failed. Logs: target/check-linux/<target>-<step>.log
#
# Builds go to their own target directory (target/check-linux, or
# CARGO_TARGET_DIR if set), so they neither wait for nor invalidate the
# host builds in target/.
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here" || exit 1
logs="$here/target/check-linux"
mkdir -p "$logs"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$logs}"
gnu=""
if [ $# -eq 0 ]; then
  set -- aarch64-unknown-linux-musl x86_64-unknown-linux-musl
  installed="$(rustup target list --installed 2> /dev/null || true)"
  for t in aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
    printf '%s\n' "$installed" | grep -qx "$t" && gnu="$gnu $t"
  done
fi

if ! command -v "${ZIG:-zig}" >/dev/null 2>&1; then
  echo "check-linux: zig not found (the linker for the musl targets); install zig or set ZIG" >&2
  exit 1
fi

summary=""
failed=0
step() { # target name cargo-subcommand [cargo-args...] [-- tool-args...]
  t="$1"; name="$2"; sub="$3"; shift 3
  log="$logs/$t-$name.log"
  printf '%-28s %-8s ... ' "$t" "$name"
  # --target goes before any "--" (after it, it would reach rustc instead).
  if cargo "$sub" --target "$t" "$@" >"$log" 2>&1; then
    echo ok
    summary="$summary
PASS  $t  $name"
  else
    echo "FAIL (log: $log)"
    failed=1
    # Which crates broke (error lines name the file).
    crates="$(grep -E '^ *--> crates/' "$log" | sed -E 's|^ *--> crates/([^/]+)/.*|\1|' | sort -u | tr '\n' ' ')"
    summary="$summary
FAIL  $t  $name  ${crates:+crates: $crates}"
    grep -E '^(error|warning)(\[[A-Z0-9]+\])?:|^ *--> ' "$log" | head -40 | sed 's/^/    /'
  fi
}

for t in "$@"; do
  step "$t" check check --workspace --all-targets
  step "$t" clippy clippy --workspace --all-targets -- -D warnings
  step "$t" test-bin test --workspace --no-run
done
# glibc targets: no cross linker here, so type-check and lint only.
for t in $gnu; do
  step "$t" check check --workspace --all-targets
  step "$t" clippy clippy --workspace --all-targets -- -D warnings
done

echo
echo "check-linux summary:$summary"
exit "$failed"
