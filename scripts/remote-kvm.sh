#!/bin/sh
# Run vemu's x86_64 Linux binaries on the real KVM host (cross-built on macOS).
#
#   scripts/remote-kvm.sh sync NAME FILE...      copy FILEs into ~/vemu-remote/NAME/ on the host
#   scripts/remote-kvm.sh run NAME SECS CMD...   run CMD (a shell command line) in ~/vemu-remote/NAME
#                                                under the host-wide VM lock and `timeout SECS`
#
# NAME: [A-Za-z0-9._-], not starting with . or -. SECS: an integer, 1 to 300.
#   scripts/remote-kvm.sh shell CMD...           run a read-only diagnostic command on the host
#
# Host: $VEMU_KVM_HOST (default 10.10.0.31; Fedora, i7-8550U 4c/8t, 15 GiB, /dev/kvm).
# Everything vemu-related lives under ~/vemu-remote/ on the host: nothing is
# installed system-wide, no sudo. The lock (/tmp/vemu-kvm.lock, flock) makes
# concurrent agents take turns, so at most one test VM runs at a time.
#
# Build first, e.g.:
#   cargo build --release --target x86_64-unknown-linux-musl -p vemu
#   scripts/remote-kvm.sh sync me target/x86_64-unknown-linux-musl/release/vemu testdata/x86_64/*
#   scripts/remote-kvm.sh run me 60 './vemu --kernel bzImage --initrd initramfs.cpio.gz --append "console=hvc0 vemu.test=1" --net none --cpus 2 --memory 512M'
set -eu
host="${VEMU_KVM_HOST:-10.10.0.31}"
ssh_opts="-o BatchMode=yes -o ConnectTimeout=10"
die() { echo "remote-kvm: $*" >&2; exit 2; }
# NAME is a directory under ~/vemu-remote, interpolated into remote shell
# commands: plain characters only, and not "." or "..".
check_name() {
  case "$1" in
    ''|.*|-*|*[!A-Za-z0-9._-]*) die "bad NAME '$1' (want [A-Za-z0-9._-], not starting with . or -)" ;;
  esac
}
# SECS: an integer in 1..=300. `timeout 0` would mean no timeout at all,
# leaving a VM running unbounded while it holds the host-wide lock.
check_secs() {
  case "$1" in
    ''|0*|*[!0-9]*|????*) die "bad SECS '$1' (want an integer from 1 to 300)" ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 300 ] || die "bad SECS '$1' (want an integer from 1 to 300)"
}
cmd="${1:?usage: remote-kvm.sh sync|run|shell ...}"; shift
case "$cmd" in
  sync)
    name="${1:?NAME}"; shift
    check_name "$name"
    # shellcheck disable=SC2086
    ssh $ssh_opts "$host" "mkdir -p ~/vemu-remote/$name"
    # shellcheck disable=SC2086
    rsync -a -e "ssh $ssh_opts" "$@" "$host:vemu-remote/$name/"
    ;;
  run)
    name="${1:?NAME}"; secs="${2:?SECS}"; shift 2
    check_name "$name"
    check_secs "$secs"
    q=$(printf '%s' "$*" | sed "s/'/'\\\\''/g")
    # shellcheck disable=SC2086
    exec ssh $ssh_opts "$host" "cd ~/vemu-remote/$name && exec flock /tmp/vemu-kvm.lock timeout -k 5 $secs sh -c '$q'"
    ;;
  shell)
    # shellcheck disable=SC2086
    exec ssh $ssh_opts "$host" "$*"
    ;;
  *) die "unknown command $cmd" ;;
esac
