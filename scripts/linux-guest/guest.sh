#!/bin/sh
# Guest side of scripts/linux-guest-test.sh, installed as /etc/vemu-test.sh.
# Runs every test executable in /tests (Rust libtest binaries built for
# aarch64-unknown-linux-musl) and brackets each one's output with
#   vemu-test: begin NAME
#   vemu-test: end NAME rc=STATUS
# lines that the host side parses. /init powers off afterwards.

/bin/busybox --install -s /bin 2>/dev/null

# Scratch space for the tests' temporary files (disk images, sockets...).
mount -t tmpfs -o size=256m,mode=1777 tmpfs /tmp
# Unprivileged ICMP echo ("ping") sockets for every group, as most
# distributions configure it; vemu-net's NAT uses one.
echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range
export TMPDIR=/tmp HOME=/tmp RUST_BACKTRACE=1

threads=$(grep -c ^processor /proc/cpuinfo)
# vemu.ignored=1: also the #[ignore]d tests (those needing Internet access).
extra=
grep -q 'vemu.ignored=1' /proc/cmdline && extra=--include-ignored
for t in /tests/*; do
  [ -x "$t" ] || continue
  n=${t##*/}
  echo "vemu-test: begin $n"
  (cd /tmp && "$t" --test-threads="$threads" $extra </dev/null 2>&1)
  echo "vemu-test: end $n rc=$?"
done
echo "vemu-test: all done"
