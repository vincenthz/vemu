#!/usr/bin/env python3
"""Build a tiny busybox initramfs (newc cpio, gzip) for testing vemu.

usage: mkinitramfs.py BUSYBOX OUT.cpio.gz [DEST=SRC...]

Each DEST=SRC adds host file SRC at DEST in the image (e.g.
tests/vemu_net=target/.../vemu_net-1234), executable, with any missing parent
directories. VEMU_TEST_SCRIPT=PATH installs PATH as /etc/vemu-test.sh.

Hand-written cpio so /dev/console can be a real char device without root.
The /init script runs self-tests when the kernel command line contains
`vemu.test=1` and powers off; otherwise it drops to a shell on hvc0.
"""
import gzip, os, stat, sys

INIT = r'''#!/bin/sh
export PATH=/bin:/sbin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts && mount -t devpts devpts /dev/pts
echo "vemu-init: up $(uname -r) cpus=$(grep -c ^processor /proc/cpuinfo)"
ip link set lo up
if [ -e /sys/class/net/eth0 ]; then
  ip link set eth0 up
  udhcpc -i eth0 -q -n -t 5 -s /etc/udhcpc.script >/dev/null 2>&1 && echo "vemu-init: eth0 $(ip -4 -o addr show eth0 | awk '{print $4}')"
fi
for d in /dev/vd?; do [ -b "$d" ] && echo "vemu-init: disk $d $(cat /sys/block/${d#/dev/}/size) sectors"; done
if grep -q 'vemu.test=1' /proc/cmdline; then
  [ -x /etc/vemu-test.sh ] && /etc/vemu-test.sh
  for a in $(cat /proc/cmdline); do case $a in vemu.run=*) eval "$(echo ${a#vemu.run=} | sed 's/,/ /g')";; esac; done
  echo "vemu-init: done"
  poweroff -f
fi
# A login shell with the console as its controlling terminal (job control,
# Ctrl-C). cttyhack does that when busybox has it; otherwise the shell opens
# the console device itself as a new session's leader. The last entry of
# console/active is /dev/console.
if /bin/busybox cttyhack true 2>/dev/null; then
  setsid cttyhack sh -l
else
  con=$(sed 's/.* //' /sys/class/tty/console/active 2>/dev/null)
  setsid sh -c "exec sh -l <>/dev/${con:-console} >&0 2>&1"
fi
poweroff -f
'''

DHCP = r'''#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev $interface
    ip addr add $ip/${mask:-24} dev $interface
    [ -n "$router" ] && ip route add default via ${router%% *} dev $interface
    : > /etc/resolv.conf
    for d in $dns; do echo "nameserver $d" >> /etc/resolv.conf; done
    ;;
esac
'''

APPLETS = "sh ash mount umount ls cat echo ip udhcpc poweroff reboot uname grep awk sed mkdir " \
          "wget nc ping nslookup dd sleep setsid cttyhack sync md5sum head tail hexdump stty " \
          "telnetd httpd ifconfig route dmesg ps kill free df".split()

def main():
    if len(sys.argv) < 3:
        sys.exit("usage: mkinitramfs.py BUSYBOX OUT.cpio.gz [DEST=SRC...]")
    busybox, out = sys.argv[1], sys.argv[2]
    extra = []
    for arg in sys.argv[3:]:
        dest, sep, src = arg.partition("=")
        dest = dest.strip("/")
        if not sep or not dest or not src or ".." in dest.split("/"):
            sys.exit(f"mkinitramfs: bad extra file {arg!r} (want DEST=SRC)")
        extra.append((dest, src))
    entries = []  # (name, mode, data, rdev)
    def d(n): entries.append((n, stat.S_IFDIR | 0o755, b"", (0, 0)))
    def f(n, data, mode=0o755): entries.append((n, stat.S_IFREG | mode, data, (0, 0)))
    def l(n, target): entries.append((n, stat.S_IFLNK | 0o777, target.encode(), (0, 0)))
    def c(n, maj, mi): entries.append((n, stat.S_IFCHR | 0o600, b"", (maj, mi)))
    for n in ["bin", "sbin", "dev", "proc", "sys", "etc", "tmp", "root", "mnt", "usr", "var", "run"]:
        d(n)
    c("dev/console", 5, 1)
    c("dev/null", 1, 3)
    f("bin/busybox", open(busybox, "rb").read())
    for a in APPLETS:
        l(f"bin/{a}", "busybox")
    f("init", INIT.encode())
    f("etc/udhcpc.script", DHCP.encode())
    f("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o644)
    test = os.environ.get("VEMU_TEST_SCRIPT")
    if test:
        f("etc/vemu-test.sh", open(test, "rb").read())
    have = {e[0] for e in entries}
    for dest, src in extra:
        parts = dest.split("/")
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i])
            if parent not in have:
                d(parent)
                have.add(parent)
        if dest in have:
            sys.exit(f"mkinitramfs: {dest} is already in the image")
        with open(src, "rb") as fh:
            f(dest, fh.read())
        have.add(dest)
    buf = bytearray()
    def hdr(ino, name, mode, data, rdev):
        nb = name.encode() + b"\0"
        h = "070701" + "".join("%08X" % v for v in [
            ino, mode, 0, 0, 1, 0, len(data), 0, 0, rdev[0], rdev[1], len(nb), 0])
        buf.extend(h.encode()); buf.extend(nb)
        while len(buf) % 4: buf.append(0)
        buf.extend(data)
        while len(buf) % 4: buf.append(0)
    for i, (n, m, data, rdev) in enumerate(entries, 1):
        hdr(i, n, m, data, rdev)
    hdr(0, "TRAILER!!!", 0, b"", (0, 0))
    with gzip.open(out, "wb") as g:
        g.write(bytes(buf))

main()
