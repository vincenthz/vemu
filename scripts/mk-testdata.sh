#!/bin/sh
# Populate testdata/ with a guest kernel, a busybox initramfs and a disk image
# for one guest architecture (the guest always matches the host's).
#
#   VEMU_ARCH     aarch64 or x86_64 (default: the host's architecture)
#   VEMU_KERNEL   guest kernel (default: the skeletos 7.2.15 build)
#                   aarch64: an arm64 Image
#                   x86_64:  a bzImage (boot protocol >= 2.12, 64-bit entry)
#   VEMU_BUSYBOX  static busybox for that architecture. Defaults:
#                   aarch64: turbine's busybox-static-aarch64
#                   x86_64:  bin/busybox.static from Alpine's busybox-static
#                            package, downloaded from dl-cdn.alpinelinux.org
#   VEMU_ALPINE   Alpine branch for that download (default: latest-stable)
#
# Output (the aarch64 paths are the historical ones, used by the scripts):
#   aarch64: testdata/Image             testdata/initramfs.cpio.gz  testdata/disk.img
#   x86_64:  testdata/x86_64/bzImage    testdata/x86_64/initramfs.cpio.gz
#            testdata/x86_64/disk.img
set -eu
here="$(cd "$(dirname "$0")/.." && pwd)"

arch="${VEMU_ARCH:-$(uname -m)}"
case "$arch" in
  arm64 | aarch64) arch=aarch64 ;;
  amd64 | x86_64) arch=x86_64 ;;
  *) echo "mk-testdata: unsupported VEMU_ARCH $arch (aarch64 or x86_64)" >&2; exit 2 ;;
esac
skeletos="$HOME/Work/skeletos/.skeletos/out/kernel/7.2.15/$arch/vmlinuz.efi"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/vemu-testdata.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Fetch Alpine's busybox-static for x86_64 and print the path of its static
# busybox. The download is untrusted data: it lands in its own empty
# directory, only the one member is read out of it (no extraction), and the
# result must be a static x86-64 ELF executable.
alpine_busybox() {
  dl="$tmp/download"
  mkdir "$dl"
  base="https://dl-cdn.alpinelinux.org/alpine/${VEMU_ALPINE:-latest-stable}/main/x86_64"
  apk="$(curl -fsSL -m 60 "$base/" | grep -o 'busybox-static-[0-9][0-9A-Za-z._-]*\.apk' | sort -u | tail -n 1)"
  [ -n "$apk" ] || { echo "mk-testdata: no busybox-static package at $base/" >&2; return 1; }
  echo "mk-testdata: downloading $base/$apk" >&2
  curl -fsSL -m 300 -o "$dl/pkg.apk" "$base/$apk"
  python3 -I - "$dl/pkg.apk" "$tmp/busybox-x86_64" << 'PY'
import gzip, struct, sys, tarfile
src, out = sys.argv[1], sys.argv[2]
# An .apk is gzip streams (signature, control, data) of tar segments without
# end-of-archive markers between them: one gzip reader, ignore_zeros.
data = None
with gzip.open(src, "rb") as z, tarfile.open(fileobj=z, mode="r|", ignore_zeros=True) as t:
    for m in t:
        if m.name.lstrip("./") == "bin/busybox.static":
            if not m.isreg() or m.size > 64 << 20:
                sys.exit("mk-testdata: bin/busybox.static is not a plausible regular file")
            data = t.extractfile(m).read()
            break
if data is None:
    sys.exit("mk-testdata: no bin/busybox.static in the package")
# ELF64, little-endian, x86-64, executable (ET_EXEC or static-pie ET_DYN),
# and no PT_INTERP program header (static: no dynamic loader).
if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
    sys.exit("mk-testdata: busybox.static is not a 64-bit little-endian ELF")
e_type, e_machine = struct.unpack_from("<HH", data, 16)
e_phoff, = struct.unpack_from("<Q", data, 32)
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
if e_machine != 62 or e_type not in (2, 3):
    sys.exit(f"mk-testdata: busybox.static is not an x86-64 executable (type {e_type}, machine {e_machine})")
for i in range(e_phnum):
    p_type, = struct.unpack_from("<I", data, e_phoff + i * e_phentsize)
    if p_type == 3:
        sys.exit("mk-testdata: busybox.static has a PT_INTERP header (not static)")
with open(out, "wb") as f:
    f.write(data)
PY
  chmod 755 "$tmp/busybox-x86_64"
  echo "$tmp/busybox-x86_64"
}

# Refuse kernels the x86_64 machine cannot boot.
check_bzimage() {
  python3 -I - "$1" << 'PY'
import struct, sys
b = open(sys.argv[1], "rb").read(0x300)
if len(b) < 0x240 or b[0x202:0x206] != b"HdrS":
    sys.exit(f"mk-testdata: {sys.argv[1]} is not a bzImage (no HdrS header)")
version, = struct.unpack_from("<H", b, 0x206)
xloadflags, = struct.unpack_from("<H", b, 0x236)
if version < 0x20C or not xloadflags & 1:
    sys.exit(f"mk-testdata: {sys.argv[1]}: boot protocol {version:#x}, xloadflags {xloadflags:#x}; "
             "need >= 2.12 with XLF_KERNEL_64")
PY
}

case "$arch" in
  aarch64)
    td="$here/testdata"
    kernel_out="$td/Image"
    kernel="${VEMU_KERNEL:-$skeletos}"
    busybox="${VEMU_BUSYBOX:-$HOME/Work/turbine/vm/kernel/busybox-static-aarch64}"
    ;;
  x86_64)
    td="$here/testdata/x86_64"
    kernel_out="$td/bzImage"
    kernel="${VEMU_KERNEL:-$skeletos}"
    check_bzimage "$kernel"
    busybox="${VEMU_BUSYBOX:-}"
    [ -n "$busybox" ] || busybox="$(alpine_busybox)"
    ;;
esac
[ -f "$kernel" ] || { echo "mk-testdata: no kernel at $kernel (set VEMU_KERNEL)" >&2; exit 1; }
[ -f "$busybox" ] || { echo "mk-testdata: no busybox at $busybox (set VEMU_BUSYBOX)" >&2; exit 1; }

mkdir -p "$td"
cp "$kernel" "$kernel_out"
python3 -I "$here/scripts/mkinitramfs.py" "$busybox" "$td/initramfs.cpio.gz"
# 64 MiB raw disk whose first sector carries a marker string (bs in bytes:
# BSD dd spells a mebibyte 1m, GNU dd 1M).
dd if=/dev/zero of="$td/disk.img" bs=1048576 count=64 2> /dev/null
printf 'VEMU-DISK-MARKER' | dd of="$td/disk.img" conv=notrunc 2> /dev/null
ls -la "$td"
