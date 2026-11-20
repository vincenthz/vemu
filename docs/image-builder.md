# vemu build: Alpine Linux images

`vemu build CONFIG` makes a bootable disk image that behaves like a normal
Alpine Linux install: OpenRC, apk, the FHS, a getty on the console,
optionally an ssh server, DHCP, NTP, extra packages and host files. A
small declarative config file describes the image. The result is a sparse
raw ext4 image, meant as a read-only golden image for `vemu overlay`.

```sh
vemu build examples/alpine.conf -o alpine.raw
vemu overlay create alpine.raw vm1.vov
vemu --kernel testdata/Image --disk vm1.vov --append "root=/dev/vda rw" -p 2222:22
ssh -p 2222 root@127.0.0.1
```

The host needs no root, no `mkfs`, no loop devices and no Alpine tooling.
All filesystem work happens inside a builder VM that vemu runs in-process,
so the same path works with HVF on macOS and with KVM on Linux. The host
needs only `curl` (for the downloads) and a kernel to boot.

## How it works

```text
 host (vemu build, no root)                     builder VM (2 vCPUs, 1 GiB, NAT)
 ---------------------------                    ---------------------------------
 parse CONFIG (errors: file:line)
 resolve the release:
   https latest-releases.yaml  ---> version, file, sha256 (optional pin)
 curl the minirootfs (or the cache)
   sha256 check, cache by digest
 gunzip + untar (in Rust)
 initramfs = minirootfs + /init      boot ---> /init (generated sh script)
   + /vemu-build/ payload                        mount proc/sys/dev, clock, DHCP
   (keys, files, modules, run)                   apk add e2fsprogs (signed index)
 OUT.partial: O_EXCL, sparse  ---- /dev/vda ---> mkfs.ext4, mount /mnt
                                                 apk --root /mnt --initdb <packages>
                                                 configure (inittab, fstab, rc, ssh ...)
                                                 [files], modules + depmod, [run]
                                                 scrub host keys, seeds, caches
                                                 umount, e2fsck -f -n
 console -> OUT.build.log  <------ hvc0 -------- VEMU-BUILD-OK <nonce>; poweroff -f
 marker + power-off? fsync, rename OUT, chmod 0444
 otherwise: delete OUT.partial, show the log tail
```

The builder is the Alpine minirootfs itself, booted as an uncompressed
newc cpio initramfs with a generated `/init`. vemu's own Rust code does the
host side (SHA-256, inflate, tar reading and cpio writing), so the host
needs no gzip, tar or cpio tools. In the guest, the script installs
e2fsprogs from the Alpine mirror into the builder's RAM, formats
`/dev/vda`, and installs the image with `apk --root /mnt --initdb`, the
same way Alpine's own `setup-disk` and alpine-make-rootfs do.

The build succeeds only if the console shows `VEMU-BUILD-OK <nonce>` and
the guest then powers off. The nonce is 16 random bytes, passed as
`vemu.build=` on the kernel command line, so a stale marker (in a package's
output, or in a [run] script's) cannot fake a success. Any failing command
in the script ends the build: `set -e` plus an EXIT trap print
`VEMU-BUILD-FAILED: <step>: ...` and power off at once. The script never
waits for input.

## Command line

```text
vemu build CONFIG [-o OUT] [--force] [--cache DIR] [--kernel PATH]
                  [--timeout SECS] [-v]
```

| option | meaning |
|---|---|
| `-o, --output OUT` | the image (default: the config's `output =`, else `<config name>.raw` next to the config) |
| `--force` | replace an existing `OUT` (overlays made on the old one are then refused: its fingerprint changes), or remove a leftover `OUT.partial` that no running build holds |
| `--cache DIR` | the download cache (default `$XDG_CACHE_HOME/vemu`, `~/Library/Caches/vemu` on macOS, `~/.cache/vemu` elsewhere) |
| `--kernel PATH` | the builder kernel, overriding `kernel =`; the image boots with it too |
| `--timeout SECS` | stop the builder after SECS seconds (default 900; 10 to 86400) |
| `-v, --verbose` | stream the builder's console to stderr (without it, only the `vemu-build:` step lines are shown, with elapsed seconds) |

Exit status: 0 on success, 1 on any failure, 2 for a usage error. On
success, vemu prints how to boot the image on stdout. On failure it prints
the last 30 console lines and keeps `OUT.build.log`. The log is kept on
success too.

The output's lifecycle:
- vemu writes `OUT.partial`. It is created exclusively (`O_EXCL`), so two
  builds of one output cannot clash, and sparse at the image size.
- On success vemu fsyncs it, renames it to `OUT` (atomically replacing an
  old one under `--force`), makes it read-only (0444) and fsyncs the
  directory.
- On any failure, including SIGINT, SIGTERM, SIGHUP and SIGQUIT at any
  point (during a download too) and a panic, vemu deletes `OUT.partial`,
  the temporary initramfs and any partial download, and stops curl. A
  signal that was ignored when vemu started stays ignored (as it should
  for a background job or under nohup). Only SIGKILL (or a crash) can
  leave files behind: a leftover `OUT.partial` is reported (see
  `--force`), and temporary files in the cache older than two days are
  removed by the next build.
- The temporary initramfs carries your [files], keys, modules and [run]
  script. It is created 0600 in the cache directory (0700), never in the
  shared temporary directory, and deleted when the builder VM exits.
- A closed stdout or stderr (`vemu build ... | head`) does not stop the
  build: messages that cannot be written are dropped.
- An existing `OUT` is refused without `--force` and is left untouched.

## Config reference

`key = value` lines, `[section]` headers, and comment lines that start
with `#`. A `#` later in a line is part of the value: there are no
trailing comments, so a value can never be cut short by a comment. Values
are words separated by spaces. A word may be double-quoted (`"my
key.pub"`, with `\"` and `\\`). List keys (`authorized_keys`, `[packages]
list`) take several words and may be repeated. Every other key takes one
word and may appear once.

The following are errors that name `file:line`: unknown keys or sections,
a repeated key or section, a value of the wrong form, a key that needs a
value and has none, and `arch` that is not the host's. Relative host
paths are relative to the config file's directory. `~` and `~/...` expand
to `$HOME` (`~user` is refused). Booleans are `true/false`, `yes/no`,
`on/off` or `1/0`.

### Top level

| key | default | meaning |
|---|---|---|
| `arch` | the host's | `aarch64` (or `arm64`) or `x86_64` (or `amd64`). It must be the host's: vemu has no CPU emulation, and the builder VM runs the image's own binaries. Build x86_64 images on an x86_64 Linux (KVM) host. |
| `size` | `1G` | virtual image size: a number with `K`/`M`/`G`/`T` (binary units; a bare number is MiB), a whole number of MiB, from 128M to 2T. The file is sparse. |
| `alpine` | `latest-stable` | `latest-stable`, a branch (`v3.24`) or an exact version (`3.24.4`). `edge` is refused: it has no release index and changes daily. |
| `sha256` | none | pin the minirootfs: the build fails unless the release resolves to this tarball |
| `mirror` | `https://dl-cdn.alpinelinux.org/alpine` | the Alpine mirror, used both for the minirootfs (host) and for apk (guest) |
| `insecure` | `false` | allow an `http://` mirror (then pin `sha256`). Without a pin the release is used for this build only and never recorded in the cache index (see Caching). |
| `community` | `false` | also enable the community repository (main is always on) |
| `kernel` | none | the builder kernel and the image's kernel (`--kernel` overrides it). One of the two is required. |
| `modules` | none | a gzip tarball with `lib/modules/<version>/` inside, installed into the image (then `depmod -a`) |
| `hostname` | `vemu` | `/etc/hostname` and `/etc/hosts`: an RFC 1123 name of at most 64 characters (Linux's limit) |
| `timezone` | `UTC` | a tz name (`Europe/Paris`); anything but UTC adds `tzdata` and sets `/etc/localtime` |
| `output` | `<config name>.raw` | the image path (`-o` overrides it) |

### [network]

| key | default | meaning |
|---|---|---|
| `dhcp` | `true` | `auto eth0` / `iface eth0 inet dhcp` in `/etc/network/interfaces` (busybox udhcpc). Off: only `lo`. The networking service is enabled either way, since it brings up `lo`. |
| `ntp` | `true` | install chrony and enable `chronyd` (Alpine's default `pool.ntp.org iburst`, `makestep 1.0 3`) |

### [ssh]

| key | default | meaning |
|---|---|---|
| `enable` | `false` | an ssh server for root, key logins only |
| `server` | `openssh` | `openssh` or `dropbear` |
| `authorized_keys` | none | public key files, concatenated into `/root/.ssh/authorized_keys` (0600, in 0700 `/root/.ssh`). Required with `enable = true`, and an error without it. Files with `PRIVATE KEY` in them, empty files and files over 1 MiB are refused. |

OpenSSH gets a drop-in `/etc/ssh/sshd_config.d/50-vemu.conf` with
`PermitRootLogin prohibit-password`, `PasswordAuthentication no` and
`KbdInteractiveAuthentication no` (the `Include` line is added to
`sshd_config` if a future package drops it). Dropbear gets
`DROPBEAR_OPTS="-s"` (no passwords).

### [packages]

`list = name...`: extra apk packages, as apk world entries (`curl`,
`py3-pip`, `busybox=1.37.0-r31`). They are installed with the base system
in one `apk add`, so a missing package fails the build at that step.

As on any Alpine system, installing a package does not enable its
service: only the services of the features above are put in a runlevel.
Enable the others in a [run] script, e.g. `rc-update add nginx default`
(it works in the build chroot: it only creates the runlevel symlink).

### [files]

`/path/in/image = host/path [mode]`: copy a host file into the image,
owned by root, with `mode` (octal) or the host file's mode. Parent
directories are created 0755. A host directory is copied recursively
(regular files and directories, with their host modes). Symbolic links,
devices and sockets are refused, as is a path in the image that is not
absolute and clean (`..`, `.`, `//`). [files] are copied after the
packages and the system configuration, so they can replace any
configuration file (`/etc/motd`, `/etc/chrony/chrony.conf`, ...),
`/etc/resolv.conf` included: the builder never leaves its own resolv.conf
in the image, and does not remove yours (with `dhcp = true`, udhcpc
rewrites it at boot, as on any Alpine; give it with `dhcp = false` and a
static `/etc/network/interfaces`). All the
host data (keys, files, modules, script) is limited to 256 MiB, since it
travels in the builder's RAM.

### [run]

`script = host/path`: a script run last (after [files] and modules), in
the image as root (`chroot`), with `/proc`, `/sys`, `/dev` (recursively:
`/dev/pts` for ptys, a 1777 tmpfs on `/dev/shm`) and the network
available. A `#!` line picks the interpreter. Otherwise `/bin/sh` runs
it. A non-zero exit fails the build. Its output goes to the build log.

For its DNS, the script gets the builder's `/etc/resolv.conf` (vemu's NAT
resolver). An image resolv.conf (from [files] or a package) is set aside
while it runs and put back afterwards. If the script writes
`/etc/resolv.conf` itself, its version is kept (the log says so).

## What the image is

- Alpine `alpine-base` (busybox, OpenRC, apk-tools, musl), plus e2fsprogs
  (for the boot-time fsck of the root filesystem), the ssh server, chrony,
  tzdata and kmod as configured, and the [packages].
- A raw ext4 filesystem, labelled `vemu-root`, on the whole disk (no
  partition table). Boot it with `root=/dev/vda rw`. The `/etc/fstab`
  entry is `LABEL=vemu-root / ext4 rw,relatime 0 1`.
- The apk repositories for the release's branch (`main`, plus
  `community` if asked), so `apk add` works in the VM. Upgrades follow the
  branch.
- OpenRC runlevels:

  | runlevel | services |
  |---|---|
  | sysinit | devfs, dmesg, mdevd, mdevd-init, hwdrivers |
  | boot | modules, sysctl, hostname, bootmisc, syslog, hwclock (aarch64) or kvmclock (x86_64), seedrng, networking |
  | default | crond, chronyd (ntp), sshd or dropbear (ssh) |
  | shutdown | mount-ro, killprocs, savecache |

  On **aarch64** vemu's machine has a PL031 real-time clock holding the
  host's UTC time: the kernel sets the clock from it at boot
  (`CONFIG_RTC_HCTOSYS`), and the image runs `hwclock` like any machine
  with an RTC, so the time is right from the first second, with or without
  NTP. The builder checks that the kernel has the rtc-pl031 driver,
  built in (`/dev/rtc0`) or as a module from `modules =`; a kernel with
  neither gets `swclock` instead (the last
  shutdown time, i.e. the build time on the first boot, until chronyd
  steps it), and the build log says so. On **x86_64** (KVM) the kernel reads the host's time from the kvmclock
  wall clock at boot, which is right, without NTP too. There is no RTC,
  but some service must provide OpenRC's `clock` (busybox's `syslog`
  needs it): with none in a runlevel, OpenRC starts `hwclock`, which fails
  at boot and at shutdown, and `swclock` would set the clock back to the
  last shutdown time (it moves it backwards too). So x86_64 images get
  `/etc/init.d/kvmclock`, a service of vemu's that provides `clock` and
  does nothing.
- The device manager is **mdevd** (`setup-devd mdevd`), not busybox mdev.
  mdev's hotplug mode needs the kernel's uevent helper
  (`/proc/sys/kernel/hotplug`, `CONFIG_UEVENT_HELPER`), which the
  skeletos kernels and many others lack. Without it, mdev's start prints
  `[ !! ]` on every boot and later hotplug events go unhandled. mdevd
  reads uevents from netlink and uses the same `/etc/mdev.conf`.
- Without `modules =`, the entries of `/etc/modules` (`af_packet`,
  `ipv6`, built into such kernels) are commented out, so that modprobe
  does not complain at every boot about the missing `/lib/modules`.
- `/etc/inittab` runs a getty on `hvc0` (vemu's console) and none on
  tty1..6 (there is no display). `hvc0` is in `/etc/securetty`.

### Root, logins and keys (the security model)

There are no users besides root, and no sudo.
- **Console:** root has an empty password, which is Alpine's own default
  after `setup-alpine` without a password: `root::` in `/etc/shadow`.
  Anyone with the VM's console (vemu's stdin and stdout) is root. That is
  the person running vemu.
- **ssh:** key-based only (`PermitRootLogin prohibit-password`,
  `PasswordAuthentication no`). The empty password therefore never works
  over the network, and dropbear's `-s` does the same.
- **Per-VM secrets:** the build removes the ssh host keys, dropbear host
  keys, the seedrng seed, `/etc/machine-id` and the apk cache, and checks
  that they are gone. Each VM, on its first boot (on its own overlay),
  generates its own host keys and random seed. Two VMs from one golden
  image never share them (the build-hostkeys e2e test checks this).
  `/etc/machine-id` is not created (Alpine does not use one).
- Set a root password or add users in a [run] script if the console must
  be protected.

## The trust chain

1. vemu fetches `latest-releases.yaml`, or for an exact version the
   tarball's `.sha256` file, from the mirror over https. curl runs with
   `-q` first, so no `.curlrc` applies (one with `insecure` would silently
   turn off certificate checks), and with
   `--proto =https --proto-redir =https`, so a redirect to http is refused.
   The proxy environment variables (`https_proxy`, ...) and the system CA
   store still apply. This gives the version, the tarball name and its
   SHA-256.
2. An optional `sha256 =` pin must match it. With a pin, the result no
   longer depends on trusting the mirror's index.
3. The tarball is downloaded and its SHA-256 checked before vemu reads a
   byte of it. A mismatch is refused, and nothing is cached.
4. vemu parses the tarball in Rust with bounds:
   - decompression is capped at 256 MiB in all (all gzip members
     together), so a gzip bomb is refused;
   - absolute paths, `..`, unknown member types and hard links to
     non-earlier members are refused.

   Nothing from it is written to the host. It only becomes the builder's
   initramfs.
5. In the guest, apk verifies every repository index and package against
   the Alpine signing keys from the minirootfs (`/etc/apk/keys`, verified
   in step 3). This holds even over http, which is how Alpine itself works.
   The keys are copied into the image, so later `apk add`s in the VM are
   verified the same way.

Your own inputs (kernel, modules, keys, files, script) are trusted as they
are: they are yours. The builder VM is a normal vemu VM, so a hostile
package could at most corrupt the image being built. It sees no host
files: it gets the payload and the disk, with no shared folders, and NAT
networking without port forwards.

## Caching and offline builds

The cache directory holds:
- `alpine/<sha256>.tar.gz`: minirootfs tarballs named by their digest,
  re-verified on every use. A corrupt one is deleted and downloaded again.
- `alpine/releases.tsv`: how each `alpine =` value resolved, and when, on
  which mirror, and why its digest was trusted: `https` (the index came
  over verified https) or `pinned` (an `insecure = true` mirror, with a
  `sha256 =` pin that matched).

So:
- an **exact version** (`alpine = 3.24.4`) or a **pinned** build fetches
  nothing on the host once cached;
- `latest-stable` and branches re-fetch the small release index each
  time. If that fails, vemu warns and uses the release it resolved for the
  same value before.

An index entry is reused only under the terms it was recorded with, so the
cache never upgrades an unauthenticated digest to a trusted one:
- an `https` entry, by a config with the same `mirror =`;
- a `pinned` entry, by a config with the same mirror and the same pin;
- an `insecure = true` resolution without a pin is never recorded;
- with a pin, the cached release must also be what `alpine =` asks for
  (the same version, or the same branch), else vemu resolves it as usual
  and reports a pin mismatch, as it would on an empty cache.

Index lines written by older vemu versions (without the mirror and the
trust) are ignored. The tarballs themselves are named by their digest and
re-verified on every use, so a tarball is used only when a trusted digest
names it.

The cache is created 0700, and vemu refuses one that is not yours or that
others can write to (`chmod go-w` it, or pass another `--cache`). Writes
are atomic (a temporary file, then a rename), so concurrent builds can
share it. Temporary files (`.download-*`, `.tmp-*`, `.initrd-*`) older
than two days, left by a killed build, are removed when a build opens the
cache.

The guest always needs the network: apk downloads the packages from the
mirror on every build. There is no package cache, which keeps the image
free of cache files and the trust chain simple. A build needs outbound
https (or http) to the mirror from vemu's user-mode NAT.

## Reproducibility

A build is repeatable but not bit-for-bit reproducible:
- The packages are whatever the branch has on the day. Pin `alpine` to
  an exact version and `sha256` to fix the base system. The packages
  still move within the branch (security fixes). Version constraints in
  `[packages] list` (`curl=8.17.0-r0`) pin those too, until the mirror
  drops that version.
- File times are the build time (the builder's clock comes from the host
  through `vemu.epoch=`). The ext4 UUID, hash seed and directory order are
  random.
- The same config on the same day gives the same set of packages and
  configuration files.

## Disk usage and the mkfs options

```text
mkfs.ext4 -q -F -L vemu-root -b 4096 -i 16384 -I 256 \
          -E assume_storage_prezeroed=1,nodiscard /dev/vda
```

- `assume_storage_prezeroed=1` (e2fsprogs 1.47) is the important one. The
  new disk is a fresh sparse file and reads as zeros, so mke2fs neither
  writes the inode tables nor leaves them for lazy init, and still marks
  every group `ITABLE_ZEROED`. Without it, mke2fs either writes every
  inode table (tens of MiB of zeros allocated in the image) or leaves the
  work to the kernel's `ext4lazyinit` thread. That thread would then write
  them on the first boot of every VM, into every overlay. The script
  checks with dumpe2fs that all groups are zeroed, and fails otherwise.
- `nodiscard`: discards on a sparse file buy nothing at mkfs time.
- `-i 16384 -I 256`: the usual ext4 density, explicit so that the result
  does not depend on mke2fs.conf.

The modules tarball is unpacked in the builder's RAM and copied into the
image once. Unpacking it in the image would leave the freed blocks of the
tarball allocated in the raw file, because nothing discards them.

Typical result (aarch64, HVF): a 1 GiB image with curl takes ~47 MiB on
disk. With the 21 MiB aarch64 modules tarball and jq it takes ~144 MiB,
for 118 MiB used in the filesystem. A VM on an overlay of it writes ~1 MiB
to boot, run 20 s and power off.

## Kernel requirements

The builder and the image use the same kernel. It needs:
- virtio-mmio or virtio-pci (vemu's transports), virtio-blk, virtio-net
  and the virtio console (`hvc0`);
- ext4, devtmpfs, an uncompressed initramfs, and `CONFIG_UNIX` and
  `CONFIG_PACKET` (udhcpc). `CONFIG_UEVENT_HELPER` is not needed (the
  image uses mdevd).

`testdata/Image` (aarch64) and `testdata/x86_64/bzImage` qualify. The
builder appends `console=hvc0 quiet panic=-1 vemu.build=<nonce>
vemu.epoch=<secs>` to the command line, so an x86 kernel's built-in
command line (`root=`, `panic=10`) is overridden where it matters. For
`modprobe` to work in the VM, give the matching `modules =`. The build
warns if the modules are not for the builder's kernel.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `curl: not found` / `install curl` | vemu downloads with the system curl |
| `host cannot reach ...`, curl exit 6/7/28 | no internet on the host, a proxy, or DNS. Exact or pinned releases still work offline once cached, but the guest needs the mirror. |
| `sha256 pin mismatch` | the release moved (a new point release on the branch) or the pin is wrong. Pin an exact `alpine =` together with `sha256 =`. |
| `VEMU-BUILD-FAILED: network (DHCP on eth0): no DHCP lease` | the builder's NAT failed. The kernel needs virtio-net, `CONFIG_PACKET`. |
| `VEMU-BUILD-FAILED: installing packages ...: apk could not install` | a misspelt package (apk's message is in the tail) or the mirror is unreachable from the guest. apk is retried 3 times. |
| `the builder did not finish within N s` | slow mirror. Use a closer `mirror =` or a larger `--timeout`. Run with `-v` to watch. |
| `the builder VM rebooted` / `Kernel panic` in the log | the kernel cannot run the builder (see Kernel requirements); `panic=-1` makes a panic end the build at once |
| `OUT.partial exists` | another build of the same output is running, or one was killed with SIGKILL. `--force` removes a leftover (not one a running build holds). |
| the image boots to `VFS: Unable to mount root fs` | boot with `--append "root=/dev/vda rw"`, with the kernel it was built with |
| `rc-status` shows chronyd failing | no network in the VM. NTP needs outbound UDP 123, which vemu's NAT forwards. |
| ssh `Permission denied (publickey)` | the key is not in `authorized_keys =`, or you are not logging in as `root` |
| `the kernel has no RTC driver ... using swclock` in the build log, and the clock is wrong for a few seconds after boot / `WARNING: clock skew detected!` (aarch64) | the kernel lacks `CONFIG_RTC_DRV_PL031` (and `CONFIG_RTC_HCTOSYS`): the image falls back to swclock until chrony steps the clock. Enable them for a correct clock from boot. |
| `sysctl: error: 'net.ipv4.tcp_syncookies' is an unknown key` at boot | harmless: Alpine's default sysctl.conf sets it, and the kernel has no `CONFIG_SYN_COOKIES` (the skeletos kernels); the service still starts |
| `refusing the cache directory ...` | the cache is not yours or others can write to it: `chmod go-w` it, or `--cache DIR` |
| `insecure = true without a sha256 = pin ... not recorded` | expected: an unauthenticated release is used once and never reused; pin `sha256 =` to cache it |

The full builder console is in `OUT.build.log`, on success too.

## Deviations from the plan, and why

- **The networking service is always enabled**, even with `dhcp = false`.
  It brings up `lo`, which many programs expect.
- **crond is in the default runlevel**, as in a stock Alpine install
  (`setup-alpine` enables it).
- **Root's console password is empty** (`root::`). The minirootfs has `*`,
  which would lock the console. Alpine's installed systems default to an
  empty password unless one is set.
- **Trailing `#` comments are not supported**: only full-line comments.
  `#` is valid in values (URLs, file names), and silently cutting a value
  would be worse than the restriction.
- **`[ssh] enable = true` requires keys**, and keys without `enable` are an
  error. A server that nobody can log in to (no passwords) is a mistake
  worth reporting.
- **`/etc/machine-id` is not generated**: Alpine (OpenRC, no systemd or
  dbus by default) does not use one. It is removed in case a package
  created it.
- **The host payload is capped at 256 MiB** (it travels in the builder's
  RAM, which is 1 GiB). Put larger data in a [run] script that downloads
  it, or copy it in with an overlay.
- **e2fsprogs-extra in the builder only**, for the dumpe2fs check of the
  inode tables (not in the image).
- **mdevd instead of busybox mdev** in sysinit (see What the image is):
  mdev needs the kernel's uevent helper, which the designated kernels
  lack.
- **hwclock on aarch64 only** (swclock with a kernel lacking rtc-pl031):
  x86_64 guests have no RTC device and get the right time from kvmclock,
  which swclock would overwrite with the last shutdown time; their `clock`
  provider is vemu's no-op `kvmclock` service instead.
- **The builder initramfs lives in the cache directory**, not the system
  temporary directory: it holds the [files] data, and the shared `/tmp`
  is readable by others on a multi-user host.
