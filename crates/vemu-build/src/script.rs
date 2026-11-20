//! The builder's `/init`: a POSIX shell script for busybox ash, run as PID
//! 1 of the builder initramfs (the Alpine minirootfs itself). It formats
//! `/dev/vda`, installs Alpine into it with `apk --root`, configures it
//! like a normal Alpine install, checks it, and prints the success marker
//! `VEMU-BUILD-OK <nonce>` (the nonce comes from `vemu.build=` on the
//! kernel command line) before powering off.
//!
//! Any failing command ends the build: `set -e` plus an EXIT trap that
//! prints `VEMU-BUILD-FAILED: <step>: ...` and powers off at once. The
//! script never drops to a shell and never waits for input. Progress lines
//! start with `vemu-build: `.
//!
//! Everything the host passes in is either validated by the config parser
//! (names, paths, URLs) or single-quoted ([`quote`]).

use std::fmt::Write as _;

use crate::config::SshServer;

/// Where the host's payload is in the builder initramfs.
pub const PAYLOAD: &str = "/vemu-build";
/// The success marker (followed by a space and the nonce).
pub const OK_MARKER: &str = "VEMU-BUILD-OK";
/// The failure marker (followed by `: <step>...`).
pub const FAIL_MARKER: &str = "VEMU-BUILD-FAILED";
/// Progress lines.
pub const STEP_PREFIX: &str = "vemu-build: ";
/// Filesystem label of the root filesystem.
pub const ROOT_LABEL: &str = "vemu-root";

/// A `[files]` item as it is in the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadItem {
    /// `/vemu-build/files/<index>` copied to `image` with `mode`.
    File {
        index: usize,
        image: String,
        mode: u32,
    },
    /// A directory created at `image` with `mode`.
    Dir { image: String, mode: u32 },
}

/// Everything the script depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub arch: String,
    /// `v3.24`.
    pub branch: String,
    /// `3.24.4` (for messages).
    pub version: String,
    pub mirror: String,
    pub community: bool,
    pub hostname: String,
    pub timezone: String,
    pub dhcp: bool,
    pub ntp: bool,
    pub ssh: Option<SshServer>,
    /// The `[packages]` list.
    pub packages: Vec<String>,
    pub files: Vec<PayloadItem>,
    /// `/vemu-build/modules.tar.gz` is present.
    pub modules: bool,
    /// The `[run]` script is present; `true` when it starts with `#!`
    /// (then it is executed directly, else with /bin/sh).
    pub run: Option<bool>,
}

impl Plan {
    /// The packages installed into the image, in order: the base system,
    /// what the features need, then `[packages]`.
    pub fn image_packages(&self) -> Vec<String> {
        // mdevd: the device manager (see runlevels()).
        let mut p: Vec<String> = ["alpine-base", "e2fsprogs", "mdevd", "mdevd-openrc"]
            .map(String::from)
            .to_vec();
        match self.ssh {
            Some(SshServer::OpenSsh) => p.push("openssh".into()),
            Some(SshServer::Dropbear) => p.extend(["dropbear".into(), "dropbear-openrc".into()]),
            None => {}
        }
        if self.ntp {
            p.push("chrony".into());
        }
        if self.timezone != "UTC" {
            p.push("tzdata".into());
        }
        if self.modules {
            p.push("kmod".into());
        }
        for x in &self.packages {
            if !p.contains(x) {
                p.push(x.clone());
            }
        }
        p
    }

    /// The clock service: `hwclock` on aarch64, `kvmclock` on x86_64.
    ///
    /// An aarch64 vemu machine has a PL031 RTC holding the host's time:
    /// `hwclock` reads it at boot, like on any machine with an RTC. The
    /// builder runs the image's own kernel, so the script checks it has the
    /// rtc-pl031 driver (/dev/rtc0) and falls back to `swclock` when it does
    /// not (the last shutdown time, i.e. the build time on a first boot,
    /// until NTP steps it); see [`CLOCK_FALLBACK`].
    ///
    /// An x86_64 guest has no RTC device; on KVM the kernel reads the host's
    /// time from the kvmclock wall clock at boot, which is right. But a
    /// service must provide OpenRC's `clock` (busybox's syslog needs it):
    /// with none in a runlevel OpenRC starts hwclock, which fails at boot
    /// and at shutdown without an RTC, and swclock would set the clock back
    /// to the last shutdown time (it moves it backwards too). So x86_64
    /// images get [`KVMCLOCK_SERVICE`], which provides `clock` and does
    /// nothing.
    pub fn clock_service(&self) -> &'static str {
        if self.arch == "aarch64" {
            "hwclock"
        } else {
            "kvmclock"
        }
    }

    /// The image's OpenRC runlevels: (runlevel, services).
    pub fn runlevels(&self) -> Vec<(&'static str, Vec<&'static str>)> {
        // mdevd, not busybox mdev: mdev's hotplug mode needs the kernel's
        // uevent helper (/proc/sys/kernel/hotplug, CONFIG_UEVENT_HELPER),
        // which kernels often lack (the skeletos ones do); its start then
        // fails on every boot. mdevd reads uevents from netlink, like
        // `setup-devd mdevd` sets up (mdevd-init is its coldplug).
        let sysinit = vec!["devfs", "dmesg", "mdevd", "mdevd-init", "hwdrivers"];
        // networking always (it brings up lo; eth0 too with dhcp). seedrng
        // is replaced by urandom on an OpenRC that lacks it (by the script).
        let mut boot = vec!["modules", "sysctl", "hostname", "bootmisc", "syslog"];
        boot.push(self.clock_service());
        boot.extend(["seedrng", "networking"]);
        let mut default = vec!["crond"];
        if self.ntp {
            default.push("chronyd");
        }
        match self.ssh {
            Some(SshServer::OpenSsh) => default.push("sshd"),
            Some(SshServer::Dropbear) => default.push("dropbear"),
            None => {}
        }
        let shutdown = vec!["mount-ro", "killprocs", "savecache"];
        vec![
            ("sysinit", sysinit),
            ("boot", boot),
            ("default", default),
            ("shutdown", shutdown),
        ]
    }

    pub fn repositories(&self) -> Vec<String> {
        let mut r = vec![format!("{}/{}/main", self.mirror, self.branch)];
        if self.community {
            r.push(format!("{}/{}/community", self.mirror, self.branch));
        }
        r
    }
}

/// Single-quote `s` for the shell.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

const HEADER: &str = r#"#!/bin/sh
# vemu build: the image builder's /init (generated; runs as PID 1 in the
# builder VM). It installs Alpine Linux into /dev/vda and powers off.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root TERM=dumb
umask 022
T=/mnt
P=/vemu-build
STEP="starting"

step() {
	STEP="$1"
	echo "vemu-build: $1"
}

# End the build: report and power off at once (never a shell, never a hang).
die() {
	trap - EXIT
	echo "VEMU-BUILD-FAILED: $STEP${1:+: $1}"
	sync
	poweroff -f
	echo o > /proc/sysrq-trigger 2>/dev/null
	exit 1
}
trap 'die "a command failed (exit status $?)"' EXIT
set -eu

# A command, up to 3 times (mirrors and networks have hiccups).
retry() {
	n=1
	until "$@"; do
		[ "$n" -lt 3 ] || return 1
		echo "vemu-build: retrying ($n): $*"
		n=$((n + 1))
		sleep 3
	done
}

# rc_add SERVICE RUNLEVEL: what rc-update add does, without a chroot.
rc_add() {
	[ -e "$T/etc/init.d/$1" ] || die "the image has no service $1 (/etc/init.d/$1)"
	mkdir -p "$T/etc/runlevels/$2"
	ln -sf "/etc/init.d/$1" "$T/etc/runlevels/$2/$1"
}

in_image() {
	chroot "$T" "$@"
}

step "mounting /proc, /sys and /dev"
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs -o nosuid,nodev,mode=1777 shm /dev/shm

NONCE=
EPOCH=
for a in $(cat /proc/cmdline); do
	case "$a" in
	vemu.build=*) NONCE="${a#vemu.build=}" ;;
	vemu.epoch=*) EPOCH="${a#vemu.epoch=}" ;;
	esac
done
[ -n "$NONCE" ] || die "no vemu.build= on the kernel command line"
case "$EPOCH" in
'' | *[!0-9]*) die "no valid vemu.epoch= on the kernel command line" ;;
esac
# The host's time (TLS certificates need a correct clock). The kernel has
# usually set it from the PL031 already; this covers kernels without it.
date -s "@$EPOCH" > /dev/null
echo "vemu-build: kernel $(uname -r), $(grep -c ^processor /proc/cpuinfo) CPUs, clock $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
[ -f "$P/manifest" ] && sed 's/^/vemu-build: manifest: /' "$P/manifest"

step "network (DHCP on eth0)"
ip link set lo up
[ -e /sys/class/net/eth0 ] || die "no eth0: the builder needs vemu's user network"
ip link set eth0 up
retry udhcpc -i eth0 -f -q -n -t 5 -T 2 > /dev/null 2>&1 || die "no DHCP lease on eth0"
[ -s /etc/resolv.conf ] || die "DHCP gave no DNS server"
echo "vemu-build: eth0 $(ip -4 -o addr show eth0 | awk '{print $4}')"
"#;

/// /etc/init.d/kvmclock, installed in x86_64 images: the `clock` provider
/// (see [`Plan::clock_service`]). The kernel has already set the clock.
pub const KVMCLOCK_SERVICE: &str = r#"#!/sbin/openrc-run
# Installed by vemu build. The kernel sets the system clock from the KVM
# paravirtual clock (kvmclock) at boot, and a vemu x86_64 machine has no
# RTC for hwclock to read or save: this service provides the "clock" that
# other services need (syslog) in place of hwclock, and does nothing.

description="System clock from kvmclock (no RTC to read or save)"

depend() {
	provide clock
}

start() {
	return 0
}
"#;

/// The aarch64 clock check, made in the builder (which runs the image's
/// kernel) once the kernel modules are installed: hwclock reads vemu's
/// PL031 through /dev/rtc0, from the built-in rtc-pl031 driver or from the
/// module (mdevd's coldplug loads it before the boot runlevel). A kernel
/// with neither gets swclock instead, which starts the clock at the last
/// shutdown time: the build time, for the first boot (chrony then sets the
/// exact time).
pub const CLOCK_FALLBACK: &str = r#"
if [ ! -e /dev/rtc0 ] &&
	[ -z "$(find "$T/lib/modules/$(uname -r)" -name 'rtc-pl031.ko*' 2>/dev/null | head -n 1)" ]; then
	echo "vemu-build: warning: the kernel has no RTC driver (/dev/rtc0; rtc-pl031): using swclock"
	rm -f "$T/etc/runlevels/boot/hwclock"
	rc_add swclock boot
	mkdir -p "$T/var/lib/misc"
	touch "$T/var/lib/misc/openrc-shutdowntime"
fi
"#;

/// The whole `/init` script.
pub fn generate(plan: &Plan) -> String {
    let mut s = String::from(HEADER);
    let w = &mut s;

    // Repositories, for the builder and the image.
    let repos = plan.repositories().join("\n");
    let _ = write!(
        w,
        r#"
step "apk repositories (Alpine {version}, {branch})"
cat > /etc/apk/repositories << 'VEMU_EOF'
{repos}
VEMU_EOF
retry apk add --no-progress -q e2fsprogs e2fsprogs-extra || die "cannot install e2fsprogs in the builder (mirror reachable?)"

step "formatting /dev/vda (ext4)"
[ -b /dev/vda ] || die "no /dev/vda: the builder needs the target disk"
# The image is a fresh sparse file, so it already reads as zeros:
# assume_storage_prezeroed makes mke2fs skip writing the inode tables and
# the journal and mark them initialized (no lazy init at mount time, which
# would write them later, into every overlay). nodiscard: vemu has none.
mkfs.ext4 -q -F -L {label} -b 4096 -i 16384 -I 256 -E assume_storage_prezeroed=1,nodiscard /dev/vda
groups=$(dumpe2fs /dev/vda 2> /dev/null | grep -c '^Group [0-9]' || true)
zeroed=$(dumpe2fs /dev/vda 2> /dev/null | grep '^Group [0-9]' | grep -c 'ITABLE_ZEROED' || true)
[ "$groups" -gt 0 ] && [ "$groups" = "$zeroed" ] ||
	die "mke2fs left inode tables to initialize lazily ($zeroed of $groups block groups zeroed)"
echo "vemu-build: $groups block groups, inode tables initialized"
mount -t ext4 /dev/vda "$T"
mkdir -p "$T/proc" "$T/sys" "$T/dev"
mount -o bind /proc "$T/proc"
mount -o bind /sys "$T/sys"
# rbind: /dev/pts (ptys) and /dev/shm come along, for the [run] script and
# package scripts.
mount -o rbind /dev "$T/dev"

step "installing packages into the image"
mkdir -p "$T/etc/apk"
cp -a /etc/apk/keys "$T/etc/apk/"
cp /etc/apk/repositories "$T/etc/apk/repositories"
echo {arch} > "$T/etc/apk/arch"
retry apk add --no-progress --root "$T" --initdb {packages} || die "apk could not install the packages"
echo "vemu-build: $(in_image apk info 2>/dev/null | wc -l) packages installed"
"#,
        version = plan.version,
        branch = plan.branch,
        label = ROOT_LABEL,
        arch = plan.arch,
        packages = plan
            .image_packages()
            .iter()
            .map(|p| quote(p))
            .collect::<Vec<_>>()
            .join(" "),
    );

    // The system configuration.
    let hostname = quote(&plan.hostname);
    let _ = write!(
        w,
        r#"
step "configuring the system"
# Root logs in on the console without a password (Alpine's default for a
# fresh install); network logins take a key only.
sed -i 's/^root:[^:]*:/root::/' "$T/etc/shadow"
# The console is virtio-console hvc0; there are no virtual terminals.
sed -i -e '/^tty[0-9]*::/d' "$T/etc/inittab"
grep -q '^hvc0::' "$T/etc/inittab" || printf '%s\n' '' '# vemu: the guest console (virtio-console)' 'hvc0::respawn:/sbin/getty -L 115200 hvc0 vt100' >> "$T/etc/inittab"
grep -qx hvc0 "$T/etc/securetty" || echo hvc0 >> "$T/etc/securetty"
printf '%s\n' '# <fs>			<mountpoint>	<type>	<opts>		<dump/pass>' 'LABEL={label}	/		ext4	rw,relatime	0 1' > "$T/etc/fstab"
echo {hostname} > "$T/etc/hostname"
printf '127.0.0.1\t%s localhost localhost.localdomain\n::1\t\tlocalhost localhost.localdomain\n' {hostname} > "$T/etc/hosts"
"#,
        label = ROOT_LABEL,
    );
    if plan.timezone != "UTC" {
        let tz = quote(&plan.timezone);
        let _ = write!(
            w,
            r#"[ -f "$T/usr/share/zoneinfo/"{tz} ] || die "unknown timezone "{tz}
ln -sf "/usr/share/zoneinfo/"{tz} "$T/etc/localtime"
echo {tz} > "$T/etc/timezone"
"#
        );
    }
    let mut interfaces = String::from("auto lo\niface lo inet loopback\n");
    if plan.dhcp {
        interfaces.push_str("\nauto eth0\niface eth0 inet dhcp\n");
    }
    let _ = write!(
        w,
        r#"cat > "$T/etc/network/interfaces" << 'VEMU_EOF'
{interfaces}VEMU_EOF
[ -e "$T/etc/init.d/seedrng" ] || SEEDRNG=urandom
"#
    );
    if !plan.modules {
        // Without a modules tarball the image has no /lib/modules: Alpine's
        // default /etc/modules entries (af_packet, ipv6) would make modprobe
        // complain at every boot.
        w.push_str(
            r#"if [ -f "$T/etc/modules" ]; then
	{
		echo '# vemu build: the image has no kernel modules (no modules = in its build'
		echo '# config), so these entries are commented out.'
		sed -e 's/^\([^#]\)/#\1/' "$T/etc/modules"
	} > /tmp/etc-modules
	cat /tmp/etc-modules > "$T/etc/modules"
fi
"#,
        );
    }
    if plan.clock_service() == "kvmclock" {
        let _ = write!(
            w,
            "cat > \"$T/etc/init.d/kvmclock\" << 'VEMU_EOF'\n{KVMCLOCK_SERVICE}VEMU_EOF\nchmod 0755 \"$T/etc/init.d/kvmclock\"\n"
        );
    }
    for (level, services) in plan.runlevels() {
        for svc in services {
            if svc == "seedrng" {
                let _ = writeln!(w, r#"rc_add "${{SEEDRNG:-seedrng}}" {level}"#);
            } else {
                let _ = writeln!(w, "rc_add {svc} {level}");
            }
        }
    }

    match plan.ssh {
        Some(SshServer::OpenSsh) => w.push_str(
            r#"
step "ssh (OpenSSH): key-only root login"
mkdir -p "$T/etc/ssh/sshd_config.d"
cat > "$T/etc/ssh/sshd_config.d/50-vemu.conf" << 'VEMU_EOF'
# vemu build: root logs in with a key only.
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
VEMU_EOF
grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$T/etc/ssh/sshd_config" ||
	sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$T/etc/ssh/sshd_config"
"#,
        ),
        Some(SshServer::Dropbear) => w.push_str(
            r#"
step "ssh (Dropbear): key-only login"
# -s: no password logins.
echo 'DROPBEAR_OPTS="-s"' > "$T/etc/conf.d/dropbear"
"#,
        ),
        None => {}
    }
    if plan.ssh.is_some() {
        w.push_str(
            r#"mkdir -p "$T/root/.ssh"
chmod 700 "$T/root/.ssh"
cp "$P/authorized_keys" "$T/root/.ssh/authorized_keys"
chmod 600 "$T/root/.ssh/authorized_keys"
"#,
        );
    }

    // The host payload, through the chroot so that symbolic links in the
    // image resolve inside it.
    let needs_payload = !plan.files.is_empty() || plan.run.is_some();
    if needs_payload {
        w.push_str(
            r#"
mkdir -p "$T/tmp/.vemu-build"
mount -o bind "$P" "$T/tmp/.vemu-build"
"#,
        );
    }
    if !plan.files.is_empty() {
        w.push_str("\nstep \"copying [files]\"\n");
        for f in &plan.files {
            match f {
                PayloadItem::Dir { image, mode } => {
                    let q = quote(image);
                    let _ = writeln!(w, "in_image mkdir -p {q}\nin_image chmod {mode:04o} {q}");
                }
                PayloadItem::File { index, image, mode } => {
                    let _ = writeln!(
                        w,
                        "in_image install -D -m {mode:04o} /tmp/.vemu-build/files/{index} {}",
                        quote(image)
                    );
                }
            }
        }
    }
    if plan.modules {
        // Unpacked in the builder's RAM and copied into the image once (an
        // unpack in the image would leave its freed blocks allocated in the
        // raw file: there is no discard).
        w.push_str(
            r#"
step "installing kernel modules"
mkdir /tmp/modules
tar -xzf "$P/modules.tar.gz" -C /tmp/modules || die "cannot unpack the modules tarball"
[ -d /tmp/modules/lib/modules ] && [ ! -L /tmp/modules/lib/modules ] ||
	die "the modules tarball has no lib/modules/ directory"
mkdir -p "$T/tmp/.vemu-modules"
mount -o bind /tmp/modules/lib/modules "$T/tmp/.vemu-modules"
in_image mkdir -p /lib/modules
in_image cp -a /tmp/.vemu-modules/. /lib/modules/
umount "$T/tmp/.vemu-modules"
rmdir "$T/tmp/.vemu-modules"
rm -rf /tmp/modules
for v in $(in_image ls /lib/modules); do
	in_image depmod -a "$v" || die "depmod failed for $v"
	echo "vemu-build: modules for kernel $v"
done
in_image test -d "/lib/modules/$(uname -r)" ||
	echo "vemu-build: warning: no modules for the builder's kernel $(uname -r)"
"#,
        );
    }
    if plan.clock_service() == "hwclock" {
        // After the modules (the driver may be one), before the [run]
        // script (which may change the choice).
        w.push_str(CLOCK_FALLBACK);
    }
    if let Some(shebang) = plan.run {
        let cmd = if shebang {
            "in_image /tmp/.vemu-build/run"
        } else {
            "in_image /bin/sh /tmp/.vemu-build/run"
        };
        let _ = write!(
            w,
            r#"
step "running the [run] script"
# The script gets the builder's DNS (the user's own resolv.conf, from
# [files] or a package, may not work from the builder's NAT). The image's
# own is put back afterwards, unless the script wrote one.
K="$T/etc/.vemu-resolv.conf.keep"
if [ -e "$T/etc/resolv.conf" ] || [ -L "$T/etc/resolv.conf" ]; then
	mv "$T/etc/resolv.conf" "$K"
fi
cp /etc/resolv.conf "$T/etc/resolv.conf"
set +e
( cd / && {cmd} )
rc=$?
set -e
[ "$rc" = 0 ] || die "the [run] script exited with status $rc"
if [ ! -L "$T/etc/resolv.conf" ] && cmp -s /etc/resolv.conf "$T/etc/resolv.conf"; then
	rm -f "$T/etc/resolv.conf"
	if [ -e "$K" ] || [ -L "$K" ]; then mv "$K" "$T/etc/resolv.conf"; fi
else
	echo "vemu-build: keeping the /etc/resolv.conf the [run] script left"
	rm -f "$K"
fi
"#
        );
    }
    if needs_payload {
        w.push_str(
            r#"umount "$T/tmp/.vemu-build" || die "cannot unmount the payload (a process from the [run] script still running?)"
rmdir "$T/tmp/.vemu-build"
"#,
        );
    }

    // Per-machine state must not be in a golden image: every VM made from
    // it generates its own on first boot.
    w.push_str(
        r#"
step "removing per-machine state (host keys, seeds, machine-id) and caches"
rm -f "$T"/etc/ssh/ssh_host_*key "$T"/etc/ssh/ssh_host_*key.pub
rm -f "$T"/etc/dropbear/dropbear_*_host_key
rm -rf "$T/var/lib/seedrng"
rm -f "$T/var/lib/misc/random-seed" "$T/etc/machine-id" "$T/var/lib/dbus/machine-id"
rm -rf "$T"/var/cache/apk/*
rm -f "$T/root/.ash_history"
for f in "$T"/etc/ssh/ssh_host_* "$T"/etc/dropbear/dropbear_*_host_key "$T/var/lib/seedrng" "$T/etc/machine-id" "$T/etc/.vemu-resolv.conf.keep"; do
	[ ! -e "$f" ] || die "per-machine file left in the image: ${f#$T}"
done
echo "vemu-build: $(df -k "$T" | awk 'NR==2 {printf "%d MiB used of %d MiB", $3/1024, $2/1024}')"

step "unmounting and checking the filesystem"
umount "$T/dev/shm" "$T/dev/pts" "$T/dev" "$T/sys" "$T/proc" || die "cannot unmount /dev, /sys or /proc of the image (a process from the [run] script still running?)"
sync
umount "$T" || die "cannot unmount the image"
e2fsck -f -n /dev/vda > /tmp/e2fsck.log 2>&1 || { cat /tmp/e2fsck.log; die "e2fsck found problems"; }
tail -n 1 /tmp/e2fsck.log | sed 's/^/vemu-build: /'
sync
trap - EXIT
echo "VEMU-BUILD-OK $NONCE"
poweroff -f
"#,
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            arch: "aarch64".into(),
            branch: "v3.24".into(),
            version: "3.24.4".into(),
            mirror: "https://dl-cdn.alpinelinux.org/alpine".into(),
            community: false,
            hostname: "vemu".into(),
            timezone: "UTC".into(),
            dhcp: true,
            ntp: true,
            ssh: None,
            packages: vec![],
            files: vec![],
            modules: false,
            run: None,
        }
    }

    fn rc_lines(s: &str, level: &str) -> Vec<String> {
        s.lines()
            .filter_map(|l| l.strip_prefix("rc_add "))
            .filter_map(|l| l.strip_suffix(&format!(" {level}")).map(str::to_string))
            .collect()
    }

    #[test]
    fn minimal_plan() {
        let p = plan();
        let s = generate(&p);
        assert!(s.starts_with("#!/bin/sh\n"));
        // Fail-fast handling, success marker with the nonce, power off.
        assert!(s.contains("set -eu"));
        assert!(s.contains("trap 'die "));
        assert!(s.contains("echo \"VEMU-BUILD-OK $NONCE\"\npoweroff -f\n"));
        assert!(s.contains("echo \"VEMU-BUILD-FAILED: $STEP"));
        assert!(
            !s.contains("exec sh") && !s.contains("/bin/sh -l"),
            "never a shell"
        );
        // The clock, the network, the target.
        assert!(s.contains(r#"date -s "@$EPOCH""#));
        assert!(s.contains("udhcpc -i eth0"));
        assert!(s.contains("assume_storage_prezeroed=1"));
        assert!(s.contains("ITABLE_ZEROED"));
        assert!(s.contains(CLOCK_FALLBACK));
        assert!(s.contains("e2fsck -f -n /dev/vda"));
        assert!(s.contains("https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n"));
        assert!(!s.contains("/community"));
        assert!(s.contains("retry apk add --no-progress --root \"$T\" --initdb 'alpine-base' 'e2fsprogs' 'mdevd' 'mdevd-openrc' 'chrony' || die"));
        // A getty on hvc0, none on tty1..6.
        assert!(s.contains("sed -i -e '/^tty[0-9]*::/d' \"$T/etc/inittab\""));
        assert!(s.contains("hvc0::respawn:/sbin/getty -L 115200 hvc0 vt100"));
        assert!(s.contains("grep -qx hvc0 \"$T/etc/securetty\""));
        assert!(s.contains("LABEL=vemu-root\t/\t\text4"));
        // Runlevels.
        // mdevd (netlink), not mdev (needs the kernel's uevent helper).
        assert_eq!(
            rc_lines(&s, "sysinit"),
            ["devfs", "dmesg", "mdevd", "mdevd-init", "hwdrivers"]
        );
        assert_eq!(
            rc_lines(&s, "boot"),
            [
                "modules",
                "sysctl",
                "hostname",
                "bootmisc",
                "syslog",
                "hwclock",
                "\"${SEEDRNG:-seedrng}\"",
                "networking"
            ]
        );
        assert_eq!(rc_lines(&s, "default"), ["crond", "chronyd"]);
        assert_eq!(
            rc_lines(&s, "shutdown"),
            ["mount-ro", "killprocs", "savecache"]
        );
        assert!(s.contains("auto eth0\niface eth0 inet dhcp\n"));
        // Per-machine state is removed and checked.
        assert!(s.contains(r#"rm -f "$T"/etc/ssh/ssh_host_*key "$T"/etc/ssh/ssh_host_*key.pub"#));
        assert!(s.contains(r#"rm -rf "$T/var/lib/seedrng""#));
        assert!(s.contains(r#""$T/etc/machine-id""#));
        // Without [run], the builder never puts a resolv.conf in the image,
        // so it removes none (a [files] one stays).
        assert!(!s.contains("$T/etc/resolv.conf"));
        // No modules: /etc/modules entries are commented out.
        assert!(s.contains("sed -e 's/^\\([^#]\\)/#\\1/' \"$T/etc/modules\""));
        // /dev for the chroot with its submounts (ptys, shm).
        assert!(s.contains("mount -t tmpfs -o nosuid,nodev,mode=1777 shm /dev/shm\n"));
        assert!(s.contains("mount -o rbind /dev \"$T/dev\"\n"));
        assert!(s.contains("umount \"$T/dev/shm\" \"$T/dev/pts\" \"$T/dev\" \"$T/sys\""));
        assert!(s.contains("rm -rf \"$T\"/var/cache/apk/*"));
        // No ssh, no payload.
        assert!(!s.contains("sshd_config") && !s.contains("authorized_keys"));
        assert!(!s.contains("/tmp/.vemu-build"));
        // The ordering: install, configure, clean up, check.
        let at = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(at("mkfs.ext4") < at("apk add --no-progress --root"));
        assert!(at("apk add --no-progress --root") < at("rc_add devfs"));
        assert!(at("rc_add devfs") < at("ssh_host_*key"));
        assert!(at("ssh_host_*key") < at("e2fsck -f -n"));
        assert!(at("e2fsck -f -n") < at("VEMU-BUILD-OK"));
    }

    #[test]
    fn features_toggle_services_and_packages() {
        let mut p = plan();
        p.ntp = false;
        p.dhcp = false;
        let s = generate(&p);
        assert_eq!(rc_lines(&s, "default"), ["crond"]);
        assert!(!s.contains("'chrony'"));
        assert!(!s.contains("auto eth0"), "no eth0 without dhcp");
        assert!(
            rc_lines(&s, "boot").contains(&"networking".to_string()),
            "lo still comes up"
        );

        let mut p = plan();
        p.ssh = Some(SshServer::OpenSsh);
        let s = generate(&p);
        assert_eq!(rc_lines(&s, "default"), ["crond", "chronyd", "sshd"]);
        assert!(p.image_packages().contains(&"openssh".to_string()));
        assert!(s.contains("PermitRootLogin prohibit-password\nPasswordAuthentication no\n"));
        assert!(s.contains("chmod 700 \"$T/root/.ssh\""));
        assert!(s.contains("chmod 600 \"$T/root/.ssh/authorized_keys\""));
        let keys_removed = s.find("ssh_host_*key").unwrap();
        assert!(keys_removed > s.find("rc_add sshd default").unwrap());

        let mut p = plan();
        p.ssh = Some(SshServer::Dropbear);
        p.timezone = "Europe/Paris".into();
        p.community = true;
        p.packages = vec!["curl".into(), "chrony".into()];
        p.modules = true;
        let s = generate(&p);
        assert_eq!(rc_lines(&s, "default"), ["crond", "chronyd", "dropbear"]);
        assert_eq!(
            p.image_packages(),
            [
                "alpine-base",
                "e2fsprogs",
                "mdevd",
                "mdevd-openrc",
                "dropbear",
                "dropbear-openrc",
                "chrony",
                "tzdata",
                "kmod",
                "curl"
            ]
        );
        assert!(s.contains("DROPBEAR_OPTS=\"-s\""));
        assert!(s.contains("dropbear_*_host_key"));
        assert!(s.contains("ln -sf \"/usr/share/zoneinfo/\"'Europe/Paris' \"$T/etc/localtime\""));
        assert!(s.contains("/v3.24/community\n"));
        assert!(s.contains("depmod -a"));
        assert!(s.contains("tar -xzf \"$P/modules.tar.gz\" -C /tmp/modules"));
        assert!(s.contains("in_image cp -a /tmp/.vemu-modules/. /lib/modules/"));
    }

    #[test]
    fn files_and_run_go_through_the_chroot() {
        let mut p = plan();
        p.files = vec![
            PayloadItem::Dir {
                image: "/opt/app".into(),
                mode: 0o750,
            },
            PayloadItem::File {
                index: 0,
                image: "/opt/app/it's here".into(),
                mode: 0o4755,
            },
        ];
        p.run = Some(false);
        let s = generate(&p);
        assert!(s.contains("in_image mkdir -p '/opt/app'\nin_image chmod 0750 '/opt/app'\n"));
        assert!(s.contains(
            "in_image install -D -m 4755 /tmp/.vemu-build/files/0 '/opt/app/it'\\''s here'\n"
        ));
        assert!(s.contains("in_image /bin/sh /tmp/.vemu-build/run"));
        assert!(s.contains("cp /etc/resolv.conf \"$T/etc/resolv.conf\""));
        // The [run] script runs after the files, before the clean-up.
        assert!(s.find("install -D").unwrap() < s.find("/tmp/.vemu-build/run").unwrap());
        assert!(s.find("/tmp/.vemu-build/run").unwrap() < s.find("ssh_host_*key").unwrap());
        // The image's own resolv.conf (from [files]) is set aside for the
        // script and put back after it, unless the script wrote one.
        let at = |n: &str| s.find(n).unwrap_or_else(|| panic!("{n}"));
        assert!(
            at("mv \"$T/etc/resolv.conf\" \"$K\"")
                < at("cp /etc/resolv.conf \"$T/etc/resolv.conf\"")
        );
        assert!(at("( cd / && in_image") < at("cmp -s /etc/resolv.conf \"$T/etc/resolv.conf\""));
        assert!(at("cmp -s /etc/resolv.conf") < at("mv \"$K\" \"$T/etc/resolv.conf\""));
        assert!(s.contains("keeping the /etc/resolv.conf the [run] script left"));
        assert!(
            s.contains("\"$T/etc/.vemu-resolv.conf.keep\"; do"),
            "checked gone"
        );
        assert!(!s.contains("rm -f \"$T/etc/resolv.conf\" \"$T/root"));
        p.run = Some(true);
        assert!(generate(&p).contains("( cd / && in_image /tmp/.vemu-build/run )"));
    }

    /// aarch64: hwclock (the PL031), or swclock (and its seed) when the
    /// kernel has no RTC driver. x86_64 guests read kvmclock's wall clock
    /// and get the no-op kvmclock service as the `clock` provider.
    #[test]
    fn clock_service_per_arch() {
        let p = plan();
        let s = generate(&p);
        assert_eq!(p.clock_service(), "hwclock");
        assert!(rc_lines(&s, "boot").contains(&"hwclock".to_string()));
        // The fallback replaces hwclock after the runlevels are written,
        // after the modules (rtc-pl031 may be one) and before [run].
        let mut p = plan();
        p.modules = true;
        p.run = Some(true);
        let s = generate(&p);
        let fallback = s.find("if [ ! -e /dev/rtc0 ] &&").unwrap();
        assert!(s.find("rc_add hwclock boot").unwrap() < fallback);
        assert!(s.find("step \"installing kernel modules\"").unwrap() < fallback);
        assert!(fallback < s.find("in_image /tmp/.vemu-build/run").unwrap());
        assert!(CLOCK_FALLBACK.contains("-name 'rtc-pl031.ko*'"));
        assert!(
            CLOCK_FALLBACK
                .contains("rm -f \"$T/etc/runlevels/boot/hwclock\"\n\trc_add swclock boot")
        );
        assert!(CLOCK_FALLBACK.contains("touch \"$T/var/lib/misc/openrc-shutdowntime\""));
        let mut p = plan();
        p.arch = "x86_64".into();
        let s = generate(&p);
        assert_eq!(p.clock_service(), "kvmclock");
        assert_eq!(
            rc_lines(&s, "boot"),
            [
                "modules",
                "sysctl",
                "hostname",
                "bootmisc",
                "syslog",
                "kvmclock",
                "\"${SEEDRNG:-seedrng}\"",
                "networking"
            ]
        );
        assert!(!s.contains("swclock") && !s.contains("openrc-shutdowntime"));
        assert!(!s.contains("rc_add hwclock") && !s.contains("/dev/rtc0"));
        // The service is written before the runlevels (rc_add checks it).
        let svc = s.find("cat > \"$T/etc/init.d/kvmclock\"").unwrap();
        assert!(svc < s.find("rc_add kvmclock boot").unwrap());
        assert!(s.contains("chmod 0755 \"$T/etc/init.d/kvmclock\""));
        assert!(KVMCLOCK_SERVICE.starts_with("#!/sbin/openrc-run\n"));
        assert!(KVMCLOCK_SERVICE.contains("\tprovide clock\n"));
        // aarch64 images do not get it.
        assert!(!generate(&plan()).contains("etc/init.d/kvmclock"));
        // With a modules tarball, /etc/modules is left as it is.
        let mut p = plan();
        p.modules = true;
        assert!(!generate(&p).contains("$T/etc/modules"));
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("plain"), "'plain'");
        assert_eq!(quote("a'b"), r"'a'\''b'");
        assert_eq!(quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }
}
