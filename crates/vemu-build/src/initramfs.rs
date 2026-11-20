//! The builder initramfs: the Alpine minirootfs (a tar.gz) converted to an
//! uncompressed cpio, plus `/init` (the generated script), `/dev/console`
//! and the host payload under `/vemu-build/`.
//!
//! Members keep their tar modes, owners and times (the minirootfs is all
//! uid 0, with `/etc/shadow` in group shadow). The cpio is what the kernel
//! sees as its root filesystem, so nothing here touches the host's files.

use std::io::Write;

use crate::cpio::{Meta, Writer};
use crate::inflate;
use crate::script::PayloadItem;
use crate::tar::{self, Kind};

/// Largest decompressed minirootfs accepted (it is ~9 MiB).
pub const MAX_ROOTFS: usize = 256 << 20;

/// What the host passes to the guest, besides the script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Payload {
    /// `authorized_keys` for root (all the configured key files).
    pub authorized_keys: Option<Vec<u8>>,
    /// `[files]` items; `File { index }` data is `file_data[index]`.
    pub files: Vec<PayloadItem>,
    pub file_data: Vec<Vec<u8>>,
    /// The kernel modules tarball (gzip).
    pub modules: Option<Vec<u8>>,
    /// The `[run]` script.
    pub run: Option<Vec<u8>>,
    /// Human-readable summary, printed in the build log.
    pub manifest: String,
}

impl Payload {
    /// Total bytes of host data carried.
    pub fn size(&self) -> usize {
        self.authorized_keys.as_ref().map_or(0, Vec::len)
            + self.file_data.iter().map(Vec::len).sum::<usize>()
            + self.modules.as_ref().map_or(0, Vec::len)
            + self.run.as_ref().map_or(0, Vec::len)
    }
}

/// Write the initramfs to `out`; returns its size in bytes.
pub fn write<W: Write>(
    rootfs_tar_gz: &[u8],
    init: &str,
    payload: &Payload,
    out: W,
) -> Result<u64, String> {
    let tar = inflate::gunzip(rootfs_tar_gz, MAX_ROOTFS).map_err(|e| format!("minirootfs: {e}"))?;
    let entries = tar::parse(&tar).map_err(|e| format!("minirootfs: {e}"))?;
    let io = |e: std::io::Error| format!("writing the builder initramfs: {e}");
    let mut w = Writer::new(out);
    let mut has_console = false;
    for e in &entries {
        // Ours, written below.
        if e.path == "init" || e.path == "vemu-build" || e.path.starts_with("vemu-build/") {
            continue;
        }
        let meta = Meta {
            perm: e.mode,
            uid: e.uid,
            gid: e.gid,
            mtime: u32::try_from(e.mtime).unwrap_or(u32::MAX),
        };
        match &e.kind {
            Kind::File | Kind::HardLink(_) => w.file(&e.path, meta, e.data),
            Kind::Dir => w.dir(&e.path, meta),
            Kind::Symlink(t) => w.symlink(&e.path, t, meta),
            Kind::CharDev { major, minor } => {
                has_console |= e.path == "dev/console";
                w.device(&e.path, false, meta, *major, *minor)
            }
            Kind::BlockDev { major, minor } => w.device(&e.path, true, meta, *major, *minor),
            Kind::Fifo => w.fifo(&e.path, meta),
        }
        .map_err(io)?;
    }
    // The kernel opens /dev/console for init's stdio before anything is
    // mounted.
    if !has_console {
        w.device("dev/console", false, Meta::root(0o600), 5, 1)
            .map_err(io)?;
    }
    w.file("init", Meta::root(0o755), init.as_bytes())
        .map_err(io)?;
    w.dir("vemu-build", Meta::root(0o700)).map_err(io)?;
    w.file(
        "vemu-build/manifest",
        Meta::root(0o644),
        payload.manifest.as_bytes(),
    )
    .map_err(io)?;
    if let Some(k) = &payload.authorized_keys {
        w.file("vemu-build/authorized_keys", Meta::root(0o600), k)
            .map_err(io)?;
    }
    if !payload.file_data.is_empty() {
        w.dir("vemu-build/files", Meta::root(0o700)).map_err(io)?;
        for (i, d) in payload.file_data.iter().enumerate() {
            w.file(&format!("vemu-build/files/{i}"), Meta::root(0o600), d)
                .map_err(io)?;
        }
    }
    if let Some(m) = &payload.modules {
        w.file("vemu-build/modules.tar.gz", Meta::root(0o600), m)
            .map_err(io)?;
    }
    if let Some(r) = &payload.run {
        w.file("vemu-build/run", Meta::root(0o755), r).map_err(io)?;
    }
    let len = w.len();
    w.finish().map_err(io)?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpio::{S_IFCHR, S_IFDIR, S_IFLNK, S_IFREG, read};
    use crate::tar::build::{end, file, header};

    /// gzip with stored blocks (no compressor needed in tests).
    pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(65535).collect()
        };
        for (i, c) in chunks.iter().enumerate() {
            g.push(u8::from(i + 1 == chunks.len()));
            let n = c.len() as u16;
            g.extend_from_slice(&n.to_le_bytes());
            g.extend_from_slice(&(!n).to_le_bytes());
            g.extend_from_slice(c);
        }
        g.extend_from_slice(&inflate::crc32(data).to_le_bytes());
        g.extend_from_slice(&(data.len() as u32).to_le_bytes());
        g
    }

    #[test]
    fn rootfs_plus_payload() {
        let mut t = Vec::new();
        t.extend(header("./", b'5', 0o755, b"", "", false));
        t.extend(header("./etc/", b'5', 0o755, b"", "", false));
        t.extend(file("./etc/shadow", 0o640, b"root:*::0:::::\n"));
        t.extend(header("./bin/sh", b'2', 0o777, b"", "/bin/busybox", false));
        t.extend(header("./tmp/", b'5', 0o1777, b"", "", false));
        t.extend(file("./init", 0o755, b"not ours"));
        t.extend(end());
        let payload = Payload {
            authorized_keys: Some(b"ssh-ed25519 AAAA test\n".to_vec()),
            files: vec![PayloadItem::File {
                index: 0,
                image: "/etc/motd".into(),
                mode: 0o644,
            }],
            file_data: vec![b"hello\n".to_vec()],
            modules: Some(vec![0x1f, 0x8b]),
            run: Some(b"#!/bin/sh\necho hi\n".to_vec()),
            manifest: "release 3.24.4\n".into(),
        };
        let mut out = Vec::new();
        let n = write(&gzip_stored(&t), "#!/bin/sh\n# init\n", &payload, &mut out).unwrap();
        assert!(n > 0 && out.len() as u64 > n);
        let m = read::parse(&out);
        let get = |n: &str| {
            m.iter()
                .find(|m| m.name == n)
                .unwrap_or_else(|| panic!("no {n}"))
        };
        let shadow = get("etc/shadow");
        assert_eq!(
            (shadow.mode, shadow.uid, shadow.gid),
            (S_IFREG | 0o640, 0, 42)
        );
        assert_eq!(get("bin/sh").mode, S_IFLNK | 0o777);
        assert_eq!(get("tmp").mode, S_IFDIR | 0o1777);
        assert_eq!(
            (get("dev/console").mode, get("dev/console").rdev),
            (S_IFCHR | 0o600, (5, 1))
        );
        // The rootfs's own /init is replaced by ours (written once).
        assert_eq!(m.iter().filter(|m| m.name == "init").count(), 1);
        assert_eq!(get("init").data, b"#!/bin/sh\n# init\n");
        assert_eq!(get("init").mode, S_IFREG | 0o755);
        assert_eq!(get("vemu-build").mode, S_IFDIR | 0o700);
        assert_eq!(
            get("vemu-build/authorized_keys").data,
            b"ssh-ed25519 AAAA test\n"
        );
        assert_eq!(get("vemu-build/files/0").data, b"hello\n");
        assert_eq!(get("vemu-build/modules.tar.gz").data, [0x1f, 0x8b]);
        assert_eq!(get("vemu-build/run").mode, S_IFREG | 0o755);
        assert_eq!(get("vemu-build/manifest").data, b"release 3.24.4\n");
        assert_eq!(payload.size(), 22 + 6 + 2 + 18);
    }

    #[test]
    fn bad_rootfs_is_refused() {
        let mut out = Vec::new();
        let e = write(b"not gzip", "", &Payload::default(), &mut out).unwrap_err();
        assert!(e.starts_with("minirootfs: not a usable gzip"), "{e}");
        let mut t = file("/abs", 0o644, b"x");
        t.extend(end());
        let e = write(&gzip_stored(&t), "", &Payload::default(), &mut out).unwrap_err();
        assert!(e.contains("absolute"), "{e}");
    }
}
