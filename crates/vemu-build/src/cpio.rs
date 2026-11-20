//! A cpio "newc" (SVR4, `070701`) archive writer: the format the Linux
//! kernel unpacks as an initramfs (Documentation/driver-api/early-userspace/
//! buffer-format.rst).
//!
//! The kernel creates each member as it comes and never creates missing
//! parent directories, so the writer emits a parent directory (0755,
//! root) before any member whose parent it has not seen yet. Hard links
//! are written as separate copies (an initramfs does not need them
//! shared). The archive is uncompressed: the builder's kernel takes it as
//! is.

use std::collections::HashSet;
use std::io::{self, Write};

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFIFO: u32 = 0o010000;

/// Owner, permissions and time of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// Permission bits (`0o7777` at most).
    pub perm: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
}

impl Meta {
    /// Owned by root, with the given permissions, time 0.
    pub fn root(perm: u32) -> Meta {
        Meta {
            perm,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }
}

pub struct Writer<W: Write> {
    out: W,
    ino: u32,
    dirs: HashSet<String>,
    written: u64,
}

impl<W: Write> Writer<W> {
    pub fn new(out: W) -> Writer<W> {
        Writer {
            out,
            ino: 1,
            dirs: HashSet::new(),
            written: 0,
        }
    }

    /// Bytes written so far.
    pub fn len(&self) -> u64 {
        self.written
    }

    pub fn is_empty(&self) -> bool {
        self.written == 0
    }

    pub fn dir(&mut self, path: &str, meta: Meta) -> io::Result<()> {
        self.member(path, S_IFDIR, meta, 2, (0, 0), &[])?;
        self.dirs.insert(path.to_string());
        Ok(())
    }

    pub fn file(&mut self, path: &str, meta: Meta, data: &[u8]) -> io::Result<()> {
        self.member(path, S_IFREG, meta, 1, (0, 0), data)
    }

    pub fn symlink(&mut self, path: &str, target: &str, meta: Meta) -> io::Result<()> {
        let meta = Meta {
            perm: 0o777,
            ..meta
        };
        self.member(path, S_IFLNK, meta, 1, (0, 0), target.as_bytes())
    }

    /// A character (`block = false`) or block device node.
    pub fn device(
        &mut self,
        path: &str,
        block: bool,
        meta: Meta,
        major: u32,
        minor: u32,
    ) -> io::Result<()> {
        let kind = if block { S_IFBLK } else { S_IFCHR };
        self.member(path, kind, meta, 1, (major, minor), &[])
    }

    pub fn fifo(&mut self, path: &str, meta: Meta) -> io::Result<()> {
        self.member(path, S_IFIFO, meta, 1, (0, 0), &[])
    }

    /// Write the trailer and return the output.
    pub fn finish(mut self) -> io::Result<W> {
        self.raw("TRAILER!!!", 0, Meta::root(0), 1, (0, 0), &[], 0)?;
        self.out.flush()?;
        Ok(self.out)
    }

    fn member(
        &mut self,
        path: &str,
        kind: u32,
        meta: Meta,
        nlink: u32,
        rdev: (u32, u32),
        data: &[u8],
    ) -> io::Result<()> {
        if path.is_empty()
            || path.starts_with('/')
            || path
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
            || path.contains('\0')
            || path == "TRAILER!!!"
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad cpio member path {path:?}"),
            ));
        }
        if meta.perm & !0o7777 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{path}: bad mode {:o}", meta.perm),
            ));
        }
        // Parents first: the kernel does not create them.
        let mut i = 0;
        while let Some(off) = path[i..].find('/') {
            let parent = &path[..i + off];
            if !self.dirs.contains(parent) {
                self.raw(
                    parent,
                    S_IFDIR | 0o755,
                    Meta::root(0o755),
                    2,
                    (0, 0),
                    &[],
                    0,
                )?;
                self.dirs.insert(parent.to_string());
            }
            i += off + 1;
        }
        let ino = self.ino;
        self.ino += 1;
        self.raw(path, kind | meta.perm, meta, nlink, rdev, data, ino)
    }

    #[allow(clippy::too_many_arguments)]
    fn raw(
        &mut self,
        name: &str,
        mode: u32,
        meta: Meta,
        nlink: u32,
        rdev: (u32, u32),
        data: &[u8],
        ino: u32,
    ) -> io::Result<()> {
        let size = u32::try_from(data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name}: larger than 4 GiB"),
            )
        })?;
        let ino = if ino == 0 && name != "TRAILER!!!" {
            let i = self.ino;
            self.ino += 1;
            i
        } else {
            ino
        };
        let namesize = name.len() as u32 + 1;
        let header = format!(
            "070701{ino:08X}{mode:08X}{uid:08X}{gid:08X}{nlink:08X}{mtime:08X}{size:08X}\
             {dmaj:08X}{dmin:08X}{rmaj:08X}{rmin:08X}{namesize:08X}{check:08X}",
            uid = meta.uid,
            gid = meta.gid,
            mtime = meta.mtime,
            dmaj = 0,
            dmin = 0,
            rmaj = rdev.0,
            rmin = rdev.1,
            check = 0,
        );
        let mut head = header.into_bytes();
        head.extend_from_slice(name.as_bytes());
        head.push(0);
        pad4(&mut head);
        self.out.write_all(&head)?;
        self.out.write_all(data)?;
        let pad = (4 - data.len() % 4) % 4;
        self.out.write_all(&[0u8; 3][..pad])?;
        self.written += (head.len() + data.len() + pad) as u64;
        Ok(())
    }
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

/// Test helper: a newc parser, the kernel's view of an archive.
#[cfg(test)]
pub mod read {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Member {
        pub name: String,
        pub ino: u32,
        pub mode: u32,
        pub uid: u32,
        pub gid: u32,
        pub nlink: u32,
        pub mtime: u32,
        pub rdev: (u32, u32),
        pub data: Vec<u8>,
    }

    /// Every member up to the trailer (excluded). Panics on bad input.
    pub fn parse(mut b: &[u8]) -> Vec<Member> {
        let mut out = Vec::new();
        let total = b.len();
        loop {
            assert_eq!((total - b.len()) % 4, 0, "header alignment");
            assert_eq!(&b[..6], b"070701", "magic");
            let f = |i: usize| {
                u32::from_str_radix(std::str::from_utf8(&b[6 + i * 8..14 + i * 8]).unwrap(), 16)
                    .unwrap()
            };
            let (ino, mode, uid, gid, nlink, mtime, size) =
                (f(0), f(1), f(2), f(3), f(4), f(5), f(6));
            let rdev = (f(9), f(10));
            let namesize = f(11) as usize;
            assert_eq!(f(12), 0, "check");
            let name_end = 110 + namesize;
            assert_eq!(b[name_end - 1], 0, "NUL-terminated name");
            let name = String::from_utf8(b[110..name_end - 1].to_vec()).unwrap();
            let data_start = name_end.div_ceil(4) * 4;
            let data_end = data_start + size as usize;
            let data = b[data_start..data_end].to_vec();
            b = &b[data_end.div_ceil(4) * 4..];
            if name == "TRAILER!!!" {
                assert!(b.is_empty(), "nothing after the trailer");
                return out;
            }
            out.push(Member {
                name,
                ino,
                mode,
                uid,
                gid,
                nlink,
                mtime,
                rdev,
                data,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut w = Writer::new(Vec::new());
        w.dir("etc", Meta::root(0o755)).unwrap();
        w.file(
            "etc/shadow",
            Meta {
                perm: 0o640,
                uid: 0,
                gid: 42,
                mtime: 1_700_000_000,
            },
            b"root:*::0:::::\n",
        )
        .unwrap();
        // Parents created on demand.
        w.file(
            "usr/share/udhcpc/default.script",
            Meta::root(0o755),
            b"#!/bin/sh\n",
        )
        .unwrap();
        w.symlink("bin/sh", "/bin/busybox", Meta::root(0o777))
            .unwrap();
        w.device("dev/console", false, Meta::root(0o600), 5, 1)
            .unwrap();
        w.device("dev/vda", true, Meta::root(0o660), 254, 0)
            .unwrap();
        w.fifo("run/fifo", Meta::root(0o600)).unwrap();
        w.dir("tmp", Meta::root(0o1777)).unwrap();
        w.file("init", Meta::root(0o755), b"x").unwrap();
        let n = w.len();
        let bytes = w.finish().unwrap();
        assert!(bytes.len() as u64 > n);
        let m = read::parse(&bytes);
        let names: Vec<_> = m.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "etc",
                "etc/shadow",
                "usr",
                "usr/share",
                "usr/share/udhcpc",
                "usr/share/udhcpc/default.script",
                "bin",
                "bin/sh",
                "dev",
                "dev/console",
                "dev/vda",
                "run",
                "run/fifo",
                "tmp",
                "init"
            ]
        );
        let get = |n: &str| m.iter().find(|m| m.name == n).unwrap();
        let s = get("etc/shadow");
        assert_eq!(
            (s.mode, s.uid, s.gid, s.mtime, s.nlink),
            (S_IFREG | 0o640, 0, 42, 1_700_000_000, 1)
        );
        assert_eq!(s.data, b"root:*::0:::::\n");
        assert_eq!(get("usr/share").mode, S_IFDIR | 0o755);
        assert_eq!(get("bin/sh").mode, S_IFLNK | 0o777);
        assert_eq!(get("bin/sh").data, b"/bin/busybox");
        assert_eq!(
            (get("dev/console").mode, get("dev/console").rdev),
            (S_IFCHR | 0o600, (5, 1))
        );
        assert_eq!(
            (get("dev/vda").mode, get("dev/vda").rdev),
            (S_IFBLK | 0o660, (254, 0))
        );
        assert_eq!(get("run/fifo").mode, S_IFIFO | 0o600);
        assert_eq!(get("tmp").mode, S_IFDIR | 0o1777);
        // Inode numbers are unique.
        let mut inos: Vec<_> = m.iter().map(|m| m.ino).collect();
        inos.sort_unstable();
        inos.dedup();
        assert_eq!(inos.len(), m.len());
    }

    #[test]
    fn data_padding() {
        for len in 0..9 {
            let mut w = Writer::new(Vec::new());
            let data: Vec<u8> = (0..len as u8).collect();
            w.file("f", Meta::root(0o644), &data).unwrap();
            w.file("g", Meta::root(0o644), b"after").unwrap();
            let bytes = w.finish().unwrap();
            assert_eq!(bytes.len() % 4, 0);
            let m = read::parse(&bytes);
            assert_eq!(m[0].data, data);
            assert_eq!(m[1].data, b"after");
        }
    }

    #[test]
    fn bad_paths_are_refused() {
        let mut w = Writer::new(Vec::new());
        for p in ["", "/abs", "a/../b", "a//b", "./a", "TRAILER!!!"] {
            assert!(w.file(p, Meta::root(0o644), b"").is_err(), "{p:?}");
        }
        assert!(w.file("ok", Meta::root(0o10644), b"").is_err());
    }
}
