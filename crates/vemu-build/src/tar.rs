//! A tar reader for the Alpine minirootfs (and tests): ustar and GNU
//! headers, pax extended headers (`path`, `linkpath`, `size`, `uid`, `gid`,
//! `mtime`) and GNU long names (`L`, `K`).
//!
//! Member paths are normalized to relative paths without `.` or empty
//! components. Absolute paths, `..` components and member types other than
//! regular files, directories, symbolic links, hard links, character and
//! block devices and FIFOs are refused, as are bad header checksums and
//! members that run past the end of the archive.

use std::collections::HashMap;
use std::fmt;

const BLOCK: usize = 512;

/// What a member is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink(String),
    /// A hard link to an earlier regular file (its normalized path). The
    /// member's `data` is that file's.
    HardLink(String),
    CharDev {
        major: u32,
        minor: u32,
    },
    BlockDev {
        major: u32,
        minor: u32,
    },
    Fifo,
}

/// One archive member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Normalized relative path (`etc/passwd`); never empty.
    pub path: String,
    pub kind: Kind,
    /// Permission bits (`0o7777` at most).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Modification time, seconds since the epoch.
    pub mtime: u64,
    /// Contents of a regular file (or of a hard link's target); empty
    /// otherwise.
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// The member the error is about, when known.
    pub member: Option<String>,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.member {
            Some(m) => write!(f, "tar member {m:?}: {}", self.message),
            None => write!(f, "tar: {}", self.message),
        }
    }
}

impl std::error::Error for Error {}

fn err(member: Option<&str>, message: impl Into<String>) -> Error {
    Error {
        member: member.map(str::to_string),
        message: message.into(),
    }
}

/// Normalize a member path: strip `./` and empty components, refuse
/// absolute paths and `..`. `Ok(None)` for the archive root (`.` or `./`).
pub fn normalize(path: &str) -> Result<Option<String>, String> {
    if path.starts_with('/') {
        return Err("absolute path".into());
    }
    let mut parts = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err("path with a '..' component".into()),
            c => parts.push(c),
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

/// A numeric header field: octal digits (leading spaces, terminated by NUL
/// or space), or GNU base-256 when the first byte has its top bit set.
fn number(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        if field[0] & 0x40 != 0 {
            return Err("negative base-256 number".into());
        }
        let mut v: u64 = u64::from(field[0] & 0x3f);
        for &b in &field[1..] {
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(b)))
                .ok_or("base-256 number overflows")?;
        }
        return Ok(v);
    }
    let s = field
        .iter()
        .position(|&b| b != b' ')
        .map_or(&field[field.len()..], |i| &field[i..]);
    let end = s
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(s.len());
    let digits = &s[..end];
    if digits.is_empty() {
        return Ok(0);
    }
    let mut v: u64 = 0;
    for &d in digits {
        if !(b'0'..=b'7').contains(&d) {
            return Err(format!(
                "bad octal number {:?}",
                String::from_utf8_lossy(field)
            ));
        }
        v = v
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
            .ok_or("octal number overflows")?;
    }
    Ok(v)
}

/// A NUL-terminated string field.
fn text(field: &[u8]) -> Result<String, String> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec()).map_err(|_| "name is not valid UTF-8".into())
}

fn checksum_ok(h: &[u8]) -> Result<bool, String> {
    let want = number(&h[148..156])?;
    let unsigned: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(b)
            }
        })
        .sum();
    // Some old tars summed signed chars.
    let signed: i64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                i64::from(b as i8)
            }
        })
        .sum();
    Ok(want == unsigned || i64::try_from(want).is_ok_and(|w| w == signed))
}

/// Pax extended header records: `"<len> <key>=<value>\n"`.
fn pax_records(data: &[u8]) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    let mut rest = data;
    while !rest.is_empty() {
        let sp = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or("pax record without a length")?;
        let len: usize = std::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or("bad pax record length")?;
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err("bad pax record".into());
        }
        let rec =
            std::str::from_utf8(&rest[sp + 1..len - 1]).map_err(|_| "pax record is not UTF-8")?;
        let (k, v) = rec.split_once('=').ok_or("pax record without '='")?;
        map.insert(k.to_string(), v.to_string());
        rest = &rest[len..];
    }
    Ok(map)
}

fn pax_number(map: &HashMap<String, String>, key: &str) -> Result<Option<u64>, String> {
    match map.get(key) {
        None => Ok(None),
        Some(v) => {
            // mtime may be fractional ("1700000000.123456789").
            let int = v.split('.').next().unwrap_or("");
            int.parse()
                .map(Some)
                .map_err(|_| format!("bad pax {key} {v:?}"))
        }
    }
}

/// Parse a whole (uncompressed) tar archive.
pub fn parse(data: &[u8]) -> Result<Vec<Entry<'_>>, Error> {
    let mut entries: Vec<Entry<'_>> = Vec::new();
    // Path -> index of regular files, for hard links.
    let mut files: HashMap<String, usize> = HashMap::new();
    let mut pos = 0;
    let mut long_name: Option<String> = None;
    let mut long_link: Option<String> = None;
    let mut pax: Option<HashMap<String, String>> = None;
    loop {
        let Some(h) = data.get(pos..pos + BLOCK) else {
            if pos == data.len() {
                // No end-of-archive blocks; accept as GNU tar does.
                return Ok(entries);
            }
            return Err(err(None, "archive ends inside a header (truncated?)"));
        };
        if h.iter().all(|&b| b == 0) {
            // End of archive (the rest is padding).
            if long_name.is_some() || long_link.is_some() || pax.is_some() {
                return Err(err(None, "extended header with no member after it"));
            }
            return Ok(entries);
        }
        let raw_name = text(&h[..100]).map_err(|e| err(None, e))?;
        let display = long_name.clone().unwrap_or_else(|| raw_name.clone());
        let e = |m: String| err(Some(&display), m);
        if !checksum_ok(h).map_err(e)? {
            return Err(err(Some(&display), "bad header checksum"));
        }
        let typeflag = h[156];
        let mut size = number(&h[124..136]).map_err(e)?;
        if let Some(s) = pax
            .as_ref()
            .map(|p| pax_number(p, "size"))
            .transpose()
            .map_err(e)?
            .flatten()
        {
            size = s;
        }
        let start = pos + BLOCK;
        let len = usize::try_from(size).map_err(|_| e("size too large".into()))?;
        let body = start
            .checked_add(len)
            .and_then(|end| data.get(start..end))
            .ok_or_else(|| {
                e(format!(
                    "{size}-byte member runs past the end of the archive"
                ))
            })?;
        pos = start + len.div_ceil(BLOCK) * BLOCK;

        match typeflag {
            b'L' => {
                long_name = Some(text(body).map_err(e)?);
                continue;
            }
            b'K' => {
                long_link = Some(text(body).map_err(e)?);
                continue;
            }
            b'x' => {
                pax = Some(pax_records(body).map_err(e)?);
                continue;
            }
            b'g' => {
                // Global pax header: validate, but nothing in it is used.
                pax_records(body).map_err(e)?;
                continue;
            }
            _ => {}
        }

        // The member's name: pax path, GNU long name, ustar prefix + name.
        let posix = &h[257..263] == b"ustar\0";
        let mut name = raw_name;
        if posix && h[345] != 0 {
            let prefix = text(&h[345..500]).map_err(e)?;
            name = format!("{prefix}/{name}");
        }
        if let Some(n) = long_name.take() {
            name = n;
        }
        let mut link = text(&h[157..257]).map_err(e)?;
        if let Some(l) = long_link.take() {
            link = l;
        }
        let pax_hdr = pax.take();
        let mut uid = number(&h[108..116]).map_err(e)?;
        let mut gid = number(&h[116..124]).map_err(e)?;
        let mut mtime = number(&h[136..148]).map_err(e)?;
        if let Some(p) = &pax_hdr {
            if let Some(v) = p.get("path") {
                name = v.clone();
            }
            if let Some(v) = p.get("linkpath") {
                link = v.clone();
            }
            uid = pax_number(p, "uid").map_err(e)?.unwrap_or(uid);
            gid = pax_number(p, "gid").map_err(e)?.unwrap_or(gid);
            mtime = pax_number(p, "mtime").map_err(e)?.unwrap_or(mtime);
        }
        let em = |m: String| err(Some(&name), m);
        let Some(path) = normalize(&name).map_err(em)? else {
            // The archive root ("./"): nothing to create.
            if typeflag != b'5' {
                return Err(em("the archive root is not a directory".into()));
            }
            continue;
        };
        let mode = (number(&h[100..108]).map_err(em)? & 0o7777) as u32;
        let uid = u32::try_from(uid).map_err(|_| em("uid out of range".into()))?;
        let gid = u32::try_from(gid).map_err(|_| em("gid out of range".into()))?;
        let dev = || -> Result<(u32, u32), Error> {
            let major = number(&h[329..337]).map_err(em)?;
            let minor = number(&h[337..345]).map_err(em)?;
            Ok((
                u32::try_from(major).map_err(|_| em("device major out of range".into()))?,
                u32::try_from(minor).map_err(|_| em("device minor out of range".into()))?,
            ))
        };
        let mut file_data: &[u8] = &[];
        let kind = match typeflag {
            b'0' | 0 | b'7' => {
                file_data = body;
                Kind::File
            }
            b'5' => Kind::Dir,
            b'2' => {
                if link.is_empty() {
                    return Err(em("symbolic link with an empty target".into()));
                }
                Kind::Symlink(link)
            }
            b'1' => {
                let target = normalize(&link)
                    .map_err(|m| em(format!("hard link target: {m}")))?
                    .ok_or_else(|| em("hard link to the archive root".into()))?;
                let &i = files.get(&target).ok_or_else(|| {
                    em(format!(
                        "hard link to {target:?}, which is not an earlier regular file"
                    ))
                })?;
                file_data = entries[i].data;
                Kind::HardLink(target)
            }
            b'3' => {
                let (major, minor) = dev()?;
                Kind::CharDev { major, minor }
            }
            b'4' => {
                let (major, minor) = dev()?;
                Kind::BlockDev { major, minor }
            }
            b'6' => Kind::Fifo,
            t => {
                return Err(em(format!("unsupported member type {:?}", char::from(t))));
            }
        };
        if kind == Kind::File {
            files.insert(path.clone(), entries.len());
        } else {
            files.remove(&path);
        }
        entries.push(Entry {
            path,
            kind,
            mode,
            uid,
            gid,
            mtime,
            data: file_data,
        });
    }
}

/// Test helper: build archives (also used by other modules' tests).
#[cfg(test)]
pub mod build {
    /// One ustar header + padded body.
    pub fn header(
        name: &str,
        typeflag: u8,
        mode: u32,
        body: &[u8],
        link: &str,
        posix: bool,
    ) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let oct = |h: &mut [u8; 512], at: usize, width: usize, v: u64| {
            let s = format!("{v:0w$o}\0", w = width - 1);
            h[at..at + width].copy_from_slice(s.as_bytes());
        };
        oct(&mut h, 100, 8, u64::from(mode));
        oct(&mut h, 108, 8, 0);
        oct(&mut h, 116, 8, 42);
        oct(&mut h, 124, 12, body.len() as u64);
        oct(&mut h, 136, 12, 1_700_000_000);
        h[156] = typeflag;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        if posix {
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
        } else {
            h[257..265].copy_from_slice(b"ustar  \0");
        }
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        let mut out = h.to_vec();
        out.extend_from_slice(body);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    pub fn file(name: &str, mode: u32, body: &[u8]) -> Vec<u8> {
        header(name, b'0', mode, body, "", false)
    }

    pub fn end() -> Vec<u8> {
        vec![0; 1024]
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn pax(records: &[(&str, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in records {
            let rec_len = |n: usize| format!("{n} {k}={v}\n").len();
            let mut n = rec_len(0);
            while rec_len(n) != n {
                n = rec_len(n);
            }
            body.extend_from_slice(format!("{n} {k}={v}\n").as_bytes());
        }
        header("PaxHeaders/x", b'x', 0o644, &body, "", true)
    }

    #[test]
    fn basic_members() {
        let mut t = Vec::new();
        t.extend(header("./", b'5', 0o755, b"", "", false));
        t.extend(header("./etc/", b'5', 0o755, b"", "", false));
        t.extend(file("./etc/passwd", 0o644, b"root:x:0:0\n"));
        t.extend(header("./bin/sh", b'2', 0o777, b"", "/bin/busybox", false));
        t.extend(header(
            "./etc/hard",
            b'1',
            0o644,
            b"",
            "./etc/passwd",
            false,
        ));
        t.extend(header("./dev/null", b'3', 0o666, b"", "", false));
        t.extend(header("./tmp", b'5', 0o1777, b"", "", false));
        t.extend(header("./fifo", b'6', 0o600, b"", "", false));
        t.extend(end());
        let e = parse(&t).unwrap();
        let paths: Vec<_> = e.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "etc",
                "etc/passwd",
                "bin/sh",
                "etc/hard",
                "dev/null",
                "tmp",
                "fifo"
            ]
        );
        assert_eq!(e[1].data, b"root:x:0:0\n");
        assert_eq!(
            (e[1].mode, e[1].uid, e[1].gid, e[1].mtime),
            (0o644, 0, 42, 1_700_000_000)
        );
        assert_eq!(e[2].kind, Kind::Symlink("/bin/busybox".into()));
        assert_eq!(e[3].kind, Kind::HardLink("etc/passwd".into()));
        assert_eq!(e[3].data, b"root:x:0:0\n");
        assert_eq!(e[4].kind, Kind::CharDev { major: 0, minor: 0 });
        assert_eq!(e[5].mode, 0o1777);
        assert_eq!(e[6].kind, Kind::Fifo);
    }

    #[test]
    fn long_names() {
        let long = format!("usr/share/{}/file.txt", "d".repeat(150));
        let mut t = Vec::new();
        // GNU: an 'L' member carrying the name, then the real header.
        let mut name = long.clone().into_bytes();
        name.push(0);
        t.extend(header("././@LongLink", b'L', 0o644, &name, "", false));
        t.extend(file(&long[..99], 0o644, b"gnu"));
        // GNU long link target.
        let target = format!("/{}", "t".repeat(120));
        let mut tb = target.clone().into_bytes();
        tb.push(0);
        t.extend(header("././@LongLink", b'K', 0o644, &tb, "", false));
        t.extend(header("lnk", b'2', 0o777, b"", "short", false));
        // pax path, linkpath, uid, mtime (fractional).
        let pax_name = format!("var/{}/pax.txt", "p".repeat(200));
        t.extend(pax(&[
            ("path", &pax_name),
            ("uid", "1000"),
            ("mtime", "1700000001.5"),
        ]));
        t.extend(file("short-name", 0o600, b"pax"));
        // POSIX ustar prefix field.
        let mut h = header("name.txt", b'0', 0o644, b"pfx", "", true);
        h[345..352].copy_from_slice(b"a/b/cde");
        h[148..156].fill(b' ');
        let sum: u32 = h[..512].iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        t.extend(h);
        // A global pax header is accepted and ignored.
        let mut g = pax(&[("comment", "hello")]);
        g[156] = b'g';
        g[148..156].fill(b' ');
        let sum: u32 = g[..512].iter().map(|&b| u32::from(b)).sum();
        g[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        t.extend(g);
        t.extend(end());
        let e = parse(&t).unwrap();
        assert_eq!(e.len(), 4);
        assert_eq!(
            (e[0].path.as_str(), e[0].data),
            (long.as_str(), &b"gnu"[..])
        );
        assert_eq!(e[1].kind, Kind::Symlink(target));
        assert_eq!(e[2].path, pax_name);
        assert_eq!(
            (e[2].uid, e[2].mtime, e[2].mode),
            (1000, 1_700_000_001, 0o600)
        );
        assert_eq!(e[3].path, "a/b/cde/name.txt");
    }

    #[test]
    fn refusals() {
        let one = |h: Vec<u8>| {
            let mut t = h;
            t.extend(end());
            parse(&t).map(|e| e.len()).map_err(|e| e.to_string())
        };
        let msg = one(file("/etc/passwd", 0o644, b"x")).unwrap_err();
        assert!(msg.contains("absolute"), "{msg}");
        let msg = one(file("etc/../../x", 0o644, b"x")).unwrap_err();
        assert!(msg.contains(".."), "{msg}");
        let msg = one(header("sock", b'S', 0o644, b"", "", false)).unwrap_err();
        assert!(msg.contains("unsupported member type 'S'"), "{msg}");
        let msg = one(header("hl", b'1', 0o644, b"", "missing", false)).unwrap_err();
        assert!(msg.contains("not an earlier regular file"), "{msg}");
        let msg = one(header("hl", b'1', 0o644, b"", "../x", false)).unwrap_err();
        assert!(msg.contains(".."), "{msg}");
        let msg = one(header("s", b'2', 0o777, b"", "", false)).unwrap_err();
        assert!(msg.contains("empty target"), "{msg}");
        // pax path is checked too.
        let mut t = pax(&[("path", "/abs")]);
        t.extend(file("ok", 0o644, b""));
        let msg = one(t).unwrap_err();
        assert!(msg.contains("absolute"), "{msg}");
        // Bad checksum.
        let mut h = file("f", 0o644, b"data");
        h[0] = b'g';
        let msg = one(h).unwrap_err();
        assert!(msg.contains("checksum"), "{msg}");
        // A member running past the end.
        let mut t = file("f", 0o644, &[7u8; 2000]);
        t.truncate(1024);
        assert!(parse(&t).unwrap_err().to_string().contains("past the end"));
        // Truncated header.
        assert!(
            parse(&[1u8; 100])
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
        // A dangling long name.
        let mut t = header("././@LongLink", b'L', 0o644, b"x\0", "", false);
        t.extend(end());
        assert!(parse(&t).unwrap_err().to_string().contains("no member"));
    }

    #[test]
    fn numbers_and_paths() {
        assert_eq!(number(b"0000644\0"), Ok(0o644));
        assert_eq!(number(b"   755 \0"), Ok(0o755));
        assert_eq!(number(b"\0\0\0\0"), Ok(0));
        assert_eq!(number(&[0x80, 0, 0, 0, 0, 0, 1, 0]), Ok(256));
        assert!(number(b"0009").is_err());
        assert!(number(&[0xff, 0xff]).is_err());
        assert_eq!(normalize("./a//b/./c/"), Ok(Some("a/b/c".into())));
        assert_eq!(normalize("./"), Ok(None));
        assert!(normalize("a/../b").is_err());
        // No end-of-archive marker at all is accepted.
        assert_eq!(parse(&file("f", 0o644, b"x")).unwrap().len(), 1);
        assert_eq!(parse(&[]).unwrap().len(), 0);
    }
}
