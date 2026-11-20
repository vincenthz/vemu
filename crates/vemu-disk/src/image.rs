//! Overlay files on disk: creating them, opening them on their golden
//! image (locking, the base reference, the fingerprint check), throwaway
//! snapshots, and `info`.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::buf::{ReadBuf, WriteBuf};
use crate::format::{
    DEFAULT_BLOCK_SIZE, Fingerprint, Fnv64, Header, MAGIC, MAX_BLOCK_SIZE, SAMPLE_LEN,
    check_block_size, sample_offsets, stored_base_path,
};
use crate::io::{FileStorage, pread_all, pwrite_all, sync_fd};
use crate::lock::{LockedFile, Role};
use crate::overlay::{Overlay, load_bitmap, read_header};

/// `e` with `what` in front of its message (same kind).
pub(crate) fn context(e: io::Error, what: impl fmt::Display) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Whether `file` starts with the overlay magic.
pub(crate) fn has_overlay_magic(file: &File) -> io::Result<bool> {
    let mut head = [0u8; MAGIC.len()];
    loop {
        // SAFETY: pread into a local array of the given length.
        let r = unsafe { libc::pread(file.as_raw_fd(), head.as_mut_ptr().cast(), head.len(), 0) };
        if r >= 0 {
            return Ok(r as usize == head.len() && head == MAGIC);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Size of `file` (seeking works for block devices too).
fn size_of(file: &File) -> io::Result<u64> {
    let mut f = file;
    f.seek(SeekFrom::End(0))
}

fn mtime_ns(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}

/// The fingerprint of a golden image: size, mtime and sampled digest. Reads
/// at most `SAMPLES * SAMPLE_LEN` (1 MiB), however big the image is.
pub fn fingerprint(file: &File) -> io::Result<Fingerprint> {
    let size = size_of(file)?;
    let mtime = mtime_ns(file.metadata()?.modified()?);
    let mut h = Fnv64::new();
    h.update(&size.to_le_bytes());
    let mut buf = vec![0u8; SAMPLE_LEN as usize];
    for off in sample_offsets(size) {
        let n = SAMPLE_LEN.min(size - off) as usize;
        pread_all(file.as_raw_fd(), ReadBuf::new(&mut buf[..n]), off)?;
        h.update(&off.to_le_bytes());
        h.update(&buf[..n]);
    }
    Ok(Fingerprint {
        size,
        mtime_ns: mtime,
        digest: h.finish(),
    })
}

fn fmt_time(ns: i64) -> String {
    format!(
        "{}.{:09}",
        ns.div_euclid(1_000_000_000),
        ns.rem_euclid(1_000_000_000)
    )
}

/// What differs between the recorded and the current fingerprint, if
/// anything.
pub fn fingerprint_changes(recorded: &Fingerprint, now: &Fingerprint) -> Option<String> {
    let mut d = Vec::new();
    if recorded.size != now.size {
        d.push(format!("size was {}, now {}", recorded.size, now.size));
    }
    if recorded.mtime_ns != now.mtime_ns {
        d.push(format!(
            "modification time was {}, now {}",
            fmt_time(recorded.mtime_ns),
            fmt_time(now.mtime_ns)
        ));
    }
    if recorded.digest != now.digest {
        d.push("sampled content differs".into());
    }
    (!d.is_empty()).then(|| d.join("; "))
}

/// Open the golden image `path` read-only with a shared lock, refusing an
/// overlay (no chains).
fn open_golden(path: &Path) -> io::Result<LockedFile> {
    let f = File::open(path).map_err(|e| {
        context(
            e,
            format_args!("cannot open the golden image {}", path.display()),
        )
    })?;
    let f = LockedFile::lock(f, false, Role::Golden(path))?;
    check_not_overlay(f.file(), path)?;
    Ok(f)
}

fn check_not_overlay(file: &File, path: &Path) -> io::Result<()> {
    if has_overlay_magic(file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the golden image {} is itself a vemu overlay: overlay chains are not \
                 supported (the golden image must be a raw image)",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn canonical_dir_of(path: &Path) -> io::Result<PathBuf> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    fs::canonicalize(dir).map_err(|e| context(e, format_args!("directory {}", dir.display())))
}

/// Where the golden image of the overlay at `overlay` is: `stored` itself
/// if absolute, else relative to the overlay's (canonical) directory.
pub fn resolve_base(overlay: &Path, stored: &Path) -> io::Result<PathBuf> {
    if stored.is_absolute() {
        return Ok(stored.to_path_buf());
    }
    let canon = fs::canonicalize(overlay)?;
    Ok(canon.parent().unwrap_or(Path::new("/")).join(stored))
}

/// Create a persistent overlay `overlay` on the raw golden image `base`.
/// Refuses an existing `overlay`, an empty or unreadable base, a base that
/// is an overlay, and a base that a VM has open read-write.
pub fn create(base: &Path, overlay: &Path, block_size: u32) -> io::Result<Header> {
    check_block_size(block_size)?;
    let base_abs = fs::canonicalize(base).map_err(|e| {
        context(
            e,
            format_args!("cannot open the golden image {}", base.display()),
        )
    })?;
    let golden = open_golden(&base_abs)?;
    let fp = fingerprint(golden.file()).map_err(|e| {
        context(
            e,
            format_args!("cannot read the golden image {}", base_abs.display()),
        )
    })?;
    let dir = canonical_dir_of(overlay)?;
    let header = Header::new(block_size, fp, stored_base_path(&dir, &base_abs))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(overlay)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    e.kind(),
                    format!(
                        "{} already exists; refusing to overwrite it",
                        overlay.display()
                    ),
                )
            } else {
                context(e, format_args!("cannot create {}", overlay.display()))
            }
        })?;
    let write = || -> io::Result<()> {
        let file = LockedFile::lock(file, true, Role::Overlay)?;
        pwrite_all(file.file().as_raw_fd(), WriteBuf::new(&header.encode()), 0)?;
        // Sparse: the bitmap and the data region are holes.
        file.file().set_len(header.file_len())?;
        sync_fd(file.file().as_raw_fd())?;
        // The new directory entry (best effort: not every filesystem
        // supports syncing a directory).
        if let Ok(d) = File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(overlay);
        return Err(context(
            e,
            format_args!("cannot write {}", overlay.display()),
        ));
    }
    Ok(header)
}

/// Open the overlay in `file` (opened from `path`, read-write unless
/// `read_only`) on its golden image. With `hint`, header errors suggest
/// `format=raw` (the format was detected from the magic).
pub(crate) fn open_overlay(
    file: File,
    path: &Path,
    read_only: bool,
    hint: bool,
) -> io::Result<Overlay> {
    let storage = FileStorage(LockedFile::lock(file, !read_only, Role::Overlay)?);
    let header = read_header(&storage).map_err(|e| {
        if hint && e.kind() == io::ErrorKind::InvalidData {
            io::Error::new(
                e.kind(),
                format!(
                    "{e} (if this is a raw image that happens to start with the overlay \
                     magic \"VEMUOVL\", give it as format=raw)"
                ),
            )
        } else {
            e
        }
    })?;
    let base_path = resolve_base(path, &header.base_path)?;
    let golden = open_golden(&base_path)?;
    let now = fingerprint(golden.file()).map_err(|e| {
        context(
            e,
            format_args!("cannot read the golden image {}", base_path.display()),
        )
    })?;
    if let Some(changes) = fingerprint_changes(&header.base, &now) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the golden image {} has changed since the overlay was created ({changes}); \
                 refusing to use the overlay, whose blocks would no longer match it",
                base_path.display()
            ),
        ));
    }
    Overlay::from_parts(
        Box::new(storage),
        Box::new(FileStorage(golden)),
        header,
        read_only,
        true,
        base_path,
        true,
    )
}

/// A throwaway overlay on the raw image `base`, in the temporary directory
/// ([`temp_dir`]): its file never has a name, or is unlinked right after it
/// is created, so it disappears when vemu exits, even when killed.
pub fn snapshot(base: &Path) -> io::Result<Overlay> {
    snapshot_in(base, &temp_dir())
}

/// Where snapshot files go: `$TMPDIR` unless it is unset or empty (an
/// empty one must not mean the current directory), made absolute; else the
/// system's temporary directory.
pub fn temp_dir() -> PathBuf {
    temp_dir_from(
        std::env::var_os("TMPDIR").as_deref(),
        std::env::current_dir().ok().as_deref(),
    )
}

fn temp_dir_from(tmpdir: Option<&std::ffi::OsStr>, cwd: Option<&Path>) -> PathBuf {
    match tmpdir {
        Some(t) if !t.is_empty() => {
            let t = Path::new(t);
            match cwd {
                Some(cwd) if t.is_relative() => cwd.join(t),
                _ => t.to_path_buf(),
            }
        }
        _ => system_temp_dir(),
    }
}

/// The per-user temporary directory (what `TMPDIR` is set to by default).
#[cfg(target_os = "macos")]
fn system_temp_dir() -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let mut buf = vec![0u8; 1024];
    // SAFETY: confstr writes at most `buf.len()` bytes (NUL included) into
    // `buf`, which is valid for that many bytes.
    let n = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n == 0 || n > buf.len() {
        return PathBuf::from("/tmp");
    }
    buf.truncate(n - 1);
    PathBuf::from(std::ffi::OsString::from_vec(buf))
}

#[cfg(not(target_os = "macos"))]
fn system_temp_dir() -> PathBuf {
    PathBuf::from("/tmp")
}

pub(crate) fn snapshot_in(base: &Path, dir: &Path) -> io::Result<Overlay> {
    let base_abs = fs::canonicalize(base).map_err(|e| {
        context(
            e,
            format_args!("cannot open the golden image {}", base.display()),
        )
    })?;
    let golden = open_golden(&base_abs)?;
    let fp = fingerprint(golden.file()).map_err(|e| {
        context(
            e,
            format_args!("cannot read the golden image {}", base_abs.display()),
        )
    })?;
    // 4 KiB blocks, or the smallest larger size whose bitmap fits (golden
    // images over 4 TiB).
    let mut bs = DEFAULT_BLOCK_SIZE;
    let header = loop {
        match Header::new(bs, fp, base_abs.clone()) {
            Err(_) if bs < MAX_BLOCK_SIZE => bs *= 2,
            r => break r?,
        }
    };
    let file = create_unlinked(dir)?;
    let file = LockedFile::lock(file, true, Role::Overlay)?;
    let tmp_err = |e| context(e, format_args!("snapshot file in {}", dir.display()));
    pwrite_all(file.file().as_raw_fd(), WriteBuf::new(&header.encode()), 0).map_err(tmp_err)?;
    file.file().set_len(header.file_len()).map_err(tmp_err)?;
    Overlay::from_parts(
        Box::new(FileStorage(file)),
        Box::new(FileStorage(golden)),
        header,
        false,
        false,
        base_abs,
        false,
    )
}

/// A new file in `dir` (mode 0600) without a name: `O_TMPFILE` on Linux,
/// else created and unlinked at once (only a kill between the two system
/// calls leaves a name, on an empty file).
fn create_unlinked(dir: &Path) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    if let Some(f) = open_tmpfile(dir)? {
        return Ok(f);
    }
    create_then_unlink(dir)
}

/// An anonymous file in `dir`; `None` where the kernel or the filesystem
/// does not support `O_TMPFILE`. `O_EXCL`: it can never be linked in.
#[cfg(target_os = "linux")]
fn open_tmpfile(dir: &Path) -> io::Result<Option<File>> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_TMPFILE | libc::O_EXCL)
        .open(dir)
    {
        Ok(f) => Ok(Some(f)),
        // EISDIR: a kernel without O_TMPFILE (it sees O_DIRECTORY).
        Err(e)
            if e.raw_os_error()
                .is_some_and(|n| crate::io::is_unsupported(n) || n == libc::EISDIR) =>
        {
            Ok(None)
        }
        Err(e) => Err(context(
            e,
            format_args!("cannot create a snapshot file in {}", dir.display()),
        )),
    }
}

fn create_then_unlink(dir: &Path) -> io::Result<File> {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for _ in 0..100 {
        let path = dir.join(format!(
            "vemu-snapshot-{}-{}-{nanos:08x}.vov",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => {
                // Once more on failure (EINTR on network filesystems, say);
                // the error names the file, which is empty, to remove.
                if let Err(e) = fs::remove_file(&path).or_else(|_| fs::remove_file(&path)) {
                    return Err(context(
                        e,
                        format_args!(
                            "cannot unlink the snapshot file {} (it is empty: remove it)",
                            path.display()
                        ),
                    ));
                }
                return Ok(f);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(context(
                    e,
                    format_args!("cannot create a snapshot file in {}", dir.display()),
                ));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("cannot create a snapshot file in {}", dir.display()),
    ))
}

/// Can the overlay be used with its golden image?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseStatus {
    Ok,
    /// Why not (missing, changed, an overlay itself, unreadable).
    Unusable(String),
}

/// What `vemu overlay info` shows.
#[derive(Debug, Clone)]
pub struct OverlayInfo {
    pub header: Header,
    /// The golden image, resolved.
    pub base_path: PathBuf,
    pub base_status: BaseStatus,
    /// Blocks allocated in the bitmap on disk (a running VM may have more
    /// that it has not flushed yet).
    pub allocated_blocks: u64,
    /// Bytes of the virtual disk those blocks cover.
    pub allocated_bytes: u64,
    /// Apparent size of the overlay file.
    pub file_size: u64,
    /// Space the overlay file takes on the host filesystem.
    pub disk_usage: u64,
    /// A VM has the overlay open read-write.
    pub in_use: bool,
}

/// Inspect the overlay at `path` without taking it from a running VM.
pub fn info(path: &Path) -> io::Result<OverlayInfo> {
    let file = File::open(path).map_err(|e| context(e, "cannot open"))?;
    if !has_overlay_magic(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a vemu overlay (no VEMUOVL header)",
        ));
    }
    let meta = file.metadata()?;
    // A VM writing it holds LOCK_EX. The shared lock is only a probe,
    // released at once: held while reading (the bitmap can be 128 MiB, the
    // golden image slow), it would make a VM starting meanwhile fail as if
    // another VM had the overlay.
    let probe = File::open(path).map_err(|e| context(e, "cannot open"))?;
    let in_use = match LockedFile::lock(probe, false, Role::Overlay) {
        Ok(lock) => {
            drop(lock);
            false
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
        Err(e) => return Err(e),
    };
    let storage = FileStorage(LockedFile::unlocked(file));
    let header = read_header(&storage)?;
    let words = load_bitmap(&storage, &header)?;
    let allocated_blocks: u64 = words.iter().map(|w| u64::from(w.count_ones())).sum();
    let bs = u64::from(header.block_size);
    let last = header.blocks() - 1;
    let mut allocated_bytes = allocated_blocks * bs;
    if words[(last / 64) as usize] & (1 << (last % 64)) != 0 {
        allocated_bytes -= last * bs + bs - header.virtual_size;
    }
    let base_path = resolve_base(path, &header.base_path)?;
    let base_status = match base_status(&base_path, &header.base) {
        Ok(()) => BaseStatus::Ok,
        Err(e) => BaseStatus::Unusable(e),
    };
    Ok(OverlayInfo {
        file_size: meta.len(),
        disk_usage: meta.blocks() * 512,
        header,
        base_path,
        base_status,
        allocated_blocks,
        allocated_bytes,
        in_use,
    })
}

fn base_status(path: &Path, recorded: &Fingerprint) -> Result<(), String> {
    let f = File::open(path).map_err(|e| format!("cannot open it: {e}"))?;
    check_not_overlay(&f, path).map_err(|e| e.to_string())?;
    let now = fingerprint(&f).map_err(|e| format!("cannot read it: {e}"))?;
    match fingerprint_changes(recorded, &now) {
        None => Ok(()),
        Some(c) => Err(format!("changed since the overlay was created ({c})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockBackend;
    use crate::testutil::{TempDir, base_pattern};

    fn golden(dir: &TempDir, name: &str, size: u64) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, base_pattern(size)).unwrap();
        p
    }

    fn open(path: &Path, ro: bool) -> io::Result<Overlay> {
        let f = OpenOptions::new().read(true).write(!ro).open(path)?;
        open_overlay(f, path, ro, false)
    }

    fn read(d: &dyn BlockBackend, off: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        d.read_at(ReadBuf::new(&mut v), off).unwrap();
        v
    }

    #[test]
    fn create_open_write_reopen() {
        let dir = TempDir::new("create");
        let g = golden(&dir, "golden.raw", 1 << 20);
        let ov = dir.join("vm1.vov");
        let h = create(&g, &ov, 4096).unwrap();
        assert_eq!(h.base_path, Path::new("golden.raw"));
        assert_eq!(h.virtual_size, 1 << 20);
        let o = open(&ov, false).unwrap();
        assert_eq!(o.base_path(), g);
        assert_eq!(read(&o, 0, 1 << 20), base_pattern(1 << 20));
        o.write_at(WriteBuf::new(b"persisted"), 12345).unwrap();
        o.shutdown().unwrap();
        drop(o);
        let o = open(&ov, true).unwrap();
        assert_eq!(read(&o, 12345, 9), b"persisted");
        assert_eq!(o.allocated_blocks(), 1);
        drop(o);
        // The golden image is untouched.
        assert_eq!(fs::read(&g).unwrap(), base_pattern(1 << 20));
        let i = info(&ov).unwrap();
        assert_eq!(i.base_status, BaseStatus::Ok);
        assert_eq!((i.allocated_blocks, i.allocated_bytes), (1, 4096));
        assert!(!i.in_use);
    }

    #[test]
    fn create_refusals() {
        let dir = TempDir::new("create-refusals");
        let g = golden(&dir, "golden.raw", 64 << 10);
        let ov = dir.join("vm.vov");
        create(&g, &ov, 4096).unwrap();
        let e = create(&g, &ov, 4096).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        // An overlay as the golden image: chains are refused.
        let e = create(&ov, &dir.join("chain.vov"), 4096).unwrap_err();
        assert!(e.to_string().contains("chains are not supported"), "{e}");
        assert!(!dir.join("chain.vov").exists());
        // Missing and empty bases, bad block sizes.
        let e = create(&dir.join("nope.raw"), &dir.join("x.vov"), 4096).unwrap_err();
        assert!(
            e.to_string().contains("cannot open the golden image"),
            "{e}"
        );
        fs::write(dir.join("empty.raw"), b"").unwrap();
        let e = create(&dir.join("empty.raw"), &dir.join("x.vov"), 4096).unwrap_err();
        assert!(e.to_string().contains("empty"), "{e}");
        assert!(!dir.join("x.vov").exists(), "no file left on failure");
        assert!(create(&g, &dir.join("x.vov"), 1000).is_err());
        // An overlay given as a snapshot's base: a chain too.
        let e = snapshot_in(&ov, dir.path()).err().unwrap();
        assert!(e.to_string().contains("chains are not supported"), "{e}");
    }

    #[test]
    fn base_path_relative_and_absolute() {
        let dir = TempDir::new("paths");
        fs::create_dir_all(dir.join("golden")).unwrap();
        fs::create_dir_all(dir.join("vms/a")).unwrap();
        let g = golden(&dir, "golden/g.raw", 8192);
        let h = create(&g, &dir.join("vms/a/x.vov"), 4096).unwrap();
        assert_eq!(h.base_path, Path::new("../../golden/g.raw"));
        // Moving the whole tree keeps the overlay working.
        let moved = TempDir::new("paths-moved");
        let to = moved.join("tree");
        fs::rename(dir.path(), &to).unwrap();
        let o = open(&to.join("vms/a/x.vov"), false).unwrap();
        assert_eq!(o.base_path(), to.join("vms/a/../../golden/g.raw"));
        drop(o);
    }

    #[test]
    fn fingerprint_mismatch_is_refused() {
        let dir = TempDir::new("fingerprint");
        let g = golden(&dir, "golden.raw", 3 << 20);
        let ov = dir.join("vm.vov");
        create(&g, &ov, 4096).unwrap();
        let mtime = fs::metadata(&g).unwrap().modified().unwrap();
        let set_mtime = |t| {
            File::options()
                .write(true)
                .open(&g)
                .unwrap()
                .set_modified(t)
                .unwrap();
        };
        // Same content, new mtime (`touch`).
        set_mtime(mtime + std::time::Duration::from_secs(5));
        let e = open(&ov, false).err().unwrap();
        assert!(
            e.to_string().contains("has changed") && e.to_string().contains("modification time"),
            "{e}"
        );
        assert!(matches!(
            info(&ov).unwrap().base_status,
            BaseStatus::Unusable(_)
        ));
        set_mtime(mtime);
        open(&ov, false).unwrap();
        // Content changed inside a sampled window, mtime put back.
        let mut data = fs::read(&g).unwrap();
        data[10] ^= 0xff;
        fs::write(&g, &data).unwrap();
        set_mtime(mtime);
        let e = open(&ov, false).err().unwrap();
        assert!(e.to_string().contains("sampled content differs"), "{e}");
        // A size change.
        data[10] ^= 0xff;
        data.push(0);
        fs::write(&g, &data).unwrap();
        set_mtime(mtime);
        let e = open(&ov, false).err().unwrap();
        assert!(
            e.to_string().contains("size was 3145728, now 3145729"),
            "{e}"
        );
        // A missing base.
        fs::remove_file(&g).unwrap();
        let e = open(&ov, false).err().unwrap();
        assert!(
            e.to_string().contains("cannot open the golden image"),
            "{e}"
        );
    }

    #[test]
    fn corrupt_overlays_are_refused() {
        let dir = TempDir::new("corrupt");
        let g = golden(&dir, "golden.raw", 64 << 10);
        let ov = dir.join("vm.vov");
        create(&g, &ov, 4096).unwrap();
        let good = fs::read(&ov).unwrap();
        let mut bad = good.clone();
        bad[30] ^= 1;
        fs::write(&ov, &bad).unwrap();
        let e = open(&ov, false).err().unwrap();
        assert!(e.to_string().contains("checksum"), "{e}");
        let mut bad = good.clone();
        bad[8] = 9;
        fs::write(&ov, &bad).unwrap();
        let e = open(&ov, false).err().unwrap();
        assert!(e.to_string().contains("version 9"), "{e}");
        fs::write(&ov, &good[..good.len() - 100]).unwrap();
        let e = open(&ov, false).err().unwrap();
        assert!(e.to_string().contains("truncated"), "{e}");
    }

    /// Allocated bytes grow only with written blocks: holes stay holes.
    ///
    /// Host filesystems differ in what a sparse file costs (APFS fills
    /// holes of up to ~16 MiB ahead of a file's last extent when writing
    /// forward), so the overlay is compared with a sparse reference file
    /// that receives exactly the writes the format calls for: the header,
    /// one bitmap page and the written blocks. On Linux the bound is exact.
    #[test]
    fn overlay_file_stays_sparse() {
        let dir = TempDir::new("sparse");
        let size = 64u64 << 20;
        let g = dir.join("golden.raw");
        let f = File::create(&g).unwrap();
        f.set_len(size).unwrap();
        pwrite_all(f.as_raw_fd(), WriteBuf::new(b"GOLDEN"), 0).unwrap();
        drop(f);
        let ov = dir.join("vm.vov");
        let bs = 64u64 << 10;
        let h = create(&g, &ov, bs as u32).unwrap();
        let usage = |p: &Path| fs::metadata(p).unwrap().blocks() * 512;
        assert!(
            usage(&ov) <= 64 << 10,
            "a new 64 MiB overlay takes {} bytes",
            usage(&ov)
        );
        assert_eq!(fs::metadata(&ov).unwrap().len(), h.file_len());
        // Four blocks, one of them by a 1-byte copy-up.
        let blocks = [0, 16 << 20, 32 << 20, size - bs];
        let o = open(&ov, false).unwrap();
        o.write_at(WriteBuf::new(&vec![1; bs as usize]), blocks[0])
            .unwrap();
        o.write_at(WriteBuf::new(&vec![2; bs as usize]), blocks[1])
            .unwrap();
        o.write_at(WriteBuf::new(&vec![3; bs as usize]), blocks[2])
            .unwrap();
        o.write_at(WriteBuf::new(&[4]), size - 1).unwrap();
        o.shutdown().unwrap();
        drop(o);
        // The reference: the same writes, in the same order.
        let r = dir.join("reference");
        let rf = File::create(&r).unwrap();
        rf.set_len(h.file_len()).unwrap();
        let fd = rf.as_raw_fd();
        pwrite_all(fd, WriteBuf::new(&h.encode()), 0).unwrap();
        for b in blocks {
            pwrite_all(fd, WriteBuf::new(&vec![9; bs as usize]), h.data_offset + b).unwrap();
        }
        pwrite_all(fd, WriteBuf::new(&[0xff; 4096]), h.bitmap_offset).unwrap();
        sync_fd(fd).unwrap();
        drop(rf);
        let (got, reference) = (usage(&ov), usage(&r));
        assert!(
            got <= reference + (16 << 10),
            "overlay takes {got} bytes, reference {reference}"
        );
        if cfg!(target_os = "linux") {
            assert!(
                got <= 4 * bs + (16 << 10),
                "overlay takes {got} bytes for 4 blocks"
            );
        }
        let i = info(&ov).unwrap();
        assert_eq!((i.allocated_blocks, i.allocated_bytes), (4, 4 * bs));
        assert_eq!(i.disk_usage, got);
    }

    #[test]
    fn snapshot_is_unlinked_and_discarded() {
        let dir = TempDir::new("snapshot");
        let tmp = TempDir::new("snapshot-tmp");
        let g = golden(&dir, "golden.raw", 256 << 10);
        let s = snapshot_in(&g, tmp.path()).unwrap();
        assert!(s.is_snapshot());
        assert_eq!(
            fs::read_dir(tmp.path()).unwrap().count(),
            0,
            "no file left in TMPDIR"
        );
        s.write_at(WriteBuf::new(b"scratch"), 1000).unwrap();
        s.flush().unwrap();
        assert_eq!(read(&s, 1000, 7), b"scratch");
        // A writer of the golden image is refused while the snapshot reads it.
        let e = crate::Raw::from_file(
            File::options().read(true).write(true).open(&g).unwrap(),
            false,
        )
        .err()
        .unwrap();
        assert!(e.to_string().contains("golden image of an overlay"), "{e}");
        drop(s);
        assert_eq!(fs::read(&g).unwrap(), base_pattern(256 << 10));
        let s = snapshot_in(&g, tmp.path()).unwrap();
        assert_eq!(read(&s, 1000, 7), base_pattern(256 << 10)[1000..1007]);
    }

    /// `info` holds no lock while it reads: a VM can take the overlay
    /// read-write meanwhile. (The golden image is a FIFO here, so `info`
    /// blocks inside its fingerprint check until the test opens it.)
    #[test]
    fn info_does_not_hold_the_overlay_lock_while_reading() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::time::Duration;
        let dir = TempDir::new("info-lock");
        let g = golden(&dir, "golden.raw", 64 << 10);
        let ov = dir.join("vm.vov");
        create(&g, &ov, 4096).unwrap();
        fs::remove_file(&g).unwrap();
        let c = CString::new(g.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo with a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let path = ov.clone();
        let t = std::thread::spawn(move || info(&path));
        // Lock the overlay as a VM would, while `info` waits on the FIFO.
        let mut locked = false;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(10));
            let f = File::options().read(true).write(true).open(&ov).unwrap();
            if LockedFile::lock(f, true, Role::Overlay).is_ok() {
                locked = true;
                break;
            }
        }
        // Unblock `info` (no hang if it finished early).
        while !t.is_finished() {
            // SAFETY: open with a NUL-terminated path; closed right away.
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
            if fd >= 0 {
                // SAFETY: the fd just opened.
                unsafe { libc::close(fd) };
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let i = t.join().unwrap().unwrap();
        assert!(
            locked,
            "info held the overlay lock while reading the golden image"
        );
        assert!(matches!(i.base_status, BaseStatus::Unusable(_)));
    }

    /// An empty `TMPDIR` is unset (not the current directory); a relative
    /// one is made absolute.
    #[test]
    fn snapshot_temp_dir() {
        use std::ffi::OsStr;
        let cwd = Path::new("/some/cwd");
        let sys = temp_dir_from(None, Some(cwd));
        assert!(sys.is_absolute(), "{}", sys.display());
        assert!(sys.is_dir(), "{}", sys.display());
        assert_eq!(temp_dir_from(Some(OsStr::new("")), Some(cwd)), sys);
        assert_eq!(
            temp_dir_from(Some(OsStr::new("/var/x")), Some(cwd)),
            Path::new("/var/x")
        );
        assert_eq!(
            temp_dir_from(Some(OsStr::new("rel/t")), Some(cwd)),
            Path::new("/some/cwd/rel/t")
        );
        assert!(temp_dir().is_absolute());
    }

    /// On Linux the snapshot file never has a name (`O_TMPFILE`), where
    /// the filesystem supports it.
    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_file_is_anonymous_on_linux() {
        let tmp = TempDir::new("tmpfile");
        let Some(probe) = open_tmpfile(tmp.path()).unwrap() else {
            eprintln!("O_TMPFILE unsupported in {}: skipped", tmp.path().display());
            return;
        };
        drop(probe);
        let f = create_unlinked(tmp.path()).unwrap();
        let link = fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).unwrap();
        let link = link.to_string_lossy();
        assert!(
            !link.contains("vemu-snapshot-") && link.ends_with("(deleted)"),
            "{link}"
        );
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
        // The fallback leaves no name either.
        let f2 = create_then_unlink(tmp.path()).unwrap();
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
        drop((f, f2));
    }

    #[test]
    fn locking() {
        let dir = TempDir::new("locking");
        let g = golden(&dir, "golden.raw", 64 << 10);
        let a = dir.join("a.vov");
        let b = dir.join("b.vov");
        create(&g, &a, 4096).unwrap();
        create(&g, &b, 4096).unwrap();
        // Two overlays share one golden image (LOCK_SH twice), and a
        // read-only raw disk of it too.
        let oa = open(&a, false).unwrap();
        let ob = open(&b, false).unwrap();
        let ro = crate::Raw::from_file(File::open(&g).unwrap(), true).unwrap();
        // The golden image read-write is refused, naming the readers.
        let rw = || File::options().read(true).write(true).open(&g).unwrap();
        let e = crate::Raw::from_file(rw(), false).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        assert!(
            e.to_string().contains("in use read-only") && e.to_string().contains("golden image"),
            "{e}"
        );
        // One overlay, one writer: a second read-write or read-only open is
        // refused; read-only users share it.
        let e = open(&a, false).err().unwrap();
        assert!(
            e.to_string().contains("overlay is in use read-write"),
            "{e}"
        );
        assert!(open(&a, true).is_err());
        drop((oa, ob, ro));
        let r1 = open(&a, true).unwrap();
        let r2 = open(&a, true).unwrap();
        let e = open(&a, false).err().unwrap();
        assert!(e.to_string().contains("overlay is in use read-only"), "{e}");
        assert!(!info(&a).unwrap().in_use);
        drop((r1, r2));
        let oa = open(&a, false).unwrap();
        assert!(info(&a).unwrap().in_use);
        drop(oa);
        // While a VM writes the golden image, overlays on it are refused.
        let w = crate::Raw::from_file(rw(), false).unwrap();
        let e = open(&a, false).err().unwrap();
        assert!(
            e.to_string().contains("in use read-write")
                && e.to_string().contains("overlays need it unchanged"),
            "{e}"
        );
        let e = snapshot_in(&g, dir.path()).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        let e = create(&g, &dir.join("c.vov"), 4096).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        drop(w);
    }
}
