//! Explaining a lock conflict between two disks of the same VM.
//!
//! `flock` locks belong to open file descriptions, so one vemu that opens
//! a file twice conflicts with itself, and the lock error, which cannot
//! know the holder, blames "another vemu or process". When opening a disk
//! fails that way, [`conflict_within`] looks for the disk given earlier on
//! the same command line that uses the same file (same device and inode,
//! whatever the path), and says so.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::io::FileStorage;
use crate::lock::LockedFile;
use crate::overlay::read_header;
use crate::{DiskOptions, Format, image};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The `--disk` file itself (a raw image or an overlay).
    Disk,
    /// The golden image of an overlay or snapshot.
    Golden,
}

struct Use {
    id: (u64, u64),
    path: PathBuf,
    kind: Kind,
    /// Takes `LOCK_EX`.
    exclusive: bool,
}

fn file_id(path: &Path) -> Option<(u64, u64)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.dev(), m.ino()))
}

/// The files the disk `path` with `opts` locks, as far as they can be
/// found (best effort: what cannot be read is left out).
fn uses(path: &Path, opts: DiskOptions) -> Vec<Use> {
    let Some(id) = file_id(path) else {
        return Vec::new();
    };
    let golden = |p: PathBuf| {
        file_id(&p).map(|id| Use {
            id,
            path: p,
            kind: Kind::Golden,
            exclusive: false,
        })
    };
    if opts.snapshot {
        return golden(path.to_path_buf()).into_iter().collect();
    }
    let mut v = vec![Use {
        id,
        path: path.to_path_buf(),
        kind: Kind::Disk,
        exclusive: !opts.read_only,
    }];
    let Ok(file) = File::open(path) else {
        return v;
    };
    let overlay = match opts.format {
        Format::Raw => false,
        Format::Auto | Format::Overlay => image::has_overlay_magic(&file).unwrap_or(false),
    };
    if overlay {
        let storage = FileStorage(LockedFile::unlocked(file));
        if let Ok(h) = read_header(&storage)
            && let Ok(base) = image::resolve_base(path, &h.base_path)
        {
            v.extend(golden(base));
        }
    }
    v
}

/// Why opening disk `path` (`opts`) conflicts with one of the `earlier`
/// disks of the same VM, if it does. The message does not repeat `path`.
pub fn conflict_within(
    earlier: &[(&Path, DiskOptions)],
    path: &Path,
    opts: DiskOptions,
) -> Option<String> {
    let new = uses(path, opts);
    for (n, &(epath, eopts)) in earlier.iter().enumerate() {
        let n = n + 1;
        let what = if eopts.snapshot {
            format!("the snapshot disk {n} ({})", epath.display())
        } else {
            format!("disk {n} ({})", epath.display())
        };
        for old in uses(epath, eopts) {
            for u in new.iter().filter(|u| u.id == old.id) {
                if !u.exclusive && !old.exclusive {
                    continue;
                }
                return Some(match (u.kind, old.kind) {
                    (Kind::Disk, Kind::Disk) => format!(
                        "this file is already {what}: one VM can use an image or overlay \
                         several times only if every use is read-only (,ro)"
                    ),
                    (Kind::Disk, Kind::Golden) => format!(
                        "this file is the golden image of {what}, which needs it unchanged, so \
                         it cannot also be a read-write disk"
                    ),
                    (Kind::Golden, _) => format!(
                        "its golden image {} is also {what}, which writes it; an overlay or \
                         snapshot needs its golden image unchanged",
                        u.path.display()
                    ),
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, base_pattern};
    use crate::{create, open};
    use std::fs;
    use std::io;

    fn opts(read_only: bool, snapshot: bool) -> DiskOptions {
        DiskOptions {
            read_only,
            snapshot,
            format: Format::Auto,
        }
    }

    /// Open the disks in order as a VM would; the first refusal, explained.
    fn open_all(disks: &[(&Path, DiskOptions)]) -> Result<usize, String> {
        let mut held = Vec::new();
        for (i, &(p, o)) in disks.iter().enumerate() {
            match open(p, o) {
                Ok(d) => held.push(d),
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
                    return Err(conflict_within(&disks[..i], p, o).unwrap_or(e.to_string()));
                }
            }
        }
        Ok(held.len())
    }

    #[test]
    fn conflicts_within_one_vm_are_named() {
        let dir = TempDir::new("conflict");
        let g = dir.join("g.raw");
        fs::write(&g, base_pattern(64 << 10)).unwrap();
        let ov = dir.join("vm.vov");
        create(&g, &ov, 4096).unwrap();
        // Another path to the same overlay.
        fs::create_dir(dir.join("sub")).unwrap();
        let other = dir.join("sub/../vm.vov");
        let (rw, ro, snap) = (opts(false, false), opts(true, false), opts(false, true));

        let e = open_all(&[(&ov, rw), (&ov, rw)]).unwrap_err();
        assert!(e.contains("already disk 1") && e.contains("vm.vov"), "{e}");
        let e = open_all(&[(&ov, ro), (&other, rw)]).unwrap_err();
        assert!(e.contains("already disk 1"), "{e}");
        let e = open_all(&[(&ov, rw), (&g, rw)]).unwrap_err();
        assert!(e.contains("golden image of disk 1"), "{e}");
        let e = open_all(&[(&g, snap), (&g, rw)]).unwrap_err();
        assert!(e.contains("golden image of the snapshot disk 1"), "{e}");
        let e = open_all(&[(&g, rw), (&ov, rw)]).unwrap_err();
        assert!(
            e.contains("its golden image") && e.contains("also disk 1") && e.contains("writes it"),
            "{e}"
        );
        let e = open_all(&[(&g, rw), (&g, snap)]).unwrap_err();
        assert!(e.contains("its golden image"), "{e}");
        assert!(!e.contains("another vemu"), "{e}");
        // Readers share: no conflict.
        assert_eq!(
            open_all(&[(&ov, ro), (&ov, ro), (&g, ro), (&g, snap)]),
            Ok(4)
        );
        // A conflict with something outside the VM is not explained away.
        let _held = open(&ov, rw).unwrap();
        assert_eq!(conflict_within(&[(&g, ro)], &ov, rw), None);
    }
}
