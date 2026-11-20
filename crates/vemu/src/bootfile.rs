//! Boot files on the host side, common to every guest architecture: size
//! checks before anything is read, and streaming the initrd into guest RAM.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use vemu_core::GuestMemory;

/// The size of the regular file at `path` (the `what` image, for messages),
/// if it is at most `max_size` bytes. Checked on the metadata alone, so a
/// wrong path (a disk image, a device, a FIFO) is refused without reading.
pub fn regular_file_len(what: &str, path: &Path, max_size: u64) -> Result<u64, String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot read {what} {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{what} {} is not a regular file", path.display()));
    }
    if meta.len() > max_size {
        return Err(format!(
            "{what} {} is {} bytes, larger than the {} MiB of guest memory",
            path.display(),
            meta.len(),
            max_size >> 20
        ));
    }
    Ok(meta.len())
}

/// The `--initrd` file, opened and sized from its metadata. Its contents
/// are copied into guest RAM in bounded chunks, never held whole on the
/// host side.
pub struct Initrd {
    path: PathBuf,
    file: File,
    len: u64,
}

/// Chunk size for copying the initrd into guest RAM.
const INITRD_CHUNK: usize = 1 << 20;

impl Initrd {
    /// Open the initrd: a regular file of at most `max_size` bytes.
    pub fn open(path: &Path, max_size: u64) -> Result<Initrd, String> {
        let len = regular_file_len("initrd", path, max_size)?;
        let file =
            File::open(path).map_err(|e| format!("cannot read initrd {}: {e}", path.display()))?;
        Ok(Initrd {
            path: path.to_path_buf(),
            file,
            len,
        })
    }

    /// Size in bytes (from the metadata at open time).
    pub fn size(&self) -> u64 {
        self.len
    }

    /// Copy the first `size()` bytes of the file to guest RAM at `gpa`.
    pub fn load(&mut self, mem: &GuestMemory, gpa: u64) -> Result<(), String> {
        let err = |e: &dyn std::fmt::Display| {
            format!("cannot load the initrd {}: {e}", self.path.display())
        };
        let mut buf = vec![0u8; INITRD_CHUNK.min(self.len as usize)];
        let mut done = 0u64;
        while done < self.len {
            let n = (self.len - done).min(buf.len() as u64) as usize;
            self.file.read_exact(&mut buf[..n]).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    err(&"the file shrank while it was being loaded")
                } else {
                    err(&e)
                }
            })?;
            mem.write(gpa + done, &buf[..n]).map_err(|e| err(&e))?;
            done += n as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;
    const RAM_BASE: u64 = 0x4000_0000;

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vemu-bootfile-{name}-{}", std::process::id()))
    }

    #[test]
    fn initrd_is_copied_into_guest_memory_in_chunks() {
        let path = temp_file("initrd");
        // Not a multiple of the chunk size, so the last chunk is partial.
        let data: Vec<u8> = (0..(2 * INITRD_CHUNK + 12345))
            .map(|i| (i * 7 + i / 4093) as u8)
            .collect();
        std::fs::write(&path, &data).unwrap();
        let mem = GuestMemory::new(RAM_BASE, (8 * MIB) as usize).unwrap();
        let mut initrd = Initrd::open(&path, 8 * MIB).unwrap();
        assert_eq!(initrd.size(), data.len() as u64);
        let gpa = RAM_BASE + 64 * 1024;
        initrd.load(&mem, gpa).unwrap();
        let mut back = vec![0u8; data.len()];
        mem.read(gpa, &mut back).unwrap();
        assert!(back == data, "guest copy differs");

        // A file that shrinks after it was sized is an error, not garbage.
        let mut initrd = Initrd::open(&path, 8 * MIB).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MIB)
            .unwrap();
        let e = initrd.load(&mem, gpa).unwrap_err();
        assert!(e.contains("shrank"), "{e}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn initrd_size_is_checked_before_reading() {
        let path = temp_file("sparse");
        // Sparse: sized without being written, never read by these checks.
        let f = File::create(&path).unwrap();
        f.set_len(96 * MIB).unwrap();
        let e = Initrd::open(&path, 64 * MIB).err().unwrap();
        assert!(e.contains("larger than the 64 MiB of guest memory"), "{e}");
        drop(f);
        std::fs::remove_file(&path).unwrap();

        let e = Initrd::open(Path::new("/dev/zero"), 64 * MIB)
            .err()
            .unwrap();
        assert!(e.contains("not a regular file"), "{e}");
        let e = Initrd::open(&std::env::temp_dir(), 64 * MIB).err().unwrap();
        assert!(e.contains("not a regular file"), "{e}");
        let e = Initrd::open(&temp_file("missing"), 64 * MIB).err().unwrap();
        assert!(e.starts_with("cannot read initrd"), "{e}");
    }
}
