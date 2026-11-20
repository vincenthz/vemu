//! arm64 Linux `Image` loader (Documentation/arch/arm64/booting.rst).
//!
//! The image starts with a 64-byte header:
//!
//! ```text
//! u32 code0; u32 code1;          executable code (a branch, or "MZ" for EFI)
//! u64 text_offset;               load offset from a 2 MiB aligned base
//! u64 image_size;                effective size including BSS (0 before 3.17)
//! u64 flags;                     bit 0: big-endian, bits 1-2: page size,
//!                                bit 3: may be placed anywhere in RAM
//! u64 res2, res3, res4;
//! u32 magic = "ARM\x64";         at offset 0x38
//! u32 res5;                      PE header offset (EFI stub)
//! ```
//!
//! Only uncompressed little-endian Images are accepted: there is no firmware
//! or decompressor in front of the kernel. Common other formats (gzip'd
//! `Image.gz`, EFI zboot `vmlinuz.efi`, ELF `vmlinux`, U-Boot `uImage`) are
//! recognised and rejected with a hint.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::bootfile::regular_file_len;

/// `"ARM\x64"`, little-endian, at offset 0x38.
pub const IMAGE_MAGIC: u32 = 0x644d_5241;
const HEADER_LEN: usize = 64;
const MAGIC_OFFSET: usize = 0x38;
/// `text_offset` to assume when `image_size` is 0 (kernels before 3.17).
const LEGACY_TEXT_OFFSET: u64 = 0x8_0000;
const FLAG_BIG_ENDIAN: u64 = 1 << 0;

/// A validated arm64 kernel Image.
pub struct KernelImage {
    data: Vec<u8>,
    text_offset: u64,
    image_size: u64,
}

/// Why a file is not a bootable Image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError(String);

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

impl KernelImage {
    /// Read and validate the Image at `path`, which must be a regular file
    /// of at most `max_size` bytes (the guest RAM: anything larger cannot
    /// be loaded). The size is checked before anything is read.
    pub fn from_file(path: &Path, max_size: u64) -> Result<KernelImage, LoadError> {
        let len = regular_file_len("kernel", path, max_size).map_err(LoadError)?;
        let mut data = Vec::with_capacity(len as usize);
        File::open(path)
            .and_then(|f| f.take(max_size).read_to_end(&mut data))
            .map_err(|e| LoadError(format!("cannot read kernel {}: {e}", path.display())))?;
        KernelImage::parse(data)
            .map_err(|LoadError(msg)| LoadError(format!("kernel {}: {msg}", path.display())))
    }

    /// Validate an Image held in memory.
    pub fn parse(data: Vec<u8>) -> Result<KernelImage, LoadError> {
        if data.len() < HEADER_LEN || le32(&data, MAGIC_OFFSET) != IMAGE_MAGIC {
            return Err(LoadError(not_an_image(&data)));
        }
        let mut text_offset = le64(&data, 8);
        let image_size = le64(&data, 16);
        let flags = le64(&data, 24);
        if image_size != 0 && flags & FLAG_BIG_ENDIAN != 0 {
            return Err(LoadError(
                "big-endian kernel Image; only little-endian guests are supported".into(),
            ));
        }
        if image_size == 0 {
            text_offset = LEGACY_TEXT_OFFSET;
        }
        if !text_offset.is_multiple_of(4096) {
            return Err(LoadError(format!(
                "Image header has an unaligned text_offset {text_offset:#x}"
            )));
        }
        Ok(KernelImage {
            data,
            text_offset,
            image_size,
        })
    }

    /// Offset of the load address from the 2 MiB-aligned start of RAM.
    pub fn text_offset(&self) -> u64 {
        self.text_offset
    }

    /// Bytes of RAM the kernel occupies from its load address: the header's
    /// `image_size` (which includes BSS), or the file size if larger or the
    /// header predates the field.
    pub fn load_size(&self) -> u64 {
        self.image_size.max(self.data.len() as u64)
    }

    /// The file contents, to copy to the load address.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Explain what a file without the Image magic most likely is.
fn not_an_image(data: &[u8]) -> String {
    let what = if data.starts_with(&[0x1f, 0x8b]) {
        Some("gzip-compressed (like Image.gz)")
    } else if data.starts_with(b"MZ") && data.get(4..8) == Some(b"zimg") {
        Some("an EFI zboot image (vmlinuz.efi), which needs EFI firmware to decompress")
    } else if data.starts_with(b"\x7fELF") {
        Some("an ELF file (vmlinux)")
    } else if data.starts_with(&[0x27, 0x05, 0x19, 0x56]) {
        Some("a U-Boot uImage")
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        Some("xz-compressed")
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd-compressed")
    } else if data.starts_with(&[0x04, 0x22, 0x4d, 0x18])
        || data.starts_with(&[0x02, 0x21, 0x4c, 0x18])
    {
        Some("lz4-compressed")
    } else if data.starts_with(b"BZh") {
        Some("bzip2-compressed")
    } else {
        None
    };
    let hint = "vemu boots the uncompressed arm64 Image (arch/arm64/boot/Image)";
    match what {
        Some(w) => format!("this is {w}, not an arm64 Image; {hint}"),
        None => format!("no arm64 Image header (magic \"ARM\\x64\" at offset 0x38); {hint}"),
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4-byte slice"))
}

fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8-byte slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(text_offset: u64, image_size: u64, flags: u64) -> Vec<u8> {
        let mut h = vec![0u8; 4096];
        h[0..2].copy_from_slice(b"MZ");
        h[8..16].copy_from_slice(&text_offset.to_le_bytes());
        h[16..24].copy_from_slice(&image_size.to_le_bytes());
        h[24..32].copy_from_slice(&flags.to_le_bytes());
        h[0x38..0x3c].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        h
    }

    #[test]
    fn modern_image() {
        let k = KernelImage::parse(header(0, 0x295_0000, 0xa)).unwrap();
        assert_eq!(k.text_offset(), 0);
        assert_eq!(k.load_size(), 0x295_0000);
        assert_eq!(k.bytes().len(), 4096);
    }

    #[test]
    fn legacy_image_assumes_text_offset() {
        let k = KernelImage::parse(header(0x1234, 0, 1)).unwrap();
        assert_eq!(k.text_offset(), 0x8_0000);
        assert_eq!(k.load_size(), 4096);
    }

    #[test]
    fn rejects() {
        let err = |d: Vec<u8>| KernelImage::parse(d).err().unwrap().0;
        assert!(err(header(0, 0x1000, 1)).contains("big-endian"));
        assert!(err(header(0x10, 0x1000, 0)).contains("text_offset"));
        assert!(err(vec![0; 10]).contains("no arm64 Image header"));
        assert!(err(vec![0; 100]).contains("no arm64 Image header"));
        let mut gz = vec![0x1f, 0x8b, 8, 0];
        gz.resize(100, 0);
        assert!(err(gz).contains("gzip"));
        let mut zboot = b"MZ\0\0zimg".to_vec();
        zboot.resize(100, 0);
        assert!(err(zboot).contains("zboot"));
        assert!(err(b"\x7fELF\x02\x01\x01".to_vec()).contains("ELF"));
        assert!(err(vec![0x27, 0x05, 0x19, 0x56]).contains("uImage"));
    }

    #[test]
    fn from_file_checks_size_and_type_first() {
        let dir = std::env::temp_dir().join(format!("vemu-loader-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Image");
        std::fs::write(&path, header(0, 0x1000, 0)).unwrap();
        assert!(KernelImage::from_file(&path, 1 << 20).is_ok());
        // Sparse: no data is written, and the size check refuses it before
        // anything is read.
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(3 << 20)
            .unwrap();
        let e = KernelImage::from_file(&path, 2 << 20).err().unwrap().0;
        assert!(e.contains("larger than the 2 MiB of guest memory"), "{e}");
        let e = KernelImage::from_file(&dir, 2 << 20).err().unwrap().0;
        assert!(e.contains("not a regular file"), "{e}");
        let e = KernelImage::from_file(Path::new("/dev/zero"), 2 << 20)
            .err()
            .unwrap()
            .0;
        assert!(e.contains("not a regular file"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_kernel_if_present() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/Image");
        if !p.exists() {
            eprintln!("skipping: {} not found", p.display());
            return;
        }
        let k = KernelImage::from_file(&p, 1 << 30).unwrap();
        assert!(k.load_size() >= k.bytes().len() as u64);
    }
}
