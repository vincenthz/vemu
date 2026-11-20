//! x86 Linux `bzImage` parsing (Documentation/arch/x86/boot.rst).
//!
//! A bzImage is the real-mode setup code (`(setup_sects + 1) * 512` bytes,
//! with the setup header at offset 0x1f1) followed by the protected-mode
//! kernel (`syssize * 16` bytes), which decompresses itself. vemu uses the
//! 64-bit boot protocol: it loads the protected-mode part, fills
//! `boot_params` and jumps to its 64-bit entry point (load address + 0x200)
//! in long mode, so it needs boot protocol 2.12 or later
//! (`xloadflags`) and a kernel with `XLF_KERNEL_64`.

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::layout::{KernelPlacement, LOW_RAM_MAX};
use crate::bootfile::regular_file_len;

/// Offset of `struct setup_header` in the image and in `boot_params`.
pub const SETUP_HEADER_OFFSET: usize = 0x1f1;
/// End of `struct setup_header` as of boot protocol 2.15 (`kernel_info_offset`
/// ends at 0x26c); `boot_params` has room up to 0x290.
pub const SETUP_HEADER_MAX_END: usize = 0x290;
/// `"HdrS"`, little-endian, at 0x202.
pub const HDRS_MAGIC: u32 = 0x5372_6448;
pub const BOOT_FLAG: u16 = 0xaa55;
/// Boot protocol 2.12: `xloadflags`.
pub const MIN_PROTOCOL: u16 = 0x020c;
/// `loadflags` bit 0: the protected-mode code is loaded at 0x100000.
pub const LOADED_HIGH: u8 = 1 << 0;
/// `xloadflags` bit 0: the kernel has the 64-bit entry point at 0x200.
pub const XLF_KERNEL_64: u16 = 1 << 0;
/// Offset of the 64-bit entry point from the protected-mode load address.
pub const ENTRY_64_OFFSET: u64 = 0x200;

// Field offsets in the image / boot_params (boot.rst, "THE REAL-MODE KERNEL HEADER").
pub const OFF_SETUP_SECTS: usize = 0x1f1;
pub const OFF_SYSSIZE: usize = 0x1f4;
pub const OFF_BOOT_FLAG: usize = 0x1fe;
pub const OFF_JUMP: usize = 0x200;
pub const OFF_HEADER: usize = 0x202;
pub const OFF_VERSION: usize = 0x206;
pub const OFF_TYPE_OF_LOADER: usize = 0x210;
pub const OFF_LOADFLAGS: usize = 0x211;
pub const OFF_RAMDISK_IMAGE: usize = 0x218;
pub const OFF_RAMDISK_SIZE: usize = 0x21c;
pub const OFF_CMD_LINE_PTR: usize = 0x228;
pub const OFF_INITRD_ADDR_MAX: usize = 0x22c;
pub const OFF_KERNEL_ALIGNMENT: usize = 0x230;
pub const OFF_RELOCATABLE_KERNEL: usize = 0x234;
pub const OFF_XLOADFLAGS: usize = 0x236;
pub const OFF_CMDLINE_SIZE: usize = 0x238;
pub const OFF_PREF_ADDRESS: usize = 0x258;
pub const OFF_INIT_SIZE: usize = 0x260;

/// How much of the file is read to validate the setup header before the
/// image itself is read: more than [`SETUP_HEADER_MAX_END`], and enough to
/// recognize the formats [`not_a_bzimage`] names.
pub const HEAD_LEN: usize = 4096;

/// The parts of the setup header the loader uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupHeader {
    /// Boot protocol version, e.g. 0x020f for 2.15.
    pub version: u16,
    /// Number of 512-byte setup sectors after the boot sector (0 means 4).
    pub setup_sects: u8,
    /// Protected-mode code size in 16-byte paragraphs.
    pub syssize: u32,
    pub loadflags: u8,
    pub xloadflags: u16,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable: bool,
    /// Longest command line, without the terminating NUL.
    pub cmdline_size: u32,
    pub pref_address: u64,
    pub init_size: u32,
    /// End of the setup header in the image (0x202 + the jump's offset
    /// byte), capped at [`SETUP_HEADER_MAX_END`].
    pub header_end: usize,
}

/// A validated bzImage, held in memory.
pub struct BzImage {
    data: Vec<u8>,
    header: SetupHeader,
}

/// Why a file is not a bootable bzImage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError(pub String);

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

fn le16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(d[off..off + 2].try_into().expect("2 bytes"))
}

fn le32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().expect("4 bytes"))
}

fn le64(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().expect("8 bytes"))
}

impl BzImage {
    /// Read and validate the bzImage at `path`: a regular file of at most
    /// `max_size` bytes (the guest RAM), checked on its metadata. The setup
    /// header is validated from the first [`HEAD_LEN`] bytes, and only then
    /// is the image itself (setup code and protected-mode kernel, nothing
    /// after them) read, so a wrong file (a disk image, a vmlinux) is
    /// refused without being read whole.
    pub fn from_file(path: &Path, max_size: u64) -> Result<BzImage, LoadError> {
        let len = regular_file_len("kernel", path, max_size).map_err(LoadError)?;
        let file = File::open(path)
            .map_err(|e| LoadError(format!("cannot read kernel {}: {e}", path.display())))?;
        BzImage::read(file, len).map_err(|e| match e {
            ReadError::Io(e) => LoadError(format!("cannot read kernel {}: {e}", path.display())),
            ReadError::Invalid(msg) => LoadError(format!("kernel {}: {msg}", path.display())),
        })
    }

    /// Validate and read a bzImage of `len` bytes from `r`: the header
    /// first, from at most [`HEAD_LEN`] bytes, then the image it describes.
    fn read(mut r: impl Read, len: u64) -> Result<BzImage, ReadError> {
        let mut head = Vec::with_capacity(HEAD_LEN);
        r.by_ref()
            .take(len.min(HEAD_LEN as u64))
            .read_to_end(&mut head)
            .map_err(ReadError::Io)?;
        let header = parse_header(&head, len).map_err(|LoadError(m)| ReadError::Invalid(m))?;
        let image_len = header.image_len();
        if image_len > LOW_RAM_MAX {
            return Err(ReadError::Invalid(format!(
                "the setup header describes a {} MiB image; an x86_64 kernel must be \
                 loaded below the 3 GiB PCI hole",
                image_len >> 20
            )));
        }
        // image_len <= len (parse_header checked), and <= 3 GiB.
        let mut data = head;
        data.truncate(image_len as usize);
        data.reserve_exact(image_len as usize - data.len());
        let rest = image_len - data.len() as u64;
        r.take(rest).read_to_end(&mut data).map_err(ReadError::Io)?;
        if (data.len() as u64) < image_len {
            return Err(ReadError::Invalid(format!(
                "truncated: the file is {} bytes but ended after {} while reading it",
                len,
                data.len()
            )));
        }
        Ok(BzImage { data, header })
    }

    /// Validate a bzImage held in memory (tests build images this way).
    #[cfg(test)]
    pub fn parse(data: Vec<u8>) -> Result<BzImage, LoadError> {
        let header = parse_header(&data, data.len() as u64)?;
        Ok(BzImage { data, header })
    }

    pub fn header(&self) -> &SetupHeader {
        &self.header
    }

    /// The setup header bytes as found in the image (0x1f1 to its end), to
    /// copy into `boot_params`.
    pub fn setup_header_bytes(&self) -> &[u8] {
        &self.data[SETUP_HEADER_OFFSET..self.header.header_end]
    }

    /// The protected-mode kernel, to load at [`BootLayout::kernel`](super::layout::BootLayout).
    pub fn protected_mode(&self) -> &[u8] {
        let start = self.header.setup_len();
        &self.data[start..start + self.header.syssize as usize * 16]
    }

    /// What [`boot_layout`](super::layout::boot_layout) needs.
    pub fn placement(&self) -> KernelPlacement {
        let h = &self.header;
        KernelPlacement {
            load_size: self.protected_mode().len() as u64,
            relocatable: h.relocatable,
            pref_address: h.pref_address,
            alignment: u64::from(h.kernel_alignment).max(1),
            init_size: u64::from(h.init_size),
            initrd_addr_max: u64::from(h.initrd_addr_max),
        }
    }
}

impl SetupHeader {
    /// Bytes of real-mode code (boot sector included) before the
    /// protected-mode kernel.
    pub fn setup_len(&self) -> usize {
        let sects = if self.setup_sects == 0 {
            4
        } else {
            usize::from(self.setup_sects)
        };
        (sects + 1) * 512
    }

    /// Bytes of the image the loader uses: the setup code and the
    /// protected-mode kernel (anything after them, such as a signature, is
    /// ignored).
    pub fn image_len(&self) -> u64 {
        self.setup_len() as u64 + u64::from(self.syssize) * 16
    }
}

/// How [`BzImage::read`] failed.
#[derive(Debug)]
enum ReadError {
    Io(std::io::Error),
    Invalid(String),
}

/// Validate the setup header at the start of `head`, the first bytes of an
/// image of `file_len` bytes (`head` may be the whole image).
fn parse_header(head: &[u8], file_len: u64) -> Result<SetupHeader, LoadError> {
    let data = head;
    let err = |m: &str| Err(LoadError(m.to_string()));
    if data.len() < OFF_INIT_SIZE + 4 || le32(data, OFF_HEADER) != HDRS_MAGIC {
        return Err(LoadError(not_a_bzimage(data)));
    }
    let version = le16(data, OFF_VERSION);
    if version < MIN_PROTOCOL {
        return Err(LoadError(format!(
            "boot protocol {}.{:02} is too old (2.12 or later is needed for the 64-bit entry)",
            version >> 8,
            version & 0xff
        )));
    }
    if le16(data, OFF_BOOT_FLAG) != BOOT_FLAG {
        return err("no 0xAA55 boot flag in the setup header");
    }
    let xloadflags = le16(data, OFF_XLOADFLAGS);
    if xloadflags & XLF_KERNEL_64 == 0 {
        return err("not a 64-bit kernel (no XLF_KERNEL_64 entry point)");
    }
    let loadflags = data[OFF_LOADFLAGS];
    if loadflags & LOADED_HIGH == 0 {
        return err("not a bzImage (zImage loaded low: LOADED_HIGH is clear)");
    }
    let setup_sects = data[OFF_SETUP_SECTS];
    let syssize = le32(data, OFF_SYSSIZE);
    let kernel_alignment = le32(data, OFF_KERNEL_ALIGNMENT);
    let relocatable = data[OFF_RELOCATABLE_KERNEL] != 0;
    if relocatable && !kernel_alignment.is_power_of_two() {
        return Err(LoadError(format!(
            "bad kernel_alignment {kernel_alignment:#x} (not a power of two)"
        )));
    }
    // The jump at 0x200 is "jmp short"; its offset byte gives the
    // header's end.
    let header_end = (OFF_HEADER + usize::from(data[OFF_JUMP + 1])).min(SETUP_HEADER_MAX_END);
    let header = SetupHeader {
        version,
        setup_sects,
        syssize,
        loadflags,
        xloadflags,
        initrd_addr_max: le32(data, OFF_INITRD_ADDR_MAX),
        kernel_alignment,
        relocatable,
        cmdline_size: le32(data, OFF_CMDLINE_SIZE),
        pref_address: le64(data, OFF_PREF_ADDRESS),
        init_size: le32(data, OFF_INIT_SIZE),
        header_end,
    };
    if header_end < OFF_INIT_SIZE + 4 {
        return err("setup header too short for boot protocol 2.12");
    }
    if syssize == 0 || header.image_len() > file_len {
        return Err(LoadError(format!(
            "truncated: the setup header describes {} bytes of setup code and {} \
             of kernel, the file has {file_len}",
            header.setup_len(),
            u64::from(syssize) * 16,
        )));
    }
    if header.init_size == 0 {
        return err("init_size is 0");
    }
    Ok(header)
}

/// The message for a file without a setup header, naming formats that are
/// commonly passed by mistake.
fn not_a_bzimage(data: &[u8]) -> String {
    let what = if data.starts_with(b"\x7fELF") {
        "an ELF file (vmlinux?); pass the bzImage (arch/x86/boot/bzImage)"
    } else if data.starts_with(&[0x1f, 0x8b]) {
        "gzip-compressed; pass the bzImage itself"
    } else if data.starts_with(b"MZ") {
        "a PE/EFI image without a Linux setup header"
    } else if data.len() >= 0x40 && le32(data, 0x38) == 0x644d_5241 {
        "an arm64 Image, not an x86_64 kernel"
    } else {
        "no \"HdrS\" setup header"
    };
    format!("not an x86 bzImage: {what}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A minimal valid bzImage: 1 setup sector after the boot sector and
    /// `pm_len` bytes of "kernel".
    pub(crate) fn fake_image(pm_len: usize) -> Vec<u8> {
        let setup_sects = 1u8;
        let mut d = vec![0u8; (usize::from(setup_sects) + 1) * 512 + pm_len];
        d[OFF_SETUP_SECTS] = setup_sects;
        d[OFF_SYSSIZE..OFF_SYSSIZE + 4]
            .copy_from_slice(&((pm_len as u32).div_ceil(16)).to_le_bytes());
        d[OFF_BOOT_FLAG..OFF_BOOT_FLAG + 2].copy_from_slice(&BOOT_FLAG.to_le_bytes());
        d[OFF_JUMP] = 0xeb;
        d[OFF_JUMP + 1] = 0x6a; // header ends at 0x26c
        d[OFF_HEADER..OFF_HEADER + 4].copy_from_slice(&HDRS_MAGIC.to_le_bytes());
        d[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&0x020fu16.to_le_bytes());
        d[OFF_LOADFLAGS] = LOADED_HIGH;
        d[OFF_INITRD_ADDR_MAX..OFF_INITRD_ADDR_MAX + 4]
            .copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        d[OFF_KERNEL_ALIGNMENT..OFF_KERNEL_ALIGNMENT + 4]
            .copy_from_slice(&0x20_0000u32.to_le_bytes());
        d[OFF_RELOCATABLE_KERNEL] = 1;
        d[OFF_XLOADFLAGS..OFF_XLOADFLAGS + 2].copy_from_slice(&0x7fu16.to_le_bytes());
        d[OFF_CMDLINE_SIZE..OFF_CMDLINE_SIZE + 4].copy_from_slice(&2047u32.to_le_bytes());
        d[OFF_PREF_ADDRESS..OFF_PREF_ADDRESS + 8].copy_from_slice(&0x100_0000u64.to_le_bytes());
        d[OFF_INIT_SIZE..OFF_INIT_SIZE + 4].copy_from_slice(&0x40_0000u32.to_le_bytes());
        // The setup sector's sentinel byte, which must not be copied.
        d[0x1ef] = 0xff;
        for (i, b) in d[1024..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        d
    }

    fn with(mut d: Vec<u8>, off: usize, bytes: &[u8]) -> Vec<u8> {
        d[off..off + bytes.len()].copy_from_slice(bytes);
        d
    }

    fn parse_err(d: Vec<u8>) -> String {
        BzImage::parse(d).err().expect("should be refused").0
    }

    #[test]
    fn valid_image() {
        let img = BzImage::parse(fake_image(4096)).unwrap();
        let h = img.header();
        assert_eq!(h.version, 0x020f);
        assert_eq!(h.setup_len(), 1024);
        assert_eq!(h.header_end, 0x26c);
        assert_eq!(img.setup_header_bytes().len(), 0x26c - 0x1f1);
        assert_eq!(img.setup_header_bytes()[0], 1, "starts at setup_sects");
        assert_eq!(img.protected_mode().len(), 4096);
        assert_eq!(img.protected_mode()[..3], [0, 1, 2]);
        let p = img.placement();
        assert_eq!(p.pref_address, 0x100_0000);
        assert_eq!(p.alignment, 0x20_0000);
        assert_eq!(p.init_size, 0x40_0000);
        assert_eq!(p.initrd_addr_max, 0x7fff_ffff);
        assert!(p.relocatable);
    }

    #[test]
    fn setup_sects_zero_means_four() {
        let mut d = fake_image(0);
        // Rebuild with 4 setup sectors: the kernel starts at 5 * 512.
        d[OFF_SETUP_SECTS] = 0;
        d.resize(5 * 512 + 32, 0);
        d[5 * 512] = 0xab;
        d[OFF_SYSSIZE..OFF_SYSSIZE + 4].copy_from_slice(&2u32.to_le_bytes());
        let img = BzImage::parse(d).unwrap();
        assert_eq!(img.header().setup_len(), 2560);
        assert_eq!(img.protected_mode().len(), 32);
        assert_eq!(img.protected_mode()[0], 0xab);
    }

    #[test]
    fn refusals() {
        let d = fake_image(4096);
        assert!(parse_err(with(d.clone(), OFF_HEADER, b"HdrX")).contains("no \"HdrS\""));
        assert!(
            parse_err(with(d.clone(), OFF_VERSION, &0x020bu16.to_le_bytes()))
                .contains("boot protocol 2.11 is too old")
        );
        assert!(parse_err(with(d.clone(), OFF_BOOT_FLAG, &[0, 0])).contains("0xAA55"));
        assert!(
            parse_err(with(d.clone(), OFF_XLOADFLAGS, &[0x7e, 0])).contains("not a 64-bit kernel")
        );
        assert!(parse_err(with(d.clone(), OFF_LOADFLAGS, &[0])).contains("LOADED_HIGH"));
        assert!(
            parse_err(with(
                d.clone(),
                OFF_KERNEL_ALIGNMENT,
                &0x30_0000u32.to_le_bytes()
            ))
            .contains("kernel_alignment")
        );
        assert!(
            parse_err(with(d.clone(), OFF_SYSSIZE, &0x1000u32.to_le_bytes())).contains("truncated")
        );
        assert!(parse_err(with(d.clone(), OFF_SYSSIZE, &[0, 0, 0, 0])).contains("truncated"));
        assert!(parse_err(with(d.clone(), OFF_INIT_SIZE, &[0, 0, 0, 0])).contains("init_size"));
        assert!(parse_err(with(d.clone(), OFF_JUMP + 1, &[0x30])).contains("too short"));
        let mut short = d.clone();
        short.truncate(0x100);
        assert!(parse_err(short).contains("not an x86 bzImage"));
        assert!(parse_err(b"\x7fELF\x02\x01\x01".repeat(200)).contains("vmlinux"));
        assert!(parse_err(vec![0x1f; 2000]).contains("not an x86 bzImage"));
        let mut gz = vec![0u8; 2000];
        gz[..2].copy_from_slice(&[0x1f, 0x8b]);
        assert!(parse_err(gz).contains("gzip"));
        let mut arm = vec![0u8; 2000];
        arm[0x38..0x3c].copy_from_slice(b"ARM\x64");
        assert!(parse_err(arm).contains("arm64 Image"));
    }

    /// A reader serving `prefix` and then zeros without end, counting the
    /// bytes it hands out.
    struct Counting {
        prefix: Vec<u8>,
        served: u64,
    }

    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(64 << 10);
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = self
                    .prefix
                    .get(self.served as usize + i)
                    .copied()
                    .unwrap_or(0);
            }
            self.served += n as u64;
            Ok(n)
        }
    }

    fn counting(prefix: Vec<u8>) -> Counting {
        Counting { prefix, served: 0 }
    }

    fn read_err(r: &mut Counting, len: u64) -> String {
        match BzImage::read(r, len) {
            Err(ReadError::Invalid(m)) => m,
            Err(ReadError::Io(e)) => panic!("unexpected I/O error {e}"),
            Ok(_) => panic!("should be refused"),
        }
    }

    /// A wrong file (here 40 GiB of something that is not a bzImage) is
    /// refused from its first page, without reading the rest.
    #[test]
    fn wrong_file_refused_from_its_head() {
        let mut r = counting(b"\x7fELF\x02\x01\x01".to_vec());
        assert!(read_err(&mut r, 40 << 30).contains("vmlinux"));
        assert!(r.served <= HEAD_LEN as u64, "read {} bytes", r.served);
        let mut r = counting(Vec::new());
        assert!(read_err(&mut r, 40 << 30).contains("no \"HdrS\""));
        assert!(r.served <= HEAD_LEN as u64, "read {} bytes", r.served);
        // A header that is wrong further in is refused the same way.
        let bad = with(fake_image(4096), OFF_XLOADFLAGS, &[0x7e, 0]);
        let mut r = counting(bad);
        assert!(read_err(&mut r, 40 << 30).contains("not a 64-bit kernel"));
        assert!(r.served <= HEAD_LEN as u64, "read {} bytes", r.served);
    }

    /// A valid header describing more than fits below the PCI hole is
    /// refused before the image is read.
    #[test]
    fn oversized_image_refused_before_reading() {
        let syssize = ((LOW_RAM_MAX / 16) as u32) + 1;
        let d = with(fake_image(4096), OFF_SYSSIZE, &syssize.to_le_bytes());
        let mut r = counting(d);
        assert!(read_err(&mut r, 40 << 30).contains("below the 3 GiB PCI hole"));
        assert!(r.served <= HEAD_LEN as u64, "read {} bytes", r.served);
    }

    /// Only the image the header describes is read, not what follows it,
    /// and the result is what `parse` gives for the image alone.
    #[test]
    fn reads_only_the_described_image() {
        let img = fake_image(100_000);
        let mut r = counting(img.clone());
        let b = BzImage::read(&mut r, 1 << 30).unwrap();
        let image_len = b.header().image_len();
        assert_eq!(image_len, 1024 + 100_000);
        assert!(
            r.served <= image_len + (64 << 10),
            "read {} bytes",
            r.served
        );
        let p = BzImage::parse(img).unwrap();
        assert_eq!(b.header(), p.header());
        assert_eq!(b.protected_mode(), p.protected_mode());
        assert_eq!(b.setup_header_bytes(), p.setup_header_bytes());
        // An image smaller than the head buffer.
        let small = fake_image(16);
        let b = BzImage::read(&mut counting(small.clone()), small.len() as u64).unwrap();
        assert_eq!(
            b.protected_mode(),
            BzImage::parse(small).unwrap().protected_mode()
        );
    }

    /// The file's size bounds the image; a file that shrinks while it is
    /// read is reported as truncated.
    #[test]
    fn truncation() {
        let img = fake_image(4096);
        let n = img.len() as u64;
        assert!(read_err(&mut counting(img.clone()), n - 1).contains("truncated"));
        // The metadata said n bytes but the reader ends early.
        let short = &img[..img.len() - 10];
        match BzImage::read(short, n) {
            Err(ReadError::Invalid(m)) => assert!(m.contains("ended after"), "{m}"),
            _ => panic!("should be refused"),
        }
    }

    #[test]
    fn from_file_errors_name_the_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vemu-bzimage-{}", std::process::id()));
        let mut d = fake_image(4096);
        d.extend_from_slice(&[0xee; 300]); // trailing bytes are ignored
        std::fs::write(&path, &d).unwrap();
        let b = BzImage::from_file(&path, 1 << 20).unwrap();
        assert_eq!(b.protected_mode().len(), 4096);
        std::fs::write(&path, b"\x7fELF\x02\x01\x01".repeat(200)).unwrap();
        let e = BzImage::from_file(&path, 1 << 20).err().unwrap().0;
        assert!(e.starts_with("kernel ") && e.contains("vmlinux"), "{e}");
        let e = BzImage::from_file(&path, 16).err().unwrap().0;
        assert!(e.contains("larger than"), "{e}");
        std::fs::remove_file(&path).unwrap();
    }

    /// The real test kernel (skipped when the fixture is absent).
    fn real_kernel() -> Option<PathBuf> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut candidates = vec![root.join("testdata/x86_64/bzImage")];
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(
                PathBuf::from(home)
                    .join("Work/skeletos/.skeletos/out/kernel/7.2.15/x86_64/vmlinuz.efi"),
            );
        }
        candidates.into_iter().find(|p| p.is_file())
    }

    #[test]
    fn real_bzimage() {
        let Some(path) = real_kernel() else {
            eprintln!("skipped: no x86_64 bzImage fixture (scripts/mk-testdata.sh)");
            return;
        };
        let img = BzImage::from_file(&path, 1 << 30).unwrap();
        let h = *img.header();
        assert!(h.version >= MIN_PROTOCOL, "{:#x}", h.version);
        assert_ne!(h.xloadflags & XLF_KERNEL_64, 0);
        assert!(h.relocatable);
        assert!(h.kernel_alignment.is_power_of_two());
        assert!(h.pref_address >= 0x10_0000);
        assert!(u64::from(h.init_size) >= img.protected_mode().len() as u64);
        assert!(h.cmdline_size >= 2047);
        // The header the image carries is what the kernel expects back.
        assert_eq!(
            &img.setup_header_bytes()[OFF_HEADER - SETUP_HEADER_OFFSET..][..4],
            b"HdrS"
        );
        // The 64-bit entry is 0x200 into the protected-mode part, which for
        // an x86_64 kernel starts with startup_32 then startup_64 at 0x200.
        assert!(img.protected_mode().len() > ENTRY_64_OFFSET as usize);
        // It fits the default 1 GiB machine.
        let b =
            super::super::layout::boot_layout(1 << 30, &img.placement(), Some(1 << 20)).unwrap();
        assert_eq!(b.kernel, h.pref_address);
    }
}
