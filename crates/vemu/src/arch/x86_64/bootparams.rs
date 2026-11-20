//! `struct boot_params`, the "zero page" (arch/x86/include/uapi/asm/bootparam.h
//! and Documentation/arch/x86/zero-page.rst), and the boot-time page tables
//! and GDT of the 64-bit boot protocol.

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use vemu_hv::x86_64::BOOT_GDT;

use super::bzimage::{
    OFF_CMD_LINE_PTR, OFF_RAMDISK_IMAGE, OFF_RAMDISK_SIZE, OFF_TYPE_OF_LOADER,
    SETUP_HEADER_MAX_END, SETUP_HEADER_OFFSET,
};
use super::layout::E820Entry;

pub const BOOT_PARAMS_SIZE: usize = 4096;
/// `boot_params.acpi_rsdp_addr` (u64).
pub const OFF_ACPI_RSDP_ADDR: usize = 0x070;
/// `boot_params.ext_ramdisk_image`, `ext_ramdisk_size`, `ext_cmd_line_ptr`
/// (u32 each): the high 32 bits of the setup header fields.
pub const OFF_EXT_RAMDISK_IMAGE: usize = 0x0c0;
pub const OFF_EXT_RAMDISK_SIZE: usize = 0x0c4;
pub const OFF_EXT_CMD_LINE_PTR: usize = 0x0c8;
/// `boot_params.e820_entries` (u8).
pub const OFF_E820_ENTRIES: usize = 0x1e8;
/// `boot_params.sentinel` (u8): must stay 0 (otherwise the kernel assumes
/// a loader that doesn't clear `boot_params` and wipes fields).
pub const OFF_SENTINEL: usize = 0x1ef;
/// `boot_params.e820_table[E820_MAX_ENTRIES_ZEROPAGE]`, 20 bytes each.
pub const OFF_E820_TABLE: usize = 0x2d0;
pub const E820_MAX_ENTRIES: usize = 128;
pub const E820_ENTRY_SIZE: usize = 20;
/// `type_of_loader` for a boot loader without an assigned ID.
pub const LOADER_TYPE_UNDEFINED: u8 = 0xff;

const _: () = assert!(OFF_E820_TABLE + E820_MAX_ENTRIES * E820_ENTRY_SIZE <= 0xcd0);
const _: () = assert!(SETUP_HEADER_MAX_END <= OFF_E820_TABLE);

/// What goes into `boot_params` besides the kernel's own setup header.
pub struct BootParams<'a> {
    /// The setup header bytes from the image (from offset 0x1f1).
    pub setup_header: &'a [u8],
    pub cmdline_addr: u64,
    /// `(gpa, size)` of the initrd.
    pub initrd: Option<(u64, u64)>,
    pub e820: &'a [E820Entry],
    pub rsdp_addr: u64,
}

fn put(page: &mut [u8], off: usize, bytes: &[u8]) {
    page[off..off + bytes.len()].copy_from_slice(bytes);
}

/// The zero page: all zeroes but for the image's setup header (with the
/// loader's fields filled in), the e820 table and the RSDP address.
pub fn build(p: &BootParams<'_>) -> Result<[u8; BOOT_PARAMS_SIZE], String> {
    let mut z = [0u8; BOOT_PARAMS_SIZE];
    if SETUP_HEADER_OFFSET + p.setup_header.len() > SETUP_HEADER_MAX_END {
        return Err("setup header too large".into());
    }
    if p.e820.len() > E820_MAX_ENTRIES {
        return Err("too many e820 entries".into());
    }
    put(&mut z, SETUP_HEADER_OFFSET, p.setup_header);
    z[OFF_TYPE_OF_LOADER] = LOADER_TYPE_UNDEFINED;
    put(
        &mut z,
        OFF_CMD_LINE_PTR,
        &(p.cmdline_addr as u32).to_le_bytes(),
    );
    put(
        &mut z,
        OFF_EXT_CMD_LINE_PTR,
        &((p.cmdline_addr >> 32) as u32).to_le_bytes(),
    );
    if let Some((addr, size)) = p.initrd {
        put(&mut z, OFF_RAMDISK_IMAGE, &(addr as u32).to_le_bytes());
        put(&mut z, OFF_RAMDISK_SIZE, &(size as u32).to_le_bytes());
        put(
            &mut z,
            OFF_EXT_RAMDISK_IMAGE,
            &((addr >> 32) as u32).to_le_bytes(),
        );
        put(
            &mut z,
            OFF_EXT_RAMDISK_SIZE,
            &((size >> 32) as u32).to_le_bytes(),
        );
    }
    put(&mut z, OFF_ACPI_RSDP_ADDR, &p.rsdp_addr.to_le_bytes());
    z[OFF_E820_ENTRIES] = p.e820.len() as u8;
    for (i, e) in p.e820.iter().enumerate() {
        let off = OFF_E820_TABLE + i * E820_ENTRY_SIZE;
        put(&mut z, off, &e.addr.to_le_bytes());
        put(&mut z, off + 8, &e.size.to_le_bytes());
        put(&mut z, off + 16, &e.kind.to_le_bytes());
    }
    debug_assert_eq!(z[OFF_SENTINEL], 0);
    Ok(z)
}

/// Page-table entry bits.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_PAGE_SIZE: u64 = 1 << 7;
/// Gigabytes the boot page tables identity-map with 2 MiB pages.
pub const IDENTITY_MAP_GIB: usize = 4;

/// Identity page tables for the first 4 GiB with 2 MiB pages, to be placed
/// at `pml4`: the PML4, one PDPT and four page directories, one 4 KiB page
/// each, contiguous. Returns the bytes (6 pages).
pub fn identity_page_tables(pml4: u64) -> Vec<u8> {
    let pages = 2 + IDENTITY_MAP_GIB;
    let mut t = vec![0u8; pages * 4096];
    let mut entry = |page: usize, index: usize, value: u64| {
        let off = page * 4096 + index * 8;
        t[off..off + 8].copy_from_slice(&value.to_le_bytes());
    };
    let pdpt = pml4 + 0x1000;
    entry(0, 0, pdpt | PTE_PRESENT | PTE_WRITE);
    for g in 0..IDENTITY_MAP_GIB {
        let pd = pdpt + 0x1000 * (1 + g as u64);
        entry(1, g, pd | PTE_PRESENT | PTE_WRITE);
        for i in 0..512 {
            let addr = ((g as u64) << 30) | ((i as u64) << 21);
            entry(2 + g, i, addr | PTE_PRESENT | PTE_WRITE | PTE_PAGE_SIZE);
        }
    }
    t
}

/// [`BOOT_GDT`] as bytes.
pub fn gdt_bytes() -> Vec<u8> {
    BOOT_GDT.iter().flat_map(|d| d.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::super::layout::{E820_RAM, E820_RESERVED};
    use super::*;

    fn le32(d: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
    }
    fn le64(d: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
    }

    #[test]
    fn zero_page_fields() {
        let mut hdr = vec![0u8; 0x26c - 0x1f1];
        hdr[0] = 0x27; // setup_sects
        hdr[0x202 - 0x1f1..0x206 - 0x1f1].copy_from_slice(b"HdrS");
        hdr[0x211 - 0x1f1] = 0x01; // loadflags
        let e820 = [
            E820Entry {
                addr: 0,
                size: 0x9_fc00,
                kind: E820_RAM,
            },
            E820Entry {
                addr: 0x9_fc00,
                size: 0x6_0400,
                kind: E820_RESERVED,
            },
        ];
        let z = build(&BootParams {
            setup_header: &hdr,
            cmdline_addr: 0x2_0000,
            initrd: Some((0x3ff0_0000, 0x9_c000)),
            e820: &e820,
            rsdp_addr: 0xe_0000,
        })
        .unwrap();
        assert_eq!(z[0x1f1], 0x27);
        assert_eq!(&z[0x202..0x206], b"HdrS");
        assert_eq!(z[0x210], 0xff, "type_of_loader");
        assert_eq!(z[0x211], 0x01, "loadflags kept");
        assert_eq!(le32(&z, 0x228), 0x2_0000, "cmd_line_ptr");
        assert_eq!(le32(&z, 0x0c8), 0, "ext_cmd_line_ptr");
        assert_eq!(le32(&z, 0x218), 0x3ff0_0000, "ramdisk_image");
        assert_eq!(le32(&z, 0x21c), 0x9_c000, "ramdisk_size");
        assert_eq!(le32(&z, 0x0c0), 0);
        assert_eq!(le32(&z, 0x0c4), 0);
        assert_eq!(le64(&z, 0x070), 0xe_0000, "acpi_rsdp_addr");
        assert_eq!(z[0x1e8], 2, "e820_entries");
        assert_eq!(le64(&z, 0x2d0), 0);
        assert_eq!(le64(&z, 0x2d8), 0x9_fc00);
        assert_eq!(le32(&z, 0x2e0), 1);
        assert_eq!(le64(&z, 0x2e4), 0x9_fc00);
        assert_eq!(le64(&z, 0x2ec), 0x6_0400);
        assert_eq!(le32(&z, 0x2f4), 2);
        assert_eq!(z[0x1ef], 0, "sentinel");
        // Everything else is zero.
        let nonzero: usize = z.iter().filter(|&&b| b != 0).count();
        let expected: usize = [
            &z[0x1f1..0x26c],
            &z[0x070..0x078],
            &z[0x2d0..0x2f8],
            &z[0x1e8..0x1e9],
        ]
        .iter()
        .map(|s| s.iter().filter(|&&b| b != 0).count())
        .sum();
        assert_eq!(nonzero, expected);
    }

    #[test]
    fn high_addresses_use_the_ext_fields() {
        let z = build(&BootParams {
            setup_header: &[],
            cmdline_addr: 0x1_2345_6000,
            initrd: Some((0x2_0000_1000, 0x1_0000_0002)),
            e820: &[],
            rsdp_addr: 0,
        })
        .unwrap();
        assert_eq!(le32(&z, 0x228), 0x2345_6000);
        assert_eq!(le32(&z, 0x0c8), 1);
        assert_eq!(le32(&z, 0x218), 0x1000);
        assert_eq!(le32(&z, 0x0c0), 2);
        assert_eq!(le32(&z, 0x21c), 2);
        assert_eq!(le32(&z, 0x0c4), 1);
    }

    #[test]
    fn limits() {
        let big = vec![0u8; 0x290 - 0x1f1 + 1];
        let p = |h: &[u8], e: &[E820Entry]| {
            build(&BootParams {
                setup_header: h,
                cmdline_addr: 0,
                initrd: None,
                e820: e,
                rsdp_addr: 0,
            })
        };
        assert!(p(&big, &[]).is_err());
        let many = vec![
            E820Entry {
                addr: 0,
                size: 1,
                kind: 1
            };
            129
        ];
        assert!(p(&[], &many).is_err());
        assert!(p(&[], &many[..128]).is_ok());
    }

    /// Walk the tables like the MMU (4-level, 2 MiB leaves).
    fn translate(t: &[u8], base: u64, va: u64) -> Option<u64> {
        let read = |gpa: u64| -> u64 { le64(t, (gpa - base) as usize) };
        let pml4e = read(base + ((va >> 39) & 0x1ff) * 8);
        if pml4e & 1 == 0 {
            return None;
        }
        let pdpte = read((pml4e & !0xfff) + ((va >> 30) & 0x1ff) * 8);
        if pdpte & 1 == 0 || pdpte & 0x80 != 0 {
            return None;
        }
        let pde = read((pdpte & !0xfff) + ((va >> 21) & 0x1ff) * 8);
        if pde & 1 == 0 || pde & 0x80 == 0 || pde & 2 == 0 {
            return None;
        }
        Some((pde & !0x1f_ffff & ((1 << 52) - 1)) | (va & 0x1f_ffff))
    }

    #[test]
    fn identity_map_covers_4_gib() {
        let base = 0x9000;
        let t = identity_page_tables(base);
        assert_eq!(t.len(), 6 * 4096);
        assert_eq!(le64(&t, 0), 0xa003, "PML4[0] -> PDPT");
        assert_eq!(le64(&t, 0x1000), 0xb003, "PDPT[0] -> PD0");
        assert_eq!(le64(&t, 0x1018), 0xe003, "PDPT[3] -> PD3");
        assert_eq!(le64(&t, 0x2000), 0x83, "PD0[0]: 2 MiB page at 0");
        assert_eq!(le64(&t, 0x2008), 0x20_0083);
        assert_eq!(le64(&t, 0x5ff8), 0xffe0_0083, "PD3[511]");
        for va in [
            0,
            0x7000,
            0x100_0000 + 0x200,
            0x3fff_ffff,
            0xc000_0000,
            0xffff_ffff,
        ] {
            assert_eq!(translate(&t, base, va), Some(va), "{va:#x}");
        }
        assert_eq!(translate(&t, base, 0x1_0000_0000), None);
        // Nothing else is mapped.
        assert_eq!(t[8..0x1000].iter().filter(|&&b| b != 0).count(), 0);
        assert_eq!(t[0x1020..0x2000].iter().filter(|&&b| b != 0).count(), 0);
    }

    #[test]
    fn gdt() {
        let g = gdt_bytes();
        assert_eq!(g.len(), 32);
        assert_eq!(le64(&g, 0x10), 0x00af_9b00_0000_ffff);
        assert_eq!(le64(&g, 0x18), 0x00cf_9300_0000_ffff);
    }
}
