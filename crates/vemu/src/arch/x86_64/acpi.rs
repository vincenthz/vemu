//! ACPI tables of the x86_64 machine (ACPI 6.5), hardware-reduced: RSDP
//! (revision 2) → XSDT → FADT (→ DSDT) and MADT.
//!
//! - FADT: `HW_REDUCED_ACPI`, so there are no fixed-feature PM blocks, no
//!   SCI and no FACS. Sleep control/status registers and the reset
//!   register are bytes in I/O space (see [`super::devices::AcpiRegs`]); the
//!   boot architecture flags say there is no VGA, no CMOS RTC, no i8042 and
//!   no MSI.
//! - MADT: one enabled local APIC per vCPU (APIC ID = vCPU index), the
//!   in-kernel IOAPIC (ID 0, GSI base 0), ISA IRQ 0 → GSI 2 as on a PC, and
//!   LINT1 = NMI on every CPU.
//! - DSDT: `\_S5` (so Linux powers off through the sleep registers), the
//!   debug UART as COM1 (`PNP0501`) when present, and one `LNRO0005`
//!   (virtio-mmio) device per populated slot.

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use super::aml::{self, Polarity, Trigger};
use super::layout;

pub const OEM_ID: [u8; 6] = *b"VEMU  ";
pub const CREATOR_ID: [u8; 4] = *b"VEMU";
pub const CREATOR_REVISION: u32 = 1;
pub const OEM_REVISION: u32 = 1;
/// FADT "Hypervisor Vendor Identity".
pub const HYPERVISOR_VENDOR_ID: [u8; 8] = *b"VEMU    ";

/// RSDP revision 2 size (with the extended fields) and the length covered
/// by its first checksum.
pub const RSDP_SIZE: usize = 36;
pub const RSDP_CHECKSUM_LEN: usize = 20;
pub const HEADER_SIZE: usize = 36;
/// ACPI 6.x FADT size.
pub const FADT_SIZE: usize = 276;
pub const FADT_REVISION: u8 = 6;
pub const FADT_MINOR_REVISION: u8 = 5;
pub const MADT_REVISION: u8 = 5;
/// DSDT revision 2: 64-bit AML integers.
pub const DSDT_REVISION: u8 = 2;

// FADT field offsets.
pub const FADT_DSDT: usize = 40;
pub const FADT_IAPC_BOOT_ARCH: usize = 109;
pub const FADT_FLAGS: usize = 112;
pub const FADT_RESET_REG: usize = 116;
pub const FADT_RESET_VALUE: usize = 128;
pub const FADT_MINOR_VERSION: usize = 131;
pub const FADT_X_DSDT: usize = 140;
pub const FADT_SLEEP_CONTROL_REG: usize = 244;
pub const FADT_SLEEP_STATUS_REG: usize = 256;
pub const FADT_HYPERVISOR_VENDOR: usize = 268;

// FADT flags.
pub const FADT_F_WBINVD: u32 = 1 << 0;
pub const FADT_F_PWR_BUTTON: u32 = 1 << 4;
pub const FADT_F_SLP_BUTTON: u32 = 1 << 5;
pub const FADT_F_RESET_REG_SUP: u32 = 1 << 10;
pub const FADT_F_HW_REDUCED_ACPI: u32 = 1 << 20;
// IA-PC boot architecture flags.
pub const IAPC_VGA_NOT_PRESENT: u16 = 1 << 2;
pub const IAPC_MSI_NOT_SUPPORTED: u16 = 1 << 3;
pub const IAPC_PCIE_ASPM_CONTROLS: u16 = 1 << 4;
pub const IAPC_CMOS_RTC_NOT_PRESENT: u16 = 1 << 5;

/// Generic Address Structure: address space "System I/O".
pub const GAS_SYSTEM_IO: u8 = 1;
/// GAS access size: byte.
pub const GAS_ACCESS_BYTE: u8 = 1;
/// Value written to the reset register to reset the machine.
pub const RESET_VALUE: u8 = 1;
/// `\_S5` sleep type, written as SLP_TYP to the sleep control register.
pub const S5_SLEEP_TYPE: u8 = 5;

// MADT.
pub const MADT_PCAT_COMPAT: u32 = 1 << 0;
pub const MADT_LOCAL_APIC: u8 = 0;
pub const MADT_IO_APIC: u8 = 1;
pub const MADT_INT_SRC_OVERRIDE: u8 = 2;
pub const MADT_LOCAL_APIC_NMI: u8 = 4;
pub const MADT_LAPIC_ENABLED: u32 = 1 << 0;
/// The IOAPIC's ID.
pub const IOAPIC_ID: u8 = 0;
/// Largest xAPIC ID in a MADT Processor Local APIC entry (0xff is
/// "broadcast").
pub const MAX_XAPIC_CPUS: usize = 255;

/// A virtio-mmio device for the DSDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioDev {
    pub base: u64,
    pub size: u64,
    pub gsi: u32,
}

/// What the tables describe.
#[derive(Debug, Clone, Copy)]
pub struct AcpiConfig<'a> {
    pub cpus: usize,
    pub virtio: &'a [VirtioDev],
    /// Describe the debug UART (COM1, I/O 0x3f8, GSI 4).
    pub com1: bool,
}

/// The tables as one blob to load at `base`; the RSDP is at its start.
pub fn build(base: u64, cfg: &AcpiConfig<'_>) -> Result<Vec<u8>, String> {
    if cfg.cpus == 0 || cfg.cpus > MAX_XAPIC_CPUS {
        return Err(format!("ACPI: cannot describe {} CPUs", cfg.cpus));
    }
    let dsdt = sdt(*b"DSDT", DSDT_REVISION, *b"VEMUDSDT", &dsdt_body(cfg)?);
    let madt = sdt(*b"APIC", MADT_REVISION, *b"VEMUMADT", &madt_body(cfg.cpus));

    let align = |n: usize| n.next_multiple_of(16);
    let xsdt_off = align(RSDP_SIZE);
    let xsdt_len = HEADER_SIZE + 2 * 8;
    let fadt_off = align(xsdt_off + xsdt_len);
    let madt_off = align(fadt_off + FADT_SIZE);
    let dsdt_off = align(madt_off + madt.len());
    let total = dsdt_off + dsdt.len();
    if total as u64 > layout::ACPI_MAX {
        return Err(format!("ACPI tables too large ({total} bytes)"));
    }
    let at = |off: usize| base + off as u64;

    let fadt = sdt(
        *b"FACP",
        FADT_REVISION,
        *b"VEMUFADT",
        &fadt_body(at(dsdt_off))?,
    );
    debug_assert_eq!(fadt.len(), FADT_SIZE);
    let xsdt_entries: Vec<u8> = [at(fadt_off), at(madt_off)]
        .iter()
        .flat_map(|a| a.to_le_bytes())
        .collect();
    let xsdt = sdt(*b"XSDT", 1, *b"VEMUXSDT", &xsdt_entries);
    debug_assert_eq!(xsdt.len(), xsdt_len);

    let mut blob = vec![0u8; total];
    blob[..RSDP_SIZE].copy_from_slice(&rsdp(at(xsdt_off)));
    for (off, t) in [
        (xsdt_off, &xsdt),
        (fadt_off, &fadt),
        (madt_off, &madt),
        (dsdt_off, &dsdt),
    ] {
        blob[off..off + t.len()].copy_from_slice(t);
    }
    Ok(blob)
}

/// Two's-complement byte sum, so that the bytes plus it sum to 0.
pub fn checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0u8, |a, &b| a.wrapping_add(b))
        .wrapping_neg()
}

/// A System Description Table: the 36-byte header, then `body`.
pub fn sdt(signature: [u8; 4], revision: u8, oem_table_id: [u8; 8], body: &[u8]) -> Vec<u8> {
    let len = HEADER_SIZE + body.len();
    let mut t = Vec::with_capacity(len);
    t.extend_from_slice(&signature);
    t.extend_from_slice(&(len as u32).to_le_bytes());
    t.push(revision);
    t.push(0); // checksum, below
    t.extend_from_slice(&OEM_ID);
    t.extend_from_slice(&oem_table_id);
    t.extend_from_slice(&OEM_REVISION.to_le_bytes());
    t.extend_from_slice(&CREATOR_ID);
    t.extend_from_slice(&CREATOR_REVISION.to_le_bytes());
    t.extend_from_slice(body);
    t[9] = checksum(&t);
    t
}

/// RSDP revision 2 pointing at the XSDT (no RSDT).
fn rsdp(xsdt: u64) -> [u8; RSDP_SIZE] {
    let mut r = [0u8; RSDP_SIZE];
    r[..8].copy_from_slice(b"RSD PTR ");
    r[9..15].copy_from_slice(&OEM_ID);
    r[15] = 2; // revision
    // RsdtAddress (16..20) stays 0.
    r[20..24].copy_from_slice(&(RSDP_SIZE as u32).to_le_bytes());
    r[24..32].copy_from_slice(&xsdt.to_le_bytes());
    r[8] = checksum(&r[..RSDP_CHECKSUM_LEN]);
    r[32] = checksum(&r);
    r
}

/// A Generic Address Structure for one byte in I/O space.
fn gas_io_byte(port: u16) -> [u8; 12] {
    let mut g = [0u8; 12];
    g[0] = GAS_SYSTEM_IO;
    g[1] = 8; // bit width
    g[2] = 0; // bit offset
    g[3] = GAS_ACCESS_BYTE;
    g[4..12].copy_from_slice(&u64::from(port).to_le_bytes());
    g
}

/// The FADT after its header.
fn fadt_body(dsdt: u64) -> Result<Vec<u8>, String> {
    let mut f = vec![0u8; FADT_SIZE];
    let put = |f: &mut [u8], off: usize, b: &[u8]| f[off..off + b.len()].copy_from_slice(b);
    let dsdt32 = u32::try_from(dsdt).map_err(|_| "ACPI: DSDT above 4 GiB".to_string())?;
    put(&mut f, FADT_DSDT, &dsdt32.to_le_bytes());
    put(&mut f, FADT_X_DSDT, &dsdt.to_le_bytes());
    let iapc = IAPC_VGA_NOT_PRESENT
        | IAPC_MSI_NOT_SUPPORTED
        | IAPC_PCIE_ASPM_CONTROLS
        | IAPC_CMOS_RTC_NOT_PRESENT;
    put(&mut f, FADT_IAPC_BOOT_ARCH, &iapc.to_le_bytes());
    let flags = FADT_F_WBINVD
        | FADT_F_PWR_BUTTON
        | FADT_F_SLP_BUTTON
        | FADT_F_RESET_REG_SUP
        | FADT_F_HW_REDUCED_ACPI;
    put(&mut f, FADT_FLAGS, &flags.to_le_bytes());
    put(
        &mut f,
        FADT_RESET_REG,
        &gas_io_byte(layout::ACPI_RESET_PORT),
    );
    f[FADT_RESET_VALUE] = RESET_VALUE;
    f[FADT_MINOR_VERSION] = FADT_MINOR_REVISION;
    put(
        &mut f,
        FADT_SLEEP_CONTROL_REG,
        &gas_io_byte(layout::ACPI_SLEEP_CONTROL_PORT),
    );
    put(
        &mut f,
        FADT_SLEEP_STATUS_REG,
        &gas_io_byte(layout::ACPI_SLEEP_STATUS_PORT),
    );
    put(&mut f, FADT_HYPERVISOR_VENDOR, &HYPERVISOR_VENDOR_ID);
    Ok(f.split_off(HEADER_SIZE))
}

/// The MADT after its header.
fn madt_body(cpus: usize) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&(layout::LAPIC_ADDR as u32).to_le_bytes());
    m.extend_from_slice(&MADT_PCAT_COMPAT.to_le_bytes());
    for i in 0..cpus {
        // Processor Local APIC: UID, APIC ID, flags.
        m.extend_from_slice(&[MADT_LOCAL_APIC, 8, i as u8, i as u8]);
        m.extend_from_slice(&MADT_LAPIC_ENABLED.to_le_bytes());
    }
    // I/O APIC: ID, reserved, address, GSI base.
    m.extend_from_slice(&[MADT_IO_APIC, 12, IOAPIC_ID, 0]);
    m.extend_from_slice(&(layout::IOAPIC_ADDR as u32).to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    // Interrupt Source Override: ISA bus, IRQ 0 → GSI 2, conforming.
    m.extend_from_slice(&[MADT_INT_SRC_OVERRIDE, 10, 0, 0]);
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    // Local APIC NMI: all processors (UID 0xff), conforming, LINT1.
    m.extend_from_slice(&[MADT_LOCAL_APIC_NMI, 6, 0xff]);
    m.extend_from_slice(&0u16.to_le_bytes());
    m.push(1);
    m
}

/// The DSDT's AML.
fn dsdt_body(cfg: &AcpiConfig<'_>) -> Result<Vec<u8>, String> {
    let s5 = aml::name(
        "\\_S5",
        &aml::package(&[
            aml::integer(u64::from(S5_SLEEP_TYPE)),
            aml::integer(0),
            aml::integer(0),
            aml::integer(0),
        ]),
    );
    let mut devices = Vec::new();
    if cfg.com1 {
        devices.push(aml::device(
            "COM1",
            &[
                aml::name("_HID", &aml::eisa_id("PNP0501")),
                aml::name("_UID", &aml::integer(0)),
                aml::name("_DDN", &aml::string("COM1")),
                aml::name(
                    "_CRS",
                    &aml::resource_template(&[
                        aml::io(layout::COM1_PORT, layout::COM1_PORT, 1, 8),
                        aml::interrupt(
                            Trigger::Edge,
                            Polarity::ActiveHigh,
                            false,
                            layout::COM1_GSI,
                        ),
                    ]),
                ),
            ],
        ));
    }
    if cfg.virtio.len() > 0x100 {
        return Err("ACPI: too many virtio devices".into());
    }
    for (n, v) in cfg.virtio.iter().enumerate() {
        let base = u32::try_from(v.base)
            .ok()
            .filter(|b| b.checked_add(v.size as u32).is_some() && v.size <= u64::from(u32::MAX))
            .ok_or_else(|| format!("ACPI: virtio device at {:#x} is above 4 GiB", v.base))?;
        devices.push(aml::device(
            &format!("VR{n:02X}"),
            &[
                aml::name("_HID", &aml::string("LNRO0005")),
                aml::name("_UID", &aml::integer(n as u64)),
                aml::name(
                    "_CRS",
                    &aml::resource_template(&[
                        aml::memory32_fixed(true, base, v.size as u32),
                        aml::interrupt(Trigger::Level, Polarity::ActiveHigh, false, v.gsi),
                    ]),
                ),
            ],
        ));
    }
    let mut body = s5;
    body.extend(aml::scope("\\_SB", &devices));
    Ok(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::aml::decode::{self, Resource, Term};
    use super::*;

    const BASE: u64 = layout::ACPI_ADDR;

    fn le16(d: &[u8], o: usize) -> u16 {
        u16::from_le_bytes(d[o..o + 2].try_into().unwrap())
    }
    fn le32(d: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
    }
    fn le64(d: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
    }
    fn sum(b: &[u8]) -> u8 {
        b.iter().fold(0u8, |a, &x| a.wrapping_add(x))
    }

    /// The tables found the way Linux finds them: scan `mem` (guest
    /// physical memory from `mem_base`) for the RSDP in the BIOS area on a
    /// 16-byte boundary, validate it, follow the XSDT. Returns
    /// signature → table bytes (checksums and lengths checked).
    pub(crate) fn find_tables(mem: &[u8], mem_base: u64) -> Vec<([u8; 4], Vec<u8>)> {
        let at = |gpa: u64| (gpa - mem_base) as usize;
        let rsdp = (0xe_0000u64..0x10_0000)
            .step_by(16)
            .find(|&a| &mem[at(a)..at(a) + 8] == b"RSD PTR ")
            .expect("no RSDP in 0xe0000..0xfffff");
        let r = &mem[at(rsdp)..at(rsdp) + RSDP_SIZE];
        assert_eq!(sum(&r[..20]), 0, "RSDP checksum");
        assert_eq!(r[15], 2, "RSDP revision");
        assert_eq!(le32(r, 20), 36, "RSDP length");
        assert_eq!(sum(r), 0, "RSDP extended checksum");
        let table = |gpa: u64| -> Vec<u8> {
            let h = &mem[at(gpa)..];
            let len = le32(h, 4) as usize;
            assert!(len >= HEADER_SIZE);
            let t = h[..len].to_vec();
            assert_eq!(sum(&t), 0, "{} checksum", String::from_utf8_lossy(&t[..4]));
            assert_eq!(&t[10..16], b"VEMU  ");
            t
        };
        let xsdt = table(le64(r, 24));
        assert_eq!(&xsdt[..4], b"XSDT");
        let mut out = vec![(*b"XSDT", xsdt.clone())];
        for e in xsdt[HEADER_SIZE..].chunks(8) {
            let t = table(u64::from_le_bytes(e.try_into().unwrap()));
            if &t[..4] == b"FACP" {
                let d = le64(&t, FADT_X_DSDT);
                assert_eq!(u64::from(le32(&t, FADT_DSDT)), d, "DSDT and X_DSDT agree");
                out.push((*b"DSDT", table(d)));
            }
            out.push((t[..4].try_into().unwrap(), t));
        }
        out
    }

    pub(crate) fn get<'a>(tables: &'a [([u8; 4], Vec<u8>)], sig: &[u8; 4]) -> &'a [u8] {
        &tables.iter().find(|(s, _)| s == sig).expect("table").1
    }

    fn slots(n: usize) -> Vec<VirtioDev> {
        (0..n)
            .map(|i| VirtioDev {
                base: layout::virtio_slot_base(i),
                size: layout::VIRTIO_SLOT_SIZE,
                gsi: layout::virtio_gsi(i),
            })
            .collect()
    }

    fn tables(cpus: usize, virtio: usize, com1: bool) -> Vec<([u8; 4], Vec<u8>)> {
        let v = slots(virtio);
        let blob = build(
            BASE,
            &AcpiConfig {
                cpus,
                virtio: &v,
                com1,
            },
        )
        .unwrap();
        let mut mem = vec![0u8; 0x2_0000];
        mem[..blob.len()].copy_from_slice(&blob);
        find_tables(&mem, BASE)
    }

    #[test]
    fn rsdp_xsdt() {
        let v = slots(1);
        let blob = build(
            BASE,
            &AcpiConfig {
                cpus: 1,
                virtio: &v,
                com1: false,
            },
        )
        .unwrap();
        assert_eq!(&blob[..8], b"RSD PTR ");
        assert_eq!(le32(&blob, 16), 0, "no RSDT");
        assert_eq!(le64(&blob, 24), BASE + 0x30, "XSDT right after the RSDP");
        let t = tables(1, 1, false);
        let x = get(&t, b"XSDT");
        assert_eq!(x.len(), 36 + 16);
        assert_eq!(x[8], 1, "XSDT revision");
        let sigs: Vec<_> = t.iter().map(|(s, _)| *s).collect();
        assert_eq!(sigs, [*b"XSDT", *b"DSDT", *b"FACP", *b"APIC"]);
    }

    #[test]
    fn fadt() {
        let t = tables(2, 3, false);
        let f = get(&t, b"FACP");
        assert_eq!(f.len(), 276);
        assert_eq!(f[8], 6, "revision");
        assert_eq!(f[131], 5, "minor revision");
        let flags = le32(f, 112);
        assert_eq!(flags, (1 << 20) | (1 << 10) | (1 << 5) | (1 << 4) | 1);
        assert_eq!(le16(f, 109), 0x3c, "no VGA, MSI, ASPM, CMOS RTC; no 8042");
        assert_eq!(le32(f, 36), 0, "no FACS");
        assert_eq!(le64(f, 132), 0, "no X_FACS");
        assert_eq!(le16(f, 46), 0, "no SCI");
        assert_eq!(le32(f, 56), 0, "no PM1a event block");
        // RESET_REG: System I/O, 8 bits at offset 0, byte access, 0x604.
        assert_eq!(&f[116..128], &[1, 8, 0, 1, 0x04, 0x06, 0, 0, 0, 0, 0, 0]);
        assert_eq!(f[128], 1, "RESET_VALUE");
        assert_eq!(&f[244..256], &[1, 8, 0, 1, 0x00, 0x06, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&f[256..268], &[1, 8, 0, 1, 0x01, 0x06, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&f[268..276], b"VEMU    ");
        // All legacy X_ blocks are empty.
        assert!(f[148..244].iter().all(|&b| b == 0));
    }

    #[test]
    fn madt() {
        let t = tables(4, 1, false);
        let m = get(&t, b"APIC");
        assert_eq!(m[8], 5);
        assert_eq!(le32(m, 36), 0xfee0_0000);
        assert_eq!(le32(m, 40), 1, "PCAT_COMPAT");
        let mut lapics = Vec::new();
        let mut ioapics = Vec::new();
        let mut overrides = Vec::new();
        let mut nmis = Vec::new();
        let mut i = 44;
        while i < m.len() {
            let (ty, len) = (m[i], usize::from(m[i + 1]));
            let e = &m[i..i + len];
            match ty {
                0 => {
                    assert_eq!(len, 8);
                    lapics.push((e[2], e[3], le32(e, 4)));
                }
                1 => {
                    assert_eq!(len, 12);
                    ioapics.push((e[2], le32(e, 4), le32(e, 8)));
                }
                2 => {
                    assert_eq!(len, 10);
                    overrides.push((e[2], e[3], le32(e, 4), le16(e, 8)));
                }
                4 => {
                    assert_eq!(len, 6);
                    nmis.push((e[2], le16(e, 3), e[5]));
                }
                _ => panic!("unexpected MADT entry {ty}"),
            }
            i += len;
        }
        assert_eq!(i, m.len());
        assert_eq!(lapics, [(0, 0, 1), (1, 1, 1), (2, 2, 1), (3, 3, 1)]);
        assert_eq!(ioapics, [(0, 0xfec0_0000, 0)]);
        assert_eq!(overrides, [(0, 0, 2, 0)]);
        assert_eq!(nmis, [(0xff, 0, 1)]);
    }

    #[test]
    fn madt_cpu_limits() {
        let v = slots(0);
        let b = |cpus| {
            build(
                BASE,
                &AcpiConfig {
                    cpus,
                    virtio: &v,
                    com1: false,
                },
            )
        };
        assert!(b(0).is_err());
        assert!(b(255).is_ok());
        assert!(b(256).is_err());
    }

    /// The DSDT's devices, decoded: (name, _HID, _UID, resources).
    type DecodedDev = (String, Term, Term, Vec<Resource>);
    fn dsdt_devices(dsdt: &[u8]) -> (Vec<Term>, Vec<DecodedDev>) {
        assert_eq!(dsdt[8], 2, "DSDT revision");
        let terms = decode::decode(&dsdt[HEADER_SIZE..]).unwrap();
        let mut devs = Vec::new();
        for t in &terms {
            if let Term::Scope(s, body) = t {
                assert_eq!(s, "\\_SB_");
                for d in body {
                    let Term::Device(name, items) = d else {
                        panic!("{d:?}")
                    };
                    let hid = Term::find_name(items, "_HID").unwrap().clone();
                    let uid = Term::find_name(items, "_UID").unwrap().clone();
                    let Some(Term::Buffer(crs)) = Term::find_name(items, "_CRS") else {
                        panic!("no _CRS buffer")
                    };
                    devs.push((name.clone(), hid, uid, decode::resources(crs).unwrap()));
                }
            }
        }
        (terms, devs)
    }

    #[test]
    fn dsdt_virtio_and_s5() {
        let t = tables(1, 16, false);
        let (terms, devs) = dsdt_devices(get(&t, b"DSDT"));
        assert_eq!(
            Term::find_name(&terms, "\\_S5_"),
            Some(&Term::Package(vec![
                Term::Integer(5),
                Term::Integer(0),
                Term::Integer(0),
                Term::Integer(0)
            ]))
        );
        assert_eq!(devs.len(), 16);
        for (n, (name, hid, uid, res)) in devs.iter().enumerate() {
            assert_eq!(name, &format!("VR{n:02X}"));
            assert_eq!(hid, &Term::String("LNRO0005".into()));
            assert_eq!(uid, &Term::Integer(n as u64));
            assert_eq!(
                res,
                &vec![
                    Resource::Memory32Fixed {
                        read_write: true,
                        base: 0xd000_0000 + 0x200 * n as u32,
                        length: 0x200
                    },
                    // Consumer, level, active high, exclusive.
                    Resource::Interrupt {
                        flags: 0x01,
                        irqs: vec![layout::virtio_gsi(n)]
                    },
                ]
            );
        }
    }

    #[test]
    fn dsdt_com1() {
        let (_, devs) = dsdt_devices(get(&tables(1, 1, true), b"DSDT"));
        let (name, hid, uid, res) = &devs[0];
        assert_eq!(name, "COM1");
        assert_eq!(
            hid,
            &Term::Integer(u64::from(aml::eisa_id_value("PNP0501")))
        );
        assert_eq!(uid, &Term::Integer(0));
        assert_eq!(
            res,
            &vec![
                Resource::Io {
                    decode16: true,
                    min: 0x3f8,
                    max: 0x3f8,
                    alignment: 1,
                    length: 8
                },
                // Consumer, edge, active high, exclusive.
                Resource::Interrupt {
                    flags: 0x03,
                    irqs: vec![4]
                },
            ]
        );
        assert_eq!(devs[1].0, "VR00");
        let (_, devs) = dsdt_devices(get(&tables(1, 1, false), b"DSDT"));
        assert_eq!(devs.len(), 1);
    }

    #[test]
    fn tables_fit_with_the_most_cpus_and_devices() {
        let v = slots(layout::VIRTIO_SLOTS);
        let blob = build(
            BASE,
            &AcpiConfig {
                cpus: 255,
                virtio: &v,
                com1: true,
            },
        )
        .unwrap();
        assert!(blob.len() as u64 <= layout::ACPI_MAX);
        // Every table is 16-byte aligned.
        let mut mem = vec![0u8; 0x2_0000];
        mem[..blob.len()].copy_from_slice(&blob);
        for (_, t) in find_tables(&mem, BASE) {
            let off = blob
                .windows(t.len())
                .position(|w| w == t.as_slice())
                .unwrap();
            assert_eq!(off % 16, 0);
        }
    }

    #[test]
    fn virtio_above_4_gib_is_refused() {
        let v = [VirtioDev {
            base: 1 << 32,
            size: 0x200,
            gsi: 5,
        }];
        assert!(
            build(
                BASE,
                &AcpiConfig {
                    cpus: 1,
                    virtio: &v,
                    com1: false
                }
            )
            .is_err()
        );
    }

    #[test]
    fn checksum_helper() {
        assert_eq!(checksum(&[]), 0);
        assert_eq!(checksum(&[1, 2, 3]), 0xfa);
        let t = sdt(*b"TEST", 1, *b"12345678", &[9; 7]);
        assert_eq!(t.len(), 43);
        assert_eq!(le32(&t, 4), 43);
        assert_eq!(sum(&t), 0);
        assert_eq!(&t[28..32], b"VEMU");
    }
}
