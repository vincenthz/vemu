//! Assembling the boot state in guest RAM: kernel, initrd, command line,
//! `boot_params`, page tables, GDT and ACPI tables, and the boot vCPU's
//! entry state for the 64-bit boot protocol (Documentation/arch/x86/boot.rst,
//! "64-bit BOOT PROTOCOL").

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use vemu_core::GuestMemory;
use vemu_hv::x86_64::BootState;

use super::acpi::{self, AcpiConfig, VirtioDev};
use super::bootparams::{self, BootParams};
use super::bzimage::{BzImage, ENTRY_64_OFFSET};
use super::layout::{self, BootLayout};
use crate::bootfile::Initrd;

/// What the firmware tables describe.
pub struct MachineDesc<'a> {
    pub cpus: usize,
    /// Guest RAM in bytes (for the e820 map).
    pub ram_size: u64,
    pub cmdline: &'a str,
    pub virtio: &'a [VirtioDev],
    /// The debug UART (COM1) is present.
    pub com1: bool,
}

/// Check the command line fits the kernel and the buffer.
pub fn check_cmdline(kernel: &BzImage, cmdline: &str) -> Result<(), String> {
    let max = (u64::from(kernel.header().cmdline_size)).min(layout::CMDLINE_MAX - 1);
    if cmdline.len() as u64 > max || cmdline.contains('\0') {
        return Err(format!(
            "kernel command line is {} bytes; this kernel accepts at most {max}",
            cmdline.len()
        ));
    }
    Ok(())
}

/// Warnings for kernel options that leave this machine's guest without an
/// interrupt controller. The machine is hardware-reduced ACPI, so Linux
/// replaces the legacy PIC with a null one (`acpi_generic_reduced_hw_init`)
/// and the IOAPIC (with the LAPIC) is the only interrupt route. Options
/// that turn the IOAPIC (or the LAPIC) off leave no route at all: the virtio-mmio devices
/// fail to probe ("IRQ index 0 not found") and the hvc0 console stays
/// silent, although the guest still runs and can power off.
pub fn cmdline_warnings(cmdline: &str) -> Vec<String> {
    const WHY: &str = "this machine is hardware-reduced ACPI with no legacy PIC, so the guest \
                       gets no device interrupts: virtio devices and the hvc0 console will not work";
    let mut out = Vec::new();
    // Words after a bare "--" are for init, not the kernel.
    for word in cmdline.split_whitespace().take_while(|w| *w != "--") {
        let (off, fix) = match word {
            "nosmp" => (
                "the IOAPIC",
                "remove it (to run one vCPU, use --cpus 1 instead)",
            ),
            "noapic" => ("the IOAPIC", "remove it"),
            "nolapic" => ("the local APIC and the IOAPIC", "remove it"),
            w if w
                .strip_prefix("maxcpus=")
                .is_some_and(|v| parse_kernel_uint(v) == Some(0)) =>
            {
                (
                    "the IOAPIC",
                    "remove it (to run one vCPU, use --cpus 1 or maxcpus=1 instead)",
                )
            }
            _ => continue,
        };
        out.push(format!(
            "kernel option `{word}` turns off {off}, and {WHY}; {fix}"
        ));
    }
    out
}

/// An unsigned integer as the kernel's `get_option` reads it (base 0:
/// decimal, 0x hex or leading-0 octal).
fn parse_kernel_uint(v: &str) -> Option<u64> {
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if v.len() > 1 && v.starts_with('0') {
        u64::from_str_radix(&v[1..], 8).ok()
    } else {
        v.parse().ok()
    }
}

/// Write everything the guest needs into `mem` (the low RAM region, at
/// guest-physical 0) and return the boot vCPU's state.
pub fn load(
    mem: &GuestMemory,
    kernel: &BzImage,
    boot: &BootLayout,
    initrd: Option<&mut Initrd>,
    m: &MachineDesc<'_>,
) -> Result<BootState, String> {
    let w = |what: &str, gpa: u64, bytes: &[u8]| {
        mem.write(gpa, bytes)
            .map_err(|e| format!("cannot load the {what}: {e}"))
    };
    w("kernel", boot.kernel, kernel.protected_mode())?;
    if let (Some((start, _)), Some(initrd)) = (boot.initrd, initrd) {
        initrd.load(mem, start)?;
    }

    check_cmdline(kernel, m.cmdline)?;
    let mut cmdline = m.cmdline.as_bytes().to_vec();
    cmdline.push(0);
    w("command line", layout::CMDLINE_ADDR, &cmdline)?;

    let tables = acpi::build(
        layout::ACPI_ADDR,
        &AcpiConfig {
            cpus: m.cpus,
            virtio: m.virtio,
            com1: m.com1,
        },
    )?;
    w("ACPI tables", layout::ACPI_ADDR, &tables)?;

    let e820 = layout::e820_map(m.ram_size);
    let zero_page = bootparams::build(&BootParams {
        setup_header: kernel.setup_header_bytes(),
        cmdline_addr: layout::CMDLINE_ADDR,
        initrd: boot.initrd.map(|(s, e)| (s, e - s)),
        e820: &e820,
        rsdp_addr: layout::ACPI_ADDR,
    })?;
    w("boot parameters", layout::BOOT_PARAMS_ADDR, &zero_page)?;
    w(
        "page tables",
        layout::PML4_ADDR,
        &bootparams::identity_page_tables(layout::PML4_ADDR),
    )?;
    w("GDT", layout::GDT_ADDR, &bootparams::gdt_bytes())?;
    w("reset vector", layout::RESET_VECTOR, &layout::RESET_STUB)?;

    Ok(BootState {
        rip: boot.kernel + ENTRY_64_OFFSET,
        rsi: layout::BOOT_PARAMS_ADDR,
        rsp: layout::STACK_TOP,
        cr3: layout::PML4_ADDR,
        gdt_base: layout::GDT_ADDR,
    })
}

#[cfg(test)]
mod tests {
    use super::super::acpi::tests::{find_tables, get};
    use super::super::bzimage;
    use super::*;
    use std::path::PathBuf;

    const MIB: u64 = 1 << 20;

    #[test]
    fn interrupt_less_options_warned() {
        assert!(cmdline_warnings("console=hvc0 vemu.test=1").is_empty());
        assert!(cmdline_warnings("maxcpus=1 nosmpx xnoapic lapic maxcpus=10").is_empty());
        for (line, opt, fix) in [
            (
                "console=hvc0 nosmp",
                "`nosmp`",
                "remove it (to run one vCPU, use --cpus 1",
            ),
            ("noapic console=hvc0", "`noapic`", "remove it"),
            ("nolapic", "`nolapic` turns off the local APIC", "remove it"),
            ("maxcpus=0", "`maxcpus=0`", "maxcpus=1"),
            ("maxcpus=0x0", "`maxcpus=0x0`", "maxcpus=1"),
            ("maxcpus=00", "`maxcpus=00`", "maxcpus=1"),
        ] {
            let w = cmdline_warnings(line);
            assert_eq!(w.len(), 1, "{line}: {w:?}");
            assert!(w[0].contains(opt), "{}", w[0]);
            assert!(w[0].contains(fix), "{}", w[0]);
            assert!(w[0].contains("no device interrupts"), "{}", w[0]);
        }
        assert_eq!(cmdline_warnings("nosmp noapic").len(), 2);
        // Arguments for init are not kernel options.
        assert!(cmdline_warnings("console=hvc0 -- nosmp").is_empty());
    }

    fn le32(d: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
    }

    fn fake_kernel() -> BzImage {
        // Same shape as bzimage's test image (relocatable, 16 MiB, 4 MiB
        // init_size), with a recognisable protected-mode part.
        let mut d = vec![0u8; 1024 + 8192];
        d[bzimage::OFF_SETUP_SECTS] = 1;
        d[bzimage::OFF_SYSSIZE..][..4].copy_from_slice(&(8192u32 / 16).to_le_bytes());
        d[bzimage::OFF_BOOT_FLAG..][..2].copy_from_slice(&0xaa55u16.to_le_bytes());
        d[bzimage::OFF_JUMP..][..2].copy_from_slice(&[0xeb, 0x6a]);
        d[bzimage::OFF_HEADER..][..4].copy_from_slice(b"HdrS");
        d[bzimage::OFF_VERSION..][..2].copy_from_slice(&0x020fu16.to_le_bytes());
        d[bzimage::OFF_LOADFLAGS] = bzimage::LOADED_HIGH;
        d[bzimage::OFF_INITRD_ADDR_MAX..][..4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        d[bzimage::OFF_KERNEL_ALIGNMENT..][..4].copy_from_slice(&0x20_0000u32.to_le_bytes());
        d[bzimage::OFF_RELOCATABLE_KERNEL] = 1;
        d[bzimage::OFF_XLOADFLAGS..][..2].copy_from_slice(&1u16.to_le_bytes());
        d[bzimage::OFF_CMDLINE_SIZE..][..4].copy_from_slice(&2047u32.to_le_bytes());
        d[bzimage::OFF_PREF_ADDRESS..][..8].copy_from_slice(&0x100_0000u64.to_le_bytes());
        d[bzimage::OFF_INIT_SIZE..][..4].copy_from_slice(&(4u32 << 20).to_le_bytes());
        d[1024..1028].copy_from_slice(b"KERN");
        BzImage::parse(d).unwrap()
    }

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vemu-x86-boot-{name}-{}", std::process::id()))
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

    #[test]
    fn everything_lands_where_boot_state_says() {
        let ram = 64 * MIB;
        let kernel = fake_kernel();
        let initrd_path = temp_file("initrd");
        std::fs::write(&initrd_path, b"070701 fake cpio").unwrap();
        let mut initrd = Initrd::open(&initrd_path, ram).unwrap();
        let boot = layout::boot_layout(ram, &kernel.placement(), Some(initrd.size())).unwrap();
        let mem = GuestMemory::new(0, ram as usize).unwrap();
        let v = slots(3);
        let cmdline = "console=hvc0 quiet";
        let s = load(
            &mem,
            &kernel,
            &boot,
            Some(&mut initrd),
            &MachineDesc {
                cpus: 2,
                ram_size: ram,
                cmdline,
                virtio: &v,
                com1: false,
            },
        )
        .unwrap();
        std::fs::remove_file(&initrd_path).unwrap();

        assert_eq!(
            s,
            BootState {
                rip: 0x100_0200,
                rsi: 0x7000,
                rsp: 0x8ff0,
                cr3: 0x9000,
                gdt_base: 0x500
            }
        );
        let mut all = vec![0u8; ram as usize];
        mem.read(0, &mut all).unwrap();
        // Kernel at its load address.
        assert_eq!(&all[0x100_0000..0x100_0004], b"KERN");
        // boot_params: the header, the command line, the initrd.
        let z = &all[0x7000..0x8000];
        assert_eq!(&z[0x202..0x206], b"HdrS");
        assert_eq!(z[0x210], 0xff);
        let cmd = le32(z, 0x228) as usize;
        assert_eq!(&all[cmd..cmd + cmdline.len() + 1], b"console=hvc0 quiet\0");
        let (rd, rd_len) = (le32(z, 0x218) as usize, le32(z, 0x21c) as usize);
        assert_eq!(&all[rd..rd + rd_len], b"070701 fake cpio");
        assert!(rd as u64 >= boot.kernel_end);
        // e820: RAM covers the kernel, the initrd and the low structures.
        let n = usize::from(z[0x1e8]);
        let e820: Vec<(u64, u64, u32)> = (0..n)
            .map(|i| {
                let o = 0x2d0 + 20 * i;
                (
                    u64::from_le_bytes(z[o..o + 8].try_into().unwrap()),
                    u64::from_le_bytes(z[o + 8..o + 16].try_into().unwrap()),
                    le32(z, o + 16),
                )
            })
            .collect();
        let is_ram = |a: u64, len: u64| {
            e820.iter()
                .any(|&(s, l, t)| t == 1 && s <= a && a + len <= s + l)
        };
        assert!(is_ram(0x100_0000, boot.kernel_end - 0x100_0000));
        assert!(is_ram(rd as u64, rd_len as u64));
        for a in [0x500, 0x7000, 0x8000, 0x9000, 0x2_0000] {
            assert!(is_ram(a, 0x1000), "{a:#x}");
        }
        assert!(!is_ram(0xe_0000, 1), "ACPI tables are in reserved memory");
        // The RSDP pointer, and the tables.
        assert_eq!(
            u64::from_le_bytes(z[0x70..0x78].try_into().unwrap()),
            0xe_0000
        );
        let t = find_tables(&all, 0);
        assert_eq!(get(&t, b"APIC").len(), 44 + 2 * 8 + 12 + 10 + 6);
        // GDT and page tables.
        assert_eq!(&all[0x510..0x518], &0x00af_9b00_0000_ffffu64.to_le_bytes());
        assert_eq!(&all[0x9000..0x9008], &0xa003u64.to_le_bytes());
        // The reset vector stub (reserved memory): out 0x604, 1.
        assert!(!is_ram(0xf_fff0, 16));
        assert_eq!(
            &all[0xf_fff0..0xf_fffa],
            &[0xba, 0x04, 0x06, 0xb0, 0x01, 0xee, 0xfa, 0xf4, 0xeb, 0xfd]
        );
    }

    #[test]
    fn command_line_limits() {
        let k = fake_kernel();
        assert!(check_cmdline(&k, &"x".repeat(2047)).is_ok());
        let e = check_cmdline(&k, &"x".repeat(2048)).unwrap_err();
        assert_eq!(
            e,
            "kernel command line is 2048 bytes; this kernel accepts at most 2047"
        );
        assert!(check_cmdline(&k, "a\0b").is_err());
    }

    /// Lay out the real test kernel in a default-sized machine (skipped
    /// without the fixture).
    #[test]
    fn real_bzimage_layout() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/x86_64");
        let (kpath, ipath) = (root.join("bzImage"), root.join("initramfs.cpio.gz"));
        if !kpath.is_file() {
            eprintln!("skipped: no testdata/x86_64/bzImage (scripts/mk-testdata.sh)");
            return;
        }
        let ram = 256 * MIB;
        let kernel = BzImage::from_file(&kpath, ram).unwrap();
        let mut initrd = ipath.is_file().then(|| Initrd::open(&ipath, ram).unwrap());
        let boot = layout::boot_layout(ram, &kernel.placement(), initrd.as_ref().map(Initrd::size))
            .unwrap();
        let mem = GuestMemory::new(0, ram as usize).unwrap();
        let v = slots(4);
        let s = load(
            &mem,
            &kernel,
            &boot,
            initrd.as_mut(),
            &MachineDesc {
                cpus: 4,
                ram_size: ram,
                cmdline: "console=hvc0",
                virtio: &v,
                com1: true,
            },
        )
        .unwrap();
        assert_eq!(s.rip, kernel.header().pref_address + 0x200);
        let mut entry = [0u8; 16];
        mem.read(boot.kernel, &mut entry).unwrap();
        assert_eq!(&entry, &kernel.protected_mode()[..16]);
    }
}
