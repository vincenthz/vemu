//! Guest-physical memory map of the x86_64 machine, the e820 table and boot
//! image placement (docs/kvm-design.md, "x86_64 machine").
//!
//! | Range                         | What                                     |
//! |-------------------------------|------------------------------------------|
//! | `0x0000_0500`                 | boot GDT ([`BOOT_GDT`])                  |
//! | `0x0000_7000`                 | `boot_params` (the zero page)            |
//! | `0x0000_8ff0`                 | initial stack pointer (grows down)       |
//! | `0x0000_9000..0x0000_f000`    | identity page tables (PML4, PDPT, 4 PDs) |
//! | `0x0002_0000`                 | kernel command line                      |
//! | `0x0009_fc00..0x0010_0000`    | reserved (EBDA, VGA, BIOS area)          |
//! | `0x000e_0000`                 | ACPI tables, RSDP first                  |
//! | `0x000f_fff0`                 | reset vector stub ([`RESET_STUB`])       |
//! | `pref_address` (16 MiB)       | kernel (protected-mode part of bzImage)  |
//! | top of low RAM                | initrd                                   |
//! | `0xc000_0000..0x1_0000_0000`  | MMIO hole                                |
//! | `0xd000_0000`                 | virtio-mmio slots, `0x200` bytes each    |
//! | `0xfec0_0000`                 | IOAPIC (in-kernel)                       |
//! | `0xfee0_0000`                 | local APICs (in-kernel)                  |
//! | `0xfffb_c000..0xfffc_0000`    | KVM identity-map page + TSS (reserved)   |
//! | `0x1_0000_0000`               | RAM above 3 GiB, if any                  |
//!
//! [`BOOT_GDT`]: vemu_hv::x86_64::BOOT_GDT

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use std::fmt;

/// Guest RAM below the hole ends here at most.
pub const LOW_RAM_MAX: u64 = 0xc000_0000;
/// RAM beyond [`LOW_RAM_MAX`] continues here.
pub const HIGH_RAM_BASE: u64 = 0x1_0000_0000;
/// Largest guest RAM supported: 64 GiB, so the top of RAM (just above
/// 65 GiB) stays below 2^37, inside the physical address width of any
/// x86-64 host KVM runs on in practice (39 bits or more on current CPUs).
pub const MAX_RAM: u64 = 64 << 30;
/// Smallest guest RAM: room for the low-memory boot structures, a kernel
/// at 16 MiB and its decompression buffer.
pub const MIN_RAM: u64 = 32 << 20;
/// RAM size granule.
pub const RAM_ALIGN: u64 = 2 << 20;

pub const GDT_ADDR: u64 = 0x500;
pub const BOOT_PARAMS_ADDR: u64 = 0x7000;
pub const STACK_TOP: u64 = 0x8ff0;
/// PML4; then the PDPT and the four page directories, one page each.
pub const PML4_ADDR: u64 = 0x9000;
pub const PAGE_TABLES_END: u64 = PML4_ADDR + 6 * 0x1000;
pub const CMDLINE_ADDR: u64 = 0x2_0000;
/// Command line buffer (Linux's x86 COMMAND_LINE_SIZE).
pub const CMDLINE_MAX: u64 = 2048;
/// End of usable conventional memory (where a BIOS's EBDA would start).
pub const EBDA_START: u64 = 0x9_fc00;
/// ACPI tables; the RSDP at the start, in the BIOS area Linux scans.
pub const ACPI_ADDR: u64 = 0xe_0000;
pub const ACPI_MAX: u64 = 0x1_0000;
/// The reset vector, F000:FFF0 in real mode. A BIOS would be here; Linux's
/// "BIOS" reboot method (`machine_real_restart`, which a hardware-reduced
/// ACPI machine without EFI falls back to by default: `reboot_init` picks
/// BOOT_EFI, `efi_reboot` returns, then BOOT_BIOS) switches to real mode and
/// jumps here. [`RESET_STUB`] resets the machine through the ACPI reset
/// register instead of running whatever RAM holds.
pub const RESET_VECTOR: u64 = 0xf_fff0;
/// Real-mode code at [`RESET_VECTOR`]: `mov dx, ACPI_RESET_PORT; mov al,
/// RESET_VALUE; out dx, al; cli; hlt; jmp $-1` (back to the hlt).
pub const RESET_STUB: [u8; 10] = [
    0xba,
    ACPI_RESET_PORT as u8,
    (ACPI_RESET_PORT >> 8) as u8,
    0xb0,
    super::acpi::RESET_VALUE,
    0xee,
    0xfa,
    0xf4,
    0xeb,
    0xfd,
];
/// Start of extended memory: no kernel below this.
pub const HIGH_MEMORY: u64 = 0x10_0000;

pub const IOAPIC_ADDR: u64 = 0xfec0_0000;
pub const LAPIC_ADDR: u64 = 0xfee0_0000;
/// The page KVM uses for its EPT identity map (`KVM_SET_IDENTITY_MAP_ADDR`)
/// followed by the 3 pages of its real-mode TSS (`KVM_SET_TSS_ADDR`), set by
/// the backend. Reserved in the e820 table. These are the backend's own
/// constants, so the reservation always matches what it gives KVM.
pub use vemu_hv::x86_64::{KVM_IDENTITY_MAP_ADDR, KVM_RESERVED_END, KVM_TSS_ADDR};

pub const VIRTIO_BASE: u64 = 0xd000_0000;
pub const VIRTIO_SLOT_SIZE: u64 = 0x200;
pub const VIRTIO_SLOTS: usize = 16;
/// IOAPIC GSI of each virtio slot. The in-kernel IOAPIC has 24 pins; these
/// avoid the ISA interrupts a PC guest may still assume: 0/2 timer, 1
/// keyboard, 3 COM2, 4 COM1 (the debug UART), 8 RTC, 9 ACPI SCI.
pub const VIRTIO_GSIS: [u32; VIRTIO_SLOTS] =
    [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
/// Pins of the in-kernel IOAPIC (KVM_IOAPIC_NUM_PINS).
pub const IOAPIC_PINS: u32 = 24;

/// Debug 16550 (COM1).
pub const COM1_PORT: u16 = 0x3f8;
pub const COM1_GSI: u32 = 4;
/// Ports of the other legacy UARTs Linux probes.
pub const ABSENT_UART_PORTS: [u16; 3] = [0x2f8, 0x3e8, 0x2e8];
/// ACPI fixed registers (I/O space): sleep control, sleep status, reset.
pub const ACPI_PORT: u16 = 0x600;
pub const ACPI_PORT_COUNT: u16 = 8;
pub const ACPI_SLEEP_CONTROL_PORT: u16 = ACPI_PORT;
pub const ACPI_SLEEP_STATUS_PORT: u16 = ACPI_PORT + 1;
pub const ACPI_RESET_PORT: u16 = ACPI_PORT + 4;
/// i8042 data port (0x60) .. command/status port (0x64).
pub const I8042_PORT: u16 = 0x60;
pub const I8042_PORT_COUNT: u16 = 5;
/// PCI configuration mechanism #1 address (0xcf8) and data (0xcfc) ports.
pub const PCI_CONFIG_PORT: u16 = 0xcf8;
pub const PCI_CONFIG_PORT_COUNT: u16 = 8;
/// CMOS RTC index/data ports (not emulated; the FADT says there is none).
pub const CMOS_PORT: u16 = 0x70;
/// POST code / I/O delay port 0x80 and the 8237 DMA page registers around
/// it (0x81-0x8f). Linux's `i8237A_init_ops` reads DMA_PAGE_0 (0x87) and
/// takes 0xff to mean "no legacy DMA controller", as on PCHs since Skylake.
pub const POST_PORT: u16 = 0x80;
pub const POST_PORT_COUNT: u16 = 0x10;

// Every virtio GSI is a pin of the IOAPIC.
const _: () = {
    let mut i = 0;
    while i < VIRTIO_SLOTS {
        assert!(VIRTIO_GSIS[i] < IOAPIC_PINS);
        i += 1;
    }
};
// The fixed low-memory structures don't overlap each other.
const _: () = assert!(GDT_ADDR + 32 <= BOOT_PARAMS_ADDR);
const _: () = assert!(BOOT_PARAMS_ADDR + 0x1000 <= STACK_TOP);
const _: () = assert!(STACK_TOP < PML4_ADDR);
const _: () = assert!(PAGE_TABLES_END <= CMDLINE_ADDR);
const _: () = assert!(CMDLINE_ADDR + CMDLINE_MAX <= EBDA_START);
const _: () = assert!(ACPI_ADDR + ACPI_MAX <= RESET_VECTOR);
const _: () = assert!(RESET_VECTOR + RESET_STUB.len() as u64 <= HIGH_MEMORY);
const _: () = assert!(MIN_RAM > HIGH_MEMORY);
// The MMIO windows are inside the hole and don't overlap.
const _: () = assert!(LOW_RAM_MAX <= VIRTIO_BASE);
const _: () = assert!(VIRTIO_BASE + VIRTIO_SLOTS as u64 * VIRTIO_SLOT_SIZE <= IOAPIC_ADDR);
const _: () = assert!(IOAPIC_ADDR + 0x1000 <= LAPIC_ADDR);
const _: () = assert!(LAPIC_ADDR + 0x10_0000 <= KVM_IDENTITY_MAP_ADDR);
const _: () = assert!(KVM_IDENTITY_MAP_ADDR + 0x1000 == KVM_TSS_ADDR);
const _: () = assert!(KVM_RESERVED_END <= HIGH_RAM_BASE);

/// Guest-physical base of virtio slot `n`.
pub const fn virtio_slot_base(n: usize) -> u64 {
    VIRTIO_BASE + n as u64 * VIRTIO_SLOT_SIZE
}

/// IOAPIC GSI of virtio slot `n < VIRTIO_SLOTS`.
pub const fn virtio_gsi(n: usize) -> u32 {
    VIRTIO_GSIS[n]
}

/// Why the memory size or the boot images don't fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutError(pub String);

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LayoutError {}

/// Check a guest RAM size: between [`MIN_RAM`] and [`MAX_RAM`], a multiple
/// of [`RAM_ALIGN`].
pub fn check_ram_size(size: u64) -> Result<(), LayoutError> {
    if size < MIN_RAM {
        return Err(LayoutError(format!(
            "at least {} MiB of memory is needed for an x86_64 guest",
            MIN_RAM >> 20
        )));
    }
    if size > MAX_RAM {
        return Err(LayoutError(format!(
            "at most {} MiB of memory is supported for an x86_64 guest",
            MAX_RAM >> 20
        )));
    }
    if !size.is_multiple_of(RAM_ALIGN) {
        return Err(LayoutError(format!(
            "memory size must be a multiple of {} MiB",
            RAM_ALIGN >> 20
        )));
    }
    Ok(())
}

/// Guest RAM as `(gpa, size)` ranges: below the hole, then above 4 GiB.
pub fn ram_ranges(size: u64) -> Vec<(u64, u64)> {
    let low = size.min(LOW_RAM_MAX);
    let mut out = vec![(0, low)];
    if size > low {
        out.push((HIGH_RAM_BASE, size - low));
    }
    out
}

/// e820 entry types (Linux `enum e820_type`).
pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;

/// One entry of the BIOS e820 memory map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub kind: u32,
}

/// The e820 map for `size` bytes of RAM: conventional memory up to the
/// EBDA, the BIOS area reserved (the ACPI tables live there), extended
/// memory, the KVM pages in the hole reserved, and RAM above 4 GiB.
pub fn e820_map(size: u64) -> Vec<E820Entry> {
    let e = |addr, end: u64, kind| E820Entry {
        addr,
        size: end - addr,
        kind,
    };
    let ranges = ram_ranges(size);
    let low_end = ranges[0].1;
    let mut map = vec![
        e(0, EBDA_START, E820_RAM),
        e(EBDA_START, HIGH_MEMORY, E820_RESERVED),
        e(HIGH_MEMORY, low_end, E820_RAM),
        e(KVM_IDENTITY_MAP_ADDR, KVM_RESERVED_END, E820_RESERVED),
    ];
    if let Some(&(gpa, len)) = ranges.get(1) {
        map.push(e(gpa, gpa + len, E820_RAM));
    }
    map
}

/// Where the boot images go (guest-physical addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootLayout {
    /// Load address of the protected-mode kernel; the 64-bit entry point is
    /// at `+ 0x200`.
    pub kernel: u64,
    /// End of the memory the kernel uses before it reads the memory map:
    /// the loaded image and its decompression buffer (`init_size` from its
    /// runtime start).
    pub kernel_end: u64,
    /// `[start, end)` of the initrd.
    pub initrd: Option<(u64, u64)>,
}

/// What the placement needs to know about the kernel (from its setup
/// header, see `bzimage::SetupHeader`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelPlacement {
    /// Size of the protected-mode part to load.
    pub load_size: u64,
    pub relocatable: bool,
    /// `pref_address`: where a non-relocatable kernel runs.
    pub pref_address: u64,
    /// `kernel_alignment` (a power of two).
    pub alignment: u64,
    /// `init_size`: memory needed from the runtime start address.
    pub init_size: u64,
    /// `initrd_addr_max`: highest address the initrd may occupy.
    pub initrd_addr_max: u64,
}

/// Place the kernel and the initrd in `ram_size` bytes of RAM, following
/// Documentation/arch/x86/boot.rst: a relocatable kernel is loaded at its
/// runtime start (`pref_address`, aligned up to `kernel_alignment`, at
/// least 1 MiB), so the image and its `init_size` buffer are one range; a
/// non-relocatable one at 1 MiB, running at `pref_address`. The initrd goes
/// as high as possible in low RAM, below `initrd_addr_max`, page-aligned,
/// above everything the kernel uses.
pub fn boot_layout(
    ram_size: u64,
    k: &KernelPlacement,
    initrd_size: Option<u64>,
) -> Result<BootLayout, LayoutError> {
    check_ram_size(ram_size)?;
    let low_end = ram_size.min(LOW_RAM_MAX);
    let too_small = |what: &str| {
        LayoutError(format!(
            "{} MiB of memory is too small for the {what}",
            ram_size >> 20
        ))
    };
    let bad = |what: &str| LayoutError(format!("kernel: {what}"));

    let runtime = if k.relocatable {
        k.pref_address
            .max(HIGH_MEMORY)
            .checked_next_multiple_of(k.alignment)
            .ok_or_else(|| bad("bad pref_address/kernel_alignment"))?
    } else {
        if k.pref_address < HIGH_MEMORY {
            return Err(bad("non-relocatable kernel with pref_address below 1 MiB"));
        }
        k.pref_address
    };
    let kernel = if k.relocatable { runtime } else { HIGH_MEMORY };
    let image_end = kernel
        .checked_add(k.load_size)
        .ok_or_else(|| too_small("kernel"))?;
    let buffer_end = runtime
        .checked_add(k.init_size)
        .ok_or_else(|| too_small("kernel"))?;
    let kernel_end = image_end.max(buffer_end);
    if kernel_end > low_end {
        return Err(too_small("kernel"));
    }

    let initrd = match initrd_size {
        None => None,
        Some(len) => {
            let top = low_end.min(k.initrd_addr_max.saturating_add(1));
            let start = top
                .checked_sub(len)
                .map(|s| s & !0xfff)
                .filter(|&s| s >= kernel_end)
                .ok_or_else(|| too_small("kernel and initrd"))?;
            Some((start, start + len))
        }
    };
    Ok(BootLayout {
        kernel,
        kernel_end,
        initrd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    fn skeletos() -> KernelPlacement {
        // The 7.2.15 test kernel's header values.
        KernelPlacement {
            load_size: 0xf8440 * 16,
            relocatable: true,
            pref_address: 0x100_0000,
            alignment: 0x20_0000,
            init_size: 0x30a_0000,
            initrd_addr_max: 0x7fff_ffff,
        }
    }

    #[test]
    fn slots_and_gsis() {
        assert_eq!(virtio_slot_base(0), 0xd000_0000);
        assert_eq!(virtio_slot_base(15), 0xd000_1e00);
        let mut seen = std::collections::HashSet::new();
        for n in 0..VIRTIO_SLOTS {
            let g = virtio_gsi(n);
            assert!(g < IOAPIC_PINS);
            assert!(![0, 1, 2, 3, 4, 8, 9].contains(&g), "GSI {g} is an ISA one");
            assert!(seen.insert(g), "GSI {g} used twice");
        }
    }

    #[test]
    fn ram_split_at_the_hole() {
        assert_eq!(ram_ranges(GIB), vec![(0, GIB)]);
        assert_eq!(ram_ranges(3 * GIB), vec![(0, 3 * GIB)]);
        assert_eq!(ram_ranges(5 * GIB), vec![(0, 3 * GIB), (4 * GIB, 2 * GIB)]);
    }

    #[test]
    fn ram_size_limits() {
        assert!(check_ram_size(GIB).is_ok());
        assert!(check_ram_size(MIN_RAM).is_ok());
        assert!(check_ram_size(MAX_RAM).is_ok());
        let e = check_ram_size(MAX_RAM + RAM_ALIGN).unwrap_err().0;
        assert!(e.contains("at most 65536 MiB"), "{e}");
        assert!(check_ram_size(5 * GIB).is_ok(), "RAM above the hole");
        assert!(
            check_ram_size(16 * MIB)
                .unwrap_err()
                .0
                .contains("at least 32 MiB")
        );
        assert!(
            check_ram_size(GIB + 4096)
                .unwrap_err()
                .0
                .contains("multiple of 2 MiB")
        );
    }

    #[test]
    fn e820_low_ram_only() {
        let m = e820_map(GIB);
        assert_eq!(
            m,
            vec![
                E820Entry {
                    addr: 0,
                    size: 0x9_fc00,
                    kind: E820_RAM
                },
                E820Entry {
                    addr: 0x9_fc00,
                    size: 0x6_0400,
                    kind: E820_RESERVED
                },
                E820Entry {
                    addr: 0x10_0000,
                    size: GIB - 0x10_0000,
                    kind: E820_RAM
                },
                E820Entry {
                    addr: 0xfffb_c000,
                    size: 0x4000,
                    kind: E820_RESERVED
                },
            ]
        );
    }

    #[test]
    fn e820_with_high_ram_is_sorted_and_disjoint() {
        let m = e820_map(5 * GIB);
        assert_eq!(m.len(), 5);
        assert_eq!(
            m[3],
            E820Entry {
                addr: 0xfffb_c000,
                size: 0x4000,
                kind: E820_RESERVED
            }
        );
        assert_eq!(
            m[4],
            E820Entry {
                addr: 4 * GIB,
                size: 2 * GIB,
                kind: E820_RAM
            }
        );
        for w in m.windows(2) {
            assert!(w[0].addr + w[0].size <= w[1].addr, "{w:?}");
        }
        let ram: u64 = m
            .iter()
            .filter(|e| e.kind == E820_RAM)
            .map(|e| e.size)
            .sum();
        assert_eq!(ram, 5 * GIB - (HIGH_MEMORY - EBDA_START));
    }

    #[test]
    fn relocatable_kernel_runs_where_it_is_loaded() {
        let k = skeletos();
        let b = boot_layout(GIB, &k, Some(600 * 1024)).unwrap();
        assert_eq!(b.kernel, 0x100_0000);
        assert_eq!(b.kernel_end, 0x100_0000 + 0x30a_0000, "init_size dominates");
        let (s, e) = b.initrd.unwrap();
        assert_eq!(s % 4096, 0);
        assert!(e <= GIB && e > GIB - 4096);
        assert_eq!(e - s, 600 * 1024);
    }

    #[test]
    fn initrd_below_initrd_addr_max() {
        let k = KernelPlacement {
            initrd_addr_max: 0x37ff_ffff,
            ..skeletos()
        };
        let (s, e) = boot_layout(2 * GIB, &k, Some(10 * MIB))
            .unwrap()
            .initrd
            .unwrap();
        assert!(e <= 0x3800_0000, "{e:#x}");
        assert_eq!(s, 0x3800_0000 - 10 * MIB);
    }

    #[test]
    fn unaligned_pref_address_is_aligned_up() {
        let k = KernelPlacement {
            pref_address: 0x10_0000,
            alignment: 0x20_0000,
            ..skeletos()
        };
        let b = boot_layout(GIB, &k, None).unwrap();
        assert_eq!(b.kernel, 0x20_0000);
        assert_eq!(b.initrd, None);
    }

    #[test]
    fn non_relocatable_kernel_is_loaded_at_1_mib() {
        let k = KernelPlacement {
            relocatable: false,
            ..skeletos()
        };
        let b = boot_layout(GIB, &k, None).unwrap();
        assert_eq!(b.kernel, HIGH_MEMORY);
        assert_eq!(b.kernel_end, 0x100_0000 + 0x30a_0000);
    }

    #[test]
    fn too_small() {
        let k = skeletos();
        // The kernel needs 16 MiB + init_size (48.6 MiB).
        assert!(boot_layout(66 * MIB, &k, None).is_ok());
        let e = boot_layout(64 * MIB, &k, None).unwrap_err().0;
        assert_eq!(e, "64 MiB of memory is too small for the kernel");
        let e = boot_layout(66 * MIB, &k, Some(2 * MIB)).unwrap_err().0;
        assert_eq!(e, "66 MiB of memory is too small for the kernel and initrd");
        assert!(boot_layout(68 * MIB, &k, Some(2 * MIB)).is_ok());
    }
}
