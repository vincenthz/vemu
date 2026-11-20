//! Guest-physical memory map and boot image placement.
//!
//! The map mirrors QEMU's `virt` machine (see DESIGN.md, "Machine layout"):
//!
//! | Base          | What                                            |
//! |---------------|-------------------------------------------------|
//! | `0x0800_0000` | GIC distributor                                 |
//! | `0x0801_0000` | GICv2 CPU interface (KVM hosts without GICv3)   |
//! | `0x080A_0000` | GICv3 redistributors (`cpus * 0x20000`)         |
//! | `0x0900_0000` | debug PL011 (only with `--debug-uart`)          |
//! | `0x0901_0000` | PL031 real-time clock                           |
//! | `0x0A00_0000` | virtio-mmio slots, `0x200` bytes each, 32 slots |
//! | `0x4000_0000` | RAM                                             |

use std::fmt;

pub const GIC_DIST_BASE: u64 = 0x0800_0000;
/// GICv2 only: CPU interface (QEMU `virt`'s VIRT_GIC_CPU).
pub const GIC_V2_CPU_BASE: u64 = 0x0801_0000;
pub const GIC_REDIST_BASE: u64 = 0x080A_0000;

pub const UART_BASE: u64 = 0x0900_0000;
pub const UART_SIZE: u64 = 0x1000;
/// GIC INTID of the debug UART (DT `GIC_SPI 1`).
pub const UART_INTID: u32 = 33;

/// PL031 RTC (QEMU `virt`'s VIRT_RTC).
pub const RTC_BASE: u64 = 0x0901_0000;
pub const RTC_SIZE: u64 = 0x1000;
/// GIC INTID of the RTC alarm (DT `GIC_SPI 2`).
pub const RTC_INTID: u32 = 34;

pub const VIRTIO_BASE: u64 = 0x0A00_0000;
pub const VIRTIO_SLOT_SIZE: u64 = 0x200;
pub const VIRTIO_SLOTS: usize = 32;
/// GIC INTID of virtio slot 0; slot `n` uses `VIRTIO_INTID_BASE + n`.
pub const VIRTIO_INTID_BASE: u32 = 48;

pub const RAM_BASE: u64 = 0x4000_0000;
/// The guest-physical address space the VM maps (Hypervisor.framework's
/// default IPA size, 36 bits).
pub const IPA_LIMIT: u64 = 1 << 36;
/// Largest RAM that fits below [`IPA_LIMIT`].
pub const MAX_RAM: u64 = IPA_LIMIT - RAM_BASE;
/// RAM size granule: the kernel and DTB placement work in 2 MiB blocks.
pub const RAM_ALIGN: u64 = 2 << 20;

/// Largest device tree the arm64 boot protocol accepts.
pub const DTB_MAX_SIZE: u64 = 2 << 20;
/// arm64 boot protocol: the initrd must lie in a 1 GiB-aligned window of at
/// most 32 GiB that also covers the kernel. RAM starts at 1 GiB, so keeping
/// the initrd below 32 GiB satisfies that for every RAM size.
const INITRD_LIMIT: u64 = 32 << 30;
/// Initrd start alignment (any guest page size divides it).
const INITRD_ALIGN: u64 = 64 << 10;

/// Redistributor frame per vCPU (RD_base + SGI_base).
const GIC_REDIST_STRIDE: u64 = 0x20000;
/// Most vCPUs a VM can have (Hypervisor.framework's limit).
pub const MAX_CPUS: usize = 64;

// The windows don't overlap each other or RAM, even with the most vCPUs.
const _: () = assert!(GIC_DIST_BASE + 0x10000 <= GIC_V2_CPU_BASE);
const _: () = assert!(GIC_V2_CPU_BASE + 0x10000 <= GIC_REDIST_BASE);
const _: () = assert!(GIC_REDIST_BASE + MAX_CPUS as u64 * GIC_REDIST_STRIDE <= UART_BASE);
const _: () = assert!(UART_BASE + UART_SIZE <= RTC_BASE);
const _: () = assert!(RTC_BASE + RTC_SIZE <= VIRTIO_BASE);
const _: () = assert!(VIRTIO_BASE + VIRTIO_SLOTS as u64 * VIRTIO_SLOT_SIZE <= RAM_BASE);

/// Guest-physical base of virtio slot `n`.
pub fn virtio_slot_base(n: usize) -> u64 {
    VIRTIO_BASE + n as u64 * VIRTIO_SLOT_SIZE
}

/// GIC INTID of virtio slot `n`.
pub fn virtio_intid(n: usize) -> u32 {
    VIRTIO_INTID_BASE + n as u32
}

/// Where the boot images go in guest RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootLayout {
    /// Kernel load address (= entry point).
    pub kernel: u64,
    /// End of the memory the kernel image occupies (including its BSS).
    pub kernel_end: u64,
    /// `[start, end)` of the initrd.
    pub initrd: Option<(u64, u64)>,
    /// Device tree address (start of the last 2 MiB block below the
    /// placement limit; holds up to [`DTB_MAX_SIZE`] bytes).
    pub dtb: u64,
}

/// A configuration that cannot be laid out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutError(String);

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LayoutError {}

/// Check a RAM size against the machine's limits.
pub fn check_ram_size(size: u64) -> Result<(), LayoutError> {
    if size == 0 || !size.is_multiple_of(RAM_ALIGN) {
        return Err(LayoutError(format!(
            "memory size {size:#x} must be a non-zero multiple of 2 MiB"
        )));
    }
    if size > MAX_RAM {
        return Err(LayoutError(format!(
            "memory size {} MiB exceeds the maximum of {} MiB",
            size >> 20,
            MAX_RAM >> 20
        )));
    }
    Ok(())
}

/// Place the kernel, initrd and device tree in RAM `[RAM_BASE, RAM_BASE +
/// ram_size)` following Linux's arm64 boot protocol
/// (Documentation/arch/arm64/booting.rst):
///
/// - kernel at `RAM_BASE + text_offset` (RAM_BASE is 2 MiB aligned), taking
///   `kernel_size` bytes (the header's `image_size`, which includes BSS);
/// - DTB at the start of the last 2 MiB block (8-byte aligned, never crossing
///   a 2 MiB boundary), below 32 GiB;
/// - initrd immediately below the DTB, 64 KiB aligned.
pub fn boot_layout(
    ram_size: u64,
    text_offset: u64,
    kernel_size: u64,
    initrd_size: Option<u64>,
) -> Result<BootLayout, LayoutError> {
    check_ram_size(ram_size)?;
    let ram_end = RAM_BASE + ram_size;
    let too_small = |what: &str| {
        LayoutError(format!(
            "{} MiB of memory is too small for the {what}",
            ram_size >> 20
        ))
    };

    let kernel = RAM_BASE
        .checked_add(text_offset)
        .ok_or_else(|| too_small("kernel"))?;
    let kernel_end = kernel
        .checked_add(kernel_size)
        .ok_or_else(|| too_small("kernel"))?;

    let top = ram_end.min(INITRD_LIMIT);
    let dtb = top - DTB_MAX_SIZE;
    if dtb < kernel_end {
        return Err(too_small("kernel and device tree"));
    }

    let initrd = match initrd_size {
        None => None,
        Some(len) => {
            let start = dtb
                .checked_sub(len)
                .map(|s| s & !(INITRD_ALIGN - 1))
                .filter(|&s| s >= kernel_end)
                .ok_or_else(|| too_small("kernel, initrd and device tree"))?;
            Some((start, start + len))
        }
    };

    Ok(BootLayout {
        kernel,
        kernel_end,
        initrd,
        dtb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn slots() {
        assert_eq!(virtio_slot_base(0), 0x0A00_0000);
        assert_eq!(virtio_slot_base(31), 0x0A00_3E00);
        assert_eq!(virtio_intid(0), 48);
        assert_eq!(virtio_intid(31), 79);
    }

    #[test]
    fn default_layout() {
        let l = boot_layout(1 << 30, 0, 0x295_0000, Some(661_851)).unwrap();
        assert_eq!(l.kernel, RAM_BASE);
        assert_eq!(l.kernel_end, RAM_BASE + 0x295_0000);
        assert_eq!(l.dtb, 0x7FE0_0000);
        let (s, e) = l.initrd.unwrap();
        assert_eq!(e - s, 661_851);
        assert_eq!(s % INITRD_ALIGN, 0);
        assert!(e <= l.dtb);
        assert!(l.dtb - e < INITRD_ALIGN);
    }

    #[test]
    fn text_offset_and_no_initrd() {
        let l = boot_layout(64 * MIB, 0x8_0000, 8 * MIB, None).unwrap();
        assert_eq!(l.kernel, RAM_BASE + 0x8_0000);
        assert_eq!(l.initrd, None);
        assert_eq!(l.dtb, RAM_BASE + 62 * MIB);
    }

    #[test]
    fn big_ram_keeps_boot_data_below_32g() {
        let l = boot_layout(48 << 30, 0, 40 * MIB, Some(MIB)).unwrap();
        assert_eq!(l.dtb, (32 << 30) - 2 * MIB);
        assert!(l.initrd.unwrap().1 <= l.dtb);
    }

    #[test]
    fn too_small() {
        assert!(boot_layout(32 * MIB, 0, 31 * MIB, None).is_err());
        assert!(boot_layout(32 * MIB, 0, 29 * MIB, Some(2 * MIB)).is_err());
        assert!(boot_layout(32 * MIB, 0, 29 * MIB, Some(MIB)).is_ok());
        assert!(boot_layout(32 * MIB, u64::MAX, 1, None).is_err());
    }

    #[test]
    fn ram_size_checks() {
        assert!(check_ram_size(0).is_err());
        assert!(check_ram_size(3 * MIB).is_err());
        assert!(check_ram_size(MAX_RAM).is_ok());
        assert!(check_ram_size(MAX_RAM + RAM_ALIGN).is_err());
    }
}
