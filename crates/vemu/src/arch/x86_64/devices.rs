//! The x86_64 machine's small port-I/O devices: the ACPI sleep/reset
//! registers, a minimal i8042 (reset only), PCI configuration ports with
//! nothing behind them, and quiet "absent hardware" ranges for legacy ports
//! Linux probes. All implement [`MmioDevice`] with `offset` = port − base
//! (see `crate::bus::PortIoBus`).

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use std::sync::{Arc, Mutex};

use vemu_core::MmioDevice;

use super::acpi::{RESET_VALUE, S5_SLEEP_TYPE};
use super::layout;
use super::uart::Serial16550;
use crate::bus::PortIoBus;
use crate::power::{Control, Exit};

/// Put the machine's port-I/O devices on `pio`: the ACPI registers, the
/// i8042, the debug UART at COM1 if given, and quiet absent-hardware ranges
/// for the PCI configuration ports, the other UARTs (and COM1 without a
/// debug UART), the CMOS RTC, the POST port and the DMA page registers.
pub fn install(
    pio: &mut PortIoBus,
    control: &Arc<Control>,
    uart: Option<Serial16550>,
) -> Result<(), String> {
    fn dev(d: impl MmioDevice + 'static) -> Arc<Mutex<dyn MmioDevice>> {
        Arc::new(Mutex::new(d))
    }
    pio.insert(
        "acpi",
        layout::ACPI_PORT,
        layout::ACPI_PORT_COUNT,
        dev(AcpiRegs::new(control.clone())),
    )?;
    pio.insert(
        "i8042",
        layout::I8042_PORT,
        layout::I8042_PORT_COUNT,
        dev(I8042::new(control.clone())),
    )?;
    match uart {
        Some(u) => pio.insert("com1", layout::COM1_PORT, 8, dev(u))?,
        None => pio.insert("com1 (absent)", layout::COM1_PORT, 8, dev(Absent))?,
    }
    for port in layout::ABSENT_UART_PORTS {
        pio.insert(format!("uart {port:#x} (absent)"), port, 8, dev(Absent))?;
    }
    pio.insert(
        "pci config (absent)",
        layout::PCI_CONFIG_PORT,
        layout::PCI_CONFIG_PORT_COUNT,
        dev(Absent),
    )?;
    pio.insert("cmos (absent)", layout::CMOS_PORT, 2, dev(Absent))?;
    pio.insert(
        "post / dma pages (absent)",
        layout::POST_PORT,
        layout::POST_PORT_COUNT,
        dev(Absent),
    )?;
    Ok(())
}

/// ACPI hardware-reduced sleep control register: SLP_TYP (bits 4:2) and
/// SLP_EN (bit 5) (ACPI 6.5, 4.8.3.7).
pub const SLP_TYP_SHIFT: u8 = 2;
pub const SLP_TYP_MASK: u8 = 0x1c;
pub const SLP_EN: u8 = 1 << 5;

/// The FADT's sleep control (offset 0), sleep status (offset 1) and reset
/// (offset 4) registers, at `layout::ACPI_PORT`. Writing SLP_TYP = S5 with
/// SLP_EN powers the machine off; writing [`RESET_VALUE`] to the reset
/// register resets it (vemu exits). The sleep status register reads 0:
/// the guest never wakes up.
pub struct AcpiRegs {
    control: Arc<Control>,
}

pub const ACPI_SLEEP_CONTROL: u64 = 0;
pub const ACPI_SLEEP_STATUS: u64 = 1;
pub const ACPI_RESET: u64 = 4;

impl AcpiRegs {
    pub fn new(control: Arc<Control>) -> AcpiRegs {
        AcpiRegs { control }
    }
}

impl MmioDevice for AcpiRegs {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let v = data[0];
        match offset {
            ACPI_SLEEP_CONTROL
                if v & SLP_EN != 0 && (v & SLP_TYP_MASK) >> SLP_TYP_SHIFT == S5_SLEEP_TYPE =>
            {
                self.control.request_exit(Exit::PowerOff);
            }
            ACPI_RESET if v == RESET_VALUE => self.control.request_exit(Exit::Reset),
            // Clearing WAK_STS before sleeping: there is nothing to clear.
            ACPI_SLEEP_STATUS => {}
            // Other sleep states (not advertised), other reset values.
            _ => {}
        }
    }
}

/// i8042 keyboard controller, only as far as rebooting goes: data port
/// (offset 0, port 0x60, reads 0, writes ignored) and status/command port
/// (offset 4, port 0x64).
/// The status reads 0 (both buffers empty), so `kb_wait()` passes;
/// command 0xFE (pulse the reset line) resets the machine. Ports 0x61–0x63
/// in between read 0 (KVM's in-kernel PIT handles 0x61 before it gets
/// here).
pub struct I8042 {
    control: Arc<Control>,
}

pub const I8042_COMMAND: u64 = 4;
/// "Pulse output line 0" (the CPU reset line).
pub const I8042_CMD_RESET: u8 = 0xfe;

impl I8042 {
    pub fn new(control: Arc<Control>) -> I8042 {
        I8042 { control }
    }
}

impl MmioDevice for I8042 {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if offset == I8042_COMMAND && data[0] == I8042_CMD_RESET {
            self.control.request_exit(Exit::Reset);
        }
    }
}

/// Hardware that isn't there: reads all ones (a floating ISA bus), ignores
/// writes, logs nothing. Used for the PCI configuration ports (no PCI
/// devices: the config-mechanism probes fail and Linux gives up on PCI),
/// the legacy UARTs other than the debug one, the CMOS RTC and the POST
/// port, which a PC guest pokes during boot.
pub struct Absent;

impl MmioDevice for Absent {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        data.fill(0xff);
    }

    fn write(&mut self, _offset: u64, _data: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use vemu_core::IrqLine;

    struct NoIrq;
    impl IrqLine for NoIrq {
        fn set_level(&self, _level: bool) {}
    }

    #[test]
    fn installed_ports() {
        let c = Arc::new(Control::new());
        let mut pio = PortIoBus::new();
        let uart = Serial16550::new(Box::new(std::io::sink()), Arc::new(NoIrq));
        install(&mut pio, &c, Some(uart)).unwrap();
        // COM1 is the 16550 (LSR: transmitter empty), COM2 is absent.
        assert_eq!(pio.read(0x3fd, 1), 0x60);
        assert_eq!(pio.read(0x2fd, 1), 0xff);
        // PCI config space is all ones; the CMOS too.
        pio.write(0xcf8, 4, 0x8000_0000);
        assert_eq!(pio.read(0xcf8, 4), 0xffff_ffff);
        assert_eq!(pio.read(0xcfc, 4), 0xffff_ffff);
        assert_eq!(pio.read(0x71, 1), 0xff);
        // No 8237 DMA controller: DMA_PAGE_0 reads 0xff (i8237A_init_ops).
        assert_eq!(pio.read(0x87, 1), 0xff);
        // i8042 status, then ACPI S5.
        assert_eq!(pio.read(0x64, 1), 0);
        pio.write(0x600, 1, 0x34);
        assert_eq!(c.wait_for_exit(), Exit::PowerOff);

        let c = Arc::new(Control::new());
        let mut pio = PortIoBus::new();
        install(&mut pio, &c, None).unwrap();
        assert_eq!(pio.read(0x3fd, 1), 0xff, "no UART at COM1");
        pio.write(0x64, 1, 0xfe);
        assert_eq!(c.wait_for_exit(), Exit::Reset);
        let c2 = Arc::new(Control::new());
        let mut pio = PortIoBus::new();
        install(&mut pio, &c2, None).unwrap();
        pio.write(0x604, 1, 1);
        assert_eq!(c2.wait_for_exit(), Exit::Reset);
    }

    fn read(d: &mut dyn MmioDevice, off: u64, len: usize) -> Vec<u8> {
        let mut b = vec![0x5a; len];
        d.read(off, &mut b);
        b
    }

    #[test]
    fn acpi_s5_powers_off() {
        let c = Arc::new(Control::new());
        let mut r = AcpiRegs::new(c.clone());
        // Linux: clear WAK_STS in the status register, then SLP_TYP|SLP_EN.
        r.write(ACPI_SLEEP_STATUS, &[0x80]);
        assert!(!c.is_exiting());
        // SLP_TYP = 5 without SLP_EN, or another sleep type: nothing.
        r.write(ACPI_SLEEP_CONTROL, &[5 << 2]);
        r.write(ACPI_SLEEP_CONTROL, &[(3 << 2) | SLP_EN]);
        assert!(!c.is_exiting());
        assert_eq!(read(&mut r, ACPI_SLEEP_STATUS, 1), [0]);
        r.write(ACPI_SLEEP_CONTROL, &[0x34]);
        assert_eq!(c.wait_for_exit(), Exit::PowerOff);
    }

    #[test]
    fn acpi_reset_register() {
        let c = Arc::new(Control::new());
        let mut r = AcpiRegs::new(c.clone());
        r.write(ACPI_RESET, &[2]);
        r.write(ACPI_SLEEP_STATUS, &[1]);
        assert!(!c.is_exiting());
        r.write(ACPI_RESET, &[RESET_VALUE]);
        assert_eq!(c.wait_for_exit(), Exit::Reset);
    }

    #[test]
    fn i8042_reset_pulse() {
        let c = Arc::new(Control::new());
        let mut k = I8042::new(c.clone());
        assert_eq!(read(&mut k, I8042_COMMAND, 1), [0], "buffers empty");
        k.write(0, &[0xfe]); // data port
        k.write(I8042_COMMAND, &[0xd1]);
        assert!(!c.is_exiting());
        k.write(I8042_COMMAND, &[0xfe]);
        assert_eq!(c.wait_for_exit(), Exit::Reset);
    }

    #[test]
    fn absent_reads_all_ones() {
        let mut a = Absent;
        // PCI config mechanism #1 probe: the address doesn't latch, and the
        // data reads all ones (no device 0xffff vendor).
        a.write(0, &0x8000_0000u32.to_le_bytes());
        assert_eq!(read(&mut a, 0, 4), [0xff; 4]);
        assert_eq!(read(&mut a, 4, 2), [0xff; 2]);
        // Mechanism #2 probe: byte reads of 0xcf8 / 0xcfa aren't 0.
        a.write(0, &[0]);
        assert_eq!(read(&mut a, 0, 1), [0xff]);
        assert_eq!(read(&mut a, 2, 1), [0xff]);
    }
}
