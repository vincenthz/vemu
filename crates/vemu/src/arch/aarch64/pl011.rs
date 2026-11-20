//! Write-only Arm PL011 UART, a debugging aid (`--debug-uart`).
//!
//! Enough of the PL011 (Arm DDI 0183) for Linux's `earlycon=pl011,...` and
//! the `amba-pl011` driver (`console=ttyAMA0`) to print: characters written
//! to the data register go straight to the host writer. The transmit FIFO is
//! therefore always empty, so the transmit interrupt is pending whenever the
//! driver unmasks it. There is no receive path: the receive FIFO always reads
//! empty.
//!
//! The PrimeCell identification registers are implemented because the AMBA
//! bus code reads them to match the driver.

use std::io::Write;
use std::sync::Arc;

use vemu_core::{IrqLine, MmioDevice};

const DR: u64 = 0x000;
const RSR: u64 = 0x004;
const FR: u64 = 0x018;
const ILPR: u64 = 0x020;
const IBRD: u64 = 0x024;
const FBRD: u64 = 0x028;
const LCR_H: u64 = 0x02c;
const CR: u64 = 0x030;
const IFLS: u64 = 0x034;
const IMSC: u64 = 0x038;
const RIS: u64 = 0x03c;
const MIS: u64 = 0x040;
const ICR: u64 = 0x044;
const DMACR: u64 = 0x048;
/// PeriphID0..3 then PCellID0..3, one byte per 32-bit register.
const ID_BASE: u64 = 0xfe0;
const ID: [u8; 8] = [0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

/// FR: transmit FIFO empty.
const FR_TXFE: u32 = 1 << 7;
/// FR: receive FIFO empty.
const FR_RXFE: u32 = 1 << 4;
/// Interrupt bit for "transmit FIFO at or below its trigger level".
const INT_TX: u32 = 1 << 5;
/// IFLS reset value: both FIFO triggers at half full.
const IFLS_RESET: u32 = 0x12;
/// CR reset value: TXE and RXE set, UART disabled.
const CR_RESET: u32 = 0x300;

pub struct Pl011 {
    out: Box<dyn Write + Send>,
    irq: Arc<dyn IrqLine>,
    level: bool,
    ilpr: u32,
    ibrd: u32,
    fbrd: u32,
    lcr_h: u32,
    cr: u32,
    ifls: u32,
    imsc: u32,
    dmacr: u32,
}

impl Pl011 {
    pub fn new(out: Box<dyn Write + Send>, irq: Arc<dyn IrqLine>) -> Pl011 {
        Pl011 {
            out,
            irq,
            level: false,
            ilpr: 0,
            ibrd: 0,
            fbrd: 0,
            lcr_h: 0,
            cr: CR_RESET,
            ifls: IFLS_RESET,
            imsc: 0,
            dmacr: 0,
        }
    }

    /// Raw interrupt status: only "transmit FIFO below trigger level", which
    /// is always true.
    fn ris(&self) -> u32 {
        INT_TX
    }

    fn update_irq(&mut self) {
        let level = self.ris() & self.imsc != 0;
        if level != self.level {
            self.level = level;
            self.irq.set_level(level);
        }
    }

    fn read_reg(&self, offset: u64) -> u32 {
        match offset {
            FR => FR_TXFE | FR_RXFE,
            ILPR => self.ilpr,
            IBRD => self.ibrd,
            FBRD => self.fbrd,
            LCR_H => self.lcr_h,
            CR => self.cr,
            IFLS => self.ifls,
            IMSC => self.imsc,
            RIS => self.ris(),
            MIS => self.ris() & self.imsc,
            DMACR => self.dmacr,
            ID_BASE..0x1000 if offset.is_multiple_of(4) => {
                ID[((offset - ID_BASE) / 4) as usize].into()
            }
            // DR (receive FIFO empty), RSR (no errors), ICR (write-only), ...
            _ => 0,
        }
    }

    fn write_reg(&mut self, offset: u64, v: u32) {
        match offset {
            DR => {
                // Output errors (closed stderr) are ignored: this is a debug aid.
                let _ = self.out.write_all(&[v as u8]);
                let _ = self.out.flush();
            }
            RSR => {} // clears receive errors; there are none
            ILPR => self.ilpr = v & 0xff,
            IBRD => self.ibrd = v & 0xffff,
            FBRD => self.fbrd = v & 0x3f,
            LCR_H => self.lcr_h = v & 0xff,
            CR => self.cr = v & 0xff87,
            IFLS => self.ifls = v & 0x3f,
            IMSC => {
                self.imsc = v & 0x7ff;
                self.update_irq();
            }
            // The transmit condition is a level that cannot be cleared while
            // the FIFO is empty; nothing else is ever raised.
            ICR => {}
            DMACR => self.dmacr = v & 0x7,
            _ => {}
        }
    }
}

impl MmioDevice for Pl011 {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // Registers are at most 16 bits wide; any access width reads the
        // register at the (word-aligned) offset.
        let v = self.read_reg(offset & !3).to_le_bytes();
        let n = data.len().min(4);
        data[..n].copy_from_slice(&v[..n]);
        data[n..].fill(0);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let mut v = [0u8; 4];
        let n = data.len().min(4);
        v[..n].copy_from_slice(&data[..n]);
        self.write_reg(offset & !3, u32::from_le_bytes(v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Line(Mutex<Vec<bool>>);
    impl IrqLine for Line {
        fn set_level(&self, level: bool) {
            self.0.lock().unwrap().push(level);
        }
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn rd(u: &mut Pl011, off: u64, len: usize) -> u64 {
        let mut b = [0u8; 8];
        u.read(off, &mut b[..len]);
        u64::from_le_bytes(b)
    }

    fn wr(u: &mut Pl011, off: u64, len: usize, v: u64) {
        u.write(off, &v.to_le_bytes()[..len]);
    }

    #[test]
    fn transmit_and_ids() {
        let sink = Sink::default();
        let line = Arc::new(Line::default());
        let mut u = Pl011::new(Box::new(sink.clone()), line.clone());
        for &c in b"hi\n" {
            wr(&mut u, DR, 4, c as u64);
        }
        wr(&mut u, DR, 1, b'!' as u64);
        assert_eq!(&*sink.0.lock().unwrap(), b"hi\n!");
        assert_eq!(rd(&mut u, FR, 4), 0x90);
        assert_eq!(rd(&mut u, FR, 2), 0x90);
        let ids: Vec<u64> = (0..8).map(|i| rd(&mut u, ID_BASE + 4 * i, 4)).collect();
        assert_eq!(ids, vec![0x11, 0x10, 0x14, 0, 0x0d, 0xf0, 0x05, 0xb1]);
        wr(&mut u, IBRD, 2, 0x1234_5678);
        assert_eq!(rd(&mut u, IBRD, 4), 0x5678);
        assert_eq!(rd(&mut u, CR, 4), 0x300);
        assert_eq!(rd(&mut u, DR, 4), 0);
    }

    #[test]
    fn tx_interrupt_follows_mask() {
        let line = Arc::new(Line::default());
        let mut u = Pl011::new(Box::new(std::io::sink()), line.clone());
        assert_eq!(rd(&mut u, RIS, 4), 0x20);
        assert_eq!(rd(&mut u, MIS, 4), 0);
        wr(&mut u, IMSC, 4, 0x10); // RX only: nothing pending
        wr(&mut u, IMSC, 4, 0x30);
        assert_eq!(rd(&mut u, MIS, 4), 0x20);
        wr(&mut u, ICR, 4, 0x7ff);
        assert_eq!(rd(&mut u, MIS, 4), 0x20);
        wr(&mut u, IMSC, 4, 0x30); // no change, no extra edge
        wr(&mut u, IMSC, 4, 0);
        assert_eq!(*line.0.lock().unwrap(), vec![true, false]);
    }
}
