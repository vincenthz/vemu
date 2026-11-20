//! Transmit-only 16550A UART at COM1, a debugging aid (`--debug-uart`).
//!
//! Enough of the 16550 register set for Linux's `earlyprintk=ttyS0`,
//! `earlycon=uart,io,0x3f8` and the 8250 driver (`console=ttyS0`) to find
//! the port (scratch register, IER read-back, loopback modem-status test,
//! FIFO bits in IIR) and print: bytes written to THR go straight to the
//! host writer, so the transmitter is always empty (LSR THRE|TEMT) and the
//! THR-empty interrupt is pending whenever the driver enables it. There is
//! no receive path: LSR.DR is never set.
//!
//! The interrupt output (COM1: ISA IRQ 4) is gated by MCR.OUT2 as on a PC.

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use std::io::Write;
use std::sync::Arc;

use vemu_core::{IrqLine, MmioDevice};

// Register offsets (DLAB = LCR bit 7 selects DLL/DLM at 0 and 1).
const RBR_THR: u64 = 0;
const IER: u64 = 1;
const IIR_FCR: u64 = 2;
const LCR: u64 = 3;
const MCR: u64 = 4;
const LSR: u64 = 5;
const MSR: u64 = 6;
const SCR: u64 = 7;

const IER_THRI: u8 = 1 << 1;
const IER_MASK: u8 = 0x0f;
const IIR_NO_INT: u8 = 0x01;
const IIR_THRI: u8 = 0x02;
const IIR_FIFO_ENABLED: u8 = 0xc0;
const FCR_ENABLE_FIFO: u8 = 1 << 0;
const LCR_DLAB: u8 = 1 << 7;
const MCR_DTR: u8 = 1 << 0;
const MCR_RTS: u8 = 1 << 1;
const MCR_OUT1: u8 = 1 << 2;
const MCR_OUT2: u8 = 1 << 3;
const MCR_LOOP: u8 = 1 << 4;
const MCR_MASK: u8 = 0x1f;
const LSR_THRE: u8 = 1 << 5;
const LSR_TEMT: u8 = 1 << 6;
const MSR_CTS: u8 = 1 << 4;
const MSR_DSR: u8 = 1 << 5;
const MSR_RI: u8 = 1 << 6;
const MSR_DCD: u8 = 1 << 7;

pub struct Serial16550 {
    out: Box<dyn Write + Send>,
    irq: Arc<dyn IrqLine>,
    level: bool,
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    dll: u8,
    dlm: u8,
    fifo: bool,
    /// THR-empty interrupt pending: set when THR becomes empty (always
    /// right after a write) or THRI is enabled; cleared by reading IIR
    /// while it is the reported source, or by writing THR.
    thre_pending: bool,
}

impl Serial16550 {
    pub fn new(out: Box<dyn Write + Send>, irq: Arc<dyn IrqLine>) -> Serial16550 {
        Serial16550 {
            out,
            irq,
            level: false,
            ier: 0,
            lcr: 0,
            mcr: 0,
            scr: 0,
            // 115200 baud with the PC's 1.8432 MHz clock.
            dll: 1,
            dlm: 0,
            fifo: false,
            thre_pending: false,
        }
    }

    fn dlab(&self) -> bool {
        self.lcr & LCR_DLAB != 0
    }

    fn loopback(&self) -> bool {
        self.mcr & MCR_LOOP != 0
    }

    fn thr_interrupt(&self) -> bool {
        self.ier & IER_THRI != 0 && self.thre_pending
    }

    fn update_irq(&mut self) {
        let level = self.thr_interrupt() && self.mcr & MCR_OUT2 != 0 && !self.loopback();
        if level != self.level {
            self.level = level;
            self.irq.set_level(level);
        }
    }

    fn iir(&mut self) -> u8 {
        let fifo = if self.fifo { IIR_FIFO_ENABLED } else { 0 };
        if self.thr_interrupt() {
            // Reading IIR with THRE as the source acknowledges it.
            self.thre_pending = false;
            fifo | IIR_THRI
        } else {
            fifo | IIR_NO_INT
        }
    }

    fn msr(&self) -> u8 {
        if self.loopback() {
            // Modem outputs looped back to the inputs.
            let m = self.mcr;
            (if m & MCR_RTS != 0 { MSR_CTS } else { 0 })
                | (if m & MCR_DTR != 0 { MSR_DSR } else { 0 })
                | (if m & MCR_OUT1 != 0 { MSR_RI } else { 0 })
                | (if m & MCR_OUT2 != 0 { MSR_DCD } else { 0 })
        } else {
            // A terminal is attached and ready.
            MSR_DCD | MSR_DSR | MSR_CTS
        }
    }

    fn read_reg(&mut self, offset: u64) -> u8 {
        match offset {
            RBR_THR if self.dlab() => self.dll,
            IER if self.dlab() => self.dlm,
            RBR_THR => 0, // no received data
            IER => self.ier,
            IIR_FCR => self.iir(),
            LCR => self.lcr,
            MCR => self.mcr,
            LSR => LSR_THRE | LSR_TEMT,
            MSR => self.msr(),
            SCR => self.scr,
            _ => 0,
        }
    }

    fn write_reg(&mut self, offset: u64, v: u8) {
        match offset {
            RBR_THR if self.dlab() => self.dll = v,
            IER if self.dlab() => self.dlm = v,
            RBR_THR => {
                if !self.loopback() {
                    // Output errors (closed stderr) are ignored: a debug aid.
                    let _ = self.out.write_all(&[v]);
                    let _ = self.out.flush();
                }
                // Transmitted at once: THR is empty again.
                self.thre_pending = true;
            }
            IER => {
                let enabling = v & IER_THRI != 0 && self.ier & IER_THRI == 0;
                self.ier = v & IER_MASK;
                if enabling {
                    self.thre_pending = true;
                }
            }
            IIR_FCR => self.fifo = v & FCR_ENABLE_FIFO != 0,
            LCR => self.lcr = v,
            MCR => self.mcr = v & MCR_MASK,
            SCR => self.scr = v,
            _ => {} // LSR, MSR: read-only
        }
    }
}

impl MmioDevice for Serial16550 {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // Byte registers; a wider access reads consecutive ones.
        for (i, b) in data.iter_mut().enumerate() {
            *b = self.read_reg(offset + i as u64);
        }
        self.update_irq();
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            self.write_reg(offset + i as u64, b);
        }
        self.update_irq();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Line {
        level: AtomicBool,
        changes: AtomicUsize,
    }
    impl IrqLine for Line {
        fn set_level(&self, level: bool) {
            self.level.store(level, Ordering::SeqCst);
            self.changes.fetch_add(1, Ordering::SeqCst);
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

    fn uart() -> (Serial16550, Sink, Arc<Line>) {
        let sink = Sink::default();
        let line = Arc::new(Line::default());
        (
            Serial16550::new(Box::new(sink.clone()), line.clone()),
            sink,
            line,
        )
    }

    fn rd(u: &mut Serial16550, off: u64) -> u8 {
        let mut b = [0u8];
        u.read(off, &mut b);
        b[0]
    }

    fn wr(u: &mut Serial16550, off: u64, v: u8) {
        u.write(off, &[v]);
    }

    #[test]
    fn linux_autoconfig_finds_a_16550a() {
        // drivers/tty/serial/8250/8250_port.c autoconfig(), in order.
        let (mut u, sink, _) = uart();
        // IER read-back test.
        wr(&mut u, IER, 0);
        assert_eq!(rd(&mut u, IER) & 0x0f, 0);
        wr(&mut u, IER, 0x0f);
        assert_eq!(rd(&mut u, IER) & 0x0f, 0x0f);
        wr(&mut u, IER, 0);
        // Loopback test: MCR = LOOP | OUT2 | RTS → MSR CTS | DCD.
        let save_mcr = rd(&mut u, MCR);
        wr(&mut u, MCR, MCR_LOOP | 0x0a);
        assert_eq!(rd(&mut u, MSR) & 0xf0, 0x90);
        wr(&mut u, MCR, save_mcr);
        // FIFO: IIR bits 7:6 = 11 once enabled → 16550A.
        assert_eq!(rd(&mut u, IIR_FCR) >> 6, 0);
        wr(&mut u, IIR_FCR, FCR_ENABLE_FIFO);
        assert_eq!(rd(&mut u, IIR_FCR) >> 6, 3);
        // Scratch register.
        wr(&mut u, SCR, 0xa5);
        assert_eq!(rd(&mut u, SCR), 0xa5);
        // Divisor latch behind DLAB.
        wr(&mut u, LCR, LCR_DLAB);
        wr(&mut u, RBR_THR, 0x0c);
        wr(&mut u, IER, 0x00);
        assert_eq!((rd(&mut u, RBR_THR), rd(&mut u, IER)), (0x0c, 0));
        wr(&mut u, LCR, 0x03);
        assert_eq!(rd(&mut u, IER), 0, "IER untouched by the DLM write");
        assert!(sink.0.lock().unwrap().is_empty(), "DLL write is not output");
    }

    #[test]
    fn transmit_goes_to_the_writer() {
        let (mut u, sink, _) = uart();
        wr(&mut u, LCR, 0x03);
        for &b in b"hi\r\n" {
            assert_ne!(rd(&mut u, LSR) & LSR_THRE, 0);
            wr(&mut u, RBR_THR, b);
        }
        assert_eq!(rd(&mut u, LSR), LSR_THRE | LSR_TEMT);
        assert_eq!(rd(&mut u, RBR_THR), 0);
        // Not in loopback mode.
        wr(&mut u, MCR, MCR_LOOP);
        wr(&mut u, RBR_THR, b'x');
        assert_eq!(&*sink.0.lock().unwrap(), b"hi\r\n");
    }

    #[test]
    fn thre_interrupt() {
        let (mut u, _, line) = uart();
        // Enabled THRI with OUT2: pending at once.
        wr(&mut u, MCR, MCR_OUT2 | MCR_DTR | MCR_RTS);
        assert!(!line.level.load(Ordering::SeqCst));
        wr(&mut u, IER, IER_THRI);
        assert!(line.level.load(Ordering::SeqCst));
        // Reading IIR acknowledges it.
        assert_eq!(rd(&mut u, IIR_FCR), IIR_THRI);
        assert!(!line.level.load(Ordering::SeqCst));
        assert_eq!(rd(&mut u, IIR_FCR), IIR_NO_INT);
        // Writing a byte makes THR empty again → pending.
        wr(&mut u, RBR_THR, b'a');
        assert!(line.level.load(Ordering::SeqCst));
        wr(&mut u, IER, 0);
        assert!(!line.level.load(Ordering::SeqCst));
        // The driver's THRE re-assert test (serial8250_do_startup): enabling
        // THRI twice reports THRI both times.
        wr(&mut u, IER, IER_THRI);
        assert_eq!(rd(&mut u, IIR_FCR) & 0x0f, IIR_THRI);
        wr(&mut u, IER, 0);
        wr(&mut u, IER, IER_THRI);
        assert_eq!(rd(&mut u, IIR_FCR) & 0x0f, IIR_THRI);
        // Without OUT2 the line stays low.
        wr(&mut u, IER, 0);
        wr(&mut u, MCR, 0);
        wr(&mut u, IER, IER_THRI | 0x01); // and receive-data interrupts
        assert!(!line.level.load(Ordering::SeqCst));
        assert_eq!(rd(&mut u, IIR_FCR) & 0x0f, IIR_THRI, "still reported");
        let changes = line.changes.load(Ordering::SeqCst);
        assert_eq!(changes, 8, "only edges are signalled");
    }
}
