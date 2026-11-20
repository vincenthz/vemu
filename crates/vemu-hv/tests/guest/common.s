// Shared guest code for the vemu-hv integration tests (AArch64, EL1, MMU off).
//
// Register conventions (set by the host):
//   x20  per-vCPU record area in RAM: [x20] = last IRQ INTID, [x20+8] = IRQ count
//   x21  (output of gic_init) this CPU's redistributor RD_base
// The IRQ handler clobbers x9..x12; test code leaves those alone.
// HVC #0xdead = unexpected guest exception (x1 = ESR_EL1, x2 = ELR_EL1).
// Assembled into the test binary; the host copies everything between
// _vemu_guest_start and _vemu_guest_end to the start of guest RAM.

    .text
    .p2align 12
    .globl _vemu_guest_start
_vemu_guest_start:

// EL1 vector table (VBAR_EL1 needs 2 KiB alignment; the blob is 4 KiB aligned).
L_vectors:
    .rept 5                     // EL1t sync/irq/fiq/serror, EL1h sync
    mrs x1, esr_el1
    mrs x2, elr_el1
    hvc #0xdead
    .balign 128
    .endr

    // 0x280: EL1h IRQ. Record the INTID, quiesce its source, EOI.
    mrs x9, icc_iar1_el1
    cmp x9, #1023               // spurious
    b.eq 3f
    str x9, [x20]
    ldr x10, [x20, #8]
    add x10, x10, #1
    str x10, [x20, #8]
    cmp x9, #27                 // virtual timer: disable it (drops the level)
    b.ne 1f
    msr cntv_ctl_el0, xzr
    isb
1:  cmp x9, #32                 // SPI 32..63: disable it in the distributor
    b.lo 2f
    movz x10, #0x0800, lsl #16
    mov w11, #1
    lsl w11, w11, w9
    str w11, [x10, #0x184]      // GICD_ICENABLER1
2:  msr icc_eoir1_el1, x9
3:  eret
    .balign 128

    .rept 10                    // EL1h fiq/serror, lower ELs
    mrs x1, esr_el1
    mrs x2, elr_el1
    hvc #0xdead
    .balign 128
    .endr

// install_vbar: VBAR_EL1 = L_vectors. Clobbers x0.
L_install_vbar:
    adr x0, L_vectors
    msr vbar_el1, x0
    isb
    ret

// gic_find_rd: x0 = this CPU's RD_base, found like Linux does it: walk the
// redistributor frames from 0x080A0000 until GICR_TYPER.Affinity matches
// MPIDR_EL1 (Aff0 only; Aff1..3 are 0), stopping at GICR_TYPER.Last.
// HVC #0xbad if not found. Clobbers x1..x3.
L_gic_find_rd:
    mrs x1, mpidr_el1
    and x1, x1, #0xff
    movz x0, #0x080a, lsl #16
1:  ldr x2, [x0, #8]            // GICR_TYPER (64-bit)
    lsr x3, x2, #32
    cmp x3, x1
    b.eq 2f
    tbnz x2, #4, 3f             // Last
    add x0, x0, #0x20000
    b 1b
3:  hvc #0xbad
2:  ret

// gic_init: x21 = RD_base. Enables distributor group 1, wakes this CPU's
// redistributor, makes all SGIs/PPIs group 1, enabled, priority 0x80, and
// enables the CPU interface (PMR 0xff, IGRPEN1). Clobbers x0..x3, x28.
L_gic_init:
    mov x28, x30
    bl L_gic_find_rd
    mov x21, x0
    movz x1, #0x0800, lsl #16   // GICD
    ldr w0, [x1]
    orr w0, w0, #0x2            // EnableGrp1 (GICD_CTLR.DS=1: bit 1)
    str w0, [x1]
1:  ldr w0, [x1]
    tbnz w0, #31, 1b            // RWP
    ldr w0, [x21, #0x14]        // GICR_WAKER: clear ProcessorSleep
    bic w0, w0, #2
    str w0, [x21, #0x14]
2:  ldr w0, [x21, #0x14]
    tbnz w0, #2, 2b             // ChildrenAsleep
    add x3, x21, #0x10000       // SGI_base frame
    mov w0, #0xffffffff
    str w0, [x3, #0x80]         // GICR_IGROUPR0
    str w0, [x3, #0x100]        // GICR_ISENABLER0
    movz w0, #0x8080
    movk w0, #0x8080, lsl #16
    mov x2, #0x400              // GICR_IPRIORITYR0..7
3:  str w0, [x3, x2]
    add x2, x2, #4
    cmp x2, #0x420
    b.ne 3b
    mov x0, #0xff
    msr icc_pmr_el1, x0
    mov x0, #1
    msr icc_igrpen1_el1, x0
    isb
    mov x30, x28
    ret

// spi_enable: x0 = INTID (32..63), x1 = target Aff0. Group 1, priority 0x80,
// routed to that CPU, enabled. Clobbers x2..x7.
L_spi_enable:
    movz x2, #0x0800, lsl #16   // GICD
    and x4, x0, #31
    mov w5, #1
    lsl w5, w5, w4
    ldr w6, [x2, #0x84]         // GICD_IGROUPR1
    orr w6, w6, w5
    str w6, [x2, #0x84]
    add x6, x2, #0x400          // GICD_IPRIORITYR<n>, one byte per INTID
    mov w7, #0x80
    strb w7, [x6, x0]
    add x6, x2, #0x6000         // GICD_IROUTER<n>
    str x1, [x6, x0, lsl #3]
    str w5, [x2, #0x104]        // GICD_ISENABLER1
    ret
