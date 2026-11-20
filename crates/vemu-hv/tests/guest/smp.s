// Guest programs for tests/smp.rs (two vCPUs).

    // vCPU 1: wait in WFI for interrupts, report each one (x1 = INTID).
    .globl _t_waiter
_t_waiter:
    bl L_install_vbar
    bl L_gic_init
    mov x1, x21
    hvc #7                          // ready (x1 = RD_base); IRQs unmasked next
    msr daifclr, #2
1:  wfi
    ldr x1, [x20, #8]
    cbz x1, 1b
    str xzr, [x20, #8]
    ldr x1, [x20]
    hvc #8
    b 1b

    // vCPU 0: send ICC_SGI1R_EL1 = x22, then route SPI 49 to vCPU 1.
    .globl _t_sender
_t_sender:
    bl L_install_vbar
    bl L_gic_init
    mov x1, x21
    hvc #9                          // ready (x1 = RD_base); host then resumes us
    msr icc_sgi1r_el1, x22
    isb
    hvc #10
    mov x0, #49
    mov x1, #1                      // Aff0 = 1
    bl L_spi_enable
    hvc #11

    .globl _vemu_guest_end
_vemu_guest_end:
