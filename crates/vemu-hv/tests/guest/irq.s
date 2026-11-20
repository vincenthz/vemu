// Guest programs for tests/irq.rs (single vCPU).

    .globl _t_wfi_masked
_t_wfi_masked:
    msr daifset, #0xf
    wfi                             // nothing can wake this but a kick
    hvc #1

    .globl _t_spin
_t_spin:
    b _t_spin

    .globl _t_hvc2
_t_hvc2:
    hvc #2

    // Arm the virtual timer 10 ms ahead, wait for its interrupt in WFI.
    // x1 = INTID taken, x2 = CNTVCT ticks waited.
    .globl _t_vtimer
_t_vtimer:
    bl L_install_vbar
    bl L_gic_init
    mrs x3, cntvct_el0
    movz x1, #0xa980                // 240000 ticks = 10 ms at 24 MHz
    movk x1, #0x3, lsl #16
    msr cntv_tval_el0, x1
    mov x0, #1                      // ENABLE, not masked
    msr cntv_ctl_el0, x0
    isb
    msr daifclr, #2
1:  wfi
    ldr x1, [x20, #8]
    cbz x1, 1b
    msr daifset, #2
    mrs x2, cntvct_el0
    sub x2, x2, x3
    ldr x1, [x20]
    hvc #3

    // Enable SPI 48 routed to this CPU, wait for it in WFI. x1 = INTID taken.
    .globl _t_spi
_t_spi:
    mov x0, #48
    mov x1, #0
    bl L_spi_enable
    mov x0, #0x10
    hvc #4                          // ready: host raises the line after this
    msr daifclr, #2
1:  wfi
    ldr x1, [x20, #8]
    cbz x1, 1b
    msr daifset, #2
    ldr x1, [x20]
    hvc #5

    .globl _vemu_guest_end
_vemu_guest_end:
