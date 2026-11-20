// Guest programs for tests/psci.rs (two vCPUs).

    // vCPU 0: make the SMCCC call in x0..x3 (set by the host), report the
    // result in x1 via HVC #1, repeat.
    .globl _t_psci_call
_t_psci_call:
    hvc #0
    mov x1, x0
    hvc #1
    b _t_psci_call

    // vCPU 1, entered by PSCI CPU_ON: report the context (x1), SCTLR_EL1
    // (x2) and DAIF (x3), then dirty what CPU_ON must reset (caches on,
    // interrupts unmasked) and CPU_OFF.
    .globl _t_psci_sec
_t_psci_sec:
    mov x1, x0
    mrs x2, sctlr_el1
    mrs x3, daif
    hvc #2
    mrs x4, sctlr_el1
    orr x4, x4, #(1 << 2)           // C
    orr x4, x4, #(1 << 12)          // I
    msr sctlr_el1, x4
    isb
    msr daifclr, #0xf
    movz x0, #0x0002
    movk x0, #0x8400, lsl #16       // CPU_OFF
    hvc #0
    hvc #0xdead                     // CPU_OFF returned

    .globl _vemu_guest_end
_vemu_guest_end:
