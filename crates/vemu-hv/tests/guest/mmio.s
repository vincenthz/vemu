// Guest programs for tests/mmio.rs. x19 = MMIO window base (set by the host).

    .globl _t_store
_t_store:
    movz x1, #0x7788
    movk x1, #0x5566, lsl #16
    movk x1, #0x3344, lsl #32
    movk x1, #0x1122, lsl #48
    str x1, [x19]
    str w1, [x19, #0x8]
    strh w1, [x19, #0x12]
    strb w1, [x19, #0x1b]
    str xzr, [x19, #0x20]
    str wzr, [x19, #0x28]
    strh wzr, [x19, #0x2e]
    strb wzr, [x19, #0x2f]
    stur w1, [x19, #-4]
    mov x2, #0x30
    str x1, [x19, x2]               // register offset
    hvc #1

    .globl _t_load
_t_load:
    ldr x2, [x19]
    ldr w3, [x19, #0x4]
    ldrb w4, [x19, #0x8]
    ldrh w5, [x19, #0xa]
    ldrsb x6, [x19, #0xc]
    ldrsb w7, [x19, #0xd]
    ldrsh x8, [x19, #0xe]
    ldrsh w13, [x19, #0x10]
    ldrsw x14, [x19, #0x14]
    ldr xzr, [x19, #0x18]
    ldrb w15, [x19, #0x1f]
    hvc #2

    // HVC #0 is an SMCCC call, answered by the backend's PSCI without an
    // exit: x1 = PSCI_VERSION result + 1.
    .globl _t_hvc
_t_hvc:
    movz x0, #0x0000
    movk x0, #0x8400, lsl #16       // PSCI_VERSION
    mov x1, #0x11
    .globl _t_hvc_insn
_t_hvc_insn:
    hvc #0
    add x1, x0, #1                  // skipped if the PC were advanced again
    hvc #0x11

    // SMC is answered NOT_SUPPORTED without an exit: x1 = x0 + 1 = 0.
    .globl _t_smc
_t_smc:
    mov x0, #5
    .globl _t_smc_insn
_t_smc_insn:
    smc #0x77
    add x1, x0, #1
    hvc #0x12

    .globl _t_sysreg
_t_sysreg:
    mov x1, #1
    msr oslar_el1, x1               // lock
    mrs x2, oslsr_el1
    msr oslar_el1, xzr              // unlock (what Linux does at boot)
    mrs x3, oslsr_el1
    msr osdlr_el1, xzr
    mrs x4, osdlr_el1
    mrs x5, mdccsr_el0
    movz x6, #0x4000, lsl #16       // MDCCINT_EL1.RX
    msr mdccint_el1, x6
    mrs x7, mdccint_el1
    msr dbgprcr_el1, xzr
    mov x8, #-1
    mrs x8, s3_0_c10_c4_3           // LORC_EL1: unknown to the backend -> RAZ
    msr s3_0_c10_c4_3, x1           // WI
    hvc #3

    .globl _t_state
_t_state:
    mrs x1, mpidr_el1
    mrs x2, sctlr_el1
    mrs x3, id_aa64mmfr0_el1
    mrs x4, cntvct_el0
    mrs x5, currentel
    mrs x6, id_aa64pfr0_el1
    hvc #4

    .globl _t_sctlr
_t_sctlr:
    mrs x1, sctlr_el1
    orr x1, x1, #(1 << 2)           // C: data cache on
    orr x1, x1, #(1 << 12)          // I: instruction cache on
    msr sctlr_el1, x1
    isb
    msr daifclr, #0xf               // unmask interrupts
    hvc #7

    .globl _t_ldp
_t_ldp:
    ldp x1, x2, [x19]               // no instruction syndrome (ISV=0)
    hvc #5

    .globl _t_writeback
_t_writeback:
    str x1, [x19, #8]!              // pre-index writeback
    hvc #6

    .globl _vemu_guest_end
_vemu_guest_end:
