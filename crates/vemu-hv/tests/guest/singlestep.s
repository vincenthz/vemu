// Software step over instructions the backend emulates (tests/singlestep.rs).
//
// Host sets: x0 = target, x4 = MDSCR_EL1 value, x19 = MMIO window, x7 = 0.
// _t_ss_setup installs L_ss_vectors, clears the OS lock (so MDSCR_EL1.KDE
// takes effect) and ERETs to the target with SPSR.SS=1 and PSTATE.D clear:
// with MDSCR_EL1.SS=1 the step exception is taken after exactly one
// instruction. Each target is: the instruction under test, `add x7, x7, #1`
// (must not run before the step exception), `hvc #n` (stepping off).
// The EL1h sync vector reports ESR/ELR/SPSR_EL1 in x1/x2/x3 via HVC #0x55.

    .balign 2048
L_ss_vectors:
    .rept 4                     // EL1t
    mrs x1, esr_el1
    mrs x2, elr_el1
    hvc #0xdead
    .balign 128
    .endr
    // 0x200: EL1h sync (the software step exception)
    mrs x1, esr_el1
    mrs x2, elr_el1
    mrs x3, spsr_el1
    hvc #0x55
    .balign 128
    .rept 11
    mrs x1, esr_el1
    mrs x2, elr_el1
    hvc #0xdead
    .balign 128
    .endr

    .globl _t_ss_setup
_t_ss_setup:
    adr x5, L_ss_vectors
    msr vbar_el1, x5
    msr oslar_el1, xzr
    msr osdlr_el1, xzr
    msr mdscr_el1, x4
    isb
    msr elr_el1, x0
    movz x5, #0x01c5            // EL1h, A/I/F masked, D clear
    movk x5, #0x0020, lsl #16   // SPSR.SS
    msr spsr_el1, x5
    eret

    .globl _t_ss_nop
_t_ss_nop:
    nop
    add x7, x7, #1
    hvc #1

    .globl _t_ss_store
_t_ss_store:
    str x1, [x19]               // MMIO store
    add x7, x7, #1
    hvc #2

    .globl _t_ss_load
_t_ss_load:
    ldr x6, [x19]               // MMIO load
    add x7, x7, #1
    hvc #3

    .globl _t_ss_msr
_t_ss_msr:
    msr oslar_el1, xzr          // emulated sysreg write
    add x7, x7, #1
    hvc #4

    .globl _t_ss_mrs
_t_ss_mrs:
    mrs x6, oslsr_el1           // emulated sysreg read
    add x7, x7, #1
    hvc #5

    .globl _t_ss_smc
_t_ss_smc:
    smc #0
    add x7, x7, #1
    hvc #6

    .globl _t_ss_psci
_t_ss_psci:
    hvc #0                      // SMCCC call (x0 = target: unknown function)
    add x7, x7, #1
    hvc #9

    .globl _t_ss_hvc
_t_ss_hvc:
    hvc #0x77
    add x7, x7, #1
    hvc #7

// Indirect call onto an MMIO store (sets PSTATE.BTYPE): x5 = _t_bt_store.
    .globl _t_bt_call
_t_bt_call:
    blr x5
    .globl _t_bt_store
_t_bt_store:
    str x1, [x19]
    add x7, x7, #1
    hvc #8

    .globl _vemu_guest_end
_vemu_guest_end:
