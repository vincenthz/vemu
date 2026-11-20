//! Hand-written bindings for the parts of Hypervisor.framework (arm64) that
//! vemu uses. Declarations mirror the macOS SDK headers `hv_vm.h`,
//! `hv_vm_config.h`, `hv_vcpu.h`, `hv_vcpu_types.h`, `hv_gic.h`,
//! `hv_gic_config.h`, `hv_gic_parameters.h` and `arm64/hv/hv_kern_types.h`.
//!
//! The GIC entry points need macOS 15 or later.

#![allow(non_camel_case_types)]

use std::ffi::c_void;

/// `hv_return_t` (a `mach_error_t`).
pub type hv_return_t = i32;
/// `hv_vcpu_t`: vCPU instance id.
pub type hv_vcpu_t = u64;
/// `hv_ipa_t`: guest-physical (intermediate physical) address.
pub type hv_ipa_t = u64;
/// `hv_memory_flags_t`.
pub type hv_memory_flags_t = u64;
/// `hv_reg_t`.
pub type hv_reg_t = u32;
/// `hv_sys_reg_t`.
pub type hv_sys_reg_t = u16;
/// `hv_exit_reason_t`.
pub type hv_exit_reason_t = u32;

/// Opaque `os_object` handles (`hv_vm_config_t`, `hv_gic_config_t`). Released
/// with [`os_release`].
pub type hv_vm_config_t = *mut c_void;
pub type hv_gic_config_t = *mut c_void;

pub const HV_SUCCESS: hv_return_t = 0;
// err_local | err_sub(0xba5) | code
pub const HV_ERROR: hv_return_t = 0xfae9_4001_u32 as i32;
pub const HV_BUSY: hv_return_t = 0xfae9_4002_u32 as i32;
pub const HV_BAD_ARGUMENT: hv_return_t = 0xfae9_4003_u32 as i32;
pub const HV_ILLEGAL_GUEST_STATE: hv_return_t = 0xfae9_4004_u32 as i32;
pub const HV_NO_RESOURCES: hv_return_t = 0xfae9_4005_u32 as i32;
pub const HV_NO_DEVICE: hv_return_t = 0xfae9_4006_u32 as i32;
pub const HV_DENIED: hv_return_t = 0xfae9_4007_u32 as i32;
pub const HV_EXISTS: hv_return_t = 0xfae9_4008_u32 as i32;
pub const HV_UNSUPPORTED: hv_return_t = 0xfae9_400f_u32 as i32;

/// Symbolic name of a Hypervisor.framework return code, if known.
pub fn return_name(code: hv_return_t) -> Option<&'static str> {
    Some(match code {
        HV_SUCCESS => "HV_SUCCESS",
        HV_ERROR => "HV_ERROR",
        HV_BUSY => "HV_BUSY",
        HV_BAD_ARGUMENT => "HV_BAD_ARGUMENT",
        HV_ILLEGAL_GUEST_STATE => "HV_ILLEGAL_GUEST_STATE",
        HV_NO_RESOURCES => "HV_NO_RESOURCES",
        HV_NO_DEVICE => "HV_NO_DEVICE",
        HV_DENIED => "HV_DENIED",
        HV_EXISTS => "HV_EXISTS",
        HV_UNSUPPORTED => "HV_UNSUPPORTED",
        _ => return None,
    })
}

pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

pub const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
pub const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;

/// `hv_vcpu_exit_exception_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_exception_t {
    /// ESR_EL2 of the exit.
    pub syndrome: u64,
    /// FAR_EL2 (guest virtual address).
    pub virtual_address: u64,
    /// Faulting IPA (full address, including the page offset).
    pub physical_address: hv_ipa_t,
}

/// `hv_vcpu_exit_t`, written by the framework on every `hv_vcpu_run` return.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_t {
    pub reason: hv_exit_reason_t,
    pub exception: hv_vcpu_exit_exception_t,
}

// hv_reg_t
pub const HV_REG_X0: hv_reg_t = 0;
pub const HV_REG_PC: hv_reg_t = 31;
pub const HV_REG_CPSR: hv_reg_t = 34;

// hv_sys_reg_t (encoding: op0<<14 | op1<<11 | CRn<<7 | CRm<<3 | op2, with
// op0 stored as op0-2 in the top two bits; see hv_vcpu_types.h).
pub const HV_SYS_REG_MDCCINT_EL1: hv_sys_reg_t = 0x8010;
pub const HV_SYS_REG_MPIDR_EL1: hv_sys_reg_t = 0xc005;
pub const HV_SYS_REG_ID_AA64MMFR0_EL1: hv_sys_reg_t = 0xc038;
pub const HV_SYS_REG_SCTLR_EL1: hv_sys_reg_t = 0xc080;
pub const HV_SYS_REG_SP_EL1: hv_sys_reg_t = 0xe208;

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    // hv_vm_config.h
    pub fn hv_vm_config_create() -> hv_vm_config_t;
    pub fn hv_vm_config_get_default_ipa_size(ipa_bit_length: *mut u32) -> hv_return_t;
    pub fn hv_vm_config_set_ipa_size(config: hv_vm_config_t, ipa_bit_length: u32) -> hv_return_t;

    // hv_vm.h
    pub fn hv_vm_get_max_vcpu_count(max_vcpu_count: *mut u32) -> hv_return_t;
    pub fn hv_vm_create(config: hv_vm_config_t) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_map(
        addr: *mut c_void,
        ipa: hv_ipa_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;

    // hv_vcpu.h
    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut *const hv_vcpu_exit_t,
        config: *mut c_void,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpus_exit(vcpus: *mut hv_vcpu_t, vcpu_count: u32) -> hv_return_t;
    pub fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, vtimer_offset: u64) -> hv_return_t;

    // hv_gic_config.h
    pub fn hv_gic_config_create() -> hv_gic_config_t;
    pub fn hv_gic_config_set_distributor_base(
        config: hv_gic_config_t,
        distributor_base_address: hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_config_set_redistributor_base(
        config: hv_gic_config_t,
        redistributor_base_address: hv_ipa_t,
    ) -> hv_return_t;

    // hv_gic.h
    pub fn hv_gic_create(gic_config: hv_gic_config_t) -> hv_return_t;
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> hv_return_t;

    // hv_gic_parameters.h
    pub fn hv_gic_get_distributor_size(distributor_size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_distributor_base_alignment(
        distributor_base_alignment: *mut usize,
    ) -> hv_return_t;
    pub fn hv_gic_get_redistributor_region_size(
        redistributor_region_size: *mut usize,
    ) -> hv_return_t;
    pub fn hv_gic_get_redistributor_size(redistributor_size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_redistributor_base_alignment(
        redistributor_base_alignment: *mut usize,
    ) -> hv_return_t;
    pub fn hv_gic_get_spi_interrupt_range(
        spi_intid_base: *mut u32,
        spi_intid_count: *mut u32,
    ) -> hv_return_t;
}

unsafe extern "C" {
    /// `os_release` from libSystem (`<os/object.h>`, non-Objective-C build):
    /// drops a reference on an `os_object` such as `hv_vm_config_t`.
    pub fn os_release(object: *mut c_void);
    /// Host monotonic counter; on Apple Silicon it ticks at CNTFRQ_EL0 and is
    /// what the guest's CNTVCT_EL0 is derived from.
    pub fn mach_absolute_time() -> u64;
}
