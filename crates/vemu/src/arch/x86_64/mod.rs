//! The x86_64 machine (see docs/kvm-design.md, "x86_64 machine" and "Binary
//! arch interface"): RAM below and above the 3-4 GiB hole ([`layout`]), a `bzImage`
//! booted through the 64-bit boot protocol ([`bzimage`], [`bootparams`],
//! [`boot`]), hardware-reduced ACPI describing the CPUs, the in-kernel
//! IOAPIC and the virtio-mmio devices ([`acpi`], [`aml`]), and a few
//! port-I/O devices ([`devices`], plus the debug 16550 in [`uart`]).
//!
//! This module is also compiled for unit tests on other hosts, so that its
//! pure parts are tested on the development Mac: only the
//! [`ArchMachine`](super::ArchMachine) implementation in `machine.rs`,
//! which uses the host's `vemu_hv` types, is gated on x86_64. The pure
//! modules use `vemu_hv::x86_64::*` explicitly, never the crate-root
//! re-exports.

pub mod acpi;
pub mod aml;
pub mod boot;
pub mod bootparams;
pub mod bzimage;
pub mod devices;
pub mod layout;
pub mod uart;

#[cfg(target_arch = "x86_64")]
mod machine;
#[cfg(target_arch = "x86_64")]
pub use machine::X86_64;
