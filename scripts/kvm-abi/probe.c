/*
 * Compile-time check of vemu-hv's KVM ABI definitions against the Linux UAPI
 * headers (the ones bundled with zig, or a Linux host's). Nothing runs: the
 * file compiles only if every value matches. Driven by check.sh.
 *
 * VEMU_ABI_HEADER is generated from the Rust definitions
 * (crates/vemu-hv/src/kvm/abi.rs, test kvm::abi::tests::c_header): one
 * VEMU_CHECK(C expression, Rust value) line per size, offset, ioctl number
 * and constant. The Rust side pins the same sizes/offsets with const
 * asserts on every target, so checking the host-generated values here for
 * each Linux target covers the Rust build for that target.
 *
 * Arch-specific definitions (kvm/aarch64.rs, kvm/x86_64.rs) are checked in
 * probe-aarch64.h / probe-x86_64.h with VEMU_CHECK and literal values, which
 * the Rust side pins with matching const asserts.
 */
#include <stddef.h>
#include <linux/kvm.h>

#define VEMU_CHECK(expr, val) \
	_Static_assert((unsigned long long)(expr) == (val), #expr " differs from vemu-hv (" #val ")");

#include VEMU_ABI_HEADER

#if defined(__aarch64__)
#include "probe-aarch64.h"
#elif defined(__x86_64__)
#include "probe-x86_64.h"
#else
#error "vemu supports aarch64 and x86_64 Linux hosts only"
#endif

/* The generic ioctl encoding is what both arches use. */
VEMU_CHECK(_IOC_SIZESHIFT, 16)
VEMU_CHECK(_IOC_DIRSHIFT, 30)
VEMU_CHECK(_IOC_WRITE, 1)
VEMU_CHECK(_IOC_READ, 2)

int vemu_kvm_abi_probe;
