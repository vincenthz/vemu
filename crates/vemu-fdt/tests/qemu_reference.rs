//! Compare against the DTB QEMU generates for `-M virt,gic-version=3` with
//! the host's accelerator (HVF on macOS, KVM on Linux): everything QEMU
//! expresses can be re-encoded by `FdtWriter` without loss, and our
//! `virt`-like tree is a faithful subset of QEMU's.
//!
//! Skipped (with a message) when qemu-system-aarch64 is not installed or
//! cannot produce a DTB on this host (no accelerator for aarch64 guests,
//! such as an x86_64 host, or no /dev/kvm access).

mod common;

use std::collections::BTreeSet;
use std::process::Command;
use std::time::Duration;

use common::{
    Dtb, VirtParams, dtc_decompile, find_tool, parse, reencode, run_with_timeout, scratch_dir,
    virt_tree,
};

const RAM: u64 = 1 << 30;

/// QEMU's accelerator on this host (`-cpu host` needs a real one).
const ACCEL: &str = if cfg!(target_os = "macos") {
    "hvf"
} else {
    "kvm"
};

/// Ask QEMU for its DTB (2 CPUs, 1 GiB, a cmdline and a fake initrd).
fn qemu_dtb(scratch: &std::path::Path) -> Option<Vec<u8>> {
    let Some(qemu) = find_tool("qemu-system-aarch64") else {
        eprintln!("qemu-system-aarch64 not found; skipping reference comparison");
        return None;
    };
    let dtb = scratch.join("qemu.dtb");
    let initrd = scratch.join("initrd");
    let kernel = scratch.join("kernel");
    std::fs::write(&initrd, vec![0u8; 4096]).unwrap();
    std::fs::write(&kernel, vec![0u8; 4096]).unwrap();
    let (ok, _, stderr) = run_with_timeout(
        Command::new(qemu)
            .arg("-M")
            .arg(format!("virt,gic-version=3,dumpdtb={}", dtb.display()))
            .args(["-accel", ACCEL, "-cpu", "host", "-smp", "2", "-m", "1G"])
            .args(["-display", "none", "-kernel"])
            .arg(&kernel)
            .arg("-initrd")
            .arg(&initrd)
            .args(["-append", "console=hvc0 vemu.test=1"]),
        Duration::from_secs(60),
    );
    match std::fs::read(&dtb) {
        Ok(blob) if ok => Some(blob),
        _ => {
            eprintln!("qemu could not dump its DTB; skipping reference comparison:\n{stderr}");
            None
        }
    }
}

#[test]
fn qemu_virt_reference() {
    let scratch = scratch_dir("qemu");
    let Some(qemu_blob) = qemu_dtb(&scratch) else {
        std::fs::remove_dir_all(&scratch).unwrap();
        return;
    };
    let qemu = parse(&qemu_blob).expect("strict parse of QEMU's DTB");

    // Lossless re-encoding of QEMU's whole tree.
    let ours = reencode(&qemu);
    assert_eq!(parse(&ours).unwrap(), qemu);
    assert!(ours.len() <= qemu_blob.len());
    if let Some(dtc) = find_tool("dtc") {
        let (theirs_dts, _) = dtc_decompile(&dtc, &qemu_blob, &scratch, "qemu.dtb");
        let (ours_dts, _) = dtc_decompile(&dtc, &ours, &scratch, "ours.dtb");
        assert_eq!(ours_dts, theirs_dts, "dtc sees a different tree");
    }
    std::fs::remove_dir_all(&scratch).unwrap();

    // Our virt-like tree only uses nodes and properties QEMU has too.
    let chosen = qemu.root.find("chosen").unwrap();
    let initrd = |name| u64::from_be_bytes(chosen.prop(name).unwrap().try_into().unwrap());
    let virt = parse(&virt_tree(&VirtParams {
        cpus: 2,
        ram_base: 0x4000_0000,
        ram_size: RAM,
        bootargs: "console=hvc0 vemu.test=1",
        initrd: Some((initrd("linux,initrd-start"), initrd("linux,initrd-end"))),
        virtio_slots: 32,
    }))
    .unwrap();
    assert_subset(&virt, &qemu);
}

/// Every node of `ours` exists in `reference`, with a subset of its property
/// names; values agree where they do not depend on phandle numbering or on
/// interrupt trigger choices.
fn assert_subset(ours: &Dtb, reference: &Dtb) {
    // Values that legitimately differ: phandles (allocation order), interrupt
    // trigger types (vemu's choice per DESIGN.md), and GIC region sizes (host
    // dependent under HVF).
    let value_may_differ = |path: &str, prop: &str| {
        matches!(prop, "phandle" | "interrupt-parent" | "interrupts")
            || (path == "/intc@8000000" && prop == "reg")
    };
    ours.root.walk("", &mut |path, node| {
        let theirs = reference
            .root
            .find(path)
            .unwrap_or_else(|| panic!("QEMU has no node {path}"));
        let their_names: BTreeSet<_> = theirs.props.iter().map(|(n, _)| n.as_str()).collect();
        for (name, value) in &node.props {
            assert!(
                their_names.contains(name.as_str()),
                "QEMU's {path} has no property {name}"
            );
            if !value_may_differ(path, name) {
                assert_eq!(
                    Some(value.as_slice()),
                    theirs.prop(name),
                    "{path}:{name} differs"
                );
            }
        }
    });
}
