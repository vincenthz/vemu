//! A realistic `virt`-like tree: parsed back strictly, and decompiled by
//! `dtc` (skipped when dtc is not installed).

mod common;

use common::{VirtParams, dtc_decompile, find_tool, parse, scratch_dir, virt_tree};

const PARAMS: VirtParams = VirtParams {
    cpus: 4,
    ram_base: 0x4000_0000,
    ram_size: 0x4000_0000,
    bootargs: "console=hvc0 vemu.test=1",
    initrd: Some((0x7fa0_0000, 0x7fc1_2345)),
    virtio_slots: 3,
};

#[test]
fn virt_tree_parses_back() {
    let blob = virt_tree(&PARAMS);
    let dtb = parse(&blob).expect("strict parse");
    assert_eq!(dtb.boot_cpuid_phys, 0);
    assert!(dtb.mem_reserve.is_empty());

    let root = &dtb.root;
    let gic = root.find("intc@8000000").unwrap();
    assert_eq!(root.prop("interrupt-parent"), gic.prop("phandle"));
    assert_eq!(gic.prop("phandle"), Some(&[0, 0, 0, 1][..]));
    assert_eq!(gic.prop("interrupt-controller"), Some(&[][..]));

    let chosen = root.find("chosen").unwrap();
    assert_eq!(
        chosen.prop("bootargs"),
        Some(&b"console=hvc0 vemu.test=1\0"[..])
    );
    assert_eq!(
        chosen.prop("linux,initrd-start"),
        Some(&0x7fa0_0000u64.to_be_bytes()[..])
    );
    assert_eq!(
        chosen.prop("linux,initrd-end"),
        Some(&0x7fc1_2345u64.to_be_bytes()[..])
    );

    for i in 0..4u32 {
        let cpu = root.find(&format!("cpus/cpu@{i:x}")).unwrap();
        assert_eq!(cpu.prop("reg"), Some(&i.to_be_bytes()[..]));
    }
    let names: Vec<_> = root.children.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "chosen",
            "memory@40000000",
            "cpus",
            "psci",
            "intc@8000000",
            "timer",
            "virtio_mmio@a000000",
            "virtio_mmio@a000200",
            "virtio_mmio@a000400",
        ]
    );

    // Every property name is stored once in the strings block.
    let off_strings = u32::from_be_bytes(blob[12..16].try_into().unwrap()) as usize;
    let size_strings = u32::from_be_bytes(blob[32..36].try_into().unwrap()) as usize;
    let strings = &blob[off_strings..off_strings + size_strings];
    let mut seen = std::collections::HashSet::new();
    for s in strings.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        assert!(
            seen.insert(s),
            "{} stored twice",
            String::from_utf8_lossy(s)
        );
    }
    assert!(seen.contains(&b"compatible"[..]));
}

#[test]
fn virt_tree_through_dtc() {
    let Some(dtc) = find_tool("dtc") else {
        eprintln!("dtc not found; skipping dtc round-trip");
        return;
    };
    let scratch = scratch_dir("virt");
    let (dts, warnings) = dtc_decompile(&dtc, &virt_tree(&PARAMS), &scratch, "virt.dtb");
    std::fs::remove_dir_all(&scratch).unwrap();
    assert!(warnings.trim().is_empty(), "dtc warnings:\n{warnings}");

    let expected = [
        "/dts-v1/;",
        "/ {",
        "\tcompatible = \"linux,dummy-virt\";",
        "\t#address-cells = <0x02>;",
        "\tinterrupt-parent = <0x01>;",
        "\tdma-coherent;",
        "\tchosen {",
        "\t\tbootargs = \"console=hvc0 vemu.test=1\";",
        "\t\tlinux,initrd-start = <0x00 0x7fa00000>;",
        "\t\tlinux,initrd-end = <0x00 0x7fc12345>;",
        "\tmemory@40000000 {",
        "\t\tdevice_type = \"memory\";",
        "\t\treg = <0x00 0x40000000 0x00 0x40000000>;",
        "\tcpus {",
        "\t\t#size-cells = <0x00>;",
        "\t\tcpu@3 {",
        "\t\t\treg = <0x03>;",
        "\t\t\tenable-method = \"psci\";",
        "\t\tcompatible = \"arm,psci-1.0\", \"arm,psci-0.2\", \"arm,psci\";",
        "\t\tmethod = \"hvc\";",
        "\tintc@8000000 {",
        "\t\tcompatible = \"arm,gic-v3\";",
        "\t\t#interrupt-cells = <0x03>;",
        "\t\tinterrupt-controller;",
        "\t\treg = <0x00 0x8000000 0x00 0x10000 0x00 0x80a0000 0x00 0xf60000>;",
        "\t\tphandle = <0x01>;",
        "\ttimer {",
        "\t\tcompatible = \"arm,armv8-timer\", \"arm,armv7-timer\";",
        "\t\tinterrupts = <0x01 0x0d 0x08 0x01 0x0e 0x08 0x01 0x0b 0x08 0x01 0x0a 0x08>;",
        "\t\talways-on;",
        "\tvirtio_mmio@a000400 {",
        "\t\tcompatible = \"virtio,mmio\";",
        "\t\treg = <0x00 0xa000400 0x00 0x200>;",
        "\t\tinterrupts = <0x00 0x12 0x04>;",
    ];
    let lines: Vec<&str> = dts.lines().collect();
    for line in expected {
        assert!(
            lines.contains(&line),
            "missing {line:?} in dtc output:\n{dts}"
        );
    }
}
