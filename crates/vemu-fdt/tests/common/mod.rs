//! Test support: a strict DTB reader, a `dtc` wrapper and a QEMU `virt`-like
//! tree built with `FdtWriter`.
//!
//! Each integration test binary uses a different subset of this module.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vemu_fdt::{
    FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_MAGIC, FDT_NOP, FDT_PROP, FdtWriter, GIC_PPI,
    GIC_SPI, IRQ_TYPE_LEVEL_HIGH, IRQ_TYPE_LEVEL_LOW,
};

/// A parsed device tree blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dtb {
    pub boot_cpuid_phys: u32,
    pub mem_reserve: Vec<(u64, u64)>,
    pub root: Node,
}

/// One node: name, properties in blob order, children in blob order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub props: Vec<(String, Vec<u8>)>,
    pub children: Vec<Node>,
}

impl Node {
    /// Look up a node by `/`-separated path relative to this one.
    pub fn find(&self, path: &str) -> Option<&Node> {
        path.split('/')
            .filter(|c| !c.is_empty())
            .try_fold(self, |node, component| {
                node.children.iter().find(|c| c.name == component)
            })
    }

    pub fn prop(&self, name: &str) -> Option<&[u8]> {
        self.props
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// Visit every node with its absolute path ("/" for the root).
    pub fn walk(&self, path: &str, f: &mut dyn FnMut(&str, &Node)) {
        f(if path.is_empty() { "/" } else { path }, self);
        for child in &self.children {
            child.walk(&format!("{path}/{}", child.name), f);
        }
    }
}

fn be32(b: &[u8], off: usize) -> Result<u32, String> {
    let bytes = b
        .get(off..off + 4)
        .ok_or_else(|| format!("read past end at {off:#x}"))?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

fn be64(b: &[u8], off: usize) -> Result<u64, String> {
    let bytes = b
        .get(off..off + 8)
        .ok_or_else(|| format!("read past end at {off:#x}"))?;
    Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
}

/// NUL-terminated string at `off` within `b`.
fn cstr(b: &[u8], off: usize) -> Result<String, String> {
    let tail = b
        .get(off..)
        .ok_or_else(|| format!("string offset {off:#x} out of range"))?;
    let len = tail
        .iter()
        .position(|&c| c == 0)
        .ok_or("unterminated string")?;
    String::from_utf8(tail[..len].to_vec()).map_err(|e| e.to_string())
}

/// Parse a DTB, checking the header and every structural rule a reader
/// (Linux's libfdt-based unflattening, dtc) relies on.
pub fn parse(blob: &[u8]) -> Result<Dtb, String> {
    let field = |i: usize| be32(blob, i * 4);
    if field(0)? != FDT_MAGIC {
        return Err("bad magic".into());
    }
    let totalsize = field(1)? as usize;
    let off_struct = field(2)? as usize;
    let off_strings = field(3)? as usize;
    let off_rsv = field(4)? as usize;
    let (version, last_comp) = (field(5)?, field(6)?);
    let boot_cpuid_phys = field(7)?;
    let size_strings = field(8)? as usize;
    let size_struct = field(9)? as usize;
    if version < 17 || last_comp > 16 {
        return Err(format!("unsupported version {version}/{last_comp}"));
    }
    if totalsize > blob.len() {
        return Err(format!("totalsize {totalsize:#x} > blob {:#x}", blob.len()));
    }
    if !off_rsv.is_multiple_of(8)
        || !off_struct.is_multiple_of(4)
        || !size_struct.is_multiple_of(4)
        || off_rsv < 40
    {
        return Err("misaligned block".into());
    }
    if off_struct + size_struct > totalsize || off_strings + size_strings > totalsize {
        return Err("block extends past totalsize".into());
    }
    let blob = &blob[..totalsize];

    let mut mem_reserve = Vec::new();
    let mut off = off_rsv;
    loop {
        let (addr, size) = (be64(blob, off)?, be64(blob, off + 8)?);
        off += 16;
        if (addr, size) == (0, 0) {
            break;
        }
        mem_reserve.push((addr, size));
    }
    if off > off_struct {
        return Err("reservation map overlaps the structure block".into());
    }

    let structure = &blob[off_struct..off_struct + size_struct];
    let strings = &blob[off_strings..off_strings + size_strings];
    let mut pos = 0;
    let next_token = |pos: &mut usize| -> Result<u32, String> {
        loop {
            let t = be32(structure, *pos)?;
            *pos += 4;
            if t != FDT_NOP {
                return Ok(t);
            }
        }
    };

    // Stack of nodes being built; the root ends up alone at the bottom.
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    loop {
        match next_token(&mut pos)? {
            FDT_BEGIN_NODE => {
                if root.is_some() {
                    return Err("second root node".into());
                }
                let name = cstr(structure, pos)?;
                pos = (pos + name.len() + 1).next_multiple_of(4);
                if stack.is_empty() != name.is_empty() {
                    return Err(format!("bad node name {name:?} at depth {}", stack.len()));
                }
                stack.push(Node {
                    name,
                    props: Vec::new(),
                    children: Vec::new(),
                });
            }
            FDT_PROP => {
                let len = be32(structure, pos)? as usize;
                let nameoff = be32(structure, pos + 4)? as usize;
                pos += 8;
                let value = structure
                    .get(pos..pos + len)
                    .ok_or("property value past end of structure block")?
                    .to_vec();
                pos = (pos + len).next_multiple_of(4);
                if nameoff >= strings.len() {
                    return Err(format!("nameoff {nameoff:#x} outside strings block"));
                }
                let name = cstr(strings, nameoff)?;
                let node = stack.last_mut().ok_or("property outside node")?;
                if !node.children.is_empty() {
                    return Err(format!("property {name} after subnode in {}", node.name));
                }
                if node.prop(&name).is_some() {
                    return Err(format!("duplicate property {name} in {}", node.name));
                }
                node.props.push((name, value));
            }
            FDT_END_NODE => {
                let node = stack.pop().ok_or("unbalanced FDT_END_NODE")?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }
            FDT_END => break,
            t => return Err(format!("unknown token {t:#x} at {pos:#x}")),
        }
    }
    if !stack.is_empty() {
        return Err("FDT_END with open nodes".into());
    }
    if pos != size_struct {
        return Err(format!(
            "FDT_END at {pos:#x}, size_dt_struct {size_struct:#x}"
        ));
    }
    Ok(Dtb {
        boot_cpuid_phys,
        mem_reserve,
        root: root.ok_or("no root node")?,
    })
}

/// Write a parsed tree back out with `FdtWriter`.
pub fn reencode(dtb: &Dtb) -> Vec<u8> {
    fn node(w: &mut FdtWriter, n: &Node) {
        let h = w.begin_node(&n.name).unwrap_or_else(|e| panic!("{e}"));
        for (name, value) in &n.props {
            w.property(name, value).unwrap_or_else(|e| panic!("{e}"));
        }
        for child in &n.children {
            node(w, child);
        }
        w.end_node(h).unwrap();
    }
    let mut w = FdtWriter::new();
    w.set_boot_cpuid_phys(dtb.boot_cpuid_phys);
    for &(addr, size) in &dtb.mem_reserve {
        w.add_mem_reserve(addr, size).unwrap();
    }
    node(&mut w, &dtb.root);
    w.finish().unwrap()
}

/// Where to find a host tool: on `PATH`, or Homebrew's prefix.
pub fn find_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain([
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/usr/local/bin"),
        ])
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// A fresh scratch directory for one test.
pub fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vemu-fdt-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `cmd` to completion, killing it after `limit`. Returns (status ok, stdout, stderr).
pub fn run_with_timeout(cmd: &mut Command, limit: Duration) -> (bool, String, String) {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"));
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > limit {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Decompile `blob` with `dtc -I dtb -O dts` (via a file in `scratch`).
/// Returns (dts, warnings); panics if dtc rejects the blob.
pub fn dtc_decompile(dtc: &Path, blob: &[u8], scratch: &Path, name: &str) -> (String, String) {
    let file = scratch.join(name);
    std::fs::write(&file, blob).unwrap();
    let (ok, dts, stderr) = run_with_timeout(
        Command::new(dtc)
            .args(["-I", "dtb", "-O", "dts"])
            .arg(&file),
        Duration::from_secs(30),
    );
    assert!(ok, "dtc failed on {}: {stderr}", file.display());
    (dts, stderr)
}

/// Parameters of the `virt`-like tree.
pub struct VirtParams {
    pub cpus: u32,
    pub ram_base: u64,
    pub ram_size: u64,
    pub bootargs: &'static str,
    pub initrd: Option<(u64, u64)>,
    pub virtio_slots: u32,
}

/// A device tree shaped like vemu's machine (and QEMU's `virt` with GICv3):
/// see DESIGN.md "Machine layout".
pub fn virt_tree(p: &VirtParams) -> Vec<u8> {
    let mut w = FdtWriter::new();
    let gic = w.alloc_phandle();

    let root = w.begin_node("").unwrap();
    w.property_string("compatible", "linux,dummy-virt").unwrap();
    w.property_string("model", "linux,dummy-virt").unwrap();
    w.property_u32("#address-cells", 2).unwrap();
    w.property_u32("#size-cells", 2).unwrap();
    w.property_u32("interrupt-parent", gic).unwrap();
    w.property_null("dma-coherent").unwrap();

    let chosen = w.begin_node("chosen").unwrap();
    w.property_string("bootargs", p.bootargs).unwrap();
    if let Some((start, end)) = p.initrd {
        w.property_u64("linux,initrd-start", start).unwrap();
        w.property_u64("linux,initrd-end", end).unwrap();
    }
    w.end_node(chosen).unwrap();

    let memory = w.begin_node(&format!("memory@{:x}", p.ram_base)).unwrap();
    w.property_string("device_type", "memory").unwrap();
    w.property_array_u64("reg", &[p.ram_base, p.ram_size])
        .unwrap();
    w.end_node(memory).unwrap();

    let cpus = w.begin_node("cpus").unwrap();
    w.property_u32("#address-cells", 1).unwrap();
    w.property_u32("#size-cells", 0).unwrap();
    for i in 0..p.cpus {
        let cpu = w.begin_node(&format!("cpu@{i:x}")).unwrap();
        w.property_string("device_type", "cpu").unwrap();
        w.property_string("compatible", "arm,armv8").unwrap();
        w.property_u32("reg", i).unwrap();
        w.property_string("enable-method", "psci").unwrap();
        w.end_node(cpu).unwrap();
    }
    w.end_node(cpus).unwrap();

    let psci = w.begin_node("psci").unwrap();
    w.property_string_list("compatible", &["arm,psci-1.0", "arm,psci-0.2", "arm,psci"])
        .unwrap();
    w.property_string("method", "hvc").unwrap();
    w.end_node(psci).unwrap();

    let intc = w.begin_node("intc@8000000").unwrap();
    w.property_string("compatible", "arm,gic-v3").unwrap();
    w.property_u32("#interrupt-cells", 3).unwrap();
    w.property_null("interrupt-controller").unwrap();
    w.property_u32("#redistributor-regions", 1).unwrap();
    w.property_array_u64("reg", &[0x0800_0000, 0x1_0000, 0x080a_0000, 0xf6_0000])
        .unwrap();
    w.property_u32("phandle", gic).unwrap();
    w.end_node(intc).unwrap();

    let timer = w.begin_node("timer").unwrap();
    w.property_string_list("compatible", &["arm,armv8-timer", "arm,armv7-timer"])
        .unwrap();
    let ppis: Vec<u32> = [13, 14, 11, 10]
        .iter()
        .flat_map(|&ppi| [GIC_PPI, ppi, IRQ_TYPE_LEVEL_LOW])
        .collect();
    w.property_array_u32("interrupts", &ppis).unwrap();
    w.property_null("always-on").unwrap();
    w.end_node(timer).unwrap();

    for slot in 0..p.virtio_slots {
        let base = 0x0a00_0000 + u64::from(slot) * 0x200;
        let dev = w.begin_node(&format!("virtio_mmio@{base:x}")).unwrap();
        w.property_string("compatible", "virtio,mmio").unwrap();
        w.property_array_u64("reg", &[base, 0x200]).unwrap();
        w.property_array_u32("interrupts", &[GIC_SPI, 16 + slot, IRQ_TYPE_LEVEL_HIGH])
            .unwrap();
        w.property_null("dma-coherent").unwrap();
        w.end_node(dev).unwrap();
    }

    w.end_node(root).unwrap();
    w.finish().unwrap()
}
