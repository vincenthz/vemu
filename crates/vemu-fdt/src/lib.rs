//! A writer for flattened device trees (DTB, the Devicetree Specification's
//! "flattened devicetree" format, version 17, last compatible version 16).
//!
//! The tree is built sequentially, depth first: open a node with
//! [`FdtWriter::begin_node`], add its properties, then its child nodes, and
//! close it with [`FdtWriter::end_node`]. [`FdtWriter::finish`] lays out the
//! blob:
//!
//! ```text
//! +-------------------------+ 0
//! | header (40 bytes)       |
//! +-------------------------+ 40   (8-byte aligned)
//! | memory reservation map  |      16-byte entries, terminated by (0, 0)
//! +-------------------------+      (4-byte aligned)
//! | structure block         |      FDT_BEGIN_NODE / FDT_PROP / FDT_NOP /
//! |                         |      FDT_END_NODE tokens, closed by FDT_END
//! +-------------------------+
//! | strings block           |      NUL-terminated property names, deduplicated
//! +-------------------------+ totalsize
//! ```
//!
//! All integers are big-endian and every structure-block item is padded to a
//! 4-byte boundary.
//!
//! Mistakes are reported as [`Error`]s rather than producing a blob the guest
//! kernel would misparse: unbalanced nodes, properties outside a node or after
//! a child node, invalid or duplicate names, and so on. A failed call leaves
//! the writer unchanged, so callers may report the error and carry on.
//!
//! ```
//! use vemu_fdt::{FdtWriter, GIC_SPI, IRQ_TYPE_LEVEL_HIGH};
//!
//! let mut fdt = FdtWriter::new();
//! let root = fdt.begin_node("")?;
//! fdt.property_string("compatible", "linux,dummy-virt")?;
//! fdt.property_u32("#address-cells", 2)?;
//! fdt.property_u32("#size-cells", 2)?;
//! let gic = fdt.alloc_phandle();
//! fdt.property_u32("interrupt-parent", gic)?;
//!
//! let dev = fdt.begin_node("virtio_mmio@a000000")?;
//! fdt.property_string("compatible", "virtio,mmio")?;
//! fdt.property_array_u64("reg", &[0x0a00_0000, 0x200])?;
//! fdt.property_array_u32("interrupts", &[GIC_SPI, 16, IRQ_TYPE_LEVEL_HIGH])?;
//! fdt.end_node(dev)?;
//!
//! fdt.end_node(root)?;
//! let dtb = fdt.finish()?;
//! assert_eq!(&dtb[..4], &[0xd0, 0x0d, 0xfe, 0xed]);
//! # Ok::<(), vemu_fdt::Error>(())
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

/// First cell of a GIC `interrupts` specifier: shared peripheral interrupt.
/// The second cell is then the SPI number (INTID - 32).
pub const GIC_SPI: u32 = 0;
/// First cell of a GIC `interrupts` specifier: private peripheral interrupt.
/// The second cell is then the PPI number (INTID - 16).
pub const GIC_PPI: u32 = 1;

/// Third cell of a GIC `interrupts` specifier: rising-edge triggered.
pub const IRQ_TYPE_EDGE_RISING: u32 = 1;
/// Third cell of a GIC `interrupts` specifier: active-high level triggered.
pub const IRQ_TYPE_LEVEL_HIGH: u32 = 4;
/// Third cell of a GIC `interrupts` specifier: active-low level triggered.
pub const IRQ_TYPE_LEVEL_LOW: u32 = 8;

/// Header magic, first word of every DTB.
pub const FDT_MAGIC: u32 = 0xd00d_feed;
/// The format version this writer produces.
pub const FDT_VERSION: u32 = 17;
/// The oldest format version a reader must understand to parse our output.
pub const FDT_LAST_COMP_VERSION: u32 = 16;

/// Structure block token: start of a node, followed by its NUL-terminated name.
pub const FDT_BEGIN_NODE: u32 = 0x1;
/// Structure block token: end of a node.
pub const FDT_END_NODE: u32 = 0x2;
/// Structure block token: a property (`len`, `nameoff`, then `len` value bytes).
pub const FDT_PROP: u32 = 0x3;
/// Structure block token: no-op, ignored by readers.
pub const FDT_NOP: u32 = 0x4;
/// Structure block token: end of the structure block.
pub const FDT_END: u32 = 0x9;

/// Size of the version 17 header: ten big-endian `u32` fields.
const HEADER_SIZE: usize = 40;
/// Size of one memory reservation entry: big-endian `u64` address and size.
const MEM_RESERVE_ENTRY_SIZE: usize = 16;
/// Longest node name (the part before `@`) and property name the
/// Devicetree Specification allows.
const MAX_NAME_LEN: usize = 31;

/// Errors from building a device tree.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A node name is empty (outside the root), longer than 31 characters
    /// before the `@`, has an empty unit address, or uses characters outside
    /// `[0-9a-zA-Z,._+-]` (plus a single `@`).
    InvalidNodeName(String),
    /// The root node was given a name; it must be `""`.
    RootNodeNamed(String),
    /// A second top-level node was started after the root node was closed.
    MultipleRootNodes(String),
    /// Two children of the same node share a name.
    DuplicateNode(String),
    /// A property name is empty, longer than 31 characters, or uses
    /// characters outside `[0-9a-zA-Z,._+?#-]`.
    InvalidPropertyName(String),
    /// A node already has a property with this name.
    DuplicateProperty(String),
    /// A property was added while no node is open.
    PropertyOutsideNode(String),
    /// A property was added to a node after one of its child nodes; the
    /// format requires all properties to precede the children.
    PropertyAfterSubnode(String),
    /// A string property value contains an interior NUL byte (the property
    /// name is carried).
    StringContainsNul(String),
    /// A NOP token was requested while no node is open (readers expect the
    /// structure block to start with the root node).
    NopOutsideNode,
    /// [`FdtWriter::end_node`] was given a handle that is not the innermost
    /// open node.
    MismatchedEndNode,
    /// [`FdtWriter::finish`] was called with this many nodes still open.
    UnclosedNodes(usize),
    /// [`FdtWriter::finish`] was called before any root node was written.
    NoRootNode,
    /// A memory reservation has size zero (which would read as the list
    /// terminator) or extends past the end of the 64-bit address space.
    InvalidMemReserve {
        /// Start of the rejected reservation.
        addr: u64,
        /// Size of the rejected reservation.
        size: u64,
    },
    /// The blob, or a property value, does not fit the format's 32-bit sizes.
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidNodeName(n) => write!(f, "invalid device tree node name {n:?}"),
            Error::RootNodeNamed(n) => {
                write!(f, "device tree root node must be named \"\", not {n:?}")
            }
            Error::MultipleRootNodes(n) => {
                write!(
                    f,
                    "device tree node {n:?} started after the root node was closed"
                )
            }
            Error::DuplicateNode(n) => write!(f, "duplicate device tree node {n:?}"),
            Error::InvalidPropertyName(n) => write!(f, "invalid device tree property name {n:?}"),
            Error::DuplicateProperty(n) => write!(f, "duplicate device tree property {n:?}"),
            Error::PropertyOutsideNode(n) => {
                write!(f, "device tree property {n:?} written outside of any node")
            }
            Error::PropertyAfterSubnode(n) => {
                write!(f, "device tree property {n:?} written after a child node")
            }
            Error::StringContainsNul(n) => {
                write!(f, "device tree string property {n:?} contains a NUL byte")
            }
            Error::NopOutsideNode => write!(f, "device tree NOP written outside of any node"),
            Error::MismatchedEndNode => {
                write!(
                    f,
                    "device tree end_node handle is not the innermost open node"
                )
            }
            Error::UnclosedNodes(n) => {
                write!(f, "device tree finished with {n} node(s) still open")
            }
            Error::NoRootNode => write!(f, "device tree has no root node"),
            Error::InvalidMemReserve { addr, size } => {
                write!(
                    f,
                    "invalid device tree memory reservation addr={addr:#x} size={size:#x}"
                )
            }
            Error::TooLarge => write!(f, "device tree exceeds the format's 32-bit size limits"),
        }
    }
}

impl std::error::Error for Error {}

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Proof that a node is open, returned by [`FdtWriter::begin_node`] and
/// consumed by [`FdtWriter::end_node`].
///
/// Handles are deliberately neither `Copy` nor `Clone`: each node is closed
/// exactly once, and closing out of order is detected.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a device tree node must be closed with FdtWriter::end_node"]
pub struct NodeHandle {
    serial: u64,
}

/// Book-keeping for a node between `begin_node` and `end_node`.
#[derive(Debug)]
struct OpenNode {
    serial: u64,
    /// String-block offsets of the property names already used here.
    properties: HashSet<u32>,
    /// Names of the child nodes already written.
    children: HashSet<String>,
}

/// Sequential flattened device tree builder. See the [crate docs](crate).
#[derive(Debug)]
pub struct FdtWriter {
    mem_reserve: Vec<(u64, u64)>,
    structure: Vec<u8>,
    strings: Vec<u8>,
    string_offsets: HashMap<String, u32>,
    stack: Vec<OpenNode>,
    next_serial: u64,
    root_written: bool,
    boot_cpuid_phys: u32,
    last_phandle: u32,
}

impl Default for FdtWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FdtWriter {
    /// An empty tree: no nodes, no memory reservations, boot CPU 0.
    pub fn new() -> FdtWriter {
        FdtWriter {
            mem_reserve: Vec::new(),
            structure: Vec::new(),
            strings: Vec::new(),
            string_offsets: HashMap::new(),
            stack: Vec::new(),
            next_serial: 0,
            root_written: false,
            boot_cpuid_phys: 0,
            last_phandle: 0,
        }
    }

    /// Open a node. The first node must be the root, named `""`; every other
    /// node is a child of the innermost open node and is named
    /// `node-name[@unit-address]`.
    pub fn begin_node(&mut self, name: &str) -> Result<NodeHandle> {
        match self.stack.last() {
            None if self.root_written => return Err(Error::MultipleRootNodes(name.to_owned())),
            None if !name.is_empty() => return Err(Error::RootNodeNamed(name.to_owned())),
            None => {}
            Some(parent) => {
                validate_node_name(name)?;
                if parent.children.contains(name) {
                    return Err(Error::DuplicateNode(name.to_owned()));
                }
            }
        }

        if let Some(parent) = self.stack.last_mut() {
            parent.children.insert(name.to_owned());
        }
        self.root_written = true;
        let serial = self.next_serial;
        self.next_serial += 1;
        self.stack.push(OpenNode {
            serial,
            properties: HashSet::new(),
            children: HashSet::new(),
        });

        self.push_u32(FDT_BEGIN_NODE);
        self.structure.extend_from_slice(name.as_bytes());
        self.structure.push(0);
        self.pad_structure();
        Ok(NodeHandle { serial })
    }

    /// Close the innermost open node, which `h` must refer to.
    pub fn end_node(&mut self, h: NodeHandle) -> Result<()> {
        match self.stack.last() {
            Some(node) if node.serial == h.serial => {}
            _ => return Err(Error::MismatchedEndNode),
        }
        self.stack.pop();
        self.push_u32(FDT_END_NODE);
        Ok(())
    }

    /// Add a property with a raw value to the innermost open node.
    ///
    /// Properties of a node must all be written before its first child node.
    pub fn property(&mut self, name: &str, value: &[u8]) -> Result<()> {
        validate_property_name(name)?;
        let Some(node) = self.stack.last() else {
            return Err(Error::PropertyOutsideNode(name.to_owned()));
        };
        if !node.children.is_empty() {
            return Err(Error::PropertyAfterSubnode(name.to_owned()));
        }
        if let Some(off) = self.string_offsets.get(name)
            && node.properties.contains(off)
        {
            return Err(Error::DuplicateProperty(name.to_owned()));
        }
        let len = u32::try_from(value.len()).map_err(|_| Error::TooLarge)?;
        let nameoff = self.intern(name)?;

        self.stack
            .last_mut()
            .expect("checked above")
            .properties
            .insert(nameoff);
        self.push_u32(FDT_PROP);
        self.push_u32(len);
        self.push_u32(nameoff);
        self.structure.extend_from_slice(value);
        self.pad_structure();
        Ok(())
    }

    /// Add an empty (boolean) property, e.g. `interrupt-controller`.
    pub fn property_null(&mut self, name: &str) -> Result<()> {
        self.property(name, &[])
    }

    /// Add a NUL-terminated string property.
    pub fn property_string(&mut self, name: &str, s: &str) -> Result<()> {
        self.property_string_list(name, &[s])
    }

    /// Add a string-list property: each string NUL-terminated, concatenated
    /// (e.g. `compatible = "arm,psci-1.0", "arm,psci-0.2"`).
    pub fn property_string_list(&mut self, name: &str, l: &[&str]) -> Result<()> {
        if l.iter().any(|s| s.contains('\0')) {
            return Err(Error::StringContainsNul(name.to_owned()));
        }
        let mut value = Vec::with_capacity(l.iter().map(|s| s.len() + 1).sum());
        for s in l {
            value.extend_from_slice(s.as_bytes());
            value.push(0);
        }
        self.property(name, &value)
    }

    /// Add a single-cell (big-endian `u32`) property.
    pub fn property_u32(&mut self, name: &str, v: u32) -> Result<()> {
        self.property(name, &v.to_be_bytes())
    }

    /// Add a two-cell (big-endian `u64`) property, e.g. `linux,initrd-start`.
    pub fn property_u64(&mut self, name: &str, v: u64) -> Result<()> {
        self.property(name, &v.to_be_bytes())
    }

    /// Add a property made of consecutive big-endian `u32` cells.
    pub fn property_array_u32(&mut self, name: &str, v: &[u32]) -> Result<()> {
        let value: Vec<u8> = v.iter().flat_map(|c| c.to_be_bytes()).collect();
        self.property(name, &value)
    }

    /// Add a property made of consecutive big-endian `u64` values (two cells
    /// each), e.g. `reg` with `#address-cells = #size-cells = 2`.
    pub fn property_array_u64(&mut self, name: &str, v: &[u64]) -> Result<()> {
        let value: Vec<u8> = v.iter().flat_map(|c| c.to_be_bytes()).collect();
        self.property(name, &value)
    }

    /// Emit an `FDT_NOP` token inside the innermost open node. Readers skip
    /// it; it exists to reserve or blank out space in place.
    pub fn nop(&mut self) -> Result<()> {
        if self.stack.is_empty() {
            return Err(Error::NopOutsideNode);
        }
        self.push_u32(FDT_NOP);
        Ok(())
    }

    /// Add a memory reservation map entry: guest-physical memory the OS must
    /// not use. Entries are emitted in the order added.
    pub fn add_mem_reserve(&mut self, addr: u64, size: u64) -> Result<()> {
        if size == 0 || addr.checked_add(size - 1).is_none() {
            return Err(Error::InvalidMemReserve { addr, size });
        }
        self.mem_reserve.push((addr, size));
        Ok(())
    }

    /// Set the header's `boot_cpuid_phys` (the `reg` of the boot CPU node).
    /// Defaults to 0.
    pub fn set_boot_cpuid_phys(&mut self, id: u32) {
        self.boot_cpuid_phys = id;
    }

    /// Allocate a fresh phandle (1, 2, 3, ...) to put in a node's `phandle`
    /// property and in the properties that reference it. Allocation is
    /// independent of the tree structure, so a phandle can be referenced
    /// before the node carrying it is written.
    ///
    /// # Panics
    ///
    /// After 0xffff_fffe allocations: 0 and 0xffff_ffff are not valid phandles.
    pub fn alloc_phandle(&mut self) -> u32 {
        assert!(
            self.last_phandle < 0xffff_fffe,
            "device tree phandles exhausted"
        );
        self.last_phandle += 1;
        self.last_phandle
    }

    /// Lay out the blob. Fails if no root node was written or nodes are
    /// still open.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        if !self.stack.is_empty() {
            return Err(Error::UnclosedNodes(self.stack.len()));
        }
        if !self.root_written {
            return Err(Error::NoRootNode);
        }
        self.push_u32(FDT_END);

        let off_mem_rsvmap = HEADER_SIZE;
        let off_dt_struct = off_mem_rsvmap + (self.mem_reserve.len() + 1) * MEM_RESERVE_ENTRY_SIZE;
        let off_dt_strings = off_dt_struct + self.structure.len();
        let totalsize = off_dt_strings + self.strings.len();
        let to_u32 = |v: usize| u32::try_from(v).map_err(|_| Error::TooLarge);

        let header = [
            FDT_MAGIC,
            to_u32(totalsize)?,
            to_u32(off_dt_struct)?,
            to_u32(off_dt_strings)?,
            to_u32(off_mem_rsvmap)?,
            FDT_VERSION,
            FDT_LAST_COMP_VERSION,
            self.boot_cpuid_phys,
            to_u32(self.strings.len())?,
            to_u32(self.structure.len())?,
        ];

        let mut blob = Vec::with_capacity(totalsize);
        blob.extend(header.iter().flat_map(|w| w.to_be_bytes()));
        for &(addr, size) in self.mem_reserve.iter().chain(&[(0, 0)]) {
            blob.extend_from_slice(&addr.to_be_bytes());
            blob.extend_from_slice(&size.to_be_bytes());
        }
        blob.extend_from_slice(&self.structure);
        blob.extend_from_slice(&self.strings);
        debug_assert_eq!(blob.len(), totalsize);
        Ok(blob)
    }

    /// Offset of `name` in the strings block, adding it on first use.
    fn intern(&mut self, name: &str) -> Result<u32> {
        if let Some(&off) = self.string_offsets.get(name) {
            return Ok(off);
        }
        let off = u32::try_from(self.strings.len()).map_err(|_| Error::TooLarge)?;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.string_offsets.insert(name.to_owned(), off);
        Ok(off)
    }

    fn push_u32(&mut self, v: u32) {
        self.structure.extend_from_slice(&v.to_be_bytes());
    }

    fn pad_structure(&mut self) {
        let padded = self.structure.len().next_multiple_of(4);
        self.structure.resize(padded, 0);
    }
}

/// Check `node-name[@unit-address]` against the Devicetree Specification
/// (section 2.2.1): a 1..=31 character node name and an optional non-empty
/// unit address, both from `[0-9a-zA-Z,._+-]`.
fn validate_node_name(name: &str) -> Result<()> {
    let is_node_char = |c: char| c.is_ascii_alphanumeric() || ",._+-".contains(c);
    let (base, unit) = match name.split_once('@') {
        Some((base, unit)) => (base, Some(unit)),
        None => (name, None),
    };
    let base_ok = (1..=MAX_NAME_LEN).contains(&base.len()) && base.chars().all(is_node_char);
    let unit_ok = unit.is_none_or(|u| !u.is_empty() && u.chars().all(is_node_char));
    if base_ok && unit_ok {
        Ok(())
    } else {
        Err(Error::InvalidNodeName(name.to_owned()))
    }
}

/// Check a property name against the Devicetree Specification (section
/// 2.2.4): 1..=31 characters from `[0-9a-zA-Z,._+?#-]`.
fn validate_property_name(name: &str) -> Result<()> {
    let is_prop_char = |c: char| c.is_ascii_alphanumeric() || ",._+?#-".contains(c);
    if (1..=MAX_NAME_LEN).contains(&name.len()) && name.chars().all(is_prop_char) {
        Ok(())
    } else {
        Err(Error::InvalidPropertyName(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flatten big-endian words into bytes, for writing expectations.
    fn words(w: &[u32]) -> Vec<u8> {
        w.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    fn header(totalsize: u32, off_struct: u32, size_strings: u32, size_struct: u32) -> Vec<u8> {
        words(&[
            FDT_MAGIC,
            totalsize,
            off_struct,
            off_struct + size_struct,
            40,
            17,
            16,
            0,
            size_strings,
            size_struct,
        ])
    }

    #[test]
    fn empty_root_exact_bytes() {
        let mut w = FdtWriter::new();
        let root = w.begin_node("").unwrap();
        w.end_node(root).unwrap();
        let dtb = w.finish().unwrap();

        let mut expected = header(72, 56, 0, 16);
        expected.extend(words(&[0, 0, 0, 0])); // reservation map terminator
        expected.extend(words(&[FDT_BEGIN_NODE, 0, FDT_END_NODE, FDT_END]));
        assert_eq!(dtb, expected);
    }

    #[test]
    fn properties_children_and_padding_exact_bytes() {
        let mut w = FdtWriter::new();
        let root = w.begin_node("").unwrap();
        w.property_u32("#address-cells", 2).unwrap();
        w.property_string("model", "abc").unwrap();
        w.property_null("dma-coherent").unwrap();
        let child = w.begin_node("cpu@0").unwrap();
        w.property_u32("#address-cells", 1).unwrap(); // deduplicated name
        w.property_u64("reg", 0x0102_0304_0506_0708).unwrap();
        w.nop().unwrap();
        w.end_node(child).unwrap();
        w.end_node(root).unwrap();
        let dtb = w.finish().unwrap();

        let strings = b"#address-cells\0model\0dma-coherent\0reg\0";
        let mut structure = words(&[FDT_BEGIN_NODE, 0]);
        structure.extend(words(&[FDT_PROP, 4, 0, 2]));
        structure.extend(words(&[FDT_PROP, 4, 15]));
        structure.extend(b"abc\0");
        structure.extend(words(&[FDT_PROP, 0, 21]));
        structure.extend(words(&[FDT_BEGIN_NODE]));
        structure.extend(b"cpu@0\0\0\0");
        structure.extend(words(&[FDT_PROP, 4, 0, 1]));
        structure.extend(words(&[FDT_PROP, 8, 34, 0x0102_0304, 0x0506_0708]));
        structure.extend(words(&[FDT_NOP, FDT_END_NODE, FDT_END_NODE, FDT_END]));

        let size_struct = structure.len() as u32;
        let total = 56 + size_struct + strings.len() as u32;
        let mut expected = header(total, 56, strings.len() as u32, size_struct);
        expected.extend(words(&[0, 0, 0, 0]));
        expected.extend(structure);
        expected.extend(strings);
        assert_eq!(dtb, expected);
    }

    #[test]
    fn mem_reserve_and_boot_cpu_exact_bytes() {
        let mut w = FdtWriter::new();
        w.add_mem_reserve(0x4000_0000, 0x1000).unwrap();
        w.add_mem_reserve(0x1_0000_0000, 0x20_0000).unwrap();
        w.set_boot_cpuid_phys(3);
        let root = w.begin_node("").unwrap();
        w.end_node(root).unwrap();
        let dtb = w.finish().unwrap();

        let mut expected = words(&[FDT_MAGIC, 104, 88, 104, 40, 17, 16, 3, 0, 16]);
        expected.extend(words(&[0, 0x4000_0000, 0, 0x1000]));
        expected.extend(words(&[1, 0, 0, 0x20_0000]));
        expected.extend(words(&[0, 0, 0, 0]));
        expected.extend(words(&[FDT_BEGIN_NODE, 0, FDT_END_NODE, FDT_END]));
        assert_eq!(dtb, expected);
    }

    #[test]
    fn string_list_and_arrays() {
        let mut w = FdtWriter::new();
        let root = w.begin_node("").unwrap();
        w.property_string_list("compatible", &["a,b", "cd"])
            .unwrap();
        w.property_array_u32("interrupts", &[GIC_PPI, 13, IRQ_TYPE_LEVEL_LOW])
            .unwrap();
        w.property_array_u64("reg", &[0x4000_0000, 0x4000_0000])
            .unwrap();
        w.end_node(root).unwrap();
        let dtb = w.finish().unwrap();

        let mut expected = words(&[FDT_PROP, 7, 0]);
        expected.extend(b"a,b\0cd\0\0");
        expected.extend(words(&[FDT_PROP, 12, 11, 1, 13, 8]));
        expected.extend(words(&[FDT_PROP, 16, 22, 0, 0x4000_0000, 0, 0x4000_0000]));
        // Structure starts at 56: BEGIN_NODE + empty name, then the properties.
        assert_eq!(&dtb[64..64 + expected.len()], &expected[..]);
    }

    #[test]
    fn phandles_are_sequential_from_one() {
        let mut w = FdtWriter::new();
        assert_eq!(w.alloc_phandle(), 1);
        assert_eq!(w.alloc_phandle(), 2);
        assert_eq!(w.alloc_phandle(), 3);
    }

    #[test]
    fn node_structure_errors() {
        let mut w = FdtWriter::new();
        assert_eq!(w.begin_node("foo"), Err(Error::RootNodeNamed("foo".into())));
        let root = w.begin_node("").unwrap();
        assert_eq!(w.begin_node(""), Err(Error::InvalidNodeName("".into())));
        let a = w.begin_node("a").unwrap();
        let b = w.begin_node("b").unwrap();
        // Closing the outer node while the inner one is open.
        assert_eq!(w.end_node(a), Err(Error::MismatchedEndNode));
        w.end_node(b).unwrap();
        assert_eq!(w.begin_node("b"), Err(Error::DuplicateNode("b".into())));
        assert_eq!(w.end_node(root), Err(Error::MismatchedEndNode));
        assert_eq!(w.finish(), Err(Error::UnclosedNodes(2)));
    }

    #[test]
    fn second_root_and_missing_root() {
        assert_eq!(FdtWriter::new().finish(), Err(Error::NoRootNode));

        let mut w = FdtWriter::new();
        let root = w.begin_node("").unwrap();
        w.end_node(root).unwrap();
        assert_eq!(w.begin_node(""), Err(Error::MultipleRootNodes("".into())));
        assert_eq!(
            w.property_u32("x", 1),
            Err(Error::PropertyOutsideNode("x".into()))
        );
        assert_eq!(w.nop(), Err(Error::NopOutsideNode));
        assert!(w.finish().is_ok());
    }

    #[test]
    fn property_errors() {
        let mut w = FdtWriter::new();
        assert_eq!(
            w.property_null("x"),
            Err(Error::PropertyOutsideNode("x".into()))
        );
        assert_eq!(w.nop(), Err(Error::NopOutsideNode));
        let root = w.begin_node("").unwrap();
        w.property_u32("x", 1).unwrap();
        assert_eq!(
            w.property_u32("x", 2),
            Err(Error::DuplicateProperty("x".into()))
        );
        assert_eq!(
            w.property_string("s", "a\0b"),
            Err(Error::StringContainsNul("s".into()))
        );
        let child = w.begin_node("child").unwrap();
        // Same name in a different node is fine.
        w.property_u32("x", 3).unwrap();
        w.end_node(child).unwrap();
        assert_eq!(
            w.property_u32("y", 1),
            Err(Error::PropertyAfterSubnode("y".into()))
        );
        w.end_node(root).unwrap();
        w.finish().unwrap();
    }

    #[test]
    fn name_validation() {
        for ok in [
            "cpu@0",
            "virtio_mmio@a000000",
            "a,b.c_d+e-f",
            "x@1,2",
            &"n".repeat(31),
        ] {
            validate_node_name(ok).unwrap();
        }
        for bad in [
            "",
            "@1",
            "cpu@",
            "a@b@c",
            "sp ace",
            "Ü",
            "a/b",
            &"n".repeat(32),
        ] {
            assert_eq!(
                validate_node_name(bad),
                Err(Error::InvalidNodeName(bad.into())),
                "{bad}"
            );
        }
        for ok in [
            "#address-cells",
            "linux,initrd-start",
            "a?",
            "_",
            &"p".repeat(31),
        ] {
            validate_property_name(ok).unwrap();
        }
        for bad in ["", "a@b", "a b", "a/b", &"p".repeat(32)] {
            assert_eq!(
                validate_property_name(bad),
                Err(Error::InvalidPropertyName(bad.into())),
                "{bad}"
            );
        }
    }

    #[test]
    fn failed_calls_leave_writer_unchanged() {
        let mut w = FdtWriter::new();
        let root = w.begin_node("").unwrap();
        w.property_u32("a", 1).unwrap();
        let before = (w.structure.clone(), w.strings.clone());
        assert!(w.property_u32("a", 1).is_err());
        assert!(w.property_u32("bad name", 1).is_err());
        assert!(w.property_string("nul", "\0").is_err());
        assert!(w.begin_node("bad/name").is_err());
        assert_eq!((w.structure.clone(), w.strings.clone()), before);
        w.end_node(root).unwrap();
        w.finish().unwrap();
    }

    #[test]
    fn mem_reserve_errors() {
        let mut w = FdtWriter::new();
        assert_eq!(
            w.add_mem_reserve(0x1000, 0),
            Err(Error::InvalidMemReserve {
                addr: 0x1000,
                size: 0
            })
        );
        assert_eq!(
            w.add_mem_reserve(u64::MAX, 2),
            Err(Error::InvalidMemReserve {
                addr: u64::MAX,
                size: 2
            })
        );
        w.add_mem_reserve(u64::MAX, 1).unwrap();
    }
}
