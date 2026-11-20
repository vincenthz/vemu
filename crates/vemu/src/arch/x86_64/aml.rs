//! A small ACPI Machine Language (AML) encoder: just what the DSDT needs
//! (ACPI 6.5, chapter 20 "ACPI Machine Language (AML) Specification" and
//! section 6.4 "Resource Data Types for ACPI").
//!
//! Every function returns the encoded bytes of one term; compound terms
//! (`Scope`, `Device`, `Package`, `Buffer`) take their already-encoded
//! contents and add the opcode and the `PkgLength`. Names are given in ASL
//! notation (`"\\_SB_.VR00"`, `"_HID"`) and checked: invalid names are
//! programming errors and panic.

#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const NAME_OP: u8 = 0x08;
const BYTE_PREFIX: u8 = 0x0a;
const WORD_PREFIX: u8 = 0x0b;
const DWORD_PREFIX: u8 = 0x0c;
const STRING_PREFIX: u8 = 0x0d;
const QWORD_PREFIX: u8 = 0x0e;
const SCOPE_OP: u8 = 0x10;
const BUFFER_OP: u8 = 0x11;
const PACKAGE_OP: u8 = 0x12;
const DUAL_NAME_PREFIX: u8 = 0x2e;
const MULTI_NAME_PREFIX: u8 = 0x2f;
const EXT_OP_PREFIX: u8 = 0x5b;
const DEVICE_OP: u8 = 0x82; // after EXT_OP_PREFIX
const ROOT_CHAR: u8 = b'\\';
const PARENT_PREFIX_CHAR: u8 = b'^';
const NULL_NAME: u8 = 0x00;

/// Large resource descriptor: 32-bit fixed memory range.
const MEMORY32_FIXED: u8 = 0x86;
/// Large resource descriptor: extended interrupt.
const EXTENDED_INTERRUPT: u8 = 0x89;
/// Small resource descriptor: I/O port (type 0x08, 7 bytes).
const IO_PORT: u8 = 0x47;
/// Small resource descriptor: end tag (type 0x0f, 1 byte).
const END_TAG: u8 = 0x79;

/// Largest value a `PkgLength` can encode (28 bits).
const PKG_LENGTH_MAX: usize = (1 << 28) - 1;

/// One 4-character `NameSeg`: a leading `A-Z` or `_`, then `A-Z`, `0-9` or
/// `_`, padded with `_` to four characters (ASL's `_SB` is `_SB_`).
pub fn name_seg(seg: &str) -> [u8; 4] {
    let b = seg.as_bytes();
    assert!(
        (1..=4).contains(&b.len()),
        "AML NameSeg {seg:?} must have 1 to 4 characters"
    );
    assert!(
        b[0].is_ascii_uppercase() || b[0] == b'_',
        "AML NameSeg {seg:?} must start with A-Z or _"
    );
    assert!(
        b.iter()
            .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_'),
        "AML NameSeg {seg:?} may only contain A-Z, 0-9 and _"
    );
    let mut out = [b'_'; 4];
    out[..b.len()].copy_from_slice(b);
    out
}

/// A `NameString`: optional root (`\`) or parent (`^`) prefixes, then
/// dot-separated segments.
pub fn name_string(path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = path;
    if let Some(r) = rest.strip_prefix('\\') {
        out.push(ROOT_CHAR);
        rest = r;
    } else {
        while let Some(r) = rest.strip_prefix('^') {
            out.push(PARENT_PREFIX_CHAR);
            rest = r;
        }
    }
    let segs: Vec<[u8; 4]> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split('.').map(name_seg).collect()
    };
    match segs.len() {
        0 => out.push(NULL_NAME),
        1 => {}
        2 => out.push(DUAL_NAME_PREFIX),
        n => {
            assert!(n <= 255, "AML name {path:?} has too many segments");
            out.push(MULTI_NAME_PREFIX);
            out.push(n as u8);
        }
    }
    for s in segs {
        out.extend_from_slice(&s);
    }
    out
}

/// An integer constant in its shortest encoding (`Zero`, `One`, or a
/// byte/word/dword/qword constant).
pub fn integer(v: u64) -> Vec<u8> {
    match v {
        0 => vec![ZERO_OP],
        1 => vec![ONE_OP],
        2..=0xff => vec![BYTE_PREFIX, v as u8],
        0x100..=0xffff => {
            let mut out = vec![WORD_PREFIX];
            out.extend_from_slice(&(v as u16).to_le_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![DWORD_PREFIX];
            out.extend_from_slice(&(v as u32).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![QWORD_PREFIX];
            out.extend_from_slice(&v.to_le_bytes());
            out
        }
    }
}

/// A string constant (ASCII, no NUL inside).
pub fn string(s: &str) -> Vec<u8> {
    assert!(
        s.bytes().all(|c| (1..=0x7f).contains(&c)),
        "AML string {s:?} must be ASCII without NUL"
    );
    let mut out = vec![STRING_PREFIX];
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    out
}

/// An EISA ID (`EisaId ("PNP0501")`): three upper-case letters and four
/// hex digits, compressed into a DWord.
pub fn eisa_id(id: &str) -> Vec<u8> {
    integer(u64::from(eisa_id_value(id)))
}

/// The 32-bit value of an EISA ID, as `EisaId()` computes it: the bytes,
/// in memory order, are the 15-bit compressed vendor (big-endian) then the
/// 16-bit product number (big-endian).
pub fn eisa_id_value(id: &str) -> u32 {
    let b = id.as_bytes();
    assert!(
        b.len() == 7
            && b[..3].iter().all(u8::is_ascii_uppercase)
            && b[3..].iter().all(u8::is_ascii_hexdigit),
        "bad EISA ID {id:?}"
    );
    let vendor = b[..3]
        .iter()
        .fold(0u16, |acc, &c| (acc << 5) | u16::from(c - 0x40));
    let product = u16::from_str_radix(&id[3..], 16).expect("hex digits");
    let v = vendor.to_be_bytes();
    let p = product.to_be_bytes();
    u32::from_le_bytes([v[0], v[1], p[0], p[1]])
}

/// The `PkgLength` of a package whose contents (after the `PkgLength`
/// itself) are `len` bytes. The encoded length counts its own bytes.
pub fn pkg_length(len: usize) -> Vec<u8> {
    // 1 byte: 6 bits of length; n bytes: 4 + 8 * (n - 1) bits.
    let (n, total) = if len < 0x3f {
        (1, len + 1)
    } else if len + 2 <= 0xfff {
        (2, len + 2)
    } else if len + 3 <= 0xf_ffff {
        (3, len + 3)
    } else {
        (4, len + 4)
    };
    assert!(
        total <= PKG_LENGTH_MAX,
        "AML package of {len} bytes too large"
    );
    if n == 1 {
        return vec![total as u8];
    }
    let mut out = vec![(((n - 1) as u8) << 6) | (total & 0xf) as u8];
    for i in 1..n {
        out.push((total >> (4 + 8 * (i - 1))) as u8);
    }
    out
}

/// `opcode PkgLength body`.
fn with_pkg_length(opcode: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = opcode.to_vec();
    out.extend(pkg_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// `Name (path, value)`; `value` is an encoded data object.
pub fn name(path: &str, value: &[u8]) -> Vec<u8> {
    let mut out = vec![NAME_OP];
    out.extend(name_string(path));
    out.extend_from_slice(value);
    out
}

/// `Package () { elements }` (at most 255 elements).
pub fn package(elements: &[Vec<u8>]) -> Vec<u8> {
    assert!(elements.len() <= 255, "AML Package with too many elements");
    let mut body = vec![elements.len() as u8];
    for e in elements {
        body.extend_from_slice(e);
    }
    with_pkg_length(&[PACKAGE_OP], &body)
}

/// `Buffer () { bytes }`.
pub fn buffer(bytes: &[u8]) -> Vec<u8> {
    let mut body = integer(bytes.len() as u64);
    body.extend_from_slice(bytes);
    with_pkg_length(&[BUFFER_OP], &body)
}

/// `Scope (path) { terms }`.
pub fn scope(path: &str, terms: &[Vec<u8>]) -> Vec<u8> {
    let mut body = name_string(path);
    body.extend(terms.concat());
    with_pkg_length(&[SCOPE_OP], &body)
}

/// `Device (path) { terms }`.
pub fn device(path: &str, terms: &[Vec<u8>]) -> Vec<u8> {
    let mut body = name_string(path);
    body.extend(terms.concat());
    with_pkg_length(&[EXT_OP_PREFIX, DEVICE_OP], &body)
}

/// `ResourceTemplate () { descriptors }`: a buffer of the resource
/// descriptors followed by an end tag whose checksum byte is 0 ("the
/// checksum is ignored", which is what iasl emits).
pub fn resource_template(descriptors: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = descriptors.concat();
    bytes.extend_from_slice(&[END_TAG, 0]);
    buffer(&bytes)
}

/// `Memory32Fixed (ReadWrite | ReadOnly, base, length)`.
pub fn memory32_fixed(read_write: bool, base: u32, length: u32) -> Vec<u8> {
    let mut out = vec![MEMORY32_FIXED];
    out.extend_from_slice(&9u16.to_le_bytes());
    out.push(u8::from(read_write));
    out.extend_from_slice(&base.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out
}

/// Interrupt trigger mode of an [`interrupt`] descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Level,
    Edge,
}

/// Interrupt polarity of an [`interrupt`] descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}

/// `Interrupt (ResourceConsumer, trigger, polarity, Exclusive | Shared)
/// { irq }`: an extended interrupt descriptor with one interrupt (a GSI on
/// x86) and no resource source.
pub fn interrupt(trigger: Trigger, polarity: Polarity, shared: bool, irq: u32) -> Vec<u8> {
    // Flags: bit 0 consumer, bit 1 edge, bit 2 active low, bit 3 shared.
    let flags = 0x01
        | (u8::from(trigger == Trigger::Edge) << 1)
        | (u8::from(polarity == Polarity::ActiveLow) << 2)
        | (u8::from(shared) << 3);
    let mut out = vec![EXTENDED_INTERRUPT];
    out.extend_from_slice(&6u16.to_le_bytes());
    out.push(flags);
    out.push(1); // interrupt table length
    out.extend_from_slice(&irq.to_le_bytes());
    out
}

/// `IO (Decode16, min, max, alignment, length)`.
pub fn io(min: u16, max: u16, alignment: u8, length: u8) -> Vec<u8> {
    let mut out = vec![IO_PORT, 0x01];
    out.extend_from_slice(&min.to_le_bytes());
    out.extend_from_slice(&max.to_le_bytes());
    out.push(alignment);
    out.push(length);
    out
}

/// A minimal AML decoder for the subset [this module](self) encodes, used by
/// the tests to check the encoder's output structurally (and to decode
/// whole DSDTs in other modules' tests).
#[cfg(test)]
pub mod decode {
    /// A decoded term or data object.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Term {
        Integer(u64),
        String(String),
        Buffer(Vec<u8>),
        Package(Vec<Term>),
        Name(String, Box<Term>),
        Scope(String, Vec<Term>),
        Device(String, Vec<Term>),
    }

    impl Term {
        /// The value of `Name (name, ...)` among `terms`.
        pub fn find_name<'a>(terms: &'a [Term], name: &str) -> Option<&'a Term> {
            terms.iter().find_map(|t| match t {
                Term::Name(n, v) if n == name => Some(&**v),
                _ => None,
            })
        }
    }

    pub struct Decoder<'a> {
        b: &'a [u8],
        pos: usize,
    }

    /// Decode a complete term list (a DSDT body).
    pub fn decode(bytes: &[u8]) -> Result<Vec<Term>, String> {
        let mut d = Decoder { b: bytes, pos: 0 };
        d.term_list(bytes.len())
    }

    impl Decoder<'_> {
        fn byte(&mut self) -> Result<u8, String> {
            let v = *self
                .b
                .get(self.pos)
                .ok_or_else(|| format!("truncated at {}", self.pos))?;
            self.pos += 1;
            Ok(v)
        }

        fn take(&mut self, n: usize) -> Result<&[u8], String> {
            let end = self.pos.checked_add(n).filter(|&e| e <= self.b.len());
            let end = end.ok_or_else(|| format!("truncated at {}", self.pos))?;
            let s = &self.b[self.pos..end];
            self.pos = end;
            Ok(s)
        }

        fn le(&mut self, n: usize) -> Result<u64, String> {
            Ok(self
                .take(n)?
                .iter()
                .rev()
                .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
        }

        /// A `PkgLength`; returns the end position of the package.
        fn pkg_end(&mut self) -> Result<usize, String> {
            let start = self.pos;
            let lead = self.byte()?;
            let n = usize::from(lead >> 6);
            let len = if n == 0 {
                usize::from(lead & 0x3f)
            } else {
                if lead & 0x30 != 0 {
                    return Err(format!("PkgLength at {start}: bits 5:4 not zero"));
                }
                let mut len = usize::from(lead & 0xf);
                for i in 0..n {
                    len |= usize::from(self.byte()?) << (4 + 8 * i);
                }
                // The encoding must be the shortest (as the encoder makes it).
                len
            };
            let end = start + len;
            if end > self.b.len() || end < self.pos {
                return Err(format!("PkgLength at {start}: bad length {len}"));
            }
            Ok(end)
        }

        fn name_string(&mut self) -> Result<String, String> {
            let mut s = String::new();
            let mut c = self.byte()?;
            if c == b'\\' {
                s.push('\\');
                c = self.byte()?;
            } else {
                while c == b'^' {
                    s.push('^');
                    c = self.byte()?;
                }
            }
            let count = match c {
                0x00 => 0,
                0x2e => 2,
                0x2f => usize::from(self.byte()?),
                _ => {
                    self.pos -= 1;
                    1
                }
            };
            for i in 0..count {
                let seg = self.take(4)?;
                if !(seg[0].is_ascii_uppercase() || seg[0] == b'_')
                    || !seg
                        .iter()
                        .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                {
                    return Err(format!("bad NameSeg {seg:?}"));
                }
                if i > 0 {
                    s.push('.');
                }
                s.push_str(std::str::from_utf8(seg).expect("ASCII"));
            }
            Ok(s)
        }

        fn data_object(&mut self) -> Result<Term, String> {
            let at = self.pos;
            Ok(match self.byte()? {
                0x00 => Term::Integer(0),
                0x01 => Term::Integer(1),
                0xff => Term::Integer(u64::MAX),
                0x0a => Term::Integer(self.le(1)?),
                0x0b => Term::Integer(self.le(2)?),
                0x0c => Term::Integer(self.le(4)?),
                0x0e => Term::Integer(self.le(8)?),
                0x0d => {
                    let rest = &self.b[self.pos..];
                    let n = rest
                        .iter()
                        .position(|&c| c == 0)
                        .ok_or("unterminated string")?;
                    let s = String::from_utf8(rest[..n].to_vec()).map_err(|e| e.to_string())?;
                    self.pos += n + 1;
                    Term::String(s)
                }
                0x11 => {
                    let end = self.pkg_end()?;
                    let Term::Integer(size) = self.data_object()? else {
                        return Err(format!("buffer at {at}: size is not an integer"));
                    };
                    let bytes = self.take(end - self.pos)?.to_vec();
                    if bytes.len() as u64 != size {
                        return Err(format!(
                            "buffer at {at}: size {size} but {} bytes",
                            bytes.len()
                        ));
                    }
                    Term::Buffer(bytes)
                }
                0x12 => {
                    let end = self.pkg_end()?;
                    let count = usize::from(self.byte()?);
                    let mut elems = Vec::new();
                    while self.pos < end {
                        elems.push(self.data_object()?);
                    }
                    if self.pos != end || elems.len() != count {
                        return Err(format!("package at {at}: bad element count"));
                    }
                    Term::Package(elems)
                }
                op => return Err(format!("unknown data object opcode {op:#x} at {at}")),
            })
        }

        fn term(&mut self) -> Result<Term, String> {
            let at = self.pos;
            match self.byte()? {
                0x08 => {
                    let n = self.name_string()?;
                    let v = self.data_object()?;
                    Ok(Term::Name(n, Box::new(v)))
                }
                0x10 => {
                    let end = self.pkg_end()?;
                    let n = self.name_string()?;
                    Ok(Term::Scope(n, self.term_list(end)?))
                }
                0x5b if self.b.get(self.pos) == Some(&0x82) => {
                    self.pos += 1;
                    let end = self.pkg_end()?;
                    let n = self.name_string()?;
                    Ok(Term::Device(n, self.term_list(end)?))
                }
                op => Err(format!("unknown term opcode {op:#x} at {at}")),
            }
        }

        fn term_list(&mut self, end: usize) -> Result<Vec<Term>, String> {
            let mut terms = Vec::new();
            while self.pos < end {
                terms.push(self.term()?);
            }
            if self.pos != end {
                return Err(format!("term list overruns its package end {end}"));
            }
            Ok(terms)
        }
    }

    /// A decoded resource descriptor.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Resource {
        Memory32Fixed {
            read_write: bool,
            base: u32,
            length: u32,
        },
        Interrupt {
            flags: u8,
            irqs: Vec<u32>,
        },
        Io {
            decode16: bool,
            min: u16,
            max: u16,
            alignment: u8,
            length: u8,
        },
    }

    /// Decode a resource template buffer (up to and including its end tag,
    /// which must be last).
    pub fn resources(b: &[u8]) -> Result<Vec<Resource>, String> {
        let mut out = Vec::new();
        let mut i = 0;
        loop {
            let tag = *b.get(i).ok_or("no end tag")?;
            if tag & 0x80 == 0 {
                let len = usize::from(tag & 7);
                let body = b.get(i + 1..i + 1 + len).ok_or("truncated descriptor")?;
                match tag >> 3 {
                    0x0f => {
                        if i + 1 + len != b.len() {
                            return Err("data after the end tag".into());
                        }
                        let sum = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
                        if body[0] != 0 && sum != 0 {
                            return Err("bad resource template checksum".into());
                        }
                        return Ok(out);
                    }
                    0x08 if len == 7 => out.push(Resource::Io {
                        decode16: body[0] & 1 != 0,
                        min: u16::from_le_bytes([body[1], body[2]]),
                        max: u16::from_le_bytes([body[3], body[4]]),
                        alignment: body[5],
                        length: body[6],
                    }),
                    t => return Err(format!("unknown small descriptor {t:#x}")),
                }
                i += 1 + len;
            } else {
                let len = usize::from(u16::from_le_bytes([
                    *b.get(i + 1).ok_or("truncated")?,
                    *b.get(i + 2).ok_or("truncated")?,
                ]));
                let body = b.get(i + 3..i + 3 + len).ok_or("truncated descriptor")?;
                let u32_at = |o: usize| u32::from_le_bytes(body[o..o + 4].try_into().unwrap());
                match tag {
                    0x86 if len == 9 => out.push(Resource::Memory32Fixed {
                        read_write: body[0] & 1 != 0,
                        base: u32_at(1),
                        length: u32_at(5),
                    }),
                    0x89 if len >= 6 => {
                        let n = usize::from(body[1]);
                        if len < 2 + 4 * n {
                            return Err("short interrupt descriptor".into());
                        }
                        out.push(Resource::Interrupt {
                            flags: body[0],
                            irqs: (0..n).map(|k| u32_at(2 + 4 * k)).collect(),
                        });
                    }
                    t => return Err(format!("unknown large descriptor {t:#x}")),
                }
                i += 3 + len;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode::{Resource, Term, decode, resources};
    use super::*;

    #[test]
    fn names() {
        assert_eq!(name_seg("_SB"), *b"_SB_");
        assert_eq!(name_seg("VR0A"), *b"VR0A");
        assert_eq!(name_string("_HID"), b"_HID");
        assert_eq!(name_string("\\_S5"), b"\\_S5_");
        assert_eq!(name_string("\\_SB.VR00"), b"\\\x2e_SB_VR00");
        assert_eq!(name_string("^^FOO"), b"^^FOO_");
        assert_eq!(name_string("\\"), b"\\\x00");
        assert_eq!(name_string("A.B.C"), b"\x2f\x03A___B___C___");
    }

    #[test]
    #[should_panic(expected = "must start with A-Z or _")]
    fn name_seg_cannot_start_with_a_digit() {
        name_seg("0ABC");
    }

    #[test]
    #[should_panic(expected = "1 to 4 characters")]
    fn name_seg_length() {
        name_seg("ABCDE");
    }

    #[test]
    fn integers() {
        assert_eq!(integer(0), [0x00]);
        assert_eq!(integer(1), [0x01]);
        assert_eq!(integer(5), [0x0a, 5]);
        assert_eq!(integer(0xff), [0x0a, 0xff]);
        assert_eq!(integer(0x100), [0x0b, 0x00, 0x01]);
        assert_eq!(integer(0xd000_0000), [0x0c, 0, 0, 0, 0xd0]);
        assert_eq!(integer(0x1_0000_0000), [0x0e, 0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn strings_and_eisa_ids() {
        assert_eq!(string("LNRO0005"), b"\x0dLNRO0005\x00");
        // Well-known compressed IDs: PNP0501 (16550 UART), PNP0303 (PS/2
        // keyboard), PNP0A03 (PCI host bridge).
        assert_eq!(eisa_id_value("PNP0501"), 0x0105_d041);
        assert_eq!(eisa_id_value("PNP0303"), 0x0303_d041);
        assert_eq!(eisa_id_value("PNP0A03"), 0x030a_d041);
        assert_eq!(eisa_id("PNP0501"), [0x0c, 0x41, 0xd0, 0x05, 0x01]);
    }

    #[test]
    fn pkg_lengths() {
        // One byte up to 63 in total (the byte itself included).
        assert_eq!(pkg_length(0), [0x01]);
        assert_eq!(pkg_length(62), [0x3f]);
        // Two bytes: 4 low bits in the lead byte, 8 more in the next.
        assert_eq!(pkg_length(63), [0x41, 0x04]); // 65 = 0x41
        assert_eq!(pkg_length(0xffd), [0x4f, 0xff]); // 0xfff
        // Three and four bytes.
        assert_eq!(pkg_length(0xffe), [0x81, 0x00, 0x01]); // 0x1001
        assert_eq!(pkg_length(0x10_0000), [0xc4, 0x00, 0x00, 0x01]); // 0x100004
        // Round trip through the decoder for every boundary.
        for len in [
            0, 1, 61, 62, 63, 64, 300, 0xffc, 0xffd, 0xffe, 0xfffff, 0x10_0000,
        ] {
            let enc = buffer(&vec![0xaa; len]);
            let mut d = decode::decode(&name("X", &enc)).unwrap();
            let Some(Term::Name(_, v)) = d.pop() else {
                panic!()
            };
            assert_eq!(*v, Term::Buffer(vec![0xaa; len]), "len {len}");
        }
    }

    #[test]
    fn s5_package_matches_iasl() {
        // iasl: Name (_S5, Package (0x04) { 0x05, Zero, Zero, Zero })
        let s5 = name(
            "\\_S5",
            &package(&[integer(5), integer(0), integer(0), integer(0)]),
        );
        assert_eq!(
            s5,
            [
                0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x07, 0x04, 0x0a, 0x05, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn resource_descriptors_match_iasl() {
        // Memory32Fixed (ReadWrite, 0xD0000000, 0x00000200)
        assert_eq!(
            memory32_fixed(true, 0xd000_0000, 0x200),
            [
                0x86, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x02, 0x00, 0x00
            ]
        );
        // Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 5 }
        assert_eq!(
            interrupt(Trigger::Level, Polarity::ActiveHigh, false, 5),
            [0x89, 0x06, 0x00, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00]
        );
        // Interrupt (ResourceConsumer, Edge, ActiveLow, Shared) { 4 }
        assert_eq!(
            interrupt(Trigger::Edge, Polarity::ActiveLow, true, 4)[3],
            0x01 | 0x02 | 0x04 | 0x08
        );
        // IO (Decode16, 0x03F8, 0x03F8, 0x01, 0x08)
        assert_eq!(
            io(0x3f8, 0x3f8, 1, 8),
            [0x47, 0x01, 0xf8, 0x03, 0xf8, 0x03, 0x01, 0x08]
        );
        // ResourceTemplate () {} is the end tag alone, checksum 0.
        assert_eq!(resource_template(&[]), [0x11, 0x05, 0x0a, 0x02, 0x79, 0x00]);
    }

    #[test]
    fn virtio_device_byte_exact() {
        // Device (VR00) { Name (_HID, "LNRO0005") Name (_UID, Zero)
        //   Name (_CRS, ResourceTemplate () {
        //     Memory32Fixed (ReadWrite, 0xD0000000, 0x200)
        //     Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 5 } }) }
        let dev = device(
            "VR00",
            &[
                name("_HID", &string("LNRO0005")),
                name("_UID", &integer(0)),
                name(
                    "_CRS",
                    &resource_template(&[
                        memory32_fixed(true, 0xd000_0000, 0x200),
                        interrupt(Trigger::Level, Polarity::ActiveHigh, false, 5),
                    ]),
                ),
            ],
        );
        let mut expect = vec![0x5b, 0x82, 0x3a]; // 0x3a = 58 bytes incl. itself
        expect.extend_from_slice(b"VR00");
        expect.extend_from_slice(b"\x08_HID\x0dLNRO0005\x00");
        expect.extend_from_slice(b"\x08_UID\x00");
        expect.extend_from_slice(b"\x08_CRS\x11\x1a\x0a\x17");
        expect.extend_from_slice(&[0x86, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0xd0]);
        expect.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
        expect.extend_from_slice(&[0x89, 0x06, 0x00, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00]);
        expect.extend_from_slice(&[0x79, 0x00]);
        assert_eq!(dev, expect);
        assert_eq!(dev.len(), 2 + 0x3a);
    }

    #[test]
    fn round_trip_through_the_decoder() {
        let crs = resource_template(&[
            memory32_fixed(true, 0xd000_0200, 0x200),
            interrupt(Trigger::Level, Polarity::ActiveHigh, false, 6),
            io(0x3f8, 0x3f8, 1, 8),
        ]);
        let aml = [
            name(
                "\\_S5",
                &package(&[integer(5), integer(0), integer(0), integer(0)]),
            ),
            scope(
                "\\_SB",
                &[device(
                    "VR01",
                    &[
                        name("_HID", &string("LNRO0005")),
                        name("_UID", &integer(1)),
                        name("_CRS", &crs),
                        name("BIG_", &integer(0x1234_5678_9abc)),
                        name("EISA", &eisa_id("PNP0501")),
                    ],
                )],
            ),
        ]
        .concat();
        let terms = decode(&aml).unwrap();
        assert_eq!(terms.len(), 2);
        assert_eq!(
            terms[0],
            Term::Name(
                "\\_S5_".into(),
                Box::new(Term::Package(vec![
                    Term::Integer(5),
                    Term::Integer(0),
                    Term::Integer(0),
                    Term::Integer(0)
                ]))
            )
        );
        let Term::Scope(sb, body) = &terms[1] else {
            panic!("{:?}", terms[1])
        };
        assert_eq!(sb, "\\_SB_");
        let Term::Device(dn, dev) = &body[0] else {
            panic!()
        };
        assert_eq!(dn, "VR01");
        assert_eq!(
            Term::find_name(dev, "_HID"),
            Some(&Term::String("LNRO0005".into()))
        );
        assert_eq!(Term::find_name(dev, "_UID"), Some(&Term::Integer(1)));
        assert_eq!(
            Term::find_name(dev, "BIG_"),
            Some(&Term::Integer(0x1234_5678_9abc))
        );
        assert_eq!(
            Term::find_name(dev, "EISA"),
            Some(&Term::Integer(0x0105_d041))
        );
        let Some(Term::Buffer(b)) = Term::find_name(dev, "_CRS") else {
            panic!()
        };
        assert_eq!(
            resources(b).unwrap(),
            vec![
                Resource::Memory32Fixed {
                    read_write: true,
                    base: 0xd000_0200,
                    length: 0x200
                },
                Resource::Interrupt {
                    flags: 0x01,
                    irqs: vec![6]
                },
                Resource::Io {
                    decode16: true,
                    min: 0x3f8,
                    max: 0x3f8,
                    alignment: 1,
                    length: 8
                },
            ]
        );
    }

    #[test]
    fn large_scope_uses_a_multi_byte_pkg_length() {
        let devs: Vec<Vec<u8>> = (0..16)
            .map(|i| device(&format!("VR{i:02X}"), &[name("_UID", &integer(i))]))
            .collect();
        let s = scope("\\_SB", &devs);
        assert_eq!(s[1] >> 6, 1, "two-byte PkgLength");
        let terms = decode(&s).unwrap();
        let Term::Scope(_, body) = &terms[0] else {
            panic!()
        };
        assert_eq!(body.len(), 16);
        assert_eq!(
            body[15],
            Term::Device(
                "VR0F".into(),
                vec![Term::Name("_UID".into(), Box::new(Term::Integer(15)))]
            )
        );
    }
}
