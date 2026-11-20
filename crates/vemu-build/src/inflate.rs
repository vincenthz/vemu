//! gzip (RFC 1952) and DEFLATE (RFC 1951) decompression, for the Alpine
//! minirootfs tarball.
//!
//! Stored, fixed-Huffman and dynamic-Huffman blocks. Every member's CRC-32
//! and ISIZE are checked; concatenated members are decoded in turn, and
//! anything after the last member is an error. The output is bounded by
//! the caller's `max_out` (the whole output, all members together), so a
//! small "decompression bomb" input cannot exhaust memory: decoding stops
//! with [`Error::TooLarge`] as soon as the output would pass the bound.

use std::fmt;

/// Why decompression failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not a gzip stream, or an unsupported gzip feature.
    Header(&'static str),
    /// The stream ended early.
    Truncated,
    /// Invalid DEFLATE data.
    Corrupt(&'static str),
    /// CRC-32 of the output differs from the trailer's.
    Crc { expected: u32, actual: u32 },
    /// Output length differs from the trailer's ISIZE.
    Size { expected: u32, actual: u32 },
    /// The output would exceed the caller's bound.
    TooLarge { limit: usize },
    /// Bytes after the last gzip member.
    TrailingData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Header(m) => write!(f, "not a usable gzip stream: {m}"),
            Error::Truncated => write!(f, "the compressed data ends early (truncated download?)"),
            Error::Corrupt(m) => write!(f, "corrupt compressed data: {m}"),
            Error::Crc { expected, actual } => write!(
                f,
                "CRC-32 mismatch: the trailer says {expected:08x}, the data gives {actual:08x}"
            ),
            Error::Size { expected, actual } => write!(
                f,
                "size mismatch: the trailer says {expected} bytes (mod 2^32), the data has {actual}"
            ),
            Error::TooLarge { limit } => {
                write!(f, "decompressed data is larger than the {limit}-byte limit")
            }
            Error::TrailingData => write!(f, "unexpected data after the gzip stream"),
        }
    }
}

impl std::error::Error for Error {}

// ------------------------------------------------------------------ CRC-32

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC_TABLE: [u32; 256] = crc_table();

/// Running CRC-32 (IEEE 802.3, as in gzip and zlib): start from 0.
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

// ------------------------------------------------------------------- gzip

const FTEXT: u8 = 1;
const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// Decompress a gzip stream (one or more members) of at most `max_out`
/// bytes of output in total.
pub fn gunzip(data: &[u8], max_out: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        pos += member(&data[pos..], &mut out, max_out)?;
        if pos == data.len() {
            return Ok(out);
        }
        if data[pos..].len() < 2 || data[pos..pos + 2] != [0x1f, 0x8b] {
            return Err(Error::TrailingData);
        }
    }
}

/// One gzip member appended to `out`, which must stay within `max_out`
/// bytes (earlier members included); returns the bytes consumed.
fn member(data: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<usize, Error> {
    let byte = |i: usize| data.get(i).copied().ok_or(Error::Truncated);
    if data.len() < 2 || data[..2] != [0x1f, 0x8b] {
        return Err(Error::Header("no gzip magic (1f 8b)"));
    }
    if byte(2)? != 8 {
        return Err(Error::Header("compression method is not deflate"));
    }
    let flags = byte(3)?;
    if flags & !(FTEXT | FHCRC | FEXTRA | FNAME | FCOMMENT) != 0 {
        return Err(Error::Header("reserved flag bits are set"));
    }
    let mut pos = 10; // magic, CM, FLG, MTIME (4), XFL, OS
    if data.len() < pos {
        return Err(Error::Truncated);
    }
    if flags & FEXTRA != 0 {
        let xlen = usize::from(u16::from_le_bytes([byte(pos)?, byte(pos + 1)?]));
        pos += 2 + xlen;
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            let nul = data
                .get(pos..)
                .and_then(|d| d.iter().position(|&b| b == 0))
                .ok_or(Error::Truncated)?;
            pos += nul + 1;
        }
    }
    if flags & FHCRC != 0 {
        let want = u16::from_le_bytes([byte(pos)?, byte(pos + 1)?]);
        if crc32(&data[..pos]) as u16 != want {
            return Err(Error::Header("header CRC mismatch"));
        }
        pos += 2;
    }
    if pos > data.len() {
        return Err(Error::Truncated);
    }
    let start = out.len();
    let used = inflate_into(&data[pos..], out, max_out)?;
    pos += used;
    let trailer = data.get(pos..pos + 8).ok_or(Error::Truncated)?;
    let expected = u32::from_le_bytes(trailer[..4].try_into().expect("4 bytes"));
    let actual = crc32(&out[start..]);
    if expected != actual {
        return Err(Error::Crc { expected, actual });
    }
    let expected = u32::from_le_bytes(trailer[4..].try_into().expect("4 bytes"));
    let actual = (out.len() - start) as u32;
    if expected != actual {
        return Err(Error::Size { expected, actual });
    }
    Ok(pos + 8)
}

// ---------------------------------------------------------------- DEFLATE

/// Decompress a raw DEFLATE stream of at most `max_out` bytes of output.
/// Returns the output and the number of input bytes the stream used.
pub fn inflate(data: &[u8], max_out: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut out = Vec::new();
    let used = inflate_into(data, &mut out, max_out)?;
    Ok((out, used))
}

/// LSB-first bit reader. Bits past the end of the input read as zero, but
/// consuming them is [`Error::Truncated`].
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            data,
            pos: 0,
            buf: 0,
            count: 0,
        }
    }

    fn refill(&mut self) {
        while self.count <= 56 && self.pos < self.data.len() {
            self.buf |= u64::from(self.data[self.pos]) << self.count;
            self.pos += 1;
            self.count += 8;
        }
    }

    /// The next `n` (<= 32) bits without consuming them.
    fn peek(&mut self, n: u32) -> u32 {
        if self.count < n {
            self.refill();
        }
        (self.buf & ((1u64 << n) - 1)) as u32
    }

    fn consume(&mut self, n: u32) -> Result<(), Error> {
        if n > self.count {
            return Err(Error::Truncated);
        }
        self.buf >>= n;
        self.count -= n;
        Ok(())
    }

    fn bits(&mut self, n: u32) -> Result<u32, Error> {
        let v = self.peek(n);
        self.consume(n)?;
        Ok(v)
    }

    /// Drop the bits up to the next byte boundary.
    fn align(&mut self) {
        let drop = self.count % 8;
        self.buf >>= drop;
        self.count -= drop;
    }

    /// Input bytes used so far (whole bytes still in the buffer are not).
    fn used(&self) -> usize {
        self.pos - (self.count / 8) as usize
    }

    /// Copy `n` whole bytes (after [`Bits::align`]) to `out`.
    fn copy_bytes(&mut self, mut n: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        while n > 0 && self.count >= 8 {
            out.push(self.buf as u8);
            self.buf >>= 8;
            self.count -= 8;
            n -= 1;
        }
        let rest = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or(Error::Truncated)?;
        out.extend_from_slice(rest);
        self.pos += n;
        Ok(())
    }
}

/// A canonical Huffman code as a direct lookup table on the next
/// `max_len` input bits: entry = symbol << 4 | code length (0 = no code).
struct Huffman {
    table: Vec<u16>,
    max_len: u32,
}

const MAX_BITS: usize = 15;

impl Huffman {
    /// Build from per-symbol code lengths (0 = unused). Over-subscribed
    /// codes are refused; incomplete ones are allowed (as zlib does for a
    /// single distance code), and decoding an unassigned bit pattern fails.
    fn new(lengths: &[u8]) -> Result<Huffman, Error> {
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lengths {
            count[usize::from(l)] += 1;
        }
        count[0] = 0;
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - i32::from(c);
            if left < 0 {
                return Err(Error::Corrupt("over-subscribed Huffman code"));
            }
        }
        let max_len = (1..=MAX_BITS).rev().find(|&l| count[l] != 0).unwrap_or(1) as u32;
        // First canonical code of each length.
        let mut next = [0u32; MAX_BITS + 2];
        let mut code = 0u32;
        for len in 1..=MAX_BITS {
            code = (code + u32::from(count[len - 1])) << 1;
            next[len] = code;
        }
        let mut table = vec![0u16; 1 << max_len];
        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len = u32::from(len);
            let code = next[len as usize];
            next[len as usize] += 1;
            // Huffman codes are sent MSB first into an LSB-first stream.
            let rev = code.reverse_bits() >> (32 - len);
            let entry = ((sym as u16) << 4) | len as u16;
            let mut i = rev as usize;
            while i < table.len() {
                table[i] = entry;
                i += 1 << len;
            }
        }
        Ok(Huffman { table, max_len })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, Error> {
        let e = self.table[bits.peek(self.max_len) as usize];
        let len = u32::from(e & 15);
        if len == 0 {
            // Either a code that does not exist, or the input ran out.
            return Err(
                if bits.count < self.max_len && bits.pos == bits.data.len() {
                    Error::Truncated
                } else {
                    Error::Corrupt("invalid Huffman code")
                },
            );
        }
        bits.consume(len)?;
        Ok(e >> 4)
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Order of the code length code lengths in a dynamic block header.
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn fixed_codes() -> (Huffman, Huffman) {
    let mut lit = [0u8; 288];
    lit[..144].fill(8);
    lit[144..256].fill(9);
    lit[256..280].fill(7);
    lit[280..].fill(8);
    (
        Huffman::new(&lit).expect("fixed literal code"),
        Huffman::new(&[5u8; 30]).expect("fixed distance code"),
    )
}

fn dynamic_codes(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), Error> {
    let hlit = bits.bits(5)? as usize + 257;
    let hdist = bits.bits(5)? as usize + 1;
    let hclen = bits.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(Error::Corrupt("too many length or distance codes"));
    }
    let mut clen = [0u8; 19];
    for &i in &CLEN_ORDER[..hclen] {
        clen[i] = bits.bits(3)? as u8;
    }
    let clcode = Huffman::new(&clen)?;
    let mut lengths = [0u8; 286 + 30];
    let total = hlit + hdist;
    let mut n = 0;
    while n < total {
        let sym = clcode.decode(bits)?;
        let (value, repeat) = match sym {
            0..=15 => (sym as u8, 1),
            16 => {
                if n == 0 {
                    return Err(Error::Corrupt("repeat with no previous code length"));
                }
                (lengths[n - 1], 3 + bits.bits(2)? as usize)
            }
            17 => (0, 3 + bits.bits(3)? as usize),
            18 => (0, 11 + bits.bits(7)? as usize),
            _ => return Err(Error::Corrupt("invalid code length code")),
        };
        if n + repeat > total {
            return Err(Error::Corrupt("code lengths overflow the code count"));
        }
        lengths[n..n + repeat].fill(value);
        n += repeat;
    }
    if lengths[256] == 0 {
        return Err(Error::Corrupt("no end-of-block code"));
    }
    Ok((
        Huffman::new(&lengths[..hlit])?,
        Huffman::new(&lengths[hlit..total])?,
    ))
}

/// Append a DEFLATE stream's output to `out`. `max_out` bounds the whole
/// of `out` (what it already holds included), so that a multi-member gzip
/// stream shares one bound.
fn inflate_into(data: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<usize, Error> {
    // Back-references stay within this stream's own output.
    let start = out.len();
    let room = |out: &Vec<u8>, n: usize| {
        if out.len().saturating_add(n) > max_out {
            Err(Error::TooLarge { limit: max_out })
        } else {
            Ok(())
        }
    };
    let mut bits = Bits::new(data);
    let mut fixed = None;
    loop {
        let last = bits.bits(1)? == 1;
        match bits.bits(2)? {
            0 => {
                bits.align();
                let len = bits.bits(16)?;
                let nlen = bits.bits(16)?;
                if len != !nlen & 0xffff {
                    return Err(Error::Corrupt("stored block length check failed"));
                }
                room(out, len as usize)?;
                bits.copy_bytes(len as usize, out)?;
            }
            kind @ (1 | 2) => {
                let dynamic;
                let (lit, dist) = if kind == 1 {
                    let f = fixed.get_or_insert_with(fixed_codes);
                    (&f.0, &f.1)
                } else {
                    dynamic = dynamic_codes(&mut bits)?;
                    (&dynamic.0, &dynamic.1)
                };
                loop {
                    let sym = lit.decode(&mut bits)?;
                    if sym < 256 {
                        room(out, 1)?;
                        out.push(sym as u8);
                        continue;
                    }
                    if sym == 256 {
                        break;
                    }
                    let i = usize::from(sym - 257);
                    if i >= LEN_BASE.len() {
                        return Err(Error::Corrupt("invalid length symbol"));
                    }
                    let len =
                        usize::from(LEN_BASE[i]) + bits.bits(u32::from(LEN_EXTRA[i]))? as usize;
                    let d = usize::from(dist.decode(&mut bits)?);
                    if d >= DIST_BASE.len() {
                        return Err(Error::Corrupt("invalid distance symbol"));
                    }
                    let distance =
                        usize::from(DIST_BASE[d]) + bits.bits(u32::from(DIST_EXTRA[d]))? as usize;
                    if distance > out.len() - start {
                        return Err(Error::Corrupt("distance reaches before the start"));
                    }
                    room(out, len)?;
                    let from = out.len() - distance;
                    if distance >= len {
                        out.extend_from_within(from..from + len);
                    } else {
                        for k in 0..len {
                            out.push(out[from + k]);
                        }
                    }
                }
            }
            _ => return Err(Error::Corrupt("invalid block type 3")),
        }
        if last {
            return Ok(bits.used());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// gzip framing around a raw DEFLATE stream.
    fn wrap(deflate: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        g.extend_from_slice(deflate);
        g.extend_from_slice(&crc32(plain).to_le_bytes());
        g.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        g
    }

    /// LSB-first bit writer for hand-made test streams.
    #[derive(Default)]
    struct BitWriter {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl BitWriter {
        fn put(&mut self, v: u32, n: u32) {
            self.acc |= u64::from(v) << self.n;
            self.n += n;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }
        /// A Huffman code (MSB first).
        fn code(&mut self, code: u32, len: u32) {
            self.put(code.reverse_bits() >> (32 - len), len);
        }
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.acc as u8);
            }
            self.out
        }
        /// Fixed-code literal/length symbol.
        fn fixed_sym(&mut self, sym: u32) {
            match sym {
                0..=143 => self.code(0x30 + sym, 8),
                144..=255 => self.code(0x190 + sym - 144, 9),
                256..=279 => self.code(sym - 256, 7),
                _ => self.code(0xc0 + sym - 280, 8),
            }
        }
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32_update(crc32(b"1234"), b"56789"), 0xCBF4_3926);
    }

    #[test]
    fn stored_block() {
        let raw = [0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(inflate(&raw, 100).unwrap(), (b"hello".to_vec(), raw.len()));
        // Empty stored block, then trailing bytes not part of the stream.
        assert_eq!(
            inflate(&[0x01, 0, 0, 0xff, 0xff, 0xaa], 100).unwrap(),
            (vec![], 5)
        );
        // LEN/NLEN mismatch.
        assert!(matches!(
            inflate(&[0x01, 0x05, 0x00, 0xfb, 0xff, 1, 2, 3, 4, 5], 100),
            Err(Error::Corrupt(_))
        ));
        // Data missing.
        assert_eq!(
            inflate(&[0x01, 0x05, 0x00, 0xfa, 0xff, b'h'], 100),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn fixed_block_vectors() {
        // zlib.compress(b"a") without the zlib header/trailer.
        assert_eq!(inflate(&unhex("4b0400"), 10).unwrap().0, b"a");
        // zlib's raw deflate of b"hello hello hello hello" (fixed, with a match).
        let v = unhex("cb48cdc9c957c8402701");
        assert_eq!(inflate(&v, 100).unwrap().0, b"hello hello hello hello");
    }

    /// The words test text: 400 Greek letter names, every 7th of the 24.
    fn greek() -> Vec<u8> {
        let words = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi \
                     omicron pi rho sigma tau upsilon phi chi psi omega";
        let words: Vec<&str> = words.split_whitespace().collect();
        let t: Vec<&str> = (0..400).map(|i| words[(i * 7) % words.len()]).collect();
        t.join(" ").into_bytes()
    }

    #[test]
    fn dynamic_block_vector() {
        // Python: zlib.compressobj(9, zlib.DEFLATED, 31) of greek(): a
        // gzip member holding one dynamic-Huffman block.
        let gz = unhex(
            "1f8b0800000000000213edcdd10d80200c04d0556eb553093452691412e3f496c421fce80f29\
             edb58fd50ad14bea445359cf76602d82649754af75a07360997369fe98c0477866e318185f2e\
             5395d869469ca5f9ad948919ba7dc10f6ea9faa752978db8247b9a61871d76d861871df65fec\
             173e9a361713080000",
        );
        assert_eq!((gz[10] >> 1) & 3, 2, "a dynamic block");
        let want = greek();
        assert_eq!(want.len(), 2067);
        assert_eq!(gunzip(&gz, 1 << 20).unwrap(), want);
        // Every truncation fails cleanly, never panics or succeeds.
        for n in 0..gz.len() {
            assert!(gunzip(&gz[..n], 1 << 20).is_err(), "prefix {n}");
        }
        // Single-bit flips are caught (by the decoder or the CRC).
        // (Not the last DEFLATE byte: its padding bits are unused.)
        for i in 10..gz.len() - 9 {
            for bit in [0, 3, 7] {
                let mut b = gz.clone();
                b[i] ^= 1 << bit;
                assert!(gunzip(&b, 1 << 20).is_err(), "flip byte {i} bit {bit}");
            }
        }
    }

    #[test]
    fn hand_made_matches_and_overlap() {
        // "ab" then a length-6 copy at distance 2 (overlapping): "abababab".
        let mut w = BitWriter::default();
        w.put(1, 1); // BFINAL
        w.put(1, 2); // fixed
        w.fixed_sym(u32::from(b'a'));
        w.fixed_sym(u32::from(b'b'));
        w.fixed_sym(260); // length 6
        w.code(1, 5); // distance code 1 = distance 2
        w.fixed_sym(256);
        let raw = w.finish();
        assert_eq!(inflate(&raw, 100).unwrap().0, b"abababab");
        let gz = wrap(&raw, b"abababab");
        assert_eq!(gunzip(&gz, 100).unwrap(), b"abababab");
    }

    /// A tiny input expanding to 258 * n bytes: refused past the bound.
    #[test]
    fn bomb_is_bounded() {
        let copies = 40_000u32; // ~10 MiB of output from ~ 60 KiB input
        let mut w = BitWriter::default();
        w.put(1, 1);
        w.put(1, 2);
        w.fixed_sym(0);
        for _ in 0..copies {
            w.fixed_sym(285); // length 258
            w.code(0, 5); // distance 1
        }
        w.fixed_sym(256);
        let raw = w.finish();
        assert!(raw.len() < 64 << 10);
        let n = 1 + 258 * copies as usize;
        assert_eq!(inflate(&raw, n).unwrap().0.len(), n);
        assert_eq!(
            inflate(&raw, 1 << 20),
            Err(Error::TooLarge { limit: 1 << 20 })
        );
        let gz = wrap(&raw, &vec![0u8; n]);
        assert_eq!(
            gunzip(&gz, 1 << 20),
            Err(Error::TooLarge { limit: 1 << 20 })
        );
        assert_eq!(gunzip(&gz, n).unwrap().len(), n);
    }

    #[test]
    fn corrupt_streams() {
        // Block type 3.
        assert!(matches!(inflate(&[0x07], 10), Err(Error::Corrupt(_))));
        // A distance before the start of the output.
        let mut w = BitWriter::default();
        w.put(1, 1);
        w.put(1, 2);
        w.fixed_sym(u32::from(b'a'));
        w.fixed_sym(257);
        w.code(1, 5); // distance 2 > 1 byte of output
        w.fixed_sym(256);
        assert!(matches!(inflate(&w.finish(), 10), Err(Error::Corrupt(_))));
        // Fixed distance symbols 30 and 31 are invalid.
        let mut w = BitWriter::default();
        w.put(1, 1);
        w.put(1, 2);
        w.fixed_sym(u32::from(b'a'));
        w.fixed_sym(257);
        w.code(30, 5);
        assert!(matches!(inflate(&w.finish(), 10), Err(Error::Corrupt(_))));
        // A dynamic header whose code-length code is over-subscribed.
        let mut w = BitWriter::default();
        w.put(1, 1);
        w.put(2, 2);
        w.put(0, 5);
        w.put(0, 5);
        w.put(15, 4); // 19 code length codes
        for _ in 0..19 {
            w.put(1, 3); // 19 codes of length 1
        }
        assert!(matches!(inflate(&w.finish(), 10), Err(Error::Corrupt(_))));
        // Truncated in the middle of a block.
        let v = unhex("cb48cdc9c957c8402701");
        assert_eq!(inflate(&v[..4], 100), Err(Error::Truncated));
        assert_eq!(inflate(&[], 100), Err(Error::Truncated));
    }

    #[test]
    fn gzip_framing_errors() {
        let good = wrap(&unhex("4b0400"), b"a");
        assert_eq!(gunzip(&good, 10).unwrap(), b"a");
        let mut bad_crc = good.clone();
        let n = bad_crc.len();
        bad_crc[n - 8] ^= 1;
        assert!(matches!(gunzip(&bad_crc, 10), Err(Error::Crc { .. })));
        let mut bad_size = good.clone();
        bad_size[n - 4] = 2;
        assert!(matches!(gunzip(&bad_size, 10), Err(Error::Size { .. })));
        assert_eq!(gunzip(&good[..n - 3], 10), Err(Error::Truncated));
        assert!(matches!(gunzip(b"PK\x03\x04", 10), Err(Error::Header(_))));
        let mut reserved = good.clone();
        reserved[3] = 0x20;
        assert!(matches!(gunzip(&reserved, 10), Err(Error::Header(_))));
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(gunzip(&trailing, 10), Err(Error::TrailingData));
        // Two members concatenated (like `cat a.gz b.gz`).
        let mut two = good.clone();
        two.extend_from_slice(&wrap(
            &unhex("cb48cdc9c957c8402701"),
            b"hello hello hello hello",
        ));
        assert_eq!(gunzip(&two, 100).unwrap(), b"ahello hello hello hello");
        // The bound covers all members together.
        assert!(matches!(gunzip(&two, 10), Err(Error::TooLarge { .. })));
        assert!(matches!(gunzip(&two, 23), Err(Error::TooLarge { .. })));
        assert_eq!(gunzip(&two, 24).unwrap().len(), 24);
    }

    /// Many members, each within the bound, whose sum is not: refused (a
    /// bomb made of concatenated members must not escape the bound).
    #[test]
    fn gzip_bound_is_global_across_members() {
        let plain = vec![0x5au8; 1 << 10];
        let mut stored = vec![1u8]; // BFINAL, BTYPE 00
        stored.extend_from_slice(&(1u16 << 10).to_le_bytes());
        stored.extend_from_slice(&(!(1u16 << 10)).to_le_bytes());
        stored.extend_from_slice(&plain);
        let one = wrap(&stored, &plain);
        assert_eq!(gunzip(&one, 1 << 10).unwrap(), plain);
        let eight: Vec<u8> = (0..8).flat_map(|_| one.clone()).collect();
        assert_eq!(
            gunzip(&eight, 4 << 10),
            Err(Error::TooLarge { limit: 4 << 10 })
        );
        assert_eq!(
            gunzip(&eight, (8 << 10) - 1),
            Err(Error::TooLarge {
                limit: (8 << 10) - 1
            })
        );
        assert_eq!(gunzip(&eight, 8 << 10).unwrap().len(), 8 << 10);
    }

    #[test]
    fn gzip_optional_header_fields() {
        // FEXTRA + FNAME + FCOMMENT + FHCRC.
        let mut g = vec![
            0x1f,
            0x8b,
            8,
            FEXTRA | FNAME | FCOMMENT | FHCRC,
            0,
            0,
            0,
            0,
            0,
            3,
        ];
        g.extend_from_slice(&[3, 0, b'x', b'y', b'z']);
        g.extend_from_slice(b"name.txt\0a comment\0");
        let hcrc = crc32(&g) as u16;
        g.extend_from_slice(&hcrc.to_le_bytes());
        g.extend_from_slice(&unhex("4b0400"));
        g.extend_from_slice(&crc32(b"a").to_le_bytes());
        g.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(gunzip(&g, 10).unwrap(), b"a");
        let mut bad = g.clone();
        bad[30] ^= 0xff; // inside the header CRC
        assert!(matches!(gunzip(&bad, 10), Err(Error::Header(_))));
    }

    /// Round trip through the system gzip at several levels, if installed.
    #[test]
    fn system_gzip_round_trip() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut data = Vec::new();
        let mut x = 12345u32;
        for i in 0..300_000u32 {
            // Text-like with repeats, plus some noise.
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            data.push(if i % 7 == 0 {
                (x >> 24) as u8
            } else {
                b"abcdefgh \n"[(i % 10) as usize]
            });
        }
        for level in ["-1", "-6", "-9"] {
            let child = Command::new("gzip")
                .args([level, "-c", "-n"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn();
            let Ok(mut child) = child else {
                eprintln!("skipping: no gzip");
                return;
            };
            let mut stdin = child.stdin.take().unwrap();
            let input = data.clone();
            let writer = std::thread::spawn(move || stdin.write_all(&input));
            let out = child.wait_with_output().unwrap();
            writer.join().unwrap().unwrap();
            assert!(out.status.success());
            assert_eq!(
                gunzip(&out.stdout, data.len()).unwrap(),
                data,
                "gzip {level}"
            );
            assert!(matches!(
                gunzip(&out.stdout, data.len() - 1),
                Err(Error::TooLarge { .. })
            ));
        }
    }
}
