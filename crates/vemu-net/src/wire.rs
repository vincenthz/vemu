//! Wire formats: Ethernet II, ARP, IPv4, ICMP, UDP and TCP.
//!
//! Parsers borrow the input and validate lengths and checksums; anything
//! malformed yields `None` so callers can drop it quietly. Builders append to a
//! `Vec<u8>` and always produce correct checksums.

use std::net::Ipv4Addr;

pub const ETH_HDR_LEN: usize = 14;
pub const IPV4_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;
pub const TCP_HDR_LEN: usize = 20;
pub const ICMP_HDR_LEN: usize = 8;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const MAC_BROADCAST: [u8; 6] = [0xff; 6];

/// TTL of every IPv4 packet we originate.
pub const DEFAULT_TTL: u8 = 64;

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
}

/// Codes for ICMP destination unreachable.
pub mod unreach_code {
    pub const NET: u8 = 0;
    pub const HOST: u8 = 1;
    pub const PORT: u8 = 3;
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

fn mac_at(b: &[u8], at: usize) -> [u8; 6] {
    b[at..at + 6].try_into().expect("6-byte slice")
}

// ---------------------------------------------------------------------------
// Internet checksum (RFC 1071)
// ---------------------------------------------------------------------------

/// One's-complement sum of `data` as big-endian 16-bit words, added to `acc`
/// (not folded).
pub fn sum16(data: &[u8], mut acc: u64) -> u64 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u64::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        acc += u64::from(*last) << 8;
    }
    acc
}

/// Fold a 64-bit accumulator and complement it into a checksum field value.
pub fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Checksum of `data` alone (IPv4 header, ICMP).
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum16(data, 0))
}

/// Sum of the TCP/UDP pseudo header.
pub fn pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u64 {
    let mut acc = sum16(&src.octets(), 0);
    acc = sum16(&dst.octets(), acc);
    acc + u64::from(proto) + len as u64
}

// ---------------------------------------------------------------------------
// Ethernet
// ---------------------------------------------------------------------------

/// A parsed Ethernet II frame (no 802.1Q tags: tagged frames are dropped).
#[derive(Debug, Clone, Copy)]
pub struct EthFrame<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthFrame<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Self> {
        if b.len() < ETH_HDR_LEN {
            return None;
        }
        Some(EthFrame {
            dst: mac_at(b, 0),
            src: mac_at(b, 6),
            ethertype: be16(b, 12),
            payload: &b[ETH_HDR_LEN..],
        })
    }
}

fn push_eth(f: &mut Vec<u8>, dst: [u8; 6], src: [u8; 6], ethertype: u16) {
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
}

// ---------------------------------------------------------------------------
// ARP (Ethernet/IPv4 only)
// ---------------------------------------------------------------------------

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;
const ARP_LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < ARP_LEN
            || be16(b, 0) != 1 // hardware: Ethernet
            || be16(b, 2) != ETHERTYPE_IPV4
            || b[4] != 6
            || b[5] != 4
        {
            return None;
        }
        Some(ArpPacket {
            op: be16(b, 6),
            sender_mac: mac_at(b, 8),
            sender_ip: ip_at(b, 14),
            target_mac: mac_at(b, 18),
            target_ip: ip_at(b, 24),
        })
    }

    /// The whole Ethernet frame carrying this ARP packet.
    pub fn frame(&self, eth_dst: [u8; 6]) -> Vec<u8> {
        let mut f = Vec::with_capacity(ETH_HDR_LEN + ARP_LEN);
        push_eth(&mut f, eth_dst, self.sender_mac, ETHERTYPE_ARP);
        f.extend_from_slice(&1u16.to_be_bytes());
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.extend_from_slice(&[6, 4]);
        f.extend_from_slice(&self.op.to_be_bytes());
        f.extend_from_slice(&self.sender_mac);
        f.extend_from_slice(&self.sender_ip.octets());
        f.extend_from_slice(&self.target_mac);
        f.extend_from_slice(&self.target_ip.octets());
        f
    }
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/// A parsed, checksum-verified IPv4 packet. `payload` is trimmed to the
/// header's total length (Ethernet padding removed).
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub ttl: u8,
    /// More-fragments flag set or non-zero fragment offset.
    pub is_fragment: bool,
    /// Header including options.
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Self> {
        if b.len() < IPV4_HDR_LEN || b[0] >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(b[0] & 0x0f) * 4;
        let total = usize::from(be16(b, 2));
        if ihl < IPV4_HDR_LEN || total < ihl || total > b.len() {
            return None;
        }
        if checksum(&b[..ihl]) != 0 {
            return None;
        }
        let frag = be16(b, 6);
        Some(Ipv4Packet {
            src: ip_at(b, 12),
            dst: ip_at(b, 16),
            proto: b[9],
            ttl: b[8],
            is_fragment: frag & 0x2000 != 0 || frag & 0x1fff != 0,
            header: &b[..ihl],
            payload: &b[ihl..total],
        })
    }

    /// Header plus the first 8 payload bytes: what ICMP errors quote.
    pub fn icmp_quote(&self) -> Vec<u8> {
        let mut q = self.header.to_vec();
        q.extend_from_slice(&self.payload[..self.payload.len().min(8)]);
        q
    }
}

/// Addressing of an IPv4 packet we originate.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Out {
    pub eth_dst: [u8; 6],
    pub eth_src: [u8; 6],
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub id: u16,
}

/// Build Ethernet + IPv4 (DF set, TTL 64, no options) around the L4 bytes
/// appended by `l4`. The L4 closure leaves its checksum field zero; this
/// computes it (TCP and UDP with the pseudo header, ICMP without).
pub fn ipv4_frame(out: &Ipv4Out, capacity: usize, l4: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETH_HDR_LEN + IPV4_HDR_LEN + capacity);
    push_eth(&mut f, out.eth_dst, out.eth_src, ETHERTYPE_IPV4);
    let ip = f.len();
    f.extend_from_slice(&[0; IPV4_HDR_LEN]);
    let l4_start = f.len();
    l4(&mut f);
    let l4_len = f.len() - l4_start;
    let total = (IPV4_HDR_LEN + l4_len) as u16;

    let h = &mut f[ip..l4_start];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&out.id.to_be_bytes());
    h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    h[8] = DEFAULT_TTL;
    h[9] = out.proto;
    h[12..16].copy_from_slice(&out.src.octets());
    h[16..20].copy_from_slice(&out.dst.octets());
    let c = checksum(h);
    h[10..12].copy_from_slice(&c.to_be_bytes());

    let csum_at = match out.proto {
        PROTO_TCP => Some((16, true)),
        PROTO_UDP => Some((6, true)),
        PROTO_ICMP => Some((2, false)),
        _ => None,
    };
    if let Some((at, pseudo)) = csum_at {
        let acc = if pseudo {
            pseudo_header_sum(out.src, out.dst, out.proto, l4_len)
        } else {
            0
        };
        let mut c = fold(sum16(&f[l4_start..], acc));
        if out.proto == PROTO_UDP && c == 0 {
            c = 0xffff; // 0 means "no checksum" for UDP
        }
        f[l4_start + at..l4_start + at + 2].copy_from_slice(&c.to_be_bytes());
    }
    f
}

/// Split the IPv4 packet in Ethernet frame `frame` into fragments whose IP
/// packets are at most `mtu` bytes (RFC 791): each gets a copy of the header
/// with DF cleared, the fragment offset and MF set, and its own header
/// checksum. The L4 checksum, computed over the whole datagram, is left as
/// is; the receiver checks it after reassembly. A packet that already fits is
/// returned unchanged as the only element.
pub fn fragment(frame: Vec<u8>, mtu: usize) -> Vec<Vec<u8>> {
    let ip = &frame[ETH_HDR_LEN..];
    if ip.len() <= mtu {
        return vec![frame];
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    let payload = &ip[ihl..];
    // Every fragment but the last carries a multiple of 8 payload bytes.
    let chunk = (mtu - ihl) & !7;
    assert!(chunk > 0, "MTU {mtu} too small to fragment");
    payload
        .chunks(chunk)
        .enumerate()
        .map(|(i, part)| {
            let off = i * chunk;
            let last = off + part.len() == payload.len();
            let mut f = Vec::with_capacity(ETH_HDR_LEN + ihl + part.len());
            f.extend_from_slice(&frame[..ETH_HDR_LEN + ihl]);
            let h = &mut f[ETH_HDR_LEN..];
            h[2..4].copy_from_slice(&((ihl + part.len()) as u16).to_be_bytes());
            let flags = if last { 0 } else { 0x2000 }; // MF; DF clear
            h[6..8].copy_from_slice(&(flags | (off / 8) as u16).to_be_bytes());
            h[10..12].fill(0);
            let c = checksum(&h[..ihl]);
            h[10..12].copy_from_slice(&c.to_be_bytes());
            f.extend_from_slice(part);
            f
        })
        .collect()
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Parse and verify (checksum 0 = none, accepted).
    pub fn parse(ip: &Ipv4Packet<'a>) -> Option<Self> {
        let b = ip.payload;
        if b.len() < UDP_HDR_LEN {
            return None;
        }
        let len = usize::from(be16(b, 4));
        if len < UDP_HDR_LEN || len > b.len() {
            return None;
        }
        let b = &b[..len];
        if be16(b, 6) != 0 && fold(sum16(b, pseudo_header_sum(ip.src, ip.dst, PROTO_UDP, len))) != 0
        {
            return None;
        }
        Some(UdpDatagram {
            sport: be16(b, 0),
            dport: be16(b, 2),
            payload: &b[UDP_HDR_LEN..],
        })
    }
}

/// Append a UDP header (checksum left zero for [`ipv4_frame`]) and payload.
pub fn write_udp(f: &mut Vec<u8>, sport: u16, dport: u16, payload: &[u8]) {
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&((UDP_HDR_LEN + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct IcmpMessage<'a> {
    pub ty: u8,
    pub code: u8,
    /// Bytes 4..8 of the header (echo: identifier and sequence number).
    pub rest: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> IcmpMessage<'a> {
    /// Parse a whole ICMP message, verifying its checksum.
    pub fn parse(b: &'a [u8]) -> Option<Self> {
        if b.len() < ICMP_HDR_LEN || checksum(b) != 0 {
            return None;
        }
        Some(IcmpMessage {
            ty: b[0],
            code: b[1],
            rest: b[4..8].try_into().expect("4 bytes"),
            payload: &b[ICMP_HDR_LEN..],
        })
    }

    pub fn echo_id(&self) -> u16 {
        u16::from_be_bytes([self.rest[0], self.rest[1]])
    }

    /// Echo sequence number (bytes 6..8).
    pub fn echo_seq(&self) -> u16 {
        u16::from_be_bytes([self.rest[2], self.rest[3]])
    }
}

/// Append an ICMP message (checksum left zero for [`ipv4_frame`]).
pub fn write_icmp(f: &mut Vec<u8>, ty: u8, code: u8, rest: [u8; 4], payload: &[u8]) {
    f.extend_from_slice(&[ty, code, 0, 0]);
    f.extend_from_slice(&rest);
    f.extend_from_slice(payload);
}

/// A standalone ICMP message with a valid checksum (for host sockets).
pub fn icmp_message(ty: u8, code: u8, rest: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ICMP_HDR_LEN + payload.len());
    write_icmp(&mut m, ty, code, rest, payload);
    let c = checksum(&m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    m
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// A parsed, checksum-verified TCP segment.
#[derive(Debug, Clone, Copy)]
pub struct TcpSegment<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// MSS option (only meaningful on SYN).
    pub mss: Option<u16>,
    /// Window-scale shift option (only meaningful on SYN).
    pub wscale: Option<u8>,
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn parse(ip: &Ipv4Packet<'a>) -> Option<Self> {
        let b = ip.payload;
        if b.len() < TCP_HDR_LEN {
            return None;
        }
        let off = usize::from(b[12] >> 4) * 4;
        if off < TCP_HDR_LEN || off > b.len() {
            return None;
        }
        if fold(sum16(
            b,
            pseudo_header_sum(ip.src, ip.dst, PROTO_TCP, b.len()),
        )) != 0
        {
            return None;
        }
        let (mut mss, mut wscale) = (None, None);
        let mut opts = &b[TCP_HDR_LEN..off];
        while let [kind, rest @ ..] = opts {
            match *kind {
                0 => break,
                1 => opts = rest,
                _ => {
                    let Some(&len) = rest.first() else { break };
                    let len = usize::from(len);
                    if len < 2 || len > opts.len() {
                        break;
                    }
                    match (*kind, len) {
                        (2, 4) => mss = Some(be16(opts, 2)),
                        (3, 3) => wscale = Some(opts[2].min(14)),
                        _ => {}
                    }
                    opts = &opts[len..];
                }
            }
        }
        Some(TcpSegment {
            sport: be16(b, 0),
            dport: be16(b, 2),
            seq: be32(b, 4),
            ack: be32(b, 8),
            flags: b[13],
            window: be16(b, 14),
            mss,
            wscale,
            payload: &b[off..],
        })
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Sequence space occupied: payload plus one each for SYN and FIN.
    pub fn seq_len(&self) -> u32 {
        self.payload.len() as u32
            + u32::from(self.has(tcp_flags::SYN))
            + u32::from(self.has(tcp_flags::FIN))
    }
}

/// Header fields of a TCP segment we originate.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpHeader {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
}

/// Append a TCP header (checksum left zero for [`ipv4_frame`]) followed by
/// the concatenation of `payload` parts.
pub fn write_tcp(f: &mut Vec<u8>, h: &TcpHeader, payload: [&[u8]; 2]) {
    let mut opts = Vec::<u8>::new();
    if let Some(mss) = h.mss {
        opts.extend_from_slice(&[2, 4]);
        opts.extend_from_slice(&mss.to_be_bytes());
    }
    if let Some(ws) = h.wscale {
        opts.extend_from_slice(&[1, 3, 3, ws]); // NOP + window scale
    }
    let off = TCP_HDR_LEN + opts.len();
    f.extend_from_slice(&h.sport.to_be_bytes());
    f.extend_from_slice(&h.dport.to_be_bytes());
    f.extend_from_slice(&h.seq.to_be_bytes());
    f.extend_from_slice(&h.ack.to_be_bytes());
    f.push(((off / 4) as u8) << 4);
    f.push(h.flags);
    f.extend_from_slice(&h.window.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
    f.extend_from_slice(&opts);
    for p in payload {
        f.extend_from_slice(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        // RFC 1071 section 3 example: words 0001 f203 f4f5 f6f7 sum to ddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2);
        // Odd length pads with a zero byte.
        assert_eq!(checksum(&[0x12]), !0x1200);
    }

    #[test]
    fn ipv4_roundtrip_and_bad_checksum() {
        let out = Ipv4Out {
            eth_dst: [1; 6],
            eth_src: [2; 6],
            src: Ipv4Addr::new(10, 0, 2, 2),
            dst: Ipv4Addr::new(10, 0, 2, 15),
            proto: PROTO_UDP,
            id: 7,
        };
        let mut f = ipv4_frame(&out, 16, |f| write_udp(f, 53, 1000, b"hello"));
        f.extend_from_slice(&[0; 6]); // Ethernet padding must be ignored
        let eth = EthFrame::parse(&f).unwrap();
        let ip = Ipv4Packet::parse(eth.payload).unwrap();
        assert_eq!(
            (ip.src, ip.dst, ip.ttl, ip.is_fragment),
            (out.src, out.dst, 64, false)
        );
        let udp = UdpDatagram::parse(&ip).unwrap();
        assert_eq!(
            (udp.sport, udp.dport, udp.payload),
            (53, 1000, &b"hello"[..])
        );

        let mut bad = f.clone();
        bad[ETH_HDR_LEN + 8] ^= 1; // TTL flipped: header checksum fails
        assert!(Ipv4Packet::parse(&bad[ETH_HDR_LEN..]).is_none());
        let mut bad = f.clone();
        let n = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;
        bad[n] ^= 1; // payload flipped: UDP checksum fails
        let ip = Ipv4Packet::parse(&bad[ETH_HDR_LEN..]).unwrap();
        assert!(UdpDatagram::parse(&ip).is_none());
    }

    /// Reassemble fragments (in any order) the way a receiver would.
    fn reassemble(frags: &[Vec<u8>]) -> Vec<u8> {
        let mut parts: Vec<(usize, bool, Vec<u8>, Vec<u8>)> = frags
            .iter()
            .map(|f| {
                let ip = &f[ETH_HDR_LEN..];
                assert_eq!(checksum(&ip[..IPV4_HDR_LEN]), 0, "fragment header checksum");
                let total = usize::from(be16(ip, 2));
                assert_eq!(total, ip.len());
                let fl = be16(ip, 6);
                assert_eq!(fl & 0x4000, 0, "DF cleared on fragments");
                (
                    usize::from(fl & 0x1fff) * 8,
                    fl & 0x2000 != 0,
                    ip[..IPV4_HDR_LEN].to_vec(),
                    ip[IPV4_HDR_LEN..].to_vec(),
                )
            })
            .collect();
        parts.sort_by_key(|p| p.0);
        let mut payload = Vec::new();
        for (i, (off, mf, _, data)) in parts.iter().enumerate() {
            assert_eq!(*off, payload.len(), "contiguous fragments");
            assert_eq!(*mf, i + 1 < parts.len(), "MF on all but the last");
            payload.extend_from_slice(data);
        }
        // Rebuild an unfragmented packet from the first header.
        let mut ip = parts[0].2.clone();
        ip[2..4].copy_from_slice(&((IPV4_HDR_LEN + payload.len()) as u16).to_be_bytes());
        ip[6..8].fill(0);
        ip[10..12].fill(0);
        let c = checksum(&ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        ip.extend_from_slice(&payload);
        ip
    }

    fn udp_out() -> Ipv4Out {
        Ipv4Out {
            eth_dst: [1; 6],
            eth_src: [2; 6],
            src: Ipv4Addr::new(10, 0, 2, 2),
            dst: Ipv4Addr::new(10, 0, 2, 15),
            proto: PROTO_UDP,
            id: 0x1234,
        }
    }

    #[test]
    fn fragment_small_packet_is_untouched() {
        let f = ipv4_frame(&udp_out(), 16, |f| write_udp(f, 1, 2, &[7; 1472]));
        assert_eq!(fragment(f.clone(), 1500), vec![f]);
    }

    #[test]
    fn fragment_and_reassemble() {
        for len in [1473, 2000, 2952, 2953, 4000, 65507] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + i / 251) as u8).collect();
            let f = ipv4_frame(&udp_out(), len + 8, |f| write_udp(f, 53, 4000, &data));
            let frags = fragment(f, 1500);
            assert_eq!(frags.len(), (len + 8).div_ceil(1480), "{len}");
            for fr in &frags {
                assert!(fr.len() - ETH_HDR_LEN <= 1500);
                assert_eq!(fr[..ETH_HDR_LEN], frags[0][..ETH_HDR_LEN]);
                assert_eq!(be16(&fr[ETH_HDR_LEN..], 4), 0x1234, "same IP id");
            }
            // Out of order on purpose.
            let mut shuffled = frags.clone();
            shuffled.reverse();
            let ip = reassemble(&shuffled);
            let p = Ipv4Packet::parse(&ip).expect("reassembled header");
            assert!(!p.is_fragment);
            let u = UdpDatagram::parse(&p).expect("UDP checksum over the whole datagram");
            assert_eq!((u.sport, u.dport, u.payload), (53, 4000, &data[..]));
        }
    }

    #[test]
    fn tcp_options_roundtrip() {
        let out = Ipv4Out {
            eth_dst: [1; 6],
            eth_src: [2; 6],
            src: Ipv4Addr::new(1, 2, 3, 4),
            dst: Ipv4Addr::new(5, 6, 7, 8),
            proto: PROTO_TCP,
            id: 1,
        };
        let h = TcpHeader {
            sport: 1,
            dport: 2,
            seq: 3,
            ack: 4,
            flags: tcp_flags::SYN | tcp_flags::ACK,
            window: 5,
            mss: Some(1460),
            wscale: Some(7),
        };
        let f = ipv4_frame(&out, 64, |f| write_tcp(f, &h, [b"ab", b"c"]));
        let ip = Ipv4Packet::parse(&f[ETH_HDR_LEN..]).unwrap();
        let t = TcpSegment::parse(&ip).unwrap();
        assert_eq!((t.sport, t.dport, t.seq, t.ack, t.window), (1, 2, 3, 4, 5));
        assert_eq!(
            (t.mss, t.wscale, t.payload),
            (Some(1460), Some(7), &b"abc"[..])
        );
        assert_eq!(t.seq_len(), 4);
    }
}
