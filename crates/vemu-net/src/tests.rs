//! Sans-IO tests: synthetic guest frames through [`Stack`], with every frame
//! the stack emits checked by an independent checksum verifier.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use crate::config::UserNetConfig;
use crate::stack::{
    FlowId, HostError, HostOp, Limits, MAX_TCP_CONNS, MAX_TCP_FWD_CONNS, ROUTER_MAC, Stack,
};
use crate::tcp::{MSS, Phase, RESET_LINGER};
use crate::wire::{tcp_flags::*, *};

const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const GW: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const DNS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
const UPSTREAM: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 53), 53);
const REMOTE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 80);

/// Checksum verification written independently of `wire`: plain RFC 1071
/// summation over a concatenated buffer.
mod check {
    fn sum(parts: &[&[u8]]) -> u16 {
        let mut bytes: Vec<u8> = parts.concat();
        if bytes.len() % 2 == 1 {
            bytes.push(0);
        }
        let mut s: u32 = 0;
        for w in bytes.chunks(2) {
            s += (u32::from(w[0]) << 8) | u32::from(w[1]);
            s = (s & 0xffff) + (s >> 16);
        }
        s as u16
    }

    /// Panics unless every checksum in the Ethernet frame is right (and the
    /// IPv4 header is what we promise: DF unless a fragment, TTL 64, no
    /// padding, at most the 1500-byte MTU). Fragments have their L4
    /// checksum checked after [`super::reassemble`].
    pub fn frame(f: &[u8]) {
        assert!(f.len() >= 14);
        assert_eq!(f[6..12], super::ROUTER_MAC, "source MAC");
        if f[12..14] != [0x08, 0x00] {
            return;
        }
        let ip = &f[14..];
        let ihl = usize::from(ip[0] & 15) * 4;
        assert_eq!(ip[0] >> 4, 4);
        assert_eq!(sum(&[&ip[..ihl]]), 0xffff, "IPv4 header checksum");
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        assert_eq!(total, ip.len(), "IPv4 total length");
        assert_eq!(ip[8], 64, "TTL");
        let frag = u16::from_be_bytes([ip[6], ip[7]]);
        if frag & 0x3fff != 0 {
            assert_eq!(frag & 0x4000, 0, "DF clear on a fragment");
            assert!(total <= 1500, "fragment within the MTU");
            return;
        }
        assert_eq!(ip[6] & 0x40, 0x40, "DF set");
        let l4 = &ip[ihl..total];
        let pseudo = |proto: u8| {
            let mut p = ip[12..20].to_vec();
            p.extend_from_slice(&[0, proto]);
            p.extend_from_slice(&(l4.len() as u16).to_be_bytes());
            p
        };
        match ip[9] {
            1 => assert_eq!(sum(&[l4]), 0xffff, "ICMP checksum"),
            6 => assert_eq!(sum(&[&pseudo(6), l4]), 0xffff, "TCP checksum"),
            17 => {
                assert_ne!(l4[6..8], [0, 0], "UDP checksum present");
                assert_eq!(sum(&[&pseudo(17), l4]), 0xffff, "UDP checksum");
            }
            p => panic!("unexpected protocol {p}"),
        }
    }
}

struct H {
    s: Stack,
    now: Instant,
}

impl H {
    fn new() -> H {
        let mut s = Stack::new(&UserNetConfig::default(), 42);
        s.set_dns_upstream(Some(UPSTREAM));
        H {
            s,
            now: Instant::now(),
        }
    }

    fn input(&mut self, f: Vec<u8>) {
        self.s.handle_frame(&f, self.now);
        self.s.flush(self.now);
    }

    fn frames(&mut self) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| self.s.pop_frame())
            .inspect(|f| check::frame(f))
            .collect()
    }

    fn one_frame(&mut self) -> Vec<u8> {
        let mut f = self.frames();
        assert_eq!(f.len(), 1, "expected exactly one frame");
        f.pop().unwrap()
    }

    fn ops(&mut self) -> Vec<HostOp> {
        std::iter::from_fn(|| self.s.pop_op()).collect()
    }

    fn advance(&mut self, d: Duration) {
        self.now += d;
        self.s.on_timer(self.now);
    }
}

fn guest_ip(dst: Ipv4Addr, proto: u8, l4: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let out = Ipv4Out {
        eth_dst: ROUTER_MAC,
        eth_src: GUEST_MAC,
        src: GUEST,
        dst,
        proto,
        id: 1,
    };
    ipv4_frame(&out, 2000, l4)
}

fn guest_udp(sport: u16, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    guest_ip(*dst.ip(), PROTO_UDP, |f| {
        write_udp(f, sport, dst.port(), payload)
    })
}

fn guest_echo(dst: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let [a, b] = id.to_be_bytes();
    let [c, d] = seq.to_be_bytes();
    guest_ip(dst, PROTO_ICMP, |f| {
        write_icmp(f, icmp_type::ECHO_REQUEST, 0, [a, b, c, d], payload)
    })
}

#[allow(clippy::too_many_arguments)]
fn guest_tcp_opts(
    sport: u16,
    dst: SocketAddrV4,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    mss: Option<u16>,
    wscale: Option<u8>,
) -> Vec<u8> {
    let h = TcpHeader {
        sport,
        dport: dst.port(),
        seq,
        ack,
        flags,
        window,
        mss,
        wscale,
    };
    guest_ip(*dst.ip(), PROTO_TCP, |f| write_tcp(f, &h, [payload, &[]]))
}

fn guest_tcp(
    sport: u16,
    dst: SocketAddrV4,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    guest_tcp_opts(sport, dst, seq, ack, flags, window, payload, None, None)
}

/// An IPv4 packet the stack sent to the guest.
struct Ip {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    eth_dst: [u8; 6],
    proto: u8,
    payload: Vec<u8>,
}

fn ip_of(f: &[u8]) -> Ip {
    let eth = EthFrame::parse(f).unwrap();
    assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
    let ip = Ipv4Packet::parse(eth.payload).unwrap();
    Ip {
        src: ip.src,
        dst: ip.dst,
        eth_dst: eth.dst,
        proto: ip.proto,
        payload: ip.payload.to_vec(),
    }
}

fn udp_of(f: &[u8]) -> (SocketAddrV4, SocketAddrV4, Vec<u8>) {
    let eth = EthFrame::parse(f).unwrap();
    let ip = Ipv4Packet::parse(eth.payload).unwrap();
    let u = UdpDatagram::parse(&ip).unwrap();
    (
        SocketAddrV4::new(ip.src, u.sport),
        SocketAddrV4::new(ip.dst, u.dport),
        u.payload.to_vec(),
    )
}

#[derive(Debug)]
struct Seg {
    src: SocketAddrV4,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    wscale: Option<u8>,
    payload: Vec<u8>,
}

fn tcp_of(f: &[u8]) -> Seg {
    let eth = EthFrame::parse(f).unwrap();
    assert_eq!(eth.dst, GUEST_MAC);
    let ip = Ipv4Packet::parse(eth.payload).unwrap();
    assert_eq!((ip.dst, ip.proto), (GUEST, PROTO_TCP));
    let t = TcpSegment::parse(&ip).unwrap();
    Seg {
        src: SocketAddrV4::new(ip.src, t.sport),
        dport: t.dport,
        seq: t.seq,
        ack: t.ack,
        flags: t.flags,
        window: t.window,
        mss: t.mss,
        wscale: t.wscale,
        payload: t.payload.to_vec(),
    }
}

/// Reassemble IPv4 fragments of one packet (any order) into a whole frame,
/// checked like any other, written independently of `wire::fragment`.
fn reassemble(frags: &[Vec<u8>]) -> Vec<u8> {
    let mut parts: Vec<(usize, bool, &[u8])> = frags
        .iter()
        .map(|f| {
            let ip = &f[14..];
            assert_eq!(ip[4..6], frags[0][14 + 4..14 + 6], "one IP id");
            let frag = u16::from_be_bytes([ip[6], ip[7]]);
            (
                usize::from(frag & 0x1fff) * 8,
                frag & 0x2000 != 0,
                &ip[20..],
            )
        })
        .collect();
    parts.sort_by_key(|p| p.0);
    let mut payload = Vec::new();
    for (i, (off, more, data)) in parts.iter().enumerate() {
        assert_eq!(*off, payload.len(), "no holes or overlaps");
        assert_eq!(*more, i + 1 < parts.len(), "MF on all but the last");
        payload.extend_from_slice(data);
    }
    let mut f = frags[0][..34].to_vec();
    f[14 + 2..14 + 4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    f[14 + 6] = 0x40; // whole again: as if sent with DF
    f[14 + 7] = 0;
    f[14 + 10..14 + 12].fill(0);
    let c = checksum(&f[14..34]);
    f[14 + 10..14 + 12].copy_from_slice(&c.to_be_bytes());
    f.extend_from_slice(&payload);
    check::frame(&f);
    f
}

fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

// ---------------------------------------------------------------------------
// Link layer
// ---------------------------------------------------------------------------

fn arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    ArpPacket {
        op: ARP_REQUEST,
        sender_mac,
        sender_ip,
        target_mac: [0; 6],
        target_ip: target,
    }
    .frame(MAC_BROADCAST)
}

#[test]
fn arp_answers_virtual_hosts_only() {
    let mut h = H::new();
    for target in [GW, DNS] {
        h.input(arp_request(GUEST_MAC, GUEST, target));
        let f = h.one_frame();
        assert_eq!(f[..6], GUEST_MAC);
        assert_eq!(f[12..14], [0x08, 0x06]);
        let arp = ArpPacket::parse(&f[14..]).unwrap();
        assert_eq!(arp.op, ARP_REPLY);
        assert_eq!((arp.sender_mac, arp.sender_ip), (ROUTER_MAC, target));
        assert_eq!((arp.target_mac, arp.target_ip), (GUEST_MAC, GUEST));
    }
    // Duplicate address detection probe for the guest's own address, other
    // addresses on the subnet, and gratuitous probes: no answer.
    h.input(arp_request(GUEST_MAC, Ipv4Addr::UNSPECIFIED, GUEST));
    h.input(arp_request(GUEST_MAC, GUEST, Ipv4Addr::new(10, 0, 2, 99)));
    h.input(arp_request(GUEST_MAC, Ipv4Addr::UNSPECIFIED, GW));
    assert!(h.frames().is_empty());
}

#[test]
fn guest_mac_is_learned() {
    let mut h = H::new();
    let mac = [0x02, 0, 0, 0, 0, 7];
    h.input(arp_request(mac, GUEST, GW));
    assert_eq!(h.one_frame()[..6], mac);
    let mut echo = guest_echo(DNS, 1, 1, b"x");
    echo[6..12].copy_from_slice(&mac);
    h.input(echo);
    assert_eq!(ip_of(&h.one_frame()).eth_dst, mac);
}

#[test]
fn ignored_frames() {
    let mut h = H::new();
    // IPv6 (router solicitation-ish), silently.
    let mut v6 = MAC_BROADCAST.to_vec();
    v6.extend_from_slice(&GUEST_MAC);
    v6.extend_from_slice(&[0x86, 0xdd]);
    v6.extend_from_slice(&[0x60; 48]);
    h.input(v6);
    // Unicast to some other MAC.
    let mut other = guest_echo(DNS, 1, 1, b"x");
    other[..6].copy_from_slice(&[2, 2, 2, 2, 2, 2]);
    h.input(other);
    // Fragment (MF set; header checksum fixed up).
    let mut frag = guest_echo(DNS, 1, 1, b"x");
    frag[14 + 6] |= 0x20;
    frag[14 + 10..14 + 12].fill(0);
    let c = checksum(&frag[14..34]);
    frag[24..26].copy_from_slice(&c.to_be_bytes());
    h.input(frag);
    // Bad IPv4 header checksum.
    let mut bad = guest_echo(DNS, 1, 1, b"x");
    bad[14 + 10] ^= 0xff;
    h.input(bad);
    // Bad ICMP checksum.
    let mut bad = guest_echo(DNS, 1, 1, b"x");
    let n = bad.len();
    bad[n - 1] ^= 0xff;
    h.input(bad);
    // Truncated.
    h.input(vec![0; 10]);
    assert!(h.frames().is_empty());
    assert!(h.ops().is_empty());
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

fn dhcp_frame(payload: &[u8]) -> Vec<u8> {
    let out = Ipv4Out {
        eth_dst: MAC_BROADCAST,
        eth_src: GUEST_MAC,
        src: Ipv4Addr::UNSPECIFIED,
        dst: Ipv4Addr::BROADCAST,
        proto: PROTO_UDP,
        id: 1,
    };
    ipv4_frame(&out, 600, |f| write_udp(f, 68, 67, payload))
}

#[test]
fn dhcp_full_exchange() {
    use crate::dhcp::tests::{client_msg, reply_options};
    let mut h = H::new();

    h.input(dhcp_frame(&client_msg(1, 0, Ipv4Addr::UNSPECIFIED, &[])));
    let f = h.one_frame();
    let ip = ip_of(&f);
    assert_eq!((ip.src, ip.dst, ip.eth_dst), (GW, GUEST, GUEST_MAC)); // unicast: no broadcast flag
    let (from, to, offer) = udp_of(&f);
    assert_eq!((from.port(), to.port()), (67, 68));
    assert_eq!(offer[16..20], GUEST.octets());
    let opts = reply_options(&offer);
    assert!(opts.contains(&(53, vec![2])));
    assert!(opts.contains(&(54, GW.octets().to_vec())));
    assert!(opts.contains(&(1, vec![255, 255, 255, 0])));
    assert!(opts.contains(&(3, GW.octets().to_vec())));
    assert!(opts.contains(&(6, DNS.octets().to_vec())));
    assert!(opts.iter().any(|(c, _)| *c == 51));

    // udhcpc-style REQUEST with the broadcast flag: broadcast ACK.
    let req = client_msg(
        3,
        0x8000,
        Ipv4Addr::UNSPECIFIED,
        &[(50, &GUEST.octets()), (54, &GW.octets())],
    );
    h.input(dhcp_frame(&req));
    let f = h.one_frame();
    let ip = ip_of(&f);
    assert_eq!((ip.dst, ip.eth_dst), (Ipv4Addr::BROADCAST, MAC_BROADCAST));
    assert!(reply_options(&udp_of(&f).2).contains(&(53, vec![5])));

    // Renewal unicast to the server from the leased address.
    let renew = client_msg(3, 0, GUEST, &[]);
    h.input(guest_udp(68, SocketAddrV4::new(GW, 67), &renew));
    let f = h.one_frame();
    assert_eq!(ip_of(&f).dst, GUEST);
    assert!(reply_options(&udp_of(&f).2).contains(&(53, vec![5])));

    // Wrong address: NAK.
    h.input(dhcp_frame(&client_msg(
        3,
        0,
        Ipv4Addr::UNSPECIFIED,
        &[(50, &[10, 0, 2, 50])],
    )));
    assert!(reply_options(&udp_of(&h.one_frame()).2).contains(&(53, vec![6])));
    assert!(h.ops().is_empty(), "DHCP is answered locally");
}

// ---------------------------------------------------------------------------
// DNS and UDP
// ---------------------------------------------------------------------------

#[test]
fn dns_relay_maps_replies_per_guest_port() {
    let mut h = H::new();
    let dns = SocketAddrV4::new(DNS, 53);
    h.input(guest_udp(5000, dns, b"\x00\x01query-a"));
    h.input(guest_udp(5001, dns, b"\x00\x01query-b"));
    let ops = h.ops();
    let Ok(
        [
            HostOp::UdpOpen {
                id: a,
                connect: Some(up),
            },
            HostOp::UdpSend {
                id: a2,
                to: None,
                data,
            },
            HostOp::UdpOpen {
                id: b,
                connect: Some(_),
            },
            HostOp::UdpSend { .. },
        ],
    ) = <[HostOp; 4]>::try_from(ops.clone())
    else {
        panic!("{ops:?}")
    };
    assert_eq!(
        (up, a, data.as_slice()),
        (UPSTREAM, a2, &b"\x00\x01query-a"[..]),
        "a socket connected to the upstream resolver"
    );
    assert_ne!(a, b);

    // A second query from the same port reuses the flow.
    h.input(guest_udp(5000, dns, b"\x00\x02again"));
    assert_eq!(
        h.ops(),
        vec![HostOp::UdpSend {
            id: a,
            to: None,
            data: b"\x00\x02again".to_vec()
        }]
    );

    h.s.udp_received(b, UPSTREAM, b"\x00\x01answer-b", h.now);
    h.s.udp_received(a, UPSTREAM, b"\x00\x01answer-a", h.now);
    let f = h.frames();
    assert_eq!(
        udp_of(&f[0]),
        (
            dns,
            SocketAddrV4::new(GUEST, 5001),
            b"\x00\x01answer-b".to_vec()
        )
    );
    assert_eq!(
        udp_of(&f[1]),
        (
            dns,
            SocketAddrV4::new(GUEST, 5000),
            b"\x00\x01answer-a".to_vec()
        )
    );

    // DNS flows expire quickly.
    h.advance(Duration::from_secs(11));
    let mut ops = h.ops();
    ops.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        ops,
        vec![HostOp::UdpClose { id: a }, HostOp::UdpClose { id: b }]
    );
}

#[test]
fn dns_without_upstream_answers_servfail() {
    let mut h = H::new();
    h.s.set_dns_upstream(None);
    let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x03foo\x00\x00\x01\x00\x01");
    h.input(guest_udp(5000, SocketAddrV4::new(DNS, 53), &q));
    let (from, _, r) = udp_of(&h.one_frame());
    assert_eq!(from, SocketAddrV4::new(DNS, 53));
    assert_eq!((r[0], r[1], r[3] & 0x0f), (0xab, 0xcd, 2));
    assert!(h.ops().is_empty());
}

#[test]
fn udp_nat_is_full_cone() {
    let mut h = H::new();
    let far = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9999);
    let host7 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7);
    h.input(guest_udp(4000, far, b"ping"));
    h.input(guest_udp(4000, SocketAddrV4::new(GW, 7), b"to-host"));
    h.input(guest_udp(4001, far, b"other port"));
    // One mapping (one unconnected host socket) per guest source port,
    // whatever the destination; 10.0.2.2 is the host's loopback.
    let ops = h.ops();
    let Ok(
        [
            HostOp::UdpOpen { id, connect: None },
            HostOp::UdpSend {
                id: i1,
                to: Some(t1),
                data: d1,
            },
            HostOp::UdpSend {
                id: i2,
                to: Some(t2),
                data: d2,
            },
            HostOp::UdpOpen {
                id: other,
                connect: None,
            },
            HostOp::UdpSend { id: i3, .. },
        ],
    ) = <[HostOp; 5]>::try_from(ops.clone())
    else {
        panic!("{ops:?}")
    };
    assert_eq!((i1, t1, d1.as_slice()), (id, far, &b"ping"[..]));
    assert_eq!((i2, t2, d2.as_slice()), (id, host7, &b"to-host"[..]));
    assert_ne!(id, other);
    assert_eq!(i3, other);

    // Replies from anyone reach the guest port with their real source, like
    // a TFTP server answering from a new port or a STUN peer.
    let new_port = SocketAddrV4::new(*far.ip(), 50123);
    let stranger = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 3478);
    h.s.udp_received(id, new_port, b"data", h.now);
    h.s.udp_received(id, stranger, b"hello", h.now);
    h.s.udp_received(id, host7, b"echo", h.now);
    // Sources the guest could not have talked to are dropped.
    for bogus in [
        Ipv4Addr::new(10, 0, 2, 9),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::BROADCAST,
    ] {
        h.s.udp_received(id, SocketAddrV4::new(bogus, 1), b"x", h.now);
    }
    let to = SocketAddrV4::new(GUEST, 4000);
    let got: Vec<_> = h.frames().iter().map(|f| udp_of(f)).collect();
    assert_eq!(
        got,
        vec![
            (new_port, to, b"data".to_vec()),
            (stranger, to, b"hello".to_vec()),
            (SocketAddrV4::new(GW, 7), to, b"echo".to_vec()),
        ]
    );

    // ECONNREFUSED: port unreachable from the remote the guest last sent
    // to, quoting the guest's datagram.
    h.s.udp_error(other, HostError::Refused, false);
    let ip = ip_of(&h.one_frame());
    assert_eq!((ip.src, ip.proto), (*far.ip(), PROTO_ICMP));
    let m = IcmpMessage::parse(&ip.payload).unwrap();
    assert_eq!(
        (m.ty, m.code),
        (icmp_type::DEST_UNREACHABLE, unreach_code::PORT)
    );
    assert_eq!(
        m.payload[12..20],
        [GUEST.octets(), far.ip().octets()].concat()
    );
    assert_eq!(m.payload[20..22], 4001u16.to_be_bytes());
    // Running out of descriptors is no ICMP: the datagram is just lost.
    h.s.udp_error(other, HostError::NoResources, false);
    assert!(h.frames().is_empty());

    // Mappings live 240 s without traffic (qemu's timeout), and traffic in
    // either direction keeps them.
    h.advance(Duration::from_secs(200));
    assert!(h.ops().is_empty());
    h.s.udp_received(id, stranger, b"keepalive", h.now);
    h.frames();
    h.advance(Duration::from_secs(41));
    assert_eq!(h.ops(), vec![HostOp::UdpClose { id: other }]);
    assert_eq!(h.s.udp_flow_count(), 1);
    h.advance(Duration::from_secs(200));
    assert_eq!(h.ops(), vec![HostOp::UdpClose { id }]);
    assert_eq!(h.s.udp_flow_count(), 0);
}

#[test]
fn large_udp_datagrams_are_fragmented() {
    let mut h = H::new();
    let dns = SocketAddrV4::new(DNS, 53);
    h.input(guest_udp(5000, dns, b"\x00\x01q"));
    let HostOp::UdpOpen { id, .. } = h.ops()[0] else {
        panic!()
    };
    // An EDNS answer bigger than the MTU, up to the largest UDP datagram.
    for len in [1472, 1473, 2952, 2953, 4000, 65507] {
        let data = pattern(len, 9);
        h.s.udp_received(id, UPSTREAM, &data, h.now);
        let frags = h.frames();
        assert_eq!(frags.len(), (len + 8).div_ceil(1480), "{len} bytes");
        let whole = reassemble(&frags);
        assert_eq!(
            udp_of(&whole),
            (dns, SocketAddrV4::new(GUEST, 5000), data),
            "{len} bytes"
        );
    }

    // Host forwards too.
    let client = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6001);
    let data = pattern(9000, 10);
    h.s.udp_fwd_received(0, 53, client, &data, h.now);
    let frags = h.frames();
    assert_eq!(frags.len(), 7);
    let (from, to, got) = udp_of(&reassemble(&frags));
    assert_eq!(
        (*from.ip(), to, got),
        (GW, SocketAddrV4::new(GUEST, 53), data)
    );
}

#[test]
fn udp_socket_cap_evicts_least_recently_used() {
    let mut h = H::new();
    h.s.set_limits(Limits {
        tcp: 2,
        tcp_fwd: 1,
        udp: 2,
    });
    let far = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9999);
    let open_id = |h: &mut H| match h.ops()[..] {
        [HostOp::UdpOpen { id, .. }, HostOp::UdpSend { .. }] => id,
        ref ops => panic!("{ops:?}"),
    };
    h.input(guest_udp(4000, far, b"a"));
    let a = open_id(&mut h);
    h.advance(Duration::from_millis(10));
    h.input(guest_udp(4001, far, b"b"));
    let b = open_id(&mut h);
    h.advance(Duration::from_millis(10));
    h.input(guest_udp(4000, far, b"a again")); // a is now the newest
    h.ops();
    h.input(guest_udp(4002, far, b"c"));
    let ops = h.ops();
    assert_eq!(ops[0], HostOp::UdpClose { id: b }, "{ops:?}");
    assert!(matches!(ops[1], HostOp::UdpOpen { id, .. } if id != a));
    assert_eq!(h.s.udp_flow_count(), 2);
}

#[test]
fn udp_special_destinations() {
    let mut h = H::new();
    // Non-DNS port on the DNS address: port unreachable from 10.0.2.3.
    h.input(guest_udp(4000, SocketAddrV4::new(DNS, 1234), b"x"));
    let ip = ip_of(&h.one_frame());
    assert_eq!(ip.src, DNS);
    assert_eq!(ip.payload[..2], [3, 3]);
    // Broadcast, other subnet hosts, multicast: dropped.
    h.input(guest_udp(
        4000,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 255), 9),
        b"x",
    ));
    h.input(guest_udp(
        4000,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 7), 9),
        b"x",
    ));
    h.input(guest_udp(
        4000,
        SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353),
        b"x",
    ));
    assert!(h.frames().is_empty());
    assert!(h.ops().is_empty());

    // TTL 1 to the outside world: time exceeded from the gateway.
    let mut f = guest_udp(4000, REMOTE, b"trace");
    f[14 + 8] = 1;
    f[24..26].fill(0);
    let c = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    h.input(f);
    let ip = ip_of(&h.one_frame());
    assert_eq!((ip.src, ip.payload[0]), (GW, icmp_type::TIME_EXCEEDED));
    assert!(h.ops().is_empty());
}

#[test]
fn udp_hostfwd_maps_clients() {
    let mut h = H::new();
    let c1 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6001);
    let c2 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6002);
    h.s.udp_fwd_received(0, 53, c1, b"q1", h.now);
    h.s.udp_fwd_received(0, 53, c2, b"q2", h.now);
    let f = h.frames();
    let (from1, to1, d1) = udp_of(&f[0]);
    let (from2, _, _) = udp_of(&f[1]);
    assert_eq!(
        (*from1.ip(), to1, d1),
        (GW, SocketAddrV4::new(GUEST, 53), b"q1".to_vec())
    );
    assert!(from1.port() >= 49152 && from1 != from2);

    h.input(guest_udp(53, from2, b"r2"));
    h.input(guest_udp(53, from1, b"r1"));
    assert_eq!(
        h.ops(),
        vec![
            HostOp::UdpFwdSend {
                rule: 0,
                to: c2,
                data: b"r2".to_vec()
            },
            HostOp::UdpFwdSend {
                rule: 0,
                to: c1,
                data: b"r1".to_vec()
            },
        ]
    );
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

#[test]
fn icmp_echo_nat() {
    let mut h = H::new();
    let far = Ipv4Addr::new(8, 8, 8, 8);
    h.input(guest_echo(far, 0x1234, 1, b"payload"));
    h.input(guest_echo(GW, 0x1234, 1, b"local"));
    let ops = h.ops();
    let HostOp::IcmpSend { dst, msg } = &ops[0] else {
        panic!()
    };
    assert_eq!(*dst, far);
    let req = IcmpMessage::parse(msg).expect("valid checksum");
    assert_eq!(
        (req.ty, req.payload, &req.rest[2..]),
        (icmp_type::ECHO_REQUEST, &b"payload"[..], &[0, 1][..])
    );
    let nat_far = req.echo_id();
    let HostOp::IcmpSend { dst, msg } = &ops[1] else {
        panic!()
    };
    assert_eq!(
        *dst,
        Ipv4Addr::LOCALHOST,
        "echo to 10.0.2.2 pings the host's loopback"
    );
    let nat_gw = IcmpMessage::parse(msg).unwrap().echo_id();

    // Replies come back with the guest's id and the guest-visible source.
    let [a, b] = nat_gw.to_be_bytes();
    let reply = icmp_message(icmp_type::ECHO_REPLY, 0, [a, b, 0, 1], b"local");
    h.s.icmp_received(Ipv4Addr::LOCALHOST, &reply, h.now);
    let [a, b] = nat_far.to_be_bytes();
    let reply = icmp_message(icmp_type::ECHO_REPLY, 0, [a, b, 0, 1], b"payload");
    h.s.icmp_received(far, &reply, h.now);
    // Unknown id, and our own request looped back: ignored.
    h.s.icmp_received(
        far,
        &icmp_message(icmp_type::ECHO_REPLY, 0, [0xde, 0xad, 0, 1], b""),
        h.now,
    );
    h.s.icmp_received(far, msg, h.now);

    let f = h.frames();
    assert_eq!(f.len(), 2);
    for (frame, src, payload) in [(&f[0], GW, &b"local"[..]), (&f[1], far, &b"payload"[..])] {
        let ip = ip_of(frame);
        assert_eq!(ip.src, src);
        let m = IcmpMessage::parse(&ip.payload).unwrap();
        assert_eq!(
            (m.ty, m.echo_id(), m.payload),
            (icmp_type::ECHO_REPLY, 0x1234, payload)
        );
    }
}

/// The ICMP socket's kernel replaces the echo identifier (Linux): the
/// sequence number carries the mapping, and the guest sees its own
/// identifier and sequence number in the replies.
#[test]
fn icmp_echo_nat_by_sequence_when_the_host_rewrites_ids() {
    let mut h = H::new();
    h.s.set_icmp_ident_rewritten(true);
    let far = Ipv4Addr::new(8, 8, 8, 8);
    // Two guest flows to the same host with the same sequence numbers, and
    // one to the gateway.
    h.input(guest_echo(far, 0x1111, 1, b"one"));
    h.input(guest_echo(far, 0x2222, 1, b"two"));
    h.input(guest_echo(GW, 0x1111, 1, b"gw"));
    let sent: Vec<(Ipv4Addr, Vec<u8>)> = h
        .ops()
        .into_iter()
        .map(|op| match op {
            HostOp::IcmpSend { dst, msg } => (dst, msg),
            _ => panic!("unexpected op"),
        })
        .collect();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[2].0, Ipv4Addr::LOCALHOST);
    let seqs: Vec<u16> = sent
        .iter()
        .map(|(_, m)| IcmpMessage::parse(m).expect("valid checksum").echo_seq())
        .collect();
    assert_ne!(
        seqs[0], seqs[1],
        "distinct NAT sequence numbers per request"
    );

    // Replies as Linux delivers them: identifier = the socket's port.
    let reply = |seq: u16, payload: &[u8]| {
        let [c, d] = seq.to_be_bytes();
        icmp_message(icmp_type::ECHO_REPLY, 0, [0x9a, 0xbc, c, d], payload)
    };
    h.s.icmp_received(far, &reply(seqs[1], b"two"), h.now);
    h.s.icmp_received(far, &reply(seqs[0], b"one"), h.now);
    h.s.icmp_received(Ipv4Addr::LOCALHOST, &reply(seqs[2], b"gw"), h.now);
    // A duplicate reply maps too; an unknown sequence, a reply from the wrong
    // host, and a looped-back request do not.
    h.s.icmp_received(far, &reply(seqs[0], b"one"), h.now);
    h.s.icmp_received(far, &reply(seqs[0].wrapping_add(100), b"?"), h.now);
    h.s.icmp_received(Ipv4Addr::new(9, 9, 9, 9), &reply(seqs[0], b"?"), h.now);
    h.s.icmp_received(far, &sent[0].1, h.now);

    let got: Vec<(Ipv4Addr, [u8; 4], Vec<u8>)> = h
        .frames()
        .iter()
        .map(|f| {
            let ip = ip_of(f);
            let m = IcmpMessage::parse(&ip.payload).unwrap();
            assert_eq!(m.ty, icmp_type::ECHO_REPLY);
            (ip.src, m.rest, m.payload.to_vec())
        })
        .collect();
    assert_eq!(
        got,
        [
            (far, [0x22, 0x22, 0, 1], b"two".to_vec()),
            (far, [0x11, 0x11, 0, 1], b"one".to_vec()),
            (GW, [0x11, 0x11, 0, 1], b"gw".to_vec()),
            (far, [0x11, 0x11, 0, 1], b"one".to_vec()),
        ]
    );

    // Requests are forgotten after a while.
    h.advance(Duration::from_secs(31));
    h.advance(Duration::from_secs(1));
    h.s.icmp_received(far, &reply(seqs[0], b"late"), h.now);
    assert!(h.frames().is_empty());
}

/// The per-request table is bounded: the oldest requests go first.
#[test]
fn icmp_sequence_nat_is_bounded() {
    let mut h = H::new();
    h.s.set_icmp_ident_rewritten(true);
    let far = Ipv4Addr::new(8, 8, 8, 8);
    let mut seqs = Vec::new();
    for i in 0..1100u16 {
        h.input(guest_echo(far, 7, i, b""));
        let Some(HostOp::IcmpSend { msg, .. }) = h.ops().pop() else {
            panic!("no request sent")
        };
        seqs.push(IcmpMessage::parse(&msg).unwrap().echo_seq());
    }
    let reply = |seq: u16| {
        let [c, d] = seq.to_be_bytes();
        icmp_message(icmp_type::ECHO_REPLY, 0, [0, 0, c, d], b"")
    };
    h.s.icmp_received(far, &reply(seqs[0]), h.now);
    assert!(h.frames().is_empty(), "the oldest request was evicted");
    h.s.icmp_received(far, &reply(seqs[1099]), h.now);
    let ip = ip_of(&h.one_frame());
    let m = IcmpMessage::parse(&ip.payload).unwrap();
    assert_eq!(m.rest, [0, 7, 0x04, 0x4b], "guest id 7, seq 1099");
}

#[test]
fn icmp_echo_to_dns_is_local_and_fallback_without_socket() {
    let mut h = H::new();
    h.input(guest_echo(DNS, 7, 3, b"hi"));
    let ip = ip_of(&h.one_frame());
    let m = IcmpMessage::parse(&ip.payload).unwrap();
    assert_eq!(
        (ip.src, m.ty, m.rest, m.payload),
        (DNS, 0, [0, 7, 0, 3], &b"hi"[..])
    );

    h.s.set_icmp_available(false);
    h.input(guest_echo(GW, 7, 4, b"hi"));
    assert_eq!(ip_of(&h.one_frame()).src, GW);
    h.input(guest_echo(Ipv4Addr::new(1, 1, 1, 1), 7, 5, b"hi"));
    assert!(h.frames().is_empty());
    assert!(h.ops().is_empty());
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

const ISN: u32 = 0xffff_f000; // close to wrapping, on purpose

struct Conn {
    id: FlowId,
    sport: u16,
    remote: SocketAddrV4,
    /// Next guest sequence number.
    gseq: u32,
    /// Next sequence number expected from the stack.
    sseq: u32,
    window: u16,
}

impl Conn {
    fn seg(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
        guest_tcp(
            self.sport,
            self.remote,
            self.gseq,
            self.sseq,
            flags,
            self.window,
            payload,
        )
    }

    /// Guest sends data (advancing its sequence number).
    fn send(&mut self, h: &mut H, payload: &[u8]) {
        let f = self.seg(ACK | PSH, payload);
        self.gseq = self.gseq.wrapping_add(payload.len() as u32);
        h.input(f);
    }

    fn ack(&self, h: &mut H, ack: u32, window: u16) {
        h.input(guest_tcp(
            self.sport,
            self.remote,
            self.gseq,
            ack,
            ACK,
            window,
            &[],
        ));
    }
}

/// Guest connects to `remote`; the host accepts.
fn open(h: &mut H, sport: u16, remote: SocketAddrV4, window: u16, wscale: Option<u8>) -> Conn {
    h.input(guest_tcp_opts(
        sport,
        remote,
        ISN,
        0,
        SYN,
        window,
        &[],
        Some(1460),
        wscale,
    ));
    assert!(
        h.frames().is_empty(),
        "no SYN-ACK before the host connect completes"
    );
    let ops = h.ops();
    let [HostOp::TcpConnect { id, dst }] = ops[..] else {
        panic!("{ops:?}")
    };
    assert_eq!(dst, remote);
    h.s.tcp_connected(id, h.now);
    let synack = tcp_of(&h.one_frame());
    assert_eq!(synack.flags, SYN | ACK);
    assert_eq!(
        (synack.src, synack.dport, synack.ack),
        (remote, sport, ISN.wrapping_add(1))
    );
    assert_eq!(synack.mss, Some(MSS));
    assert_eq!(synack.wscale, wscale.map(|_| 3));
    let c = Conn {
        id,
        sport,
        remote,
        gseq: ISN.wrapping_add(1),
        sseq: synack.seq.wrapping_add(1),
        window,
    };
    c.ack(h, c.sseq, window);
    assert!(h.frames().is_empty());
    assert_eq!(h.s.tcp_phases(), vec![Phase::Open]);
    c
}

fn to_host(h: &H, id: FlowId) -> Vec<u8> {
    let (a, b) = h.s.tcp_to_host(id);
    [a, b].concat()
}

#[test]
fn tcp_handshake_and_data_both_ways() {
    let mut h = H::new();
    let mut c = open(&mut h, 40000, REMOTE, 512, Some(7));
    assert_eq!(
        h.s.tcp_read_budget(c.id),
        512 << 7,
        "guest window is scaled after the SYN"
    );

    // Guest -> host: two segments in one batch get a single ACK.
    let data = pattern(2000, 1);
    let (f1, f2) = (c.seg(ACK, &data[..1000]), {
        let mut c2 = Conn { ..c };
        c2.gseq = c.gseq.wrapping_add(1000);
        c2.seg(ACK | PSH, &data[1000..])
    });
    c.gseq = c.gseq.wrapping_add(2000);
    h.s.handle_frame(&f1, h.now);
    h.s.handle_frame(&f2, h.now);
    h.s.flush(h.now);
    let ack = tcp_of(&h.one_frame());
    assert_eq!((ack.flags, ack.ack, ack.seq), (ACK, c.gseq, c.sseq));
    assert_eq!(u32::from(ack.window) << 3, 256 * 1024 - 2000);
    assert_eq!(to_host(&h, c.id), data);
    h.s.tcp_host_wrote(c.id, 2000, h.now);
    assert!(to_host(&h, c.id).is_empty());

    // Host -> guest: segmented at the MSS, PSH on the last.
    let data = pattern(4000, 2);
    h.s.tcp_host_data(c.id, &data, h.now);
    let segs: Vec<Seg> = h.frames().iter().map(|f| tcp_of(f)).collect();
    assert_eq!(
        segs.iter().map(|s| s.payload.len()).collect::<Vec<_>>(),
        [1460, 1460, 1080]
    );
    let mut seq = c.sseq;
    for s in &segs {
        assert_eq!((s.seq, s.ack), (seq, c.gseq));
        seq = seq.wrapping_add(s.payload.len() as u32);
    }
    assert_eq!(segs[2].flags, ACK | PSH);
    assert_eq!(
        segs.iter()
            .flat_map(|s| s.payload.clone())
            .collect::<Vec<_>>(),
        data
    );
    c.sseq = seq;
    c.ack(&mut h, c.sseq, 512);
    assert!(h.frames().is_empty());
    assert_eq!(h.s.tcp_read_budget(c.id), 512 << 7);
    h.advance(Duration::from_secs(5));
    assert!(
        h.frames().is_empty(),
        "everything acknowledged: no retransmission"
    );
}

#[test]
fn tcp_zero_window_persist() {
    let mut h = H::new();
    let mut c = open(&mut h, 40000, REMOTE, 1000, None);
    assert_eq!(h.s.tcp_read_budget(c.id), 1000);
    h.s.tcp_host_data(c.id, &pattern(1000, 3), h.now);
    assert_eq!(tcp_of(&h.one_frame()).payload.len(), 1000);
    assert_eq!(
        h.s.tcp_read_budget(c.id),
        0,
        "never read past the guest's window"
    );
    c.sseq = c.sseq.wrapping_add(1000);
    c.ack(&mut h, c.sseq, 0);
    assert_eq!(h.s.tcp_read_budget(c.id), 0);
    assert!(h.frames().is_empty());

    // The window update could be lost: probe with backoff.
    let mut probes = Vec::new();
    for _ in 0..40 {
        h.advance(Duration::from_millis(100));
        probes.extend(h.frames().iter().map(|f| (h.now, tcp_of(f))));
    }
    assert!(
        probes.len() >= 2 && probes.len() <= 5,
        "{} probes",
        probes.len()
    );
    for (_, p) in &probes {
        assert_eq!(
            (p.seq, p.flags, p.payload.len()),
            (c.sseq.wrapping_sub(1), ACK, 0)
        );
    }
    assert!(
        probes[1].0 - probes[0].0 < probes[2].0 - probes[1].0,
        "backoff"
    );

    c.ack(&mut h, c.sseq, 3000);
    assert_eq!(h.s.tcp_read_budget(c.id), 3000);
    h.advance(Duration::from_secs(120));
    assert!(h.frames().is_empty());
}

#[test]
fn tcp_receive_window_back_pressure() {
    let mut h = H::new();
    // Window scaling lets the advertised window cover the whole buffer.
    let mut c = open(&mut h, 40000, REMOTE, 65535, Some(7));
    let data = pattern(256 * 1024, 4);
    for chunk in data.chunks(1460) {
        c.send(&mut h, chunk);
    }
    let last = tcp_of(&h.frames().pop().unwrap());
    assert_eq!((last.ack, last.window), (c.gseq, 0));
    // More data does not fit: ACKed with a zero window and dropped.
    let f = c.seg(ACK, b"overflow");
    h.input(f);
    let a = tcp_of(&h.one_frame());
    assert_eq!((a.ack, a.window), (c.gseq, 0));
    assert_eq!(to_host(&h, c.id), data);
    // The host drains: window update.
    h.s.tcp_host_wrote(c.id, 1000, h.now);
    assert!(h.frames().is_empty(), "no silly window update");
    h.s.tcp_host_wrote(c.id, data.len() - 1000, h.now);
    let a = tcp_of(&h.one_frame());
    assert_eq!((a.ack, u32::from(a.window) << 3), (c.gseq, 256 * 1024));
}

#[test]
fn tcp_retransmits_lost_data() {
    let mut h = H::new();
    let c = open(&mut h, 40000, REMOTE, 65535, None);
    let data = pattern(3000, 5);
    h.s.tcp_host_data(c.id, &data, h.now);
    assert_eq!(h.frames().len(), 3); // all lost

    h.advance(Duration::from_millis(150));
    assert!(h.frames().is_empty());
    h.advance(Duration::from_millis(100)); // RTO is 200 ms after a ~0 RTT handshake
    let r = tcp_of(&h.one_frame());
    assert_eq!((r.seq, r.payload.as_slice()), (c.sseq, &data[..1460]));

    // Slow start resumes after the ACK: the rest is resent.
    c.ack(&mut h, c.sseq.wrapping_add(1460), 65535);
    let segs: Vec<Seg> = h.frames().iter().map(|f| tcp_of(f)).collect();
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0].seq, c.sseq.wrapping_add(1460));
    let mut got = r.payload.clone();
    got.extend(segs.iter().flat_map(|s| s.payload.clone()));
    assert_eq!(got, data);
    c.ack(&mut h, c.sseq.wrapping_add(3000), 65535);
    h.advance(Duration::from_secs(10));
    assert!(h.frames().is_empty());
}

#[test]
fn tcp_fast_retransmit_on_duplicate_acks() {
    let mut h = H::new();
    let c = open(&mut h, 40000, REMOTE, 65535, None);
    let data = pattern(6 * 1460, 6);
    h.s.tcp_host_data(c.id, &data, h.now);
    assert_eq!(h.frames().len(), 6);
    // Segment 2 lost: the guest ACKs segment 1, then dup-ACKs for 3..6.
    let ack1 = c.sseq.wrapping_add(1460);
    for _ in 0..4 {
        c.ack(&mut h, ack1, 65535);
    }
    let r = tcp_of(&h.one_frame());
    assert_eq!((r.seq, r.payload.as_slice()), (ack1, &data[1460..2920]));
}

#[test]
fn tcp_gives_up_after_repeated_timeouts() {
    let mut h = H::new();
    let c = open(&mut h, 40000, REMOTE, 65535, None);
    h.s.tcp_host_data(c.id, b"lost forever", h.now);
    h.frames();
    let mut rst = None;
    for _ in 0..200 {
        h.advance(Duration::from_secs(30));
        rst = h
            .frames()
            .into_iter()
            .map(|f| tcp_of(&f))
            .find(|s| s.flags & RST != 0)
            .or(rst);
    }
    assert!(rst.is_some());
    assert_eq!(
        h.ops(),
        vec![HostOp::TcpClose {
            id: c.id,
            abort: true
        }]
    );
    assert!(h.s.tcp_phases().is_empty());
}

#[test]
fn tcp_out_of_order_guest_segments() {
    let mut h = H::new();
    let c = open(&mut h, 40000, REMOTE, 65535, None);
    let data = pattern(1500, 7);
    let second = guest_tcp(
        c.sport,
        c.remote,
        c.gseq.wrapping_add(1000),
        c.sseq,
        ACK,
        65535,
        &data[1000..],
    );
    h.input(second.clone());
    let dup = tcp_of(&h.one_frame());
    assert_eq!(dup.ack, c.gseq, "duplicate ACK for the hole");
    assert!(to_host(&h, c.id).is_empty());
    h.input(c.seg(ACK, &data[..1000]));
    assert_eq!(tcp_of(&h.one_frame()).ack, c.gseq.wrapping_add(1000));
    h.input(second);
    assert_eq!(tcp_of(&h.one_frame()).ack, c.gseq.wrapping_add(1500));
    assert_eq!(to_host(&h, c.id), data);
    // A full duplicate is re-ACKed and not buffered twice.
    h.input(c.seg(ACK, &data[..1000]));
    assert_eq!(tcp_of(&h.one_frame()).ack, c.gseq.wrapping_add(1500));
    assert_eq!(to_host(&h, c.id).len(), 1500);
}

#[test]
fn tcp_guest_closes_first() {
    let mut h = H::new();
    let mut c = open(&mut h, 40000, REMOTE, 65535, None);
    let f = c.seg(ACK | PSH | FIN, b"bye");
    c.gseq = c.gseq.wrapping_add(4);
    h.input(f);
    assert_eq!(
        tcp_of(&h.one_frame()).ack,
        c.gseq,
        "data and FIN acknowledged"
    );
    assert!(
        h.ops().is_empty(),
        "shutdown waits until the data reached the host"
    );
    h.s.tcp_host_wrote(c.id, 3, h.now);
    assert_eq!(h.ops(), vec![HostOp::TcpShutdownWrite { id: c.id }]);

    // The host can keep talking on its half.
    h.s.tcp_host_data(c.id, b"still here", h.now);
    assert_eq!(tcp_of(&h.one_frame()).payload, b"still here");
    c.sseq = c.sseq.wrapping_add(10);
    h.s.tcp_host_eof(c.id, h.now);
    let fin = tcp_of(&h.one_frame());
    assert_eq!((fin.flags, fin.seq, fin.ack), (FIN | ACK, c.sseq, c.gseq));
    c.ack(&mut h, c.sseq.wrapping_add(1), 65535);
    assert_eq!(
        h.ops(),
        vec![HostOp::TcpClose {
            id: c.id,
            abort: false
        }]
    );
    assert!(h.s.tcp_phases().is_empty(), "passive closer: no TIME_WAIT");
}

#[test]
fn tcp_host_closes_first() {
    let mut h = H::new();
    let mut c = open(&mut h, 40000, REMOTE, 65535, None);
    h.s.tcp_host_data(c.id, b"hi", h.now);
    h.s.tcp_host_eof(c.id, h.now);
    let segs: Vec<Seg> = h.frames().iter().map(|f| tcp_of(f)).collect();
    assert_eq!(segs.len(), 2);
    assert_eq!(
        (segs[1].flags, segs[1].seq),
        (FIN | ACK, c.sseq.wrapping_add(2))
    );
    assert_eq!(h.s.tcp_read_budget(c.id), 0);
    c.sseq = c.sseq.wrapping_add(3);
    c.ack(&mut h, c.sseq, 65535);
    assert!(h.frames().is_empty());

    // Half-closed: the guest still sends, then closes.
    c.send(&mut h, b"more");
    assert_eq!(tcp_of(&h.one_frame()).ack, c.gseq);
    assert_eq!(to_host(&h, c.id), b"more");
    h.s.tcp_host_wrote(c.id, 4, h.now);
    let fin = c.seg(ACK | FIN, &[]);
    h.input(fin.clone());
    assert_eq!(tcp_of(&h.one_frame()).ack, c.gseq.wrapping_add(1));
    assert_eq!(
        h.ops(),
        vec![
            HostOp::TcpShutdownWrite { id: c.id },
            HostOp::TcpClose {
                id: c.id,
                abort: false
            }
        ]
    );
    assert_eq!(h.s.tcp_phases(), vec![Phase::TimeWait]);
    // A retransmitted FIN in TIME_WAIT is re-ACKed.
    h.input(fin);
    assert_eq!(tcp_of(&h.one_frame()).ack, c.gseq.wrapping_add(1));
    h.advance(Duration::from_secs(3));
    assert!(h.s.tcp_phases().is_empty());
    assert!(h.ops().is_empty());
}

#[test]
fn tcp_reset_both_directions() {
    let mut h = H::new();
    let c = open(&mut h, 40000, REMOTE, 65535, None);
    h.input(c.seg(RST, &[]));
    assert_eq!(
        h.ops(),
        vec![HostOp::TcpClose {
            id: c.id,
            abort: true
        }]
    );
    assert!(h.s.tcp_phases().is_empty());
    assert!(h.frames().is_empty());

    let c = open(&mut h, 40001, REMOTE, 65535, None);
    // An out-of-window RST is ignored (and answered with an ACK).
    h.input(guest_tcp(
        c.sport,
        c.remote,
        c.gseq.wrapping_add(1 << 20),
        0,
        RST,
        0,
        &[],
    ));
    assert_eq!(h.s.tcp_phases(), vec![Phase::Open]);
    h.frames();
    h.s.tcp_host_reset(c.id, h.now);
    assert!(
        h.frames().is_empty(),
        "the reset waits until the driver has read the socket dry"
    );
    h.s.tcp_host_eof(c.id, h.now);
    let r = tcp_of(&h.one_frame());
    assert_eq!((r.flags, r.seq, r.ack), (RST | ACK, c.sseq, c.gseq));
    assert_eq!(
        h.ops(),
        vec![HostOp::TcpClose {
            id: c.id,
            abort: true
        }]
    );
    assert!(h.s.tcp_phases().is_empty());

    // Host EOF (FIN acknowledged), then a reset: nothing left to deliver.
    let mut c = open(&mut h, 40002, REMOTE, 65535, None);
    h.s.tcp_host_eof(c.id, h.now);
    assert_eq!(tcp_of(&h.one_frame()).flags, FIN | ACK);
    c.sseq = c.sseq.wrapping_add(1);
    c.ack(&mut h, c.sseq, 65535);
    h.s.tcp_host_reset(c.id, h.now);
    let r = tcp_of(&h.one_frame());
    assert_eq!((r.flags, r.seq), (RST | ACK, c.sseq));
    assert!(h.s.tcp_phases().is_empty());

    // A reset before the guest finished the handshake: RST at once.
    h.ops();
    h.input(guest_tcp_opts(
        40003,
        REMOTE,
        ISN,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    let [HostOp::TcpConnect { id, .. }] = h.ops()[..] else {
        panic!()
    };
    h.s.tcp_connected(id, h.now);
    h.frames();
    h.s.tcp_host_reset(id, h.now);
    assert_eq!(tcp_of(&h.one_frame()).flags, RST | ACK);
    assert_eq!(h.ops(), vec![HostOp::TcpClose { id, abort: true }]);
}

/// A host peer that sends a burst and then resets (an HTTP server answering
/// 413 and closing with the request unread): the guest gets every byte the
/// peer sent, then the RST, as an end-to-end TCP client would.
#[test]
fn tcp_host_reset_delivers_data_first() {
    let mut h = H::new();
    let mut c = open(&mut h, 40000, REMOTE, 65535, None);
    c.send(&mut h, b"request the host never reads");
    h.frames();
    let head = pattern(20000, 11); // more than the initial cwnd: some unsent
    h.s.tcp_host_data(c.id, &head, h.now);
    h.s.tcp_host_reset(c.id, h.now);
    assert!(
        to_host(&h, c.id).is_empty(),
        "guest data for a dead host is dropped"
    );
    // The driver drains what is left in the socket, then reports the end.
    let tail = pattern(3000, 12);
    assert!(h.s.tcp_read_budget(c.id) >= tail.len());
    h.s.tcp_host_data(c.id, &tail, h.now);
    h.s.tcp_host_eof(c.id, h.now);
    assert_eq!(h.s.tcp_read_budget(c.id), 0);
    assert!(h.ops().is_empty(), "the socket stays until the RST");

    let mut got = Vec::new();
    let mut rst = None;
    for _ in 0..20 {
        for s in h.frames().iter().map(|f| tcp_of(f)) {
            if s.flags & RST != 0 {
                rst = Some(s);
                break;
            }
            assert_eq!(s.flags & (FIN | SYN), 0, "no FIN: the host reset");
            assert_eq!(s.seq, c.sseq, "in order");
            c.sseq = c.sseq.wrapping_add(s.payload.len() as u32);
            got.extend(s.payload);
        }
        if rst.is_some() {
            break;
        }
        // Guest data after the reset is not acknowledged.
        let more = c.seg(ACK | PSH, b"more");
        h.input(more);
        c.ack(&mut h, c.sseq, 65535);
    }
    assert_eq!(got, [head, tail].concat());
    let rst = rst.expect("RST after the data");
    assert_eq!((rst.flags, rst.seq, rst.ack), (RST | ACK, c.sseq, c.gseq));
    assert!(to_host(&h, c.id).is_empty());
    assert_eq!(
        h.ops(),
        vec![HostOp::TcpClose {
            id: c.id,
            abort: true
        }]
    );
    assert!(h.s.tcp_phases().is_empty());
}

#[test]
fn tcp_host_reset_gives_up_on_a_stalled_guest() {
    let mut h = H::new();
    let c = open(&mut h, 40000, REMOTE, 65535, None);
    h.s.tcp_host_data(c.id, b"never acknowledged", h.now);
    h.frames();
    h.s.tcp_host_reset(c.id, h.now);
    h.s.tcp_host_eof(c.id, h.now);
    let mut rst_at = None;
    for i in 1..=70 {
        h.advance(Duration::from_secs(1));
        if h.frames().iter().any(|f| tcp_of(f).flags & RST != 0) {
            rst_at = Some(i);
            break;
        }
    }
    // Well before the retransmission limit (several minutes).
    assert_eq!(rst_at, Some(RESET_LINGER.as_secs()));
    assert!(h.s.tcp_phases().is_empty());
}

#[test]
fn tcp_connect_failures() {
    let mut h = H::new();
    let syn = |sport| guest_tcp_opts(sport, REMOTE, ISN, 0, SYN, 65535, &[], Some(1460), None);
    let connect_id = |h: &mut H| match h.ops()[..] {
        [HostOp::TcpConnect { id, .. }] => id,
        ref ops => panic!("{ops:?}"),
    };

    h.input(syn(40000));
    let id = connect_id(&mut h);
    h.input(syn(40000)); // retransmitted SYN while connecting: ignored
    assert!(h.ops().is_empty());
    assert!(h.frames().is_empty());
    h.s.tcp_connect_failed(id, HostError::Refused, h.now);
    let r = tcp_of(&h.one_frame());
    assert_eq!(
        (r.flags, r.seq, r.ack, r.src),
        (RST | ACK, 0, ISN.wrapping_add(1), REMOTE)
    );

    h.input(syn(40001));
    let id = connect_id(&mut h);
    h.s.tcp_connect_failed(id, HostError::HostUnreachable, h.now);
    let ip = ip_of(&h.one_frame());
    let m = IcmpMessage::parse(&ip.payload).unwrap();
    assert_eq!(
        (ip.src, m.ty, m.code),
        (GW, icmp_type::DEST_UNREACHABLE, unreach_code::HOST)
    );
    assert_eq!(
        m.payload[16..20],
        REMOTE.ip().octets(),
        "quotes the SYN's IP header"
    );
    assert_eq!(
        m.payload[20..24],
        [&40001u16.to_be_bytes()[..], &80u16.to_be_bytes()].concat()
    );

    // Out of descriptors on the host: the guest's connect fails at once
    // (RST), not as "host unreachable".
    h.input(syn(40003));
    let id = connect_id(&mut h);
    h.s.tcp_connect_failed(id, HostError::NoResources, h.now);
    assert_eq!(tcp_of(&h.one_frame()).flags, RST | ACK);
    assert!(h.s.tcp_phases().is_empty());

    h.input(syn(40002));
    let id = connect_id(&mut h);
    h.advance(Duration::from_secs(61));
    let ip = ip_of(&h.one_frame());
    assert_eq!((ip.proto, ip.payload[0], ip.payload[1]), (PROTO_ICMP, 3, 1));
    assert_eq!(h.ops(), vec![HostOp::TcpClose { id, abort: true }]);
    assert!(h.s.tcp_phases().is_empty());
}

#[test]
fn tcp_stray_segments_get_rst() {
    let mut h = H::new();
    h.input(guest_tcp(40000, REMOTE, 100, 5555, ACK, 1000, b"stale"));
    let r = tcp_of(&h.one_frame());
    assert_eq!((r.flags, r.seq), (RST, 5555));
    h.input(guest_tcp(40000, REMOTE, 100, 0, FIN, 1000, b"x"));
    let r = tcp_of(&h.one_frame());
    assert_eq!((r.flags, r.ack), (RST | ACK, 102));
    h.input(guest_tcp(40000, REMOTE, 100, 0, RST, 1000, &[]));
    assert!(h.frames().is_empty(), "never answer a RST");
    // TCP to the DNS address: port 53 relays, anything else is refused.
    h.input(guest_tcp_opts(
        40000,
        SocketAddrV4::new(DNS, 80),
        1,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    assert_eq!(tcp_of(&h.one_frame()).flags, RST | ACK);
    h.input(guest_tcp_opts(
        40000,
        SocketAddrV4::new(DNS, 53),
        1,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    assert!(matches!(
        h.ops()[..],
        [HostOp::TcpConnect { dst: UPSTREAM, .. }]
    ));
}

#[test]
fn tcp_connection_limit() {
    let mut h = H::new();
    for i in 0..MAX_TCP_CONNS as u16 {
        h.input(guest_tcp_opts(
            10000 + i,
            REMOTE,
            1,
            0,
            SYN,
            1000,
            &[],
            None,
            None,
        ));
    }
    assert_eq!(h.ops().len(), MAX_TCP_CONNS);
    assert!(h.frames().is_empty());
    h.input(guest_tcp_opts(
        9999,
        REMOTE,
        1,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    assert_eq!(tcp_of(&h.one_frame()).flags, RST | ACK);
    assert!(h.ops().is_empty());
    // Host forwards have a budget of their own.
    assert!(h.s.tcp_fwd_room());
    assert!(h.s.tcp_fwd_accepted(22, h.now).is_some());
}

/// Clients of a forwarded port (reachable from the LAN by default) cannot
/// take the slots the guest needs for its own connections.
#[test]
fn tcp_hostfwd_has_its_own_budget() {
    let mut h = H::new();
    let ids: Vec<FlowId> = (0..MAX_TCP_FWD_CONNS)
        .map(|_| h.s.tcp_fwd_accepted(22, h.now).unwrap())
        .collect();
    assert!(!h.s.tcp_fwd_room());
    assert!(h.s.tcp_fwd_accepted(22, h.now).is_none());
    let syns: Vec<Seg> = h.frames().iter().map(|f| tcp_of(f)).collect();
    assert_eq!(syns.len(), MAX_TCP_FWD_CONNS);

    // Guest-initiated connections still work.
    h.input(guest_tcp_opts(
        40000,
        REMOTE,
        1,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    assert!(matches!(h.ops()[..], [HostOp::TcpConnect { .. }]));

    // A forwarded connection that ends frees its slot.
    h.input(guest_tcp(
        22,
        syns[0].src,
        0,
        syns[0].seq.wrapping_add(1),
        RST | ACK,
        0,
        &[],
    ));
    assert_eq!(
        h.ops(),
        vec![HostOp::TcpClose {
            id: ids[0],
            abort: true
        }]
    );
    assert!(h.s.tcp_fwd_room());
    assert!(h.s.tcp_fwd_accepted(22, h.now).is_some());
    assert!(!h.s.tcp_fwd_room());
}

#[test]
fn lowered_limits_cap_tcp() {
    let mut h = H::new();
    h.s.set_limits(Limits {
        tcp: 2,
        tcp_fwd: 1,
        udp: 2,
    });
    for sport in [40000, 40001] {
        h.input(guest_tcp_opts(
            sport,
            REMOTE,
            1,
            0,
            SYN,
            1000,
            &[],
            None,
            None,
        ));
    }
    assert_eq!(h.ops().len(), 2);
    h.input(guest_tcp_opts(
        40002,
        REMOTE,
        1,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    assert_eq!(tcp_of(&h.one_frame()).flags, RST | ACK);
    assert!(h.ops().is_empty());
    assert!(h.s.tcp_fwd_accepted(22, h.now).is_some());
    assert!(h.s.tcp_fwd_accepted(22, h.now).is_none());
}

#[test]
fn limits_scale_to_descriptors() {
    let d = Limits::DEFAULT;
    assert_eq!(Limits::for_fds(4096 - 70), d);
    assert_eq!(Limits::for_fds(d.fds()), d);
    let half = Limits::for_fds(d.fds() / 2);
    assert_eq!(
        (half.tcp, half.tcp_fwd, half.udp),
        (d.tcp / 2, d.tcp_fwd / 2, d.udp / 2)
    );
    assert!(half.fds() <= d.fds() / 2);
    // macOS's default soft limit of 256, if the hard limit cannot be raised.
    let small = Limits::for_fds(256 - 64 - 4);
    assert!(small.fds() <= 188 && small.tcp > 0 && small.udp > 0);
    assert_eq!(
        Limits::for_fds(0),
        Limits {
            tcp: 1,
            tcp_fwd: 1,
            udp: 1
        }
    );
}

#[test]
fn tcp_syn_ack_retransmitted_when_lost() {
    let mut h = H::new();
    h.input(guest_tcp_opts(
        40000,
        REMOTE,
        ISN,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    let [HostOp::TcpConnect { id, .. }] = h.ops()[..] else {
        panic!()
    };
    h.s.tcp_connected(id, h.now);
    let first = tcp_of(&h.one_frame());
    h.advance(Duration::from_millis(1100));
    let again = tcp_of(&h.one_frame());
    assert_eq!((again.flags, again.seq), (SYN | ACK, first.seq));
    // The guest's retransmitted SYN also gets the SYN-ACK again.
    h.input(guest_tcp_opts(
        40000,
        REMOTE,
        ISN,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    assert_eq!(tcp_of(&h.one_frame()).flags, SYN | ACK);
}

#[test]
fn tcp_hostfwd_active_open() {
    let mut h = H::new();
    let id = h.s.tcp_fwd_accepted(22, h.now).unwrap();
    let syn = tcp_of(&h.one_frame());
    assert_eq!((syn.flags, syn.dport, *syn.src.ip()), (SYN, 22, GW));
    assert!(syn.src.port() >= 49152);
    assert_eq!((syn.mss, syn.wscale), (Some(MSS), Some(3)));
    assert_eq!(
        h.s.tcp_read_budget(id),
        0,
        "nothing is read before the guest accepts"
    );

    let gisn = 0x1000_0000u32;
    h.input(guest_tcp_opts(
        22,
        syn.src,
        gisn,
        syn.seq.wrapping_add(1),
        SYN | ACK,
        1000,
        &[],
        Some(1400),
        Some(7),
    ));
    let ack = tcp_of(&h.one_frame());
    assert_eq!(
        (ack.flags, ack.seq, ack.ack),
        (ACK, syn.seq.wrapping_add(1), gisn.wrapping_add(1))
    );
    assert_eq!(h.s.tcp_read_budget(id), 1000);

    // The guest's SSH banner reaches the host; the host's data is segmented
    // at the guest's MSS.
    h.input(guest_tcp(
        22,
        syn.src,
        gisn.wrapping_add(1),
        ack.seq,
        ACK | PSH,
        1000,
        b"SSH-2.0-x\r\n",
    ));
    assert_eq!(to_host(&h, id), b"SSH-2.0-x\r\n");
    h.frames();
    h.input(guest_tcp(
        22,
        syn.src,
        gisn.wrapping_add(12),
        ack.seq,
        ACK,
        100,
        &[],
    ));
    assert_eq!(h.s.tcp_read_budget(id), 100 << 7);
    h.s.tcp_host_data(id, &pattern(3000, 8), h.now);
    let lens: Vec<usize> = h.frames().iter().map(|f| tcp_of(f).payload.len()).collect();
    assert_eq!(lens, [1400, 1400, 200]);
}

#[test]
fn tcp_hostfwd_refused_or_unanswered() {
    let mut h = H::new();
    let id = h.s.tcp_fwd_accepted(22, h.now).unwrap();
    let syn = tcp_of(&h.one_frame());
    h.input(guest_tcp(
        22,
        syn.src,
        0,
        syn.seq.wrapping_add(1),
        RST | ACK,
        0,
        &[],
    ));
    assert_eq!(h.ops(), vec![HostOp::TcpClose { id, abort: true }]);
    assert!(h.s.tcp_phases().is_empty());

    let id = h.s.tcp_fwd_accepted(22, h.now).unwrap();
    let syn = tcp_of(&h.one_frame());
    let mut retries = 0;
    for _ in 0..200 {
        h.advance(Duration::from_secs(1));
        for f in h.frames() {
            let s = tcp_of(&f);
            assert_eq!((s.flags, s.seq), (SYN, syn.seq));
            retries += 1;
        }
    }
    assert_eq!(retries, 6);
    assert_eq!(h.ops(), vec![HostOp::TcpClose { id, abort: true }]);
}

#[test]
fn tcp_time_wait_pair_can_be_reused() {
    let mut h = H::new();
    let mut c = open(&mut h, 40000, REMOTE, 65535, None);
    h.s.tcp_host_eof(c.id, h.now);
    h.frames();
    c.sseq = c.sseq.wrapping_add(1);
    c.ack(&mut h, c.sseq, 65535);
    let f = c.seg(ACK | FIN, &[]);
    h.input(f);
    h.frames();
    h.ops();
    assert_eq!(h.s.tcp_phases(), vec![Phase::TimeWait]);
    h.input(guest_tcp_opts(
        40000,
        REMOTE,
        7,
        0,
        SYN,
        1000,
        &[],
        None,
        None,
    ));
    assert!(matches!(h.ops()[..], [HostOp::TcpConnect { .. }]));
    assert_eq!(h.s.tcp_phases(), vec![Phase::Connecting]);
}
