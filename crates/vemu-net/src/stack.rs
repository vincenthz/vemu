//! The sans-IO core of the user-mode network.
//!
//! [`Stack`] turns Ethernet frames from the guest into frames for the guest
//! and [`HostOp`]s for the driver, which owns the host sockets and feeds
//! socket events back through the `udp_*`, `icmp_*` and `tcp_*` methods. Time
//! is always passed in, so the core is deterministic and unit-testable with
//! synthetic frames.
//!
//! Virtual network (qemu's defaults): the guest is 10.0.2.15 (via DHCP), the
//! gateway 10.0.2.2 is the host itself (its traffic goes to 127.0.0.1), and
//! 10.0.2.3 relays DNS to the host's resolver. Both virtual hosts answer ARP
//! with [`ROUTER_MAC`]. Everything else outside the /24 is NATed through host
//! sockets: UDP through one unconnected socket per guest source port
//! (endpoint-independent mapping and filtering, "full cone", as in qemu's
//! slirp), DNS through a socket per guest port connected to the upstream
//! resolver, ICMP echo through one shared socket, and TCP terminated and
//! proxied ([`crate::tcp`]). IPv6 and other ethertypes are ignored without a
//! trace. Packets for the guest larger than the 1500-byte MTU (UDP datagrams
//! up to 64 KiB) are sent as IPv4 fragments.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use crate::config::UserNetConfig;
use crate::dhcp::{self, DhcpConfig};
use crate::dns;
use crate::tcp::{Phase, TcpConn};
use crate::wire::{self, *};

/// MAC of the virtual router (and of the virtual DNS server), as in qemu's
/// slirp: 52:55 followed by the gateway address.
pub const ROUTER_MAC: [u8; 6] = [0x52, 0x55, 10, 0, 2, 2];

/// Frames queued for the guest beyond this are dropped (TCP retransmits).
const MAX_QUEUED_FRAMES: usize = 1024;
/// Largest IPv4 packet on the guest link; larger ones are fragmented.
pub const MTU: usize = 1500;
/// UDP host sockets (NAT mappings plus DNS relay flows) at once.
pub const MAX_UDP_SOCKS: usize = 256;
/// Host-forwarded UDP clients tracked at once (they share the rule's socket).
const MAX_UDP_FWD_FLOWS: usize = 256;
const MAX_ICMP_FLOWS: usize = 256;
/// Echo requests remembered at once when the sequence number carries the
/// NAT mapping ([`Stack::set_icmp_ident_rewritten`]): one per request, not
/// per flow, so more of them (30 s of `ping -i 0.05`).
const MAX_ICMP_REQS: usize = 1024;
/// Guest-initiated TCP connections at once (each buffers at most 512 KiB).
pub const MAX_TCP_CONNS: usize = 256;
/// Host-forwarded TCP connections at once. A budget of their own, so clients
/// of a forwarded port (reachable from the LAN by default) cannot use up the
/// slots the guest needs for its own connections, and vice versa.
pub const MAX_TCP_FWD_CONNS: usize = 128;
/// A UDP NAT mapping expires after this long without traffic in either
/// direction (qemu's slirp uses 240 s; RFC 4787 REQ-5 asks for at least 2
/// minutes).
pub const UDP_IDLE: Duration = Duration::from_secs(240);
/// DNS relay flows: one query and its answer, normally.
const DNS_IDLE: Duration = Duration::from_secs(10);
const ICMP_IDLE: Duration = Duration::from_secs(30);
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Largest UDP payload an IPv4 datagram can carry (sent fragmented).
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize - IPV4_HDR_LEN - UDP_HDR_LEN;

/// How many flows that each hold a host file descriptor the stack keeps at
/// once. The driver sizes these to the process's open-file limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Guest-initiated TCP connections (one host socket each).
    pub tcp: usize,
    /// Host-forwarded TCP connections (one accepted socket each).
    pub tcp_fwd: usize,
    /// UDP host sockets: NAT mappings and DNS relay flows.
    pub udp: usize,
}

impl Limits {
    pub const DEFAULT: Limits = Limits {
        tcp: MAX_TCP_CONNS,
        tcp_fwd: MAX_TCP_FWD_CONNS,
        udp: MAX_UDP_SOCKS,
    };

    /// The default caps, scaled down in proportion when they would need more
    /// than `fds` descriptors in total (each cap stays at least 1).
    pub fn for_fds(fds: usize) -> Limits {
        let d = Limits::DEFAULT;
        let want = d.fds();
        if fds >= want {
            return d;
        }
        let scale = |n: usize| (n * fds / want).max(1);
        Limits {
            tcp: scale(d.tcp),
            tcp_fwd: scale(d.tcp_fwd),
            udp: scale(d.udp),
        }
    }

    /// Host descriptors these caps allow at once.
    pub fn fds(&self) -> usize {
        self.tcp + self.tcp_fwd + self.udp
    }
}
/// Source ports for host-forwarded flows, as seen by the guest.
const EPHEMERAL: std::ops::RangeInclusive<u16> = 49152..=65535;

/// Identifies a host socket the driver keeps for a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowId(pub u64);

/// Socket work for the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOp {
    /// Create a UDP socket for flow `id` on an ephemeral port: unconnected
    /// (a NAT mapping: datagrams go out with `to` and come back from anyone)
    /// or, with `connect`, connected to that address (DNS relay).
    UdpOpen {
        id: FlowId,
        connect: Option<SocketAddrV4>,
    },
    /// Send on flow `id`'s socket: to `to`, or to the connected peer.
    UdpSend {
        id: FlowId,
        to: Option<SocketAddrV4>,
        data: Vec<u8>,
    },
    UdpClose {
        id: FlowId,
    },
    /// Send from the host-forward socket of rule `rule` to `to`.
    UdpFwdSend {
        rule: usize,
        to: SocketAddrV4,
        data: Vec<u8>,
    },
    /// Send an ICMP message (echo request) through the shared ICMP socket.
    IcmpSend {
        dst: Ipv4Addr,
        msg: Vec<u8>,
    },
    /// Start a non-blocking connect for flow `id`; report the outcome with
    /// [`Stack::tcp_connected`] or [`Stack::tcp_connect_failed`].
    TcpConnect {
        id: FlowId,
        dst: SocketAddrV4,
    },
    TcpShutdownWrite {
        id: FlowId,
    },
    /// Close the socket; `abort` resets it (SO_LINGER 0).
    TcpClose {
        id: FlowId,
        abort: bool,
    },
}

/// A host socket failure, as reported by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    Refused,
    HostUnreachable,
    NetUnreachable,
    TimedOut,
    /// Out of file descriptors or buffers on the host (EMFILE, ENFILE,
    /// ENOBUFS): a local condition, not the remote's answer.
    NoResources,
    Other,
}

impl HostError {
    pub fn from_io(e: &std::io::Error) -> HostError {
        match e.raw_os_error() {
            Some(libc::ECONNREFUSED) => HostError::Refused,
            Some(libc::EHOSTUNREACH | libc::EHOSTDOWN) => HostError::HostUnreachable,
            Some(libc::ENETUNREACH | libc::ENETDOWN | libc::EADDRNOTAVAIL) => {
                HostError::NetUnreachable
            }
            Some(libc::ETIMEDOUT) => HostError::TimedOut,
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS) => HostError::NoResources,
            _ => HostError::Other,
        }
    }
}

/// The link layer toward the guest: addressing and the outgoing frame queue.
pub struct Link {
    pub guest_mac: [u8; 6],
    pub guest_ip: Ipv4Addr,
    ip_id: u16,
    frames: VecDeque<Vec<u8>>,
}

impl Link {
    fn push(&mut self, frame: Vec<u8>) {
        if self.frames.len() < MAX_QUEUED_FRAMES {
            self.frames.push_back(frame);
        }
    }

    /// Queue an IPv4 frame, fragmented to the MTU if needed. The fragments
    /// of one packet are queued all together or not at all.
    fn push_ip(&mut self, frame: Vec<u8>) {
        if frame.len() - ETH_HDR_LEN <= MTU {
            return self.push(frame);
        }
        let frags = wire::fragment(frame, MTU);
        if self.frames.len() + frags.len() <= MAX_QUEUED_FRAMES {
            self.frames.extend(frags);
        }
    }

    /// Send an IPv4 packet from `src` to the guest (or to `dst`/`eth_dst`).
    fn send_ip(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        eth_dst: [u8; 6],
        proto: u8,
        capacity: usize,
        l4: impl FnOnce(&mut Vec<u8>),
    ) {
        self.ip_id = self.ip_id.wrapping_add(1);
        let out = Ipv4Out {
            eth_dst,
            eth_src: ROUTER_MAC,
            src,
            dst,
            proto,
            id: self.ip_id,
        };
        let f = ipv4_frame(&out, capacity, l4);
        self.push_ip(f);
    }

    /// Send a TCP segment from `from` (whose port is in `h`) to the guest.
    pub fn send_tcp(
        &mut self,
        from: SocketAddrV4,
        guest_port: u16,
        h: &TcpHeader,
        payload: [&[u8]; 2],
    ) {
        debug_assert_eq!((h.sport, h.dport), (from.port(), guest_port));
        let len = TCP_HDR_LEN + 8 + payload[0].len() + payload[1].len();
        let (dst, mac) = (self.guest_ip, self.guest_mac);
        self.send_ip(*from.ip(), dst, mac, PROTO_TCP, len, |f| {
            write_tcp(f, h, payload)
        });
    }

    fn send_udp(&mut self, from: SocketAddrV4, guest_port: u16, payload: &[u8]) {
        let (dst, mac) = (self.guest_ip, self.guest_mac);
        self.send_ip(
            *from.ip(),
            dst,
            mac,
            PROTO_UDP,
            UDP_HDR_LEN + payload.len(),
            |f| write_udp(f, from.port(), guest_port, payload),
        );
    }

    fn send_icmp(&mut self, src: Ipv4Addr, ty: u8, code: u8, rest: [u8; 4], payload: &[u8]) {
        let (dst, mac) = (self.guest_ip, self.guest_mac);
        self.send_ip(
            src,
            dst,
            mac,
            PROTO_ICMP,
            ICMP_HDR_LEN + payload.len(),
            |f| write_icmp(f, ty, code, rest, payload),
        );
    }
}

/// What a TCP connection needs to act: the link and the op queue.
pub struct Ctx<'a> {
    pub link: &'a mut Link,
    pub ops: &'a mut VecDeque<HostOp>,
    pub now: Instant,
}

/// A flow as the guest sees it: its port and the remote endpoint it talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    guest_port: u16,
    remote: SocketAddrV4,
}

/// A UDP flow as the stack tracks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UdpKey {
    /// The NAT mapping of a guest source port: one unconnected host socket
    /// for every destination, which accepts replies from any address
    /// (endpoint-independent mapping and filtering, like qemu's slirp).
    Nat(u16),
    /// DNS relay flow from a guest port to the virtual DNS server: a host
    /// socket connected to the upstream resolver, so replies are known to
    /// come from it and are sent to the guest from 10.0.2.3.
    Dns(u16),
    /// A host-forward client mapped to a virtual 10.0.2.2:port.
    Fwd(FlowKey),
}

enum UdpKind {
    /// Our own host socket.
    Sock(FlowId),
    /// Datagrams from `client` arriving at host-forward rule `rule`.
    Fwd { rule: usize, client: SocketAddrV4 },
}

struct UdpFlow {
    kind: UdpKind,
    last_used: Instant,
    idle: Duration,
    /// IP header + 8 bytes of the guest's last datagram, for ICMP errors.
    quote: Vec<u8>,
    /// Where the guest's last datagram went (as the guest addressed it).
    remote: SocketAddrV4,
}

struct IcmpFlow {
    nat_id: u16,
    host: Ipv4Addr,
    last_used: Instant,
}

/// Echo NAT for hosts whose ICMP datagram sockets choose the echo identifier
/// themselves. Linux overwrites it with the socket's "port" on send and
/// delivers to the socket only replies carrying it, so the identifier cannot
/// tell the guest's flows apart. The sequence number, which the kernel keeps,
/// carries the mapping instead: each request gets a fresh one, and the
/// reply's (source, sequence) finds the guest's identifier and sequence.
struct IcmpSeqNat {
    next_seq: u16,
    /// (host, NAT sequence) -> the guest's request.
    reqs: HashMap<(Ipv4Addr, u16), EchoReq>,
    /// Requests in the order they were sent (`generation` tells a live entry from
    /// one whose key was reused since), for expiry and the cap.
    order: VecDeque<((Ipv4Addr, u16), u64, Instant)>,
    next_generation: u64,
}

struct EchoReq {
    guest_dst: Ipv4Addr,
    guest_id: u16,
    guest_seq: u16,
    generation: u64,
}

impl IcmpSeqNat {
    fn new(first_seq: u16) -> IcmpSeqNat {
        IcmpSeqNat {
            next_seq: first_seq,
            reqs: HashMap::new(),
            order: VecDeque::new(),
            next_generation: 0,
        }
    }

    /// Remember a request to `host` and return the sequence number to send
    /// it with. A key still in use 65536 requests later is simply reused.
    fn insert(&mut self, host: Ipv4Addr, req: (Ipv4Addr, u16, u16), now: Instant) -> u16 {
        while self.order.len() >= MAX_ICMP_REQS {
            self.pop_oldest();
        }
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        let generation = self.next_generation;
        self.next_generation += 1;
        let (guest_dst, guest_id, guest_seq) = req;
        self.reqs.insert(
            (host, seq),
            EchoReq {
                guest_dst,
                guest_id,
                guest_seq,
                generation,
            },
        );
        self.order.push_back(((host, seq), generation, now));
        seq
    }

    fn pop_oldest(&mut self) {
        if let Some((key, generation, _)) = self.order.pop_front()
            && self
                .reqs
                .get(&key)
                .is_some_and(|r| r.generation == generation)
        {
            self.reqs.remove(&key);
        }
    }

    /// Forget requests sent `ICMP_IDLE` or longer ago.
    fn expire(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|(_, _, t)| now.saturating_duration_since(*t) >= ICMP_IDLE)
        {
            self.pop_oldest();
        }
    }
}

/// Where a guest packet is headed.
enum Dest {
    /// The gateway: the host itself (127.0.0.1).
    Gateway,
    /// The virtual DNS server.
    Dns,
    /// Anywhere else outside the virtual network.
    Host(Ipv4Addr),
    /// The virtual network itself, broadcast, multicast, loopback...
    Drop,
}

pub struct Stack {
    gateway: Ipv4Addr,
    dns: Ipv4Addr,
    net: Ipv4Addr,
    netmask: Ipv4Addr,
    link: Link,
    ops: VecDeque<HostOp>,
    dns_upstream: Option<SocketAddrV4>,
    icmp_available: bool,
    rng: u64,
    next_id: u64,
    limits: Limits,
    udp: HashMap<UdpKey, UdpFlow>,
    /// Flows with a host socket (`UdpKind::Sock`).
    udp_ids: HashMap<FlowId, UdpKey>,
    udp_fwd: HashMap<(usize, SocketAddrV4), FlowKey>,
    icmp: HashMap<(Ipv4Addr, u16), IcmpFlow>,
    icmp_nat: HashMap<(Ipv4Addr, u16), (Ipv4Addr, u16)>,
    /// Set when the host's ICMP socket picks the echo identifier.
    icmp_seq_nat: Option<IcmpSeqNat>,
    tcp: HashMap<FlowKey, FlowId>,
    conns: HashMap<FlowId, TcpConn>,
    /// How many of `conns` are host-forwarded.
    tcp_fwd_count: usize,
    next_sweep: Option<Instant>,
}

impl Stack {
    /// `seed` drives initial sequence numbers, NAT ids and ports.
    pub fn new(cfg: &UserNetConfig, seed: u64) -> Stack {
        Stack {
            gateway: cfg.gateway,
            dns: cfg.dns,
            net: cfg.net,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            link: Link {
                guest_mac: cfg.guest_mac,
                guest_ip: cfg.guest,
                ip_id: 0,
                frames: VecDeque::new(),
            },
            ops: VecDeque::new(),
            dns_upstream: None,
            icmp_available: true,
            rng: seed | 1,
            next_id: 1,
            limits: Limits::DEFAULT,
            udp: HashMap::new(),
            udp_ids: HashMap::new(),
            udp_fwd: HashMap::new(),
            icmp: HashMap::new(),
            icmp_nat: HashMap::new(),
            icmp_seq_nat: None,
            tcp: HashMap::new(),
            conns: HashMap::new(),
            tcp_fwd_count: 0,
            next_sweep: None,
        }
    }

    /// Caps on flows holding host descriptors (default [`Limits::DEFAULT`]).
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Where queries to the virtual DNS server go (`None`: answer SERVFAIL).
    pub fn set_dns_upstream(&mut self, upstream: Option<SocketAddrV4>) {
        self.dns_upstream = upstream;
    }

    /// Whether the driver has an ICMP socket. Without one, echo requests to
    /// the gateway are answered locally and others dropped.
    pub fn set_icmp_available(&mut self, available: bool) {
        self.icmp_available = available;
    }

    /// Whether the host's ICMP socket replaces the echo identifier with its
    /// own (Linux, where it is the socket's local "port"; macOS keeps the
    /// identifier as sent). The NAT then maps echoes by sequence number
    /// instead of identifier; the guest sees no difference.
    pub fn set_icmp_ident_rewritten(&mut self, rewritten: bool) {
        if rewritten != self.icmp_seq_nat.is_some() {
            self.icmp_seq_nat = rewritten.then(|| IcmpSeqNat::new(self.random() as u16));
        }
    }

    /// Next frame for the guest.
    pub fn pop_frame(&mut self) -> Option<Vec<u8>> {
        self.link.frames.pop_front()
    }

    /// Next socket operation for the driver.
    pub fn pop_op(&mut self) -> Option<HostOp> {
        self.ops.pop_front()
    }

    /// When [`on_timer`](Self::on_timer) next needs to run.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.conns
            .values()
            .filter_map(TcpConn::deadline)
            .chain(self.next_sweep)
            .min()
    }

    fn random(&mut self) -> u64 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn alloc_id(&mut self) -> FlowId {
        let id = FlowId(self.next_id);
        self.next_id += 1;
        id
    }

    fn classify(&self, dst: Ipv4Addr) -> Dest {
        let in_net = u32::from(dst) & u32::from(self.netmask) == u32::from(self.net);
        if dst == self.gateway {
            Dest::Gateway
        } else if dst == self.dns {
            Dest::Dns
        } else if in_net
            || dst.is_broadcast()
            || dst.is_multicast()
            || dst.is_loopback()
            || dst.octets()[0] == 0
            || dst.octets()[0] >= 240
        {
            Dest::Drop
        } else {
            Dest::Host(dst)
        }
    }

    // ------------------------------------------------------------------
    // Frames from the guest
    // ------------------------------------------------------------------

    /// Process one Ethernet frame transmitted by the guest. Call
    /// [`flush`](Self::flush) after a batch of frames.
    pub fn handle_frame(&mut self, frame: &[u8], now: Instant) {
        let Some(eth) = EthFrame::parse(frame) else {
            return;
        };
        if eth.dst != ROUTER_MAC && eth.dst != MAC_BROADCAST {
            return;
        }
        match eth.ethertype {
            ETHERTYPE_ARP => self.handle_arp(&eth),
            ETHERTYPE_IPV4 => self.handle_ipv4(&eth, now),
            _ => {} // IPv6 and anything else: ignored quietly
        }
    }

    fn learn_mac(&mut self, mac: [u8; 6]) {
        if mac[0] & 1 == 0 && mac != [0; 6] {
            self.link.guest_mac = mac;
        }
    }

    fn handle_arp(&mut self, eth: &EthFrame<'_>) {
        let Some(arp) = ArpPacket::parse(eth.payload) else {
            return;
        };
        if arp.sender_ip == self.link.guest_ip {
            self.learn_mac(arp.sender_mac);
        }
        let ours = arp.target_ip == self.gateway || arp.target_ip == self.dns;
        if arp.op == ARP_REQUEST && ours && !arp.sender_ip.is_unspecified() {
            let reply = ArpPacket {
                op: ARP_REPLY,
                sender_mac: ROUTER_MAC,
                sender_ip: arp.target_ip,
                target_mac: arp.sender_mac,
                target_ip: arp.sender_ip,
            };
            self.link.push(reply.frame(arp.sender_mac));
        }
    }

    fn handle_ipv4(&mut self, eth: &EthFrame<'_>, now: Instant) {
        let Some(ip) = Ipv4Packet::parse(eth.payload) else {
            return;
        };
        if ip.is_fragment {
            return; // no reassembly; we send with DF so the guest's PMTU is 1500
        }
        if ip.src == self.link.guest_ip {
            self.learn_mac(eth.src);
        }
        match ip.proto {
            PROTO_UDP => self.handle_udp(&ip, eth.src, now),
            PROTO_TCP if ip.src == self.link.guest_ip => self.handle_tcp(&ip, now),
            PROTO_ICMP if ip.src == self.link.guest_ip => self.handle_icmp(&ip, now),
            _ => {}
        }
    }

    /// Forwarding to a real host decrements the TTL: answer "time exceeded"
    /// (so traceroute shows the gateway as the first hop) when it expires.
    fn ttl_expired(&mut self, ip: &Ipv4Packet<'_>) -> bool {
        if ip.ttl > 1 {
            return false;
        }
        let quote = ip.icmp_quote();
        self.link
            .send_icmp(self.gateway, icmp_type::TIME_EXCEEDED, 0, [0; 4], &quote);
        true
    }

    fn icmp_unreachable(&mut self, src: Ipv4Addr, code: u8, quote: &[u8]) {
        self.link
            .send_icmp(src, icmp_type::DEST_UNREACHABLE, code, [0; 4], quote);
    }

    // ------------------------------------------------------------------
    // UDP
    // ------------------------------------------------------------------

    fn handle_udp(&mut self, ip: &Ipv4Packet<'_>, eth_src: [u8; 6], now: Instant) {
        let Some(udp) = UdpDatagram::parse(ip) else {
            return;
        };
        if udp.dport == dhcp::SERVER_PORT && udp.sport == dhcp::CLIENT_PORT {
            self.learn_mac(eth_src);
            self.handle_dhcp(udp.payload);
            return;
        }
        if ip.src != self.link.guest_ip || udp.dport == 0 {
            return;
        }
        let remote = SocketAddrV4::new(ip.dst, udp.dport);
        let fwd_key = UdpKey::Fwd(FlowKey {
            guest_port: udp.sport,
            remote,
        });
        if let Some(flow) = self.udp.get_mut(&fwd_key) {
            // The guest answers a host-forward client.
            flow.last_used = now;
            if let UdpKind::Fwd { rule, client } = flow.kind {
                self.ops.push_back(HostOp::UdpFwdSend {
                    rule,
                    to: client,
                    data: udp.payload.to_vec(),
                });
            }
            return;
        }

        let (key, to, idle) = match self.classify(ip.dst) {
            Dest::Gateway => (
                UdpKey::Nat(udp.sport),
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, udp.dport)),
                UDP_IDLE,
            ),
            Dest::Dns if udp.dport == dns::DNS_PORT => {
                if self.dns_upstream.is_none() {
                    if let Some(r) = dns::servfail(udp.payload) {
                        self.link.send_udp(remote, udp.sport, &r);
                    }
                    return;
                }
                (UdpKey::Dns(udp.sport), None, DNS_IDLE)
            }
            Dest::Dns => {
                self.icmp_unreachable(self.dns, unreach_code::PORT, &ip.icmp_quote());
                return;
            }
            Dest::Host(a) => {
                if self.ttl_expired(ip) {
                    return;
                }
                (
                    UdpKey::Nat(udp.sport),
                    Some(SocketAddrV4::new(a, udp.dport)),
                    UDP_IDLE,
                )
            }
            Dest::Drop => return,
        };
        let quote = ip.icmp_quote();
        let id = match self.udp.get_mut(&key) {
            Some(flow) => {
                flow.last_used = now;
                flow.quote = quote;
                flow.remote = remote;
                match flow.kind {
                    UdpKind::Sock(id) => id,
                    UdpKind::Fwd { .. } => return, // not under a NAT or DNS key
                }
            }
            None => {
                if self.udp_ids.len() >= self.limits.udp {
                    self.evict_udp(|k| !matches!(k, UdpKey::Fwd(_)));
                }
                let id = self.alloc_id();
                let flow = UdpFlow {
                    kind: UdpKind::Sock(id),
                    last_used: now,
                    idle,
                    quote,
                    remote,
                };
                self.udp.insert(key, flow);
                self.udp_ids.insert(id, key);
                let connect = match key {
                    UdpKey::Dns(_) => self.dns_upstream,
                    _ => None,
                };
                self.ops.push_back(HostOp::UdpOpen { id, connect });
                self.arm_sweep(now);
                id
            }
        };
        self.ops.push_back(HostOp::UdpSend {
            id,
            to,
            data: udp.payload.to_vec(),
        });
    }

    fn handle_dhcp(&mut self, payload: &[u8]) {
        let cfg = DhcpConfig {
            server: self.gateway,
            guest: self.link.guest_ip,
            netmask: self.netmask,
            router: self.gateway,
            dns: self.dns,
        };
        let Some(reply) = dhcp::handle(&cfg, payload) else {
            return;
        };
        let len = UDP_HDR_LEN + reply.payload.len();
        self.link.send_ip(
            self.gateway,
            reply.dst_ip,
            reply.dst_mac,
            PROTO_UDP,
            len,
            |f| write_udp(f, dhcp::SERVER_PORT, dhcp::CLIENT_PORT, &reply.payload),
        );
    }

    fn remove_udp(&mut self, key: UdpKey) {
        let Some(flow) = self.udp.remove(&key) else {
            return;
        };
        match flow.kind {
            UdpKind::Sock(id) => {
                self.udp_ids.remove(&id);
                self.ops.push_back(HostOp::UdpClose { id });
            }
            UdpKind::Fwd { rule, client } => {
                self.udp_fwd.remove(&(rule, client));
            }
        }
    }

    /// Drop the least recently used flow among those `which` selects.
    fn evict_udp(&mut self, which: impl Fn(&UdpKey) -> bool) {
        if let Some(key) = self
            .udp
            .iter()
            .filter(|(k, _)| which(k))
            .min_by_key(|(_, f)| f.last_used)
            .map(|(k, _)| *k)
        {
            self.remove_udp(key);
        }
    }

    /// The address a datagram from host address `from` appears to come from
    /// in the guest: the host's loopback is the gateway (10.0.2.2, as in
    /// slirp), other hosts are themselves. `None` for sources the guest could
    /// not have talked to (they would look like hosts on its own network).
    fn guest_visible(&self, from: SocketAddrV4) -> Option<SocketAddrV4> {
        if from.ip().is_loopback() {
            return Some(SocketAddrV4::new(self.gateway, from.port()));
        }
        matches!(self.classify(*from.ip()), Dest::Host(_)).then_some(from)
    }

    /// A datagram from `from` arrived on flow `id`'s host socket.
    pub fn udp_received(&mut self, id: FlowId, from: SocketAddrV4, data: &[u8], now: Instant) {
        let Some(&key) = self.udp_ids.get(&id) else {
            return;
        };
        if data.len() > MAX_UDP_PAYLOAD {
            return;
        }
        let (guest_port, src) = match key {
            // Connected to the upstream resolver: whatever arrives is its answer.
            UdpKey::Dns(port) => (port, SocketAddrV4::new(self.dns, dns::DNS_PORT)),
            UdpKey::Nat(port) => match self.guest_visible(from) {
                Some(src) => (port, src),
                None => return,
            },
            UdpKey::Fwd(_) => return,
        };
        if let Some(flow) = self.udp.get_mut(&key) {
            flow.last_used = now;
        }
        self.link.send_udp(src, guest_port, data);
    }

    /// Flow `id`'s socket reported an error. `fatal`: the socket is gone
    /// (could not be created), so the flow is dropped.
    pub fn udp_error(&mut self, id: FlowId, err: HostError, fatal: bool) {
        let Some(&key) = self.udp_ids.get(&id) else {
            return;
        };
        let (quote, remote) = match self.udp.get(&key) {
            Some(f) => (f.quote.clone(), f.remote),
            None => return,
        };
        match err {
            // The remote host itself said "port unreachable".
            HostError::Refused => self.icmp_unreachable(*remote.ip(), unreach_code::PORT, &quote),
            HostError::HostUnreachable => {
                self.icmp_unreachable(self.gateway, unreach_code::HOST, &quote)
            }
            HostError::NetUnreachable => {
                self.icmp_unreachable(self.gateway, unreach_code::NET, &quote)
            }
            HostError::TimedOut | HostError::NoResources | HostError::Other => {}
        }
        if fatal {
            self.udp.remove(&key);
            self.udp_ids.remove(&id);
        }
    }

    /// A datagram from `client` arrived at UDP host-forward rule `rule`.
    pub fn udp_fwd_received(
        &mut self,
        rule: usize,
        guest_port: u16,
        client: SocketAddrV4,
        data: &[u8],
        now: Instant,
    ) {
        if data.len() > MAX_UDP_PAYLOAD {
            return;
        }
        let key = match self.udp_fwd.get(&(rule, client)) {
            Some(&key) => key,
            None => {
                let Some(port) = self.free_port(|s, remote| {
                    s.udp
                        .contains_key(&UdpKey::Fwd(FlowKey { guest_port, remote }))
                }) else {
                    return;
                };
                if self.udp.len() - self.udp_ids.len() >= MAX_UDP_FWD_FLOWS {
                    self.evict_udp(|k| matches!(k, UdpKey::Fwd(_)));
                }
                let key = FlowKey {
                    guest_port,
                    remote: SocketAddrV4::new(self.gateway, port),
                };
                let flow = UdpFlow {
                    kind: UdpKind::Fwd { rule, client },
                    last_used: now,
                    idle: UDP_IDLE,
                    quote: Vec::new(),
                    remote: key.remote,
                };
                self.udp.insert(UdpKey::Fwd(key), flow);
                self.udp_fwd.insert((rule, client), key);
                self.arm_sweep(now);
                key
            }
        };
        if let Some(flow) = self.udp.get_mut(&UdpKey::Fwd(key)) {
            flow.last_used = now;
        }
        self.link.send_udp(key.remote, key.guest_port, data);
    }

    /// A random gateway port for which `used(self, gateway:port)` is false.
    fn free_port(&mut self, used: impl Fn(&Self, SocketAddrV4) -> bool) -> Option<u16> {
        let span = u64::from(EPHEMERAL.end() - EPHEMERAL.start()) + 1;
        (0..64).find_map(|_| {
            let port = EPHEMERAL.start() + (self.random() % span) as u16;
            (!used(self, SocketAddrV4::new(self.gateway, port))).then_some(port)
        })
    }

    // ------------------------------------------------------------------
    // ICMP
    // ------------------------------------------------------------------

    fn handle_icmp(&mut self, ip: &Ipv4Packet<'_>, now: Instant) {
        let Some(msg) = IcmpMessage::parse(ip.payload) else {
            return;
        };
        if msg.ty != icmp_type::ECHO_REQUEST || msg.code != 0 {
            return;
        }
        let host = match self.classify(ip.dst) {
            Dest::Dns => None,
            Dest::Gateway if !self.icmp_available => None,
            Dest::Gateway => Some(Ipv4Addr::LOCALHOST),
            Dest::Host(_) if !self.icmp_available => return,
            Dest::Host(a) => {
                if self.ttl_expired(ip) {
                    return;
                }
                Some(a)
            }
            Dest::Drop => return,
        };
        let Some(host) = host else {
            // Answered by the virtual host itself.
            self.link
                .send_icmp(ip.dst, icmp_type::ECHO_REPLY, 0, msg.rest, msg.payload);
            return;
        };

        let guest_id = msg.echo_id();
        if let Some(nat) = &mut self.icmp_seq_nat {
            let guest_seq = msg.echo_seq();
            let seq = nat.insert(host, (ip.dst, guest_id, guest_seq), now);
            let mut rest = msg.rest;
            rest[2..].copy_from_slice(&seq.to_be_bytes());
            let msg = wire::icmp_message(icmp_type::ECHO_REQUEST, 0, rest, msg.payload);
            self.ops.push_back(HostOp::IcmpSend { dst: host, msg });
            self.arm_sweep(now);
            return;
        }
        let key = (ip.dst, guest_id);
        let nat_id = match self.icmp.get_mut(&key) {
            Some(flow) => {
                flow.last_used = now;
                flow.nat_id
            }
            None => {
                if self.icmp.len() >= MAX_ICMP_FLOWS {
                    let oldest = self
                        .icmp
                        .iter()
                        .min_by_key(|(_, f)| f.last_used)
                        .map(|(k, _)| *k);
                    if let Some(k) = oldest.and_then(|k| self.icmp.remove(&k).map(|f| (k, f))) {
                        self.icmp_nat.remove(&(k.1.host, k.1.nat_id));
                    }
                }
                let Some(nat_id) = (0..64).find_map(|_| {
                    let n = self.random() as u16;
                    (!self.icmp_nat.contains_key(&(host, n))).then_some(n)
                }) else {
                    return;
                };
                self.icmp.insert(
                    key,
                    IcmpFlow {
                        nat_id,
                        host,
                        last_used: now,
                    },
                );
                self.icmp_nat.insert((host, nat_id), key);
                self.arm_sweep(now);
                nat_id
            }
        };
        let mut rest = msg.rest;
        rest[..2].copy_from_slice(&nat_id.to_be_bytes());
        let msg = wire::icmp_message(icmp_type::ECHO_REQUEST, 0, rest, msg.payload);
        self.ops.push_back(HostOp::IcmpSend { dst: host, msg });
    }

    /// An ICMP message (without IP header) from `from` on the ICMP socket.
    pub fn icmp_received(&mut self, from: Ipv4Addr, data: &[u8], now: Instant) {
        let Some(msg) = IcmpMessage::parse(data) else {
            return;
        };
        if msg.ty != icmp_type::ECHO_REPLY {
            return;
        }
        if let Some(nat) = &self.icmp_seq_nat {
            // Kept until it expires: duplicate replies map too.
            let Some(req) = nat.reqs.get(&(from, msg.echo_seq())) else {
                return;
            };
            let [a, b] = req.guest_id.to_be_bytes();
            let [c, d] = req.guest_seq.to_be_bytes();
            let guest_dst = req.guest_dst;
            self.link.send_icmp(
                guest_dst,
                icmp_type::ECHO_REPLY,
                0,
                [a, b, c, d],
                msg.payload,
            );
            return;
        }
        let Some(&(guest_dst, guest_id)) = self.icmp_nat.get(&(from, msg.echo_id())) else {
            return;
        };
        if let Some(flow) = self.icmp.get_mut(&(guest_dst, guest_id)) {
            flow.last_used = now;
        }
        let mut rest = msg.rest;
        rest[..2].copy_from_slice(&guest_id.to_be_bytes());
        self.link
            .send_icmp(guest_dst, icmp_type::ECHO_REPLY, 0, rest, msg.payload);
    }

    // ------------------------------------------------------------------
    // TCP
    // ------------------------------------------------------------------

    fn handle_tcp(&mut self, ip: &Ipv4Packet<'_>, now: Instant) {
        let Some(seg) = TcpSegment::parse(ip) else {
            return;
        };
        let key = FlowKey {
            guest_port: seg.sport,
            remote: SocketAddrV4::new(ip.dst, seg.dport),
        };
        if let Some(&id) = self.tcp.get(&key) {
            let new_syn = seg.has(tcp_flags::SYN) && !seg.has(tcp_flags::ACK);
            if !(new_syn && self.conns[&id].phase == Phase::TimeWait) {
                self.with_conn(id, now, |c, ctx| c.on_segment(&seg, ctx));
                return;
            }
            self.remove_conn(id); // a new incarnation reuses a TIME_WAIT pair
        }
        if seg.has(tcp_flags::RST) {
            return;
        }
        if !seg.has(tcp_flags::SYN) || seg.has(tcp_flags::ACK) || seg.has(tcp_flags::FIN) {
            self.reset_unknown(key, &seg);
            return;
        }
        let dst = match self.classify(ip.dst) {
            Dest::Gateway => SocketAddrV4::new(Ipv4Addr::LOCALHOST, seg.dport),
            Dest::Dns => match self.dns_upstream {
                Some(up) if seg.dport == dns::DNS_PORT => up,
                _ => return self.reset_unknown(key, &seg),
            },
            Dest::Host(a) => {
                if self.ttl_expired(ip) {
                    return;
                }
                SocketAddrV4::new(a, seg.dport)
            }
            Dest::Drop => return,
        };
        if self.conns.len() - self.tcp_fwd_count >= self.limits.tcp || seg.dport == 0 {
            return self.reset_unknown(key, &seg);
        }
        let id = self.alloc_id();
        let iss = self.random() as u32;
        let conn = TcpConn::inbound(id, key.remote, &seg, ip.icmp_quote(), iss, now);
        self.conns.insert(id, conn);
        self.tcp.insert(key, id);
        self.ops.push_back(HostOp::TcpConnect { id, dst });
    }

    /// RST for a segment that belongs to no connection (RFC 9293 3.10.7.1).
    fn reset_unknown(&mut self, key: FlowKey, seg: &TcpSegment<'_>) {
        let mut h = TcpHeader {
            sport: key.remote.port(),
            dport: key.guest_port,
            ..TcpHeader::default()
        };
        if seg.has(tcp_flags::ACK) {
            h.seq = seg.ack;
            h.flags = tcp_flags::RST;
        } else {
            h.ack = seg.seq.wrapping_add(seg.seq_len());
            h.flags = tcp_flags::RST | tcp_flags::ACK;
        }
        self.link
            .send_tcp(key.remote, key.guest_port, &h, [&[], &[]]);
    }

    /// Run `f` on connection `id` and drop the connection if it closed.
    fn with_conn<R>(
        &mut self,
        id: FlowId,
        now: Instant,
        f: impl FnOnce(&mut TcpConn, &mut Ctx<'_>) -> R,
    ) -> Option<R> {
        let conn = self.conns.get_mut(&id)?;
        let mut ctx = Ctx {
            link: &mut self.link,
            ops: &mut self.ops,
            now,
        };
        let r = f(conn, &mut ctx);
        if conn.phase == Phase::Closed {
            self.remove_conn(id);
        }
        Some(r)
    }

    fn remove_conn(&mut self, id: FlowId) {
        if let Some(c) = self.conns.remove(&id) {
            self.tcp.remove(&FlowKey {
                guest_port: c.guest_port,
                remote: c.remote,
            });
            if c.forwarded {
                self.tcp_fwd_count -= 1;
            }
        }
    }

    /// The host connect() for `id` succeeded.
    pub fn tcp_connected(&mut self, id: FlowId, now: Instant) {
        self.with_conn(id, now, |c, ctx| c.host_connected(ctx));
    }

    /// The host connect() for `id` failed; the driver dropped the socket.
    /// The guest gets RST for "refused" and when the host is out of
    /// descriptors (so the guest's connect fails at once instead of blaming
    /// the remote host), ICMP unreachable otherwise.
    pub fn tcp_connect_failed(&mut self, id: FlowId, err: HostError, now: Instant) {
        let refused = matches!(err, HostError::Refused | HostError::NoResources);
        let quote = self.with_conn(id, now, |c, ctx| {
            c.connect_failed(refused, ctx);
            std::mem::take(&mut c.syn_quote)
        });
        if let (Some(quote), false) = (quote, refused) {
            let code = if err == HostError::NetUnreachable {
                unreach_code::NET
            } else {
                unreach_code::HOST
            };
            self.icmp_unreachable(self.gateway, code, &quote);
        }
    }

    /// Bytes the driver may read from `id`'s host socket.
    pub fn tcp_read_budget(&self, id: FlowId) -> usize {
        self.conns.get(&id).map_or(0, TcpConn::read_budget)
    }

    pub fn tcp_host_data(&mut self, id: FlowId, data: &[u8], now: Instant) {
        self.with_conn(id, now, |c, ctx| c.host_data(data, ctx));
    }

    pub fn tcp_host_eof(&mut self, id: FlowId, now: Instant) {
        self.with_conn(id, now, |c, ctx| c.host_eof(ctx));
    }

    /// `id`'s host socket was reset or failed. Host data the stack already
    /// holds still goes to the guest, and so does what the driver can still
    /// read from the socket (it keeps reading, then reports the end with
    /// [`tcp_host_eof`](Self::tcp_host_eof)); the guest is reset after that
    /// and the stack then closes the socket with `TcpClose`.
    pub fn tcp_host_reset(&mut self, id: FlowId, now: Instant) {
        self.with_conn(id, now, |c, ctx| c.host_reset(ctx));
    }

    /// Guest bytes to write to `id`'s host socket.
    pub fn tcp_to_host(&self, id: FlowId) -> (&[u8], &[u8]) {
        self.conns.get(&id).map_or((&[], &[]), TcpConn::to_host)
    }

    pub fn tcp_host_wrote(&mut self, id: FlowId, n: usize, now: Instant) {
        self.with_conn(id, now, |c, ctx| c.host_wrote(n, ctx));
    }

    /// Whether another host-forwarded connection fits. While not, the
    /// driver leaves new clients in the listen backlog.
    pub fn tcp_fwd_room(&self) -> bool {
        self.tcp_fwd_count < self.limits.tcp_fwd
    }

    /// A host-forward listener accepted a connection for `guest_port`.
    /// Returns the flow id for its socket, or `None` to refuse it.
    pub fn tcp_fwd_accepted(&mut self, guest_port: u16, now: Instant) -> Option<FlowId> {
        if !self.tcp_fwd_room() {
            return None;
        }
        let port =
            self.free_port(|s, remote| s.tcp.contains_key(&FlowKey { guest_port, remote }))?;
        let remote = SocketAddrV4::new(self.gateway, port);
        let id = self.alloc_id();
        let iss = self.random() as u32;
        let mut ctx = Ctx {
            link: &mut self.link,
            ops: &mut self.ops,
            now,
        };
        let conn = TcpConn::outbound(id, remote, guest_port, iss, &mut ctx);
        self.conns.insert(id, conn);
        self.tcp.insert(FlowKey { guest_port, remote }, id);
        self.tcp_fwd_count += 1;
        Some(id)
    }

    // ------------------------------------------------------------------
    // Time
    // ------------------------------------------------------------------

    /// Send the ACKs owed for the frames handled since the last flush (one
    /// ACK per connection per batch instead of one per segment).
    pub fn flush(&mut self, now: Instant) {
        let pending: Vec<FlowId> = self
            .conns
            .iter()
            .filter(|(_, c)| c.ack_pending())
            .map(|(id, _)| *id)
            .collect();
        for id in pending {
            self.with_conn(id, now, |c, ctx| c.flush_ack(ctx));
        }
    }

    /// Run due timers: TCP retransmission/persist/TIME_WAIT/connect timeout,
    /// idle UDP and ICMP flows.
    pub fn on_timer(&mut self, now: Instant) {
        let due: Vec<FlowId> = self
            .conns
            .iter()
            .filter(|(_, c)| c.deadline().is_some_and(|d| d <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            let timed_out = self.with_conn(id, now, |c, ctx| {
                c.on_timer(ctx).then(|| std::mem::take(&mut c.syn_quote))
            });
            if let Some(Some(quote)) = timed_out {
                self.icmp_unreachable(self.gateway, unreach_code::HOST, &quote);
            }
        }
        if self.next_sweep.is_some_and(|t| t <= now) {
            self.sweep(now);
        }
    }

    /// Live TCP connections and their phases (tests).
    #[cfg(test)]
    pub fn tcp_phases(&self) -> Vec<Phase> {
        self.conns.values().map(|c| c.phase).collect()
    }

    /// Live UDP flows (tests).
    #[cfg(test)]
    pub fn udp_flow_count(&self) -> usize {
        self.udp.len()
    }

    fn arm_sweep(&mut self, now: Instant) {
        self.next_sweep.get_or_insert(now + SWEEP_INTERVAL);
    }

    fn sweep(&mut self, now: Instant) {
        let idle: Vec<UdpKey> = self
            .udp
            .iter()
            .filter(|(_, f)| now.saturating_duration_since(f.last_used) >= f.idle)
            .map(|(k, _)| *k)
            .collect();
        for key in idle {
            self.remove_udp(key);
        }
        let nat = &mut self.icmp_nat;
        self.icmp.retain(|_, f| {
            let keep = now.saturating_duration_since(f.last_used) < ICMP_IDLE;
            if !keep {
                nat.remove(&(f.host, f.nat_id));
            }
            keep
        });
        if let Some(nat) = &mut self.icmp_seq_nat {
            nat.expire(now);
        }
        let busy = !self.udp.is_empty()
            || !self.icmp.is_empty()
            || self
                .icmp_seq_nat
                .as_ref()
                .is_some_and(|n| !n.order.is_empty());
        self.next_sweep = busy.then(|| now + SWEEP_INTERVAL);
    }
}
