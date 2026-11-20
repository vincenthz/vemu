//! Integration tests: a real [`UserNet`] with real host sockets on loopback,
//! driven through a fake virtio-net frontend by a tiny guest network stack
//! written here independently of the crate's own packet code.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vemu_core::{NetBackend, NetFrontend};
use vemu_net::{HostFwd, Proto, ROUTER_MAC, UserNet, UserNetConfig};

const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const GW: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const TEST_DEADLINE: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Minimal packet code for the fake guest
// ---------------------------------------------------------------------------

mod pkt {
    use std::net::Ipv4Addr;

    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMP: u8 = 1;
    pub const FIN: u8 = 1;
    pub const SYN: u8 = 2;
    pub const RST: u8 = 4;
    pub const PSH: u8 = 8;
    pub const ACK: u8 = 16;

    /// RFC 1071 checksum over the concatenation of `parts`.
    pub fn csum(parts: &[&[u8]]) -> u16 {
        let mut b = parts.concat();
        if b.len() % 2 == 1 {
            b.push(0);
        }
        let mut s: u32 = b
            .chunks(2)
            .map(|w| (u32::from(w[0]) << 8) | u32::from(w[1]))
            .sum();
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }

    fn pseudo(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> Vec<u8> {
        let mut p = [src.octets(), dst.octets()].concat();
        p.extend_from_slice(&[0, proto]);
        p.extend_from_slice(&(len as u16).to_be_bytes());
        p
    }

    /// Ethernet + IPv4 around `l4`, whose checksum (at `csum_at`, if any)
    /// is filled in here.
    pub fn frame(
        dst_mac: [u8; 6],
        dst: Ipv4Addr,
        proto: u8,
        mut l4: Vec<u8>,
        csum_at: Option<usize>,
    ) -> Vec<u8> {
        let src = super::GUEST;
        if let Some(at) = csum_at {
            let c = if proto == ICMP {
                csum(&[&l4])
            } else {
                csum(&[&pseudo(src, dst, proto, l4.len()), &l4])
            };
            l4[at..at + 2].copy_from_slice(&c.to_be_bytes());
        }
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&dst.octets());
        let c = csum(&[&ip]);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        let mut f = dst_mac.to_vec();
        f.extend_from_slice(&super::GUEST_MAC);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&l4);
        f
    }

    pub fn udp(dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut l4 = sport.to_be_bytes().to_vec();
        l4.extend_from_slice(&dport.to_be_bytes());
        l4.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        l4.extend_from_slice(&[0, 0]);
        l4.extend_from_slice(payload);
        frame(super::ROUTER_MAC, dst, UDP, l4, Some(6))
    }

    pub fn echo_request(dst: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut l4 = vec![8, 0, 0, 0];
        l4.extend_from_slice(&id.to_be_bytes());
        l4.extend_from_slice(&seq.to_be_bytes());
        l4.extend_from_slice(payload);
        frame(super::ROUTER_MAC, dst, ICMP, l4, Some(2))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tcp(
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        syn_opts: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        // MSS 1460, NOP, window scale 7
        let opts: &[u8] = if syn_opts {
            &[2, 4, 0x05, 0xb4, 1, 3, 3, 7]
        } else {
            &[]
        };
        let mut l4 = sport.to_be_bytes().to_vec();
        l4.extend_from_slice(&dport.to_be_bytes());
        l4.extend_from_slice(&seq.to_be_bytes());
        l4.extend_from_slice(&ack.to_be_bytes());
        l4.push((((20 + opts.len()) / 4) as u8) << 4);
        l4.push(flags);
        l4.extend_from_slice(&window.to_be_bytes());
        l4.extend_from_slice(&[0, 0, 0, 0]);
        l4.extend_from_slice(opts);
        l4.extend_from_slice(payload);
        frame(super::ROUTER_MAC, dst, TCP, l4, Some(16))
    }

    /// An IPv4 packet addressed to the guest, checksums verified (the L4
    /// checksum only for unfragmented packets).
    pub struct Ip {
        pub src: Ipv4Addr,
        pub dst: Ipv4Addr,
        pub proto: u8,
        pub id: u16,
        /// Flags and fragment offset field.
        pub frag: u16,
        pub l4: Vec<u8>,
    }

    impl Ip {
        pub fn is_fragment(&self) -> bool {
            self.frag & 0x3fff != 0
        }
    }

    /// Reassemble fragments of one datagram; `None` until all have arrived.
    pub fn reassemble(frags: &[Ip]) -> Option<Ip> {
        let mut parts: Vec<&Ip> = frags.iter().collect();
        parts.sort_by_key(|p| p.frag & 0x1fff);
        let mut l4 = Vec::new();
        for p in &parts {
            if usize::from(p.frag & 0x1fff) * 8 != l4.len() {
                return None; // a hole: more to come
            }
            l4.extend_from_slice(&p.l4);
        }
        if parts.last()?.frag & 0x2000 != 0 {
            return None; // the last fragment is missing
        }
        let first = parts[0];
        assert_eq!(
            csum(&[&pseudo(first.src, first.dst, first.proto, l4.len()), &l4]),
            0,
            "L4 checksum of the reassembled datagram"
        );
        Some(Ip {
            src: first.src,
            dst: first.dst,
            proto: first.proto,
            id: first.id,
            frag: 0,
            l4,
        })
    }

    pub fn parse(f: &[u8]) -> Option<Ip> {
        if f.len() < 34 || f[12..14] != [0x08, 0x00] {
            return None;
        }
        assert_eq!(f[..6], super::GUEST_MAC);
        let ip = &f[14..];
        let ihl = usize::from(ip[0] & 15) * 4;
        assert_eq!(csum(&[&ip[..ihl]]), 0, "IPv4 header checksum");
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        let (src, dst) = (
            Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
            Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        );
        let l4 = ip[ihl..total].to_vec();
        let frag = u16::from_be_bytes([ip[6], ip[7]]);
        if frag & 0x3fff == 0 {
            match ip[9] {
                ICMP => assert_eq!(csum(&[&l4]), 0, "ICMP checksum"),
                p @ (TCP | UDP) => assert_eq!(
                    csum(&[&pseudo(src, dst, p, l4.len()), &l4]),
                    0,
                    "L4 checksum"
                ),
                _ => {}
            }
        } else {
            assert_eq!(frag & 0x4000, 0, "DF clear on fragments");
            assert!(total <= 1500, "fragments fit the MTU");
        }
        Some(Ip {
            src,
            dst,
            proto: ip[9],
            id: u16::from_be_bytes([ip[4], ip[5]]),
            frag,
            l4,
        })
    }

    pub struct Tcp {
        pub sport: u16,
        pub dport: u16,
        pub seq: u32,
        pub ack: u32,
        pub flags: u8,
        pub window: u16,
        pub wscale: Option<u8>,
        pub mss: Option<u16>,
        pub payload: Vec<u8>,
    }

    pub fn tcp_view(l4: &[u8]) -> Tcp {
        let be16 = |i: usize| u16::from_be_bytes([l4[i], l4[i + 1]]);
        let be32 = |i: usize| u32::from_be_bytes([l4[i], l4[i + 1], l4[i + 2], l4[i + 3]]);
        let off = usize::from(l4[12] >> 4) * 4;
        let (mut wscale, mut mss) = (None, None);
        let mut i = 20;
        while i < off {
            match l4[i] {
                0 => break,
                1 => i += 1,
                k => {
                    let len = usize::from(l4[i + 1]);
                    if k == 2 {
                        mss = Some(be16(i + 2));
                    }
                    if k == 3 {
                        wscale = Some(l4[i + 2]);
                    }
                    i += len;
                }
            }
        }
        Tcp {
            sport: be16(0),
            dport: be16(2),
            seq: be32(4),
            ack: be32(8),
            flags: l4[13],
            window: be16(14),
            wscale,
            mss,
            payload: l4[off..].to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Fake frontend: a NIC with a limited number of receive buffers
// ---------------------------------------------------------------------------

/// Like virtio-net: `deliver` fails when no receive buffer is posted; the
/// guest posts buffers back as it consumes frames and calls `rx_ready`.
struct FakeNic {
    tx: Mutex<Sender<Vec<u8>>>,
    credits: AtomicUsize,
    refused: AtomicUsize,
}

impl NetFrontend for FakeNic {
    fn deliver(&self, frame: &[u8]) -> bool {
        let mut c = self.credits.load(Ordering::Acquire);
        loop {
            if c == 0 {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            match self
                .credits
                .compare_exchange_weak(c, c - 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(now) => c = now,
            }
        }
        let _ = self.tx.lock().unwrap().send(frame.to_vec());
        true
    }
}

const RX_BUFFERS: usize = 32;

struct Guest {
    net: Arc<UserNet>,
    nic: Arc<FakeNic>,
    rx: Receiver<Vec<u8>>,
    started: Instant,
}

impl Guest {
    fn new(hostfwd: Vec<HostFwd>) -> Guest {
        Guest::try_new(hostfwd).expect("UserNet::new")
    }

    fn try_new(hostfwd: Vec<HostFwd>) -> std::io::Result<Guest> {
        let net = UserNet::new(UserNetConfig {
            hostfwd,
            ..UserNetConfig::default()
        })?;
        let (tx, rx) = mpsc::channel();
        let nic = Arc::new(FakeNic {
            tx: Mutex::new(tx),
            credits: AtomicUsize::new(RX_BUFFERS),
            refused: AtomicUsize::new(0),
        });
        net.attach(nic.clone());
        Ok(Guest {
            net,
            nic,
            rx,
            started: Instant::now(),
        })
    }

    fn send(&self, frame: Vec<u8>) {
        self.net.transmit(&frame);
    }

    /// Next frame for the guest (posting its buffer back), or None on timeout.
    fn recv(&self, timeout: Duration) -> Option<Vec<u8>> {
        assert!(self.started.elapsed() < TEST_DEADLINE, "test took too long");
        let f = self.rx.recv_timeout(timeout).ok()?;
        self.nic.credits.fetch_add(1, Ordering::AcqRel);
        self.net.rx_ready();
        Some(f)
    }

    /// Wait for the first packet matching `pred`.
    fn wait_for(&self, what: &str, mut pred: impl FnMut(&pkt::Ip) -> bool) -> pkt::Ip {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Some(ip) = self
                .recv(Duration::from_millis(50))
                .as_deref()
                .and_then(pkt::parse)
                && pred(&ip)
            {
                return ip;
            }
        }
        panic!("timed out waiting for {what}");
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.net.shutdown();
    }
}

// ---------------------------------------------------------------------------
// A small guest TCP endpoint
// ---------------------------------------------------------------------------

const GUEST_WSCALE: u8 = 7;
const GUEST_WINDOW: u32 = 256 * 1024;

struct GuestTcp {
    lport: u16,
    remote: SocketAddrV4,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    peer_wnd: u32,
    peer_shift: u8,
    peer_mss: usize,
    established: bool,
    /// Everything this side sends; FIN follows once all is acknowledged... or sent.
    out: Vec<u8>,
    close_after_send: bool,
    fin_sent: bool,
    fin_acked: bool,
    received: Vec<u8>,
    peer_fin: bool,
    /// Advertise a zero window and drop incoming data (a stalled reader).
    paused: bool,
    /// Payload bytes that arrived (and were dropped) while paused.
    dropped_while_paused: usize,
    /// A RST from the NAT is expected (otherwise it fails the test).
    allow_rst: bool,
    /// Bytes received when the RST came.
    rst_after: Option<usize>,
    ack_due: bool,
    last_progress: Instant,
}

impl GuestTcp {
    fn new(lport: u16, remote: SocketAddrV4, iss: u32) -> GuestTcp {
        GuestTcp {
            lport,
            remote,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            rcv_nxt: 0,
            peer_wnd: 0,
            peer_shift: 0,
            peer_mss: 536,
            established: false,
            out: Vec::new(),
            close_after_send: false,
            fin_sent: false,
            fin_acked: false,
            received: Vec::new(),
            peer_fin: false,
            paused: false,
            dropped_while_paused: 0,
            allow_rst: false,
            rst_after: None,
            ack_due: false,
            last_progress: Instant::now(),
        }
    }

    fn window(&self) -> u16 {
        if self.paused {
            0
        } else {
            (GUEST_WINDOW >> GUEST_WSCALE) as u16
        }
    }

    fn seg(&self, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        pkt::tcp(
            *self.remote.ip(),
            self.lport,
            self.remote.port(),
            seq,
            self.rcv_nxt,
            flags,
            self.window(),
            false,
            payload,
        )
    }

    fn connect(&mut self, g: &Guest) {
        g.send(pkt::tcp(
            *self.remote.ip(),
            self.lport,
            self.remote.port(),
            self.iss,
            0,
            pkt::SYN,
            65535,
            true,
            &[],
        ));
        self.snd_nxt = self.iss.wrapping_add(1);
    }

    fn done(&self) -> bool {
        self.fin_acked && self.peer_fin
    }

    /// Process one segment addressed to this connection.
    fn on_segment(&mut self, g: &Guest, t: &pkt::Tcp) {
        if self.allow_rst && t.flags & pkt::RST != 0 {
            assert_eq!(t.seq, self.rcv_nxt, "RST in sequence");
            self.rst_after.get_or_insert(self.received.len());
            return;
        }
        assert_eq!(t.flags & pkt::RST, 0, "connection reset by the NAT");
        if t.flags & pkt::SYN != 0 {
            self.rcv_nxt = t.seq.wrapping_add(1);
            self.peer_shift = t.wscale.unwrap_or(0);
            self.peer_mss = usize::from(t.mss.unwrap_or(536));
            self.peer_wnd = u32::from(t.window);
            if t.flags & pkt::ACK != 0 {
                // Our active open completed.
                assert_eq!(t.ack, self.iss.wrapping_add(1));
                self.snd_una = t.ack;
                self.established = true;
                self.ack_due = true;
            } else {
                // Passive open (host forward): answer with SYN-ACK.
                let f = pkt::tcp(
                    *self.remote.ip(),
                    self.lport,
                    self.remote.port(),
                    self.iss,
                    self.rcv_nxt,
                    pkt::SYN | pkt::ACK,
                    65535,
                    true,
                    &[],
                );
                g.send(f);
                self.snd_nxt = self.iss.wrapping_add(1);
            }
            return;
        }
        if t.flags & pkt::ACK != 0 {
            let acked = t.ack.wrapping_sub(self.snd_una) as i32;
            if acked > 0 && t.ack.wrapping_sub(self.snd_nxt) as i32 <= 0 {
                self.snd_una = t.ack;
                self.last_progress = Instant::now();
                if self.fin_sent && t.ack == self.fin_seq().wrapping_add(1) {
                    self.fin_acked = true;
                }
            }
            if !self.established && t.ack == self.iss.wrapping_add(1) {
                self.established = true;
            }
            self.peer_wnd = u32::from(t.window) << self.peer_shift;
        }
        if !t.payload.is_empty() || t.flags & pkt::FIN != 0 {
            self.ack_due = true;
        }
        if self.paused {
            self.dropped_while_paused += t.payload.len();
        } else if t.seq == self.rcv_nxt {
            self.received.extend_from_slice(&t.payload);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(t.payload.len() as u32);
            if t.flags & pkt::FIN != 0 {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.peer_fin = true;
            }
        }
    }

    fn fin_seq(&self) -> u32 {
        self.iss.wrapping_add(1).wrapping_add(self.out.len() as u32)
    }

    /// Send what the peer's window allows, the FIN, and owed ACKs.
    fn pump(&mut self, g: &Guest) {
        if !self.established || self.rst_after.is_some() {
            return;
        }
        // Crude go-back-N if nothing moved for a while (lost frames).
        if self.snd_nxt != self.snd_una && self.last_progress.elapsed() > Duration::from_millis(500)
        {
            self.snd_nxt = self.snd_una;
            self.fin_sent = false;
            self.last_progress = Instant::now();
        }
        loop {
            let off = self.snd_nxt.wrapping_sub(self.iss.wrapping_add(1)) as usize;
            if off >= self.out.len() {
                if self.close_after_send && !self.fin_sent && off == self.out.len() {
                    g.send(self.seg(self.snd_nxt, pkt::FIN | pkt::ACK, &[]));
                    self.snd_nxt = self.snd_nxt.wrapping_add(1);
                    self.fin_sent = true;
                    self.ack_due = false;
                }
                break;
            }
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
            let room = self.peer_wnd.saturating_sub(in_flight) as usize;
            let n = (self.out.len() - off).min(self.peer_mss).min(room);
            if n == 0 {
                break;
            }
            let seq = self.snd_nxt;
            g.send(self.seg(seq, pkt::ACK | pkt::PSH, &self.out[off..off + n]));
            self.snd_nxt = seq.wrapping_add(n as u32);
            self.ack_due = false;
        }
        if self.ack_due {
            g.send(self.seg(self.snd_nxt, pkt::ACK, &[]));
            self.ack_due = false;
        }
    }

    /// Run until `stop` says so, feeding segments for this connection.
    fn run(&mut self, g: &Guest, mut stop: impl FnMut(&mut GuestTcp, &Guest) -> bool) {
        while !stop(self, g) {
            // Drain everything available, then answer once (like NAPI).
            let mut got = g.recv(Duration::from_millis(20));
            while let Some(f) = got {
                if let Some(ip) = pkt::parse(&f)
                    && ip.proto == pkt::TCP
                    && ip.src == *self.remote.ip()
                {
                    let t = pkt::tcp_view(&ip.l4);
                    if t.dport == self.lport
                        && (self.remote.port() == 0 || t.sport == self.remote.port())
                    {
                        if self.remote.port() == 0 {
                            self.remote.set_port(t.sport); // passive open learns the peer port
                        }
                        self.on_segment(g, &t);
                    }
                }
                got = g.recv(Duration::ZERO);
            }
            self.pump(g);
        }
    }
}

fn set_int_opt(s: &impl AsRawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
    // SAFETY: `value` is a live c_int whose size is passed alongside, and
    // the descriptor belongs to `s` for the duration of the call.
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(r, 0, "setsockopt: {}", std::io::Error::last_os_error());
}

fn pattern(n: usize, salt: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761).wrapping_add(salt) >> 13) as u8)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn guest_tcp_to_host_listener_bulk_both_ways() {
    const UP: usize = 2 * 1024 * 1024 + 123; // guest -> host
    const DOWN: usize = 3 * 1024 * 1024 + 77; // host -> guest
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        let writer = thread::spawn(move || {
            w.write_all(&pattern(DOWN, 2)).unwrap();
            w.shutdown(Shutdown::Write).unwrap();
        });
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        writer.join().unwrap();
        got
    });

    let g = Guest::new(Vec::new());
    let mut c = GuestTcp::new(40000, SocketAddrV4::new(GW, port), 0x7000_0000);
    c.out = pattern(UP, 1);
    c.close_after_send = true;
    c.connect(&g);
    let mut paused_once = false;
    let mut pause_until = None;
    c.run(&g, |c, g| {
        // Stall the guest reader once mid-stream: the NAT must stop reading
        // from the host (zero window), then resume on the window update.
        if !paused_once && c.received.len() > 512 * 1024 {
            paused_once = true;
            c.paused = true;
            c.ack_due = true;
            pause_until = Some(Instant::now() + Duration::from_millis(300));
        }
        if pause_until.is_some_and(|t| Instant::now() >= t) {
            pause_until = None;
            c.paused = false;
            g.send(c.seg(c.snd_nxt, pkt::ACK, &[])); // window update
        }
        c.done()
    });
    assert!(
        c.received.len() == DOWN && c.received == pattern(DOWN, 2),
        "host -> guest bytes differ"
    );
    // Only data already in flight when the window closed may arrive during
    // the stall: the NAT stops reading the host socket at a zero window.
    assert!(
        c.dropped_while_paused <= GUEST_WINDOW as usize,
        "{} bytes sent into a zero window",
        c.dropped_while_paused
    );
    assert!(
        g.nic.refused.load(Ordering::Relaxed) > 0,
        "receive-buffer back-pressure was exercised"
    );
    let got = host.join().unwrap();
    assert!(
        got.len() == UP && got == pattern(UP, 1),
        "guest -> host bytes differ ({} bytes)",
        got.len()
    );
}

#[test]
fn guest_tcp_connect_refused_gets_rst() {
    let g = Guest::new(Vec::new());
    // A port found closed can be taken by a concurrent test before the SYN:
    // by a listener (SYN-ACK), or as a connection's source port (macOS then
    // drops SYNs to it instead of resetting them). Either way, try another.
    'ports: for sport in 40001..40011 {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        }; // closed again: nothing listens
        g.send(pkt::tcp(GW, sport, port, 1, 0, pkt::SYN, 65535, true, &[]));
        let end = Instant::now() + Duration::from_secs(2);
        while Instant::now() < end {
            let Some(ip) = g
                .recv(Duration::from_millis(50))
                .as_deref()
                .and_then(pkt::parse)
            else {
                continue;
            };
            if ip.proto != pkt::TCP {
                continue;
            }
            let t = pkt::tcp_view(&ip.l4);
            if t.dport != sport {
                continue;
            }
            if t.flags == pkt::SYN | pkt::ACK {
                let rst = pkt::RST | pkt::ACK;
                g.send(pkt::tcp(
                    GW,
                    sport,
                    port,
                    2,
                    t.seq.wrapping_add(1),
                    rst,
                    0,
                    false,
                    &[],
                ));
                continue 'ports;
            }
            assert_eq!((t.flags, t.ack), (pkt::RST | pkt::ACK, 2));
            return;
        }
    }
    panic!("no RST for a connect to a closed port");
}

/// A guest whose network forwards a free host port (returned) to
/// `guest_port`. A port found free can be taken by a concurrent test before
/// the forward binds it, so that is retried with another one.
fn guest_with_fwd(proto: Proto, guest_port: u16) -> (Guest, u16) {
    for _ in 0..50 {
        let port = match proto {
            Proto::Tcp => TcpListener::bind("127.0.0.1:0").unwrap().local_addr(),
            Proto::Udp => UdpSocket::bind("127.0.0.1:0").unwrap().local_addr(),
        }
        .unwrap()
        .port();
        let fwd = HostFwd {
            proto,
            host_addr: Ipv4Addr::LOCALHOST,
            host_port: port,
            guest_port,
        };
        match Guest::try_new(vec![fwd]) {
            Ok(g) => return (g, port),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => panic!("UserNet::new: {e}"),
        }
    }
    panic!("no free port for a host forward");
}

#[test]
fn hostfwd_tcp_to_guest() {
    const SIZE: usize = 1024 * 1024 + 5;
    let (g, port) = guest_with_fwd(Proto::Tcp, 22);

    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut w = s.try_clone().unwrap();
        let writer = thread::spawn(move || {
            w.write_all(&pattern(SIZE, 3)).unwrap();
            w.shutdown(Shutdown::Write).unwrap();
        });
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        writer.join().unwrap();
        got
    });

    // The guest "server" on port 22 echoes everything back, then closes
    // after the client does.
    let mut c = GuestTcp::new(22, SocketAddrV4::new(GW, 0), 0x0123_4567);
    c.run(&g, |c, _| {
        if c.received.len() > c.out.len() {
            let more = c.received[c.out.len()..].to_vec();
            c.out.extend(more);
        }
        if c.peer_fin && c.out.len() == c.received.len() {
            c.close_after_send = true;
        }
        c.done()
    });
    assert!(
        c.remote.port() >= 49152,
        "connections come from 10.0.2.2:ephemeral"
    );
    let got = client.join().unwrap();
    assert!(
        got.len() == SIZE && got == pattern(SIZE, 3),
        "echoed bytes differ ({} bytes)",
        got.len()
    );
}

#[test]
fn hostfwd_tcp_guest_not_listening() {
    let (g, port) = guest_with_fwd(Proto::Tcp, 23);
    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut b = [0; 1];
        s.read(&mut b)
    });
    let ip = g.wait_for("SYN", |ip| ip.proto == pkt::TCP);
    let t = pkt::tcp_view(&ip.l4);
    assert_eq!(t.flags, pkt::SYN);
    g.send(pkt::tcp(
        GW,
        23,
        t.sport,
        0,
        t.seq.wrapping_add(1),
        pkt::RST | pkt::ACK,
        0,
        false,
        &[],
    ));
    let r = client.join().unwrap();
    assert!(
        matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
            || matches!(r, Ok(0)),
        "{r:?}"
    );
}

#[test]
fn udp_echo_via_gateway() {
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut b = [0; 2048];
        for _ in 0..2 {
            let (n, from) = echo.recv_from(&mut b).unwrap();
            echo.send_to(&b[..n], from).unwrap();
        }
    });
    let g = Guest::new(Vec::new());
    for msg in [&b"hello udp"[..], &[0xa5; 1400][..]] {
        g.send(pkt::udp(GW, 5555, port, msg));
        let ip = g.wait_for("UDP reply", |ip| ip.proto == pkt::UDP);
        assert_eq!(ip.src, GW);
        assert_eq!(
            ip.l4[..4],
            [&port.to_be_bytes()[..], &5555u16.to_be_bytes()].concat()
        );
        assert_eq!(&ip.l4[8..], msg);
    }
    server.join().unwrap();
}

/// The UDP NAT is endpoint-independent (full cone, as in qemu): one host
/// port per guest port whatever the destination, and replies from any
/// address and port reach the guest, like a TFTP server answering from a
/// new port. (So, as with qemu, a datagram to a closed port gets no ICMP
/// error: unconnected sockets are not told.)
#[test]
fn udp_nat_accepts_replies_from_other_ports() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let closed = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let g = Guest::new(Vec::new());
    g.send(pkt::udp(GW, 5556, closed, b"anyone?"));
    g.send(pkt::udp(GW, 5556, port, b"RRQ file"));
    let mut b = [0; 64];
    let (n, mapped) = server.recv_from(&mut b).unwrap();
    assert_eq!(&b[..n], b"RRQ file");
    // The reply comes from a fresh port (a TFTP "TID"), and a stranger
    // writes to the mapping too.
    let tid = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tid_port = tid.local_addr().unwrap().port();
    tid.send_to(b"DATA 1", mapped).unwrap();
    let ip = g.wait_for("reply from another port", |ip| ip.proto == pkt::UDP);
    assert_eq!(ip.src, GW, "the host's loopback is 10.0.2.2");
    assert_eq!(
        ip.l4[..4],
        [&tid_port.to_be_bytes()[..], &5556u16.to_be_bytes()].concat()
    );
    assert_eq!(&ip.l4[8..], b"DATA 1");
    // The guest answers the new port: same host-side mapping.
    g.send(pkt::udp(GW, 5556, tid_port, b"ACK 1"));
    tid.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (n, from) = tid.recv_from(&mut b).unwrap();
    assert_eq!((&b[..n], from), (&b"ACK 1"[..], mapped));
}

/// Datagrams too big for the 1500-byte MTU (EDNS answers, for one) reach
/// the guest as IPv4 fragments.
#[test]
fn udp_large_reply_is_fragmented() {
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    // macOS limits UDP sends to net.inet.udp.maxdgram (9216) by default.
    set_int_opt(&echo, libc::SOL_SOCKET, libc::SO_SNDBUF, 70_000);
    const SIZES: [usize; 3] = [1473, 4000, 65507];
    let server = thread::spawn(move || {
        let mut b = [0; 64];
        for size in SIZES {
            let (_, from) = echo.recv_from(&mut b).unwrap();
            echo.send_to(&pattern(size, size as u32), from).unwrap();
        }
    });
    let g = Guest::new(Vec::new());
    for size in SIZES {
        g.send(pkt::udp(GW, 5557, port, b"big please"));
        let mut frags = Vec::new();
        let ip = loop {
            let ip = g.wait_for("UDP reply or fragment", |ip| ip.proto == pkt::UDP);
            if !ip.is_fragment() {
                break ip;
            }
            frags.push(ip);
            if let Some(ip) = pkt::reassemble(&frags) {
                break ip;
            }
        };
        assert_eq!(frags.len(), (size + 8).div_ceil(1480), "{size} bytes");
        assert_eq!(&ip.l4[8..], pattern(size, size as u32), "{size} bytes");
    }
    server.join().unwrap();
}

#[test]
fn hostfwd_udp_round_trip() {
    let (g, port) = guest_with_fwd(Proto::Udp, 5353);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(b"question", ("127.0.0.1", port)).unwrap();

    let ip = g.wait_for("forwarded datagram", |ip| ip.proto == pkt::UDP);
    let sport = u16::from_be_bytes([ip.l4[0], ip.l4[1]]);
    assert_eq!(
        (ip.src, &ip.l4[2..4], &ip.l4[8..]),
        (GW, &5353u16.to_be_bytes()[..], &b"question"[..])
    );
    g.send(pkt::udp(GW, 5353, sport, b"answer"));
    let mut b = [0; 64];
    let (n, from) = client.recv_from(&mut b).unwrap();
    assert_eq!((&b[..n], from.port()), (&b"answer"[..], port));
}

#[test]
fn icmp_echo_to_gateway() {
    let g = Guest::new(Vec::new());
    for seq in 1..=3u16 {
        g.send(pkt::echo_request(GW, 0x4242, seq, b"vemu ping payload"));
        let ip = g.wait_for("echo reply", |ip| ip.proto == pkt::ICMP);
        assert_eq!((ip.src, ip.l4[0]), (GW, 0), "echo reply from 10.0.2.2");
        assert_eq!(
            ip.l4[4..8],
            [&0x4242u16.to_be_bytes()[..], &seq.to_be_bytes()].concat()
        );
        assert_eq!(&ip.l4[8..], b"vemu ping payload");
    }
}

/// On Linux the echo really goes through the host's ICMP ("ping") socket,
/// whose kernel replaces the identifier (the NAT maps by sequence number
/// then): the host kernel counts the echo requests it answered. Two guest
/// flows use the same sequence numbers and each gets its own replies.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn icmp_echo_to_gateway_goes_through_the_host() {
    // SAFETY: socket(2) with integer arguments; closed right away.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        eprintln!(
            "no ICMP datagram socket ({}; see net.ipv4.ping_group_range); skipping",
            std::io::Error::last_os_error()
        );
        return;
    }
    // SAFETY: closing the descriptor just created.
    unsafe { libc::close(fd) };
    let before = icmp_in_echos();
    let g = Guest::new(Vec::new());
    for seq in 1..=3u16 {
        for id in [0x1111u16, 0x2222] {
            let payload = format!("flow {id:x} seq {seq}");
            g.send(pkt::echo_request(GW, id, seq, payload.as_bytes()));
            let ip = g.wait_for("echo reply", |ip| ip.proto == pkt::ICMP);
            assert_eq!((ip.src, ip.l4[0]), (GW, 0), "echo reply from 10.0.2.2");
            assert_eq!(
                (&ip.l4[4..8], &ip.l4[8..]),
                (
                    &[&id.to_be_bytes()[..], &seq.to_be_bytes()].concat()[..],
                    payload.as_bytes()
                )
            );
        }
    }
    let answered = icmp_in_echos() - before;
    assert!(
        answered >= 6,
        "the host answered {answered} echo requests, not 6"
    );
}

/// The host's `Icmp: InEchos` counter (/proc/net/snmp).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn icmp_in_echos() -> u64 {
    let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let mut rows = snmp.lines().filter(|l| l.starts_with("Icmp: "));
    let (names, values) = (rows.next().unwrap(), rows.next().unwrap());
    let i = names
        .split_whitespace()
        .position(|n| n == "InEchos")
        .unwrap();
    values.split_whitespace().nth(i).unwrap().parse().unwrap()
}

#[test]
fn arp_and_dhcp_through_the_backend() {
    let g = Guest::new(Vec::new());
    // ARP for the gateway.
    let mut arp = vec![0xff; 6];
    arp.extend_from_slice(&GUEST_MAC);
    arp.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1]);
    arp.extend_from_slice(&GUEST_MAC);
    arp.extend_from_slice(&GUEST.octets());
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&GW.octets());
    g.send(arp);
    let reply = g.recv(Duration::from_secs(5)).expect("ARP reply");
    assert_eq!(reply[12..14], [0x08, 0x06]);
    assert_eq!(reply[22..28], ROUTER_MAC);

    // DHCPDISCOVER from 0.0.0.0, broadcast flag set.
    let mut d = vec![1, 1, 6, 0, 1, 2, 3, 4, 0, 0, 0x80, 0];
    d.extend_from_slice(&[0; 16]);
    d.extend_from_slice(&GUEST_MAC);
    d.resize(236, 0);
    d.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
    let mut udp = 68u16.to_be_bytes().to_vec();
    udp.extend_from_slice(&67u16.to_be_bytes());
    udp.extend_from_slice(&((8 + d.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // no checksum, as allowed
    udp.extend_from_slice(&d);
    let mut f = pkt::frame([0xff; 6], Ipv4Addr::BROADCAST, pkt::UDP, udp, None);
    f[26..30].fill(0); // source 0.0.0.0
    f[24..26].fill(0);
    let c = pkt::csum(&[&f[14..34]]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    g.send(f);

    let offer = loop {
        let f = g.recv(Duration::from_secs(5)).expect("DHCPOFFER");
        if f[12..14] == [0x08, 0x00] {
            break f;
        }
    };
    assert_eq!(offer[..6], [0xff; 6], "broadcast flag honoured");
    let udp = &offer[34..];
    assert_eq!(udp[8 + 16..8 + 20], GUEST.octets(), "yiaddr");
}

#[test]
fn many_short_connections_are_cleaned_up() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    const N: u16 = 40;
    let host = thread::spawn(move || {
        for _ in 0..N {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = Vec::new();
            s.read_to_end(&mut b).unwrap();
            s.write_all(&b).unwrap();
        }
    });
    let g = Guest::new(Vec::new());
    let mut pending: VecDeque<u16> = (0..N).collect();
    while let Some(i) = pending.pop_front() {
        let mut c = GuestTcp::new(30000 + i, SocketAddrV4::new(GW, port), u32::from(i) << 20);
        c.out = format!("request {i}").into_bytes();
        c.close_after_send = true;
        c.connect(&g);
        c.run(&g, |c, _| c.done());
        assert_eq!(c.received, format!("request {i}").into_bytes());
    }
    host.join().unwrap();
}

/// The host peer sends a burst, then resets the connection (an HTTP server
/// answering 413 and closing with the request body unread). The guest gets
/// every byte the peer sent, then the RST, as a client on the host would.
#[test]
fn host_reset_delivers_data_sent_before_it() {
    const SIZE: usize = 100_000; // fits the host's socket buffers (128 KiB)
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (reset_tx, reset_rx) = mpsc::channel();
    let host = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(&pattern(SIZE, 5)).unwrap();
        // Wait until the data sits in vemu's receive buffer (no byte left
        // that the receiving kernel has not acknowledged).
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if unacked_bytes(&s) == 0 {
                break;
            }
            assert!(Instant::now() < end, "data never left the host socket");
            thread::sleep(Duration::from_millis(5));
        }
        let off = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: `off` is a live linger struct of the size passed.
        let r = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&off as *const libc::linger).cast(),
                size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(r, 0);
        drop(s); // RST
        reset_tx.send(()).unwrap();
    });

    let g = Guest::new(Vec::new());
    let mut c = GuestTcp::new(40100, SocketAddrV4::new(GW, port), 0x0600_0000);
    c.allow_rst = true;
    // A stalled reader: with a zero window the NAT reads nothing, so all of
    // the host's data is still in the host socket when the reset arrives.
    c.paused = true;
    c.connect(&g);
    let mut reset = false;
    c.run(&g, |c, _| {
        reset |= reset_rx.try_recv().is_ok();
        c.established && reset
    });
    thread::sleep(Duration::from_millis(100)); // let the NAT see the reset
    c.paused = false;
    g.send(c.seg(c.snd_nxt, pkt::ACK, &[])); // window update
    c.run(&g, |c, _| c.rst_after.is_some());
    assert_eq!(c.rst_after, Some(SIZE), "all the data, then the RST");
    assert!(c.received == pattern(SIZE, 5), "bytes differ");
    assert_eq!(c.dropped_while_paused, 0);
    host.join().unwrap();
}

/// Bytes written to `s` that the peer's kernel has not acknowledged yet.
#[cfg(target_os = "macos")]
fn unacked_bytes(s: &TcpStream) -> libc::c_int {
    let mut n: libc::c_int = -1;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `n` and `len` are live locals of the sizes passed.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            (&mut n as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    assert_eq!(r, 0, "SO_NWRITE: {}", std::io::Error::last_os_error());
    n
}

/// Bytes written to `s` that the peer's kernel has not acknowledged yet
/// (SIOCOUTQ, an alias of TIOCOUTQ: unsent plus unacknowledged).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unacked_bytes(s: &TcpStream) -> libc::c_int {
    let mut n: libc::c_int = -1;
    // SAFETY: TIOCOUTQ writes one int, to the live local passed.
    let r = unsafe { libc::ioctl(s.as_raw_fd(), libc::TIOCOUTQ, &mut n) };
    assert_eq!(r, 0, "SIOCOUTQ: {}", std::io::Error::last_os_error());
    n
}

// ---------------------------------------------------------------------------
// File descriptor limits (each in a child process: they change rlimits)
// ---------------------------------------------------------------------------

const CHILD_ENV: &str = "VEMU_NET_TEST_CHILD";

/// Run test `name` in a child process of this test binary, with the
/// environment marking it as the child. Returns true in the child, which
/// then runs the test body; false in the parent, once the child passed.
/// Returns the child's stderr to the parent through `stderr`.
fn in_child(name: &str, stderr: &mut String) -> bool {
    if std::env::var(CHILD_ENV).as_deref() == Ok(name) {
        return true;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, name)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    *stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child {name} failed:\n{stdout}\n{stderr}"
    );
    false
}

fn set_nofile(cur: libc::rlim_t, max: libc::rlim_t) {
    let rl = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    // SAFETY: setrlimit reads the live rlimit struct passed.
    let r = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) };
    assert_eq!(r, 0, "setrlimit: {}", std::io::Error::last_os_error());
}

fn get_nofile() -> libc::rlimit {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the live rlimit struct passed.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) }, 0);
    rl
}

/// A guest SYN from `sport` to the gateway's `port`: what comes back.
fn syn_answer(g: &Guest, sport: u16, port: u16) -> (u8, u8) {
    g.send(pkt::tcp(GW, sport, port, 1, 0, pkt::SYN, 65535, true, &[]));
    let ip = g.wait_for("SYN answer", |ip| {
        ip.proto == pkt::ICMP || (ip.proto == pkt::TCP && pkt::tcp_view(&ip.l4).dport == sport)
    });
    let kind = if ip.proto == pkt::TCP {
        pkt::tcp_view(&ip.l4).flags
    } else {
        ip.l4[0] // ICMP type
    };
    if ip.proto == pkt::TCP && kind & pkt::SYN != 0 {
        let t = pkt::tcp_view(&ip.l4);
        g.send(pkt::tcp(
            GW,
            sport,
            port,
            2,
            t.seq.wrapping_add(1),
            pkt::RST | pkt::ACK,
            0,
            false,
            &[],
        ));
    }
    (ip.proto, kind)
}

/// The process starts with a low hard limit (it cannot be raised): the NAT
/// sizes its flow caps to it, so many UDP flows do not starve TCP of
/// descriptors. When the process does run out, connects get RST (not
/// "host unreachable"), UDP flows fail quietly, the condition is logged
/// once, and everything works again once descriptors are free.
#[test]
fn nat_fits_a_low_fd_limit() {
    let mut stderr = String::new();
    if !in_child("nat_fits_a_low_fd_limit", &mut stderr) {
        assert_eq!(
            stderr.matches("out of file descriptors").count(),
            1,
            "logged once: {stderr}"
        );
        return;
    }
    set_nofile(128, 128);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let g = Guest::new(Vec::new());
    assert_eq!(get_nofile().rlim_cur, 128, "the hard limit is respected");

    // Many UDP mappings (a DNS-heavy guest with random source ports): the
    // NAT keeps at most its cap open, evicting the oldest.
    for i in 0..150 {
        g.send(pkt::udp(GW, 20000 + i, 9, b"x"));
    }
    assert_eq!(syn_answer(&g, 41000, port), (pkt::TCP, pkt::SYN | pkt::ACK));

    // Exhaust the process's descriptors (bounded by the 128 limit).
    let mut hog = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(f) => hog.push(f),
            Err(e) if e.raw_os_error() == Some(libc::EMFILE) => break,
            Err(e) => panic!("{e}"),
        }
        assert!(hog.len() < 256);
    }
    for i in 0..3 {
        assert_eq!(
            syn_answer(&g, 41001 + i, port),
            (pkt::TCP, pkt::RST | pkt::ACK),
            "out of descriptors: connection refused, not host unreachable"
        );
    }
    g.send(pkt::udp(GW, 30000, 9, b"lost"));
    // The network thread is still alive: ICMP echo is answered.
    g.send(pkt::echo_request(GW, 7, 1, b"alive?"));
    let ip = g.wait_for("echo reply", |ip| ip.proto == pkt::ICMP);
    assert_eq!(ip.l4[0], 0);

    drop(hog);
    assert_eq!(syn_answer(&g, 41010, port), (pkt::TCP, pkt::SYN | pkt::ACK));
}

/// From a stock macOS shell (soft limit 256; Linux: 1024), the NAT raises
/// the soft limit to fit its caps, within the hard limit.
#[test]
fn nat_raises_the_soft_fd_limit() {
    if !in_child("nat_raises_the_soft_fd_limit", &mut String::new()) {
        return;
    }
    // Without privileges the hard limit can only be lowered (some Linux
    // systems set it to 4096).
    let hard = get_nofile().rlim_max.min(8192);
    set_nofile(256, hard);
    let _g = Guest::new(Vec::new());
    let rl = get_nofile();
    assert_eq!((rl.rlim_cur, rl.rlim_max), (hard.min(4096), hard));
}

/// Clients of a forwarded port beyond the forward budget wait in the
/// listen backlog (they are not accepted and dropped), and get their turn
/// when a forwarded connection ends.
#[test]
fn hostfwd_budget_leaves_clients_in_the_backlog() {
    if !in_child(
        "hostfwd_budget_leaves_clients_in_the_backlog",
        &mut String::new(),
    ) {
        return;
    }
    set_nofile(128, 128); // a small forward budget
    let (g, port) = guest_with_fwd(Proto::Tcp, 22);
    const CLIENTS: usize = 30;
    let clients: Vec<TcpStream> = (0..CLIENTS)
        .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    // The guest's firewall drops the SYNs: count the distinct connections
    // the NAT opens toward it.
    let mut seen = std::collections::HashSet::new();
    let end = Instant::now() + Duration::from_millis(1500);
    let mut first = None;
    while Instant::now() < end {
        if let Some(ip) = g
            .recv(Duration::from_millis(50))
            .as_deref()
            .and_then(pkt::parse)
            && ip.proto == pkt::TCP
        {
            let t = pkt::tcp_view(&ip.l4);
            assert_eq!(t.flags, pkt::SYN);
            seen.insert(t.sport);
            first.get_or_insert((t.sport, t.seq));
        }
    }
    let n = seen.len();
    assert!(n > 0 && n < CLIENTS, "{n} forwarded connections");
    // Nobody was accepted and dropped: no client sees EOF.
    for c in &clients {
        c.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
        let r = (&*c).read(&mut [0; 1]);
        assert!(
            matches!(&r, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
            "{r:?}"
        );
    }
    // The guest refuses one: the next client in the backlog gets its turn.
    let (sport, seq) = first.unwrap();
    g.send(pkt::tcp(
        GW,
        22,
        sport,
        0,
        seq.wrapping_add(1),
        pkt::RST | pkt::ACK,
        0,
        false,
        &[],
    ));
    let ip = g.wait_for("SYN of the next client", |ip| {
        ip.proto == pkt::TCP && !seen.contains(&pkt::tcp_view(&ip.l4).sport)
    });
    assert_eq!(pkt::tcp_view(&ip.l4).flags, pkt::SYN);
    drop(clients);
}

/// End-to-end through the real host network: DNS via the relay at 10.0.2.3,
/// then HTTP over the TCP NAT to the resolved address, then ICMP echo to it.
/// Needs Internet access, so it only runs with `cargo test -- --ignored`.
#[test]
#[ignore = "needs Internet access"]
fn internet_dns_tcp_and_ping() {
    let g = Guest::new(Vec::new());
    let dns = Ipv4Addr::new(10, 0, 2, 3);
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    g.send(pkt::udp(dns, 5300, 53, &q));
    let ip = g.wait_for("DNS answer", |ip| ip.proto == pkt::UDP && ip.src == dns);
    let r = &ip.l4[8..];
    assert_eq!(
        (r[0], r[1], r[2] & 0x80, r[3] & 0x0f),
        (0x12, 0x34, 0x80, 0),
        "NOERROR response to our id"
    );
    // Take the first A record (name compression: answers start with a pointer).
    let mut i = q.len();
    let addr = loop {
        let (ty, len) = (
            u16::from_be_bytes([r[i + 2], r[i + 3]]),
            usize::from(u16::from_be_bytes([r[i + 10], r[i + 11]])),
        );
        if ty == 1 && len == 4 {
            break Ipv4Addr::new(r[i + 12], r[i + 13], r[i + 14], r[i + 15]);
        }
        i += 12 + len;
    };

    let mut c = GuestTcp::new(41000, SocketAddrV4::new(addr, 80), 0x5555_0000);
    c.out = b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n".to_vec();
    c.connect(&g);
    // Close after the server does: some servers drop half-closed clients.
    c.run(&g, |c, _| {
        c.close_after_send |= c.peer_fin;
        c.done()
    });
    assert!(
        c.received.starts_with(b"HTTP/1."),
        "{:?}",
        String::from_utf8_lossy(&c.received)
    );

    g.send(pkt::echo_request(addr, 77, 1, b"ping"));
    let ip = g.wait_for("echo reply", |ip| ip.proto == pkt::ICMP && ip.src == addr);
    assert_eq!((ip.l4[0], &ip.l4[4..6]), (0, &77u16.to_be_bytes()[..]));
}
