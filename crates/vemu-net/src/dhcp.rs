//! A single-lease DHCP server (RFC 2131 / RFC 2132).
//!
//! There is one guest and one address, so the server keeps no lease table:
//! every client is offered the configured guest address. Replies follow the
//! RFC 2131 section 4.1 addressing rules (unicast to `ciaddr` when set,
//! broadcast when the client asks for it or for NAKs, otherwise unicast to
//! `yiaddr` at the client's hardware address).

use std::net::Ipv4Addr;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

/// Lease time handed out, in seconds (qemu uses one day too).
pub const LEASE_SECS: u32 = 86_400;

const FIXED_LEN: usize = 236;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// BOOTP minimum message size; some clients drop shorter replies.
const MIN_LEN: usize = 300;
const BROADCAST_FLAG: u16 = 0x8000;

mod opt {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const BROADCAST_ADDR: u8 = 28;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MSG_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const CLIENT_ID: u8 = 61;
    pub const END: u8 = 255;
}

mod msg {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
}

/// The addresses the server hands out.
#[derive(Debug, Clone, Copy)]
pub struct DhcpConfig {
    pub server: Ipv4Addr,
    pub guest: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns: Ipv4Addr,
}

/// A reply to send from `server:67` to `dst_ip:68` at Ethernet `dst_mac`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpReply {
    pub dst_ip: Ipv4Addr,
    pub dst_mac: [u8; 6],
    pub payload: Vec<u8>,
}

/// A parsed client message (only the fields the server uses).
struct Request<'a> {
    xid: [u8; 4],
    flags: u16,
    ciaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    msg_type: u8,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    client_id: Option<&'a [u8]>,
}

fn ip(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

impl<'a> Request<'a> {
    fn parse(b: &'a [u8]) -> Option<Self> {
        // op = BOOTREQUEST, htype = Ethernet, hlen = 6
        if b.len() < FIXED_LEN + MAGIC.len() || b[0] != 1 || b[1] != 1 || b[2] != 6 {
            return None;
        }
        if b[FIXED_LEN..FIXED_LEN + 4] != MAGIC {
            return None;
        }
        let mut r = Request {
            xid: b[4..8].try_into().ok()?,
            flags: u16::from_be_bytes([b[10], b[11]]),
            ciaddr: ip(&b[12..16]),
            giaddr: ip(&b[24..28]),
            chaddr: b[28..44].try_into().ok()?,
            msg_type: 0,
            requested_ip: None,
            server_id: None,
            client_id: None,
        };
        let mut opts = &b[FIXED_LEN + 4..];
        while let [code, rest @ ..] = opts {
            match *code {
                opt::PAD => opts = rest,
                opt::END => break,
                code => {
                    let [len, rest @ ..] = rest else { break };
                    let len = usize::from(*len);
                    if rest.len() < len {
                        break;
                    }
                    let v = &rest[..len];
                    match (code, len) {
                        (opt::MSG_TYPE, 1) => r.msg_type = v[0],
                        (opt::REQUESTED_IP, 4) => r.requested_ip = Some(ip(v)),
                        (opt::SERVER_ID, 4) => r.server_id = Some(ip(v)),
                        (opt::CLIENT_ID, 1..) => r.client_id = Some(v),
                        _ => {}
                    }
                    opts = &rest[len..];
                }
            }
        }
        (r.msg_type != 0).then_some(r)
    }

    fn mac(&self) -> [u8; 6] {
        self.chaddr[..6].try_into().expect("6 bytes")
    }
}

/// Handle one client message (the UDP payload sent to port 67). Returns the
/// reply, if any.
pub fn handle(cfg: &DhcpConfig, payload: &[u8]) -> Option<DhcpReply> {
    let req = Request::parse(payload)?;
    if req.giaddr != Ipv4Addr::UNSPECIFIED {
        return None; // relayed: not on our virtual link
    }
    let (ty, yiaddr) = match req.msg_type {
        msg::DISCOVER => (msg::OFFER, cfg.guest),
        msg::REQUEST => {
            if req.server_id.is_some_and(|s| s != cfg.server) {
                return None; // the client chose another server
            }
            // SELECTING / INIT-REBOOT carry option 50; RENEWING / REBINDING
            // carry ciaddr instead.
            let wanted = req.requested_ip.unwrap_or(req.ciaddr);
            if wanted == cfg.guest {
                (msg::ACK, cfg.guest)
            } else {
                (msg::NAK, Ipv4Addr::UNSPECIFIED)
            }
        }
        msg::INFORM => (msg::ACK, Ipv4Addr::UNSPECIFIED),
        msg::DECLINE | msg::RELEASE => return None,
        _ => return None,
    };

    let mut p = Vec::with_capacity(MIN_LEN + 64);
    p.extend_from_slice(&[2, 1, 6, 0]); // BOOTREPLY, Ethernet
    p.extend_from_slice(&req.xid);
    p.extend_from_slice(&[0, 0]); // secs
    p.extend_from_slice(&(req.flags & BROADCAST_FLAG).to_be_bytes());
    let ciaddr = if matches!(ty, msg::OFFER | msg::NAK) {
        Ipv4Addr::UNSPECIFIED
    } else {
        req.ciaddr
    };
    p.extend_from_slice(&ciaddr.octets());
    p.extend_from_slice(&yiaddr.octets());
    p.extend_from_slice(&[0; 4]); // siaddr: no boot server
    p.extend_from_slice(&[0; 4]); // giaddr
    p.extend_from_slice(&req.chaddr);
    p.resize(FIXED_LEN, 0); // sname, file
    p.extend_from_slice(&MAGIC);

    let mut put = |code: u8, v: &[u8]| {
        p.push(code);
        p.push(v.len() as u8);
        p.extend_from_slice(v);
    };
    put(opt::MSG_TYPE, &[ty]);
    put(opt::SERVER_ID, &cfg.server.octets());
    if ty != msg::NAK {
        if req.msg_type != msg::INFORM {
            put(opt::LEASE_TIME, &LEASE_SECS.to_be_bytes());
            put(opt::RENEWAL_TIME, &(LEASE_SECS / 2).to_be_bytes());
            put(opt::REBINDING_TIME, &(LEASE_SECS / 8 * 7).to_be_bytes());
        }
        put(opt::SUBNET_MASK, &cfg.netmask.octets());
        put(opt::ROUTER, &cfg.router.octets());
        put(opt::DNS, &cfg.dns.octets());
        let bcast = u32::from(cfg.guest) | !u32::from(cfg.netmask);
        put(opt::BROADCAST_ADDR, &bcast.to_be_bytes());
    }
    if let Some(id) = req.client_id {
        put(opt::CLIENT_ID, id); // RFC 6842: echo the client identifier
    }
    p.push(opt::END);
    if p.len() < MIN_LEN {
        p.resize(MIN_LEN, opt::PAD);
    }

    let broadcast = (Ipv4Addr::BROADCAST, [0xff; 6]);
    let (dst_ip, dst_mac) = if ty == msg::NAK {
        broadcast
    } else if req.ciaddr != Ipv4Addr::UNSPECIFIED {
        (req.ciaddr, req.mac())
    } else if req.flags & BROADCAST_FLAG != 0 {
        broadcast
    } else {
        (yiaddr, req.mac())
    };
    Some(DhcpReply {
        dst_ip,
        dst_mac,
        payload: p,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const CHADDR: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn cfg() -> DhcpConfig {
        DhcpConfig {
            server: Ipv4Addr::new(10, 0, 2, 2),
            guest: Ipv4Addr::new(10, 0, 2, 15),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(10, 0, 2, 2),
            dns: Ipv4Addr::new(10, 0, 2, 3),
        }
    }

    /// Build a client message the way udhcpc/dhclient do.
    pub fn client_msg(ty: u8, flags: u16, ciaddr: Ipv4Addr, opts: &[(u8, &[u8])]) -> Vec<u8> {
        let mut p = vec![1, 1, 6, 0, 0xde, 0xad, 0xbe, 0xef, 0, 0];
        p.extend_from_slice(&flags.to_be_bytes());
        p.extend_from_slice(&ciaddr.octets());
        p.extend_from_slice(&[0; 12]);
        p.extend_from_slice(&CHADDR);
        p.resize(FIXED_LEN, 0);
        p.extend_from_slice(&MAGIC);
        p.extend_from_slice(&[opt::MSG_TYPE, 1, ty, opt::PAD]);
        for (c, v) in opts {
            p.push(*c);
            p.push(v.len() as u8);
            p.extend_from_slice(v);
        }
        p.push(opt::END);
        p
    }

    /// Options of a server reply as (code, value) pairs.
    pub fn reply_options(p: &[u8]) -> Vec<(u8, Vec<u8>)> {
        assert_eq!(p[FIXED_LEN..FIXED_LEN + 4], MAGIC);
        let mut out = Vec::new();
        let mut i = FIXED_LEN + 4;
        while p[i] != opt::END {
            if p[i] == opt::PAD {
                i += 1;
                continue;
            }
            let len = usize::from(p[i + 1]);
            out.push((p[i], p[i + 2..i + 2 + len].to_vec()));
            i += 2 + len;
        }
        out
    }

    fn get(opts: &[(u8, Vec<u8>)], code: u8) -> Option<Vec<u8>> {
        opts.iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.clone())
    }

    const ANY: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    const GUEST: [u8; 4] = [10, 0, 2, 15];
    const SERVER: [u8; 4] = [10, 0, 2, 2];

    #[test]
    fn discover_offer_request_ack() {
        let offer = handle(&cfg(), &client_msg(msg::DISCOVER, 0, ANY, &[])).unwrap();
        assert!(offer.payload.len() >= MIN_LEN);
        assert_eq!(offer.payload[0], 2);
        assert_eq!(offer.payload[4..8], [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(offer.payload[16..20], GUEST); // yiaddr
        assert_eq!(
            (offer.dst_ip, offer.dst_mac),
            (Ipv4Addr::from(GUEST), CHADDR)
        );
        let o = reply_options(&offer.payload);
        assert_eq!(get(&o, opt::MSG_TYPE), Some(vec![msg::OFFER]));
        assert_eq!(get(&o, opt::SERVER_ID), Some(SERVER.to_vec()));
        assert_eq!(get(&o, opt::SUBNET_MASK), Some(vec![255, 255, 255, 0]));
        assert_eq!(get(&o, opt::ROUTER), Some(SERVER.to_vec()));
        assert_eq!(get(&o, opt::DNS), Some(vec![10, 0, 2, 3]));
        assert_eq!(
            get(&o, opt::LEASE_TIME),
            Some(LEASE_SECS.to_be_bytes().to_vec())
        );
        assert_eq!(get(&o, opt::BROADCAST_ADDR), Some(vec![10, 0, 2, 255]));

        let req = client_msg(
            msg::REQUEST,
            BROADCAST_FLAG,
            ANY,
            &[
                (opt::REQUESTED_IP, &GUEST),
                (opt::SERVER_ID, &SERVER),
                (opt::CLIENT_ID, &[1, 2, 3]),
            ],
        );
        let ack = handle(&cfg(), &req).unwrap();
        assert_eq!((ack.dst_ip, ack.dst_mac), (Ipv4Addr::BROADCAST, [0xff; 6]));
        assert_eq!(ack.payload[10..12], BROADCAST_FLAG.to_be_bytes());
        let o = reply_options(&ack.payload);
        assert_eq!(get(&o, opt::MSG_TYPE), Some(vec![msg::ACK]));
        assert_eq!(get(&o, opt::CLIENT_ID), Some(vec![1, 2, 3]));
    }

    #[test]
    fn request_for_wrong_address_is_naked() {
        let req = client_msg(
            msg::REQUEST,
            0,
            ANY,
            &[(opt::REQUESTED_IP, &[10, 0, 2, 99])],
        );
        let nak = handle(&cfg(), &req).unwrap();
        assert_eq!((nak.dst_ip, nak.dst_mac), (Ipv4Addr::BROADCAST, [0xff; 6]));
        assert_eq!(nak.payload[16..20], [0; 4]);
        let o = reply_options(&nak.payload);
        assert_eq!(get(&o, opt::MSG_TYPE), Some(vec![msg::NAK]));
        assert_eq!(get(&o, opt::LEASE_TIME), None);
    }

    #[test]
    fn renew_is_unicast_and_other_server_ignored() {
        let renew = client_msg(msg::REQUEST, 0, GUEST.into(), &[]);
        let ack = handle(&cfg(), &renew).unwrap();
        assert_eq!((ack.dst_ip, ack.dst_mac), (Ipv4Addr::from(GUEST), CHADDR));
        assert_eq!(
            get(&reply_options(&ack.payload), opt::MSG_TYPE),
            Some(vec![msg::ACK])
        );

        let other = client_msg(msg::REQUEST, 0, ANY, &[(opt::SERVER_ID, &[10, 0, 2, 9])]);
        assert!(handle(&cfg(), &other).is_none());
        assert!(handle(&cfg(), &client_msg(msg::RELEASE, 0, GUEST.into(), &[])).is_none());
    }

    #[test]
    fn inform_has_no_lease() {
        let inform = client_msg(msg::INFORM, 0, GUEST.into(), &[]);
        let ack = handle(&cfg(), &inform).unwrap();
        assert_eq!(ack.dst_ip, Ipv4Addr::from(GUEST));
        assert_eq!(ack.payload[16..20], [0; 4]);
        let o = reply_options(&ack.payload);
        assert_eq!(get(&o, opt::MSG_TYPE), Some(vec![msg::ACK]));
        assert_eq!(get(&o, opt::LEASE_TIME), None);
        assert_eq!(get(&o, opt::DNS), Some(vec![10, 0, 2, 3]));
    }

    #[test]
    fn garbage_is_ignored() {
        assert!(handle(&cfg(), &[]).is_none());
        assert!(handle(&cfg(), &[1; 300]).is_none());
        let mut m = client_msg(msg::DISCOVER, 0, ANY, &[]);
        m[0] = 2; // a BOOTREPLY
        assert!(handle(&cfg(), &m).is_none());
    }
}
