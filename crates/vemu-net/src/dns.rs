//! Host resolver discovery and DNS helpers for the relay at the virtual DNS
//! address.
//!
//! Queries are relayed, not interpreted: each guest source port gets its own
//! host UDP socket connected to the upstream resolver, so replies come back on
//! the socket that carried the query and keep the guest's query id untouched.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

pub const DNS_PORT: u16 = 53;

/// The first usable IPv4 `nameserver` in resolv.conf-formatted text.
///
/// Unusable entries are skipped: IPv6 servers (the relay's host sockets are
/// IPv4), `0.0.0.0`, and multicast/broadcast addresses. Loopback resolvers
/// (systemd-resolved's 127.0.0.53, dnsmasq) are fine: the relay runs on the
/// host.
pub fn parse_resolv_conf(text: &str) -> Option<Ipv4Addr> {
    text.lines()
        .map(|l| l.split(['#', ';']).next().unwrap_or(""))
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == "nameserver")
                .then(|| words.next())
                .flatten()
        })
        .filter_map(|a| a.parse::<Ipv4Addr>().ok())
        .find(|a| !a.is_unspecified() && !a.is_multicast() && !a.is_broadcast())
}

/// The host resolver from `path` (normally `/etc/resolv.conf`), on port 53.
///
/// `Ok(None)` when there is none (no network, or IPv6-only, or no such
/// file): the relay then answers queries itself with SERVFAIL so guest
/// lookups fail fast instead of timing out. Other read errors (such as
/// running out of descriptors) are returned so the caller can keep the
/// resolver it had.
pub fn host_resolver(path: &Path) -> io::Result<Option<SocketAddrV4>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(parse_resolv_conf(&text).map(|a| SocketAddrV4::new(a, DNS_PORT)))
}

/// A SERVFAIL response to `query` (same id and question), or `None` if
/// `query` is not a DNS query.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    const HDR: usize = 12;
    if query.len() < HDR || query[2] & 0x80 != 0 {
        return None; // too short, or already a response
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    // Echo the question section only when it is the usual single question.
    let question_end = if qdcount == 1 {
        question_end(query, HDR)
    } else {
        None
    };
    let mut r = query[..question_end.unwrap_or(HDR)].to_vec();
    r[2] = 0x80 | (query[2] & 0x79); // QR, keep opcode and RD
    r[3] = 0x80 | 2; // RA, RCODE = SERVFAIL
    r[4..6].copy_from_slice(&u16::from(question_end.is_some()).to_be_bytes());
    r[6..12].fill(0); // no answer, authority or additional records
    Some(r)
}

/// End offset of the question starting at `at` (name, type, class).
fn question_end(m: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = usize::from(*m.get(at)?);
        if len == 0 {
            at += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointers do not occur in questions
        }
        at += 1 + len;
    }
    (at + 4 <= m.len()).then_some(at + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf() {
        let text = "# comment\nsearch lan\nnameserver fe80::1%en0\nnameserver 0.0.0.0\n\
                    nameserver   192.168.1.1 # router\nnameserver 8.8.8.8\n";
        assert_eq!(parse_resolv_conf(text), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(
            parse_resolv_conf("nameserver 127.0.0.53\n"),
            Some(Ipv4Addr::new(127, 0, 0, 53))
        );
        assert_eq!(
            parse_resolv_conf("; nameserver 1.1.1.1\nnameserver ::1\n"),
            None
        );
        assert_eq!(parse_resolv_conf(""), None);
    }

    #[test]
    fn host_resolver_missing_file_is_none() {
        let r = host_resolver(Path::new("/nonexistent/vemu/resolv.conf")).unwrap();
        assert_eq!(r, None);
        // A directory cannot be read as text: an error, not "no resolver".
        assert!(host_resolver(Path::new("/")).is_err());
    }

    #[test]
    fn servfail_keeps_id_and_question() {
        // id 0x1234, RD, one question: example.com A IN
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        q.extend_from_slice(&[0, 0, 0x29, 0x10, 0, 0, 0, 0, 0, 0, 0]); // EDNS OPT
        let r = servfail(&q).unwrap();
        assert_eq!(r[..2], [0x12, 0x34]);
        assert_eq!(r[2], 0x81);
        assert_eq!(r[3] & 0x0f, 2);
        assert_eq!(r[4..12], [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&r[12..], &q[12..12 + 17]);
        assert!(servfail(&r).is_none(), "responses are not answered");
        assert!(servfail(&[0; 4]).is_none());
    }
}
