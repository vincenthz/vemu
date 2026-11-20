//! Public configuration: addresses of the virtual network and host forwards.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Configuration of the user-mode network, mirroring qemu's `-netdev user`
/// defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserNetConfig {
    /// Network address of the /24 virtual network (10.0.2.0).
    pub net: Ipv4Addr,
    /// The virtual router, which is also the host: traffic to it reaches the
    /// host's 127.0.0.1 (10.0.2.2).
    pub gateway: Ipv4Addr,
    /// The virtual DNS server, relaying to the host's resolver (10.0.2.3).
    pub dns: Ipv4Addr,
    /// The address handed to the guest by DHCP (10.0.2.15).
    pub guest: Ipv4Addr,
    /// The guest's MAC, used until the guest's own frames reveal it.
    pub guest_mac: [u8; 6],
    /// Host port forwards.
    pub hostfwd: Vec<HostFwd>,
}

impl Default for UserNetConfig {
    fn default() -> Self {
        UserNetConfig {
            net: Ipv4Addr::new(10, 0, 2, 0),
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns: Ipv4Addr::new(10, 0, 2, 3),
            guest: DEFAULT_GUEST,
            guest_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            hostfwd: Vec::new(),
        }
    }
}

const DEFAULT_GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

/// Transport protocol of a host forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        })
    }
}

/// A host port forward: connections (TCP) or datagrams (UDP) arriving at
/// `host_addr:host_port` on the host are forwarded to the guest's
/// `guest_port`, appearing to come from the gateway address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostFwd {
    pub proto: Proto,
    pub host_addr: Ipv4Addr,
    pub host_port: u16,
    pub guest_port: u16,
}

/// Error parsing a [`HostFwd`] spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFwdParseError(String);

impl fmt::Display for HostFwdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid hostfwd: {}", self.0)
    }
}

impl std::error::Error for HostFwdParseError {}

impl FromStr for HostFwd {
    type Err = HostFwdParseError;

    /// Parse qemu's `hostfwd` syntax:
    /// `[tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport`.
    ///
    /// Semantics follow qemu: an empty protocol means `tcp`, and an empty
    /// host address means all interfaces (`0.0.0.0`), so `tcp::8080-:80` is
    /// reachable from the LAN; write `tcp:127.0.0.1:8080-:80` to stay local.
    /// The guest address may be empty or the guest's DHCP address
    /// (10.0.2.15): vemu has exactly one guest, so any other address is an
    /// error rather than silently ignored.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |m: &str| HostFwdParseError(format!("{s:?}: {m}"));
        let (host, guest) = s.split_once('-').ok_or_else(|| err("missing '-'"))?;

        let (proto, host) = match host.split_once(':') {
            Some(("tcp" | "", rest)) => (Proto::Tcp, rest),
            Some(("udp", rest)) => (Proto::Udp, rest),
            Some((p, _)) => return Err(err(&format!("unknown protocol {p:?}"))),
            None => return Err(err("expected [tcp|udp]:[hostaddr]:hostport")),
        };
        let (host_addr, host_port) = host
            .rsplit_once(':')
            .ok_or_else(|| err("host side must be [addr]:port"))?;
        let host_addr = if host_addr.is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else {
            host_addr.parse().map_err(|_| err("bad host address"))?
        };

        let (guest_addr, guest_port) = guest
            .rsplit_once(':')
            .ok_or_else(|| err("guest side must be [addr]:port"))?;
        if !guest_addr.is_empty() {
            let a: Ipv4Addr = guest_addr.parse().map_err(|_| err("bad guest address"))?;
            if a != DEFAULT_GUEST {
                return Err(err(
                    "the only guest address is 10.0.2.15 (or leave it empty)",
                ));
            }
        }

        let port = |p: &str, what: &str| -> Result<u16, HostFwdParseError> {
            match p.parse::<u16>() {
                Ok(0) | Err(_) => Err(err(&format!("bad {what} port"))),
                Ok(n) => Ok(n),
            }
        };
        Ok(HostFwd {
            proto,
            host_addr,
            host_port: port(host_port, "host")?,
            guest_port: port(guest_port, "guest")?,
        })
    }
}

impl fmt::Display for HostFwd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}-:{}",
            self.proto, self.host_addr, self.host_port, self.guest_port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(proto: Proto, a: [u8; 4], hp: u16, gp: u16) -> HostFwd {
        HostFwd {
            proto,
            host_addr: a.into(),
            host_port: hp,
            guest_port: gp,
        }
    }

    #[test]
    fn parse_qemu_syntax() {
        assert_eq!(
            "tcp:127.0.0.1:2222-:22".parse(),
            Ok(fwd(Proto::Tcp, [127, 0, 0, 1], 2222, 22))
        );
        assert_eq!(
            "tcp::8080-:80".parse(),
            Ok(fwd(Proto::Tcp, [0, 0, 0, 0], 8080, 80))
        );
        assert_eq!(
            "udp::5353-:53".parse(),
            Ok(fwd(Proto::Udp, [0, 0, 0, 0], 5353, 53))
        );
        assert_eq!(
            "::2222-:22".parse(),
            Ok(fwd(Proto::Tcp, [0, 0, 0, 0], 2222, 22))
        );
        assert_eq!(
            "tcp:127.0.0.1:2222-10.0.2.15:22".parse(),
            Ok(fwd(Proto::Tcp, [127, 0, 0, 1], 2222, 22))
        );
        let f: HostFwd = "udp:127.0.0.1:5353-:53".parse().unwrap();
        assert_eq!(f.to_string().parse(), Ok(f));
    }

    #[test]
    fn parse_errors() {
        for bad in [
            "",
            "tcp:2222:22",
            "sctp::1-:2",
            "tcp::0-:22",
            "tcp::2222-:0",
            "tcp::70000-:22",
            "tcp:localhost:2222-:22",
            "tcp::2222-10.0.2.16:22",
            "tcp::2222-22",
            ":2222-:22",
            "127.0.0.1:2222-:22",
        ] {
            assert!(bad.parse::<HostFwd>().is_err(), "{bad:?} should not parse");
        }
    }
}
