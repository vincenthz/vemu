//! User-mode NAT network backend for vemu, in the spirit of qemu's
//! `-netdev user` (libslirp), written from scratch on `std` + `libc`.
//!
//! The guest sees a small virtual network (qemu's defaults):
//!
//! | Address | Role |
//! |---|---|
//! | 10.0.2.15 | the guest, handed out by the built-in DHCP server |
//! | 10.0.2.2 | gateway; also "the host": its TCP/UDP/ICMP go to the host's 127.0.0.1 |
//! | 10.0.2.3 | DNS relay to the host resolver (first IPv4 `nameserver` in `/etc/resolv.conf`) |
//!
//! Traffic to anything outside 10.0.2.0/24 leaves through ordinary
//! unprivileged host sockets: each guest UDP source port gets one unconnected
//! UDP socket (endpoint-independent "full cone" mapping, as in qemu: replies
//! may come from any address and port; idle mappings close after 240 s), DNS
//! queries a socket connected to the host's resolver, ICMP echo goes through
//! an unprivileged ICMP datagram socket, and TCP is terminated in vemu and
//! proxied to a non-blocking host connection. Host port forwards
//! ([`HostFwd`]) listen on the host and open connections to the guest that
//! appear to come from 10.0.2.2.
//!
//! Every flow holds a host file descriptor: [`UserNet::new`] raises the soft
//! `RLIMIT_NOFILE` (up to 4096, within the hard limit) and sizes the flow
//! caps to it. Forwarded TCP connections have a cap of their own; clients
//! beyond it wait in the listen backlog.
//!
//! Structure: the private `stack` module is a sans-IO core (frames in,
//! frames and socket operations out, explicit time) unit-tested with
//! synthetic frames; [`UserNet`] runs it on a thread with a `poll(2)` loop
//! over the host sockets.
//!
//! Not supported: IPv6 (ignored), IP fragments from the guest (dropped;
//! what we send has DF set, so the guest's path MTU is 1500; only packets
//! for the guest larger than that, such as big UDP replies, are fragmented),
//! TCP SACK/timestamps/urgent data, multiple guests. As with qemu, guest TCP
//! keepalives are answered by the NAT itself, and UDP to a closed port gets
//! no ICMP error (unconnected host sockets are not told).

mod config;
mod dhcp;
mod dns;
mod driver;
mod stack;
mod tcp;
mod wire;

pub use config::{HostFwd, HostFwdParseError, Proto, UserNetConfig};
pub use driver::UserNet;
pub use stack::ROUTER_MAC;

#[cfg(test)]
mod tests;
