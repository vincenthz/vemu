//! The guest-facing half of a proxied TCP connection.
//!
//! The NAT terminates the guest's TCP: a [`TcpConn`] is a full TCP endpoint
//! talking to the guest, and its byte streams are spliced to a host socket by
//! the driver. Data flows through two bounded buffers:
//!
//! - `snd_buf`: host bytes on their way to the guest, from `snd_una` on
//!   (unacknowledged and not yet sent). The driver may read from the host only
//!   [`TcpConn::read_budget`] bytes, which keeps everything buffered inside the
//!   guest's advertised window, so a slow guest back-pressures the host peer
//!   through the host kernel's TCP.
//! - `rcv_buf`: guest bytes waiting to be written to the host socket. The
//!   window advertised to the guest is the free space in this buffer, so a
//!   slow host peer back-pressures the guest.
//!
//! Implemented: MSS and window-scale options, RFC 6298 retransmission timer
//! with Karn's rule and exponential backoff, slow start / congestion
//! avoidance with fast retransmit on three duplicate ACKs, zero-window
//! probing (persist timer), half-close in both directions, RST in both
//! directions, TIME_WAIT. Out-of-order guest segments are dropped and
//! answered with a duplicate ACK (the guest is one virtio hop away, so
//! reordering does not happen in practice). No SACK, timestamps or urgent
//! data.
//!
//! When the host connection is reset, the guest still gets every byte the
//! host peer sent before the reset (what is buffered here and what the
//! driver can still read from the socket), then a RST, as an end-to-end
//! TCP client would.
//!
//! Known limitation, shared with every slirp-style NAT (qemu's included):
//! the guest's keepalive probes are answered by this endpoint, not by the
//! remote host, so guest keepalives never detect a dead remote. The host
//! socket only notices once data is in flight (retransmission timeout).

use std::collections::VecDeque;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::stack::{Ctx, FlowId, HostOp};
use crate::wire::{TcpHeader, TcpSegment, tcp_flags::*};

/// Largest segment payload we send or accept (Ethernet MTU 1500).
pub const MSS: u16 = 1460;
/// Default MSS when the guest's SYN has no MSS option (RFC 9293).
const DEFAULT_MSS: u16 = 536;
/// Host-to-guest buffer cap (unacknowledged + unsent).
pub const SND_BUF_CAP: usize = 256 * 1024;
/// Guest-to-host buffer cap: the largest window we advertise.
pub const RCV_BUF_CAP: usize = 256 * 1024;
/// Our window-scale shift: `RCV_BUF_CAP >> RCV_WSCALE` fits in 16 bits.
const RCV_WSCALE: u8 = 3;
const INITIAL_CWND_SEGMENTS: u32 = 10;

const RTO_INITIAL: Duration = Duration::from_secs(1);
const RTO_MIN: Duration = Duration::from_millis(200);
const RTO_MAX: Duration = Duration::from_secs(60);
const PERSIST_MAX: Duration = Duration::from_secs(60);
/// Retransmissions of a SYN or SYN-ACK before giving up.
const SYN_RETRIES: u32 = 6;
/// Retransmissions of data or FIN before resetting the connection.
const DATA_RETRIES: u32 = 12;
/// How long a host connect() may take before the guest is told the host is
/// unreachable.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// TIME_WAIT duration (2 MSL). The guest is one hop away, so a short MSL is
/// plenty to absorb a retransmitted FIN.
pub const TIME_WAIT: Duration = Duration::from_secs(2);
/// After a host reset, how long the guest gets to take the host data still
/// buffered before it is reset anyway (a guest that keeps a zero window).
pub const RESET_LINGER: Duration = Duration::from_secs(60);

/// `a < b` in sequence space.
fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn le(a: u32, b: u32) -> bool {
    a == b || lt(a, b)
}

/// Where the connection is in its lifecycle. Once synchronized, half-close
/// progress is tracked by the `guest_fin` / `fin_*` flags rather than by
/// separate RFC 9293 states (FIN-WAIT, CLOSE-WAIT, LAST-ACK, CLOSING):
/// the proxy treats both directions symmetrically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Guest SYN seen; the host connect() is in progress. Nothing has been
    /// sent to the guest yet: it only gets a SYN-ACK once the host accepts.
    Connecting,
    /// Host connected, SYN-ACK sent, waiting for the guest's ACK.
    SynReceived,
    /// Host-forwarded connection: our SYN sent, waiting for the guest's SYN-ACK.
    SynSent,
    /// Synchronized.
    Open,
    /// Both FINs exchanged and acknowledged after we closed first; lingering
    /// to re-ACK a retransmitted guest FIN.
    TimeWait,
    /// Done; the stack drops the connection.
    Closed,
}

pub struct TcpConn {
    pub id: FlowId,
    /// The remote endpoint as the guest sees it (e.g. 10.0.2.2:80).
    pub remote: SocketAddrV4,
    pub guest_port: u16,
    pub phase: Phase,
    /// Opened by a host forward (an active open toward the guest).
    pub forwarded: bool,

    // Send side (us -> guest).
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent (snd_nxt can move back on retransmit).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_shift: u8,
    mss: u32,
    snd_buf: VecDeque<u8>,
    /// The host reached EOF: send FIN after the buffered data.
    fin_queued: bool,
    fin_sent: bool,
    fin_acked: bool,
    /// The host connection was reset: deliver the host data, then reset
    /// the guest instead of sending FIN.
    reset_queued: bool,
    /// After a reset, the driver has read everything left in the socket.
    host_drained: bool,
    cwnd: u32,
    ssthresh: u32,
    dupacks: u32,

    // Timers.
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    rtx_deadline: Option<Instant>,
    retries: u32,
    /// (sequence number that acknowledges the timed segment, send time).
    rtt_sample: Option<(u32, Instant)>,
    persist_deadline: Option<Instant>,
    persist_backoff: Duration,
    /// Connect timeout (Connecting) or end of TIME_WAIT.
    phase_deadline: Option<Instant>,

    // Receive side (guest -> us).
    rcv_nxt: u32,
    rcv_shift: u8,
    /// Right edge of the window last advertised (never moves left).
    rcv_adv: u32,
    rcv_buf: VecDeque<u8>,
    guest_fin: bool,
    /// We sent our FIN before the guest's FIN arrived (so we TIME_WAIT).
    closed_first: bool,
    ack_pending: bool,

    /// The host socket still exists (no TcpClose op emitted yet).
    host_open: bool,
    host_shut_wr: bool,
    /// IP header + 8 bytes of the guest's SYN, quoted by ICMP errors.
    pub syn_quote: Vec<u8>,
}

impl TcpConn {
    fn blank(id: FlowId, remote: SocketAddrV4, guest_port: u16, iss: u32, phase: Phase) -> Self {
        TcpConn {
            id,
            remote,
            guest_port,
            phase,
            forwarded: false,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_shift: 0,
            mss: u32::from(DEFAULT_MSS),
            snd_buf: VecDeque::new(),
            fin_queued: false,
            fin_sent: false,
            fin_acked: false,
            reset_queued: false,
            host_drained: false,
            cwnd: 0,
            ssthresh: u32::MAX,
            dupacks: 0,
            srtt: None,
            rttvar: Duration::ZERO,
            rto: RTO_INITIAL,
            rtx_deadline: None,
            retries: 0,
            rtt_sample: None,
            persist_deadline: None,
            persist_backoff: RTO_INITIAL,
            phase_deadline: None,
            rcv_nxt: 0,
            rcv_shift: 0,
            rcv_adv: 0,
            rcv_buf: VecDeque::new(),
            guest_fin: false,
            closed_first: false,
            ack_pending: false,
            host_open: true,
            host_shut_wr: false,
            syn_quote: Vec::new(),
        }
    }

    /// A guest SYN to `remote`: the stack asks the driver to connect, and the
    /// handshake continues in [`TcpConn::host_connected`].
    pub fn inbound(
        id: FlowId,
        remote: SocketAddrV4,
        syn: &TcpSegment<'_>,
        syn_quote: Vec<u8>,
        iss: u32,
        now: Instant,
    ) -> Self {
        let mut c = Self::blank(id, remote, syn.sport, iss, Phase::Connecting);
        c.rcv_nxt = syn.seq.wrapping_add(1);
        c.mss = u32::from(syn.mss.unwrap_or(DEFAULT_MSS).clamp(64, MSS));
        if let Some(ws) = syn.wscale {
            c.snd_shift = ws;
            c.rcv_shift = RCV_WSCALE;
        }
        c.snd_wnd = u32::from(syn.window); // never scaled in a SYN
        c.snd_wl1 = syn.seq;
        c.snd_wl2 = iss;
        c.cwnd = INITIAL_CWND_SEGMENTS * c.mss;
        c.syn_quote = syn_quote;
        c.phase_deadline = Some(now + CONNECT_TIMEOUT);
        c
    }

    /// A host-forwarded connection: actively open to the guest's `guest_port`.
    pub fn outbound(
        id: FlowId,
        remote: SocketAddrV4,
        guest_port: u16,
        iss: u32,
        ctx: &mut Ctx<'_>,
    ) -> Self {
        let mut c = Self::blank(id, remote, guest_port, iss, Phase::SynSent);
        c.forwarded = true;
        c.rcv_shift = RCV_WSCALE; // tentatively; dropped if the guest does not scale
        c.send_syn(ctx);
        c
    }

    // ------------------------------------------------------------------
    // Driver-facing API
    // ------------------------------------------------------------------

    /// The host connect() completed: answer the guest's SYN.
    pub fn host_connected(&mut self, ctx: &mut Ctx<'_>) {
        if self.phase != Phase::Connecting {
            return;
        }
        self.phase = Phase::SynReceived;
        self.phase_deadline = None;
        self.send_syn(ctx);
    }

    /// How many bytes the driver may read from the host socket now.
    pub fn read_budget(&self) -> usize {
        if self.phase != Phase::Open || self.fin_queued || self.host_drained {
            return 0;
        }
        let limit = (self.snd_wnd as usize).min(SND_BUF_CAP);
        limit.saturating_sub(self.snd_buf.len())
    }

    /// Bytes read from the host (at most [`read_budget`](Self::read_budget)).
    pub fn host_data(&mut self, data: &[u8], ctx: &mut Ctx<'_>) {
        debug_assert!(data.len() <= self.read_budget());
        self.snd_buf.extend(data);
        self.output(ctx);
    }

    /// The host peer closed its sending side or, after
    /// [`host_reset`](Self::host_reset), the socket has nothing left to read.
    pub fn host_eof(&mut self, ctx: &mut Ctx<'_>) {
        if self.reset_queued {
            self.host_drained = true;
            self.maybe_reset(ctx);
        } else if self.phase == Phase::Open && !self.fin_queued {
            self.fin_queued = true;
            self.output(ctx);
        }
    }

    /// The host socket was reset or failed. Before the handshake completes,
    /// reset the guest at once. Otherwise stop taking guest data (the host
    /// cannot receive it), keep sending the host data, and reset the guest
    /// once it has acknowledged all of it and the driver has drained the
    /// socket (see [`host_eof`](Self::host_eof)), or after [`RESET_LINGER`].
    pub fn host_reset(&mut self, ctx: &mut Ctx<'_>) {
        if self.phase != Phase::Open {
            return self.abort(ctx);
        }
        if self.reset_queued {
            return;
        }
        self.reset_queued = true;
        self.rcv_buf.clear();
        self.phase_deadline = Some(ctx.now + RESET_LINGER);
        self.maybe_reset(ctx);
    }

    /// After a host reset: reset the guest once it has everything.
    fn maybe_reset(&mut self, ctx: &mut Ctx<'_>) {
        let host_done = self.host_drained || self.fin_queued;
        if self.reset_queued
            && self.phase == Phase::Open
            && host_done
            && self.snd_buf.is_empty()
            && self.snd_una == self.snd_max
        {
            self.abort(ctx);
        }
    }

    /// Guest bytes waiting for the host socket.
    pub fn to_host(&self) -> (&[u8], &[u8]) {
        self.rcv_buf.as_slices()
    }

    /// The driver wrote `n` bytes of [`to_host`](Self::to_host).
    pub fn host_wrote(&mut self, n: usize, ctx: &mut Ctx<'_>) {
        self.rcv_buf.drain(..n.min(self.rcv_buf.len()));
        if self.phase != Phase::Open {
            return;
        }
        // Receiver-side silly window avoidance: only announce a window that
        // grew by a useful amount.
        let edge = self.rcv_nxt.wrapping_add(self.window_bytes());
        let growth = edge.wrapping_sub(self.rcv_adv);
        if !lt(edge, self.rcv_adv)
            && growth as usize >= (2 * self.mss as usize).min(RCV_BUF_CAP / 2)
        {
            self.send_ack(ctx);
        }
        self.maybe_shutdown_host(ctx);
        self.check_done(ctx);
    }

    /// The earliest timer deadline.
    pub fn deadline(&self) -> Option<Instant> {
        [
            self.rtx_deadline,
            self.persist_deadline,
            self.phase_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn ack_pending(&self) -> bool {
        self.ack_pending
    }

    /// Send the ACK owed for segments processed since the last flush.
    pub fn flush_ack(&mut self, ctx: &mut Ctx<'_>) {
        if self.ack_pending && matches!(self.phase, Phase::Open | Phase::TimeWait) {
            self.send_ack(ctx);
        }
        self.ack_pending = false;
    }

    /// Send RST to the guest and close the host socket (abortively).
    pub fn abort(&mut self, ctx: &mut Ctx<'_>) {
        if matches!(self.phase, Phase::SynReceived | Phase::Open) {
            let h = self.header(self.snd_nxt, RST | ACK);
            ctx.link
                .send_tcp(self.remote, self.guest_port, &h, [&[], &[]]);
        }
        self.close_host(true, ctx);
        self.phase = Phase::Closed;
    }

    /// Fire due timers. Returns true if the host connect() timed out: the
    /// connection is then closed and the stack tells the guest.
    pub fn on_timer(&mut self, ctx: &mut Ctx<'_>) -> bool {
        let now = ctx.now;
        if self.phase_deadline.is_some_and(|d| d <= now) {
            self.phase_deadline = None;
            match self.phase {
                Phase::Connecting => {
                    self.close_host(true, ctx);
                    self.phase = Phase::Closed;
                    return true;
                }
                Phase::TimeWait => self.phase = Phase::Closed,
                Phase::Open if self.reset_queued => {
                    self.abort(ctx); // the guest never took the rest
                    return false;
                }
                _ => {}
            }
        }
        if self.persist_deadline.is_some_and(|d| d <= now) {
            self.persist_deadline = None;
            if self.snd_wnd == 0 && self.phase == Phase::Open {
                // Zero-window probe: an out-of-window ACK makes the guest
                // answer with its current window.
                let h = self.header(self.snd_una.wrapping_sub(1), ACK);
                ctx.link
                    .send_tcp(self.remote, self.guest_port, &h, [&[], &[]]);
                self.persist_backoff = (self.persist_backoff * 2).min(PERSIST_MAX);
                self.persist_deadline = Some(now + self.persist_backoff);
            }
        }
        if self.rtx_deadline.is_some_and(|d| d <= now) {
            self.rtx_deadline = None;
            self.retransmit_timeout(ctx);
        }
        false
    }

    /// The host connect() failed; the driver has already dropped the
    /// socket. With `refused`, answer the guest's SYN with RST (the stack
    /// reports other failures as ICMP unreachable).
    pub fn connect_failed(&mut self, refused: bool, ctx: &mut Ctx<'_>) {
        self.host_open = false;
        if self.phase == Phase::Connecting && refused {
            let h = TcpHeader {
                seq: 0,
                flags: RST | ACK,
                window: 0,
                ..self.header(0, 0)
            };
            ctx.link
                .send_tcp(self.remote, self.guest_port, &h, [&[], &[]]);
        }
        self.phase = Phase::Closed;
    }

    // ------------------------------------------------------------------
    // Guest segments
    // ------------------------------------------------------------------

    /// Process a segment from the guest.
    pub fn on_segment(&mut self, seg: &TcpSegment<'_>, ctx: &mut Ctx<'_>) {
        match self.phase {
            Phase::Connecting => {
                if seg.has(RST) {
                    self.close_host(true, ctx);
                    self.phase = Phase::Closed;
                }
                // Retransmitted SYNs wait for the host connect.
            }
            Phase::SynReceived => self.on_segment_syn_received(seg, ctx),
            Phase::SynSent => self.on_segment_syn_sent(seg, ctx),
            Phase::Open | Phase::TimeWait => self.on_segment_synchronized(seg, ctx),
            Phase::Closed => {}
        }
    }

    fn on_segment_syn_received(&mut self, seg: &TcpSegment<'_>, ctx: &mut Ctx<'_>) {
        if seg.has(RST) {
            if seg.seq == self.rcv_nxt {
                self.close_host(true, ctx);
                self.phase = Phase::Closed;
            }
            return;
        }
        if seg.has(SYN) {
            if seg.seq.wrapping_add(1) == self.rcv_nxt {
                self.send_syn(ctx); // our SYN-ACK was lost
            }
            return;
        }
        if !seg.has(ACK) {
            return;
        }
        if seg.ack != self.iss.wrapping_add(1) {
            let h = TcpHeader {
                seq: seg.ack,
                flags: RST,
                ..self.header(0, 0)
            };
            ctx.link
                .send_tcp(self.remote, self.guest_port, &h, [&[], &[]]);
            return;
        }
        // Our SYN is acknowledged; the rest of the segment (window, data,
        // FIN) is processed as in the synchronized states.
        self.snd_una = seg.ack;
        self.take_rtt_sample(seg.ack, ctx.now);
        self.rtx_deadline = None;
        self.retries = 0;
        self.phase = Phase::Open;
        self.on_segment_synchronized(seg, ctx);
    }

    fn on_segment_syn_sent(&mut self, seg: &TcpSegment<'_>, ctx: &mut Ctx<'_>) {
        if seg.has(ACK) && seg.ack != self.iss.wrapping_add(1) {
            if !seg.has(RST) {
                let h = TcpHeader {
                    seq: seg.ack,
                    flags: RST,
                    ..self.header(0, 0)
                };
                ctx.link
                    .send_tcp(self.remote, self.guest_port, &h, [&[], &[]]);
            }
            return;
        }
        if seg.has(RST) {
            if seg.has(ACK) {
                // Nothing listens on the guest port.
                self.close_host(true, ctx);
                self.phase = Phase::Closed;
            }
            return;
        }
        if !(seg.has(SYN) && seg.has(ACK)) {
            return; // simultaneous open is not supported
        }
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.rcv_adv = self.rcv_nxt; // set properly by the ACK below
        self.mss = u32::from(seg.mss.unwrap_or(DEFAULT_MSS).clamp(64, MSS));
        match seg.wscale {
            Some(ws) => self.snd_shift = ws,
            None => self.rcv_shift = 0,
        }
        self.cwnd = INITIAL_CWND_SEGMENTS * self.mss;
        self.snd_una = seg.ack;
        self.snd_nxt = seg.ack;
        self.snd_wnd = u32::from(seg.window); // unscaled in a SYN
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        self.take_rtt_sample(seg.ack, ctx.now);
        self.rtx_deadline = None;
        self.retries = 0;
        self.phase = Phase::Open;
        self.send_ack(ctx);
    }

    fn on_segment_synchronized(&mut self, seg: &TcpSegment<'_>, ctx: &mut Ctx<'_>) {
        let wnd = self.rcv_room();
        let seg_len = seg.seq_len();
        let in_window = |s: u32| le(self.rcv_nxt, s) && lt(s, self.rcv_nxt.wrapping_add(wnd));
        let acceptable = match (seg_len, wnd) {
            (0, 0) => seg.seq == self.rcv_nxt,
            (0, _) => in_window(seg.seq),
            (_, 0) => false,
            (n, _) => in_window(seg.seq) || in_window(seg.seq.wrapping_add(n - 1)),
        };

        if seg.has(RST) {
            if acceptable || seg.seq == self.rcv_nxt {
                self.close_host(true, ctx);
                self.phase = Phase::Closed;
            }
            return;
        }
        // A zero window accepts no data, but the ACK field of a segment at
        // rcv_nxt must still be processed (RFC 9293 3.10.7.4).
        //
        // This also answers the guest's keepalive probes (seq = rcv_nxt - 1)
        // on behalf of the remote host, whether or not it is still there:
        // inherent to terminating TCP in the NAT, and what qemu's slirp does
        // too (see the module docs).
        if !acceptable && seg.seq != self.rcv_nxt {
            self.send_ack(ctx);
            return;
        }
        if seg.has(SYN) {
            self.send_ack(ctx); // RFC 5961 challenge ACK
            return;
        }
        if !seg.has(ACK) {
            return;
        }
        if !self.process_ack(seg, ctx) {
            return;
        }
        if self.phase == Phase::TimeWait {
            return;
        }

        // Data and FIN. Only in-order data is accepted, and none once the
        // host connection is gone: the guest's retransmissions then meet
        // the RST that follows the host's data.
        if !self.reset_queued && !self.guest_fin && acceptable {
            let skip = self.rcv_nxt.wrapping_sub(seg.seq) as usize;
            if lt(self.rcv_nxt, seg.seq) {
                self.send_ack(ctx); // out of order: duplicate ACK, drop
            } else {
                let data = seg
                    .payload
                    .get(skip.min(seg.payload.len())..)
                    .unwrap_or(&[]);
                let n = data.len().min(self.rcv_room() as usize);
                self.rcv_buf.extend(&data[..n]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
                if n > 0 {
                    self.ack_pending = true;
                }
                if n < data.len() {
                    self.send_ack(ctx); // trimmed to the window
                } else if seg.has(FIN) {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.guest_fin = true;
                    self.ack_pending = true;
                    self.maybe_shutdown_host(ctx);
                }
            }
        } else if !acceptable && seg_len > 0 {
            self.send_ack(ctx); // zero window probe
        }

        self.output(ctx);
        self.check_done(ctx);
        self.maybe_reset(ctx);
    }

    /// Handle the ACK field. Returns false when the segment must be dropped.
    fn process_ack(&mut self, seg: &TcpSegment<'_>, ctx: &mut Ctx<'_>) -> bool {
        let ack = seg.ack;
        if lt(self.snd_max, ack) {
            self.send_ack(ctx); // acknowledges something never sent
            return false;
        }
        let wnd = u32::from(seg.window) << self.snd_shift;
        if lt(self.snd_una, ack) {
            self.ack_new_data(ack, ctx.now);
        } else if ack == self.snd_una
            && seg.payload.is_empty()
            && !seg.has(FIN)
            && wnd == self.snd_wnd
            && self.snd_una != self.snd_max
        {
            self.dupacks += 1;
            if self.dupacks == 3 {
                self.fast_retransmit(ctx);
            }
        }
        // Window update (RFC 9293 3.10.7.4), for acks within snd_una..=snd_max.
        if le(self.snd_una, ack)
            && (lt(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && le(self.snd_wl2, ack)))
        {
            self.snd_wnd = wnd;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = ack;
            if wnd > 0 {
                self.persist_deadline = None;
                self.persist_backoff = self.rto;
            }
        }
        true
    }

    fn ack_new_data(&mut self, ack: u32, now: Instant) {
        let mut acked = ack.wrapping_sub(self.snd_una) as usize;
        if acked > self.snd_buf.len() {
            debug_assert!(self.fin_sent && acked == self.snd_buf.len() + 1);
            self.fin_acked = true;
            acked = self.snd_buf.len();
        }
        self.snd_buf.drain(..acked);
        self.snd_una = ack;
        if lt(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        self.take_rtt_sample(ack, now);
        // Slow start, then congestion avoidance (RFC 5681).
        if self.cwnd < self.ssthresh {
            self.cwnd += (acked as u32).clamp(1, self.mss);
        } else {
            self.cwnd += (self.mss * self.mss / self.cwnd).max(1);
        }
        self.cwnd = self.cwnd.min(SND_BUF_CAP as u32 * 2);
        self.dupacks = 0;
        if self.retries > 0 {
            self.retries = 0;
            self.rto = self.base_rto();
        }
        self.rtx_deadline = (self.snd_una != self.snd_max).then(|| now + self.rto);
    }

    fn take_rtt_sample(&mut self, ack: u32, now: Instant) {
        let Some((seq, sent)) = self.rtt_sample else {
            return;
        };
        if lt(ack, seq) {
            return;
        }
        self.rtt_sample = None;
        let r = now.saturating_duration_since(sent);
        // RFC 6298 section 2.
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(r);
                self.rttvar = self.rttvar * 3 / 4 + diff / 4;
                self.srtt = Some(srtt * 7 / 8 + r / 8);
            }
        }
        self.rto = self.base_rto();
    }

    fn base_rto(&self) -> Duration {
        match self.srtt {
            None => RTO_INITIAL,
            Some(srtt) => {
                (srtt + (self.rttvar * 4).max(Duration::from_millis(10))).clamp(RTO_MIN, RTO_MAX)
            }
        }
    }

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------

    fn flight(&self) -> u32 {
        self.snd_max.wrapping_sub(self.snd_una)
    }

    /// Send whatever the windows allow.
    fn output(&mut self, ctx: &mut Ctx<'_>) {
        if self.phase != Phase::Open {
            return;
        }
        loop {
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
            let off = in_flight as usize;
            if off > self.snd_buf.len() {
                break; // FIN already sent
            }
            let unsent = self.snd_buf.len() - off;
            let room = self.snd_wnd.min(self.cwnd).saturating_sub(in_flight) as usize;
            let n = unsent.min(room).min(self.mss as usize);
            let fin = self.fin_queued && !self.fin_acked && n == unsent;
            if n == 0 && !fin {
                break;
            }
            // Sender silly-window avoidance: no runt segments while the
            // window, not the data, is the limit and ACKs are still due.
            if !fin && n < self.mss as usize && n < unsent && in_flight > 0 {
                break;
            }
            let seq = self.snd_nxt;
            self.send_data(seq, off, n, fin, ctx);
            self.snd_nxt = seq.wrapping_add(n as u32 + u32::from(fin));
            if lt(self.snd_max, self.snd_nxt) {
                if self.rtt_sample.is_none() && !lt(seq, self.snd_max) {
                    self.rtt_sample = Some((self.snd_nxt, ctx.now));
                }
                self.snd_max = self.snd_nxt;
            }
            if fin && !self.fin_sent {
                self.fin_sent = true;
                self.closed_first = !self.guest_fin;
            }
            if self.rtx_deadline.is_none() {
                self.rtx_deadline = Some(ctx.now + self.rto);
            }
            if fin {
                break;
            }
        }
        // Persist timer: the window is zero and nothing is in flight to
        // elicit a window update. Probe even with nothing buffered while the
        // host may still send: reads from the host wait for the window, so
        // a lost window update would otherwise stall the connection.
        let unsent = self.snd_buf.len() > self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        if self.snd_wnd == 0 && (unsent || !self.fin_queued) && self.snd_nxt == self.snd_una {
            if self.persist_deadline.is_none() {
                self.persist_backoff = self.rto;
                self.persist_deadline = Some(ctx.now + self.persist_backoff);
            }
        } else if self.snd_wnd > 0 {
            self.persist_deadline = None;
        }
    }

    /// Send `n` buffered bytes starting `off` bytes after snd_una, as `seq`.
    fn send_data(&mut self, seq: u32, off: usize, n: usize, fin: bool, ctx: &mut Ctx<'_>) {
        let mut flags = ACK;
        if n > 0 && off + n == self.snd_buf.len() {
            flags |= PSH;
        }
        if fin {
            flags |= FIN;
        }
        let h = self.header(seq, flags);
        let (a, b) = self.snd_buf.as_slices();
        let end = off + n;
        let a_part = &a[off.min(a.len())..end.min(a.len())];
        let b_part = &b[off.saturating_sub(a.len())..end.saturating_sub(a.len())];
        ctx.link
            .send_tcp(self.remote, self.guest_port, &h, [a_part, b_part]);
        self.ack_pending = false;
    }

    fn send_ack(&mut self, ctx: &mut Ctx<'_>) {
        let h = self.header(self.snd_nxt, ACK);
        ctx.link
            .send_tcp(self.remote, self.guest_port, &h, [&[], &[]]);
        self.ack_pending = false;
    }

    /// SYN (active open) or SYN-ACK (passive open), with options.
    fn send_syn(&mut self, ctx: &mut Ctx<'_>) {
        let passive = self.phase == Phase::SynReceived;
        let mut h = self.header(self.iss, if passive { SYN | ACK } else { SYN });
        h.mss = Some(MSS);
        if !passive {
            h.ack = 0;
        }
        if self.rcv_shift > 0 {
            h.wscale = Some(self.rcv_shift);
        }
        // The window in a SYN is never scaled.
        h.window = RCV_BUF_CAP.min(usize::from(u16::MAX)) as u16;
        self.rcv_adv = self.rcv_nxt.wrapping_add(u32::from(h.window));
        ctx.link
            .send_tcp(self.remote, self.guest_port, &h, [&[], &[]]);
        self.snd_nxt = self.iss.wrapping_add(1);
        self.snd_max = self.snd_nxt;
        if self.retries == 0 {
            self.rtt_sample = Some((self.snd_nxt, ctx.now));
        }
        self.rtx_deadline = Some(ctx.now + self.rto);
    }

    /// Header for a segment from us with the current ACK and window.
    fn header(&mut self, seq: u32, flags: u8) -> TcpHeader {
        let window = if flags & SYN != 0 {
            0
        } else {
            self.advertise()
        };
        TcpHeader {
            sport: self.remote.port(),
            dport: self.guest_port,
            seq,
            ack: self.rcv_nxt,
            flags,
            window,
            mss: None,
            wscale: None,
        }
    }

    /// Free receive-buffer space in bytes, before scaling.
    fn window_bytes(&self) -> u32 {
        let avail = RCV_BUF_CAP.saturating_sub(self.rcv_buf.len()) as u32;
        let max = u32::from(u16::MAX) << self.rcv_shift;
        // Round down to the scale granularity so the advertised window is exact.
        (avail.min(max) >> self.rcv_shift) << self.rcv_shift
    }

    /// Bytes the guest may still send per our last advertisement.
    fn rcv_room(&self) -> u32 {
        if lt(self.rcv_adv, self.rcv_nxt) {
            0
        } else {
            self.rcv_adv.wrapping_sub(self.rcv_nxt)
        }
    }

    /// Window field for an outgoing segment. The right edge never moves
    /// left by more than the scale granularity (RFC 7323 section 2.4 allows
    /// that much), and rounding down keeps `rcv_adv` within the buffer cap.
    fn advertise(&mut self) -> u16 {
        let promised = (self.rcv_room() >> self.rcv_shift) << self.rcv_shift;
        let wnd = self.window_bytes().max(promised);
        let field = (wnd >> self.rcv_shift).min(u32::from(u16::MAX));
        let edge = self.rcv_nxt.wrapping_add(field << self.rcv_shift);
        if lt(self.rcv_adv, edge) {
            self.rcv_adv = edge;
        }
        field as u16
    }

    // ------------------------------------------------------------------
    // Retransmission
    // ------------------------------------------------------------------

    fn retransmit_timeout(&mut self, ctx: &mut Ctx<'_>) {
        let limit = match self.phase {
            Phase::SynReceived | Phase::SynSent => SYN_RETRIES,
            Phase::Open if self.snd_una != self.snd_max => DATA_RETRIES,
            _ => return,
        };
        self.retries += 1;
        if self.retries > limit {
            self.abort(ctx);
            return;
        }
        self.rtt_sample = None; // Karn: never time a retransmission
        self.rto = (self.rto * 2).min(RTO_MAX);
        match self.phase {
            Phase::SynReceived | Phase::SynSent => self.send_syn(ctx),
            _ => {
                self.ssthresh = (self.flight() / 2).max(2 * self.mss);
                self.cwnd = self.mss;
                self.snd_nxt = self.snd_una; // go back N
                self.output(ctx);
            }
        }
    }

    fn fast_retransmit(&mut self, ctx: &mut Ctx<'_>) {
        self.ssthresh = (self.flight() / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh;
        self.rtt_sample = None;
        let n = self.snd_buf.len().min(self.mss as usize);
        let fin = self.fin_sent && n == self.snd_buf.len();
        self.send_data(self.snd_una, 0, n, fin, ctx);
        self.rtx_deadline = Some(ctx.now + self.rto);
    }

    // ------------------------------------------------------------------
    // Teardown
    // ------------------------------------------------------------------

    fn maybe_shutdown_host(&mut self, ctx: &mut Ctx<'_>) {
        if self.guest_fin && self.rcv_buf.is_empty() && !self.host_shut_wr && self.host_open {
            self.host_shut_wr = true;
            ctx.ops.push_back(HostOp::TcpShutdownWrite { id: self.id });
        }
    }

    fn close_host(&mut self, abort: bool, ctx: &mut Ctx<'_>) {
        if self.host_open {
            self.host_open = false;
            ctx.ops.push_back(HostOp::TcpClose { id: self.id, abort });
        }
    }

    /// Both directions are finished: release the host socket.
    fn check_done(&mut self, ctx: &mut Ctx<'_>) {
        if self.phase == Phase::Open && self.guest_fin && self.fin_acked && self.host_shut_wr {
            self.close_host(false, ctx);
            self.rtx_deadline = None;
            self.persist_deadline = None;
            if self.closed_first {
                self.phase = Phase::TimeWait;
                self.phase_deadline = Some(ctx.now + TIME_WAIT);
            } else {
                self.phase = Phase::Closed;
            }
        }
    }
}
