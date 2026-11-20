//! [`UserNet`]: the [`NetBackend`] and the thread that owns the host sockets.
//!
//! `transmit` / `rx_ready` only queue and wake the thread through a socket
//! pair (the "self-pipe"), as the vemu-core locking rule requires. The thread
//! runs a `poll(2)` loop over the wake socket and every host socket, feeds
//! guest frames and socket events into the sans-IO [`Stack`], executes the
//! [`HostOp`]s it emits, and delivers the frames it produces to the guest.
//! Frames the frontend cannot take yet stay queued until the next wake-up
//! (`rx_ready` is one).

use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSlice, Read, Write as _};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vemu_core::{NetBackend, NetFrontend};

use crate::config::{HostFwd, Proto, UserNetConfig};
use crate::dns;
use crate::stack::{FlowId, HostError, HostOp, Limits, Stack};

/// Guest frames waiting for the thread beyond this are dropped.
const MAX_INBOX_FRAMES: usize = 1024;
/// Frames waiting for guest receive buffers beyond this are dropped.
const MAX_PENDING_FRAMES: usize = 1024;
/// Datagrams read from one UDP socket per wake-up (fairness).
const UDP_BURST: usize = 64;
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// How often resolv.conf is re-read (the host may change networks).
const RESOLV_RECHECK: Duration = Duration::from_secs(5);
/// On shutdown, how long guest data already accepted (ACKed) for host TCP
/// sockets may take to drain to them.
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(1);
/// The soft open-file limit [`UserNet::new`] raises the process to, as far
/// as the hard limit allows: enough for every flow cap in
/// [`Limits::DEFAULT`] plus the rest of the VMM. (macOS shells start
/// processes with a soft limit of 256; this stays below `OPEN_MAX`, which
/// macOS's `setrlimit` refuses to exceed.)
const NOFILE_TARGET: libc::rlim_t = 4096;
/// Descriptors left to the rest of the process (disk images, stdio, the
/// console socket, the hypervisor) when the flow caps are sized to the
/// open-file limit.
const FD_RESERVE: usize = 64;
/// Descriptors the network itself holds besides flows: the wake socket
/// pair, the ICMP socket and a transient one for re-reading resolv.conf.
const FD_FIXED: usize = 4;
/// After accept() fails for lack of descriptors, how long host-forward
/// listeners are left alone (new clients wait in the listen backlog).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(250);
/// Linux ICMP datagram ("ping") sockets put their own identifier (the
/// socket's local port) in every echo request and only receive replies
/// carrying it; macOS sends the identifier it is given.
const ICMP_IDENT_REWRITTEN: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// User-mode NAT backend (see the crate docs). Runs its own `poll(2)`
/// thread, started by [`UserNet::new`].
///
/// The frontend holds an `Arc` to the backend and the backend's thread holds
/// the frontend, so dropping the handles does not stop the thread: call
/// [`UserNet::shutdown`] for that (process exit also does).
pub struct UserNet {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

struct Shared {
    inbox: Mutex<Inbox>,
    /// A wake byte is in flight (saves a syscall per transmitted frame).
    wake_pending: AtomicBool,
    waker: UnixStream,
}

#[derive(Default)]
struct Inbox {
    frames: VecDeque<Vec<u8>>,
    frontend: Option<Arc<dyn NetFrontend>>,
    stop: bool,
}

impl Shared {
    fn inbox(&self) -> MutexGuard<'_, Inbox> {
        self.inbox.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wake(&self) {
        if !self.wake_pending.swap(true, Ordering::AcqRel) {
            // A full socket buffer means a wake-up is pending anyway; a
            // stopped thread (closed peer) needs none.
            let _ = send_vectored(self.waker.as_raw_fd(), [&[1]]);
        }
    }
}

impl UserNet {
    /// Bind the host forwards (failing like qemu if one cannot be bound),
    /// open the shared ICMP socket if the host allows it, and start the
    /// network thread.
    ///
    /// Every NAT flow holds a host descriptor, so this also raises the
    /// process's soft `RLIMIT_NOFILE` toward 4096 descriptors (never above
    /// the hard limit, never lowering it) and sizes the flow caps to what the
    /// limit leaves after a reserve for the rest of the VMM.
    pub fn new(cfg: UserNetConfig) -> io::Result<Arc<UserNet>> {
        let fds = raise_nofile_limit().saturating_sub(FD_RESERVE + FD_FIXED + cfg.hostfwd.len());
        let limits = Limits::for_fds(fds);

        let mut tcp_listeners = Vec::new();
        let mut udp_listeners = Vec::new();
        for fwd in &cfg.hostfwd {
            let addr = SocketAddrV4::new(fwd.host_addr, fwd.host_port);
            let ctx = |e: io::Error| io::Error::new(e.kind(), format!("hostfwd {fwd}: {e}"));
            match fwd.proto {
                Proto::Tcp => {
                    let l = TcpListener::bind(addr).map_err(ctx)?;
                    l.set_nonblocking(true)?;
                    tcp_listeners.push((l, *fwd));
                }
                Proto::Udp => {
                    let s = UdpSocket::bind(addr).map_err(ctx)?;
                    s.set_nonblocking(true)?;
                    udp_listeners.push((s, *fwd));
                }
            }
        }

        let (waker, wake_rx) = UnixStream::pair()?;
        no_sigpipe(waker.as_raw_fd())?;
        waker.set_nonblocking(true)?;
        wake_rx.set_nonblocking(true)?;
        let icmp = open_icmp_socket().ok();

        let mut stack = Stack::new(&cfg, random_seed());
        stack.set_limits(limits);
        stack.set_icmp_available(icmp.is_some());
        stack.set_icmp_ident_rewritten(ICMP_IDENT_REWRITTEN);
        stack.set_dns_upstream(dns::host_resolver(Path::new(RESOLV_CONF)).unwrap_or(None));

        let shared = Arc::new(Shared {
            inbox: Mutex::new(Inbox::default()),
            wake_pending: AtomicBool::new(false),
            waker,
        });
        let driver = Driver {
            stack,
            shared: shared.clone(),
            wake_rx,
            frontend: None,
            pending: VecDeque::new(),
            icmp,
            udp: HashMap::new(),
            tcp: HashMap::new(),
            tcp_listeners,
            udp_listeners,
            resolv_checked: Instant::now(),
            accept_paused_until: None,
            fd_warned: false,
            buf: vec![0; 64 * 1024],
        };
        let thread = std::thread::Builder::new()
            .name("vemu-net".into())
            .spawn(move || driver.run())?;
        Ok(Arc::new(UserNet {
            shared,
            thread: Mutex::new(Some(thread)),
        }))
    }

    /// Stop the network thread and close every host socket. Idempotent.
    ///
    /// Guest data the stack has already acknowledged to the guest but not
    /// yet written to a host TCP socket gets up to a second to drain first,
    /// so a guest that closes a connection and powers off right away does not
    /// lose the tail of what it sent.
    pub fn shutdown(&self) {
        self.shared.inbox().stop = true;
        self.shared.wake_pending.store(false, Ordering::Release);
        self.shared.wake();
        let handle = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = handle {
            let _ = h.join();
        }
    }
}

impl Drop for UserNet {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl NetBackend for UserNet {
    fn attach(&self, frontend: Arc<dyn NetFrontend>) {
        self.shared.inbox().frontend = Some(frontend);
        self.shared.wake();
    }

    fn transmit(&self, frame: &[u8]) {
        {
            let mut inbox = self.shared.inbox();
            if inbox.frames.len() >= MAX_INBOX_FRAMES {
                return; // the guest's TCP retransmits; UDP is best effort
            }
            inbox.frames.push_back(frame.to_vec());
        }
        self.shared.wake();
    }

    fn rx_ready(&self) {
        self.shared.wake();
    }
}

/// A host TCP socket proxied for one guest connection.
struct TcpSock {
    stream: TcpStream,
    connecting: bool,
    /// EOF (or error) seen on reads.
    read_closed: bool,
    /// The last write hit EWOULDBLOCK: wait for POLLOUT.
    write_blocked: bool,
    /// POLLHUP/POLLERR seen: only poll it again when there is work to do.
    hup: bool,
    /// The connection was reset or failed: no more writes; what is left to
    /// read still goes to the guest, then the stack resets it and closes us.
    reset: bool,
}

#[derive(Clone, Copy)]
enum Token {
    Wake,
    Icmp,
    Udp(FlowId),
    Tcp(FlowId),
    TcpListener(usize),
    UdpListener(usize),
}

struct Driver {
    stack: Stack,
    shared: Arc<Shared>,
    wake_rx: UnixStream,
    frontend: Option<Arc<dyn NetFrontend>>,
    /// Frames for the guest that `deliver` has not accepted yet.
    pending: VecDeque<Vec<u8>>,
    icmp: Option<UdpSocket>,
    udp: HashMap<FlowId, UdpSocket>,
    tcp: HashMap<FlowId, TcpSock>,
    tcp_listeners: Vec<(TcpListener, HostFwd)>,
    udp_listeners: Vec<(UdpSocket, HostFwd)>,
    resolv_checked: Instant,
    /// Host-forward listeners are not polled until then (out of fds).
    accept_paused_until: Option<Instant>,
    /// Running out of descriptors was reported (it is logged once).
    fd_warned: bool,
    buf: Vec<u8>,
}

impl Driver {
    fn run(mut self) {
        let mut fds: Vec<libc::pollfd> = Vec::new();
        let mut tokens: Vec<Token> = Vec::new();
        loop {
            if self
                .accept_paused_until
                .is_some_and(|t| t <= Instant::now())
            {
                self.accept_paused_until = None;
            }
            self.build_poll_set(&mut fds, &mut tokens);
            let deadline = self.stack.next_deadline().into_iter();
            let timeout = match deadline.chain(self.accept_paused_until).min() {
                None => -1,
                Some(d) => {
                    let ms = d
                        .saturating_duration_since(Instant::now())
                        .as_micros()
                        .div_ceil(1000);
                    ms.min(i32::MAX as u128) as i32
                }
            };
            // SAFETY: `fds` holds `fds.len()` initialised pollfd structs and
            // is not touched by anything else during the call.
            let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = writeln!(
                    io::stderr(),
                    "vemu-net: poll failed, network thread exiting: {e}"
                );
                return;
            }
            let now = Instant::now();
            if !self.take_inbox(now) {
                self.flush_to_host(now + SHUTDOWN_FLUSH);
                return;
            }
            for (pfd, token) in fds.iter().zip(&tokens) {
                if pfd.revents != 0 {
                    self.handle_event(*token, pfd.revents, now);
                }
            }
            if self.stack.next_deadline().is_some_and(|d| d <= now) {
                self.stack.on_timer(now);
            }
            self.stack.flush(now);
            self.run_ops(now);
            while self.write_pass(now) {
                self.run_ops(now);
            }
            self.deliver();
        }
    }

    fn build_poll_set(&mut self, fds: &mut Vec<libc::pollfd>, tokens: &mut Vec<Token>) {
        fds.clear();
        tokens.clear();
        let mut add = |fd: RawFd, events: i16, token: Token| {
            fds.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            });
            tokens.push(token);
        };
        add(self.wake_rx.as_raw_fd(), libc::POLLIN, Token::Wake);
        if let Some(s) = &self.icmp {
            add(s.as_raw_fd(), libc::POLLIN, Token::Icmp);
        }
        for (id, s) in &self.udp {
            add(s.as_raw_fd(), libc::POLLIN, Token::Udp(*id));
        }
        for (id, s) in &self.tcp {
            let events = if s.connecting {
                libc::POLLOUT
            } else {
                let mut ev = 0;
                if !s.read_closed && self.stack.tcp_read_budget(*id) > 0 {
                    ev |= libc::POLLIN;
                }
                if s.write_blocked && !s.reset {
                    ev |= libc::POLLOUT;
                }
                ev
            };
            // poll() reports POLLHUP even with no events requested; once
            // seen, skip the socket until there is something to do.
            if events != 0 || !s.hup {
                add(s.stream.as_raw_fd(), events, Token::Tcp(*id));
            }
        }
        // A full forward budget or no descriptors: clients wait in the
        // listen backlog instead of being accepted and dropped.
        if self.stack.tcp_fwd_room() && self.accept_paused_until.is_none() {
            for (i, (l, _)) in self.tcp_listeners.iter().enumerate() {
                add(l.as_raw_fd(), libc::POLLIN, Token::TcpListener(i));
            }
        }
        for (i, (s, _)) in self.udp_listeners.iter().enumerate() {
            add(s.as_raw_fd(), libc::POLLIN, Token::UdpListener(i));
        }
    }

    /// Drain the wake socket and the inbox. Returns false to stop.
    fn take_inbox(&mut self, now: Instant) -> bool {
        while matches!((&self.wake_rx).read(&mut self.buf[..64]), Ok(n) if n > 0) {}
        self.shared.wake_pending.store(false, Ordering::Release);
        let (frames, frontend, stop) = {
            let mut inbox = self.shared.inbox();
            (
                std::mem::take(&mut inbox.frames),
                inbox.frontend.take(),
                inbox.stop,
            )
        };
        if stop {
            return false;
        }
        if frontend.is_some() {
            self.frontend = frontend;
        }
        if now.duration_since(self.resolv_checked) >= RESOLV_RECHECK {
            self.resolv_checked = now;
            // A failed read (out of descriptors...) keeps the last resolver.
            if let Ok(up) = dns::host_resolver(Path::new(RESOLV_CONF)) {
                self.stack.set_dns_upstream(up);
            }
        }
        for f in &frames {
            self.stack.handle_frame(f, now);
        }
        true
    }

    fn handle_event(&mut self, token: Token, revents: i16, now: Instant) {
        match token {
            Token::Wake => {} // drained in take_inbox
            Token::Icmp => self.icmp_readable(now),
            Token::Udp(id) => self.udp_readable(id, now),
            Token::Tcp(id) => self.tcp_event(id, revents, now),
            Token::TcpListener(i) => self.accept(i, now),
            Token::UdpListener(i) => self.udp_fwd_readable(i, now),
        }
    }

    fn icmp_readable(&mut self, now: Instant) {
        let Some(sock) = &self.icmp else { return };
        for _ in 0..UDP_BURST {
            match sock.recv_from(&mut self.buf) {
                Ok((n, SocketAddr::V4(from))) => {
                    self.stack
                        .icmp_received(*from.ip(), strip_ip_header(&self.buf[..n]), now)
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    fn udp_readable(&mut self, id: FlowId, now: Instant) {
        let Some(sock) = self.udp.get(&id) else {
            return;
        };
        for _ in 0..UDP_BURST {
            match sock.recv_from(&mut self.buf) {
                Ok((n, SocketAddr::V4(from))) => {
                    self.stack.udp_received(id, from, &self.buf[..n], now)
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // e.g. ECONNREFUSED from an ICMP port unreachable.
                    self.stack.udp_error(id, HostError::from_io(&e), false);
                    break;
                }
            }
        }
    }

    fn udp_fwd_readable(&mut self, rule: usize, now: Instant) {
        let (sock, fwd) = &self.udp_listeners[rule];
        for _ in 0..UDP_BURST {
            match sock.recv_from(&mut self.buf) {
                Ok((n, SocketAddr::V4(from))) => {
                    self.stack
                        .udp_fwd_received(rule, fwd.guest_port, from, &self.buf[..n], now)
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {} // a previous reply was refused; keep reading
            }
        }
    }

    fn accept(&mut self, rule: usize, now: Instant) {
        let (listener, fwd) = &self.tcp_listeners[rule];
        let guest_port = fwd.guest_port;
        let mut failure = None;
        // Past the forward budget, clients stay in the listen backlog.
        while self.stack.tcp_fwd_room() {
            let stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            };
            if configure_stream(&stream).is_err() {
                continue;
            }
            if let Some(id) = self.stack.tcp_fwd_accepted(guest_port, now) {
                let sock = TcpSock {
                    stream,
                    connecting: false,
                    read_closed: false,
                    write_blocked: false,
                    hup: false,
                    reset: false,
                };
                self.tcp.insert(id, sock);
            } // else: no free virtual port; the client sees the close
        }
        if let Some(e) = failure
            && is_out_of_fds(&e)
        {
            self.out_of_fds(&e);
            self.accept_paused_until = Some(now + ACCEPT_BACKOFF);
        }
    }

    /// Log (once) that the process ran out of descriptors. The flows that
    /// needed one fail on their own (RST, dropped datagram); nothing else
    /// is torn down.
    fn out_of_fds(&mut self, e: &io::Error) {
        if !self.fd_warned {
            self.fd_warned = true;
            let _ = writeln!(
                io::stderr(),
                "vemu-net: out of file descriptors ({e}); new connections and UDP flows \
                 fail until some close"
            );
        }
    }

    fn tcp_event(&mut self, id: FlowId, revents: i16, now: Instant) {
        let Some(s) = self.tcp.get_mut(&id) else {
            return;
        };
        if s.connecting {
            let result = match s.stream.take_error() {
                Ok(None) => s.stream.peer_addr().map(drop),
                Ok(Some(e)) | Err(e) => Err(e),
            };
            match result {
                Ok(()) => {
                    s.connecting = false;
                    self.stack.tcp_connected(id, now);
                }
                Err(e) => {
                    self.tcp.remove(&id);
                    self.stack
                        .tcp_connect_failed(id, HostError::from_io(&e), now);
                }
            }
            return;
        }
        if revents & libc::POLLOUT != 0 {
            s.write_blocked = false; // the write pass retries
        }
        if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            s.hup = true;
            if matches!(s.stream.take_error(), Ok(Some(_))) {
                self.tcp_reset_seen(id, now);
            }
        }
        if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            self.tcp_read(id, now);
        }
    }

    /// `id`'s host connection was reset or failed. Data the peer sent before
    /// is still readable (and is delivered to the guest before its RST), so
    /// the socket stays until the stack closes it.
    fn tcp_reset_seen(&mut self, id: FlowId, now: Instant) {
        if let Some(s) = self.tcp.get_mut(&id)
            && !s.reset
        {
            s.reset = true;
            s.write_blocked = false;
            self.stack.tcp_host_reset(id, now);
        }
    }

    /// Read from `id`'s host socket what the stack can take: one read
    /// normally (fairness between sockets), everything that is left once the
    /// connection was reset (nothing more can arrive then).
    fn tcp_read(&mut self, id: FlowId, now: Instant) {
        loop {
            let Some(s) = self.tcp.get_mut(&id) else {
                return;
            };
            if s.read_closed || s.connecting {
                return;
            }
            let budget = self.stack.tcp_read_budget(id).min(self.buf.len());
            if budget == 0 {
                return; // more when the guest's window opens
            }
            match s.stream.read(&mut self.buf[..budget]) {
                Ok(0) => {}
                Ok(n) => {
                    self.stack.tcp_host_data(id, &self.buf[..n], now);
                    if s.reset {
                        continue;
                    }
                    return;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && !s.reset => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // An error is only reported once the data before it is read.
                Err(_) => self.tcp_reset_seen(id, now),
            }
            // EOF, or nothing left after a reset.
            if let Some(s) = self.tcp.get_mut(&id) {
                s.read_closed = true;
            }
            self.stack.tcp_host_eof(id, now);
            return;
        }
    }

    /// Write guest data to every host socket that has some and can take it.
    /// Returns true if anything was written.
    fn write_pass(&mut self, now: Instant) -> bool {
        let mut wrote = false;
        let mut failed = Vec::new();
        for (id, s) in &mut self.tcp {
            if s.connecting || s.write_blocked || s.reset {
                continue;
            }
            let (a, b) = self.stack.tcp_to_host(*id);
            if a.is_empty() {
                continue;
            }
            match send_vectored(s.stream.as_raw_fd(), [a, b]) {
                Ok(n) => {
                    wrote |= n > 0;
                    self.stack.tcp_host_wrote(*id, n, now);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => s.write_blocked = true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => failed.push(*id),
            }
        }
        // EPIPE, ECONNRESET...: the peer is gone, but what it sent before
        // may still be waiting to be read.
        for id in failed {
            self.tcp_reset_seen(id, now);
            self.tcp_read(id, now);
        }
        wrote
    }

    /// Write pending guest data to the host TCP sockets until all of it is
    /// written or `deadline` passes (used when stopping).
    fn flush_to_host(&mut self, deadline: Instant) {
        let mut fds = Vec::new();
        loop {
            let now = Instant::now();
            self.run_ops(now);
            while self.write_pass(now) {
                self.run_ops(now);
            }
            fds.clear();
            for (id, s) in &self.tcp {
                if !s.connecting
                    && !s.reset
                    && s.write_blocked
                    && !self.stack.tcp_to_host(*id).0.is_empty()
                {
                    fds.push(libc::pollfd {
                        fd: s.stream.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    });
                }
            }
            let left = deadline.saturating_duration_since(now);
            if fds.is_empty() || left.is_zero() {
                return;
            }
            let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: `fds` holds `fds.len()` initialised pollfd structs and
            // is not touched by anything else during the call.
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) } < 0
                && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                return;
            }
            for s in self.tcp.values_mut() {
                s.write_blocked = false; // the next pass retries every socket
            }
        }
    }

    fn run_ops(&mut self, now: Instant) {
        while let Some(op) = self.stack.pop_op() {
            match op {
                HostOp::UdpOpen { id, connect } => match open_udp(connect) {
                    Ok(s) => {
                        self.udp.insert(id, s);
                    }
                    Err(e) => {
                        if is_out_of_fds(&e) {
                            self.out_of_fds(&e);
                        }
                        self.stack.udp_error(id, HostError::from_io(&e), true)
                    }
                },
                HostOp::UdpSend { id, to, data } => {
                    if let Some(s) = self.udp.get(&id) {
                        let r = match to {
                            Some(to) => s.send_to(&data, to),
                            None => s.send(&data),
                        };
                        if let Err(e) = r
                            && e.kind() != io::ErrorKind::WouldBlock
                        {
                            self.stack.udp_error(id, HostError::from_io(&e), false);
                        }
                    }
                }
                HostOp::UdpClose { id } => {
                    self.udp.remove(&id);
                }
                HostOp::UdpFwdSend { rule, to, data } => {
                    if let Some((s, _)) = self.udp_listeners.get(rule) {
                        let _ = s.send_to(&data, to);
                    }
                }
                HostOp::IcmpSend { dst, msg } => {
                    if let Some(s) = &self.icmp {
                        let _ = s.send_to(&msg, SocketAddrV4::new(dst, 0));
                    }
                }
                HostOp::TcpConnect { id, dst } => match connect_nonblocking(dst) {
                    Ok(stream) => {
                        let sock = TcpSock {
                            stream,
                            connecting: true,
                            read_closed: false,
                            write_blocked: false,
                            hup: false,
                            reset: false,
                        };
                        self.tcp.insert(id, sock);
                    }
                    Err(e) => {
                        if is_out_of_fds(&e) {
                            self.out_of_fds(&e);
                        }
                        self.stack
                            .tcp_connect_failed(id, HostError::from_io(&e), now)
                    }
                },
                HostOp::TcpShutdownWrite { id } => {
                    if let Some(s) = self.tcp.get(&id) {
                        let _ = s.stream.shutdown(Shutdown::Write);
                    }
                }
                HostOp::TcpClose { id, abort } => {
                    if let Some(s) = self.tcp.remove(&id)
                        && abort
                    {
                        let _ = set_linger_zero(&s.stream);
                    }
                }
            }
        }
    }

    /// Hand queued frames to the guest until it runs out of buffers.
    fn deliver(&mut self) {
        while let Some(f) = self.stack.pop_frame() {
            if self.pending.len() < MAX_PENDING_FRAMES {
                self.pending.push_back(f);
            }
        }
        let Some(fe) = &self.frontend else { return };
        while let Some(f) = self.pending.front() {
            if !fe.deliver(f) {
                break; // retried on the next wake-up (rx_ready)
            }
            self.pending.pop_front();
        }
    }
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

/// macOS ICMP datagram sockets return the IP header like raw sockets do
/// (Linux ones return the ICMP message alone).
#[cfg(target_os = "macos")]
fn strip_ip_header(b: &[u8]) -> &[u8] {
    match b.first() {
        Some(v) if v >> 4 == 4 => b.get(usize::from(v & 0x0f) * 4..).unwrap_or(&[]),
        _ => b,
    }
}

#[cfg(not(target_os = "macos"))]
fn strip_ip_header(b: &[u8]) -> &[u8] {
    b
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` points to a live T whose size is passed alongside.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    })
    .map(drop)
}

/// Make close() send RST instead of FIN.
fn set_linger_zero(s: &TcpStream) -> io::Result<()> {
    setsockopt(
        s.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_LINGER,
        &libc::linger {
            l_onoff: 1,
            l_linger: 0,
        },
    )
}

/// Non-blocking, no Nagle (the guest's stack already coalesces), and no
/// SIGPIPE on writes to a closed peer.
fn configure_stream(s: &TcpStream) -> io::Result<()> {
    s.set_nonblocking(true)?;
    s.set_nodelay(true)?;
    no_sigpipe(s.as_raw_fd())
}

/// Writing to a socket whose peer is gone must fail with `EPIPE`, not kill
/// the process (Rust ignores SIGPIPE in its own `main`, but vemu-net does not
/// count on how the embedding program set it up). macOS has a socket option
/// for that; Linux has none and [`send_vectored`] passes `MSG_NOSIGNAL`.
fn no_sigpipe(fd: RawFd) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_NOSIGPIPE,
        &(1 as libc::c_int),
    )?;
    #[cfg(not(target_os = "macos"))]
    let _ = fd;
    Ok(())
}

/// Send `bufs` in order on stream socket `fd` (one `sendmsg`; a short count
/// is possible), never raising SIGPIPE: see [`no_sigpipe`].
fn send_vectored<const N: usize>(fd: RawFd, bufs: [&[u8]; N]) -> io::Result<usize> {
    let iov = bufs.map(IoSlice::new);
    // SAFETY: msghdr is plain old data, for which all-zero is valid (no
    // address, no control data; musl's padding fields stay zero).
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    // IoSlice is ABI-compatible with iovec on Unix; sendmsg only reads it.
    msg.msg_iov = iov.as_ptr().cast_mut().cast();
    msg.msg_iovlen = iov.len() as _;
    #[cfg(not(target_os = "macos"))]
    let flags = libc::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = 0;
    // SAFETY: `msg` points at `iov`, whose slices are borrowed for the call
    // and whose length is passed alongside; the kernel only reads them.
    let r = unsafe { libc::sendmsg(fd, &msg, flags) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

fn sockaddr_in(a: SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain old data, for which all-zero is valid.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = a.port().to_be();
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from(*a.ip()).to_be(),
    };
    sa
}

/// A new non-blocking, close-on-exec AF_INET socket. Linux sets both flags
/// atomically at creation (no window for a concurrent fork+exec to inherit
/// it); macOS has no such socket(2) flags.
fn inet_socket(ty: libc::c_int, proto: libc::c_int) -> io::Result<OwnedFd> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let ty = ty | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
        // SAFETY: socket(2) with integer arguments; the result is checked.
        let fd = cvt(unsafe { libc::socket(libc::AF_INET, ty, proto) })?;
        // SAFETY: `fd` was just created and is owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SAFETY: socket(2) with integer arguments; the result is checked.
        let fd = cvt(unsafe { libc::socket(libc::AF_INET, ty, proto) })?;
        // SAFETY: `fd` was just created and is owned by nobody else.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: fcntl on the descriptor we own, with integer arguments.
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
        // SAFETY: as above.
        let fl = cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
        // SAFETY: as above.
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) })?;
        Ok(owned)
    }
}

/// Start a non-blocking TCP connect (std only has blocking connects).
fn connect_nonblocking(dst: SocketAddrV4) -> io::Result<TcpStream> {
    let stream = TcpStream::from(inet_socket(libc::SOCK_STREAM, 0)?);
    let fd = stream.as_raw_fd();
    configure_stream(&stream)?;
    let sa = sockaddr_in(dst);
    // SAFETY: `sa` is a valid sockaddr_in that outlives the call, and the
    // length passed matches its type.
    let r = unsafe {
        libc::connect(
            fd,
            (&sa as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(stream)
}

/// A UDP socket on an ephemeral port: unconnected for a NAT mapping, which
/// sends anywhere with `send_to` and receives from anyone, or connected to
/// `connect` (the DNS relay).
fn open_udp(connect: Option<SocketAddrV4>) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    if let Some(dst) = connect {
        s.connect(dst)?;
    }
    s.set_nonblocking(true)?;
    Ok(s)
}

fn is_out_of_fds(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

/// Raise the soft `RLIMIT_NOFILE` toward [`NOFILE_TARGET`] (bounded by the
/// hard limit; never lowered) and return the soft limit now in force.
fn raise_nofile_limit() -> usize {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the rlimit struct we pass, which lives
    // for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return 256; // macOS's default soft limit: a conservative guess
    }
    let target = NOFILE_TARGET.min(rl.rlim_max);
    if rl.rlim_cur < target {
        let raised = libc::rlimit {
            rlim_cur: target,
            rlim_max: rl.rlim_max,
        };
        // SAFETY: setrlimit only reads the rlimit struct we pass, which
        // lives for the duration of the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            rl.rlim_cur = target;
        }
    }
    usize::try_from(rl.rlim_cur).unwrap_or(usize::MAX)
}

/// The unprivileged ICMP socket (`SOCK_DGRAM`, `IPPROTO_ICMP`) used for
/// echo requests. It is wrapped in a `UdpSocket` purely for its
/// `send_to`/`recv_from` on an AF_INET datagram descriptor.
///
/// Linux allows it only to groups in `net.ipv4.ping_group_range` (many
/// distributions open it to everyone, the kernel default is nobody); without
/// it, echo to the gateway is answered by the stack itself and other echoes
/// are dropped.
fn open_icmp_socket() -> io::Result<UdpSocket> {
    Ok(UdpSocket::from(inet_socket(
        libc::SOCK_DGRAM,
        libc::IPPROTO_ICMP,
    )?))
}

fn random_seed() -> u64 {
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok()
    {
        return u64::from_ne_bytes(b);
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    t.as_nanos() as u64 ^ (u64::from(std::process::id()) << 32)
}
