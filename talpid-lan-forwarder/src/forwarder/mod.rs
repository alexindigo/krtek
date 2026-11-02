//! Single-owner, readiness-driven forwarding with count/size ceilings.

mod stack;

use crate::{
    Disposition, Flow, LocalAuthority, Refused, Transport,
    packet::{self, MAX_PACKET_SIZE, PacketRefusal},
};
use smoltcp::{
    iface::SocketHandle, socket::tcp, time::Instant as StackInstant, wire::TcpSeqNumber,
};
use socket2::{Domain, Protocol, Socket, Type};
use stack::Stack;
use std::{
    collections::{HashMap, VecDeque},
    future::{Future, poll_fn},
    io,
    net::Shutdown,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::Notify,
    task::JoinHandle,
    time::Instant,
};

const TCP_FLOWS: usize = 64;
const TCP_TOMBSTONES: usize = 256;
const _: () = assert!(TCP_TOMBSTONES >= TCP_FLOWS);
const UDP_FLOWS: usize = 256;
const OUTPUT_PACKETS: usize = 256;
const HELD_DATAGRAMS: usize = 4;
const STREAM_BUFFER: usize = 4096;
const CONNECT_LIMIT: Duration = Duration::from_secs(2);
const IDLE_LIMIT: Duration = Duration::from_secs(60);
const RETIRED_TCP_LIMIT: Duration = Duration::from_secs(60);
// Pending datagrams, held SYNs, both output queues, one ingress packet,
// endpoint rings, receive scratch and conservative task/metadata allowance.
const STORAGE_CEILING: usize = UDP_FLOWS * HELD_DATAGRAMS * MAX_PACKET_SIZE
    + TCP_FLOWS * MAX_PACKET_SIZE
    + 2 * OUTPUT_PACKETS * MAX_PACKET_SIZE
    + MAX_PACKET_SIZE
    + TCP_FLOWS * 2 * STREAM_BUFFER
    + TCP_TOMBSTONES * 256
    + OUTPUT_PACKETS * 256
    + MAX_PACKET_SIZE
    + 8 * 1024 * 1024;
const _: () = assert!(STORAGE_CEILING <= 128 * 1024 * 1024);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    pub tcp_flows: usize,
    pub udp_flows: usize,
    pub dropped_disposition: u64,
    pub malformed: u64,
    pub fragments: u64,
    pub unsupported_protocol: u64,
    pub bad_checksum: u64,
    pub denied: u64,
    pub stale: u64,
    pub full: u64,
    pub preparation_failed: u64,
    pub oversized_reply: u64,
    pub revoked: u64,
    pub expired: u64,
    pub stale_reply: u64,
}

struct Task<T> {
    handle: JoinHandle<Result<T, Refused>>,
    result: Option<Result<T, Refused>>,
}
impl<T> Task<T> {
    fn new(handle: JoinHandle<Result<T, Refused>>) -> Self {
        Self {
            handle,
            result: None,
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        if self.result.is_none()
            && let Poll::Ready(result) = Pin::new(&mut self.handle).poll(cx)
        {
            self.result = Some(result.unwrap_or(Err(Refused::PreparationFailed)));
        }
        self.result.is_some()
    }
}
enum Work {
    Preparing(Task<Socket>),
    Connecting(Task<TcpStream>),
    Waiting,
}
impl Work {
    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        match self {
            Self::Preparing(task) => task.poll(cx),
            Self::Connecting(task) => task.poll(cx),
            Self::Waiting => false,
        }
    }
}
struct Pending<G> {
    tcp: Option<Incarnation>,
    grant: G,
    work: Work,
    held: VecDeque<Vec<u8>>,
    deadline: Instant,
    attempt_revision: u64,
    retried: bool,
    expired: bool,
}
struct Tcp<G> {
    incarnation: Incarnation,
    finished_at: Option<Instant>,
    grant: G,
    physical: TcpStream,
    handle: SocketHandle,
    last_activity: Instant,
    physical_eof: bool,
    application_eof: bool,
    application_fin: bool,
    application_reset: bool,
    fin_delivered: bool,
}
struct Udp<G> {
    grant: G,
    physical: UdpSocket,
    held: VecDeque<Vec<u8>>,
    last_activity: Instant,
}
struct Output<G> {
    bytes: Vec<u8>,
    // Only protocol resets can outlive a grant. Application data always retains it.
    grant: Option<G>,
    tcp: Option<TcpOutput>,
}

#[derive(Clone, Copy)]
struct TcpOutput {
    flow: Flow,
    id: u64,
    fin: bool,
    reset: bool,
}

// TCP tuple reuse must not transfer either input or queued-output ownership.
// Keep the original SYN separately from the sliding terminal sequence windows:
// a long stream may wrap its sequence space more than once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Incarnation {
    id: u64,
    application_isn: TcpSeqNumber,
    application_next: TcpSeqNumber,
    peer_isn: Option<TcpSeqNumber>,
    peer_next: Option<TcpSeqNumber>,
}
impl Incarnation {
    fn new(id: u64, syn: stack::Segment) -> Self {
        Self {
            id,
            application_isn: syn.seq,
            application_next: syn.seq + 1,
            peer_isn: None,
            peer_next: None,
        }
    }
    fn observe_output(&mut self, segment: stack::Segment) {
        // A protocol reset reflects rejected input, not this stream's progress.
        if segment.rst {
            return;
        }
        if segment.syn {
            self.peer_isn = Some(segment.seq);
        }
        // Only SYN/data/FIN consumes send sequence space. A cumulative ACK can
        // independently prove newly accepted application SYN/data/FIN progress.
        if segment.end != segment.seq {
            self.peer_next = Some(
                self.peer_next
                    .map_or(segment.end, |old| old.max(segment.end)),
            );
        }
        if let Some(ack) = segment.ack {
            self.application_next = self.application_next.max(ack);
        }
    }
    fn accepts_syn(&self, segment: stack::Segment, valid_syn: bool) -> bool {
        // RFC 1122 4.2.2.13 / RFC 6191: the previous FIN consumed next-1.
        // A distinct ISN alone cannot distinguish overlapping incarnations.
        valid_syn && segment.seq > self.application_next - 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetiredTcp {
    flow: Flow,
    incarnation: Incarnation,
    deadline: Instant,
}

enum TcpInput {
    Ignore,
    Current,
    New,
    Reuse,
    Replace,
}

/// Call `ingest`, `process` and `write_output` from the owning task. Select
/// `wait` for internal progress and sink writability when `has_output` is true.
/// The consumer updates authority inputs before signalling
/// `revalidation_signal`. `close_all` joins even blocking preparations.
pub struct Forwarder<A: LocalAuthority> {
    authority: Arc<A>,
    stack: Stack,
    pending: HashMap<Flow, Pending<A::Grant>>,
    tcp: HashMap<Flow, Tcp<A::Grant>>,
    retired_tcp: Vec<RetiredTcp>,
    next_tcp_id: u64,
    udp: HashMap<Flow, Udp<A::Grant>>,
    output: VecDeque<Output<A::Grant>>,
    stats: Stats,
    started: Instant,
    revision: u64,
    notify: Arc<Notify>,
    mtu: usize,
}

impl<A: LocalAuthority> Forwarder<A> {
    pub fn new(authority: Arc<A>) -> Self {
        Self::with_mtu(authority, 1280)
    }

    pub fn with_mtu(authority: Arc<A>, mtu: usize) -> Self {
        assert!(
            (1280..=MAX_PACKET_SIZE).contains(&mtu),
            "frontend MTU outside packet ceiling"
        );
        Self {
            authority,
            stack: Stack::new(mtu),
            pending: HashMap::new(),
            tcp: HashMap::new(),
            retired_tcp: Vec::new(),
            next_tcp_id: 0,
            udp: HashMap::new(),
            output: VecDeque::new(),
            stats: Stats::default(),
            started: Instant::now(),
            revision: 0,
            notify: Arc::new(Notify::new()),
            mtu,
        }
    }

    pub fn revalidation_signal(&self) -> Arc<Notify> {
        self.notify.clone()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            tcp_flows: self.flow_count(Transport::Tcp),
            udp_flows: self.flow_count(Transport::Udp),
            ..self.stats
        }
    }

    fn flow_count(&self, transport: Transport) -> usize {
        let active = match transport {
            Transport::Tcp => self.tcp.len(),
            Transport::Udp => self.udp.len(),
        };
        active
            + self
                .pending
                .keys()
                .filter(|flow| flow.transport == transport)
                .count()
    }

    fn stack_now(&self) -> StackInstant {
        StackInstant::from_millis(self.started.elapsed().as_millis() as i64)
    }

    fn refused(&mut self, refusal: Refused) {
        match refusal {
            Refused::Denied => self.stats.denied += 1,
            Refused::Stale => self.stats.stale += 1,
            Refused::Full => self.stats.full += 1,
            Refused::PreparationFailed => self.stats.preparation_failed += 1,
        }
    }

    fn enqueue(&mut self, bytes: Vec<u8>, grant: Option<A::Grant>, tcp: Option<TcpOutput>) {
        if self.output.len() < OUTPUT_PACKETS {
            self.output.push_back(Output { bytes, grant, tcp });
        } else {
            self.refused(Refused::Full);
        }
    }

    fn reset(&mut self, bytes: &[u8]) {
        let owner = packet::parse(bytes).ok().and_then(|packet| {
            self.tcp
                .get(&packet.flow)
                .map(|entry| (packet.flow, entry.incarnation.id))
                .or_else(|| {
                    self.pending
                        .get(&packet.flow)
                        .and_then(|entry| entry.tcp.map(|tcp| (packet.flow, tcp.id)))
                })
        });
        self.reset_for(bytes, owner);
    }

    fn reset_for(&mut self, bytes: &[u8], owner: Option<(Flow, u64)>) {
        if let Some(reply) = stack::reset(bytes) {
            self.enqueue(
                reply,
                None,
                owner.map(|(flow, id)| TcpOutput {
                    flow,
                    id,
                    fin: false,
                    reset: true,
                }),
            );
        }
    }

    fn prepare(&self, flow: Flow, grant: &A::Grant) -> Work {
        let authority = self.authority.clone();
        let grant = grant.clone();
        Work::Preparing(Task::new(tokio::task::spawn_blocking(move || {
            if !authority.current(&grant) {
                return Err(Refused::Stale);
            }
            let (kind, protocol) = match flow.transport {
                Transport::Tcp => (Type::STREAM, Protocol::TCP),
                Transport::Udp => (Type::DGRAM, Protocol::UDP),
            };
            let socket = Socket::new(Domain::for_address(flow.destination), kind, Some(protocol))
                .map_err(|_| Refused::PreparationFailed)?;
            authority.prepare(&socket, &grant)?;
            socket
                .set_nonblocking(true)
                .map_err(|_| Refused::PreparationFailed)?;
            Ok(socket)
        })))
    }

    // TIME-WAIT is exclusive ownership, not an overlapping packet filter. Reuse
    // discards its record before admission, so it cannot outrank the new owner.
    fn classify_tcp(&self, flow: Flow, segment: stack::Segment, valid_syn: bool) -> TcpInput {
        if let Some(entry) = self.tcp.get(&flow) {
            if self.graceful_tcp_finished(entry) {
                return if entry.incarnation.accepts_syn(segment, valid_syn) {
                    TcpInput::Replace
                } else {
                    TcpInput::Ignore
                };
            }
            return if segment.syn && segment.seq != entry.incarnation.application_isn {
                TcpInput::Ignore
            } else {
                TcpInput::Current
            };
        }
        if let Some(entry) = self.pending.get(&flow) {
            let incarnation = entry.tcp.expect("TCP pending identity");
            return if segment.syn && segment.seq != incarnation.application_isn
                || segment.rst && segment.seq != incarnation.application_next
            {
                TcpInput::Ignore
            } else {
                TcpInput::Current
            };
        }
        if let Some(old) = self.retired_tcp.iter().find(|old| old.flow == flow) {
            return if old.incarnation.accepts_syn(segment, valid_syn) {
                TcpInput::Reuse
            } else {
                TcpInput::Ignore
            };
        }
        TcpInput::New
    }

    pub fn ingest(&mut self, bytes: &[u8]) {
        let packet = match packet::parse(bytes) {
            Ok(packet) => packet,
            Err(reason) => {
                match reason {
                    PacketRefusal::Malformed => self.stats.malformed += 1,
                    PacketRefusal::Fragment => self.stats.fragments += 1,
                    PacketRefusal::UnsupportedProtocol => self.stats.unsupported_protocol += 1,
                    PacketRefusal::Checksum => self.stats.bad_checksum += 1,
                }
                return;
            }
        };
        let flow = packet.flow;
        if self.authority.disposition(flow.destination.ip()) == Disposition::Drop {
            self.stats.dropped_disposition += 1;
            return;
        }
        self.sweep();
        let tcp_segment = stack::segment(bytes);
        if let Some(segment) = tcp_segment {
            match self.classify_tcp(flow, segment, stack::valid_syn(bytes)) {
                TcpInput::Ignore => return,
                TcpInput::Replace => self.remove_tcp(flow, false),
                TcpInput::Reuse => self.retired_tcp.retain(|old| old.flow != flow),
                TcpInput::Current | TcpInput::New => {}
            }
        }
        if let Some(pending) = self.pending.get_mut(&flow) {
            if flow.transport == Transport::Tcp && packet.tcp_flags.is_some_and(|flags| flags.rst) {
                pending.expired = true;
                pending.held.clear();
                if let Work::Connecting(task) = &pending.work {
                    task.handle.abort();
                }
            }
            if flow.transport == Transport::Udp && !pending.expired {
                if pending.held.len() < HELD_DATAGRAMS {
                    pending.held.push_back(packet.payload.to_vec());
                } else {
                    self.refused(Refused::Full);
                }
            }
            return;
        }
        if let Some(entry) = self.udp.get_mut(&flow) {
            if entry.held.len() < HELD_DATAGRAMS {
                entry.held.push_back(packet.payload.to_vec());
            } else {
                self.refused(Refused::Full);
            }
            self.process();
            return;
        }
        if self.tcp.contains_key(&flow) {
            let now = self.stack_now();
            let previous_state = self
                .stack
                .sockets
                .get::<tcp::Socket<'_>>(self.tcp[&flow].handle)
                .state();
            if !self.stack.receive(bytes, now) {
                self.refused(Refused::Full);
            }
            if let Some(entry) = self.tcp.get_mut(&flow) {
                entry.last_activity = Instant::now();
                // smoltcp validates the sequence before accepting a reset. A
                // reset during SynReceived returns a passive socket to Listen;
                // it must never remain available to claim another owner's tuple.
                let state = self
                    .stack
                    .sockets
                    .get::<tcp::Socket<'_>>(entry.handle)
                    .state();
                entry.application_reset |= packet.tcp_flags.is_some_and(|f| f.rst)
                    && state != previous_state
                    && matches!(state, tcp::State::Closed | tcp::State::Listen);
            }
            self.drain_stack();
            self.process();
            return;
        }
        if flow.transport == Transport::Tcp
            && !packet
                .tcp_flags
                .is_some_and(|flags| flags.syn && !flags.ack)
        {
            self.reset(bytes);
            return;
        }
        if flow.transport == Transport::Tcp && !stack::valid_syn(bytes) {
            self.stats.malformed += 1;
            return;
        }
        let limit = match flow.transport {
            Transport::Tcp => TCP_FLOWS,
            Transport::Udp => UDP_FLOWS,
        };
        let count = self.flow_count(flow.transport);
        // A pending/live owner reserves its eventual TIME-WAIT record. Reuse
        // removed the previous record before arriving here; no tuple has both.
        if count >= limit
            || (flow.transport == Transport::Tcp
                && (count + self.retired_tcp.len() >= TCP_TOMBSTONES
                    || self.next_tcp_id == u64::MAX))
        {
            self.refused(Refused::Full);
            if flow.transport == Transport::Tcp {
                self.reset(bytes);
            }
            return;
        }
        let grant = match self.authority.authorize(flow) {
            Ok(grant) => grant,
            Err(reason) => {
                self.refused(reason);
                if flow.transport == Transport::Tcp && reason != Refused::Stale {
                    self.reset(bytes);
                }
                return;
            }
        };
        let work = self.prepare(flow, &grant);
        let tcp = tcp_segment.map(|syn| {
            let incarnation = Incarnation::new(self.next_tcp_id, syn);
            self.next_tcp_id += 1;
            incarnation
        });
        let held = VecDeque::from([if flow.transport == Transport::Tcp {
            bytes.to_vec()
        } else {
            packet.payload.to_vec()
        }]);
        self.pending.insert(
            flow,
            Pending {
                tcp,
                grant,
                work,
                held,
                deadline: Instant::now() + CONNECT_LIMIT,
                attempt_revision: self.revision,
                retried: false,
                expired: false,
            },
        );
    }

    fn drain_stack(&mut self) {
        while let Some(bytes) = self.stack.device.outgoing.pop_front() {
            let Ok(packet) = packet::parse(&bytes) else {
                self.stats.malformed += 1;
                continue;
            };
            let flow = Flow {
                source: packet.flow.destination,
                destination: packet.flow.source,
                transport: packet.flow.transport,
            };
            let reset = packet.tcp_flags.is_some_and(|flags| flags.rst);
            let fin = packet.tcp_flags.is_some_and(|flags| flags.fin);
            if let Some(entry) = self.tcp.get_mut(&flow) {
                entry
                    .incarnation
                    .observe_output(stack::segment(&bytes).expect("parsed TCP output"));
                let owner = Some(TcpOutput {
                    flow,
                    id: entry.incarnation.id,
                    fin,
                    reset,
                });
                if reset {
                    self.enqueue(bytes, None, owner);
                } else if self.authority.current(&entry.grant) {
                    let grant = entry.grant.clone();
                    self.enqueue(bytes, Some(grant), owner);
                } else {
                    self.stats.stale_reply += 1;
                }
            }
        }
    }

    /// Expiry never detaches a blocking prepare or frees its slot prematurely.
    fn sweep(&mut self) {
        let now = Instant::now();
        self.retired_tcp.retain(|entry| now < entry.deadline);
        let dead: Vec<_> = self
            .tcp
            .iter()
            .filter_map(|(flow, entry)| {
                let revoked = !self.authority.current(&entry.grant);
                (revoked || now >= entry.last_activity + IDLE_LIMIT).then_some((*flow, revoked))
            })
            .collect();
        for (flow, revoked) in dead {
            if revoked {
                self.stats.revoked += 1;
            } else {
                self.stats.expired += 1;
            }
            self.remove_tcp(flow, true);
        }
        self.udp.retain(|_, entry| {
            if !self.authority.current(&entry.grant) {
                self.stats.revoked += 1;
                false
            } else if now >= entry.last_activity + IDLE_LIMIT {
                self.stats.expired += 1;
                false
            } else {
                true
            }
        });
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(flow, entry)| {
                let revoked =
                    flow.transport == Transport::Tcp && !self.authority.current(&entry.grant);
                (!entry.expired && (now >= entry.deadline || revoked)).then_some((*flow, revoked))
            })
            .collect();
        for (flow, revoked) in expired {
            let entry = self.pending.get_mut(&flow).expect("pending expiry");
            entry.expired = true;
            let syn = if flow.transport == Transport::Tcp {
                entry.held.pop_front()
            } else {
                None
            };
            entry.held.clear();
            if let Work::Connecting(task) = &entry.work {
                task.handle.abort();
            }
            if revoked {
                self.stats.revoked += 1;
            } else {
                self.stats.expired += 1;
            }
            if let Some(syn) = syn {
                self.reset(&syn);
            }
        }
        self.pending
            .retain(|_, entry| !(entry.expired && matches!(entry.work, Work::Waiting)));
    }

    fn remove_tcp(&mut self, flow: Flow, reset: bool) {
        let handle = self.tcp[&flow].handle;
        let id = self.tcp[&flow].incarnation.id;
        // Purge before generating the abort, so the new, identity-tagged reset
        // can outlive this socket while its queued payload cannot.
        let before = self.output.len();
        self.output
            .retain(|output| output.tcp.is_none_or(|tcp| tcp.id != id));
        self.stats.stale_reply += (before - self.output.len()) as u64;
        if reset {
            self.stack
                .sockets
                .get_mut::<tcp::Socket<'_>>(handle)
                .abort();
            self.stack.poll(self.stack_now());
            self.drain_stack();
        }
        self.stack.sockets.remove(handle);
        self.tcp.remove(&flow);
    }

    fn graceful_tcp_finished(&self, entry: &Tcp<A::Grant>) -> bool {
        let endpoint = self.stack.sockets.get::<tcp::Socket<'_>>(entry.handle);
        entry.application_eof
            && entry.physical_eof
            && matches!(endpoint.state(), tcp::State::Closed | tcp::State::TimeWait)
            && !endpoint.can_recv()
            && endpoint.send_queue() == 0
    }

    fn retire_finished_tcp(&mut self) {
        debug_assert!(self.flow_count(Transport::Tcp) + self.retired_tcp.len() <= TCP_TOMBSTONES);
        let available = TCP_TOMBSTONES - self.retired_tcp.len();
        let finished: Vec<_> =
            self.tcp
                .iter()
                .filter_map(|(flow, entry)| {
                    (self.graceful_tcp_finished(entry)
                        && entry.fin_delivered
                        && !self.output.iter().any(|output| {
                            output.tcp.is_some_and(|tcp| tcp.id == entry.incarnation.id)
                        }))
                    .then_some(*flow)
                })
                .take(available)
                .collect();
        for flow in finished {
            self.retire_tcp(flow);
        }
    }

    fn retire_tcp(&mut self, flow: Flow) {
        debug_assert!(!self.retired_tcp.iter().any(|old| old.flow == flow));
        let entry = &self.tcp[&flow];
        let retired = RetiredTcp {
            flow,
            incarnation: entry.incarnation,
            deadline: entry.finished_at.unwrap_or_else(Instant::now) + RETIRED_TCP_LIMIT,
        };
        self.remove_tcp(flow, false);
        self.retired_tcp.push(retired);
    }

    fn retry(&mut self, flow: Flow, mut pending: Pending<A::Grant>) {
        match self.authority.authorize(flow) {
            Ok(grant) => {
                pending.work = self.prepare(flow, &grant);
                pending.grant = grant;
                pending.attempt_revision = self.revision;
                pending.retried = true;
                self.pending.insert(flow, pending);
            }
            Err(reason) => self.refused(reason),
        }
    }

    fn failed_pending(&mut self, flow: Flow, mut pending: Pending<A::Grant>, reason: Refused) {
        self.refused(reason);
        if flow.transport == Transport::Tcp {
            if reason != Refused::Stale
                && let Some(syn) = pending.held.front()
            {
                self.reset_for(syn, pending.tcp.map(|tcp| (flow, tcp.id)));
            }
        } else if reason == Refused::Stale && !pending.retried {
            pending.work = Work::Waiting;
            if pending.attempt_revision != self.revision {
                self.retry(flow, pending);
            } else {
                self.pending.insert(flow, pending);
            }
        }
    }

    fn completions(&mut self) {
        let mut cx = Context::from_waker(Waker::noop());
        let done: Vec<_> = self
            .pending
            .iter_mut()
            .filter_map(|(flow, entry)| entry.work.poll(&mut cx).then_some(*flow))
            .collect();
        for flow in done {
            let mut pending = self.pending.remove(&flow).expect("completed pending");
            let work = std::mem::replace(&mut pending.work, Work::Waiting);
            if pending.expired {
                continue;
            }
            match work {
                Work::Preparing(mut task) => {
                    let result = task.result.take().expect("polled prepare");
                    let socket = match result {
                        Ok(socket) if self.authority.current(&pending.grant) => socket,
                        Ok(_) => {
                            self.failed_pending(flow, pending, Refused::Stale);
                            continue;
                        }
                        Err(reason) => {
                            self.failed_pending(flow, pending, reason);
                            continue;
                        }
                    };
                    let destination = self.authority.physical_destination(&pending.grant, flow);
                    if flow.transport == Transport::Tcp {
                        let deadline = pending.deadline;
                        pending.work = Work::Connecting(Task::new(tokio::spawn(async move {
                            tokio::time::timeout_at(
                                deadline,
                                TcpSocket::from_std_stream(socket.into()).connect(destination),
                            )
                            .await
                            .map_err(|_| Refused::PreparationFailed)?
                            .map_err(|_| Refused::PreparationFailed)
                        })));
                        self.pending.insert(flow, pending);
                    } else {
                        let result = socket
                            .connect(&destination.into())
                            .and_then(|()| UdpSocket::from_std(socket.into()));
                        match result {
                            Ok(physical) => {
                                self.udp.insert(
                                    flow,
                                    Udp {
                                        grant: pending.grant,
                                        physical,
                                        held: pending.held,
                                        last_activity: Instant::now(),
                                    },
                                );
                            }
                            Err(_) => {
                                self.failed_pending(flow, pending, Refused::PreparationFailed)
                            }
                        }
                    }
                }
                Work::Connecting(mut task) => {
                    let physical = match task.result.take().expect("polled connect") {
                        Ok(physical) if self.authority.current(&pending.grant) => physical,
                        Ok(_) => {
                            self.failed_pending(flow, pending, Refused::Stale);
                            continue;
                        }
                        Err(reason) => {
                            self.failed_pending(flow, pending, reason);
                            continue;
                        }
                    };
                    let syn = pending.held.front().expect("held SYN");
                    // Attribute every older stack packet before a tuple can be
                    // installed with a different incarnation identity.
                    self.drain_stack();
                    let Some(handle) = self.stack.accept_syn(flow, syn, self.stack_now()) else {
                        self.failed_pending(flow, pending, Refused::PreparationFailed);
                        continue;
                    };
                    self.tcp.insert(
                        flow,
                        Tcp {
                            incarnation: pending.tcp.expect("connected TCP identity"),
                            finished_at: None,
                            grant: pending.grant,
                            physical,
                            handle,
                            last_activity: Instant::now(),
                            physical_eof: false,
                            application_eof: false,
                            application_fin: false,
                            application_reset: false,
                            fin_delivered: false,
                        },
                    );
                    self.drain_stack();
                }
                Work::Waiting => unreachable!("waiting has no completion"),
            }
        }
    }

    fn pump_tcp(&mut self) {
        let mut removed = Vec::new();
        for (flow, entry) in &mut self.tcp {
            let endpoint = self.stack.sockets.get_mut::<tcp::Socket<'_>>(entry.handle);
            entry.application_fin |= matches!(
                endpoint.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
            );
            if entry.application_reset
                || endpoint.state() == tcp::State::Listen
                || (endpoint.state() == tcp::State::Closed && !entry.application_fin)
            {
                // A validated reset/stack abort discards data immediately. A
                // graceful terminal state, in contrast, can still own rx bytes.
                let _ = socket2::SockRef::from(&entry.physical).set_linger(Some(Duration::ZERO));
                removed.push((*flow, false));
                continue;
            }
            let mut failed = false;
            // Use the endpoint's rings directly: no extra unbounded stream buffers.
            while endpoint.can_recv() && self.authority.current(&entry.grant) {
                let count = endpoint
                    .recv(|data| match entry.physical.try_write(data) {
                        Ok(0) => {
                            failed = true;
                            (0, 0)
                        }
                        Ok(n) => (n, n),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
                        Err(_) => {
                            failed = true;
                            (0, 0)
                        }
                    })
                    .unwrap_or(0);
                if count == 0 {
                    break;
                }
                entry.last_activity = Instant::now();
            }
            if entry.application_fin && !endpoint.may_recv() && !entry.application_eof {
                failed |= socket2::SockRef::from(&entry.physical)
                    .shutdown(Shutdown::Write)
                    .is_err();
                entry.application_eof = true;
            }
            while !entry.physical_eof && endpoint.can_send() && self.authority.current(&entry.grant)
            {
                let count = endpoint
                    .send(|data| match entry.physical.try_read(data) {
                        Ok(0) => {
                            entry.physical_eof = true;
                            (0, 0)
                        }
                        Ok(n) => (n, n),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
                        Err(_) => {
                            failed = true;
                            (0, 0)
                        }
                    })
                    .unwrap_or(0);
                if count == 0 {
                    break;
                }
                entry.last_activity = Instant::now();
            }
            if entry.physical_eof {
                endpoint.close();
            }
            if failed {
                removed.push((*flow, true));
            }
        }
        self.stack.poll(self.stack_now());
        self.drain_stack();
        let finished: Vec<_> = self
            .tcp
            .iter()
            .filter_map(|(flow, entry)| {
                (entry.finished_at.is_none() && self.graceful_tcp_finished(entry)).then_some(*flow)
            })
            .collect();
        for flow in finished {
            self.tcp.get_mut(&flow).expect("finished TCP").finished_at = Some(Instant::now());
        }
        for (flow, reset) in removed {
            self.remove_tcp(flow, reset);
        }
        self.retire_finished_tcp();
    }

    fn pump_udp(&mut self) {
        let mut received = Vec::new();
        let mut removed = Vec::new();
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        // Global per-process receive allowance also bounds transient reply storage.
        let mut slots = OUTPUT_PACKETS - self.output.len();
        for (flow, entry) in &mut self.udp {
            while let Some(payload) = entry.held.front() {
                if !self.authority.current(&entry.grant) {
                    break;
                }
                match entry.physical.try_send(payload) {
                    Ok(n) if n == payload.len() => {
                        entry.held.pop_front();
                        entry.last_activity = Instant::now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    _ => {
                        removed.push(*flow);
                        break;
                    }
                }
            }
            while slots > 0 && self.authority.current(&entry.grant) {
                match entry.physical.try_recv(&mut buffer) {
                    Ok(n) => {
                        slots -= 1;
                        entry.last_activity = Instant::now();
                        match packet::udp_reply(*flow, &buffer[..n]) {
                            Ok(bytes) if bytes.len() <= self.mtu => {
                                received.push((bytes, entry.grant.clone()))
                            }
                            _ => self.stats.oversized_reply += 1,
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        removed.push(*flow);
                        break;
                    }
                }
            }
        }
        for flow in removed {
            self.udp.remove(&flow);
        }
        for (bytes, grant) in received {
            self.enqueue(bytes, Some(grant), None);
        }
    }

    pub fn process(&mut self) {
        self.sweep();
        self.completions();
        self.pump_tcp();
        self.pump_udp();
    }

    /// Whether the owner should select sink writability. This is deliberately
    /// independent of `wait`: a blocked sink cannot make internal work ready.
    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    /// Attempt one whole-packet nonblocking sink write, checking authority at
    /// the syscall boundary on EVERY retry. The callback must perform the write
    /// synchronously, never retain/queue the borrowed bytes. `Ok(false)` means
    /// drained (including discarded revoked packets); `Ok(true)` wrote a packet.
    /// `WouldBlock` retains the head AND its grant. Select sink writability and
    /// retry here; never cache a raw pending packet outside this owner. Other
    /// errors, including a partial packet write, are fatal to the sink owner.
    pub fn write_output(
        &mut self,
        write: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        while let Some(output) = self.output.front() {
            let owns_output = output.tcp.is_none_or(|owner| {
                let current = self
                    .tcp
                    .get(&owner.flow)
                    .map(|entry| entry.incarnation.id)
                    .or_else(|| {
                        self.pending
                            .get(&owner.flow)
                            .and_then(|entry| entry.tcp.map(|tcp| tcp.id))
                    });
                current.map_or(owner.reset, |id| id == owner.id)
            });
            if owns_output
                && output
                    .grant
                    .as_ref()
                    .is_none_or(|grant| self.authority.current(grant))
            {
                let n = write(&output.bytes)?;
                if n != output.bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial IP packet write",
                    ));
                }
                let delivered = output.tcp;
                self.output.pop_front();
                if let Some(TcpOutput {
                    flow,
                    id,
                    fin: true,
                    ..
                }) = delivered
                    && let Some(entry) = self.tcp.get_mut(&flow)
                    && entry.incarnation.id == id
                {
                    entry.fin_delivered = true;
                }
                self.retire_finished_tcp();
                return Ok(true);
            }
            self.output.pop_front();
            self.stats.stale_reply += 1;
        }
        Ok(false)
    }

    pub fn revalidate(&mut self) {
        self.revision = self.revision.wrapping_add(1);
        self.sweep();
        let waiting: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(flow, pending)| matches!(pending.work, Work::Waiting).then_some(*flow))
            .collect();
        for flow in waiting {
            let pending = self.pending.remove(&flow).expect("waiting retry");
            self.retry(flow, pending);
        }
    }

    fn deadline(&mut self) -> Option<Instant> {
        let mut nearest = self
            .pending
            .values()
            .filter(|p| !p.expired)
            .map(|p| p.deadline)
            .chain(self.tcp.values().map(|e| e.last_activity + IDLE_LIMIT))
            .chain(self.udp.values().map(|e| e.last_activity + IDLE_LIMIT))
            .chain(self.retired_tcp.iter().map(|entry| entry.deadline))
            .min();
        if let Some(delay) = self
            .stack
            .interface
            .poll_delay(self.stack_now(), &self.stack.sockets)
        {
            let deadline = Instant::now() + Duration::from_millis(delay.total_millis());
            nearest = Some(nearest.map_or(deadline, |old| old.min(deadline)));
        }
        nearest
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let mut ready = false;
        for pending in self.pending.values_mut() {
            ready |= pending.work.poll(cx);
        }
        for entry in self.tcp.values() {
            let endpoint = self.stack.sockets.get::<tcp::Socket<'_>>(entry.handle);
            if !entry.physical_eof && endpoint.can_send() {
                ready |= entry.physical.poll_read_ready(cx).is_ready();
            }
            if endpoint.can_recv() {
                ready |= entry.physical.poll_write_ready(cx).is_ready();
            }
        }
        for entry in self.udp.values() {
            if self.output.len() < OUTPUT_PACKETS {
                ready |= entry.physical.poll_recv_ready(cx).is_ready();
            }
            if !entry.held.is_empty() {
                ready |= entry.physical.poll_send_ready(cx).is_ready();
            }
        }
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Cancellation-safe: completed tasks remain owned; socket readiness is not consumed.
    pub async fn wait(&mut self) {
        // Do not consume a completion before installing the wait: even a
        // completion producing no app output is work the caller must observe.
        let deadline = self.deadline();
        let notify = self.notify.clone();
        tokio::select! {
            _ = poll_fn(|cx| self.poll_ready(cx)) => {},
            _ = notify.notified() => self.revalidate(),
            _ = async {
                if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; }
                else { std::future::pending::<()>().await; }
            } => {},
        }
        self.process();
    }

    pub async fn close_all(&mut self) {
        // Started blocking work cannot be aborted. Keep every handle across the
        // awaits, so cancelling and resuming close_all still joins all of it.
        for pending in self.pending.values_mut() {
            pending.expired = true;
            pending.held.clear();
            if let Work::Connecting(task) = &pending.work {
                task.handle.abort();
            }
        }
        for pending in self.pending.values_mut() {
            match &mut pending.work {
                Work::Preparing(task) if task.result.is_none() => {
                    task.result = Some(
                        (&mut task.handle)
                            .await
                            .unwrap_or(Err(Refused::PreparationFailed)),
                    );
                }
                Work::Connecting(task) if task.result.is_none() => {
                    task.result = Some(
                        (&mut task.handle)
                            .await
                            .unwrap_or(Err(Refused::PreparationFailed)),
                    );
                }
                _ => {}
            }
        }
        self.pending.clear();
        self.tcp.clear();
        self.retired_tcp.clear();
        self.udp.clear();
        self.output.clear();
        self.stack = Stack::new(self.mtu);
    }
}

#[cfg(test)]
mod tests;
