//! Per-attempt application target and a separate prepaid connectivity pinger.
//! Address translation is after capture selection and before SourceFilter;
//! authenticated private replies are demultiplexed before inverse translation.
use crate::{config::Config, connectivity::SmoltcpPinger};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use std::{
    collections::VecDeque,
    io,
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use talpid_netstack::{
    address_translation::{
        Direction, TargetConfig, TargetPacketPath, TranslationError, TranslationOutcome,
    },
    packet_sizing::{Emission, Feedback, FeedbackSide},
    smoltcp_network::{
        SmoltcpIcmpSocket, SmoltcpIpRecv, SmoltcpIpSend, SmoltcpNetworkConfig, SmoltcpNetworkGuard,
        smoltcp_network_retained,
    },
};
use talpid_tunnel::{
    packet_attachment::{
        AttachmentBroker, AttachmentError, AttemptControl, CaptureReceipt, ConfigurationRequest,
        TransportPair, TransportReceive, TransportSend,
    },
    tun_provider::TunConfig,
};
use talpid_types::relay_flow::{
    RelayBufferAllocator, RelayBufferReservation, RelayFlowError, RelaySources,
};

const REQUESTS: usize = 32;
const REQUEST_LIFETIME: Duration = Duration::from_secs(15);
// Private MTU never sizes ordinary IP. At most one ICMP socket, 16 queued
// 50-byte requests, 2 x 256 packet channels, 512 device packets, socket rings,
// channel/stack/ledger metadata and transient processing fit conservatively.
const CONTROL_STORAGE: usize = 4 * 1024 * 1024;
const CONTROL_MTU: u16 = 1280;

pub(super) fn unavailable() -> io::Error {
    // GotaTun retries nonfatal receive errors synchronously. Retirement is
    // terminal, including setup failure: never turn it into a hot retry loop.
    io::ErrorKind::BrokenPipe.into()
}

/// Configuration request ownership exists before any async platform wait.
pub(super) struct PendingManaged {
    broker: AttachmentBroker,
    config: TunConfig,
    capture_config: TunConfig,
    request: Option<ConfigurationRequest>,
}

impl PendingManaged {
    pub(super) fn new(source: talpid_tunnel::tun_provider::transport::ManagedTun) -> Self {
        Self {
            broker: source.broker,
            config: source.config,
            capture_config: source.capture_config,
            request: Some(source.request),
        }
    }

    #[cfg(test)]
    pub(super) fn request(broker: AttachmentBroker, config: TunConfig) -> io::Result<Self> {
        talpid_tunnel::tun_provider::transport::ManagedTun::request(broker, config)
            .map(Self::new)
            .map_err(|_| unavailable())
    }

    /// Retry uses a fresh configuration request, receipt and sole receiver.
    /// The caller must finish joined cleanup of the previous pair first.
    pub(super) async fn create(&mut self, config: &Config) -> io::Result<ManagedPair> {
        let result = self.create_inner(config).await;
        if result.is_err()
            && let Some(request) = &self.request
        {
            // No installed device escaped. The fallible control construction
            // below joins its guard before returning an error.
            request.transport_joined();
        }
        result
    }

    async fn create_inner(&mut self, config: &Config) -> io::Result<ManagedPair> {
        if self.request.is_none() {
            self.request = Some(
                self.broker
                    .request_target_capture(self.config.clone(), self.capture_config.clone())
                    .map_err(|_| unavailable())?,
            );
        }
        let receipt = tokio::time::timeout(
            Duration::from_secs(30),
            self.request.as_mut().expect("request owner").configured(),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
        let pair = self.broker.acquire(&receipt).map_err(|_| unavailable())?;
        let source = config.tunnel_ipv4().ok_or_else(unavailable)?;
        let identity = pair.control.capability();
        if identity.sources().ipv4 != Some(source)
            || identity.sources().ipv6 != config.tunnel_ipv6()
            || identity.mtu() != config.mtu
        {
            return Err(unavailable());
        }
        let path = TargetPacketPath::new(
            TargetConfig {
                target_id: identity.target().get(),
                fixed: identity.identity().sources,
                assigned: RelaySources {
                    ipv4: config.tunnel_ipv4(),
                    ipv6: config.tunnel_ipv6(),
                },
                mtu: config.mtu,
            },
            identity,
            self.broker.application_buffers(),
        )
        .map_err(|_| unavailable())?;
        let storage = self
            .broker
            .control_buffers()
            .try_reserve(CONTROL_STORAGE)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let (network, receive, send, mut guard) = smoltcp_network_retained(
            SmoltcpNetworkConfig {
                ipv4_addr: source,
                ipv6_addr: None,
                mtu: CONTROL_MTU.min(config.mtu),
            },
            storage.clone(),
        );
        let id = rand::random();
        let socket = match network.icmp_socket(id).await {
            Ok(socket) => socket,
            Err(error) => {
                guard.stop().await;
                return Err(error);
            }
        };
        // The handle with TCP methods does not escape this construction.
        drop(network);
        let TransportPair {
            control,
            receive: ordinary_receive,
            send: ordinary_send,
        } = pair;
        let owner = Arc::new(ManagedControl {
            control,
            receipt,
            request: self.request.take().expect("request owner"),
            guard: tokio::sync::Mutex::new(guard),
            socket: Mutex::new(Some(socket)),
            source,
            gateway: config.ipv4_gateway,
            id,
            secret: rand::random(),
            ledger: Mutex::new(Ledger {
                highest: 0,
                live: VecDeque::with_capacity(REQUESTS),
            }),
            application: self.broker.application_buffers(),
            ordinary_send,
            path: Mutex::new(path),
            feedback: tokio::sync::Notify::new(),
            _storage: storage,
            installed: AtomicBool::new(false),
        });
        Ok(ManagedPair {
            send: ManagedSend {
                send,
                owner: owner.clone(),
            },
            receive: ManagedReceive {
                receive,
                ordinary_receive,
                owner: owner.clone(),
                turn: 0,
                emission: None,
            },
            owner,
        })
    }
}

pub(super) struct ManagedPair {
    pub(super) send: ManagedSend,
    pub(super) receive: ManagedReceive,
    pub(super) owner: Arc<ManagedControl>,
}

struct Ledger {
    highest: u64,
    live: VecDeque<(u64, Instant)>,
}

pub(crate) struct ManagedControl {
    control: AttemptControl,
    receipt: CaptureReceipt,
    request: ConfigurationRequest,
    guard: tokio::sync::Mutex<SmoltcpNetworkGuard>,
    socket: Mutex<Option<SmoltcpIcmpSocket>>,
    source: Ipv4Addr,
    gateway: Ipv4Addr,
    id: u16,
    secret: [u8; 32],
    ledger: Mutex<Ledger>,
    application: Arc<dyn RelayBufferAllocator>,
    ordinary_send: TransportSend,
    path: Mutex<TargetPacketPath>,
    feedback: tokio::sync::Notify,
    _storage: Arc<dyn RelayBufferReservation>,
    installed: AtomicBool,
}

impl ManagedControl {
    pub(super) fn live(&self) -> bool {
        // The receipt admits this adapter's initial fd epoch. Ongoing transport
        // and private-control lifetime belongs to the exact tunnel attempt;
        // a coordinated sink handover must not terminate that live target.
        self.control.live()
    }
    pub(super) fn interface(&self) -> String {
        self.control
            .capability()
            .sink()
            .map(|sink| sink.identity().interface.clone())
            .unwrap_or_default()
    }
    pub(crate) fn pinger(&self) -> io::Result<SmoltcpPinger> {
        let socket = self
            .socket
            .lock()
            .expect("private pinger")
            .take()
            .ok_or_else(unavailable)?;
        Ok(SmoltcpPinger::new(
            socket,
            self.gateway,
            self.id,
            self.secret,
        ))
    }
    pub(crate) fn activate(&self) -> io::Result<()> {
        if !self.live() || !self.installed.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        self.control
            .activate_with_receipt(&self.receipt)
            .map_err(|_| unavailable())
    }
    pub(crate) fn publish<T>(&self, operation: impl FnOnce() -> T) -> io::Result<T> {
        self.control
            .capability()
            .with_current(operation)
            .map_err(|_| unavailable())
    }
    pub(super) fn installed(&self) {
        self.installed.store(true, Ordering::Release);
    }
    pub(crate) fn revoke(&self) {
        self.control.detach();
        self.request.cancel();
    }
    pub(crate) async fn cancelled(&self) {
        self.control.cancelled().await;
    }
    pub(super) async fn stop(&self) {
        self.revoke();
        self.path
            .lock()
            .expect("target path")
            .maintain(Instant::now());
        self.guard.lock().await.stop().await;
        // Every production caller has already joined create_devices failure or
        // devices.stop(). The control guard is the final transport task owner.
        self.request.transport_joined();
    }

    // This deliberately recognizes only a plain IPv4 private echo. Fragments,
    // errors/quotations, options and all IPv6 chains remain raw application IP.
    fn echo(&self, bytes: &[u8], outbound: bool) -> Option<u64> {
        if bytes.len() != 70
            || bytes[0] != 0x45
            || bytes[9] != 1
            || u16::from_be_bytes([bytes[2], bytes[3]]) != 70
            || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
            || internet_checksum::checksum(&bytes[..20]) != [0, 0]
            || internet_checksum::checksum(&bytes[20..]) != [0, 0]
        {
            return None;
        }
        let (source, destination) = if outbound {
            (self.source, self.gateway)
        } else {
            (self.gateway, self.source)
        };
        if bytes[12..16] != source.octets()
            || bytes[16..20] != destination.octets()
            || bytes[20..22] != [if outbound { 8 } else { 0 }, 0]
            || bytes[24..26] != self.id.to_be_bytes()
            || bytes[28..60] != self.secret
            || bytes[68..70] != [0, 0]
        {
            return None;
        }
        let counter = u64::from_be_bytes(bytes[60..68].try_into().ok()?);
        (counter != 0 && bytes[26..28] == (counter as u16).to_be_bytes()).then_some(counter)
    }
    fn record(&self, bytes: &[u8]) -> bool {
        let Some(counter) = self.echo(bytes, true) else {
            return false;
        };
        let mut ledger = self.ledger.lock().expect("private ledger");
        ledger
            .live
            .retain(|(_, sent)| sent.elapsed() < REQUEST_LIFETIME);
        if !self.live() || counter <= ledger.highest || ledger.live.len() == REQUESTS {
            return false;
        }
        ledger.highest = counter;
        ledger.live.push_back((counter, Instant::now()));
        true
    }
    fn reply(&self, bytes: &[u8]) -> Reply {
        let Some(counter) = self.echo(bytes, false) else {
            return Reply::Application;
        };
        let mut ledger = self.ledger.lock().expect("private ledger");
        ledger
            .live
            .retain(|(_, sent)| sent.elapsed() < REQUEST_LIFETIME);
        if let Some(index) = ledger.live.iter().position(|(value, _)| *value == counter) {
            ledger.live.remove(index);
            Reply::Private
        } else if counter <= ledger.highest {
            // An exact issued probe remains recognizable after bounded ledger
            // expiry/consumption, without retaining an unbounded replay history.
            Reply::Discard
        } else {
            Reply::Application
        }
    }
}

enum Reply {
    Private,
    Discard,
    Application,
}

#[cfg(test)]
#[path = "tcp_fixture.rs"]
mod tcp_fixture;

pub(super) struct ManagedReceive {
    receive: SmoltcpIpRecv,
    ordinary_receive: TransportReceive,
    owner: Arc<ManagedControl>,
    turn: u8,
    emission: Option<Emission>,
}

impl ManagedControl {
    fn translate(
        &self,
        bytes: &[u8],
        direction: Direction,
    ) -> Result<TranslationOutcome, TranslationError> {
        let result = self.path.lock().expect("target path").process(
            bytes,
            direction,
            self.control.capability().identity().mtu,
            Instant::now(),
        );
        self.feedback.notify_one();
        result
    }
    async fn target_feedback(&self) -> Feedback {
        loop {
            let wake = self.feedback.notified();
            let deadline = {
                let mut path = self.path.lock().expect("target path");
                path.maintain(Instant::now());
                if let Some(feedback) = path.take_feedback_for(FeedbackSide::Target) {
                    return feedback;
                }
                path.deadline()
            };
            match deadline {
                Some(deadline) => {
                    tokio::select! { _ = wake => (), _ = tokio::time::sleep_until(deadline.into()) => () }
                }
                None => wake.await,
            }
        }
    }
    fn refused(&self, reason: TranslationError) {
        self.path.lock().expect("target path").refused(reason);
    }
    fn handoff_refused(&self, error: RelayFlowError, feedback: bool) {
        self.refused(match error {
            RelayFlowError::Full if feedback => TranslationError::FeedbackFull,
            RelayFlowError::Full => TranslationError::Full,
            RelayFlowError::Stale | RelayFlowError::Closed => TranslationError::Stale,
            RelayFlowError::Invalid => TranslationError::Malformed,
        });
    }
    fn flush_app_feedback(&self) {
        loop {
            let feedback = self
                .path
                .lock()
                .expect("target path")
                .take_feedback_for(FeedbackSide::App);
            let Some(feedback) = feedback else {
                return;
            };
            if let Err(error) = self.ordinary_send.try_send_feedback(feedback) {
                self.refused(if error == AttachmentError::Full {
                    TranslationError::FeedbackFull
                } else {
                    TranslationError::Stale
                });
            }
        }
    }
}

impl ManagedReceive {
    async fn ordinary_parts(
        receive: &mut TransportReceive,
        emission: &mut Option<Emission>,
        owner: &ManagedControl,
    ) -> io::Result<talpid_types::relay_flow::RelayPacket> {
        loop {
            if let Some(packet) = emission.as_mut().and_then(Emission::pop) {
                return Ok(packet);
            }
            *emission = None;
            let packet = receive.recv().await.map_err(|_| unavailable())?;
            let view = packet.view();
            match owner.translate(view.bytes(), Direction::Outbound) {
                Ok(TranslationOutcome::Packets(packets)) => *emission = Some(packets),
                Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::App)) => {
                    owner.flush_app_feedback();
                }
                _ => (),
            }
            tokio::task::yield_now().await;
        }
    }
}

enum Selected {
    Private(Option<Packet<Ip>>),
    Application(talpid_types::relay_flow::RelayPacket),
    Feedback(Feedback),
}
impl IpRecv for ManagedReceive {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            if !self.owner.live() {
                return Err(unavailable());
            }
            // Rotate priority: neither an application flood nor private probes
            // can starve the other. Each handoff yields at most one packet.
            let turn = self.turn;
            self.turn = (turn + 1) % 3;
            let owner = self.owner.clone();
            let packet = if turn == 0 {
                tokio::select! { biased;
                    _ = owner.cancelled() => return Err(unavailable()),
                    packet = self.receive.recv(pool) => Selected::Private(packet?.next()),
                    feedback = owner.target_feedback() => Selected::Feedback(feedback),
                    packet = Self::ordinary_parts(&mut self.ordinary_receive, &mut self.emission, &owner) => Selected::Application(packet?),
                }
            } else if turn == 1 {
                tokio::select! { biased;
                    _ = owner.cancelled() => return Err(unavailable()),
                    packet = Self::ordinary_parts(&mut self.ordinary_receive, &mut self.emission, &owner) => Selected::Application(packet?),
                    packet = self.receive.recv(pool) => Selected::Private(packet?.next()),
                    feedback = owner.target_feedback() => Selected::Feedback(feedback),
                }
            } else {
                tokio::select! { biased;
                    _ = owner.cancelled() => return Err(unavailable()),
                    feedback = owner.target_feedback() => Selected::Feedback(feedback),
                    packet = Self::ordinary_parts(&mut self.ordinary_receive, &mut self.emission, &owner) => Selected::Application(packet?),
                    packet = self.receive.recv(pool) => Selected::Private(packet?.next()),
                }
            };
            let packet = match packet {
                Selected::Private(Some(packet)) => {
                    let bytes = packet.into_bytes();
                    if !self.owner.record(&bytes) {
                        continue;
                    }
                    bytes.try_into_ip().map_err(|_| unavailable())?
                }
                Selected::Private(_) => continue,
                Selected::Application(packet) => match talpid_netstack::raw_packet::handoff(
                    packet,
                    self.owner.application.as_ref(),
                    |packet| packet,
                ) {
                    Ok(packet) => packet,
                    Err(error) => {
                        self.owner.handoff_refused(error, false);
                        continue;
                    }
                },
                Selected::Feedback(feedback) => {
                    match talpid_netstack::raw_packet::handoff_feedback(feedback, |packet| packet) {
                        Ok(packet) => packet,
                        Err(error) => {
                            self.owner.handoff_refused(error, true);
                            continue;
                        }
                    }
                }
            };
            if !self.owner.live() {
                return Err(unavailable());
            }
            return Ok(std::iter::once(packet));
        }
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.owner.control.capability().mtu())
    }
}

pub(super) struct ManagedSend {
    send: SmoltcpIpSend,
    owner: Arc<ManagedControl>,
}
impl IpSend for ManagedSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        if !self.owner.live() {
            return Err(unavailable());
        }
        let bytes = packet.into_bytes();
        match self.owner.reply(&bytes) {
            Reply::Private => {
                // Only exact 70-byte private replies enter this fixed stack.
                let packet = bytes.try_into_ip().map_err(|_| unavailable())?;
                tokio::select! { biased;
                    _ = self.owner.cancelled() => Err(unavailable()),
                    result = self.send.send(packet) => result,
                }
            }
            Reply::Discard => Ok(()),
            Reply::Application => {
                if let Ok(TranslationOutcome::Packets(mut packets)) =
                    self.owner.translate(&bytes, Direction::Inbound)
                {
                    while let Some(packet) = packets.pop() {
                        match self.owner.ordinary_send.try_send_packet(packet) {
                            Ok(()) => (),
                            Err(AttachmentError::Full) => {
                                self.owner.refused(TranslationError::Full)
                            }
                            Err(AttachmentError::OrdinaryUnready) => {
                                self.owner.refused(TranslationError::Stale)
                            }
                            Err(_) => return Err(unavailable()),
                        }
                    }
                }
                self.owner.flush_app_feedback();
                Ok(())
            }
        }
    }
}
