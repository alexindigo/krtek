//! Raw application IP and a single private, prepaid connectivity pinger.
//! No application flow parsing, translation or control TCP surface lives here.
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
use talpid_netstack::smoltcp_network::{
    SmoltcpIcmpSocket, SmoltcpIpRecv, SmoltcpIpSend, SmoltcpNetworkConfig, SmoltcpNetworkGuard,
    smoltcp_network_retained,
};
use talpid_tunnel::{
    packet_attachment::{
        AttachmentBroker, AttachmentError, AttemptControl, CaptureReceipt, ConfigurationRequest,
        TransportPair, TransportReceive, TransportSend,
    },
    tun_provider::TunConfig,
};
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation};

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
    request: Option<ConfigurationRequest>,
}

impl PendingManaged {
    pub(super) fn new(source: talpid_tunnel::tun_provider::transport::ManagedTun) -> Self {
        Self {
            broker: source.broker,
            config: source.config,
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
                    .request_capture(self.config.clone())
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
        if identity.identity().sources.ipv4 != Some(source)
            || identity.identity().sources.ipv6 != config.tunnel_ipv6()
            || identity.identity().mtu != config.mtu
        {
            return Err(unavailable());
        }
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
            _storage: storage,
            installed: AtomicBool::new(false),
        });
        Ok(ManagedPair {
            send: ManagedSend {
                send,
                ordinary_send,
                owner: owner.clone(),
            },
            receive: ManagedReceive {
                receive,
                ordinary_receive,
                owner: owner.clone(),
                control_first: true,
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
    control_first: bool,
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
            let private = self.control_first;
            self.control_first = !private;
            let packet = if private {
                tokio::select! { biased;
                    _ = self.owner.cancelled() => return Err(unavailable()),
                    packet = self.receive.recv(pool) => either::Either::Left(packet?.next()),
                    packet = self.ordinary_receive.recv() => either::Either::Right(packet.map_err(|_| unavailable())?),
                }
            } else {
                tokio::select! { biased;
                    _ = self.owner.cancelled() => return Err(unavailable()),
                    packet = self.ordinary_receive.recv() => either::Either::Right(packet.map_err(|_| unavailable())?),
                    packet = self.receive.recv(pool) => either::Either::Left(packet?.next()),
                }
            };
            let packet = match packet {
                either::Either::Left(Some(packet)) => {
                    let bytes = packet.into_bytes();
                    if !self.owner.record(&bytes) {
                        continue;
                    }
                    bytes.try_into_ip().map_err(|_| unavailable())?
                }
                either::Either::Left(_) => continue,
                either::Either::Right(packet) => match talpid_netstack::raw_packet::handoff(
                    packet,
                    self.owner.application.as_ref(),
                    |packet| packet,
                ) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                },
            };
            if !self.owner.live() {
                return Err(unavailable());
            }
            return Ok(std::iter::once(packet));
        }
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.owner.control.capability().identity().mtu)
    }
}

pub(super) struct ManagedSend {
    send: SmoltcpIpSend,
    ordinary_send: TransportSend,
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
            Reply::Application => match self.ordinary_send.try_send(&bytes) {
                Ok(()) | Err(AttachmentError::Full | AttachmentError::OrdinaryUnready) => Ok(()),
                Err(_) => Err(unavailable()),
            },
        }
    }
}
