//! Exercise the daemon's actual configuration, classifier and authority through
//! the production capture actor, with real packet and physical socket consumers.
use super::*;
use crate::local_network::ConnectContinuation;
use crate::local_network::TunnelPhase;
use std::os::fd::{BorrowedFd, OwnedFd};
use talpid_tunnel::android_frontend::{
    CaptureConfig, FrontendOwner, FrontendPlatform, FrontendState,
};
use talpid_types::capture_network::{
    CaptureExpectation, CaptureNetworkFeed, CaptureNetworkObservation, CapturePrefix,
};
use talpid_types::local_network::{LocalPhysicalAddress, LocalPhysicalNetwork};
use tokio::net::UnixDatagram;

struct PacketPlatform {
    feed: Arc<CaptureNetworkFeed>,
    expected: Mutex<Option<CaptureExpectation>>,
    opened: Mutex<Vec<talpid_tunnel::tun_provider::TunConfig>>,
    peer: Mutex<Option<std::os::unix::net::UnixDatagram>>,
    starts: AtomicUsize,
    releases: AtomicUsize,
    completed_releases: Mutex<Vec<i64>>,
    released: tokio::sync::Notify,
    fail_release: AtomicBool,
    retain_handover: AtomicBool,
    authority: Mutex<Option<Arc<DeliveryAuthority>>>,
    generation: std::sync::atomic::AtomicI64,
    physical: (SocketAddr, SocketAddr),
}

impl FrontendPlatform for PacketPlatform {
    fn handover(
        &self,
        _: i64,
        generation: i64,
        config: &CaptureConfig,
    ) -> talpid_tunnel::android_frontend::CaptureHandover {
        if self.retain_handover.load(SeqCst) {
            return talpid_tunnel::android_frontend::CaptureHandover {
                descriptor: Err(io::Error::other("before establish")),
                predecessor_retained: true,
            };
        }
        talpid_tunnel::android_frontend::CaptureHandover {
            descriptor: self.open(generation, config),
            predecessor_retained: false,
        }
    }
    fn capture_format(
        &self,
        _: BorrowedFd<'_>,
    ) -> io::Result<talpid_tunnel::android_frontend::CaptureFormat> {
        talpid_tunnel::android_frontend::CaptureFormat::from_flags(0x1001)
    }
    fn open(&self, generation: i64, config: &CaptureConfig) -> io::Result<OwnedFd> {
        if let Some(config) = config.secured_config() {
            self.opened.lock().unwrap().push(config.clone());
        }
        let (capture, peer) = std::os::unix::net::UnixDatagram::pair()?;
        capture.set_nonblocking(true)?;
        peer.set_nonblocking(true)?;
        *self.peer.lock().unwrap() = Some(peer);
        self.generation.store(generation, SeqCst);
        self.starts.fetch_add(1, SeqCst);
        Ok(capture.into())
    }
    fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
        self.feed.clone()
    }
    fn interface_name(&self, _: BorrowedFd<'_>) -> io::Result<String> {
        Ok("tun-owned".into())
    }
    fn expectation(
        &self,
        config: &CaptureConfig,
        interface: String,
    ) -> io::Result<CaptureExpectation> {
        let config = config.secured_config().expect("secured test capture");
        let routes = config
            .routes
            .iter()
            .map(|prefix| CapturePrefix {
                address: prefix.network(),
                prefix_length: i16::from(prefix.prefix()),
            })
            .collect::<Vec<_>>();
        let expected = CaptureExpectation::requested(
            interface,
            1000,
            33,
            &config.addresses,
            &routes,
            &config
                .dns_servers
                .clone()
                .unwrap_or_else(|| config.gateways()),
            config.mtu,
        )
        .unwrap();
        *self.expected.lock().unwrap() = Some(expected.clone());
        Ok(expected)
    }
    fn bind(&self, generation: i64, _: &str) -> io::Result<bool> {
        let expected = self.expected.lock().unwrap().clone().unwrap();
        Ok(self.feed.publish(
            self.feed.registration(),
            generation,
            CaptureNetworkObservation {
                network_handle: generation << 32,
                network: format!("net-{generation}"),
                interface_name: expected.interface_name,
                owner_uid: expected.owner_uid,
                routes: expected.routes,
                addresses: expected.addresses,
                dns_servers: expected.dns_servers,
                mtu: expected.mtu,
                fresh: true,
                lost: false,
                api_level: 33,
            },
        ))
    }
    fn closed(&self, generation: i64) -> io::Result<()> {
        self.releases.fetch_add(1, SeqCst);
        let result = if self.fail_release.load(SeqCst) {
            Err(io::Error::other("test platform retains capture"))
        } else {
            self.completed_releases.lock().unwrap().push(generation);
            Ok(())
        };
        self.released.notify_one();
        result
    }
}

struct PacketFactory(Arc<PacketPlatform>);
struct PacketOwner {
    owner: FrontendOwner,
    authority: Arc<DeliveryAuthority>,
    state: watch::Receiver<FrontendState>,
    open: bool,
}
impl FrontendFactory for PacketFactory {
    type Owner = PacketOwner;
    fn supported(&self) -> bool {
        true
    }
    fn start(
        &self,
        config: DeliveryConfig,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        broker: AttachmentBroker,
    ) -> io::Result<Self::Owner> {
        let updates = authority.subscribe();
        *self.0.authority.lock().unwrap() = Some(authority.clone());
        let mtu = config.mtu();
        let frontend = config.into_frontend(authority.clone());
        let forward_authority = Arc::new(LoopbackAuthority {
            authority: authority.clone(),
            peer: Some(self.0.physical),
        });
        let forwarder = Forwarder::with_mtu(forward_authority, buffers, usize::from(mtu))
            .map_err(|_| io::Error::other("test budget full"))?;
        let owner = FrontendOwner::start(self.0.clone(), frontend, forwarder, updates, broker)?;
        Ok(PacketOwner {
            state: owner.state(),
            owner,
            authority,
            open: true,
        })
    }
}
impl DeliveryOwner for PacketOwner {
    fn handover(&mut self, config: DeliveryConfig) -> io::Result<()> {
        self.owner
            .handover(config.into_frontend(self.authority.clone()))
    }
    fn retry_handover_release(&mut self) -> io::Result<()> {
        self.owner.retry_handover_release()
    }
    async fn ready(&mut self) -> io::Result<()> {
        self.owner.ready().await
    }
    async fn stop(&mut self) -> io::Result<()> {
        self.owner.stop().await
    }
    fn retry_release(&mut self) -> io::Result<()> {
        self.owner.retry_release()
    }
    fn state(&self) -> OwnerState {
        match *self.state.borrow() {
            FrontendState::Running => OwnerState::Running,
            FrontendState::Failed => OwnerState::Failed,
            FrontendState::Stopped => OwnerState::Stopped,
        }
    }
    fn release_failed(&self) -> bool {
        self.owner.release_failed()
    }
    async fn changed(&mut self) {
        if self.open {
            self.open = self.state.changed().await.is_ok();
        } else {
            std::future::pending().await
        }
    }
}

fn physical_snapshot() -> LocalNetworkSnapshot {
    let observed = observation();
    LocalNetworkSnapshot {
        sequence: 9,
        observer_running: true,
        local_ready: true,
        fine_ready: true,
        background_ready: true,
        location_enabled: true,
        location_allowed: true,
        networks: observed
            .networks
            .into_iter()
            .map(|network| LocalPhysicalNetwork {
                network_handle: network.handle,
                transport: 1,
                capabilities_fresh: true,
                links_fresh: true,
                blocked: false,
                interface_index: network.interface_index,
                addresses: network
                    .addresses
                    .into_iter()
                    .map(|address| LocalPhysicalAddress {
                        prefix: LocalPhysicalPrefix {
                            address: address.prefix.ip(),
                            prefix_length: i16::from(address.prefix.prefix()),
                        },
                        usable: true,
                    })
                    .collect(),
                routes: network.routes,
                ssid_hex: network.ssid.map(|ssid| ssid.encoded_bytes()),
            })
            .collect(),
    }
}

async fn capture_reply(peer: &UnixDatagram) -> Vec<u8> {
    let mut bytes = vec![0; 65575];
    let count = bounded(peer.recv(&mut bytes)).await.unwrap();
    bytes.truncate(count);
    bytes
}

#[tokio::test]
async fn daemon_route_handover_retains_the_partial_grant_and_same_physical_tcp_stream() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let physical_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        for nonce in [
            b"before".as_slice(),
            b"routes",
            b"secured",
            b"exclusions",
            b"partial",
        ] {
            let mut bytes = vec![0; nonce.len()];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, nonce);
            stream.write_all(&bytes).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), tcp.accept())
                .await
                .is_err()
        );
    });
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(43),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical,
    });
    let authority = authority();
    authority.update(&policy(), Some(observation()));
    let buffers = DeliveryBuffers::new();
    let broker = broker();
    let mut delivery = Delivery::new(
        PacketFactory(platform.clone()),
        authority.clone(),
        buffers.local.clone(),
        broker.clone(),
    );
    delivery
        .maintain_config(Some(DeliveryConfig::Partial(
            vec!["10.0.2.2/32".into()].into(),
        )))
        .await;
    bounded(delivery.changed()).await;
    let mut peer = UnixDatagram::from_std(platform.peer.lock().unwrap().take().unwrap()).unwrap();
    let local = flow(Transport::Tcp, 45901);
    let grant = authority.authorize(local).unwrap();
    let session = broker.snapshot().session_generation;
    assert_eq!(
        grant.generation, session,
        "Partial uses the real logical session"
    );
    peer.send(&tcp_packet(local, 100, 0, 2, &[])).await.unwrap();
    let syn = capture_reply(&peer).await;
    assert_eq!(syn[33] & 0x12, 0x12);
    let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let mut sequence = 101;
    let mut request = None;
    for (index, nonce) in [
        b"before".as_slice(),
        b"routes",
        b"secured",
        b"exclusions",
        b"partial",
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            drop(request.take());
            let config = match index {
                1 => DeliveryConfig::Partial(
                    vec!["10.0.2.2/32".into(), "172.16.0.0/16".into()].into(),
                ),
                2 | 3 => {
                    let mut config = assigned_config();
                    config.addresses =
                        vec!["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()];
                    config.mtu = 1280;
                    if index == 3 {
                        config.dns_servers = Some(vec!["10.64.0.2".parse().unwrap()]);
                        config
                            .excluded_packages
                            .push("unrelated.excluded.app".into());
                    }
                    request = Some(broker.request_capture(config).unwrap());
                    DeliveryConfig::Secured {
                        broker: broker.clone(),
                        request: broker.pending_request().unwrap(),
                    }
                }
                _ => DeliveryConfig::Partial(vec!["10.0.2.2/32".into()].into()),
            };
            if index == 1 {
                platform.fail_release.store(true, SeqCst);
            }
            if index == 2 {
                // Retry the retained predecessor within this same live owner,
                // then fail establish before any OS switch. Neither may revoke
                // the Partial grant or the already connected physical stream.
                let previous = delivery.applied_config().unwrap();
                platform.fail_release.store(false, SeqCst);
                platform.retain_handover.store(true, SeqCst);
                delivery.maintain_config(Some(config.clone())).await;
                bounded(async {
                    while delivery.pending.is_some() {
                        delivery.changed().await;
                    }
                })
                .await;
                assert!(delivery.failed(), "failed establish was not reported");
                assert!(
                    delivery.ready(),
                    "proven rollback lost the working predecessor"
                );
                assert!(delivery.applied_config().unwrap().same_capture(&previous));
                assert!(authority.current(&grant));
                assert!(
                    !delivery.release_failed(),
                    "exact predecessor release did not recover: owner {:?}, releases {}, broker {:?}",
                    delivery.owner_state(),
                    platform.releases.load(SeqCst),
                    broker.snapshot()
                );
                platform.retain_handover.store(false, SeqCst);
            }
            delivery.maintain_config(Some(config.clone())).await;
            assert!(
                authority.current(&grant),
                "configuration change revoked the retained Local grant"
            );
            bounded(async {
                while !delivery
                    .applied_config()
                    .as_ref()
                    .is_some_and(|applied| applied.same_capture(&config))
                {
                    delivery.changed().await;
                }
            })
            .await;
            if let Some(request) = request.as_mut() {
                bounded(request.configured()).await.unwrap();
            }
            peer = UnixDatagram::from_std(platform.peer.lock().unwrap().take().unwrap()).unwrap();
            assert!(authority.current(&grant));
            assert_eq!(broker.snapshot().session_generation, session);
        }
        peer.send(&tcp_packet(local, sequence, ack, 0x18, nonce))
            .await
            .unwrap();
        let mut received = vec![];
        while received.len() < nonce.len() {
            let bytes = capture_reply(&peer).await;
            let payload = packet::parse(&bytes).unwrap().payload;
            received.extend_from_slice(payload);
            ack = ack.wrapping_add(payload.len() as u32);
        }
        assert_eq!(received, nonce);
        sequence += nonce.len() as u32;
        peer.send(&tcp_packet(local, sequence, ack, 0x10, &[]))
            .await
            .unwrap();
        if index == 1 {
            bounded(async {
                while !delivery.release_failed() {
                    delivery.changed().await;
                }
            })
            .await;
            assert!(
                authority.current(&grant),
                "failed predecessor cleanup revoked Local"
            );
            assert!(delivery.ready(), "cleanup failure stopped the current sink");
            assert_eq!(platform.starts.load(SeqCst), 2);
        }
    }
    bounded(physical_task).await.unwrap();
    delivery.stop().await.unwrap();
    assert!(!authority.current(&grant));
    assert_eq!(platform.starts.load(SeqCst), 5);
    assert_eq!(platform.releases.load(SeqCst), 7);
}

#[tokio::test]
async fn managed_capture_delivers_local_nonces_and_never_relays_denied_local() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let tcp_hits = hits.clone();
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let nonce = b"assigned-tcp-consumer";
        let mut bytes = vec![0; nonce.len()];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, nonce);
        tcp_hits.fetch_add(1, SeqCst);
        stream.write_all(&bytes).await.unwrap();
    });
    let udp_hits = hits.clone();
    let udp_task = tokio::spawn(async move {
        let mut bytes = [0; 128];
        let (count, source) = udp.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..count], b"assigned-udp-consumer");
        udp_hits.fetch_add(1, SeqCst);
        udp.send_to(&bytes[..count], source).await.unwrap();
        // Remain a real bound peer for the denied cases, so absence of delivery
        // is not merely the absence of a listener.
        let denied =
            tokio::time::timeout(Duration::from_millis(400), udp.recv_from(&mut bytes)).await;
        assert!(denied.is_err(), "denied local packet hit the physical peer");
    });
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(41),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical,
    });
    let feed = LocalNetworkFeed::new(31);
    assert!(feed.publish(31, physical_snapshot()));
    let mut runtime = LocalNetworkRuntime::with_factory(
        &policy(),
        Some(feed.clone()),
        PacketFactory(platform.clone()),
        Arc::new(|_, _| Ok(())),
    );
    let broker = runtime.broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let mut request = broker
        .request_target_capture(
            assigned_config(),
            talpid_tunnel::tun_provider::transport::router_config(
                &assigned_config(),
                policy()
                    .announced_routes()
                    .iter()
                    .map(|route| route.network())
                    .collect(),
            ),
        )
        .unwrap();
    // The real actor's startup can await its callback without holding the daemon.
    tokio::time::timeout(
        Duration::from_millis(100),
        runtime.update(&policy(), TargetState::Secured, TunnelPhase::Connecting),
    )
    .await
    .unwrap();
    assert_eq!(
        runtime.status().forwarding,
        ForwardingAvailability::PausedWhileConnected
    );
    bounded(runtime.notifications().1).await;
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connecting);
    let receipt = bounded(request.configured()).await.unwrap();
    let mut pair = broker.acquire(&receipt).unwrap();
    let peer = UnixDatagram::from_std(platform.peer.lock().unwrap().take().unwrap()).unwrap();
    let mut public = flow(Transport::Udp, 45000);
    public.source.set_ip(fixed_config().addresses[0]);
    public.destination = "1.1.1.1:443".parse().unwrap();
    let public_bytes = udp_packet(public, b"ordinary-raw");
    peer.send(&public_bytes).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), pair.receive.recv())
            .await
            .is_err()
    );
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    assert!(
        runtime
            .status()
            .rules
            .iter()
            .all(|rule| rule.state == RuleState::Forwarding)
    );
    let mut tcp_flow = flow(Transport::Tcp, 45001);
    tcp_flow.source.set_ip(public.source.ip());
    peer.send(&tcp_packet(tcp_flow, 100, 0, 2, &[]))
        .await
        .unwrap();
    let syn = capture_reply(&peer).await;
    assert_eq!(syn[33] & 0x12, 0x12);
    let ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let nonce = b"assigned-tcp-consumer";
    peer.send(&tcp_packet(tcp_flow, 101, ack, 0x18, nonce))
        .await
        .unwrap();
    let mut received = vec![];
    while received.len() < nonce.len() {
        let bytes = capture_reply(&peer).await;
        received.extend_from_slice(packet::parse(&bytes).unwrap().payload);
    }
    assert_eq!(received, nonce, "complete TCP echo at the capture consumer");
    let mut udp_flow = flow(Transport::Udp, 45002);
    udp_flow.source.set_ip(public.source.ip());
    peer.send(&udp_packet(udp_flow, b"assigned-udp-consumer"))
        .await
        .unwrap();
    loop {
        let bytes = capture_reply(&peer).await;
        let parsed = packet::parse(&bytes).unwrap();
        if parsed.flow.transport == Transport::Udp {
            assert_eq!(parsed.payload, b"assigned-udp-consumer");
            break;
        }
    }
    assert_eq!(hits.load(SeqCst), 2);
    assert!(
        !pair.control.current(),
        "Local authentication accidentally activated ordinary traffic"
    );
    pair.control.activate().unwrap();
    runtime
        .internal_update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    peer.send(&public_bytes).await.unwrap();
    bounded(pair.receive.recv())
        .await
        .unwrap()
        .handoff(|bytes| assert_eq!(bytes, public_bytes))
        .unwrap();
    let mut unmet = policy();
    unmet.rules[0].ssid_ids = vec![SsidIdentity::from_bytes(b"other".to_vec()).unwrap()];
    runtime
        .update(&unmet, TargetState::Secured, TunnelPhase::Connected)
        .await;
    peer.send(&udp_packet(udp_flow, b"denied-condition"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), pair.receive.recv())
            .await
            .is_err()
    );
    feed.close();
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    assert!(
        runtime
            .status()
            .rules
            .iter()
            .all(|rule| rule.state != RuleState::Forwarding)
    );
    peer.send(&udp_packet(udp_flow, b"denied-observer"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), pair.receive.recv())
            .await
            .is_err()
    );
    assert!(pair.control.current());
    peer.send(&public_bytes).await.unwrap();
    bounded(pair.receive.recv())
        .await
        .unwrap()
        .handoff(|bytes| assert_eq!(bytes, public_bytes))
        .unwrap();
    assert_eq!(
        platform.starts.load(SeqCst),
        1,
        "conditions and physical loss do not replace capture"
    );
    runtime.suspend();
    assert!(
        !pair.control.current(),
        "ordinary authority revoked before stop"
    );
    runtime.observe_transport(
        &mut ConnectContinuation::default(),
        TunnelPhase::Disconnected,
    );
    runtime.stop().await.unwrap();
    assert_eq!(platform.releases.load(SeqCst), 1);
    bounded(tcp_task).await.unwrap();
    bounded(udp_task).await.unwrap();
    assert_eq!(hits.load(SeqCst), 2);
}

#[tokio::test]
async fn assigned_config_replacement_and_shutdown_retain_release_and_revoke_old_sources() {
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(42),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical: (
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        ),
    });
    let feed = LocalNetworkFeed::new(32);
    assert!(feed.publish(32, physical_snapshot()));
    let mut runtime = LocalNetworkRuntime::with_factory(
        &policy(),
        Some(feed),
        PacketFactory(platform.clone()),
        Arc::new(|_, _| Ok(())),
    );
    let broker = runtime.broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let mut first_request = broker.request_capture(assigned_config()).unwrap();
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connecting)
        .await;
    bounded(runtime.notifications().1).await;
    let first = bounded(first_request.configured()).await.unwrap();
    let first_pair = broker.acquire(&first).unwrap();
    first_pair.control.activate().unwrap();
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connected);
    let authority = platform.authority.lock().unwrap().clone().unwrap();
    let mut old_flow = flow(Transport::Udp, 45010);
    old_flow.source.set_ip(assigned_config().addresses[0]);
    let old_grant = authority.authorize(old_flow).unwrap();

    let mut replacement = assigned_config();
    replacement.addresses = vec![
        "10.64.9.8".parse().unwrap(),
        "fc00:bbbb:bbbb:bb01::8".parse().unwrap(),
    ];
    replacement.dns_servers = Some(vec!["10.64.0.2".parse().unwrap()]);
    replacement.routes.push("10.0.2.2/32".parse().unwrap());
    replacement.mtu = 1420;
    replacement.excluded_packages = vec!["test.excluded".into()];
    platform.fail_release.store(true, SeqCst);
    first_pair.control.detach();
    first_request.transport_joined();
    let mut second_request = broker.request_capture(replacement.clone()).unwrap();
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    assert!(runtime.has_owner());
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Failed);
    assert!(!authority.current(&old_grant));
    assert!(!first_pair.control.current());
    assert_eq!(platform.starts.load(SeqCst), 1);
    assert!(broker.pending_request().is_some());
    let release_count = platform.releases.load(SeqCst);
    runtime
        .internal_update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    assert_eq!(
        platform.releases.load(SeqCst),
        release_count,
        "internal wake cannot retry release"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), second_request.configured())
            .await
            .is_err()
    );
    platform.fail_release.store(false, SeqCst);
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    bounded(runtime.notifications().1).await;
    let second = bounded(second_request.configured()).await.unwrap();
    assert_ne!(first.generation(), second.generation());
    let second_pair = broker.acquire(&second).unwrap();
    second_pair.control.activate().unwrap();
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connected);
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    assert!(!authority.current(&old_grant));
    assert!(authority.authorize(old_flow).is_err());
    let mut new_flow = old_flow;
    new_flow.source.set_ip(replacement.addresses[0]);
    let new_grant = authority.authorize(new_flow).unwrap();
    let observed = platform.expected.lock().unwrap().clone().unwrap();
    assert_eq!(
        observed
            .addresses
            .iter()
            .map(|p| p.address)
            .collect::<Vec<_>>(),
        replacement.addresses
    );
    assert_eq!(
        observed.dns_servers,
        replacement.dns_servers.clone().unwrap()
    );
    assert_eq!(observed.mtu, Some(1420));
    assert_eq!(
        platform.opened.lock().unwrap().last(),
        Some(&replacement),
        "exact config including routes/exclusions reaches platform"
    );
    drop(first_request);
    assert!(
        second_pair.control.current(),
        "old request Drop cannot retire the successor"
    );

    platform.fail_release.store(true, SeqCst);
    runtime.begin_shutdown();
    assert!(!authority.current(&new_grant));
    assert!(!second_pair.control.current());
    runtime.observe_transport(
        &mut ConnectContinuation::default(),
        TunnelPhase::Disconnected,
    );
    assert!(runtime.shutdown().await.is_err());
    assert!(runtime.has_owner());
    assert_eq!(platform.starts.load(SeqCst), 2);
    platform.fail_release.store(false, SeqCst);
    runtime.shutdown().await.unwrap();
    assert!(!runtime.has_owner());
    assert!(broker.snapshot().closed);
}

fn release_fixture() -> (
    Delivery<PacketFactory>,
    Arc<PacketPlatform>,
    AttachmentBroker,
) {
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(44),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical: (
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        ),
    });
    let broker = broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let delivery = Delivery::new(
        PacketFactory(platform.clone()),
        authority(),
        DeliveryBuffers::new().local.clone(),
        broker.clone(),
    );
    (delivery, platform, broker)
}

fn fixed_config() -> talpid_tunnel::tun_provider::TunConfig {
    let mut config = assigned_config();
    config.addresses = vec!["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()];
    config.mtu = 1280;
    config
}

#[tokio::test]
async fn pending_successor_defers_actual_fd_release_before_daemon_ready() {
    let (mut delivery, platform, broker) = release_fixture();
    delivery
        .maintain_config(Some(DeliveryConfig::Partial(
            vec!["10.0.2.2/32".into()].into(),
        )))
        .await;
    bounded(delivery.changed()).await;
    let old_peer = platform.peer.lock().unwrap().take().unwrap();
    let mut request = broker.request_capture(fixed_config()).unwrap();
    delivery
        .maintain_config(Some(DeliveryConfig::Secured {
            broker: broker.clone(),
            request: broker.pending_request().unwrap(),
        }))
        .await;
    bounded(request.configured()).await.unwrap();
    assert!(matches!(delivery.pending, Some(Readiness::Handover { .. })));
    let peer = platform.peer.lock().unwrap().take().unwrap();
    delivery.defer_release();
    let stopped = bounded(delivery.stop()).await;
    assert_eq!(
        peer.send(b"pending-held")
            .expect("pending successor fd released before TSM join"),
        12
    );
    assert_eq!(stopped.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(delivery.has_owner());
    delivery.transport_joined();
    bounded(delivery.stop()).await.unwrap();
    assert!(old_peer.send(b"old-closed").is_err());
    assert!(peer.send(b"new-closed").is_err());
    assert_eq!(platform.releases.load(SeqCst), 2);
}

#[tokio::test]
async fn applied_successor_acknowledges_retained_predecessor_before_stop() {
    let (mut delivery, platform, broker) = release_fixture();
    let mut first = broker.request_capture(fixed_config()).unwrap();
    let first_pending = broker.pending_request().unwrap();
    delivery
        .maintain_config(Some(DeliveryConfig::Secured {
            broker: broker.clone(),
            request: first_pending.clone(),
        }))
        .await;
    let receipt = bounded(first.configured()).await.unwrap();
    let pair = broker.acquire(&receipt).unwrap();
    bounded(delivery.changed()).await;
    let old_peer = platform.peer.lock().unwrap().take().unwrap();
    delivery.defer_release();
    first.cancel();
    let mut config = fixed_config();
    config.dns_servers = Some(vec!["10.64.0.2".parse().unwrap()]);
    let mut second = broker.request_capture(config).unwrap();
    let next = DeliveryConfig::Secured {
        broker: broker.clone(),
        request: broker.pending_request().unwrap(),
    };
    delivery.maintain_config(Some(next.clone())).await;
    bounded(second.configured()).await.unwrap();
    bounded(delivery.changed()).await;
    assert!(delivery.applied_config().unwrap().same_capture(&next));
    let peer = platform.peer.lock().unwrap().take().unwrap();
    assert_eq!(old_peer.send(b"predecessor-held").unwrap(), 16);
    assert_eq!(platform.releases.load(SeqCst), 0);
    drop(pair);
    first.transport_joined();
    assert!(
        !first_pending.release_ready(),
        "transport join bypassed the TSM stage"
    );
    assert_eq!(old_peer.send(b"predecessor-held").unwrap(), 16);
    assert_eq!(platform.releases.load(SeqCst), 0);
    delivery.transport_joined();
    bounded(delivery.stop()).await.unwrap();
    assert!(first_pending.release_ready());
    assert!(old_peer.send(b"old-closed").is_err());
    assert!(peer.send(b"new-closed").is_err());
    assert_eq!(platform.releases.load(SeqCst), 2);
}

struct Handover {
    runtime: LocalNetworkRuntime<PacketFactory>,
    platform: Arc<PacketPlatform>,
    continuation: ConnectContinuation,
    policy: LocalNetworkAccess,
    target: TargetState,
    phase: TunnelPhase,
    transport: Option<talpid_tunnel::packet_attachment::TransportPair>,
    request: Option<talpid_tunnel::packet_attachment::ConfigurationRequest>,
    commands: Vec<&'static str>,
}

#[tokio::test]
async fn router_admission_owns_local_reader_before_connect_and_before_parameters() {
    let mut h = Handover::new(policy());
    h.continuation.connect();
    assert_eq!(
        h.advance().await.unwrap(),
        None,
        "Connect preceded capture acknowledgement"
    );
    assert!(
        h.runtime.has_owner(),
        "pre-parameter blocking reader absent"
    );
    bounded(h.runtime.notifications().1).await;
    assert_eq!(h.advance().await.unwrap(), Some("Connect"));
    assert_eq!(
        h.runtime.status().forwarding,
        ForwardingAvailability::Active
    );
    let session = h.runtime.broker().snapshot().session_generation;
    for phase in [
        TunnelPhase::Connecting,
        TunnelPhase::Error,
        TunnelPhase::Disconnecting,
    ] {
        h.observe(phase);
        h.runtime.update(&h.policy, h.target, phase).await;
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active
        );
        assert_eq!(h.runtime.broker().snapshot().session_generation, session);
        assert!(!h.runtime.broker().snapshot().ordinary_ready);
    }
    h.close().await;
}

#[tokio::test]
async fn continuation_leaves_off_status_for_the_daemon_notification_boundary() {
    for off in [
        LocalNetworkAccess::default(),
        LocalNetworkAccess {
            enabled: true,
            rules: vec![],
        },
        LocalNetworkAccess {
            enabled: true,
            rules: policy()
                .rules
                .into_iter()
                .map(|mut rule| {
                    rule.enabled = false;
                    rule
                })
                .collect(),
        },
    ] {
        let mut h = Handover::new(policy());
        assert_eq!(h.admit().await, Some("Connect"));
        h.connect_endpoint().await;
        h.user_disconnect();
        h.observe(TunnelPhase::Disconnecting);
        h.acknowledge_transport_close();
        h.advance().await.unwrap();
        bounded(async {
            while !h.runtime.capture_configuration_ready() {
                h.runtime.notifications().1.await;
                h.advance().await.unwrap();
            }
        })
        .await;
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active
        );
        let revision = h.runtime.status().revision;
        h.policy = off;
        // Reproduce refresh_local_network_status: continuation first, then the
        // publication call whose returned sample actually reaches the notifier.
        assert!(
            h.runtime
                .continue_connect(&mut h.continuation, &h.policy, h.target)
                .await
                .unwrap()
                .is_none()
        );
        let published = h
            .runtime
            .update(&h.policy, h.target, h.phase)
            .await
            .expect("continuation consumed Off before the daemon could notify it");
        assert_eq!(published.forwarding, ForwardingAvailability::Off);
        assert_eq!(published.revision, revision + 1);
        assert!(
            !h.runtime.has_owner(),
            "Off must follow joined capture release"
        );
        assert!(
            h.runtime
                .internal_update(&h.policy, h.target, h.phase)
                .await
                .is_none()
        );
        h.close().await;
    }
}

#[tokio::test]
async fn runtime_router_keeps_one_local_tcp_udp_consumer_through_held_boundaries() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let tcp_task = tokio::spawn(async move {
        let (mut stream, tuple) = tcp.accept().await.unwrap();
        for index in 0..12 {
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes.as_slice(), format!("{index:08}").as_bytes());
            assert_eq!(stream.peer_addr().unwrap(), tuple);
            stream.write_all(&bytes).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), tcp.accept())
                .await
                .is_err()
        );
    });
    let udp_task = tokio::spawn(async move {
        let mut tuple = None;
        for index in 0..12 {
            let mut bytes = [0; 128];
            let (count, source) = udp.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..count], format!("{index:08}").as_bytes());
            assert_eq!(*tuple.get_or_insert(source), source);
            udp.send_to(&bytes[..count], source).await.unwrap();
        }
    });
    let mut h = Handover::unstarted_with_physical(policy(), physical);
    h.target = TargetState::Unsecured;
    h.observe(TunnelPhase::Disconnected);
    assert_eq!(h.advance().await.unwrap(), None);
    bounded(h.runtime.notifications().1).await;
    h.runtime.owner_changed(&h.policy, h.target, h.phase);
    let broker = h.runtime.broker();
    let session = broker.snapshot().session_generation;
    let authority = h.platform.authority.lock().unwrap().clone().unwrap();
    let local = flow(Transport::Tcp, 45990);
    let udp_flow = flow(Transport::Udp, 45991);
    let grant = authority.authorize(local).unwrap();
    let peer = || {
        UnixDatagram::from_std(
            h.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap()
    };
    peer()
        .send(&tcp_packet(local, 100, 0, 2, &[]))
        .await
        .unwrap();
    let syn = capture_reply(&peer()).await;
    let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let mut sequence = 101;
    for index in 0..12 {
        match index {
            1 => {
                h.target = TargetState::Secured;
                h.continuation.connect();
                assert_eq!(h.admit().await, Some("Connect"));
            }
            2 | 7 => {
                h.observe(TunnelPhase::Connecting);
            }
            3 => {
                h.observe(TunnelPhase::Error);
            }
            4 | 8 => {
                h.connect_endpoint().await;
            }
            5 => {
                h.continuation.connect();
                assert_eq!(h.advance().await.unwrap(), Some("Disconnect"));
                h.observe(TunnelPhase::Disconnecting);
            }
            6 => {
                h.acknowledge_transport_close();
                assert_eq!(h.admit().await, Some("Connect"));
            }
            9 => {
                h.runtime.suspend();
                h.transport.take();
                h.request.take();
                h.observe(TunnelPhase::Disconnecting);
                h.observe(TunnelPhase::Error);
            }
            10 => {
                h.user_disconnect();
                h.observe(TunnelPhase::Disconnecting);
            }
            11 => {
                h.acknowledge_transport_close();
                assert_eq!(h.advance().await.unwrap(), None);
                bounded(async {
                    while !h.runtime.capture_configuration_ready() {
                        h.runtime.notifications().1.await;
                        assert_eq!(h.advance().await.unwrap(), None);
                    }
                })
                .await;
            }
            _ => {}
        }
        h.runtime.update(&h.policy, h.target, h.phase).await;
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active,
            "stage {index}"
        );
        assert_eq!(
            broker.snapshot().session_generation,
            session,
            "stage {index}"
        );
        assert!(
            authority.current(&grant),
            "stage {index} revoked the Local grant"
        );
        let capture = UnixDatagram::from_std(
            h.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap();
        let nonce = format!("{index:08}");
        capture
            .send(&tcp_packet(local, sequence, ack, 0x18, nonce.as_bytes()))
            .await
            .unwrap();
        let mut received = Vec::new();
        while received.len() < 8 {
            let bytes = capture_reply(&capture).await;
            let payload = packet::parse(&bytes).unwrap().payload;
            received.extend_from_slice(payload);
            ack = ack.wrapping_add(payload.len() as u32);
        }
        assert_eq!(received, nonce.as_bytes());
        sequence += 8;
        capture
            .send(&tcp_packet(local, sequence, ack, 0x10, &[]))
            .await
            .unwrap();
        capture
            .send(&udp_packet(udp_flow, nonce.as_bytes()))
            .await
            .unwrap();
        loop {
            let bytes = capture_reply(&capture).await;
            let packet = packet::parse(&bytes).unwrap();
            if packet.flow.transport == Transport::Udp {
                assert_eq!(packet.payload, nonce.as_bytes());
                break;
            }
        }
        // A live public packet enters the real reader at every held boundary.
        // It must never appear as physical traffic or an app-facing reply.
        if !broker.snapshot().ordinary_ready {
            let mut public = udp_flow;
            public.destination = "1.1.1.1:443".parse().unwrap();
            capture
                .send(&udp_packet(public, b"public-must-drop"))
                .await
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_millis(30);
            let mut output = [0; 128];
            while let Ok(result) =
                tokio::time::timeout_at(deadline, capture.recv(&mut output)).await
            {
                let count = result.unwrap();
                let packet = packet::parse(&output[..count]).unwrap();
                // The Local peer may close after its last exact read. Permit
                // only that connection's empty TCP ACK/FIN, never a public
                // response, reset, duplicate payload or unrelated packet.
                assert_eq!(
                    packet.flow.transport,
                    Transport::Tcp,
                    "stage {index}: unexpected injection"
                );
                assert_eq!(packet.flow.source, local.destination);
                assert_eq!(packet.flow.destination, local.source);
                assert!(packet.payload.is_empty());
                assert_eq!(output[33] & 4, 0, "Local stream reset at stage {index}");
            }
            if let Some(pair) = &mut h.transport {
                assert!(bounded(pair.receive.recv()).await.is_err());
            }
        }
    }
    bounded(tcp_task).await.unwrap();
    bounded(udp_task).await.unwrap();
    assert_eq!(
        h.platform.starts.load(SeqCst),
        4,
        "Partial -> blocking -> target -> Partial only; retries must reuse the fd"
    );
    h.close().await;
}

#[tokio::test]
async fn disconnect_cancels_pre_parameter_admission_without_a_late_connect() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut h = Handover::unstarted_with_physical(
        policy(),
        ("127.0.0.1:9".parse().unwrap(), udp.local_addr().unwrap()),
    );
    h.continuation.connect();
    assert_eq!(
        h.advance().await.unwrap(),
        None,
        "Connect before initial TSM snapshot"
    );
    assert!(!h.runtime.has_owner());
    h.observe(TunnelPhase::Disconnected);
    assert_eq!(
        h.advance().await.unwrap(),
        None,
        "Connect before native acknowledgement"
    );
    h.user_disconnect();
    assert_eq!(h.advance().await.unwrap(), None);
    bounded(async {
        while !h.runtime.capture_configuration_ready() {
            h.runtime.notifications().1.await;
            assert_eq!(h.advance().await.unwrap(), None);
        }
    })
    .await;
    assert_eq!(h.commands, ["Disconnect"]);
    assert_eq!(
        h.runtime.status().forwarding,
        ForwardingAvailability::Active
    );
    let peer = UnixDatagram::from_std(
        h.platform
            .peer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_clone()
            .unwrap(),
    )
    .unwrap();
    let nonce = b"cancelled-connect-still-local";
    peer.send(&udp_packet(flow(Transport::Udp, 45992), nonce))
        .await
        .unwrap();
    let mut bytes = [0; 128];
    let (count, source) = bounded(udp.recv_from(&mut bytes)).await.unwrap();
    assert_eq!(&bytes[..count], nonce);
    udp.send_to(&bytes[..count], source).await.unwrap();
    assert_eq!(
        packet::parse(&capture_reply(&peer).await).unwrap().payload,
        nonce
    );
    assert_eq!(h.advance().await.unwrap(), None);
    assert_eq!(
        h.commands,
        ["Disconnect"],
        "late native ack resumed cancelled Secured intent"
    );
    assert!(!h.runtime.broker().snapshot().ordinary_ready);
    h.close().await;
}

#[tokio::test]
async fn actual_capture_loss_retries_with_a_fresh_router_not_a_cancelled_target_request() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut h = Handover::unstarted_with_physical(
        policy(),
        ("127.0.0.1:9".parse().unwrap(), udp.local_addr().unwrap()),
    );
    h.observe(TunnelPhase::Disconnected);
    h.continuation.connect();
    assert_eq!(h.admit().await, Some("Connect"));
    h.connect_endpoint().await;
    let broker = h.runtime.broker();
    let old_session = broker.snapshot().session_generation;
    let generation = h.platform.generation.load(SeqCst);
    h.platform.feed.invalidate(generation);
    bounded(async {
        while !h.runtime.failed() {
            h.runtime.notifications().1.await;
            h.runtime.owner_changed(&h.policy, h.target, h.phase);
        }
    })
    .await;
    assert!(!broker.snapshot().ordinary_ready);
    assert!(!broker.snapshot().capture_ready);
    h.observe(TunnelPhase::Disconnecting);
    h.acknowledge_transport_close();
    h.observe(TunnelPhase::Error);
    h.continuation.connect();
    assert_eq!(h.advance().await.unwrap(), Some("Disconnect"));
    h.acknowledge_transport_close();
    assert_eq!(
        h.admit().await,
        Some("Connect"),
        "explicit retry stalled on the cancelled target's old request"
    );
    assert_ne!(broker.snapshot().session_generation, old_session);
    h.connect_endpoint().await;
    let peer = UnixDatagram::from_std(
        h.platform
            .peer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_clone()
            .unwrap(),
    )
    .unwrap();
    let nonce = b"fresh-session-after-real-loss";
    peer.send(&udp_packet(flow(Transport::Udp, 45993), nonce))
        .await
        .unwrap();
    let mut bytes = [0; 128];
    let (count, source) = bounded(udp.recv_from(&mut bytes)).await.unwrap();
    assert_eq!(&bytes[..count], nonce);
    udp.send_to(&bytes[..count], source).await.unwrap();
    assert_eq!(
        packet::parse(&capture_reply(&peer).await).unwrap().payload,
        nonce
    );
    h.close().await;
}

impl Handover {
    fn new(policy: LocalNetworkAccess) -> Self {
        let mut harness = Self::unstarted(policy);
        harness.observe(TunnelPhase::Disconnected);
        harness
    }

    fn unstarted(policy: LocalNetworkAccess) -> Self {
        Self::unstarted_with_physical(
            policy,
            (
                "127.0.0.1:9".parse().unwrap(),
                "127.0.0.1:9".parse().unwrap(),
            ),
        )
    }

    fn unstarted_with_physical(
        policy: LocalNetworkAccess,
        physical: (SocketAddr, SocketAddr),
    ) -> Self {
        let platform = Arc::new(PacketPlatform {
            feed: CaptureNetworkFeed::new(43),
            expected: Mutex::new(None),
            opened: Mutex::new(Vec::new()),
            peer: Mutex::new(None),
            starts: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            completed_releases: Mutex::new(Vec::new()),
            released: tokio::sync::Notify::new(),
            fail_release: AtomicBool::new(false),
            retain_handover: AtomicBool::new(false),
            authority: Mutex::new(None),
            generation: 0.into(),
            physical,
        });
        let feed = LocalNetworkFeed::new(33);
        assert!(feed.publish(33, physical_snapshot()));
        let runtime = LocalNetworkRuntime::with_factory(
            &policy,
            Some(feed),
            PacketFactory(platform.clone()),
            Arc::new(|_, _| Ok(())),
        );
        Self {
            runtime,
            platform,
            continuation: ConnectContinuation::default(),
            policy,
            target: TargetState::Secured,
            phase: TunnelPhase::Disconnected,
            transport: None,
            request: None,
            commands: Vec::new(),
        }
    }

    fn observe(&mut self, phase: TunnelPhase) {
        self.phase = phase;
        self.runtime
            .observe_transport(&mut self.continuation, phase);
    }

    async fn advance(&mut self) -> io::Result<Option<&'static str>> {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        let command = self
            .runtime
            .continue_connect(&mut self.continuation, &self.policy, self.target)
            .await?;
        let command = command.map(|command| match command {
            TunnelCommand::Connect => "Connect",
            TunnelCommand::Disconnect => "Disconnect",
            _ => panic!("unexpected continuation command"),
        });
        if let Some(command) = command {
            self.commands.push(command);
        }
        self.runtime
            .update(&self.policy, self.target, self.phase)
            .await;
        Ok(command)
    }

    async fn admit(&mut self) -> Option<&'static str> {
        bounded(async {
            loop {
                if let Some(command) = self.advance().await.unwrap() {
                    break Some(command);
                }
                self.runtime.notifications().1.await;
            }
        })
        .await
    }

    async fn connect_endpoint(&mut self) {
        self.observe(TunnelPhase::Connecting);
        let broker = self.runtime.broker();
        if broker.snapshot().mode == AttachmentMode::ManagedRequired {
            let config = assigned_config();
            let projected = talpid_tunnel::tun_provider::transport::router_config(
                &config,
                broker.local_routes(),
            );
            let mut request = broker.request_target_capture(config, projected).unwrap();
            self.runtime
                .update(&self.policy, self.target, self.phase)
                .await;
            // Service native acknowledgements and queued latest-intent work as
            // the daemon does; never hold the actor awaiting a target request.
            let receipt = self.wait_for_capture_configuration(&mut request).await;
            let mut pair = broker.acquire(&receipt).unwrap();
            pair.control.activate().unwrap();
            let mut public = flow(Transport::Udp, 45100);
            public.source.set_ip(fixed_config().addresses[0]);
            public.destination = "1.1.1.1:443".parse().unwrap();
            let bytes = udp_packet(public, b"ready-handover-consumer");
            self.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send(&bytes)
                .unwrap();
            bounded(pair.receive.recv())
                .await
                .unwrap()
                .handoff(|actual| assert_eq!(actual, bytes))
                .unwrap();
            self.request = Some(request);
            self.transport = Some(pair);
        }
        self.observe(TunnelPhase::Connected);
        self.runtime
            .update(&self.policy, self.target, self.phase)
            .await;
        assert_eq!(
            self.runtime.status().forwarding,
            if self.policy.announced_routes().is_empty() {
                ForwardingAvailability::Off
            } else {
                ForwardingAvailability::Active
            }
        );
    }

    fn user_disconnect(&mut self) {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        self.target = TargetState::Unsecured;
        assert!(matches!(
            self.runtime.request_disconnect(&mut self.continuation),
            TunnelCommand::Disconnect
        ));
        self.commands.push("Disconnect");
    }

    fn acknowledge_transport_close(&mut self) {
        // The stand-in transport keeps its exact broker halves/request until the
        // delayed close acknowledgement. This is the TSM's joined boundary.
        self.transport.take();
        self.request.take();
        self.commands.push("Joined");
        self.observe(TunnelPhase::Disconnected);
    }

    async fn wait_for_capture_configuration(
        &mut self,
        request: &mut talpid_tunnel::packet_attachment::ConfigurationRequest,
    ) -> talpid_tunnel::packet_attachment::CaptureReceipt {
        bounded(async {
            loop {
                let completed = {
                    let (_, owner, broker) = self.runtime.notifications();
                    tokio::select! {
                        biased;
                        result = request.configured() => Some(result),
                        _ = owner => None,
                        _ = broker => None,
                    }
                };
                if let Some(receipt) = completed {
                    break receipt;
                }
                self.runtime
                    .owner_changed(&self.policy, self.target, self.phase);
                self.runtime
                    .internal_update(&self.policy, self.target, self.phase)
                    .await;
            }
        })
        .await
        .unwrap()
    }

    async fn wait_for_capture_release(&self, generation: i64) {
        // Readiness and target traffic can precede the asynchronous predecessor
        // release. Join the exact epoch, not a notification or aggregate count.
        bounded(async {
            loop {
                self.platform.released.notified().await;
                if self
                    .platform
                    .completed_releases
                    .lock()
                    .unwrap()
                    .contains(&generation)
                {
                    break;
                }
            }
        })
        .await;
    }

    async fn close(mut self) {
        self.runtime.begin_shutdown();
        self.acknowledge_transport_close();
        self.runtime.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn startup_snapshot_connects_or_serves_partial_without_an_initial_transition() {
    for target in [TargetState::Secured, TargetState::Unsecured] {
        for enabled in [false, true] {
            let mut configured = policy();
            configured.enabled = enabled;
            let mut h = Handover::unstarted(configured);
            h.target = target;
            // spawn() has initialized the producer's current state, but emits
            // no initial transition. Use the same snapshot seam as Daemon::run.
            h.continuation = h.runtime.initialize_transport(h.phase);
            if target == TargetState::Secured {
                h.continuation.connect();
            }
            if target == TargetState::Secured {
                assert_eq!(
                    h.admit().await,
                    Some("Connect"),
                    "startup snapshot {target:?}, rules {enabled}"
                );
            } else {
                assert_eq!(h.advance().await.unwrap(), None);
            }
            if target == TargetState::Secured {
                assert_eq!(
                    h.advance().await.unwrap(),
                    None,
                    "queued reconciliation duplicated startup Connect"
                );
                h.connect_endpoint().await;
            } else if enabled {
                bounded(h.runtime.notifications().1).await;
                h.runtime.owner_changed(&h.policy, h.target, h.phase);
            }
            assert_eq!(
                h.runtime.status().forwarding,
                if enabled {
                    ForwardingAvailability::Active
                } else {
                    ForwardingAvailability::Off
                }
            );
            h.close().await;
        }
    }
}

#[tokio::test]
async fn coalesced_handover_keeps_reconnect_until_join_unless_user_disconnects() {
    for direction in 0..3 {
        for user_disconnect in [false, true] {
            let mut original = policy();
            if direction == 1 {
                original.enabled = false;
            }
            let mut h = Handover::new(original.clone());
            h.continuation.connect();
            assert_eq!(h.admit().await, Some("Connect"));
            h.connect_endpoint().await;
            assert_eq!(
                h.platform.starts.load(SeqCst),
                2,
                "blocking reader then actual target projection, including rules off"
            );
            h.commands.clear();
            h.policy = original.clone();
            if direction == 2 {
                h.policy.rules[0].cidrs = vec!["172.16.0.0/16".parse().unwrap()];
            } else {
                h.policy.enabled = !h.policy.enabled;
            }
            assert_eq!(
                h.advance().await.unwrap(),
                None,
                "Local settings must not disconnect ordinary VPN"
            );
            assert!(h.transport.as_ref().unwrap().control.current());
            h.continuation.connect();
            assert_eq!(h.advance().await.unwrap(), Some("Disconnect"));
            h.observe(TunnelPhase::Disconnecting);
            // An ordinary settings event returns to A before the transport joins.
            h.policy = original;
            assert_eq!(h.advance().await.unwrap(), None);
            if user_disconnect {
                h.user_disconnect();
                assert_eq!(h.advance().await.unwrap(), None);
            }
            h.acknowledge_transport_close();
            if user_disconnect {
                assert_eq!(h.advance().await.unwrap(), None);
            } else {
                assert_eq!(
                    h.admit().await,
                    Some("Connect"),
                    "coalesced direction {direction}"
                );
            }
            if user_disconnect {
                assert_eq!(h.commands, ["Disconnect", "Disconnect", "Joined"]);
                if !h.policy.announced_routes().is_empty() {
                    bounded(h.runtime.notifications().1).await;
                    h.runtime.owner_changed(&h.policy, h.target, h.phase);
                    assert_eq!(
                        h.runtime.status().forwarding,
                        ForwardingAvailability::Active
                    );
                } else {
                    assert_eq!(h.runtime.status().forwarding, ForwardingAvailability::Off);
                }
            } else {
                assert_eq!(h.commands, ["Disconnect", "Joined", "Connect"]);
                h.connect_endpoint().await;
            }
            h.close().await;
        }
    }
}

#[tokio::test]
async fn managed_teardown_revokes_now_but_releases_only_after_transport_join() {
    for trigger in ["disconnect", "rules-off", "routes", "shutdown"] {
        for fail_release in [false, true] {
            let mut h = Handover::new(policy());
            h.continuation.connect();
            assert_eq!(h.admit().await, Some("Connect"));
            let initial_generation = h.platform.generation.load(SeqCst);
            h.connect_endpoint().await;
            bounded(h.runtime.notifications().1).await;
            h.wait_for_capture_release(initial_generation).await;
            if trigger != "shutdown" {
                verify_live_router_change(h, trigger, fail_release).await;
                continue;
            }
            h.commands.clear();
            let authority = h.platform.authority.lock().unwrap().clone().unwrap();
            let mut local = flow(Transport::Udp, 45020);
            local.source.set_ip(fixed_config().addresses[0]);
            let grant = authority.authorize(local).unwrap();
            let ordinary = h.transport.as_ref().unwrap().control.capability();
            let peer = h
                .platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap();

            // The actual fake transport task retains the same attempt/request
            // until an explicit close acknowledgement; no actor sleep/restart
            // or extra Connect is allowed to manufacture that acknowledgement.
            let transport = h.transport.take().unwrap();
            let request = h.request.take().unwrap();
            let (acknowledge, closed) = oneshot::channel();
            let joining = tokio::spawn(async move {
                closed.await.unwrap();
                drop(transport);
                request.transport_joined();
                drop(request);
            });
            h.platform.fail_release.store(fail_release, SeqCst);
            h.runtime.begin_shutdown();
            assert!(matches!(
                h.runtime.request_disconnect(&mut h.continuation),
                talpid_core::tunnel_state_machine::TunnelCommand::Disconnect
            ));
            h.commands.push("Disconnect");
            assert!(
                !authority.current(&grant),
                "{trigger}: Local revocation was late"
            );
            assert!(
                !ordinary.current(),
                "{trigger}: ordinary revocation was late"
            );
            h.observe(TunnelPhase::Disconnecting);
            assert_eq!(
                bounded(h.advance()).await.unwrap(),
                None,
                "actor blocked on transport close"
            );
            // Process a further ordinary settings event while the close is held.
            h.policy.rules[0].name = "latest settings while closing".into();
            assert_eq!(bounded(h.advance()).await.unwrap(), None);
            bounded(h.runtime.notifications().2).await;
            h.runtime.owner_changed(&h.policy, h.target, h.phase);
            assert!(h.runtime.has_owner());
            assert_eq!(
                h.runtime.broker().snapshot().mode,
                AttachmentMode::ManagedRequired
            );
            assert_eq!(h.commands, ["Disconnect"]);
            assert!(
                tokio::time::timeout(Duration::from_millis(80), h.platform.released.notified())
                    .await
                    .is_err(),
                "{trigger}: platform release preceded joined transport teardown"
            );
            assert_eq!(
                peer.send(b"held-capture")
                    .expect("owned descriptor closed before join"),
                12
            );
            assert!(
                h.runtime.stop().await.is_err(),
                "explicit stop bypassed joined release"
            );
            assert_eq!(h.platform.releases.load(SeqCst), 1);

            acknowledge.send(()).unwrap();
            bounded(joining).await.unwrap();
            // Physical/device/control completion alone cannot bypass the normal
            // handover's separate TSM acknowledgement.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), h.platform.released.notified())
                    .await
                    .is_err()
            );
            h.acknowledge_transport_close();
            let first = h.runtime.shutdown().await;
            if fail_release {
                assert!(first.is_err());
                assert!(h.runtime.has_owner());
                assert_eq!(
                    h.runtime.broker().snapshot().mode,
                    AttachmentMode::ManagedRequired
                );
                let attempts = h.platform.releases.load(SeqCst);
                assert_eq!(attempts, 2, "new release failure retried in the same event");
                h.runtime
                    .internal_update(&h.policy, h.target, h.phase)
                    .await;
                assert_eq!(h.platform.releases.load(SeqCst), attempts);
                h.platform.fail_release.store(false, SeqCst);
                h.runtime.shutdown().await.unwrap();
                assert_eq!(h.platform.releases.load(SeqCst), 3);
            } else {
                first.unwrap();
            }
            assert!(
                peer.send(b"closed-capture").is_err(),
                "descriptor survived acknowledged release"
            );
            assert!(!h.runtime.has_owner());
            h.close().await;
        }
    }
    // A later shutdown can inherit an already-joined, failed capture release.
    // It must not demand a second TSM transition to release that retained owner.
    let mut h = Handover::new(policy());
    h.continuation.connect();
    h.admit().await;
    let initial_generation = h.platform.generation.load(SeqCst);
    h.connect_endpoint().await;
    bounded(h.runtime.notifications().1).await;
    h.wait_for_capture_release(initial_generation).await;
    h.commands.clear();
    h.platform.fail_release.store(true, SeqCst);
    h.user_disconnect();
    h.acknowledge_transport_close();
    h.advance().await.unwrap();
    bounded(h.runtime.notifications().1).await;
    bounded(async {
        while !h.runtime.failed() {
            h.runtime.notifications().1.await;
        }
    })
    .await;
    assert!(h.runtime.has_owner());
    h.runtime.begin_shutdown();
    h.platform.fail_release.store(false, SeqCst);
    bounded(h.runtime.shutdown()).await.unwrap();
    assert!(!h.runtime.has_owner());
    assert_eq!(h.commands, ["Disconnect", "Joined"]);
    assert_eq!(h.platform.releases.load(SeqCst), 4);
}

async fn verify_live_router_change(mut h: Handover, trigger: &str, fail_release: bool) {
    h.commands.clear();
    let old_generation = h.platform.generation.load(SeqCst);
    let broker = h.runtime.broker();
    let session = broker.snapshot().session_generation;
    let authority = h.platform.authority.lock().unwrap().clone().unwrap();
    let grant = authority.authorize(flow(Transport::Udp, 45912)).unwrap();
    let old_peer = h
        .platform
        .peer
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .try_clone()
        .unwrap();
    let before = h.platform.releases.load(SeqCst);
    h.platform.fail_release.store(fail_release, SeqCst);
    if trigger == "disconnect" {
        h.user_disconnect();
        h.observe(TunnelPhase::Disconnecting);
        assert_eq!(bounded(h.advance()).await.unwrap(), None);
        assert!(
            authority.current(&grant),
            "Disconnect revoked Local before Partial handover"
        );
        assert!(!h.transport.as_ref().unwrap().control.current());
        assert_eq!(old_peer.send(b"held-capture").unwrap(), 12);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), async {
                while h.platform.releases.load(SeqCst) == before {
                    h.platform.released.notified().await;
                }
            })
            .await
            .is_err(),
            "platform released before target joined"
        );
        // A further settings event must be serviced while the target is held.
        h.policy.rules[0].name = "latest while joining".into();
        assert_eq!(bounded(h.advance()).await.unwrap(), None);
        h.acknowledge_transport_close();
    } else {
        if trigger == "rules-off" {
            h.policy.enabled = false;
        } else {
            h.policy.rules[0].cidrs = vec!["172.16.0.0/16".parse().unwrap()];
        }
    }
    assert_eq!(bounded(h.advance()).await.unwrap(), None);
    if trigger != "disconnect" {
        assert!(!authority.current(&grant), "policy revoke was late");
        assert!(
            h.transport.as_ref().unwrap().control.current(),
            "Local policy retired ordinary VPN"
        );
        assert!(h.commands.is_empty());
    }
    bounded(h.runtime.notifications().1).await;
    bounded(async {
        while h.platform.releases.load(SeqCst) == before {
            h.runtime.notifications().1.await;
        }
    })
    .await;
    if fail_release {
        bounded(async {
            while !h.runtime.failed() {
                h.runtime.notifications().1.await;
            }
        })
        .await;
        let failed_count = h.platform.releases.load(SeqCst);
        h.runtime
            .internal_update(&h.policy, h.target, h.phase)
            .await;
        assert_eq!(
            h.platform.releases.load(SeqCst),
            failed_count,
            "internal event retried failed release"
        );
        h.platform.fail_release.store(false, SeqCst);
        assert_eq!(h.advance().await.unwrap(), None);
        bounded(h.runtime.notifications().1).await;
        assert_eq!(h.platform.releases.load(SeqCst), failed_count + 1);
    }
    // A configuration ack and an unrelated platform release are not closure of
    // this exact predecessor. Drive both stages inside the same existing bound.
    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        while !h.runtime.capture_configuration_ready()
            || !h
                .platform
                .completed_releases
                .lock()
                .unwrap()
                .contains(&old_generation)
        {
            h.runtime.notifications().1.await;
            h.runtime
                .internal_update(&h.policy, h.target, h.phase)
                .await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "{trigger}, failure={fail_release}, starts={}, releases={}, broker={:?}, failed={}, applied platforms={:?}",
        h.platform.starts.load(SeqCst),
        h.platform.releases.load(SeqCst),
        broker.snapshot(),
        h.runtime.failed(),
        h.platform.opened.lock().unwrap()
    );
    h.runtime.owner_changed(&h.policy, h.target, h.phase);
    assert_eq!(broker.snapshot().session_generation, session);
    assert!(
        old_peer.send(b"old-closed").is_err(),
        "{trigger}, failure={fail_release}: predecessor survived exact configuration/release acknowledgements"
    );
    if trigger == "disconnect" {
        assert!(authority.current(&grant));
        assert_eq!(h.commands, ["Disconnect", "Joined"]);
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active
        );
    } else {
        let mut public = flow(Transport::Udp, 45913);
        public.destination = "1.1.1.1:443".parse().unwrap();
        let bytes = udp_packet(public, b"ordinary-vpn-survives-local-off");
        h.platform
            .peer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(&bytes)
            .unwrap();
        bounded(h.transport.as_mut().unwrap().receive.recv())
            .await
            .unwrap()
            .handoff(|actual| assert_eq!(actual, bytes))
            .unwrap();
    }
    h.close().await;
}

#[tokio::test]
async fn joined_internal_transport_retry_replaces_capture_without_a_tsm_handover() {
    let mut h = Handover::new(policy());
    h.continuation.connect();
    assert_eq!(h.admit().await, Some("Connect"));
    let initial_generation = h.platform.generation.load(SeqCst);
    h.connect_endpoint().await;
    h.wait_for_capture_release(initial_generation).await;
    let broker = h.runtime.broker();
    let first_generation = broker.snapshot().capture_generation.unwrap();
    let first_session = broker.snapshot().session_generation;
    let old_peer = h
        .platform
        .peer
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .try_clone()
        .unwrap();
    let config = h.platform.opened.lock().unwrap().last().unwrap().clone();
    let old_request = h.request.take().unwrap();
    let transport = h.transport.take().unwrap();
    transport.control.detach();
    bounded(h.runtime.notifications().2).await;
    h.runtime.owner_changed(&h.policy, h.target, h.phase);
    let mut next_request = broker
        .request_target_capture(assigned_config(), config)
        .unwrap();
    // A successor request is not proof that old device/control cleanup joined.
    h.observe(TunnelPhase::Connecting);
    h.runtime
        .internal_update(&h.policy, h.target, h.phase)
        .await;
    assert_eq!(h.platform.starts.load(SeqCst), 2);
    assert_eq!(h.platform.releases.load(SeqCst), 1);
    // The successor can become ready without destroying Local or acknowledging
    // predecessor cleanup. The old descriptor remains owned until the exact join.
    let receipt = h.wait_for_capture_configuration(&mut next_request).await;
    assert_eq!(
        receipt.generation(),
        first_generation,
        "equal projection unnecessarily reopened the capture"
    );
    assert_eq!(broker.snapshot().session_generation, first_session);
    assert_eq!(old_peer.send(b"predecessor-retained").unwrap(), 20);
    assert_eq!(h.platform.releases.load(SeqCst), 1);
    drop(transport);
    old_request.transport_joined();
    // This is the same production broker notification selected by the daemon.
    bounded(h.runtime.notifications().2).await;
    h.runtime
        .internal_update(&h.policy, h.target, h.phase)
        .await;
    assert_eq!(old_peer.send(b"same-current-sink").unwrap(), 17);
    let pair = broker.acquire(&receipt).unwrap();
    pair.control.activate().unwrap();
    h.request = Some(next_request);
    h.transport = Some(pair);
    drop(old_request);
    h.observe(TunnelPhase::Connected);
    h.runtime
        .internal_update(&h.policy, h.target, h.phase)
        .await;
    assert_eq!(
        h.runtime.status().forwarding,
        ForwardingAvailability::Active
    );
    assert_eq!(
        h.commands,
        ["Connect"],
        "internal device retry invented a TSM handover"
    );
    assert_eq!(h.platform.releases.load(SeqCst), 1);
    h.close().await;
}
