use super::*;
use crate::local_network::LocalNetworkRuntime;
use mullvad_types::settings::local_network_access::{
    LocalBypassRule, SsidIdentity,
    eligibility::{PermissionState, PhysicalAddress, PhysicalNetwork, PhysicalTransport},
    status::{InactiveReason, RuleState},
};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use talpid_lan_forwarder::{Forwarder, Transport, packet};
use talpid_types::local_network::{
    LocalNetworkFeed, LocalNetworkSnapshot, LocalPhysicalPrefix, LocalPhysicalRoute,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[cfg(target_os = "linux")]
#[path = "connected_tests.rs"]
mod connected;

#[test]
fn runtime_regions_share_one_root_and_local_exhaustion_preserves_control() {
    let pools = DeliveryBuffers::new();
    let root = pools._root.clone();
    assert_eq!(root.limit(), 64 * 1024 * 1024);
    assert_eq!(root.used(), 62 * 1024 * 1024 + 512);
    let local = pools.local.try_reserve(30 * 1024 * 1024 - 512).unwrap();
    assert!(pools.local.try_reserve(1).is_err());
    let application = pools
        ._application
        .try_reserve(22 * 1024 * 1024 - 512)
        .unwrap();
    let control = pools._control.try_reserve(8 * 1024 * 1024 - 512).unwrap();
    let capture = pools._capture.try_reserve(2 * 1024 * 1024 - 512).unwrap();
    assert!(pools._application.try_reserve(1).is_err());
    assert!(pools._control.try_reserve(1).is_err());
    assert!(pools._capture.try_reserve(1).is_err());
    assert_eq!(root.used(), 62 * 1024 * 1024 + 512);
    drop((pools, application, control, capture));
    assert_eq!(
        root.used(),
        30 * 1024 * 1024,
        "last owned child retains only its region"
    );
    drop(local);
    assert_eq!(root.used(), 0);
}

fn policy() -> LocalNetworkAccess {
    LocalNetworkAccess {
        enabled: true,
        rules: vec![LocalBypassRule {
            id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            name: "synthetic".into(),
            enabled: true,
            cidrs: vec!["10.0.2.2/32".parse().unwrap(), "fe80::/64".parse().unwrap()],
            ssid_ids: vec![],
        }],
    }
}

fn observation() -> NetworkObservation {
    NetworkObservation {
        sequence: 9,
        permissions: Some(PermissionState {
            local_network: true,
            precise_location: true,
            background_location: true,
            location_enabled: true,
            location_allowed: true,
        }),
        networks: vec![PhysicalNetwork {
            handle: 71,
            transport: PhysicalTransport::Wifi,
            capabilities_fresh: true,
            links_fresh: true,
            blocked: false,
            interface_index: 15,
            addresses: vec![
                PhysicalAddress {
                    prefix: "10.0.2.16/24".parse().unwrap(),
                    usable: true,
                },
                PhysicalAddress {
                    prefix: "fe80::1/64".parse().unwrap(),
                    usable: true,
                },
            ],
            routes: vec![route("10.0.2.0", 24), route("fe80::", 64)],
            ssid: Some(SsidIdentity::from_bytes(b"synthetic".to_vec()).unwrap()),
        }],
    }
}

fn route(address: &str, prefix_length: i16) -> LocalPhysicalRoute {
    LocalPhysicalRoute {
        destination: LocalPhysicalPrefix {
            address: address.parse().unwrap(),
            prefix_length,
        },
        gateway: None,
        route_type: 1,
        interface_index: 15,
    }
}

fn flow(transport: Transport, source_port: u16) -> Flow {
    Flow {
        source: SocketAddr::new("192.0.2.2".parse().unwrap(), source_port),
        destination: "10.0.2.2:18080".parse().unwrap(),
        transport,
    }
}

fn authority() -> Arc<DeliveryAuthority> {
    Arc::new(DeliveryAuthority::new(&policy(), Arc::new(|_, _| Ok(()))))
}

fn assigned_config() -> talpid_tunnel::tun_provider::TunConfig {
    let mut config = talpid_tunnel::tun_provider::blocking_config();
    config.addresses = vec![
        "10.64.2.3".parse().unwrap(),
        "fc00:bbbb:bbbb:bb01::3".parse().unwrap(),
    ];
    config.ipv6_gateway = Some("fc00:bbbb:bbbb:bb01::1".parse().unwrap());
    config.dns_servers = None;
    config.mtu = 1380;
    config
}

#[tokio::test]
async fn intentional_handover_is_paused_but_an_unacknowledged_release_is_failed() {
    use crate::local_network::TunnelPhase;
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(None, control.clone());
    runtime
        .update(&policy(), TargetState::Unsecured, TunnelPhase::Disconnected)
        .await;
    runtime.suspend();
    // Retiring a broker attempt makes its capture actor terminal. This is the
    // expected continuation of deliberate teardown, not a new owner failure.
    control
        .state
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .send_replace(OwnerState::Failed);
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Disconnecting);
    assert_eq!(
        runtime.status().forwarding,
        ForwardingAvailability::PausedWhileConnected
    );
    control.fail_release.store(true, SeqCst);
    assert!(runtime.stop().await.is_err());
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Disconnected);
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Failed);
    control.fail_release.store(false, SeqCst);
    runtime.stop().await.unwrap();
    assert!(!runtime.has_owner());
}

fn broker() -> AttachmentBroker {
    let pools = DeliveryBuffers::new();
    let broker = AttachmentBroker::new(pools._application, pools._capture, pools._control).unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    broker
}

#[tokio::test]
async fn assigned_sources_and_capture_identity_are_required_at_prepare_and_output() {
    let count = Arc::new(AtomicUsize::new(0));
    let prepares = count.clone();
    let authority = DeliveryAuthority::new(
        &policy(),
        Arc::new(move |_, _| {
            prepares.fetch_add(1, SeqCst);
            Ok(())
        }),
    );
    authority.update(&policy(), Some(observation()));
    let old_partial = authority.authorize(flow(Transport::Udp, 40100)).unwrap();
    authority.install(CaptureAuthority::partial());
    assert!(
        !authority.current(&old_partial),
        "equal-source replacement revokes an old grant"
    );
    let broker = broker();
    let config = assigned_config();
    let mut request = broker.request_capture(config.clone()).unwrap();
    let pending = broker.pending_request().unwrap();
    authority.install(
        DeliveryConfig::Secured {
            broker: broker.clone(),
            request: pending.clone(),
        }
        .authority(),
    );
    let mut assigned = flow(Transport::Udp, 40101);
    assigned.source.set_ip(config.addresses[0]);
    assert!(authority.authorize(assigned).is_err());
    let lease = broker.open_capture(Some(&pending)).unwrap();
    let sources = talpid_types::relay_flow::RelaySources {
        ipv4: Some("10.64.2.3".parse().unwrap()),
        ipv6: Some("fc00:bbbb:bbbb:bb01::3".parse().unwrap()),
    };
    let receipt = lease
        .bind_observed_identity("tun-owned", 101_u64 << 32, sources, config.mtu)
        .unwrap();
    broker.acknowledge(&pending, &receipt).unwrap();
    assert_eq!(
        request.configured().await.unwrap().generation(),
        receipt.generation()
    );
    let pair = broker.acquire(&receipt).unwrap();
    let before_target = authority.authorize(assigned).unwrap();
    assert!(
        authority.current(&before_target),
        "Local depends on target readiness"
    );
    assert!(
        !pair.control.current(),
        "Local authorization activated ordinary traffic"
    );
    pair.control.activate().unwrap();
    authority.endpoint(false);
    assert!(
        authority.authorize(assigned).is_err(),
        "ready attempt alone is not Connected"
    );
    authority.endpoint(true);
    let grant = authority.authorize(assigned).unwrap();
    pair.control.detach();
    assert!(
        authority.current(&grant),
        "target detach revoked Local grant"
    );
    let pair = broker.acquire(&receipt).unwrap();
    pair.control.activate().unwrap();
    assert!(
        authority.current(&grant),
        "target replacement revoked Local grant"
    );
    assert_eq!(grant.generation, Some(receipt.generation()));
    assert!(authority.authorize(flow(Transport::Udp, 40102)).is_err());
    assigned.source.set_ip(config.addresses[1]);
    assert!(authority.authorize(assigned).is_ok());
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    authority.prepare(&socket, &grant).unwrap();
    assert_eq!(count.load(SeqCst), 1);
    // A broad local rule never captures the VPN gateway or SOCKS control range.
    let mut broad = policy();
    broad.rules[0].cidrs = vec!["10.0.0.0/8".parse().unwrap()];
    authority.update(&broad, Some(observation()));
    for destination in ["10.64.0.1", "10.124.0.5"] {
        assert_eq!(
            authority.disposition(destination.parse().unwrap()),
            Disposition::Drop
        );
    }
    assert_eq!(
        authority.disposition("10.0.2.2".parse().unwrap()),
        Disposition::Local
    );
    authority.update(&policy(), None);
    assert!(!authority.current(&grant));
    assert!(
        pair.control.current(),
        "physical observer loss cannot retire raw VPN"
    );
    authority.update(&policy(), Some(observation()));
    assert!(authority.current(&grant));
    lease.retire();
    assert!(!authority.current(&grant));
    assert_eq!(authority.prepare(&socket, &grant), Err(Refused::Stale));
    assert_eq!(count.load(SeqCst), 1);
    authority.install(CaptureAuthority::partial());
    assert!(!authority.current(&grant));
    assert!(authority.authorize(flow(Transport::Udp, 40103)).is_ok());
}

#[tokio::test]
async fn connected_status_requires_the_current_capture_and_activated_attempt() {
    use crate::local_network::TunnelPhase;
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(None, control.clone());
    let broker = runtime.broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let mut request = broker.request_capture(assigned_config()).unwrap();
    let pending = broker.pending_request().unwrap();
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connecting)
        .await;
    assert_eq!(
        runtime.status().forwarding,
        ForwardingAvailability::PausedWhileConnected
    );
    let capture = broker.open_capture(Some(&pending)).unwrap();
    let receipt = capture
        .bind_observed_identity(
            "tun-owned",
            102_u64 << 32,
            talpid_types::relay_flow::RelaySources {
                ipv4: Some("10.64.2.3".parse().unwrap()),
                ipv6: Some("fc00:bbbb:bbbb:bb01::3".parse().unwrap()),
            },
            1380,
        )
        .unwrap();
    broker.acknowledge(&pending, &receipt).unwrap();
    request.configured().await.unwrap();
    let pair = broker.acquire(&receipt).unwrap();
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connected);
    assert_eq!(
        runtime.status().forwarding,
        ForwardingAvailability::PausedWhileConnected
    );
    pair.control.activate().unwrap();
    for target in [TargetState::Unsecured, TargetState::Secured] {
        for phase in [
            TunnelPhase::Disconnected,
            TunnelPhase::Connecting,
            TunnelPhase::Connected,
            TunnelPhase::Disconnecting,
            TunnelPhase::Error,
        ] {
            runtime.owner_changed(&policy(), target, phase);
            let expected = if target == TargetState::Secured && phase == TunnelPhase::Connected {
                ForwardingAvailability::Active
            } else if target == TargetState::Unsecured && phase == TunnelPhase::Disconnected {
                // A managed owner cannot certify the Partial endpoint.
                ForwardingAvailability::PausedWhileConnected
            } else {
                ForwardingAvailability::PausedWhileConnected
            };
            assert_eq!(
                runtime.status().forwarding,
                expected,
                "{target:?} {phase:?}"
            );
        }
    }
    capture.retire();
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connected);
    assert_eq!(
        runtime.status().forwarding,
        ForwardingAvailability::PausedWhileConnected
    );
    runtime.owner_changed(
        &LocalNetworkAccess::default(),
        TargetState::Secured,
        TunnelPhase::Connected,
    );
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Off);
    request.transport_joined();
    runtime.stop().await.unwrap();
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("bounded test consumer")
}

#[test]
fn lifecycle_and_availability_cover_every_target_tunnel_rule_and_owner_combination() {
    use ForwardingAvailability::*;
    for supported in [false, true] {
        for on in [false, true] {
            for routes in [false, true] {
                for target in [TargetState::Unsecured, TargetState::Secured] {
                    for disconnected in [false, true] {
                        for owner in [
                            None,
                            Some(OwnerState::Running),
                            Some(OwnerState::Stopped),
                            Some(OwnerState::Failed),
                        ] {
                            for failed in [false, true] {
                                assert_eq!(
                                    frontend_wanted(on, routes, target, disconnected),
                                    on && routes
                                        && target == TargetState::Unsecured
                                        && disconnected
                                );
                                let expected = if !supported {
                                    NotAvailable
                                } else if !on || !routes {
                                    Off
                                } else if failed || owner == Some(OwnerState::Failed) {
                                    Failed
                                } else if owner == Some(OwnerState::Running)
                                    && target == TargetState::Unsecured
                                    && disconnected
                                {
                                    Active
                                } else {
                                    PausedWhileConnected
                                };
                                assert_eq!(
                                    availability(
                                        supported,
                                        on,
                                        routes,
                                        target == TargetState::Unsecured && disconnected,
                                        owner,
                                        failed
                                    ),
                                    expected
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    let mut configured = policy();
    configured.rules[0].enabled = false;
    assert!(configured.announced_routes().is_empty());
    configured.rules.clear();
    assert!(configured.announced_routes().is_empty());
}

#[test]
fn authority_triages_without_preparing_and_refuses_wrong_sources_and_missing_observation() {
    let prepares = Arc::new(AtomicUsize::new(0));
    let count = prepares.clone();
    let authority = DeliveryAuthority::new(
        &policy(),
        Arc::new(move |_, _| {
            count.fetch_add(1, SeqCst);
            Ok(())
        }),
    );
    assert_eq!(
        authority.disposition("10.0.2.2".parse().unwrap()),
        Disposition::Local
    );
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "ff02::1",
        "1.1.1.1",
    ] {
        assert_eq!(
            authority.disposition(address.parse().unwrap()),
            Disposition::Drop
        );
    }
    assert_eq!(
        authority.authorize(flow(Transport::Tcp, 40000)),
        Err(Refused::Denied)
    );
    authority.update(&policy(), Some(observation()));
    for source in ["10.0.2.16", "127.0.0.1", "fd00::2", "::1"] {
        let mut request = flow(Transport::Tcp, 40000);
        request.source.set_ip(source.parse().unwrap());
        assert_eq!(authority.authorize(request), Err(Refused::Denied));
    }
    let mut request = flow(Transport::Tcp, 40000);
    request.source.set_ip("2001:db8::2".parse().unwrap());
    assert!(authority.authorize(request).is_ok());
    let mut configured = policy();
    configured.rules[0]
        .ssid_ids
        .push(SsidIdentity::from_bytes(b"different".to_vec()).unwrap());
    authority.update(&configured, Some(observation()));
    assert_eq!(
        authority.disposition(request.destination.ip()),
        Disposition::Local
    );
    assert_eq!(authority.authorize(request), Err(Refused::Denied));
    assert_eq!(prepares.load(SeqCst), 0);
    configured.enabled = false;
    authority.update(&configured, Some(observation()));
    assert_eq!(
        authority.disposition(request.destination.ip()),
        Disposition::Drop
    );
    configured.enabled = true;
    configured.rules.push(configured.rules[0].clone());
    authority.update(&configured, Some(observation()));
    assert_eq!(
        authority.disposition(request.destination.ip()),
        Disposition::Drop
    );
}

#[tokio::test]
async fn authority_update_revokes_before_notification_and_preparation_retains_sequence_and_scope() {
    let seen = Arc::new(Mutex::new(vec![]));
    let calls = seen.clone();
    let authority = DeliveryAuthority::new(
        &policy(),
        Arc::new(move |_, lease| {
            calls.lock().unwrap().push((
                lease.network_handle,
                lease.sequence,
                lease.needs_wifi_name,
            ));
            Err(Refused::Stale)
        }),
    );
    let mut updates = authority.subscribe();
    authority.update(&policy(), Some(observation()));
    bounded(updates.changed()).await.unwrap();
    let lease = authority.authorize(flow(Transport::Tcp, 40000)).unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    assert_eq!(authority.prepare(&socket, &lease), Err(Refused::Stale));
    assert_eq!(*seen.lock().unwrap(), [(71, 9, false)]);
    let mut newer = observation();
    newer.sequence += 1;
    authority.update(&policy(), Some(newer.clone()));
    assert!(authority.current(&lease));
    newer.networks[0].blocked = true;
    authority.update(&policy(), Some(newer));
    assert!(!authority.current(&lease));
    bounded(updates.changed()).await.unwrap();
    assert!(!authority.current(&lease));
    authority.update(&policy(), None);
    assert!(!authority.current(&lease));
    authority.update(&policy(), Some(observation()));
    let mut configured = policy();
    configured.rules[0].enabled = false;
    authority.update(&configured, Some(observation()));
    assert!(!authority.current(&lease));
    authority.update(&policy(), Some(observation()));
    let mut request = flow(Transport::Udp, 40001);
    request.destination = "[fe80::12]:18081".parse().unwrap();
    request.source = "[2001:db8::2]:40001".parse().unwrap();
    let scoped = authority.authorize(request).unwrap();
    assert_eq!(
        authority.physical_destination(&scoped, request),
        "[fe80::12%15]:18081".parse().unwrap()
    );
    assert_eq!(
        authority.physical_destination(&lease, flow(Transport::Tcp, 40000)),
        "10.0.2.2:18080".parse().unwrap()
    );
    let mut wifi_policy = policy();
    wifi_policy.rules[0]
        .ssid_ids
        .push(SsidIdentity::from_bytes(b"synthetic".to_vec()).unwrap());
    authority.update(&wifi_policy, Some(observation()));
    let wifi_lease = authority.authorize(flow(Transport::Tcp, 40002)).unwrap();
    assert_eq!(authority.prepare(&socket, &wifi_lease), Err(Refused::Stale));
    assert_eq!(seen.lock().unwrap().last(), Some(&(71, 9, true)));
    let mut denied = observation();
    denied.permissions.as_mut().unwrap().local_network = false;
    authority.update(&wifi_policy, Some(denied));
    assert!(!authority.current(&wifi_lease));
}

struct Control {
    history: Mutex<Vec<String>>,
    routes: Mutex<Vec<Vec<String>>>,
    starts: AtomicUsize,
    active: AtomicBool,
    fail_start: AtomicBool,
    fail_ready: AtomicBool,
    fail_release: AtomicBool,
    hold_ready: AtomicBool,
    state: Mutex<Option<watch::Sender<OwnerState>>>,
    endpoints: Mutex<Option<Endpoints>>,
    peer: Mutex<Option<(SocketAddr, SocketAddr)>>,
    hold_output: watch::Sender<bool>,
    authority: Mutex<Option<Arc<DeliveryAuthority>>>,
    queued: AtomicBool,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            history: Mutex::new(vec![]),
            routes: Mutex::new(vec![]),
            starts: AtomicUsize::new(0),
            active: AtomicBool::new(false),
            fail_start: AtomicBool::new(false),
            fail_ready: AtomicBool::new(false),
            fail_release: AtomicBool::new(false),
            hold_ready: AtomicBool::new(false),
            state: Mutex::new(None),
            endpoints: Mutex::new(None),
            peer: Mutex::new(None),
            hold_output: watch::channel(false).0,
            authority: Mutex::new(None),
            queued: AtomicBool::new(false),
        }
    }
}

struct Endpoints {
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
}
struct FakeFactory(Arc<Control>);
struct FakeOwner {
    control: Arc<Control>,
    receiver: watch::Receiver<OwnerState>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    open: bool,
    release_pending: bool,
    released: bool,
}

// Test-only physical redirection: admission still evaluates the original private
// destination, but physical I/O goes to the builder's real loopback echo peers.
struct LoopbackAuthority {
    authority: Arc<DeliveryAuthority>,
    peer: Option<(SocketAddr, SocketAddr)>,
}
impl LocalAuthority for LoopbackAuthority {
    type Grant = DeliveryGrant;
    fn disposition(&self, destination: IpAddr) -> Disposition {
        self.authority.disposition(destination)
    }
    fn authorize(&self, flow: Flow) -> Result<DeliveryGrant, Refused> {
        self.authority.authorize(flow)
    }
    fn prepare(&self, socket: &socket2::Socket, grant: &DeliveryGrant) -> Result<(), Refused> {
        self.authority.prepare(socket, grant)
    }
    fn current(&self, grant: &DeliveryGrant) -> bool {
        self.authority.current(grant)
    }
    fn physical_destination(&self, grant: &DeliveryGrant, flow: Flow) -> SocketAddr {
        self.peer
            .map(|(tcp, udp)| {
                if flow.transport == Transport::Tcp {
                    tcp
                } else {
                    udp
                }
            })
            .unwrap_or_else(|| self.authority.physical_destination(grant, flow))
    }
}

impl FrontendFactory for FakeFactory {
    type Owner = FakeOwner;
    fn supported(&self) -> bool {
        true
    }
    fn start(
        &self,
        config: DeliveryConfig,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> io::Result<FakeOwner> {
        self.0.starts.fetch_add(1, SeqCst);
        if self.0.fail_start.load(SeqCst) {
            return Err(io::Error::other("start refused"));
        }
        assert!(!self.0.active.swap(true, SeqCst), "overlapping owners");
        self.0.history.lock().unwrap().push("start".into());
        let routes = match &config {
            DeliveryConfig::Partial(routes) => routes.clone(),
            DeliveryConfig::Secured { request, .. } => request
                .config()
                .routes
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        self.0.routes.lock().unwrap().push(routes);
        let (state, receiver) = watch::channel(OwnerState::Running);
        *self.0.state.lock().unwrap() = Some(state);
        *self.0.authority.lock().unwrap() = Some(authority.clone());
        let mut updates = authority.subscribe();
        let authority = Arc::new(LoopbackAuthority {
            authority,
            peer: *self.0.peer.lock().unwrap(),
        });
        let mut forwarder = Forwarder::with_mtu(authority, buffers, usize::from(config.mtu()))
            .map_err(|_| io::Error::other("test budget full"))?;
        let (input, mut packets) = mpsc::channel::<Vec<u8>>(16);
        let (output, replies) = mpsc::channel(256);
        *self.0.endpoints.lock().unwrap() = Some(Endpoints {
            input,
            output: replies,
        });
        let (stop, mut stopped) = oneshot::channel();
        let mut hold = self.0.hold_output.subscribe();
        let control = self.0.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    packet = packets.recv() => {
                        let Some(packet) = packet else { break; };
                        forwarder.ingest(&packet);
                    }
                    _ = updates.changed() => forwarder.revalidate(),
                    _ = hold.changed() => {},
                    _ = forwarder.wait() => {},
                }
                forwarder.process();
                control.queued.store(forwarder.has_output(), SeqCst);
                if !*hold.borrow() {
                    while forwarder
                        .write_output(|bytes| {
                            output
                                .try_send(bytes.to_vec())
                                .map_err(|_| io::ErrorKind::WouldBlock)?;
                            Ok(bytes.len())
                        })
                        .unwrap()
                    {}
                }
            }
            forwarder.close_all().await;
        });
        Ok(FakeOwner {
            control: self.0.clone(),
            receiver,
            stop: Some(stop),
            task: Some(task),
            open: true,
            release_pending: false,
            released: false,
        })
    }
}

impl DeliveryOwner for FakeOwner {
    async fn ready(&mut self) -> io::Result<()> {
        if self.control.hold_ready.load(SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.control.fail_ready.load(SeqCst) {
            Err(io::Error::other("readiness failed"))
        } else {
            Ok(())
        }
    }
    async fn stop(&mut self) -> io::Result<()> {
        self.control.history.lock().unwrap().push("stop".into());
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            task.await.unwrap();
            self.task = None;
        }
        if self.release_pending {
            return Err(io::Error::other("release requires explicit retry"));
        }
        if self.released {
            return Ok(());
        }
        if self.control.fail_release.load(SeqCst) {
            self.release_pending = true;
            self.control
                .state
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send_replace(OwnerState::Failed);
            return Err(io::Error::other("release pending"));
        }
        self.control.active.store(false, SeqCst);
        self.released = true;
        self.control.history.lock().unwrap().push("released".into());
        Ok(())
    }
    fn retry_release(&mut self) -> io::Result<()> {
        assert!(self.task.is_none());
        self.control.history.lock().unwrap().push("retry".into());
        if self.control.fail_release.load(SeqCst) {
            Err(io::Error::other("release still pending"))
        } else {
            self.release_pending = false;
            self.released = true;
            self.control.active.store(false, SeqCst);
            self.control.history.lock().unwrap().push("released".into());
            Ok(())
        }
    }
    fn state(&self) -> OwnerState {
        *self.receiver.borrow()
    }
    fn release_failed(&self) -> bool {
        self.release_pending
            || (self.state() == OwnerState::Failed && self.control.fail_release.load(SeqCst))
    }
    async fn changed(&mut self) {
        if self.open {
            if self.receiver.changed().await.is_err() {
                self.open = false;
            }
        } else {
            std::future::pending().await
        }
    }
}
impl Drop for FakeOwner {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

fn make_runtime(
    feed: Option<Arc<LocalNetworkFeed>>,
    control: Arc<Control>,
) -> LocalNetworkRuntime<FakeFactory> {
    LocalNetworkRuntime::with_factory(
        &policy(),
        feed,
        FakeFactory(control),
        Arc::new(|_, _| Ok(())),
    )
}

#[tokio::test]
async fn publication_and_failed_owner_retry_are_bounded_by_external_events() {
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(None, control.clone());
    let status = runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await
        .unwrap();
    assert_eq!(status.forwarding, ForwardingAvailability::Active);
    assert!(!status.observer_available);
    control
        .state
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .send_replace(OwnerState::Failed);
    bounded(runtime.notifications().1).await;
    let failed = runtime
        .owner_changed(&policy(), TargetState::Unsecured, true)
        .unwrap();
    assert_eq!(failed.forwarding, ForwardingAvailability::Failed);
    assert!(
        runtime
            .owner_changed(&policy(), TargetState::Unsecured, true)
            .is_none()
    );
    assert_eq!(control.starts.load(SeqCst), 1);
    runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await
        .unwrap();
    assert_eq!(control.starts.load(SeqCst), 2);
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    runtime.stop().await.unwrap();
    let failed_control = Arc::new(Control::default());
    failed_control.fail_start.store(true, SeqCst);
    let mut runtime = make_runtime(None, failed_control.clone());
    assert_eq!(
        runtime
            .update(&policy(), TargetState::Unsecured, true)
            .await
            .unwrap()
            .forwarding,
        ForwardingAvailability::Failed
    );
    runtime.owner_changed(&policy(), TargetState::Unsecured, true);
    assert_eq!(failed_control.starts.load(SeqCst), 1);
    failed_control.fail_start.store(false, SeqCst);
    runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await
        .unwrap();
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    runtime.shutdown().await.unwrap();
    runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await;
    assert!(!runtime.has_owner());
}

#[tokio::test]
async fn route_reconciliation_joins_before_replacement_and_ignores_condition_and_order_changes() {
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(None, control.clone());
    let mut configured = policy();
    runtime
        .update(&configured, TargetState::Unsecured, true)
        .await;
    let original = configured.announced_routes();
    configured.rules[0].name = "renamed".into();
    configured.rules[0].cidrs.reverse();
    let duplicate = configured.rules[0].cidrs[0];
    configured.rules[0].cidrs.push(duplicate);
    configured.rules[0]
        .ssid_ids
        .push(SsidIdentity::from_bytes(b"different".to_vec()).unwrap());
    runtime
        .update(&configured, TargetState::Unsecured, true)
        .await;
    assert_eq!(configured.announced_routes(), original);
    assert_eq!(control.starts.load(SeqCst), 1);
    assert!(
        *control
            .authority
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .subscribe()
            .borrow()
            > 1
    );
    for cidrs in [
        vec!["10.0.2.3/32", "fd42::/64"],
        vec!["fe80::/64"],
        vec!["10.0.2.2/32"],
    ] {
        configured.rules[0].cidrs = cidrs.iter().map(|cidr| cidr.parse().unwrap()).collect();
        runtime
            .update(&configured, TargetState::Unsecured, true)
            .await;
        assert_eq!(
            control.routes.lock().unwrap().last().unwrap(),
            &configured
                .announced_routes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }
    let history = control.history.lock().unwrap().clone();
    assert_eq!(
        history,
        [
            "start", "stop", "released", "start", "stop", "released", "start", "stop", "released",
            "start"
        ]
    );
    configured.rules[0].enabled = false;
    runtime
        .update(&configured, TargetState::Unsecured, true)
        .await;
    assert!(!runtime.has_owner());
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Off);
    configured.rules[0].enabled = true;
    runtime
        .update(&configured, TargetState::Unsecured, true)
        .await;
    configured.enabled = false;
    runtime
        .update(&configured, TargetState::Unsecured, true)
        .await;
    assert!(!runtime.has_owner());
    configured.enabled = true;
    configured.rules.clear();
    runtime
        .update(&configured, TargetState::Unsecured, true)
        .await;
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Off);
}

#[tokio::test]
async fn outstanding_release_blocks_replacement_and_connect_until_a_later_event_retry() {
    let control = Arc::new(Control::default());
    let mut delivery = Delivery::new(
        FakeFactory(control.clone()),
        authority(),
        DeliveryBuffers::new().local,
    );
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    control.fail_release.store(true, SeqCst);
    let mut changed = policy();
    changed.rules[0].cidrs = vec!["10.0.2.3/32".parse().unwrap()];
    delivery
        .maintain(&changed, TargetState::Unsecured, true)
        .await;
    assert!(delivery.has_owner());
    assert_eq!(control.starts.load(SeqCst), 1);
    assert!(!control.history.lock().unwrap().contains(&"retry".into()));
    delivery.owner_changed();
    assert_eq!(control.starts.load(SeqCst), 1);
    assert!(delivery.stop().await.is_err());
    assert!(delivery.has_owner());
    assert_eq!(
        control
            .history
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "retry")
            .count(),
        1
    );
    control.fail_release.store(false, SeqCst);
    delivery
        .maintain(&changed, TargetState::Unsecured, true)
        .await;
    assert_eq!(control.starts.load(SeqCst), 2);
    delivery.stop().await.unwrap();
    assert!(!delivery.has_owner());
    control.history.lock().unwrap().push("connect".into());
    let history = control.history.lock().unwrap().clone();
    assert_eq!(
        &history[history.len() - 3..],
        ["stop", "released", "connect"]
    );
}

#[tokio::test]
async fn cancelled_or_failed_readiness_retains_the_recovery_owner() {
    let control = Arc::new(Control::default());
    control.hold_ready.store(true, SeqCst);
    let mut delivery = Delivery::new(
        FakeFactory(control.clone()),
        authority(),
        DeliveryBuffers::new().local,
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), async {
            delivery
                .maintain(&policy(), TargetState::Unsecured, true)
                .await;
            delivery.changed().await;
        })
        .await
        .is_err()
    );
    assert!(delivery.has_owner());
    assert_eq!(
        delivery.availability(&policy(), TargetState::Unsecured, true),
        ForwardingAvailability::PausedWhileConnected
    );
    control.fail_release.store(true, SeqCst);
    assert!(delivery.stop().await.is_err());
    assert!(delivery.has_owner());
    control.fail_release.store(false, SeqCst);
    delivery.stop().await.unwrap();
    assert!(!delivery.has_owner());
    control.hold_ready.store(false, SeqCst);
    control.fail_ready.store(true, SeqCst);
    control.fail_release.store(true, SeqCst);
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    assert!(delivery.has_owner());
    assert_eq!(
        delivery.availability(&policy(), TargetState::Unsecured, true),
        ForwardingAvailability::Failed
    );
    control.fail_ready.store(false, SeqCst);
    control.fail_release.store(false, SeqCst);
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    assert_eq!(
        delivery.availability(&policy(), TargetState::Unsecured, true),
        ForwardingAvailability::Active
    );
    delivery.stop().await.unwrap();
}

#[tokio::test]
async fn external_change_can_recover_failure_before_the_owner_notification_is_selected() {
    let control = Arc::new(Control::default());
    let mut delivery = Delivery::new(
        FakeFactory(control.clone()),
        authority(),
        DeliveryBuffers::new().local,
    );
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    control.fail_release.store(true, SeqCst);
    control
        .state
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .send_replace(OwnerState::Failed);
    // A settings/feed event may win select before the terminal-owner event.
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    assert!(delivery.has_owner());
    assert_eq!(control.starts.load(SeqCst), 1);
    assert_eq!(
        control
            .history
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "retry")
            .count(),
        1
    );
    delivery.owner_changed();
    assert_eq!(
        control
            .history
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "retry")
            .count(),
        1
    );
    control.fail_release.store(false, SeqCst);
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    assert_eq!(control.starts.load(SeqCst), 2);
    delivery.stop().await.unwrap();
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_packet(flow: Flow, sequence: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 40 + payload.len()];
    bytes[0] = 0x45;
    let len = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&len.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    let IpAddr::V4(source) = flow.source.ip() else {
        unreachable!()
    };
    let IpAddr::V4(destination) = flow.destination.ip() else {
        unreachable!()
    };
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[20..22].copy_from_slice(&flow.source.port().to_be_bytes());
    bytes[22..24].copy_from_slice(&flow.destination.port().to_be_bytes());
    bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
    bytes[28..32].copy_from_slice(&ack.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = flags;
    bytes[34..36].copy_from_slice(&32768u16.to_be_bytes());
    bytes[40..].copy_from_slice(payload);
    let mut pseudo = bytes[12..20].to_vec();
    pseudo.extend([0, 6]);
    pseudo.extend(((bytes.len() - 20) as u16).to_be_bytes());
    pseudo.extend(&bytes[20..]);
    bytes[36..38].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    let ip_checksum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    assert!(packet::parse(&bytes).is_ok());
    bytes
}

fn udp_packet(flow: Flow, payload: &[u8]) -> Vec<u8> {
    packet::udp_reply(
        Flow {
            source: flow.destination,
            destination: flow.source,
            transport: Transport::Udp,
        },
        payload,
    )
    .unwrap()
}

async fn tcp_reply(endpoints: &mut Endpoints, port: u16, nonce: &[u8]) {
    let flow = flow(Transport::Tcp, port);
    endpoints
        .input
        .send(tcp_packet(flow, 100, 0, 2, &[]))
        .await
        .unwrap();
    let syn = bounded(endpoints.output.recv()).await.unwrap();
    assert_eq!(syn[33] & 0x12, 0x12);
    let ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    endpoints
        .input
        .send(tcp_packet(flow, 101, ack, 0x18, nonce))
        .await
        .unwrap();
    let mut received = vec![];
    while received.len() < nonce.len() {
        let bytes = bounded(endpoints.output.recv()).await.unwrap();
        let packet = packet::parse(&bytes).unwrap();
        received.extend_from_slice(packet.payload);
    }
    assert_eq!(received, nonce);
}

#[tokio::test]
async fn observer_unavailable_keeps_announcements_and_denies_delivery() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let tcp_hits = hits.clone();
    let tcp_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let hits = tcp_hits.clone();
            tokio::spawn(async move {
                let mut bytes = [0; 256];
                loop {
                    let count = stream.read(&mut bytes).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    hits.fetch_add(1, SeqCst);
                    stream.write_all(&bytes[..count]).await.unwrap();
                }
            });
        }
    });
    let udp_hits = hits.clone();
    let udp_task = tokio::spawn(async move {
        let mut bytes = [0; 256];
        loop {
            let (count, source) = udp.recv_from(&mut bytes).await.unwrap();
            udp_hits.fetch_add(1, SeqCst);
            udp.send_to(&bytes[..count], source).await.unwrap();
        }
    });
    let control = Arc::new(Control::default());
    *control.peer.lock().unwrap() = Some(peer);
    // Missing feed, no first record, failed registration, stopped watcher and
    // explicit closure each start once with the exact same announcements.
    for case in 0..5 {
        let feed = LocalNetworkFeed::new(1);
        match case {
            2 => {
                assert!(!feed.register::<()>(|_| Err(())));
            }
            3 => {
                feed.publish(
                    1,
                    LocalNetworkSnapshot {
                        sequence: 1,
                        observer_running: false,
                        ..Default::default()
                    },
                );
            }
            4 => feed.close(),
            _ => {}
        }
        let local_control = Arc::new(Control::default());
        let mut runtime = make_runtime(
            if case == 0 { None } else { Some(feed) },
            local_control.clone(),
        );
        runtime
            .update(&policy(), TargetState::Unsecured, true)
            .await;
        assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
        assert!(!runtime.status().observer_available);
        assert!(
            runtime
                .status()
                .rules
                .iter()
                .all(|rule| rule.state == RuleState::Inactive(InactiveReason::ObserverUnavailable))
        );
        assert_eq!(
            *local_control.routes.lock().unwrap(),
            [policy()
                .announced_routes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()]
        );
        let authority = local_control
            .authority
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(
            authority.authorize(flow(Transport::Tcp, 41000)),
            Err(Refused::Denied)
        );
        assert_eq!(
            authority.authorize(flow(Transport::Udp, 41001)),
            Err(Refused::Denied)
        );
        runtime.stop().await.unwrap();
    }
    let prepares = Arc::new(AtomicUsize::new(0));
    let prepared = prepares.clone();
    let authority = Arc::new(DeliveryAuthority::new(
        &policy(),
        Arc::new(move |_, _| {
            prepared.fetch_add(1, SeqCst);
            Ok(())
        }),
    ));
    let mut delivery = Delivery::new(
        FakeFactory(control.clone()),
        authority.clone(),
        DeliveryBuffers::new().local,
    );
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    let mut endpoints = control.endpoints.lock().unwrap().take().unwrap();
    authority.update(&policy(), Some(observation()));
    tcp_reply(&mut endpoints, 42000, b"krtek-m3-tcp-before").await;
    let udp_flow = flow(Transport::Udp, 42001);
    endpoints
        .input
        .send(udp_packet(udp_flow, b"krtek-m3-udp-before"))
        .await
        .unwrap();
    loop {
        let bytes = bounded(endpoints.output.recv()).await.unwrap();
        if let Ok(packet) = packet::parse(&bytes)
            && packet.flow.transport == Transport::Udp
        {
            assert_eq!(packet.payload, b"krtek-m3-udp-before");
            break;
        }
    }
    let mut unmet = policy();
    unmet.rules[0]
        .ssid_ids
        .push(SsidIdentity::from_bytes(b"different".to_vec()).unwrap());
    authority.update(&unmet, Some(observation()));
    delivery
        .maintain(&unmet, TargetState::Unsecured, true)
        .await;
    assert_eq!(unmet.announced_routes(), policy().announced_routes());
    let before_unmet = hits.load(SeqCst);
    let prepares_before_unmet = prepares.load(SeqCst);
    endpoints
        .input
        .send(tcp_packet(flow(Transport::Tcp, 42500), 100, 0, 2, &[]))
        .await
        .unwrap();
    endpoints
        .input
        .send(udp_packet(flow(Transport::Udp, 42501), b"krtek-m3-unmet"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                let bytes = endpoints.output.recv().await.unwrap();
                assert!(
                    packet::parse(&bytes).unwrap().payload.is_empty(),
                    "unmet rule delivered payload"
                );
            }
        })
        .await
        .is_err()
    );
    assert_eq!(hits.load(SeqCst), before_unmet);
    assert_eq!(prepares.load(SeqCst), prepares_before_unmet);
    assert_eq!(control.starts.load(SeqCst), 1);
    authority.update(&policy(), Some(observation()));
    control.hold_output.send_replace(true);
    endpoints
        .input
        .send(udp_packet(udp_flow, b"krtek-m3-queued"))
        .await
        .unwrap();
    bounded(async {
        while hits.load(SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    bounded(async {
        while !control.queued.load(SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    authority.update(&policy(), None);
    control.hold_output.send_replace(false);
    let before = hits.load(SeqCst);
    let prepared_before = prepares.load(SeqCst);
    endpoints
        .input
        .send(tcp_packet(flow(Transport::Tcp, 43000), 100, 0, 2, &[]))
        .await
        .unwrap();
    endpoints
        .input
        .send(udp_packet(flow(Transport::Udp, 43001), b"krtek-m3-denied"))
        .await
        .unwrap();
    // Revocation may emit a protocol-only TCP RST, never a held UDP payload.
    let quiet = tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            let bytes = endpoints.output.recv().await.unwrap();
            assert!(
                packet::parse(&bytes).unwrap().payload.is_empty(),
                "revoked reply reached fake consumer"
            );
        }
    })
    .await;
    assert!(quiet.is_err());
    assert_eq!(hits.load(SeqCst), before);
    assert_eq!(prepares.load(SeqCst), prepared_before);
    assert_eq!(control.starts.load(SeqCst), 1);
    assert!(control.active.load(SeqCst));
    assert_eq!(
        delivery.availability(&policy(), TargetState::Unsecured, true),
        ForwardingAvailability::Active
    );
    authority.update(&policy(), Some(observation()));
    tcp_reply(&mut endpoints, 44000, b"krtek-m3-tcp-after").await;
    endpoints
        .input
        .send(udp_packet(
            flow(Transport::Udp, 44001),
            b"krtek-m3-udp-after",
        ))
        .await
        .unwrap();
    loop {
        let bytes = bounded(endpoints.output.recv()).await.unwrap();
        let packet = packet::parse(&bytes).unwrap();
        if packet.flow.transport == Transport::Udp {
            assert_eq!(packet.payload, b"krtek-m3-udp-after");
            break;
        }
    }
    assert_eq!(control.starts.load(SeqCst), 1);
    assert_eq!(control.routes.lock().unwrap().len(), 1);
    delivery.stop().await.unwrap();
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn closed_observer_feed_keeps_active_owner_and_publishes_one_revision_without_spin() {
    let feed = LocalNetworkFeed::new(1);
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(Some(feed.clone()), control.clone());
    runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await;
    feed.publish(
        1,
        LocalNetworkSnapshot {
            sequence: 1,
            observer_running: true,
            local_ready: true,
            ..Default::default()
        },
    );
    bounded(runtime.notifications().0).await;
    runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await;
    let before = runtime.status().revision;
    feed.close();
    bounded(runtime.notifications().0).await;
    let status = runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await
        .unwrap();
    assert_eq!(status.revision, before + 1);
    assert_eq!(status.forwarding, ForwardingAvailability::Active);
    assert!(!status.observer_available);
    assert!(
        status
            .rules
            .iter()
            .all(|rule| rule.state == RuleState::Inactive(InactiveReason::ObserverUnavailable))
    );
    assert!(
        runtime
            .update(&policy(), TargetState::Unsecured, true)
            .await
            .is_none()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), runtime.notifications().0)
            .await
            .is_err()
    );
    assert_eq!(control.starts.load(SeqCst), 1);
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn permission_and_network_changes_revalidate_without_replacing_announcements() {
    let control = Arc::new(Control::default());
    let authority = authority();
    let mut updates = authority.subscribe();
    let mut delivery = Delivery::new(
        FakeFactory(control.clone()),
        authority.clone(),
        DeliveryBuffers::new().local,
    );
    authority.update(&policy(), Some(observation()));
    delivery
        .maintain(&policy(), TargetState::Unsecured, true)
        .await;
    let lease = authority.authorize(flow(Transport::Tcp, 45000)).unwrap();
    for change in 0..4 {
        let mut observed = observation();
        match change {
            0 => observed.permissions.as_mut().unwrap().local_network = false,
            1 => observed.networks[0].handle += 1,
            2 => observed.networks[0].routes.clear(),
            3 => observed.networks[0].interface_index += 1,
            _ => unreachable!(),
        }
        authority.update(&policy(), Some(observed));
        bounded(updates.changed()).await.unwrap();
        assert!(!authority.current(&lease));
        delivery
            .maintain(&policy(), TargetState::Unsecured, true)
            .await;
        assert_eq!(control.starts.load(SeqCst), 1);
        assert_eq!(
            delivery.availability(&policy(), TargetState::Unsecured, true),
            ForwardingAvailability::Active
        );
    }
    assert_eq!(
        *control.routes.lock().unwrap(),
        [policy()
            .announced_routes()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()]
    );
    delivery.stop().await.unwrap();
}

#[tokio::test]
async fn route_replacement_failure_publishes_once_and_waits_for_an_external_event() {
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(None, control.clone());
    runtime
        .update(&policy(), TargetState::Unsecured, true)
        .await;
    let mut replacement = policy();
    replacement.rules[0]
        .cidrs
        .push("fd42::/64".parse().unwrap());
    control.fail_start.store(true, SeqCst);
    let status = runtime
        .update(&replacement, TargetState::Unsecured, true)
        .await
        .unwrap();
    assert_eq!(status.forwarding, ForwardingAvailability::Failed);
    assert!(!runtime.has_owner());
    assert_eq!(
        *control.history.lock().unwrap(),
        ["start", "stop", "released"]
    );
    assert_eq!(control.starts.load(SeqCst), 2);
    assert!(
        runtime
            .owner_changed(&replacement, TargetState::Unsecured, true)
            .is_none()
    );
    assert_eq!(control.starts.load(SeqCst), 2);
    control.fail_start.store(false, SeqCst);
    runtime
        .update(&replacement, TargetState::Unsecured, true)
        .await;
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    assert_eq!(control.starts.load(SeqCst), 3);
    assert_eq!(
        control.routes.lock().unwrap().last().unwrap(),
        &replacement
            .announced_routes()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    runtime.stop().await.unwrap();
}
