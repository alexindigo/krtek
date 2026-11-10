use super::*;
use crate::{
    packet_attachment::{AttachmentBroker, AttachmentMode, ConfigurationRequest},
    tun_provider::{TunConfig, blocking_config},
};

#[path = "router_tests.rs"]
mod router_tests;

fn assigned() -> TunConfig {
    let mut config = blocking_config();
    config.addresses = vec!["10.64.42.2".parse().unwrap(), "fc00:42::2".parse().unwrap()];
    config.ipv6_gateway = Some("fc00:42::1".parse().unwrap());
    config.dns_servers = Some(vec![
        config.ipv4_gateway.into(),
        config.ipv6_gateway.unwrap().into(),
    ]);
    config.mtu = 1440;
    config
}

#[tokio::test]
async fn unsupported_capture_formats_never_admit_packets_and_retain_failed_release() {
    for flags in [0, 1, 0x1002, 0x5001, 0x1401] {
        for secured in [false, true] {
            let (platform, peer) = Platform::new();
            *platform.format_flags.lock().unwrap() = Some(flags);
            platform.release_fails.store(true, SeqCst);
            let broker = broker();
            let (_request, managed) = managed(&broker);
            let config = if secured {
                managed
            } else {
                CaptureConfig::Partial(routes().into())
            };
            let authority = Arc::new(Authority::default());
            let (address, mut hits, echo) = udp_echo(false).await;
            let request = Flow {
                source: if secured {
                    "10.64.42.2:48500"
                } else {
                    "192.0.2.2:48500"
                }
                .parse()
                .unwrap(),
                destination: address,
                transport: Transport::Udp,
            };
            // Stage real input before opening. A format check after admission
            // would let this nonce reach the physical consumer.
            send(&peer, &udp(request, b"unsupported-format-must-not-escape")).await;
            let (_updates, updates) = watch::channel(0);
            let mut owner = FrontendOwner::start(
                platform.clone(),
                config,
                managed_forwarder(authority.clone()),
                updates,
                broker.clone(),
            )
            .unwrap();
            let error = bounded(owner.ready()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<UnsupportedCaptureFormat>()
                    .is_some()
            );
            assert!(owner.stop().await.is_err());
            assert_eq!(platform.format_calls.load(SeqCst), 1);
            assert_eq!(platform.bound_generation.load(SeqCst), 0);
            assert_eq!(authority.prepares.load(SeqCst), 0);
            assert!(hits.try_recv().is_err());
            assert!(!broker.snapshot().capture_ready);
            assert!(owner.release_failed());
            assert!(platform.active.load(SeqCst));
            platform.release_fails.store(false, SeqCst);
            owner.retry_release().unwrap();
            owner.stop().await.unwrap();
            assert_eq!(platform.closed.load(SeqCst), 2);
            assert!(!platform.active.load(SeqCst));
            echo.abort();
        }
    }
}

#[tokio::test]
async fn partial_platform_contract_delivers_replaces_and_releases_without_any_observation() {
    // The actual Kotlin Builder/API matrix is paired with this native consumer
    // seam: the readiness feed is unavailable and the managed bind hook fails.
    for api in [28, 30, 32, 33] {
        let (platform, mut peer) = Platform::new();
        platform.capture_feed().close();
        platform.bind_error.store(true, SeqCst);
        let (address, mut hits, echo) = udp_echo(false).await;
        let (tcp, mut accepts, server) = tcp_echo(false).await;
        let (_updates, updates) = watch::channel(0);
        let mut last_generation = 0;
        for replacement in [false, true] {
            let mut owner = start(
                platform.clone(),
                if replacement {
                    vec!["10.0.2.99/32".into()]
                } else {
                    routes()
                },
                test_forwarder(Arc::new(Authority::default())),
                updates.clone(),
            )
            .await
            .unwrap();
            let generation = platform.generation.load(SeqCst);
            assert!(generation > last_generation, "API {api}: reused generation");
            last_generation = generation;
            let nonce = format!("partial-api-{api}-replacement-{replacement}");
            let request = flow(address, Transport::Udp, 48500);
            let mut app = App::new(flow(
                tcp,
                Transport::Tcp,
                if replacement { 48502 } else { 48501 },
            ));
            app.nonce(&peer, nonce.as_bytes()).await;
            bounded(accepts.recv()).await.unwrap();
            app.socket().close();
            app.until(&peer, |app| !app.socket().is_open()).await;
            // The final TCP ACK is still queued in the fake interface. A later
            // UDP round trip proves the owner consumed it before the EOF check.
            send(&peer, &udp(request, nonce.as_bytes())).await;
            assert_eq!(bounded(hits.recv()).await.unwrap(), nonce.as_bytes());
            let bytes = bounded(receive(&peer)).await;
            assert_eq!(packet::parse(&bytes).unwrap().payload, nonce.as_bytes());
            assert!(platform.expected.lock().unwrap().is_none());
            assert_eq!(platform.bound_generation.load(SeqCst), 0);
            if replacement {
                platform.release_fails.store(true, SeqCst);
                assert!(owner.stop().await.is_err());
                assert!(platform.active.load(SeqCst));
                platform.release_fails.store(false, SeqCst);
                owner.retry_release().unwrap();
            }
            owner.stop().await.unwrap();
            assert!(bounded(receive(&peer)).await.is_empty());
            assert!(!platform.active.load(SeqCst));
            if !replacement {
                let (fd, next_peer) = pair();
                *platform.next.lock().unwrap() = Some(fd);
                peer = AsyncFd::new(next_peer).unwrap();
            }
        }
        assert_eq!(platform.opened.load(SeqCst), 2);
        assert_eq!(platform.closed.load(SeqCst), 3);
        echo.abort();
        server.abort();
    }
}

pub(super) fn broker() -> AttachmentBroker {
    use talpid_netstack::buffer_budget::BufferBudget;
    AttachmentBroker::new(
        Arc::new(BufferBudget::new(22 * 1024 * 1024)),
        Arc::new(BufferBudget::new(2 * 1024 * 1024)),
        Arc::new(BufferBudget::new(8 * 1024 * 1024)),
    )
    .unwrap()
}

fn managed(broker: &AttachmentBroker) -> (ConfigurationRequest, CaptureConfig) {
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let request = broker.request_capture(assigned()).unwrap();
    let config = CaptureConfig::Secured {
        broker: broker.clone(),
        request: broker.pending_request().unwrap(),
        disposition: Arc::new(|destination| {
            if destination.is_loopback() {
                CaptureDisposition::Local
            } else {
                CaptureDisposition::Tunnel(talpid_types::relay_flow::RelayTargetId::MULLVAD)
            }
        }),
    };
    (request, config)
}

fn managed_forwarder(authority: Arc<Authority>) -> Forwarder<Authority> {
    Forwarder::with_mtu(
        authority,
        Arc::new(talpid_netstack::buffer_budget::BufferBudget::new(
            30 * 1024 * 1024,
        )),
        1440,
    )
    .unwrap()
}

async fn wait_bound(platform: &Platform) -> i64 {
    bounded(async {
        loop {
            if platform.bound_generation.load(SeqCst) > 0 {
                return platform.bound_generation.load(SeqCst) as i64;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

fn raw(protocol: u8, nonce: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x9c; 20 + nonce.len()];
    bytes[0] = 0x45;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&[10, 64, 42, 2]);
    bytes[16..20].copy_from_slice(&[1, 1, 1, 1]);
    bytes[20..].copy_from_slice(nonce);
    bytes
}

fn raw_ipv6(protocol: u8, nonce: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xb3; 40 + nonce.len()];
    bytes[0] = 0x60;
    bytes[6] = protocol;
    bytes[8..24].copy_from_slice(&"fc00:42::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    bytes[24..40].copy_from_slice(
        &"2001:4860:4860::8888"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    bytes[40..].copy_from_slice(nonce);
    bytes
}

#[tokio::test]
async fn receipt_waits_for_current_fd_bound_observation_and_loss_retires_before_output() {
    let (platform, peer) = Platform::new();
    platform.manual.store(true, SeqCst);
    let broker = broker();
    let (mut request, config) = managed(&broker);
    let (_updates, updates) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        config,
        managed_forwarder(Arc::new(Authority::default())),
        updates,
        broker.clone(),
    )
    .unwrap();
    let generation = wait_bound(&platform).await;
    assert!(!broker.snapshot().capture_ready);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), owner.ready())
            .await
            .is_err()
    );
    assert!(!platform.publish(generation - 1, false));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), request.configured())
            .await
            .is_err()
    );
    assert!(platform.publish(generation, false));
    bounded(owner.ready()).await.unwrap();
    let receipt = bounded(request.configured()).await.unwrap();
    let mut transport = broker.acquire(&receipt).unwrap();
    transport.control.activate().unwrap();
    let packet = raw(1, b"ordinary-icmp-nonce");
    send(&peer, &packet).await;
    assert_eq!(
        bounded(transport.receive.recv())
            .await
            .unwrap()
            .view()
            .bytes(),
        packet
    );
    assert!(platform.publish(generation, true));
    // This is synchronous on publication, before the native task can wake.
    assert!(!receipt.current());
    assert!(!transport.control.current());
    assert!(transport.send.try_send(&packet).is_err());
    let mut state = owner.state();
    bounded(state.wait_for(|s| *s == FrontendState::Failed))
        .await
        .unwrap();
    request.transport_joined();
    owner.stop().await.unwrap();
    assert!(bounded(receive(&peer)).await.is_empty());
}

#[tokio::test]
async fn local_and_raw_consumers_share_capture_without_denied_local_fallback() {
    let (platform, peer) = Platform::new();
    let authority = Arc::new(Authority::default());
    let broker = broker();
    let (mut request, config) = managed(&broker);
    let (updates, rx) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        config,
        managed_forwarder(authority.clone()),
        rx,
        broker.clone(),
    )
    .unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = bounded(request.configured()).await.unwrap();
    let mut transport = broker.acquire(&receipt).unwrap();
    // An installed but unauthenticated carrier cannot replay ordinary input.
    send(&peer, &raw(1, b"pending-dropped")).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), transport.receive.recv())
            .await
            .is_err()
    );
    transport.control.activate().unwrap();
    let (address, mut hits, echo) = udp_echo(false).await;
    let local = Flow {
        source: "10.64.42.2:48000".parse().unwrap(),
        destination: address,
        transport: Transport::Udp,
    };
    send(&peer, &udp(local, b"assigned-local-nonce")).await;
    assert_eq!(bounded(hits.recv()).await.unwrap(), b"assigned-local-nonce");
    let bytes = bounded(receive(&peer)).await;
    let reply = packet::parse(&bytes).unwrap();
    assert_eq!(reply.payload, b"assigned-local-nonce");
    assert_eq!(reply.flow.source, local.destination);
    assert_eq!(reply.flow.destination, local.source);
    let (tcp, mut accepts, tcp_server) = tcp_echo(false).await;
    let mut app = App::new(Flow {
        source: "10.64.42.2:48001".parse().unwrap(),
        destination: tcp,
        transport: Transport::Tcp,
    });
    app.nonce(&peer, b"assigned-local-tcp-nonce").await;
    bounded(accepts.recv()).await.unwrap();
    app.socket().close();
    app.until(&peer, |app| !app.socket().is_open()).await;
    for (protocol, ipv6) in (0..=255).flat_map(|protocol| [(protocol, false), (protocol, true)]) {
        let packet = if ipv6 {
            raw_ipv6(protocol, &vec![protocol; 2000])
        } else {
            raw(protocol, &vec![protocol; 2000])
        };
        send(&peer, &packet).await;
        let outbound = bounded(transport.receive.recv()).await.unwrap();
        assert_eq!(outbound.view().bytes(), packet);
        // Authenticated return bytes are intentionally opaque at this boundary.
        transport.send.try_send(&packet).unwrap();
        assert_eq!(bounded(receive(&peer)).await, packet);
    }
    authority.available.store(false, SeqCst);
    authority.revision.fetch_add(1, SeqCst);
    updates.send(1).unwrap();
    send(&peer, &udp(local, b"unmet-local-never-relay")).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), transport.receive.recv())
            .await
            .is_err()
    );
    assert!(hits.try_recv().is_err());
    transport.control.detach();
    request.transport_joined();
    owner.stop().await.unwrap();
    echo.abort();
    tcp_server.abort();
}

#[tokio::test]
async fn raw_fatal_sink_joins_physical_work_and_retains_failed_release() {
    let (platform, peer) = Platform::new();
    let pause = Arc::new(Pause::default());
    let _release = Release(pause.clone());
    let authority = Arc::new(Authority {
        pause: Some(pause.clone()),
        ..Authority::default()
    });
    let mut forwarder = managed_forwarder(authority);
    let (address, mut hits, echo) = udp_echo(false).await;
    forwarder.ingest(&udp(
        Flow {
            source: "10.64.42.2:48010".parse().unwrap(),
            destination: address,
            transport: Transport::Udp,
        },
        b"joined-raw-fatal",
    ));
    bounded(pause.entered.notified()).await;
    nix::sys::socket::shutdown(peer.get_ref().as_raw_fd(), nix::sys::socket::Shutdown::Read)
        .unwrap();
    platform.release_fails.store(true, SeqCst);
    let broker = broker();
    let (mut request, config) = managed(&broker);
    let (_updates, updates) = watch::channel(0);
    let mut owner =
        FrontendOwner::start(platform.clone(), config, forwarder, updates, broker.clone()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = bounded(request.configured()).await.unwrap();
    let transport = broker.acquire(&receipt).unwrap();
    transport.control.activate().unwrap();
    transport
        .send
        .try_send(&raw(1, b"raw-fatal-sink-nonce"))
        .unwrap();
    let mut state = owner.state();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), state.changed())
            .await
            .is_err()
    );
    assert_eq!(platform.closed.load(SeqCst), 0);
    let (path, target) = platform.descriptor.lock().unwrap().clone().unwrap();
    assert_eq!(
        std::fs::read_link(path).unwrap(),
        target,
        "raw fatal write skipped physical join"
    );
    assert!(
        !receipt.current(),
        "fatal output did not retire capture before join"
    );
    pause.unblock();
    bounded(state.wait_for(|s| *s == FrontendState::Failed))
        .await
        .unwrap();
    request.transport_joined();
    assert!(bounded(owner.stop()).await.is_err());
    assert_eq!(platform.closed.load(SeqCst), 1);
    assert!(platform.active.load(SeqCst));
    platform.release_fails.store(false, SeqCst);
    owner.retry_release().unwrap();
    owner.stop().await.unwrap();
    assert!(!platform.active.load(SeqCst));
    assert!(hits.try_recv().is_err());
    echo.abort();
}

#[tokio::test]
async fn secured_local_output_never_uses_partial_guard_while_transport_is_pending() {
    let (platform, peer) = Platform::new();
    let authority = Arc::new(Authority::default());
    let mut forwarder = managed_forwarder(authority.clone());
    let (address, mut hits, echo) = udp_echo(false).await;
    let local = Flow {
        source: "10.64.42.2:48011".parse().unwrap(),
        destination: address,
        transport: Transport::Udp,
    };
    forwarder.ingest(&udp(local, b"unready-queued-local-nonce"));
    bounded(async {
        while !forwarder.has_output() {
            forwarder.wait().await;
        }
    })
    .await;
    assert_eq!(
        bounded(hits.recv()).await.unwrap(),
        b"unready-queued-local-nonce"
    );
    let broker = broker();
    let (mut request, config) = managed(&broker);
    let (_updates, updates) = watch::channel(0);
    let mut owner =
        FrontendOwner::start(platform, config, forwarder, updates, broker.clone()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = request.configured().await.unwrap();
    let transport = broker.acquire(&receipt).unwrap();
    assert!(!transport.control.current());
    let bytes = bounded(receive(&peer)).await;
    assert_eq!(
        packet::parse(&bytes).unwrap().payload,
        b"unready-queued-local-nonce"
    );
    send(&peer, &raw(253, b"unready-public-never-replayed")).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receive(&peer))
            .await
            .is_err()
    );
    authority.available.store(false, SeqCst);
    authority.revision.fetch_add(1, SeqCst);
    send(&peer, &udp(local, b"revoked-local-never-partial")).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receive(&peer))
            .await
            .is_err()
    );
    assert!(hits.try_recv().is_err());
    assert!(receipt.current(), "physical revocation retired capture");
    transport.control.detach();
    request.transport_joined();
    owner.stop().await.unwrap();
    assert!(bounded(receive(&peer)).await.is_empty());
    echo.abort();
}

#[tokio::test]
async fn open_name_and_bind_faults_retain_platform_release_without_receipts() {
    for fault in ["open", "name", "bind"] {
        let (platform, peer) = Platform::new();
        match fault {
            "open" => platform.open_error.store(true, SeqCst),
            "name" => platform.name_error.store(true, SeqCst),
            _ => platform.bind_error.store(true, SeqCst),
        }
        platform.release_fails.store(true, SeqCst);
        let broker = broker();
        let (mut request, config) = managed(&broker);
        let (_updates, updates) = watch::channel(0);
        let mut owner = FrontendOwner::start(
            platform.clone(),
            config,
            managed_forwarder(Arc::new(Authority::default())),
            updates,
            broker.clone(),
        )
        .unwrap();
        assert!(bounded(owner.ready()).await.is_err());
        assert!(bounded(owner.stop()).await.is_err());
        assert!(!broker.snapshot().capture_ready);
        assert!(bounded(request.configured()).await.is_err());
        assert_eq!(platform.closed.load(SeqCst), 1);
        assert!(platform.active.load(SeqCst));
        assert!(bounded(receive(&peer)).await.is_empty());
        assert!(owner.stop().await.is_err());
        assert_eq!(platform.closed.load(SeqCst), 1);
        platform.release_fails.store(false, SeqCst);
        owner.retry_release().unwrap();
        owner.stop().await.unwrap();
        assert!(!platform.active.load(SeqCst));
        assert_eq!(platform.closed.load(SeqCst), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_raw_output_retains_credit_is_idle_and_responds_to_loss_and_stop() {
    use talpid_netstack::buffer_budget::BufferBudget;
    for outcome in ["drain", "loss", "stop"] {
        let (platform, peer) = Platform::new();
        let application = BufferBudget::new(22 * 1024 * 1024);
        let broker = AttachmentBroker::new(
            Arc::new(application.clone()),
            Arc::new(BufferBudget::new(2 * 1024 * 1024)),
            Arc::new(BufferBudget::new(8 * 1024 * 1024)),
        )
        .unwrap();
        let (mut request, config) = managed(&broker);
        let lease = Arc::new(broker.open_capture(config.request()).unwrap());
        let mut observation =
            Observation::begin(platform.as_ref(), &config, lease.clone(), None, None).unwrap();
        let generation = observation.generation;
        let fd = platform.open(generation, &config).unwrap();
        observation
            .bind(
                platform.as_ref(),
                &config,
                fd.as_fd(),
                platform.capture_format(fd.as_fd()).unwrap(),
            )
            .unwrap();
        let (stop, mut stopped) = oneshot::channel();
        observation
            .wait_ready(&config, None, &mut stopped)
            .await
            .unwrap();
        let mut stop = Some(stop);
        let receipt = request.configured().await.unwrap();
        let transport = broker.acquire(&receipt).unwrap();
        transport.control.activate().unwrap();
        let (_updates, updates) = watch::channel(0);
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let (filled_tx, filled_rx) = oneshot::channel();
        let task_platform = platform.clone();
        let task = tokio::spawn(async move {
            let capture = AsyncFd::new(fd.as_fd()).unwrap();
            // Cache a real writable event, then make it stale before the
            // production adapter writes: its first retry must hit actual EAGAIN.
            let _ = capture.writable().await.unwrap();
            let mut filled = 0;
            loop {
                match nix::unistd::write(&fd, b"raw-sink-filler") {
                    Ok(_) => filled += 1,
                    Err(nix::errno::Errno::EAGAIN) => break,
                    Err(error) => panic!("fill: {error}"),
                }
            }
            filled_tx.send(filled).unwrap();
            let mut forwarder = managed_forwarder(Arc::new(Authority::default()));
            let packet = forwarder.read_buffer().unwrap();
            let terminal = {
                let mut driven = Box::pin(drive(
                    &capture,
                    &mut forwarder,
                    updates,
                    stopped,
                    Some((&config, &observation)),
                    packet,
                ));
                poll_fn(move |cx| {
                    counter.fetch_add(1, SeqCst);
                    driven.as_mut().poll(cx)
                })
                .await
            };
            observation.retire();
            forwarder.close_all().await;
            drop(capture);
            drop(fd);
            task_platform.closed(generation).unwrap();
            terminal
        });
        let filled = bounded(filled_rx).await.unwrap();
        assert!(filled > 1);
        let packets = [raw(1, b"raw-blocked-a"), raw(253, b"raw-blocked-b")];
        for bytes in &packets {
            transport.send.try_send(bytes).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let retained = application.used();
        assert!(retained >= packets.iter().map(Vec::len).sum::<usize>());
        let before = polls.load(SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(polls.load(SeqCst), before, "blocked raw output spun");
        assert_eq!(
            application.used(),
            retained,
            "blocked output refunded storage"
        );
        if outcome == "loss" {
            platform.publish(generation, true);
            assert!(!receipt.current());
            assert!(!transport.control.current());
        } else if outcome == "stop" {
            stop.take().unwrap().send(()).unwrap();
        }
        if outcome != "drain" {
            let terminal = bounded(task).await.unwrap();
            assert_eq!(
                terminal,
                if outcome == "loss" {
                    FrontendState::Failed
                } else {
                    FrontendState::Stopped
                }
            );
            for _ in 0..filled {
                assert_eq!(bounded(receive(&peer)).await, b"raw-sink-filler");
            }
            assert!(bounded(receive(&peer)).await.is_empty());
        } else {
            for _ in 0..filled {
                assert_eq!(bounded(receive(&peer)).await, b"raw-sink-filler");
            }
            for bytes in packets {
                assert_eq!(bounded(receive(&peer)).await, bytes);
            }
            stop.take().unwrap().send(()).unwrap();
            assert_eq!(bounded(task).await.unwrap(), FrontendState::Stopped);
        }
        assert_eq!(application.used(), 0);
        assert!(!receipt.current());
    }
}

#[tokio::test]
async fn mixed_backpressure_rotates_both_consumers_and_revokes_only_blocked_local_output() {
    let (platform, peer) = Platform::new();
    let broker = broker();
    let (mut request, config) = managed(&broker);
    let lease = Arc::new(broker.open_capture(config.request()).unwrap());
    let mut observation =
        Observation::begin(platform.as_ref(), &config, lease, None, None).unwrap();
    let fd = platform.open(observation.generation, &config).unwrap();
    socket2::SockRef::from(&fd)
        .set_send_buffer_size(4096)
        .unwrap();
    observation
        .bind(
            platform.as_ref(),
            &config,
            fd.as_fd(),
            platform.capture_format(fd.as_fd()).unwrap(),
        )
        .unwrap();
    let (_stop, mut stopped) = oneshot::channel();
    observation
        .wait_ready(&config, None, &mut stopped)
        .await
        .unwrap();
    let receipt = request.configured().await.unwrap();
    let transport = broker.acquire(&receipt).unwrap();
    transport.control.activate().unwrap();
    let attempt = observation.lease.capability().unwrap();
    let authority = Arc::new(Authority::default());
    let mut forwarder = managed_forwarder(authority.clone());
    let (address, mut hits, echo) = udp_echo(false).await;
    let local = Flow {
        source: "10.64.42.2:48600".parse().unwrap(),
        destination: address,
        transport: Transport::Udp,
    };
    // Warm the real UDP flow, then retain a sustained Local reply backlog.
    forwarder.ingest(&udp(local, b"local-0"));
    bounded(async {
        while !forwarder.has_output() {
            forwarder.wait().await;
        }
    })
    .await;
    bounded(hits.recv()).await.unwrap();
    for n in 1..12 {
        forwarder.ingest(&udp(local, format!("local-{n}").as_bytes()));
        forwarder.process();
        bounded(hits.recv()).await.unwrap();
    }
    while tokio::time::timeout(Duration::from_millis(10), forwarder.wait())
        .await
        .is_ok()
    {}
    for n in 0..12 {
        transport
            .send
            .try_send(&raw(253, format!("raw-{n}").as_bytes()))
            .unwrap();
    }
    let lease = observation.lease.as_ref();
    let mut reply = Some(lease.reply().await.unwrap());
    let mut taken = 1;
    let mut total = 12;
    let capture = AsyncFd::new(fd.as_fd()).unwrap();
    let _ = capture.writable().await.unwrap();
    let filler = b"mixed-sink-filler";
    let mut filled = 0;
    loop {
        match nix::unistd::write(&fd, filler) {
            Ok(_) => filled += 1,
            Err(nix::errno::Errno::EAGAIN) => break,
            Err(error) => panic!("fill: {error}"),
        }
    }
    assert!(filled > 1);
    let mut raw_first = false;
    drain_fair(
        &capture,
        &mut forwarder,
        &observation,
        Some(&attempt),
        &mut reply,
        &mut raw_first,
    )
    .unwrap();
    assert!(!raw_first, "WouldBlock changed scheduling priority");
    let mut classes = Vec::new();
    let mut raw_received = Vec::new();
    let mut revoked = false;
    bounded(async {
        while raw_received.len() < total {
            // Free exactly one packet at a time, including below the kernel's
            // writable threshold. Both producers share this actual full sink.
            let bytes = tokio::select! {
                bytes = receive(&peer) => Some(bytes),
                ready = capture.writable(), if forwarder.has_output() || reply.is_some() => {
                    let _ = ready.unwrap();
                    drain_fair(&capture, &mut forwarder, &observation, Some(&attempt), &mut reply, &mut raw_first).unwrap();
                    None
                },
            };
            if let Some(bytes) = bytes && bytes != filler {
                if bytes[9] == 253 {
                    classes.push("raw");
                    raw_received.push(String::from_utf8(bytes[20..].to_vec()).unwrap());
                } else {
                    classes.push("local");
                    assert_ne!(packet::parse(&bytes).unwrap().payload, b"local-revoked-while-blocked");
                }
                if classes.len() == 4 {
                    assert!(classes.contains(&"local") && classes.contains(&"raw"), "one class monopolized the first four output slots: {classes:?}");
                }
            }
            if !revoked && classes.len() >= 8 {
                assert!(forwarder.has_output(), "Local producer was not backlogged");
                assert!(reply.is_some() || taken < total, "raw producer was not backlogged");
                forwarder.ingest(&udp(local, b"local-revoked-while-blocked"));
                bounded(hits.recv()).await.unwrap();
                while tokio::time::timeout(Duration::from_millis(10), forwarder.wait()).await.is_ok() {}
                loop {
                    match nix::unistd::write(&fd, filler) {
                        Ok(_) => {},
                        Err(nix::errno::Errno::EAGAIN) => break,
                        Err(error) => panic!("refill: {error}"),
                    }
                }
                let priority = raw_first;
                drain_fair(&capture, &mut forwarder, &observation, Some(&attempt), &mut reply, &mut raw_first).unwrap();
                assert_eq!(raw_first, priority, "blocked classes reset priority");
                authority.available.store(false, SeqCst);
                authority.revision.fetch_add(1, SeqCst);
                forwarder.revalidate();
                transport.send.try_send(&raw(253, b"raw-after-local-revoke")).unwrap();
                total += 1;
                revoked = true;
            }
            if tokio::time::timeout(Duration::from_millis(1), capture.writable()).await.is_ok() {
                drain_fair(&capture, &mut forwarder, &observation, Some(&attempt), &mut reply, &mut raw_first).unwrap();
            }
            if reply.is_none() && taken < total { reply = Some(lease.reply().await.unwrap()); taken += 1; }
        }
    }).await;
    assert!(revoked);
    assert!(classes.iter().filter(|class| **class == "local").count() >= 2);
    assert_eq!(
        raw_received,
        (0..12)
            .map(|n| format!("raw-{n}"))
            .chain(["raw-after-local-revoke".into()])
            .collect::<Vec<_>>()
    );
    assert!(receipt.current());
    observation.retire();
    forwarder.close_all().await;
    drop(capture);
    drop(fd);
    platform.closed(observation.generation).unwrap();
    echo.abort();
}

#[tokio::test]
async fn cancelled_config_or_readiness_joins_and_never_certifies_identical_replacement() {
    for cancel_request in [false, true] {
        let (platform, peer) = Platform::new();
        platform.manual.store(true, SeqCst);
        let broker = broker();
        let (request, config) = managed(&broker);
        let (_updates, updates) = watch::channel(0);
        let mut owner = FrontendOwner::start(
            platform.clone(),
            config,
            managed_forwarder(Arc::new(Authority::default())),
            updates.clone(),
            broker.clone(),
        )
        .unwrap();
        let generation = wait_bound(&platform).await;
        if cancel_request {
            request.cancel();
            assert!(bounded(owner.ready()).await.is_err());
        }
        bounded(owner.stop()).await.unwrap();
        drop(request);
        assert_eq!(platform.closed.load(SeqCst), 1);
        assert!(bounded(receive(&peer)).await.is_empty());
        let (fd, peer) = pair();
        *platform.next.lock().unwrap() = Some(fd);
        *platform.expected.lock().unwrap() = None;
        platform.bound_generation.store(0, SeqCst);
        let (mut replacement_request, config) = managed(&broker);
        let mut replacement = FrontendOwner::start(
            platform.clone(),
            config,
            managed_forwarder(Arc::new(Authority::default())),
            updates,
            broker.clone(),
        )
        .unwrap();
        let next = wait_bound(&platform).await;
        assert!(next > generation);
        assert!(!platform.publish(generation, false));
        assert!(
            tokio::time::timeout(Duration::from_millis(30), replacement.ready())
                .await
                .is_err()
        );
        assert!(platform.publish(next, false));
        bounded(replacement.ready()).await.unwrap();
        assert!(
            bounded(replacement_request.configured())
                .await
                .unwrap()
                .current()
        );
        replacement.stop().await.unwrap();
        drop(peer);
    }
}
