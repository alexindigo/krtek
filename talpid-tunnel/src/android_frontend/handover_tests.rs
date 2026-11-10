use super::*;
use crate::{
    packet_attachment::{AttachmentBroker, AttachmentMode, ConfigurationRequest},
    tun_provider::{TunConfig, blocking_config},
};
use std::{collections::BTreeMap, path::PathBuf, sync::atomic::AtomicI64};
use talpid_types::capture_network::{CaptureNetworkObservation, CapturePrefix};

struct EpochPlatform {
    feed: Arc<CaptureNetworkFeed>,
    expected: Mutex<BTreeMap<i64, CaptureExpectation>>,
    descriptors: Mutex<BTreeMap<i64, (PathBuf, PathBuf)>>,
    peers: mpsc::UnboundedSender<OwnedFd>,
    released: Mutex<Vec<i64>>,
    changed: tokio::sync::Notify,
    pause: Mutex<Option<Arc<Pause>>>,
    close_pause: Mutex<Option<Arc<Pause>>>,
    finish_attempts: AtomicUsize,
    fail_before: AtomicBool,
    fail_after: AtomicBool,
    fail_release: AtomicI64,
    format_calls: AtomicUsize,
    fault: Mutex<Option<&'static str>>,
    fill: AtomicBool,
    filled: Mutex<BTreeMap<i64, usize>>,
}
impl EpochPlatform {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<OwnedFd>) {
        let (peers, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                feed: CaptureNetworkFeed::new(117),
                expected: Mutex::new(BTreeMap::new()),
                descriptors: Mutex::new(BTreeMap::new()),
                peers,
                released: Mutex::new(Vec::new()),
                changed: tokio::sync::Notify::new(),
                pause: Mutex::new(None),
                close_pause: Mutex::new(None),
                finish_attempts: AtomicUsize::new(0),
                fail_before: AtomicBool::new(false),
                fail_after: AtomicBool::new(false),
                fail_release: AtomicI64::new(0),
                format_calls: AtomicUsize::new(0),
                fault: Mutex::new(None),
                fill: AtomicBool::new(false),
                filled: Mutex::new(BTreeMap::new()),
            }),
            receiver,
        )
    }
    fn publish(&self, generation: i64, lost: bool) -> bool {
        let Some(mut observed) = self.observed(generation) else {
            return false;
        };
        observed.fresh = !lost;
        observed.lost = lost;
        self.feed.publish(117, generation, observed)
    }
    fn observed(&self, generation: i64) -> Option<CaptureNetworkObservation> {
        self.expected
            .lock()
            .unwrap()
            .get(&generation)
            .map(|expected| CaptureNetworkObservation {
                network_handle: (generation << 32) | 0x8765_4321,
                network: format!("net-{generation}"),
                interface_name: expected.interface_name.clone(),
                owner_uid: expected.owner_uid,
                routes: expected.routes.clone(),
                addresses: expected.addresses.clone(),
                dns_servers: expected.dns_servers.clone(),
                mtu: expected.mtu,
                fresh: true,
                lost: false,
                api_level: expected.api_level,
            })
    }
    async fn finished(&self, generation: i64) {
        bounded(async {
            loop {
                let changed = self.changed.notified();
                if self.released.lock().unwrap().contains(&generation) {
                    return;
                }
                changed.await;
            }
        })
        .await;
    }
}
impl FrontendPlatform for EpochPlatform {
    fn open(&self, generation: i64, _: &CaptureConfig) -> io::Result<OwnedFd> {
        let (fd, peer) = pair();
        if self.fill.load(SeqCst) {
            socket2::SockRef::from(&fd).set_send_buffer_size(4096)?;
            let mut filled = 0;
            loop {
                match nix::unistd::write(&fd, b"handover-sink-filler") {
                    Ok(_) => filled += 1,
                    Err(nix::errno::Errno::EAGAIN) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            assert!(filled > 1);
            self.filled.lock().unwrap().insert(generation, filled);
        }
        let path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
        self.descriptors
            .lock()
            .unwrap()
            .insert(generation, (path.clone(), std::fs::read_link(path)?));
        self.peers.send(peer).unwrap();
        Ok(fd)
    }
    fn handover(
        &self,
        predecessor: i64,
        generation: i64,
        config: &CaptureConfig,
    ) -> CaptureHandover {
        if self.fail_before.load(SeqCst) {
            return CaptureHandover {
                descriptor: Err(io::Error::other("before establish")),
                predecessor_retained: true,
            };
        }
        // Framework establish can invalidate the old Network before returning.
        self.publish(predecessor, true);
        let descriptor = self.open(generation, config);
        if let Some(pause) = self.pause.lock().unwrap().take() {
            pause.enter();
        }
        if self.fail_after.load(SeqCst) {
            drop(descriptor);
            CaptureHandover {
                descriptor: Err(io::Error::other("lost establish acknowledgement")),
                predecessor_retained: false,
            }
        } else {
            CaptureHandover {
                descriptor,
                predecessor_retained: false,
            }
        }
    }
    fn capture_format(&self, _: BorrowedFd<'_>) -> io::Result<CaptureFormat> {
        self.format_calls.fetch_add(1, SeqCst);
        CaptureFormat::from_flags(if *self.fault.lock().unwrap() == Some("format") {
            0x5001
        } else {
            0x1001
        })
    }
    fn interface_name(&self, fd: BorrowedFd<'_>) -> io::Result<String> {
        if *self.fault.lock().unwrap() == Some("interface") {
            return Err(io::Error::other("fd name lookup failed"));
        }
        let path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
        let descriptors = self.descriptors.lock().unwrap();
        let generation = descriptors.iter().find(|(_, (p, _))| *p == path).unwrap().0;
        Ok(format!("tun-{generation}"))
    }
    fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
        self.feed.clone()
    }
    fn expectation(
        &self,
        config: &CaptureConfig,
        interface: String,
    ) -> io::Result<CaptureExpectation> {
        if *self.fault.lock().unwrap() == Some("expectation") {
            return Err(io::Error::other("requested projection failed"));
        }
        let config = config
            .secured_config()
            .expect("Partial never queries managed fields");
        let routes = config
            .routes
            .iter()
            .map(|route| CapturePrefix {
                address: route.network(),
                prefix_length: i16::from(route.prefix()),
            })
            .collect::<Vec<_>>();
        let generation = interface.strip_prefix("tun-").unwrap().parse().unwrap();
        let expected = CaptureExpectation::requested(
            interface,
            1000,
            33,
            &config.addresses,
            &routes,
            config.dns_servers.as_deref().unwrap_or(&[]),
            config.mtu,
        )
        .unwrap();
        self.expected
            .lock()
            .unwrap()
            .insert(generation, expected.clone());
        Ok(expected)
    }
    fn bind(&self, generation: i64, interface: &str) -> io::Result<bool> {
        match *self.fault.lock().unwrap() {
            Some("bind") => return Err(io::Error::other("bind failed")),
            Some("observe") => return Ok(true),
            _ => {}
        }
        // Read the exact expectation already bound to the feed, using the same
        // immutable requested projection retained by this fake platform.
        let mut expected = self.expected.lock().unwrap();
        expected
            .get_mut(&generation)
            .expect("projection staged before bind")
            .interface_name = interface.into();
        drop(expected);
        Ok(self.publish(generation, false))
    }
    fn closed(&self, generation: i64) -> io::Result<()> {
        self.finish_attempts.fetch_add(1, SeqCst);
        if let Some((path, old)) = self.descriptors.lock().unwrap().get(&generation) {
            assert_ne!(
                std::fs::read_link(path).ok(),
                Some(old.clone()),
                "epoch release preceded fd close"
            );
        }
        let fail = self.fail_release.load(SeqCst) == generation;
        if let Some(pause) = self.close_pause.lock().unwrap().take() {
            pause.enter();
        }
        if fail {
            return Err(io::Error::other("retained unregister"));
        }
        self.descriptors.lock().unwrap().remove(&generation);
        self.released.lock().unwrap().push(generation);
        self.changed.notify_waiters();
        Ok(())
    }
}

#[tokio::test]
async fn explicit_release_retry_joins_outstanding_predecessor_cleanup() {
    for fail_retry in [false, true] {
        let (platform, mut peers) = EpochPlatform::new();
        let (_updates, updates) = watch::channel(0);
        let broker = managed::broker();
        let mut owner = FrontendOwner::start(
            platform.clone(),
            CaptureConfig::Partial(routes().into()),
            test_forwarder(Arc::new(Authority::default())),
            updates,
            broker,
        )
        .unwrap();
        bounded(owner.ready()).await.unwrap();
        let old_peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
        let generation = *platform.descriptors.lock().unwrap().keys().next().unwrap();
        let pause = Arc::new(Pause::default());
        let _release = Release(pause.clone());
        platform.fail_release.store(generation, SeqCst);
        *platform.close_pause.lock().unwrap() = Some(pause.clone());
        owner
            .handover(CaptureConfig::Partial(
                vec!["127.0.0.0/8".into(), "10.0.0.0/8".into()].into(),
            ))
            .unwrap();
        bounded(owner.ready()).await.unwrap();
        let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
        bounded(pause.entered.notified()).await;
        owner.retry_handover_release().unwrap();
        // A free command slot proves the actor consumed RetryRelease while the old
        // blocking finish was still held, without a scheduler sleep or test hook.
        drop(bounded(owner.commands.reserve()).await.unwrap());
        if !fail_retry {
            platform.fail_release.store(0, SeqCst);
        }
        pause.unblock();
        let retried = bounded(owner.ready()).await;
        assert_eq!(
            platform.finish_attempts.load(SeqCst),
            2,
            "explicit retry did not join and retry the exact predecessor"
        );
        if fail_retry {
            assert!(retried.is_err());
            assert!(owner.release_failed());
            platform.fail_release.store(0, SeqCst);
            owner.retry_handover_release().unwrap();
            bounded(owner.ready()).await.unwrap();
        } else {
            retried.unwrap();
        }
        platform.finished(generation).await;
        assert!(!owner.release_failed());
        assert!(bounded(receive(&old_peer)).await.is_empty());
        let (address, mut hits, echo) = udp_echo(false).await;
        send(
            &peer,
            &udp(flow(address, Transport::Udp, 49009), b"current"),
        )
        .await;
        assert_eq!(
            packet::parse(&bounded(receive(&peer)).await)
                .unwrap()
                .payload,
            b"current"
        );
        assert_eq!(bounded(hits.recv()).await.unwrap(), b"current");
        bounded(owner.stop()).await.unwrap();
        assert!(bounded(receive(&peer)).await.is_empty());
        echo.abort();
        assert_eq!(platform.released.lock().unwrap().len(), 2);
        assert_eq!(
            platform.finish_attempts.load(SeqCst),
            if fail_retry { 4 } else { 3 }
        );
    }
}

fn fixed_config(dns: &str) -> TunConfig {
    let mut config = blocking_config();
    config.addresses = vec!["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()];
    config.mtu = 1280;
    config.dns_servers = Some(vec![dns.parse().unwrap()]);
    config
}
fn secured(broker: &AttachmentBroker, config: TunConfig) -> (ConfigurationRequest, CaptureConfig) {
    let request = broker.request_capture(config).unwrap();
    (
        request,
        CaptureConfig::Secured {
            broker: broker.clone(),
            request: broker.pending_request().unwrap(),
            disposition: Arc::new(|ip| {
                if ip.is_loopback() {
                    CaptureDisposition::Local
                } else {
                    CaptureDisposition::Drop(CaptureDropReason::NoTarget)
                }
            }),
        },
    )
}

#[tokio::test]
async fn observed_router_epoch_lends_equal_projection_to_rotating_targets_without_reopen() {
    let (platform, mut peers) = EpochPlatform::new();
    let broker = managed::broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let config = fixed_config("10.64.0.1");
    let disposition = Arc::new(|ip: std::net::IpAddr| {
        if ip.is_loopback() {
            CaptureDisposition::Local
        } else {
            CaptureDisposition::Tunnel(talpid_types::relay_flow::RelayTargetId::MULLVAD)
        }
    });
    let (_, updates) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        CaptureConfig::Router {
            config: config.clone(),
            disposition: disposition.clone(),
        },
        test_forwarder(Arc::new(Authority::default())),
        updates,
        broker.clone(),
    )
    .unwrap();
    let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let generation = broker.snapshot().capture_generation;
    let session = broker.snapshot().session_generation;
    let (address, mut hits, echo) = udp_echo(false).await;
    let local = flow(address, Transport::Udp, 49190);
    for assigned in ["10.64.2.3", "10.64.9.8"] {
        let mut target = blocking_config();
        target.addresses = vec![assigned.parse().unwrap()];
        let mut request = broker
            .request_target_capture(target, config.clone())
            .unwrap();
        owner
            .handover(CaptureConfig::Secured {
                broker: broker.clone(),
                request: broker.pending_request().unwrap(),
                disposition: disposition.clone(),
            })
            .unwrap();
        bounded(owner.ready()).await.unwrap();
        let receipt = bounded(request.configured()).await.unwrap();
        assert_eq!(Some(receipt.generation()), generation);
        let mut pair = broker.acquire(&receipt).unwrap();
        pair.control.activate().unwrap();
        let public = flow("1.1.1.1:443".parse().unwrap(), Transport::Udp, 49191);
        let bytes = udp(public, assigned.as_bytes());
        send(&peer, &bytes).await;
        bounded(pair.receive.recv())
            .await
            .unwrap()
            .handoff(|actual| assert_eq!(actual, bytes))
            .unwrap();
        send(&peer, &udp(local, assigned.as_bytes())).await;
        assert_eq!(bounded(hits.recv()).await.unwrap(), assigned.as_bytes());
        assert_eq!(
            packet::parse(&bounded(receive(&peer)).await)
                .unwrap()
                .payload,
            assigned.as_bytes()
        );
        pair.control.detach();
        drop(pair);
        request.transport_joined();
        drop(request);
        assert_eq!(broker.snapshot().session_generation, session);
        assert_eq!(platform.format_calls.load(SeqCst), 1);
        assert!(
            peers.try_recv().is_err(),
            "equal projection called Builder.establish"
        );
    }
    bounded(owner.stop()).await.unwrap();
    echo.abort();
    assert_eq!(platform.released.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_local_tcp_and_udp_engine_crosses_partial_blocking_secured_partial_fd_epochs() {
    let (platform, mut peers) = EpochPlatform::new();
    let broker = managed::broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let authority = Arc::new(Authority::default());
    let (_updates, updates) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        CaptureConfig::Partial(routes().into()),
        test_forwarder(authority.clone()),
        updates,
        broker.clone(),
    )
    .unwrap();
    let mut peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let mut state = owner.state();
    let session = broker.snapshot().session_generation.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = listener.local_addr().unwrap();
    let (accepted, mut accepts) = mpsc::unbounded_channel();
    let (push, mut pushes) = mpsc::channel::<(Vec<u8>, oneshot::Sender<()>)>(1);
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        accepted.send(()).unwrap();
        let mut bytes = [0; 4096];
        loop {
            tokio::select! {
                count = socket.read(&mut bytes) => {
                    let count = count.unwrap();
                    if count == 0 { return; }
                    socket.write_all(&bytes[..count]).await.unwrap();
                },
                message = pushes.recv() => {
                    let Some((bytes, written)) = message else { return; };
                    socket.write_all(&bytes).await.unwrap();
                    written.send(()).unwrap();
                },
            }
        }
    });
    let (address, mut hits, echo) = udp_echo(false).await;
    let mut app = App::new(flow(tcp, Transport::Tcp, 49000));
    app.nonce(&peer, b"same-stream-before").await;
    bounded(accepts.recv()).await.unwrap();
    let local = flow(address, Transport::Udp, 49001);
    let mut requests = Vec::new();
    for stage in 0..3 {
        let old = broker.snapshot().capture_generation.unwrap() as i64;
        let config = if stage < 2 {
            let (request, config) = secured(
                &broker,
                fixed_config(if stage == 0 { "192.0.2.1" } else { "10.64.0.1" }),
            );
            requests.push(request);
            config
        } else {
            CaptureConfig::Partial(routes().into())
        };
        let pause = Arc::new(Pause::default());
        let _release = Release(pause.clone());
        *platform.pause.lock().unwrap() = Some(pause.clone());
        owner.handover(config.clone()).unwrap();
        bounded(pause.entered.notified()).await;
        let next_peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
        drop(std::mem::replace(&mut peer, next_peer)); // actual old EOF during establish
        assert_eq!(broker.snapshot().session_generation, Some(session));
        assert!(!broker.snapshot().capture_ready);
        assert_eq!(*owner.state().borrow(), FrontendState::Running);
        assert!(!platform.released.lock().unwrap().contains(&old));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), owner.ready())
                .await
                .is_err()
        );
        let during = format!("physical-reply-during-establish-{stage}");
        let (written, received) = oneshot::channel();
        push.send((during.as_bytes().to_vec(), written))
            .await
            .unwrap();
        bounded(received).await.unwrap();
        pause.unblock();
        bounded(owner.ready()).await.unwrap();
        platform.finished(old).await;
        bounded(state.changed()).await.unwrap();
        assert_eq!(broker.snapshot().session_generation, Some(session));
        assert!(broker.snapshot().capture_ready);
        let mut pushed = Vec::new();
        app.until(&peer, |app| {
            while app.socket().can_recv() {
                app.socket()
                    .recv(|bytes| {
                        pushed.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            pushed.len() >= during.len()
        })
        .await;
        assert_eq!(
            pushed,
            during.as_bytes(),
            "in-flight Local reply was lost or replayed"
        );
        let nonce = format!("same-stream-epoch-{stage}");
        app.nonce(&peer, nonce.as_bytes()).await;
        send(&peer, &udp(local, nonce.as_bytes())).await;
        assert_eq!(bounded(hits.recv()).await.unwrap(), nonce.as_bytes());
        assert_eq!(
            packet::parse(&bounded(receive(&peer)).await)
                .unwrap()
                .payload,
            nonce.as_bytes()
        );
        assert!(
            accepts.try_recv().is_err(),
            "handover reopened the physical TCP connection"
        );
        assert_eq!(authority.prepares.load(SeqCst), 2);
    }
    assert_eq!(platform.format_calls.load(SeqCst), 4);
    owner.stop().await.unwrap();
    assert_eq!(platform.released.lock().unwrap().len(), 4);
    assert!(broker.snapshot().session_generation.is_none());
    server.abort();
    echo.abort();
}

#[tokio::test]
async fn pre_establish_failure_restores_only_the_live_predecessor_without_reopening_local() {
    let (platform, mut peers) = EpochPlatform::new();
    let broker = managed::broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let (mut old_request, config) = secured(&broker, fixed_config("192.0.2.1"));
    let (_updates, updates) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        config,
        test_forwarder(Arc::new(Authority::default())),
        updates,
        broker.clone(),
    )
    .unwrap();
    let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = old_request.configured().await.unwrap();
    let session = broker.snapshot().session_generation;
    let (tcp, mut accepts, server) = tcp_echo(false).await;
    let mut app = App::new(flow(tcp, Transport::Tcp, 49100));
    app.nonce(&peer, b"before-pre-establish-failure").await;
    bounded(accepts.recv()).await.unwrap();
    let (request, config) = secured(&broker, fixed_config("10.64.0.1"));
    platform.fail_before.store(true, SeqCst);
    owner.handover(config).unwrap();
    assert!(bounded(owner.ready()).await.is_err());
    assert!(receipt.current());
    assert_eq!(broker.snapshot().session_generation, session);
    assert_eq!(
        broker.snapshot().capture_generation,
        Some(receipt.generation())
    );
    assert_eq!(*owner.state().borrow(), FrontendState::Running);
    app.nonce(&peer, b"after-proven-rollback").await;
    assert!(accepts.try_recv().is_err());
    assert!(
        peers.try_recv().is_err(),
        "pre-establish failure opened a successor"
    );
    assert_eq!(platform.format_calls.load(SeqCst), 1);
    assert_eq!(
        platform.released.lock().unwrap().len(),
        1,
        "lost successor obligation was not finished"
    );
    request.cancel();
    owner.stop().await.unwrap();
    assert_eq!(platform.released.lock().unwrap().len(), 2);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_joins_inflight_establish_and_post_switch_failure_never_rolls_back() {
    for cancel in [false, true] {
        let (platform, mut peers) = EpochPlatform::new();
        let broker = managed::broker();
        broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
        let (mut old_request, config) = secured(&broker, fixed_config("192.0.2.1"));
        let (_updates, updates) = watch::channel(0);
        let mut owner = FrontendOwner::start(
            platform.clone(),
            config,
            test_forwarder(Arc::new(Authority::default())),
            updates,
            broker.clone(),
        )
        .unwrap();
        let peer = bounded(peers.recv()).await.unwrap();
        bounded(owner.ready()).await.unwrap();
        let receipt = old_request.configured().await.unwrap();
        let (_request, config) = secured(&broker, fixed_config("10.64.0.1"));
        let pause = Arc::new(Pause::default());
        let _release = Release(pause.clone());
        *platform.pause.lock().unwrap() = Some(pause.clone());
        platform.fail_after.store(!cancel, SeqCst);
        owner.handover(config).unwrap();
        bounded(pause.entered.notified()).await;
        let successor = bounded(peers.recv()).await.unwrap();
        drop(peer);
        assert!(!receipt.current());
        assert!(broker.snapshot().session_generation.is_some());
        assert!(platform.released.lock().unwrap().is_empty());
        if cancel {
            assert!(
                tokio::time::timeout(Duration::from_millis(50), owner.stop())
                    .await
                    .is_err()
            );
            assert!(platform.released.lock().unwrap().is_empty());
        }
        pause.unblock();
        if !cancel {
            assert!(bounded(owner.ready()).await.is_err());
        }
        bounded(owner.stop()).await.unwrap();
        assert!(broker.snapshot().session_generation.is_none());
        assert!(
            !receipt.current(),
            "post-switch failure fabricated old authority"
        );
        assert_eq!(platform.released.lock().unwrap().len(), 2);
        drop(successor);
    }
}

#[tokio::test]
async fn predecessor_transport_join_and_failed_finish_block_third_epoch_but_not_local() {
    let (platform, mut peers) = EpochPlatform::new();
    let broker = managed::broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let (mut old_request, config) = secured(&broker, fixed_config("192.0.2.1"));
    let old_pending = broker.pending_request().unwrap();
    let (_updates, updates) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        config,
        test_forwarder(Arc::new(Authority::default())),
        updates,
        broker.clone(),
    )
    .unwrap();
    let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = old_request.configured().await.unwrap();
    let transport = broker.acquire(&receipt).unwrap();
    transport.control.activate().unwrap();
    let old = receipt.generation() as i64;
    let session = broker.snapshot().session_generation;
    let (tcp, mut accepts, server) = tcp_echo(false).await;
    let mut app = App::new(flow(tcp, Transport::Tcp, 49200));
    app.nonce(&peer, b"before-delayed-target-join").await;
    bounded(accepts.recv()).await.unwrap();
    old_pending.defer_release();
    let (_request, config) = secured(&broker, fixed_config("10.64.0.1"));
    platform.fail_release.store(old, SeqCst);
    owner.handover(config).unwrap();
    let next_peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    assert_eq!(broker.snapshot().session_generation, session);
    let (old_path, old_descriptor) = platform
        .descriptors
        .lock()
        .unwrap()
        .get(&old)
        .cloned()
        .unwrap();
    assert_eq!(
        std::fs::read_link(&old_path).unwrap(),
        old_descriptor,
        "predecessor fd closed before target join"
    );
    app.nonce(&next_peer, b"during-delayed-target-join").await;
    assert!(
        transport.control.current(),
        "descriptor handover retired the independent target"
    );
    let target_return = packet::udp_reply(
        flow("1.1.1.1:443".parse().unwrap(), Transport::Udp, 49201),
        b"same-target-new-sink",
    )
    .unwrap();
    transport.send.try_send(&target_return).unwrap();
    assert_eq!(bounded(receive(&next_peer)).await, target_return);
    assert_eq!(
        std::fs::read_link(&old_path).unwrap(),
        old_descriptor,
        "predecessor fd closed while target remains live"
    );
    assert!(platform.released.lock().unwrap().is_empty());
    owner
        .handover(CaptureConfig::Partial(routes().into()))
        .unwrap();
    assert_eq!(
        bounded(owner.ready()).await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(peers.try_recv().is_err());
    transport.control.detach();
    old_request.transport_joined();
    assert_eq!(
        std::fs::read_link(&old_path).unwrap(),
        old_descriptor,
        "device join bypassed the explicit TSM obligation"
    );
    old_pending.handover_joined();
    bounded(async {
        let mut state = owner.state();
        while !owner.release_failed() {
            state.changed().await.unwrap();
        }
    })
    .await;
    assert!(owner.release_failed());
    app.nonce(&next_peer, b"after-failed-old-finish").await;
    owner
        .handover(CaptureConfig::Partial(routes().into()))
        .unwrap();
    assert_eq!(
        bounded(owner.ready()).await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    platform.fail_release.store(0, SeqCst);
    owner.retry_handover_release().unwrap();
    bounded(owner.ready()).await.unwrap();
    assert!(!owner.release_failed());
    platform.finished(old).await;
    owner
        .handover(CaptureConfig::Partial(routes().into()))
        .unwrap();
    let final_peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    app.nonce(&final_peer, b"after-exact-release-retry").await;
    assert!(accepts.try_recv().is_err());
    bounded(owner.stop()).await.unwrap();
    assert_eq!(platform.released.lock().unwrap().len(), 3);
    server.abort();
}

#[tokio::test]
async fn invalid_handover_requests_leave_the_same_local_stream_and_epoch_untouched() {
    let (platform, mut peers) = EpochPlatform::new();
    let broker = managed::broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let (_updates, updates) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        CaptureConfig::Partial(routes().into()),
        test_forwarder(Arc::new(Authority::default())),
        updates,
        broker.clone(),
    )
    .unwrap();
    let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let snapshot = broker.snapshot();
    let (tcp, mut accepts, server) = tcp_echo(false).await;
    let mut app = App::new(flow(tcp, Transport::Tcp, 49300));
    app.nonce(&peer, b"before-invalid-configs").await;
    bounded(accepts.recv()).await.unwrap();
    for fault in ["foreign-broker", "sources", "mtu", "cancelled-request"] {
        let selected = if fault == "foreign-broker" {
            let selected = managed::broker();
            selected.set_mode(AttachmentMode::ManagedRequired).unwrap();
            selected
        } else {
            broker.clone()
        };
        let mut config = fixed_config("10.64.0.1");
        if fault == "sources" {
            config.addresses[0] = "10.64.0.2".parse().unwrap();
        }
        if fault == "mtu" {
            config.mtu = 1420;
        }
        let (request, config) = secured(&selected, config);
        if fault == "cancelled-request" {
            request.cancel();
        }
        owner.handover(config).unwrap();
        assert!(bounded(owner.ready()).await.is_err(), "{fault}");
        assert_eq!(
            broker.snapshot().session_generation,
            snapshot.session_generation
        );
        assert_eq!(
            broker.snapshot().capture_generation,
            snapshot.capture_generation
        );
        assert!(broker.snapshot().capture_ready);
        assert_eq!(*owner.state().borrow(), FrontendState::Running);
        assert_eq!(platform.format_calls.load(SeqCst), 1);
        assert!(peers.try_recv().is_err());
        app.nonce(&peer, fault.as_bytes()).await;
        assert!(accepts.try_recv().is_err());
    }
    bounded(owner.stop()).await.unwrap();
    assert_eq!(platform.released.lock().unwrap().len(), 1);
    server.abort();
}

#[tokio::test]
async fn post_switch_bind_format_and_observation_faults_never_restore_the_old_epoch() {
    for fault in ["format", "interface", "expectation", "bind", "observe"] {
        let (platform, mut peers) = EpochPlatform::new();
        let broker = managed::broker();
        broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
        let (_updates, updates) = watch::channel(0);
        let mut owner = FrontendOwner::start(
            platform.clone(),
            CaptureConfig::Partial(routes().into()),
            test_forwarder(Arc::new(Authority::default())),
            updates,
            broker.clone(),
        )
        .unwrap();
        let peer = bounded(peers.recv()).await.unwrap();
        bounded(owner.ready()).await.unwrap();
        *platform.fault.lock().unwrap() = Some(fault);
        let (_request, config) = secured(&broker, fixed_config("10.64.0.1"));
        owner.handover(config).unwrap();
        if fault == "observe" {
            assert!(
                tokio::time::timeout(Duration::from_millis(30), owner.ready())
                    .await
                    .is_err()
            );
            platform.feed.close();
        }
        assert!(bounded(owner.ready()).await.is_err(), "{fault}");
        bounded(owner.stop()).await.unwrap();
        assert!(!broker.snapshot().capture_ready);
        assert!(broker.snapshot().session_generation.is_none());
        assert!(platform.descriptors.lock().unwrap().is_empty());
        assert_eq!(platform.released.lock().unwrap().len(), 2);
        drop(peer);
    }
}

#[tokio::test]
async fn successor_readiness_requires_its_exact_observation_after_reordered_mismatches() {
    for fault in [
        "generation",
        "interface",
        "routes",
        "source",
        "dns",
        "mtu",
        "owner",
        "api",
        "netid",
    ] {
        let (platform, mut peers) = EpochPlatform::new();
        let broker = managed::broker();
        broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
        let (_updates, updates) = watch::channel(0);
        let mut owner = FrontendOwner::start(
            platform.clone(),
            CaptureConfig::Partial(routes().into()),
            test_forwarder(Arc::new(Authority::default())),
            updates,
            broker.clone(),
        )
        .unwrap();
        let old_peer = bounded(peers.recv()).await.unwrap();
        bounded(owner.ready()).await.unwrap();
        let old = broker.snapshot().capture_generation.unwrap() as i64;
        *platform.fault.lock().unwrap() = Some("observe");
        let (mut request, config) = secured(&broker, fixed_config("10.64.0.1"));
        owner.handover(config).unwrap();
        let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), owner.ready())
                .await
                .is_err()
        );
        let generation = broker.snapshot().capture_generation.unwrap() as i64;
        let expected = platform.observed(generation).unwrap();
        let mut observed = expected.clone();
        match fault {
            "interface" => observed.interface_name = "another-tun".into(),
            "routes" => observed.routes.clear(),
            "generation" => {}
            "source" => observed.addresses[0].address = "10.64.0.2".parse().unwrap(),
            "dns" => observed.dns_servers.clear(),
            "mtu" => observed.mtu = Some(1420),
            "owner" => observed.owner_uid = Some(1001),
            "api" => observed.api_level = 32,
            "netid" => observed.network_handle = 0,
            _ => unreachable!(),
        }
        platform.feed.publish(
            117,
            if fault == "generation" {
                old
            } else {
                generation
            },
            observed,
        );
        if matches!(fault, "routes" | "source" | "dns" | "mtu") {
            // A mismatched current configuration is loss, not a pending receipt
            // which a later equal callback can resurrect.
            assert!(bounded(owner.ready()).await.is_err(), "{fault}");
            bounded(owner.stop()).await.unwrap();
            assert!(request.configured().await.is_err());
            assert!(!platform.publish(generation, false));
            assert!(!broker.snapshot().capture_ready);
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), owner.ready())
                    .await
                    .is_err(),
                "{fault} acknowledged readiness"
            );
            assert!(!broker.snapshot().capture_ready);
            assert!(platform.released.lock().unwrap().is_empty());
            assert!(platform.publish(generation, false));
            bounded(owner.ready()).await.unwrap();
            let receipt = bounded(request.configured()).await.unwrap();
            assert!(receipt.current());
            let mut another_netid = expected;
            another_netid.network_handle += 1;
            assert!(!platform.feed.publish(117, generation, another_netid));
            assert!(
                receipt.current(),
                "late different netId changed the pinned receipt"
            );
            let (udp_peer, mut hits, echo) = udp_echo(false).await;
            let local = flow(udp_peer, Transport::Udp, 49301);
            send(&peer, &udp(local, b"exact-successor-consumer")).await;
            bounded(hits.recv()).await.unwrap();
            assert_eq!(
                packet::parse(&bounded(receive(&peer)).await)
                    .unwrap()
                    .payload,
                b"exact-successor-consumer"
            );
            bounded(owner.stop()).await.unwrap();
            echo.abort();
        }
        assert_eq!(platform.released.lock().unwrap().len(), 2);
        drop(old_peer);
    }
}

#[tokio::test]
async fn actual_eagain_retains_mixed_local_and_target_output_across_handover_and_refunds_after_join()
 {
    use talpid_netstack::buffer_budget::BufferBudget;
    let application = BufferBudget::new(22 * 1024 * 1024);
    let capture_storage = BufferBudget::new(2 * 1024 * 1024);
    let control = BufferBudget::new(8 * 1024 * 1024);
    let broker = AttachmentBroker::new(
        Arc::new(application.clone()),
        Arc::new(capture_storage.clone()),
        Arc::new(control.clone()),
    )
    .unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let (platform, mut peers) = EpochPlatform::new();
    platform.fill.store(true, SeqCst);
    let (mut old_request, config) = secured(&broker, fixed_config("192.0.2.1"));
    let authority = Arc::new(Authority::default());
    let (_updates, updates) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        config,
        test_forwarder(authority.clone()),
        updates,
        broker.clone(),
    )
    .unwrap();
    let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = old_request.configured().await.unwrap();
    let transport = broker.acquire(&receipt).unwrap();
    transport.control.activate().unwrap();
    let (address, mut hits, echo) = udp_echo(false).await;
    let local = flow(address, Transport::Udp, 49302);
    for index in 0..12 {
        send(&peer, &udp(local, format!("local-{index}").as_bytes())).await;
        bounded(hits.recv()).await.unwrap();
    }
    for index in 0..12 {
        let packet = packet::udp_reply(
            flow("1.1.1.1:443".parse().unwrap(), Transport::Udp, 49303),
            format!("target-{index}").as_bytes(),
        )
        .unwrap();
        transport.send.try_send(&packet).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let retained = application.used();
    let checks = authority.checks.load(SeqCst);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        application.used(),
        retained,
        "blocked target bytes refunded early"
    );
    assert_eq!(
        authority.checks.load(SeqCst),
        checks,
        "blocked checked Local writer spun"
    );
    let (request, config) = secured(&broker, fixed_config("10.64.0.1"));
    owner.handover(config).unwrap();
    let next_peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    assert!(transport.control.current());
    assert!(platform.released.lock().unwrap().is_empty());
    let generation = broker.snapshot().capture_generation.unwrap() as i64;
    let filled = platform.filled.lock().unwrap()[&generation];
    for _ in 0..filled {
        assert_eq!(bounded(receive(&next_peer)).await, b"handover-sink-filler");
    }
    let mut local_nonces = std::collections::BTreeSet::new();
    let mut target_nonces = std::collections::BTreeSet::new();
    for index in 0..24 {
        let bytes = bounded(receive(&next_peer)).await;
        let payload = packet::parse(&bytes).unwrap().payload;
        let nonce = std::str::from_utf8(payload).unwrap().to_owned();
        if nonce.starts_with("local-") {
            assert!(local_nonces.insert(nonce));
        } else {
            assert!(nonce.starts_with("target-"));
            assert!(target_nonces.insert(nonce));
        }
        if index == 3 {
            assert!(
                !local_nonces.is_empty() && !target_nonces.is_empty(),
                "one output class monopolized the replacement sink"
            );
        }
    }
    assert_eq!(local_nonces.len(), 12);
    assert_eq!(target_nonces.len(), 12);
    transport.control.detach();
    old_request.transport_joined();
    bounded(owner.stop()).await.unwrap();
    assert_eq!(platform.released.lock().unwrap().len(), 2);
    assert!(broker.snapshot().session_generation.is_none());
    drop((owner, transport, old_request, request, broker));
    assert_eq!(application.used(), 0);
    assert_eq!(capture_storage.used(), 0);
    assert_eq!(control.used(), 0);
    echo.abort();
}

#[tokio::test]
async fn delayed_successor_observation_cannot_delay_physical_grant_revocation() {
    let (platform, mut peers) = EpochPlatform::new();
    let broker = managed::broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let authority = Arc::new(Authority::default());
    let (updates, receiver) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        CaptureConfig::Partial(routes().into()),
        test_forwarder(authority.clone()),
        receiver,
        broker.clone(),
    )
    .unwrap();
    let peer = AsyncFd::new(bounded(peers.recv()).await.unwrap()).unwrap();
    bounded(owner.ready()).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (closed, closure) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 256];
        loop {
            let count = stream.read(&mut bytes).await.unwrap();
            if count == 0 {
                closed.send(()).unwrap();
                return;
            }
            stream.write_all(&bytes[..count]).await.unwrap();
        }
    });
    let mut app = App::new(flow(address, Transport::Tcp, 49304));
    app.nonce(&peer, b"before-delayed-observation").await;
    *platform.fault.lock().unwrap() = Some("observe");
    let (_request, config) = secured(&broker, fixed_config("10.64.0.1"));
    owner.handover(config).unwrap();
    let successor = bounded(peers.recv()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), owner.ready())
            .await
            .is_err()
    );
    authority.available.store(false, SeqCst);
    updates.send_modify(|revision| *revision += 1);
    bounded(closure)
        .await
        .expect("physical socket stayed open behind pending observation");
    assert!(!broker.snapshot().capture_ready);
    bounded(owner.stop()).await.unwrap();
    bounded(server).await.unwrap();
    assert_eq!(platform.released.lock().unwrap().len(), 2);
    drop(successor);
}
