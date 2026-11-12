//! Scheduling gates wrap the existing adapter/crypto peer only in this fixture.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use talpid_netstack::{
    address_translation::{Direction, TranslationOutcome},
    packet_sizing::FeedbackSide,
};
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation, RelayFlowError};

struct Gate {
    enabled: AtomicBool,
    held: AtomicUsize,
    changed: tokio::sync::Notify,
    permits: tokio::sync::Semaphore,
}
impl Default for Gate {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            held: AtomicUsize::new(0),
            changed: tokio::sync::Notify::new(),
            permits: tokio::sync::Semaphore::new(0),
        }
    }
}
impl Gate {
    async fn held_after(&self, previous: usize) -> usize {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let wake = self.changed.notified();
                let count = self.held.load(Ordering::Acquire);
                if count > previous {
                    return count;
                }
                wake.await;
            }
        })
        .await
        .expect("adapter did not reach the held handoff")
    }
}
struct GatedReceive {
    receive: ManagedReceive,
    gate: Arc<Gate>,
}
impl IpRecv for GatedReceive {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .receive
            .recv(pool)
            .await?
            .next()
            .ok_or_else(unavailable)?;
        if self.gate.enabled.load(Ordering::Acquire) {
            self.gate.held.fetch_add(1, Ordering::Release);
            self.gate.changed.notify_one();
            self.gate
                .permits
                .acquire()
                .await
                .map_err(|_| unavailable())?
                .forget();
        }
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        self.receive.mtu()
    }
}
struct GatedTunnel {
    device: Device<(TransportFactory, ManagedSend, SourceFilter<GatedReceive>)>,
    owner: Arc<ManagedControl>,
    gate: Arc<Gate>,
}
#[async_trait::async_trait]
impl Tunnel for GatedTunnel {
    fn get_interface_name(&self) -> String {
        self.owner.interface()
    }
    fn stop(self: Box<Self>) -> Result<(), TunnelError> {
        panic!("fixture uses joined shutdown")
    }
    async fn get_tunnel_stats(&self) -> Result<crate::stats::StatsMap, TunnelError> {
        Ok(self
            .device
            .read(async |device| device.peers().await)
            .await
            .into_iter()
            .map(|peer| {
                (
                    peer.peer.public_key.to_bytes(),
                    crate::stats::Stats::from(peer.stats),
                )
            })
            .collect())
    }
}
impl GatedTunnel {
    async fn new(mut pending: PendingManaged, config: &Config) -> Self {
        let pair = pending.create(config).await.unwrap();
        let gate = Arc::new(Gate {
            permits: tokio::sync::Semaphore::new(0),
            ..Gate::default()
        });
        let device = DeviceBuilder::new()
            .with_udp(transport_factory(
                true,
                None,
                config.entry_peer.endpoint,
                Arc::new(NoopBypass),
            ))
            .with_private_key(StaticSecret::from(config.tunnel.private_key.to_bytes()))
            .with_peer(to_gotatun_peer(&config.entry_peer, None))
            .with_ip_pair(
                pair.send,
                SourceFilter::new(
                    GatedReceive {
                        receive: pair.receive,
                        gate: gate.clone(),
                    },
                    config.tunnel_ipv4(),
                    config.tunnel_ipv6(),
                ),
            )
            .build()
            .await
            .unwrap();
        pair.owner.installed();
        Self {
            device,
            owner: pair.owner,
            gate,
        }
    }
    async fn check(&self) -> Check {
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(self.owner.pinger().unwrap(), 0, receiver);
        crate::establish_and_activate(
            &mut check,
            self,
            Some(&self.owner),
            async { Ok(()) },
            |()| (),
        )
        .await
        .unwrap();
        private_done(&self.owner, 0).await;
        check
    }
    async fn shutdown(self) {
        self.owner.revoke();
        self.gate.permits.close();
        self.device.stop().await;
        self.owner.stop().await;
    }
}
async fn private_done(owner: &ManagedControl, previous: u64) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            {
                let ledger = owner.ledger.lock().unwrap();
                if ledger.highest > previous && ledger.live.is_empty() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("private authenticated consumer was starved");
}
fn oversize(config: &Config, inbound: bool, nonce: u8) -> Vec<u8> {
    let mut packet = packet(config, false, 17, &vec![nonce; 1600], inbound, false);
    if inbound {
        packet = application_reply(&packet);
    }
    packet[6] = 0x40;
    fix_wire(&mut packet, 20, 17);
    packet
}
fn available(allocator: &dyn RelayBufferAllocator) -> usize {
    let (mut low, mut high) = (0usize, 22 * 1024 * 1024usize);
    while low < high {
        let n = low + (high - low).div_ceil(2);
        if allocator.try_reserve(n).is_ok() {
            low = n;
        } else {
            high = n - 1;
        }
    }
    low
}
async fn held_feedback(owner: &ManagedControl) -> talpid_netstack::packet_sizing::Feedback {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(feedback) = owner
                .path
                .lock()
                .unwrap()
                .take_feedback_for(FeedbackSide::Target)
            {
                return feedback;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("authenticated input did not generate target feedback")
}
async fn inject(input: &mpsc::Sender<Packet<Ip>>, bytes: &[u8]) {
    input
        .send(Packet::<[u8]>::copy_from(bytes).try_into_ip().unwrap())
        .await
        .unwrap();
}
#[cfg(unix)]
fn local_progress(session: &talpid_types::relay_flow::RelayCapture) {
    let sink = session.sink().unwrap();
    let (fd, consumer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    session
        .with_sink(&sink, || fd.send(b"independent-local"))
        .unwrap()
        .unwrap();
    consumer
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = [0; 32];
    let count = consumer.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"independent-local");
}

struct RefusableApplication {
    inner: BufferBudget,
    exhausted: Arc<AtomicBool>,
}
impl RelayBufferAllocator for RefusableApplication {
    fn try_reserve(&self, bytes: usize) -> Result<Arc<dyn RelayBufferReservation>, RelayFlowError> {
        if self.exhausted.load(Ordering::Acquire) {
            return Err(RelayFlowError::Full);
        }
        self.inner.try_reserve(bytes)
    }
}
fn refusable_broker() -> (AttachmentBroker, BufferBudget, Arc<AtomicBool>) {
    let root = BufferBudget::new(64 * 1024 * 1024);
    let application = root.reserve(22 * 1024 * 1024).unwrap().region().unwrap();
    let control = root.reserve(8 * 1024 * 1024).unwrap().region().unwrap();
    let capture = root.reserve(2 * 1024 * 1024).unwrap().region().unwrap();
    let exhausted = Arc::new(AtomicBool::new(false));
    let broker = AttachmentBroker::new(
        Arc::new(RefusableApplication {
            inner: application,
            exhausted: exhausted.clone(),
        }),
        Arc::new(capture),
        Arc::new(control.clone()),
    )
    .unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    (broker, control, exhausted)
}

#[cfg(unix)]
#[tokio::test]
async fn feedback_and_fresh_private_probes_progress_with_continuously_ready_ordinary_emission() {
    let (broker, _root, credit) = broker();
    let mut config = config();
    let (remote, mut observations, input) = remote_controlled(&mut config, false).await;
    let source = projected(&broker, &config);
    let capture = bind(&broker);
    let client = GatedTunnel::new(source, &config).await;
    let mut check = client.check().await;
    client.gate.enabled.store(true, Ordering::Release);
    // One datagram leaves more than 40 ordinary fragments continuously ready.
    capture
        .try_send(&packet(
            &config,
            false,
            17,
            &vec![0x81; 60000],
            false,
            false,
        ))
        .unwrap();
    let mut held = client.gate.held_after(0).await;
    inject(&input, &oversize(&config, true, 0x82)).await;
    // Hold a real generated object, then put it back by generating a second
    // packet: the first remains charged and the second competes at the merge.
    let first = held_feedback(&client.owner).await;
    inject(&input, &oversize(&config, true, 0x83)).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if client.owner.path.lock().unwrap().deadline().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let previous = client.owner.ledger.lock().unwrap().highest;
    assert!(check.establish_connectivity(&client).await.unwrap());
    let mut ordinary = 0;
    let mut feedback = 0;
    for _ in 0..8 {
        client.gate.permits.add_permits(1);
        held = client.gate.held_after(held).await;
        while let Ok(bytes) = observations.try_recv() {
            if bytes[9] == 1 {
                feedback += 1;
                assert_eq!(
                    &bytes[28..],
                    &oversize(&config, true, 0x83)[..bytes.len() - 28]
                );
            } else {
                ordinary += 1;
            }
        }
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while ordinary + feedback < 7 {
            let bytes = observed(&mut observations).await;
            if bytes[9] == 1 {
                feedback += 1;
            } else {
                ordinary += 1;
            }
        }
    })
    .await
    .unwrap();
    assert!(
        feedback > 0,
        "feedback was placed permanently behind ready ordinary fragments"
    );
    assert!(ordinary > 0);
    private_done(&client.owner, previous).await;
    local_progress(&capture.capability().unwrap());
    drop(first);
    client.shutdown().await;
    drop(check);
    assert_eq!(credit.used(), 0);
    remote.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn feedback_reserved_credit_blocked_writes_full_limit_and_retirement_reach_real_consumers() {
    let (broker, credit, exhausted) = refusable_broker();
    let application = broker.application_buffers();
    let baseline = available(application.as_ref());
    let mut config = config();
    let (remote, mut observations, input) = remote_controlled(&mut config, false).await;
    let source = projected(&broker, &config);
    let capture = bind(&broker);
    let session = capture.capability().unwrap();
    let client = GatedTunnel::new(source, &config).await;
    let mut check = client.check().await;
    client.gate.enabled.store(true, Ordering::Release);
    capture
        .try_send(&packet(
            &config,
            false,
            17,
            &vec![0x91; 60000],
            false,
            false,
        ))
        .unwrap();
    let held = client.gate.held_after(0).await;
    // Both directions retain original sender-side quotes while ordinary credit
    // is unavailable. The outgoing queue item is charged before exhaustion.
    let app = oversize(&config, false, 0x92);
    capture.try_send(&app).unwrap();
    let exhaustion = application
        .try_reserve(available(application.as_ref()))
        .unwrap();
    assert_eq!(available(application.as_ref()), 0);
    // Keep allocation refusal stable as discarded ordinary buffers refund their
    // tickets; the already-precharged feedback child remains independently usable.
    exhausted.store(true, Ordering::Release);
    inject(&input, &oversize(&config, true, 0x93)).await;
    let target_feedback = held_feedback(&client.owner).await;
    let feedback_allocator = target_feedback.buffers();
    inject(&input, &oversize(&config, true, 0x94)).await;
    let previous = client.owner.ledger.lock().unwrap().highest;
    assert!(check.establish_connectivity(&client).await.unwrap());
    client.gate.permits.add_permits(16);
    client.gate.held_after(held).await;
    let mut app_feedback = tokio::time::timeout(Duration::from_secs(2), capture.reply())
        .await
        .expect("app feedback used exhausted ordinary credit")
        .unwrap();
    let before = available(feedback_allocator.as_ref());
    let mut saved = None;
    assert!(matches!(
        app_feedback.write(|bytes| {
            saved = Some(bytes.to_vec());
            Err(io::ErrorKind::WouldBlock.into())
        }),
        RelayWriteOutcome::Retry
    ));
    assert_eq!(
        available(feedback_allocator.as_ref()),
        before,
        "WouldBlock released feedback charge"
    );
    let app_bytes = saved.unwrap();
    assert_eq!(&app_bytes[28..], &app[..app_bytes.len() - 28]);
    assert!(matches!(
        app_feedback.write(|bytes| {
            assert_eq!(bytes, app_bytes);
            Err(io::ErrorKind::WouldBlock.into())
        }),
        RelayWriteOutcome::Retry
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let bytes = observed(&mut observations).await;
            if bytes[9] == 1 {
                assert_eq!(
                    &bytes[28..],
                    &oversize(&config, true, 0x94)[..bytes.len() - 28]
                );
                break;
            }
        }
    })
    .await
    .expect("target feedback used exhausted ordinary credit");
    private_done(&client.owner, previous).await;
    local_progress(&session);
    // Keep 16 actual feedback objects live, including the blocked writer and
    // retained target producer. A lost slot on WouldBlock admits an illegal 17th.
    let now = Instant::now() + Duration::from_secs(4);
    for _ in 0..8 {
        let result =
            client
                .owner
                .path
                .lock()
                .unwrap()
                .process(&app, Direction::Outbound, 1280, now);
        assert!(matches!(
            result,
            Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::App))
        ));
        client.owner.flush_app_feedback();
    }
    assert!(matches!(
        client
            .owner
            .path
            .lock()
            .unwrap()
            .process(&app, Direction::Outbound, 1280, now),
        Err(TranslationError::RateLimited)
    ));
    for _ in 0..6 {
        assert!(matches!(
            client.owner.path.lock().unwrap().process(
                &app,
                Direction::Outbound,
                1280,
                now + Duration::from_secs(2)
            ),
            Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::App))
        ));
        client.owner.flush_app_feedback();
    }
    assert!(matches!(
        client.owner.path.lock().unwrap().process(
            &app,
            Direction::Outbound,
            1280,
            now + Duration::from_secs(3)
        ),
        Err(TranslationError::FeedbackFull)
    ));
    assert_eq!(
        client
            .owner
            .path
            .lock()
            .unwrap()
            .summary()
            .refused(TranslationError::FeedbackFull),
        1
    );
    assert_eq!(
        client
            .owner
            .path
            .lock()
            .unwrap()
            .summary()
            .refused(TranslationError::RateLimited),
        1
    );
    exhausted.store(false, Ordering::Release);
    drop(exhaustion);
    client.shutdown().await;
    drop(check);
    assert_eq!(credit.used(), 0);
    remote.stop().await;

    let (remote, mut observations, _input) = remote_controlled(&mut config, false).await;
    let source = projected(&broker, &config);
    capture
        .acknowledge_request(&broker.pending_request().unwrap())
        .unwrap();
    let mut successor = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = successor.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &successor, &owner, async { Ok(()) })
        .await
        .unwrap();
    assert!(matches!(
        app_feedback.write(|_| panic!("old app feedback entered successor")),
        RelayWriteOutcome::Stale
    ));
    assert!(matches!(
        talpid_netstack::raw_packet::handoff_feedback(target_feedback, |_| panic!(
            "old target feedback entered successor"
        )),
        Err(RelayFlowError::Stale)
    ));
    let before = available(application.as_ref());
    drop((app_feedback, feedback_allocator));
    assert!(
        available(application.as_ref()) >= before + 64 * 1024,
        "joined old feedback credit was not refunded"
    );
    let app = packet(
        &config,
        false,
        17,
        b"fresh-after-feedback-retirement",
        false,
        false,
    );
    capture.try_send(&app).unwrap();
    assert_eq!(
        observed(&mut observations).await,
        packet(
            &config,
            false,
            17,
            b"fresh-after-feedback-retirement",
            true,
            false
        )
    );
    assert_eq!(capture_bytes(&capture).await, application_reply(&app));
    local_progress(&session);
    capture.try_send(&oversize(&config, false, 0x95)).unwrap();
    assert_eq!(capture_bytes(&capture).await[20..22], [3, 4]);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), observations.recv())
            .await
            .is_err()
    );
    successor.shutdown().await;
    drop((owner, check, successor));
    assert_eq!(credit.used(), 0);
    assert_eq!(available(application.as_ref()), baseline);
    remote.stop().await;
}
