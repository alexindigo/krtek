use super::*;
use std::{
    future::{Future, poll_fn},
    os::unix::net::UnixDatagram,
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};
use talpid_netstack::buffer_budget::BufferBudget;

fn config() -> TunConfig {
    let mut config = crate::tun_provider::blocking_config();
    config.addresses = vec!["10.64.0.2".parse().unwrap(), "fc00::2".parse().unwrap()];
    config.mtu = 1420;
    config
}

fn sources() -> RelaySources {
    RelaySources {
        ipv4: Some("10.64.0.2".parse().unwrap()),
        ipv6: Some("fc00::2".parse().unwrap()),
    }
}

struct Fixture {
    broker: AttachmentBroker,
    application: BufferBudget,
    capture: BufferBudget,
    control: BufferBudget,
}
impl Fixture {
    fn new() -> Self {
        let root = BufferBudget::new(64 * 1024 * 1024);
        let application = root.reserve(22 * 1024 * 1024).unwrap().region().unwrap();
        let capture = root.reserve(2 * 1024 * 1024).unwrap().region().unwrap();
        let control = root.reserve(8 * 1024 * 1024).unwrap().region().unwrap();
        let broker =
            AttachmentBroker::new(Arc::new(application.clone()), Arc::new(capture.clone()))
                .unwrap();
        broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
        Self {
            broker,
            application,
            capture,
            control,
        }
    }
    fn request(&self) -> (ConfigurationRequest, PendingCaptureRequest) {
        let request = self.broker.request_capture(config()).unwrap();
        (request, self.broker.pending_request().unwrap())
    }
    fn bind(&self, request: &PendingCaptureRequest) -> (CaptureLease, CaptureReceipt) {
        let lease = self.broker.open_capture(Some(request)).unwrap();
        let receipt = lease
            .bind_observed_identity("tun7", 0xf123_4567_0000_0063, sources(), 1420)
            .unwrap();
        (lease, receipt)
    }
    async fn active(&self) -> (ConfigurationRequest, CaptureLease, TransportPair) {
        let (mut request, pending) = self.request();
        let (lease, receipt) = self.bind(&pending);
        self.broker.acknowledge(&pending, &receipt).unwrap();
        let receipt = request.configured().await.unwrap();
        let pair = self.broker.acquire(&receipt).unwrap();
        pair.control.activate().unwrap();
        (request, lease, pair)
    }
}

#[tokio::test]
async fn exact_request_acknowledgement_is_required_before_ordinary_activation() {
    let f = Fixture::new();
    let (mut request, pending) = f.request();
    let lease = f.broker.open_capture(Some(&pending)).unwrap();
    assert_eq!(
        lease.try_send(b"early"),
        Err(AttachmentError::OrdinaryUnready)
    );
    let mut wrong = sources();
    wrong.ipv4 = Some("10.64.0.9".parse().unwrap());
    assert!(matches!(
        lease.bind_observed_identity("tun7", 99, wrong, 1420),
        Err(AttachmentError::Invalid)
    ));
    assert!(matches!(
        lease.bind_observed_identity("tun7", 99, sources(), 1280),
        Err(AttachmentError::Invalid)
    ));
    let receipt = lease
        .bind_observed_identity("tun7", 0xf123_4567_0000_0063, sources(), 1420)
        .unwrap();
    assert!(matches!(
        f.broker.acquire(&receipt),
        Err(AttachmentError::CaptureUnready)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), request.configured())
            .await
            .is_err()
    );
    f.broker.acknowledge(&pending, &receipt).unwrap();
    assert_eq!(
        request.configured().await.unwrap().generation(),
        lease.generation()
    );
    let mut pair = f.broker.acquire(&receipt).unwrap();
    assert_eq!(
        lease.try_send(b"before connectivity"),
        Err(AttachmentError::OrdinaryUnready)
    );
    assert_eq!(
        pair.send.try_send(b"early return"),
        Err(AttachmentError::OrdinaryUnready)
    );
    pair.control.activate().unwrap();
    lease.try_send(b"exact raw bytes").unwrap();
    let packet = pair.receive.recv().await.unwrap();
    assert_eq!(
        packet.view().attempt().identity().network_handle,
        0xf123_4567_0000_0063
    );
    let mut consumer = Vec::new();
    packet
        .handoff(|bytes| consumer.extend_from_slice(bytes))
        .unwrap();
    assert_eq!(consumer, b"exact raw bytes");
}

#[tokio::test]
async fn partial_and_foreign_receipts_cannot_acknowledge_a_secured_request() {
    let f = Fixture::new();
    let (_request, pending) = f.request();
    let partial = f.broker.open_capture(None).unwrap();
    let receipt = partial
        .bind_observed_identity("tun7", 99, sources(), 1420)
        .unwrap();
    assert!(!receipt.current());
    assert_eq!(
        f.broker.acknowledge(&pending, &receipt),
        Err(AttachmentError::CaptureUnready)
    );
    partial.retire();
    let other = Fixture::new();
    let (_other_request, other_pending) = other.request();
    let (_other_lease, foreign) = other.bind(&other_pending);
    assert_eq!(
        f.broker.acknowledge(&pending, &foreign),
        Err(AttachmentError::CaptureUnready)
    );
    let (lease, receipt) = f.bind(&pending);
    f.broker.acknowledge(&pending, &receipt).unwrap();
    assert_eq!(
        f.broker.acknowledge(&pending, &receipt),
        Err(AttachmentError::Stale)
    );
    assert!(receipt.current());
    drop(partial);
    assert!(receipt.current());
    drop(lease);
    assert!(!receipt.current());
}

#[tokio::test]
async fn retiring_old_capture_preserves_successor_request_and_old_drops_cannot_retire_replacement()
{
    let f = Fixture::new();
    let (old_request, old_lease, old_pair) = f.active().await;
    old_pair.send.try_send(b"retired payload").unwrap();
    let mut old_reply = old_lease.reply().await.unwrap();
    let (mut successor, pending) = f.request();
    let next_id = pending.id();
    old_lease.retire();
    assert_eq!(f.broker.pending_request().unwrap().id(), next_id);
    old_pair.control.cancelled().await;
    let (next_lease, receipt) = f.bind(&pending);
    assert_ne!(old_lease.generation(), next_lease.generation());
    f.broker.acknowledge(&pending, &receipt).unwrap();
    let next_pair = f
        .broker
        .acquire(&successor.configured().await.unwrap())
        .unwrap();
    next_pair.control.activate().unwrap();
    drop(old_request);
    drop(old_lease);
    drop(old_pair);
    assert!(next_pair.control.current());
    assert!(matches!(
        old_reply.write(|_| panic!("retired bytes reached successor")),
        RelayWriteOutcome::Stale
    ));
    next_pair.send.try_send(b"successor nonce").unwrap();
    let mut reply = next_lease.reply().await.unwrap();
    let mut consumer = Vec::new();
    assert!(matches!(
        reply.write(|bytes| {
            consumer.extend_from_slice(bytes);
            Ok(bytes.len())
        }),
        RelayWriteOutcome::Written
    ));
    assert_eq!(consumer, b"successor nonce");
}

#[tokio::test]
async fn cancelled_wait_retains_owner_and_stale_ack_cannot_satisfy_identical_new_config() {
    let f = Fixture::new();
    let (mut request, old_pending) = f.request();
    let (lease, old_receipt) = f.bind(&old_pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), request.configured())
            .await
            .is_err()
    );
    assert!(f.broker.snapshot().capture_ready);
    request.cancel();
    assert!(!old_receipt.current());
    assert!(matches!(
        request.configured().await,
        Err(AttachmentError::Closed)
    ));
    let (mut next, pending) = f.request();
    let (_next_lease, receipt) = f.bind(&pending);
    assert_eq!(
        f.broker.acknowledge(&old_pending, &receipt),
        Err(AttachmentError::Stale)
    );
    assert_eq!(
        f.broker.acknowledge(&pending, &old_receipt),
        Err(AttachmentError::CaptureUnready)
    );
    drop(request);
    drop(lease);
    f.broker.acknowledge(&pending, &receipt).unwrap();
    assert!(next.configured().await.unwrap().current());
}

#[tokio::test]
async fn saturation_refuses_without_spending_private_control_credit_and_stop_stays_responsive() {
    let f = Fixture::new();
    let (_request, lease, pair) = f.active().await;
    for n in 0..PACKET_CAPACITY {
        lease.try_send(&n.to_be_bytes()).unwrap();
        pair.send.try_send(&n.to_le_bytes()).unwrap();
    }
    assert_eq!(lease.try_send(b"full"), Err(AttachmentError::Full));
    assert_eq!(pair.send.try_send(b"full"), Err(AttachmentError::Full));
    let control = f.control.reserve(f.control.limit()).unwrap();
    let application = f
        .application
        .reserve(f.application.limit() - f.application.used())
        .unwrap();
    assert_eq!(pair.send.try_send(b"full"), Err(AttachmentError::Full));
    let mut changes = f.broker.changes();
    lease.retire();
    tokio::time::timeout(Duration::from_secs(1), pair.control.cancelled())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), changes.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!changes.borrow().ordinary_ready);
    assert_eq!(f.application.used(), application.bytes());
    assert_eq!(f.control.used(), control.bytes());
}

#[tokio::test]
async fn blocked_real_packet_write_retains_bytes_and_credit_then_rechecks_retirement() {
    let f = Fixture::new();
    let (_request, lease, pair) = f.active().await;
    let (sink, consumer) = UnixDatagram::pair().unwrap();
    sink.set_nonblocking(true).unwrap();
    consumer.set_nonblocking(true).unwrap();
    let filler = [7u8; 1024];
    loop {
        match sink.send(&filler) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("{e}"),
        }
    }
    pair.send.try_send(b"do not deliver after revoke").unwrap();
    let mut reply = lease.reply().await.unwrap();
    let charged = f.application.used();
    assert!(matches!(
        reply.write(|bytes| sink.send(bytes)),
        RelayWriteOutcome::Retry
    ));
    assert_eq!(f.application.used(), charged);
    lease.retire();
    let mut buffer = [0u8; 2048];
    while consumer.recv(&mut buffer).is_ok() {}
    assert!(matches!(
        reply.write(|bytes| sink.send(bytes)),
        RelayWriteOutcome::Stale
    ));
    assert_eq!(
        consumer.recv(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.application.used(), charged);
    drop(reply);
    assert_eq!(f.application.used(), 0);
}

#[tokio::test]
async fn reply_and_outbound_waits_are_event_driven_for_one_real_second() {
    let f = Fixture::new();
    let (_request, lease, mut pair) = f.active().await;
    let polls = AtomicUsize::new(0);
    let mut reply = pin!(lease.reply());
    let mut outbound = pin!(pair.receive.recv());
    let mut waits = pin!(poll_fn(|cx| {
        polls.fetch_add(1, Ordering::Relaxed);
        assert!(reply.as_mut().poll(cx).is_pending());
        assert!(outbound.as_mut().poll(cx).is_pending());
        Poll::<()>::Pending
    }));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), waits.as_mut())
            .await
            .is_err()
    );
    // Timeout polls the inner future again at its deadline, but there is no
    // broker timer/self-wakeup anywhere during the real idle second.
    assert!(polls.load(Ordering::Relaxed) <= 2);
    pair.send.try_send(b"wake capture").unwrap();
    let mut reply = reply.await.unwrap();
    assert!(matches!(
        reply.write(|bytes| {
            assert_eq!(bytes, b"wake capture");
            Ok(bytes.len())
        }),
        RelayWriteOutcome::Written
    ));
    lease.try_send(b"wake transport").unwrap();
    outbound
        .await
        .unwrap()
        .handoff(|bytes| assert_eq!(bytes, b"wake transport"))
        .unwrap();
}

#[tokio::test]
async fn channel_metadata_remains_charged_through_halves_and_blocked_reply_lifetime() {
    let f = Fixture::new();
    let (request, lease, pair) = f.active().await;
    pair.send.try_send(b"retained").unwrap();
    let reply = lease.reply().await.unwrap();
    lease.retire();
    assert!(f.capture.used() >= CHANNEL_STORAGE);
    drop(pair);
    drop(lease);
    drop(request);
    assert!(f.capture.used() >= CHANNEL_STORAGE);
    drop(reply);
    assert_eq!(f.application.used(), 0);
    assert_eq!(f.capture.used(), 8192);
    drop(f.broker);
    assert_eq!(f.capture.used(), 0);
}

#[tokio::test]
async fn short_zero_and_fatal_writes_retire_exact_attempt_and_publish_unready() {
    for kind in 0..3 {
        let f = Fixture::new();
        let (_request, lease, pair) = f.active().await;
        pair.send.try_send(b"whole packet").unwrap();
        let mut reply = lease.reply().await.unwrap();
        let mut changes = f.broker.changes();
        assert!(matches!(
            reply.write(|bytes| match kind {
                0 => Ok(0),
                1 => Ok(bytes.len() - 1),
                _ => Err(io::ErrorKind::BrokenPipe.into()),
            }),
            RelayWriteOutcome::Fatal(_)
        ));
        assert!(!pair.control.current());
        pair.control.cancelled().await;
        changes.changed().await.unwrap();
        assert!(!changes.borrow().ordinary_ready);
        assert!(matches!(
            reply.write(|_| panic!("fatal packet retried")),
            RelayWriteOutcome::Stale
        ));
    }
}

#[tokio::test]
async fn absent_failed_closed_and_native_selections_never_fall_back_to_native_capture() {
    let f = Fixture::new();
    let (mut request, pending) = f.request();
    let lease = f.broker.open_capture(Some(&pending)).unwrap();
    lease.retire();
    assert!(matches!(
        request.configured().await,
        Err(AttachmentError::CaptureUnready)
    ));
    assert_eq!(f.broker.snapshot().mode, AttachmentMode::ManagedRequired);
    assert!(!f.broker.snapshot().capture_ready);
    f.broker.set_mode(AttachmentMode::Native).unwrap();
    assert!(matches!(
        f.broker.request_capture(config()),
        Err(AttachmentError::Disabled)
    ));
    f.broker.close();
    assert_eq!(
        f.broker.set_mode(AttachmentMode::ManagedRequired),
        Err(AttachmentError::Closed)
    );
    assert!(matches!(
        f.broker.open_capture(None),
        Err(AttachmentError::Closed)
    ));
}

#[tokio::test]
async fn readiness_watch_is_the_exact_live_attachment_and_request_projection() {
    let f = Fixture::new();
    let mut changes = f.broker.changes();
    let (_request, pending) = f.request();
    changes.changed().await.unwrap();
    assert_eq!(changes.borrow_and_update().request, Some(pending.id()));
    let (lease, receipt) = f.bind(&pending);
    changes.changed().await.unwrap();
    assert!(changes.borrow_and_update().capture_ready);
    f.broker.acknowledge(&pending, &receipt).unwrap();
    changes.changed().await.unwrap();
    assert_eq!(changes.borrow_and_update().request, None);
    let pair = f.broker.acquire(&receipt).unwrap();
    changes.changed().await.unwrap();
    let first_id = changes.borrow_and_update().attachment.unwrap();
    assert!(!changes.borrow().ordinary_ready);
    pair.control.activate().unwrap();
    changes.changed().await.unwrap();
    assert!(changes.borrow_and_update().ordinary_ready);
    pair.control.detach();
    changes.changed().await.unwrap();
    assert_eq!(changes.borrow_and_update().attachment, None);
    let next = f.broker.acquire(&receipt).unwrap();
    changes.changed().await.unwrap();
    assert_ne!(changes.borrow_and_update().attachment.unwrap(), first_id);
    next.control.activate().unwrap();
    drop(pair);
    assert!(next.control.current());
    drop(lease);
    assert!(!f.broker.snapshot().capture_ready);
    assert!(!f.broker.snapshot().ordinary_ready);
}

#[tokio::test]
async fn storage_refusal_is_immediate_and_dropping_a_half_revokes_queued_packets() {
    let f = Fixture::new();
    let (_request, lease, mut pair) = f.active().await;
    let held = f.application.reserve(f.application.limit()).unwrap();
    assert_eq!(lease.try_send(b"no credit"), Err(AttachmentError::Full));
    assert_eq!(pair.send.try_send(b"no credit"), Err(AttachmentError::Full));
    assert_eq!(f.control.used(), 0);
    drop(held);
    lease.try_send(b"retained handoff").unwrap();
    let packet = pair.receive.recv().await.unwrap();
    drop(pair.send);
    pair.control.cancelled().await;
    assert!(matches!(
        packet.handoff(|_| panic!("closed half delivered")),
        Err(RelayFlowError::Stale)
    ));
    assert_eq!(f.application.used(), 0);
    let before = f.capture.used();
    let held = f.capture.reserve(f.capture.limit() - before).unwrap();
    let receipt = CaptureReceipt {
        inner: Arc::downgrade(&f.broker.inner),
        generation: lease.generation(),
    };
    assert!(matches!(
        f.broker.acquire(&receipt),
        Err(AttachmentError::Full)
    ));
    assert_eq!(f.capture.used(), before + held.bytes());
    assert_eq!(f.broker.snapshot().attachment, None);
}
