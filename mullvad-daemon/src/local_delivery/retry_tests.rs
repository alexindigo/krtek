//! Deterministically hold exact readiness replies at the retry-ownership seam.
use super::*;

#[derive(Default)]
struct RetryControl {
    failed: AtomicBool,
    publish_failure_on_probe: AtomicBool,
    retries: AtomicUsize,
    handovers: AtomicUsize,
    completion: Mutex<Option<oneshot::Sender<io::Result<()>>>>,
    changed: tokio::sync::Notify,
}

impl RetryControl {
    fn fail_establishment(&self) {
        self.completion
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(Err(io::Error::other("establishment failed before switch")))
            .unwrap();
    }

    fn complete(&self, failed: bool) {
        self.failed.store(failed, SeqCst);
        self.completion
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(if failed {
                Err(io::Error::other("held release failed"))
            } else {
                Ok(())
            })
            .unwrap();
    }
}

struct RetryFactory(Arc<RetryControl>);
struct RetryOwner {
    control: Arc<RetryControl>,
    ready: Option<oneshot::Receiver<io::Result<()>>>,
}

impl RetryOwner {
    fn hold(&mut self) {
        assert!(self.ready.is_none(), "unjoined readiness was replaced");
        let (sender, receiver) = oneshot::channel();
        assert!(
            self.control
                .completion
                .lock()
                .unwrap()
                .replace(sender)
                .is_none()
        );
        self.ready = Some(receiver);
    }
}

impl FrontendFactory for RetryFactory {
    type Owner = RetryOwner;
    fn supported(&self) -> bool {
        true
    }
    fn start(
        &self,
        _: DeliveryConfig,
        _: Arc<DeliveryAuthority>,
        _: Arc<dyn RelayBufferAllocator>,
        _: AttachmentBroker,
    ) -> io::Result<RetryOwner> {
        Ok(RetryOwner {
            control: self.0.clone(),
            ready: None,
        })
    }
}

impl DeliveryOwner for RetryOwner {
    fn handover(&mut self, _: DeliveryConfig) -> io::Result<()> {
        self.control.handovers.fetch_add(1, SeqCst);
        self.hold();
        Ok(())
    }
    fn retry_handover_release(&mut self) -> io::Result<()> {
        self.control.retries.fetch_add(1, SeqCst);
        self.hold();
        Ok(())
    }
    async fn ready(&mut self) -> io::Result<()> {
        let Some(ready) = self.ready.as_mut() else {
            return Ok(());
        };
        let result = ready.await.unwrap();
        self.ready.take();
        result
    }
    async fn stop(&mut self) -> io::Result<()> {
        assert!(self.ready.is_none());
        Ok(())
    }
    fn retry_release(&mut self) -> io::Result<()> {
        panic!("live owner must retain its readiness handle")
    }
    fn state(&self) -> OwnerState {
        OwnerState::Running
    }
    fn release_failed(&self) -> bool {
        let failed = self.control.failed.load(SeqCst);
        // Publish after the caller's check, before its next reconciliation step.
        // This is deterministic and uses no timing or production fault hook.
        if self.control.publish_failure_on_probe.swap(false, SeqCst) {
            self.control.failed.store(true, SeqCst);
        }
        failed
    }
    async fn changed(&mut self) {
        self.control.changed.notified().await;
    }
}

fn configured() -> DeliveryConfig {
    DeliveryConfig::Partial(vec!["10.0.2.2/32".into()].into())
}

fn delivery(control: Arc<RetryControl>) -> Delivery<RetryFactory> {
    Delivery::new(
        RetryFactory(control),
        authority(),
        DeliveryBuffers::new().local,
        broker(),
    )
}

#[tokio::test]
async fn internal_reconciliation_cannot_retry_a_newly_published_release_failure() {
    let control = Arc::new(RetryControl::default());
    let mut delivery = delivery(control.clone());
    delivery.maintain_config(Some(configured())).await;
    control.publish_failure_on_probe.store(true, SeqCst);
    control.changed.notify_one();
    bounded(delivery.changed()).await;
    assert_eq!(
        control.retries.load(SeqCst),
        0,
        "internal event started a release retry"
    );
    assert!(delivery.release_failed());
    delivery.maintain_config(Some(configured())).await;
    assert_eq!(control.retries.load(SeqCst), 1);
    control.complete(false);
    bounded(delivery.changed()).await;
    assert!(!delivery.release_failed());
    delivery.stop().await.unwrap();
}

#[tokio::test]
async fn explicit_release_retry_during_pending_readiness_survives_the_exact_failure() {
    for final_failure in [false, true] {
        let control = Arc::new(RetryControl::default());
        let mut delivery = delivery(control.clone());
        delivery.maintain_config(Some(configured())).await;
        control.failed.store(true, SeqCst);
        delivery.maintain_config(Some(configured())).await;
        assert_eq!(control.retries.load(SeqCst), 1);
        assert!(delivery.pending.is_some());
        // These external events coalesce while the same readiness is held. None
        // may replace its receiver or dispatch before its exact failure joins.
        for _ in 0..3 {
            delivery.maintain_config(Some(configured())).await;
        }
        assert_eq!(control.retries.load(SeqCst), 1);
        control.complete(true);
        bounded(delivery.changed()).await;
        assert_eq!(
            control.retries.load(SeqCst),
            2,
            "explicit retry intent was lost at the pending failure"
        );
        assert!(delivery.pending.is_some());
        control.complete(final_failure);
        bounded(delivery.changed()).await;
        assert_eq!(control.retries.load(SeqCst), 2);
        assert_eq!(delivery.release_failed(), final_failure);
        control.changed.notify_one();
        bounded(delivery.changed()).await;
        assert_eq!(
            control.retries.load(SeqCst),
            2,
            "failure retried without another external event"
        );
        assert_eq!(control.handovers.load(SeqCst), 0);
        delivery.stop().await.unwrap();
    }
}

#[tokio::test]
async fn failed_establishment_retains_its_request_until_external_retry_or_distinct_successor() {
    for retry_while_pending in [false, true] {
        let control = Arc::new(RetryControl::default());
        let mut delivery = delivery(control.clone());
        let broker = delivery.broker.clone();
        let capture = broker.open_capture(None).unwrap();
        let sources = talpid_types::relay_flow::RelaySources {
            ipv4: Some(ROUTER_IPV4),
            ipv6: Some(ROUTER_IPV6),
        };
        let receipt = capture
            .bind_observed_identity("retained", 71_u64 << 32, sources, ROUTER_MTU)
            .unwrap();
        delivery.maintain_config(Some(configured())).await;
        delivery.authority.update(&policy(), Some(observation()));
        let grant = delivery
            .authority
            .authorize(flow(Transport::Udp, 40100))
            .unwrap();
        let config = talpid_tunnel::tun_provider::transport::router_blocking_config(vec![]);
        let request = broker.request_capture(config.clone()).unwrap();
        let wanted = DeliveryConfig::Secured {
            broker: broker.clone(),
            request: broker.pending_request().unwrap(),
        };
        delivery.reconcile_config(Some(wanted.clone())).await;
        assert_eq!(control.handovers.load(SeqCst), 1);
        if retry_while_pending {
            delivery.maintain_config(Some(wanted.clone())).await;
        }
        control.fail_establishment();
        bounded(delivery.changed()).await;
        let attempts = if retry_while_pending { 2 } else { 1 };
        assert_eq!(control.handovers.load(SeqCst), attempts);
        if retry_while_pending {
            control.fail_establishment();
            bounded(delivery.changed()).await;
        }
        for _ in 0..3 {
            delivery.reconcile_config(Some(wanted.clone())).await;
            assert_eq!(
                control.handovers.load(SeqCst),
                attempts,
                "internal event retried failed establishment"
            );
            assert!(delivery.authority.current(&grant));
            assert_eq!(
                broker.snapshot().capture_generation,
                Some(receipt.generation())
            );
            assert!(broker.snapshot().capture_ready);
            assert!(delivery.failed());
        }
        delivery.maintain_config(Some(wanted.clone())).await;
        assert_eq!(control.handovers.load(SeqCst), attempts + 1);
        control.fail_establishment();
        bounded(delivery.changed()).await;
        drop(request);
        let next_request = broker.request_capture(config).unwrap();
        let next = DeliveryConfig::Secured {
            broker: broker.clone(),
            request: broker.pending_request().unwrap(),
        };
        assert!(!next.same_capture(&wanted));
        delivery.reconcile_config(Some(next)).await;
        assert_eq!(
            control.handovers.load(SeqCst),
            attempts + 2,
            "distinct successor was suppressed"
        );
        control.fail_establishment();
        bounded(delivery.changed()).await;
        assert!(delivery.authority.current(&grant));
        drop(next_request);
        delivery.stop().await.unwrap();
    }
}
