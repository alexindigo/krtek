use super::*;
use talpid_types::relay_flow::{RelaySources, RelayTargetId};

#[tokio::test]
async fn one_local_tcp_and_udp_engine_outlives_target_cancel_detach_and_replacement() {
    let (platform, peer) = Platform::new();
    let broker = broker();
    let (mut request, mut config) = managed(&broker);
    let second = RelayTargetId::new(2).unwrap();
    if let CaptureConfig::Secured { disposition, .. } = &mut config {
        *disposition = Arc::new(move |destination| {
            if destination.is_loopback() {
                CaptureDisposition::Local
            } else if destination == "8.8.8.8".parse::<IpAddr>().unwrap() {
                CaptureDisposition::Tunnel(second)
            } else {
                CaptureDisposition::Tunnel(RelayTargetId::MULLVAD)
            }
        });
    }
    let (_updates, updates) = watch::channel(0);
    let authority = Arc::new(Authority::default());
    let mut owner = FrontendOwner::start(
        platform.clone(),
        config,
        managed_forwarder(authority.clone()),
        updates,
        broker.clone(),
    )
    .unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = request.configured().await.unwrap();
    let (tcp, mut accepts, server) = tcp_echo(false).await;
    let (address, mut hits, echo) = udp_echo(false).await;
    let local = Flow {
        source: "10.64.42.2:48700".parse().unwrap(),
        destination: address,
        transport: Transport::Udp,
    };
    let mut app = App::new(Flow {
        source: "10.64.42.2:48701".parse().unwrap(),
        destination: tcp,
        transport: Transport::Tcp,
    });
    let mut first = None;
    let mut old_cleanup = None;
    let mut replacement_request = None;
    let sources = RelaySources {
        ipv4: Some("10.77.0.2".parse().unwrap()),
        ipv6: None,
    };
    let mut other = broker
        .acquire_target(&receipt, second, sources, 1300)
        .unwrap();
    assert_eq!(other.control.capability().sources(), sources);
    assert_eq!(other.control.capability().mtu(), 1300);
    let mut stale = None;
    for stage in [
        "no-mullvad",
        "ready",
        "detached",
        "cancelled",
        "replacement",
        "provider-close",
    ] {
        match stage {
            "ready" => {
                let pair = broker.acquire(&receipt).unwrap();
                pair.control.activate().unwrap();
                pair.send.try_send(&raw(253, b"stale-return")).unwrap();
                // Let the capture own this return across target retirement.
                assert_eq!(bounded(receive(&peer)).await, raw(253, b"stale-return"));
                first = Some(pair);
            }
            "detached" => {
                first.as_ref().unwrap().control.detach();
                assert!(!first.as_ref().unwrap().control.current());
                assert!(
                    other.control.current(),
                    "detaching one target retired its sibling"
                );
            }
            "cancelled" => {
                let pair = broker.acquire(&receipt).unwrap();
                pair.control.activate().unwrap();
                first = Some(pair);
                old_cleanup = Some(broker.transport_cleanup());
                first
                    .as_ref()
                    .unwrap()
                    .send
                    .try_send(&raw(253, b"held-before-cancel"))
                    .unwrap();
                // Retain an outbound item across cancellation too.
                send(&peer, &raw(253, b"old-outbound")).await;
                stale = Some(
                    bounded(first.as_mut().unwrap().receive.recv())
                        .await
                        .unwrap(),
                );
                request.cancel();
                assert!(receipt.current());
                assert!(!first.as_ref().unwrap().control.current());
            }
            "replacement" => {
                let mut next = broker.request_capture(assigned()).unwrap();
                receipt
                    .acknowledge(&broker.pending_request().unwrap())
                    .unwrap();
                let next_receipt = next.configured().await.unwrap();
                let pair = broker.acquire(&next_receipt).unwrap();
                pair.control.activate().unwrap();
                drop(first.take());
                request.cancel();
                assert!(pair.control.current(), "old request cancelled replacement");
                old_cleanup.take().unwrap().cancel();
                assert!(
                    pair.control.current(),
                    "old provider cleanup cancelled replacement"
                );
                assert!(
                    stale
                        .take()
                        .unwrap()
                        .handoff(|_| panic!("old bytes reached replacement"))
                        .is_err()
                );
                first = Some(pair);
                replacement_request = Some(next);
            }
            "provider-close" => {
                broker.transport_cleanup().cancel();
                assert!(receipt.current());
                assert!(!first.as_ref().unwrap().control.current());
            }
            _ => {}
        }
        app.nonce(&peer, stage.as_bytes()).await;
        send(&peer, &udp(local, stage.as_bytes())).await;
        assert_eq!(bounded(hits.recv()).await.unwrap(), stage.as_bytes());
        loop {
            let bytes = bounded(receive(&peer)).await;
            if bytes == raw(253, b"held-before-cancel") {
                continue;
            }
            assert_eq!(packet::parse(&bytes).unwrap().payload, stage.as_bytes());
            break;
        }
        // Even with no active target at all, the same Local sockets progress.
        // The stand-in becomes ready only after this first Local round trip.
        other.control.activate().unwrap();
        let mut selected = raw(253, stage.as_bytes());
        selected[16..20].copy_from_slice(&[8, 8, 8, 8]);
        send(&peer, &selected).await;
        bounded(other.receive.recv())
            .await
            .unwrap()
            .handoff(|bytes| assert_eq!(bytes, selected))
            .unwrap();
        other.send.try_send(&selected).unwrap();
        assert_eq!(bounded(receive(&peer)).await, selected);
        assert_eq!(*owner.state().borrow(), FrontendState::Running);
        assert_eq!(platform.closed.load(SeqCst), 0);
    }
    bounded(accepts.recv()).await.unwrap();
    assert!(accepts.try_recv().is_err(), "Local TCP reopened");
    assert_eq!(
        authority.prepares.load(SeqCst),
        2,
        "Local physical TCP/UDP sockets reopened"
    );
    request.transport_joined();
    replacement_request.as_ref().unwrap().transport_joined();
    other.control.detach();
    owner.stop().await.unwrap();
    assert_eq!(platform.closed.load(SeqCst), 1);
    echo.abort();
    server.abort();
}
