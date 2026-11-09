use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn observed() -> CaptureNetworkObservation {
    let prefix = CapturePrefix {
        address: "10.64.0.2".parse().unwrap(),
        prefix_length: 32,
    };
    CaptureNetworkObservation {
        // The entire opaque jlong, including bits outside a 32-bit netId.
        network_handle: i64::MIN + 0x1_0000_0001,
        network: "257".into(),
        interface_name: "tun7".into(),
        owner_uid: Some(10181),
        routes: vec![CaptureRoute {
            destination: prefix.clone(),
            gateway: None,
            interface_name: "tun7".into(),
            route_type: Some(1),
        }],
        addresses: vec![prefix],
        dns_servers: vec!["10.64.0.1".parse().unwrap()],
        mtu: Some(1380),
        fresh: true,
        lost: false,
        api_level: 33,
    }
}

fn expected() -> CaptureExpectation {
    let o = observed();
    CaptureExpectation {
        interface_name: o.interface_name,
        owner_uid: o.owner_uid,
        api_level: o.api_level,
        routes: o.routes,
        addresses: o.addresses,
        dns_servers: o.dns_servers,
        mtu: o.mtu,
    }
}

#[test]
fn registration_generation_and_fd_binding_refuse_stale_equal_observations() {
    let feed = CaptureNetworkFeed::new(9);
    let mut rx = feed.begin(11).unwrap();
    assert!(!feed.publish(9, 11, observed()));
    assert!(!rx.has_changed().unwrap());
    assert!(feed.bind(11, expected()));
    assert!(!feed.publish(8, 11, observed()));
    assert!(!feed.publish(9, 10, observed()));
    let mut wrong = observed();
    wrong.owner_uid = Some(10182);
    assert!(!feed.publish(9, 11, wrong));
    let mut wrong = observed();
    wrong.interface_name = "tun0".into();
    assert!(!feed.publish(9, 11, wrong));
    assert!(feed.publish(9, 11, observed()));
    assert_eq!(
        *rx.borrow_and_update(),
        CaptureNetworkState::Ready(Arc::new(observed()))
    );
    feed.invalidate(11);
    assert_eq!(*rx.borrow(), CaptureNetworkState::Lost);
    assert!(feed.begin(11).is_none());
    let replacement = feed.begin(12).unwrap();
    assert!(feed.bind(12, expected()));
    assert!(!feed.publish(9, 11, observed()));
    assert_eq!(*replacement.borrow(), CaptureNetworkState::Pending);
    assert!(feed.publish(9, 12, observed()));
    assert!(matches!(
        *replacement.borrow(),
        CaptureNetworkState::Ready(_)
    ));
    feed.invalidate(11);
    assert!(matches!(
        *replacement.borrow(),
        CaptureNetworkState::Ready(_)
    ));
}

#[test]
fn handover_disarms_only_old_epoch_and_requires_fresh_exact_successor_observation() {
    let feed = CaptureNetworkFeed::new(9);
    let old = feed.begin(11).unwrap();
    assert!(feed.bind(11, expected()));
    assert!(feed.publish(9, 11, observed()));
    let revoked = Arc::new(AtomicUsize::new(0));
    let r = revoked.clone();
    assert_eq!(
        feed.acknowledge(
            11,
            Arc::new(move || {
                r.fetch_add(1, Ordering::SeqCst);
            }),
            |_| ()
        ),
        Some(())
    );
    assert!(feed.begin_handover(10, Some(12)).is_none());
    let next = feed.begin_handover(11, Some(12)).unwrap().unwrap();
    assert!(
        feed.with_ready(11, || panic!("predecessor still writable"))
            .is_none()
    );
    assert!(feed.begin(13).is_none());
    assert!(feed.begin_handover(12, Some(13)).is_none());
    assert!(!feed.bind(11, expected()));
    assert!(
        feed.acknowledge(11, Arc::new(|| panic!("old reacknowledged")), |_| ())
            .is_none()
    );
    let mut lost = observed();
    lost.lost = true;
    assert!(feed.publish(9, 11, lost));
    assert_eq!(*old.borrow(), CaptureNetworkState::Lost);
    assert_eq!(
        revoked.load(Ordering::SeqCst),
        0,
        "expected predecessor loss retired session"
    );
    assert!(!feed.rollback_handover(11), "lost old fd falsely restored");
    assert_eq!(*next.borrow(), CaptureNetworkState::Pending);
    assert!(
        !feed.publish(9, 12, observed()),
        "unbound successor acknowledged"
    );
    assert!(feed.bind(12, expected()));
    let mut wrong = observed();
    wrong.interface_name = "tun-old".into();
    assert!(!feed.publish(9, 12, wrong));
    assert_eq!(*next.borrow(), CaptureNetworkState::Pending);
    assert!(feed.publish(9, 12, observed()));
    let r = revoked.clone();
    assert_eq!(
        feed.acknowledge(
            12,
            Arc::new(move || {
                r.fetch_add(1, Ordering::SeqCst);
            }),
            |_| ()
        ),
        Some(())
    );
    feed.invalidate(11);
    assert_eq!(
        feed.with_ready(12, || b"new-sink-consumer"),
        Some(b"new-sink-consumer")
    );
    assert_eq!(revoked.load(Ordering::SeqCst), 0);
    assert!(!feed.publish(9, 11, observed()));
    // Loss of the actual current epoch still revokes synchronously.
    let mut lost = observed();
    lost.lost = true;
    assert!(feed.publish(9, 12, lost));
    assert_eq!(revoked.load(Ordering::SeqCst), 1);
    assert!(
        feed.with_ready(12, || panic!("lost successor write"))
            .is_none()
    );
}

#[test]
fn pre_establish_retention_restores_exact_old_feed_and_close_revokes_during_handover() {
    for partial in [false, true] {
        let feed = CaptureNetworkFeed::new(9);
        let old = feed.begin(11).unwrap();
        assert!(feed.bind(11, expected()));
        assert!(feed.publish(9, 11, observed()));
        let revoked = Arc::new(AtomicUsize::new(0));
        let r = revoked.clone();
        feed.acknowledge(
            11,
            Arc::new(move || {
                r.fetch_add(1, Ordering::SeqCst);
            }),
            |_| (),
        )
        .unwrap();
        let successor = feed.begin_handover(11, (!partial).then_some(12)).unwrap();
        assert_eq!(successor.is_none(), partial);
        assert!(!feed.rollback_handover(10));
        assert!(feed.rollback_handover(11));
        if let Some(successor) = successor {
            assert_eq!(*successor.borrow(), CaptureNetworkState::Lost);
        }
        assert_eq!(
            feed.with_ready(11, || b"retained-consumer"),
            Some(b"retained-consumer")
        );
        assert_eq!(revoked.load(Ordering::SeqCst), 0);
        assert!(matches!(*old.borrow(), CaptureNetworkState::Ready(_)));
        assert!(feed.begin_handover(11, (!partial).then_some(13)).is_some());
        feed.close();
        assert_eq!(
            revoked.load(Ordering::SeqCst),
            1,
            "feed shutdown lost suspended revoker"
        );
        assert_eq!(*old.borrow(), CaptureNetworkState::Lost);
        assert!(!feed.rollback_handover(11));
        assert!(feed.begin(14).is_none());
    }
}

#[test]
fn exact_config_and_loss_revoke_before_notification_and_cannot_recover_in_place() {
    let mutations: [fn(&mut CaptureNetworkObservation); 10] = [
        |o| o.routes.clear(),
        |o| {
            let mut extra = o.routes[0].clone();
            extra.route_type = Some(7);
            o.routes.push(extra);
        },
        |o| o.routes[0].gateway = Some("10.64.0.1".parse().unwrap()),
        |o| o.routes[0].interface_name = "tun0".into(),
        |o| o.addresses[0].address = "192.0.2.2".parse().unwrap(),
        |o| o.dns_servers.clear(),
        |o| o.mtu = Some(1280),
        |o| o.owner_uid = Some(10182),
        |o| o.fresh = false,
        |o| o.lost = true,
    ];
    for mutate in mutations {
        let feed = CaptureNetworkFeed::new(9);
        let mut rx = feed.begin(11).unwrap();
        assert!(feed.bind(11, expected()));
        assert!(feed.publish(9, 11, observed()));
        rx.borrow_and_update();
        let revocations = Arc::new(AtomicUsize::new(0));
        let r = revocations.clone();
        assert_eq!(
            feed.acknowledge(
                11,
                Arc::new(move || {
                    r.fetch_add(1, Ordering::SeqCst);
                }),
                |o| o.network_handle
            ),
            Some(observed().network_handle)
        );
        let mut wrong = observed();
        mutate(&mut wrong);
        assert!(feed.publish(9, 11, wrong));
        assert_eq!(revocations.load(Ordering::SeqCst), 1);
        assert_eq!(*rx.borrow(), CaptureNetworkState::Lost);
        assert!(!feed.publish(9, 11, observed()));
        assert!(feed.acknowledge(11, Arc::new(|| {}), |_| ()).is_none());
        feed.invalidate(11);
        assert_eq!(revocations.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn pinned_full_handle_and_semantic_duplicates_do_not_rebind_or_wake() {
    let feed = CaptureNetworkFeed::new(9);
    let mut rx = feed.begin(11).unwrap();
    feed.bind(11, expected());
    assert!(feed.publish(9, 11, observed()));
    rx.borrow_and_update();
    let mut duplicate = observed();
    duplicate.routes.push(duplicate.routes[0].clone());
    assert!(!feed.publish(9, 11, duplicate));
    let mut stale = observed();
    stale.network_handle = (stale.network_handle as i32) as i64;
    stale.lost = true;
    assert!(!feed.publish(9, 11, stale));
    assert!(!rx.has_changed().unwrap());
    assert_eq!(
        *rx.borrow(),
        CaptureNetworkState::Ready(Arc::new(observed()))
    );
}

#[test]
fn checked_local_output_is_ordered_against_capture_loss_and_refuses_later_writes() {
    use std::{sync::mpsc, time::Duration};
    let feed = CaptureNetworkFeed::new(9);
    let rx = feed.begin(11).unwrap();
    feed.bind(11, expected());
    feed.publish(9, 11, observed());
    let (entered, in_write) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (consumer, consumed) = mpsc::channel();
    let writer = feed.clone();
    let write = std::thread::spawn(move || {
        writer.with_ready(11, || {
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
            consumer.send(b"checked-current-local-nonce").unwrap();
        })
    });
    in_write.recv_timeout(Duration::from_secs(2)).unwrap();
    let publisher = feed.clone();
    let (attempted, attempt) = mpsc::channel();
    let (lost, loss) = mpsc::channel();
    let publication = std::thread::spawn(move || {
        attempted.send(()).unwrap();
        let mut observation = observed();
        observation.lost = true;
        publisher.publish(9, 11, observation);
        lost.send(()).unwrap();
    });
    attempt.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(loss.recv_timeout(Duration::from_millis(50)).is_err());
    release.send(()).unwrap();
    assert_eq!(write.join().unwrap(), Some(()));
    assert_eq!(
        consumed.recv_timeout(Duration::from_secs(2)).unwrap(),
        b"checked-current-local-nonce"
    );
    loss.recv_timeout(Duration::from_secs(2)).unwrap();
    publication.join().unwrap();
    assert_eq!(*rx.borrow(), CaptureNetworkState::Lost);
    assert!(
        feed.with_ready(11, || panic!("revoked local write ran"))
            .is_none()
    );
    assert!(
        feed.with_ready(12, || panic!("wrong generation wrote"))
            .is_none()
    );
}

#[test]
fn optional_registration_failure_and_close_invalidate_only_the_capture_feed() {
    for outcome in 0..3 {
        let feed = CaptureNetworkFeed::new(9);
        let rx = feed.begin(11).unwrap();
        feed.bind(11, expected());
        feed.publish(9, 11, observed());
        assert!(!feed.register(|_| -> Result<bool, ()> {
            match outcome {
                0 => Ok(false),
                1 => Err(()),
                _ => panic!("missing capture class"),
            }
        }));
        assert_eq!(*rx.borrow(), CaptureNetworkState::Lost);
        assert!(feed.begin(12).is_none());
        assert!(!feed.publish(9, 11, observed()));
        feed.close();
    }
}

#[test]
fn registration_failure_without_a_network_identity_retires_before_binding() {
    let feed = CaptureNetworkFeed::new(9);
    let rx = feed.begin(11).unwrap();
    let mut failed = observed();
    failed.network_handle = 0;
    failed.lost = true;
    failed.fresh = false;
    assert!(feed.publish(9, 11, failed.clone()));
    assert_eq!(*rx.borrow(), CaptureNetworkState::Lost);
    assert!(!feed.publish(9, 11, failed));
    assert!(feed.acknowledge(11, Arc::new(|| {}), |_| ()).is_none());
}

#[test]
fn requested_os_projection_has_only_explicit_bookkeeping_and_disabled_family_routes() {
    for (sources, routes, dns, wanted) in [
        (
            vec!["10.64.0.2"],
            vec!["0.0.0.0/0"],
            vec!["10.64.0.1"],
            vec![("0.0.0.0/0", 1), ("10.64.0.2/32", 1), ("::/0", 7)],
        ),
        (
            vec!["fd42::2"],
            vec!["::/0"],
            vec!["fd42::1"],
            vec![("0.0.0.0/0", 7), ("::/0", 1), ("fd42::2/128", 1)],
        ),
        (
            vec!["192.0.2.2", "2001:db8::2"],
            vec!["10.0.2.2/32"],
            vec![],
            vec![
                ("10.0.2.2/32", 1),
                ("192.0.2.2/32", 1),
                ("2001:db8::2/128", 1),
            ],
        ),
    ] {
        let prefix = |text: &str| {
            let network: ipnetwork::IpNetwork = text.parse().unwrap();
            CapturePrefix {
                address: network.ip(),
                prefix_length: i16::from(network.prefix()),
            }
        };
        let requested = CaptureExpectation::requested(
            "tun7".into(),
            10181,
            33,
            &sources
                .iter()
                .map(|s| s.parse().unwrap())
                .collect::<Vec<_>>(),
            &routes.iter().map(|r| prefix(r)).collect::<Vec<_>>(),
            &dns.iter().map(|s| s.parse().unwrap()).collect::<Vec<_>>(),
            1420,
        )
        .unwrap();
        let mut expected: Vec<_> = wanted
            .iter()
            .map(|(p, route_type)| CaptureRoute {
                destination: prefix(p),
                gateway: None,
                interface_name: "tun7".into(),
                route_type: Some(*route_type),
            })
            .collect();
        expected.sort();
        assert_eq!(requested.routes, expected);
        let mut observation = observed();
        observation.routes = expected;
        observation.addresses = requested.addresses.clone();
        observation.dns_servers = requested.dns_servers.clone();
        observation.mtu = requested.mtu;
        let feed = CaptureNetworkFeed::new(9);
        let rx = feed.begin(11).unwrap();
        assert!(feed.bind(11, requested));
        assert!(feed.publish(9, 11, observation.clone()));
        assert!(matches!(*rx.borrow(), CaptureNetworkState::Ready(_)));
        observation.routes.push(CaptureRoute {
            destination: prefix("203.0.113.0/24"),
            gateway: None,
            interface_name: "tun7".into(),
            route_type: Some(1),
        });
        assert!(feed.publish(9, 11, observation));
        assert_eq!(*rx.borrow(), CaptureNetworkState::Lost);
    }
}

#[test]
fn requested_projection_does_not_normalize_malformed_requested_prefixes() {
    for prefix in [-1, 33, 128] {
        assert!(
            CaptureExpectation::requested(
                "tun7".into(),
                10181,
                33,
                &["10.64.0.2".parse().unwrap()],
                &[CapturePrefix {
                    address: "10.0.2.2".parse().unwrap(),
                    prefix_length: prefix,
                }],
                &[],
                1380
            )
            .is_none()
        );
    }
    assert!(
        CaptureExpectation::requested(
            "tun7".into(),
            10181,
            33,
            &["10.64.0.2".parse().unwrap()],
            &[CapturePrefix {
                address: "10.0.2.2".parse().unwrap(),
                prefix_length: 24,
            }],
            &[],
            1380
        )
        .is_none()
    );
}

#[test]
fn api_scoped_projection_requires_every_reported_property_without_inventing_absent_ones() {
    for api in [28, 29, 30, 32, 33] {
        let expected = CaptureExpectation::requested(
            "tun7".into(),
            10181,
            api,
            &["10.64.0.2".parse().unwrap()],
            &[],
            &["10.64.0.1".parse().unwrap()],
            1380,
        )
        .unwrap();
        assert_eq!(expected.owner_uid, (api >= 30).then_some(10181));
        assert_eq!(expected.mtu, (api >= 29).then_some(1380));
        assert!(
            expected
                .routes
                .iter()
                .all(|route| route.route_type.is_some() == (api >= 33))
        );
        let mut observation = observed();
        observation.api_level = api;
        observation.owner_uid = expected.owner_uid;
        observation.mtu = expected.mtu;
        observation.routes = expected.routes.clone();
        assert!(expected.matches(&observation));
        let mut wrong = observation.clone();
        wrong.routes.push(CaptureRoute {
            destination: CapturePrefix {
                address: "203.0.113.0".parse().unwrap(),
                prefix_length: 24,
            },
            gateway: None,
            interface_name: "tun7".into(),
            route_type: (api >= 33).then_some(1),
        });
        assert!(!expected.matches(&wrong));
        wrong = observation.clone();
        wrong.api_level = api + 1;
        assert!(!expected.matches(&wrong));
        wrong = observation.clone();
        wrong.owner_uid = if api >= 30 { None } else { Some(10181) };
        assert!(!expected.matches(&wrong));
        wrong = observation.clone();
        wrong.mtu = if api >= 29 { None } else { Some(1380) };
        assert!(!expected.matches(&wrong));
        wrong = observation.clone();
        wrong.routes[0].route_type = if api >= 33 { None } else { Some(1) };
        assert!(!expected.matches(&wrong));
        if api >= 33 {
            wrong = observation;
            wrong.routes[0].route_type = Some(7);
            assert!(!expected.matches(&wrong));
        }
    }
}
