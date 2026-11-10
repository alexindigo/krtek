//! Extends the existing independent crypto peers, not a second network fixture.
use super::*;
use talpid_netstack::address_translation::TranslationError;

#[path = "feedback_integration_tests.rs"]
mod feedback_integration_tests;

fn fixed() -> RelaySources {
    RelaySources {
        ipv4: Some("192.0.2.2".parse().unwrap()),
        ipv6: Some("2001:db8::2".parse().unwrap()),
    }
}

pub(super) fn projected(broker: &AttachmentBroker, config: &Config) -> PendingManaged {
    let capture_config = fixed_config(config);
    let target = tun_config(config);
    let request = broker
        .request_target_capture(target.clone(), capture_config.clone())
        .unwrap();
    PendingManaged::new(talpid_tunnel::tun_provider::transport::ManagedTun {
        broker: broker.clone(),
        config: target,
        capture_config,
        request,
    })
}

pub(super) fn bind(broker: &AttachmentBroker) -> CaptureLease {
    let pending = broker.pending_request().unwrap();
    let capture = broker.open_capture(Some(&pending)).unwrap();
    let receipt = capture
        .bind_observed_identity("tun17", 99, fixed(), 1280)
        .unwrap();
    broker.acknowledge(&pending, &receipt).unwrap();
    capture
}

fn endpoints(
    mut bytes: Vec<u8>,
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
) -> Vec<u8> {
    let v4 = source.is_ipv4();
    match (source, destination) {
        (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) => {
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&destination.octets());
        }
        (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) => {
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
        }
        _ => panic!("mixed test families"),
    }
    let offset = if v4 {
        20
    } else if bytes[6] == 0 {
        48
    } else {
        40
    };
    let protocol = if v4 {
        bytes[9]
    } else if bytes[6] == 0 {
        bytes[40]
    } else {
        bytes[6]
    };
    fix_wire(&mut bytes, offset, protocol);
    bytes
}

fn packet(
    config: &Config,
    v6: bool,
    protocol: u8,
    nonce: &[u8],
    assigned: bool,
    resolver: bool,
) -> Vec<u8> {
    if !v6 {
        return endpoints(
            ipv4(protocol, nonce),
            if assigned {
                config.tunnel_ipv4().unwrap()
            } else {
                fixed().ipv4.unwrap()
            }
            .into(),
            if resolver {
                config.ipv4_gateway
            } else {
                "203.0.113.20".parse().unwrap()
            }
            .into(),
        );
    }
    let mut bytes = vec![0; 60 + nonce.len()];
    bytes[0] = 0x60;
    bytes[6] = protocol;
    bytes[7] = 64;
    let size = (bytes.len() - 40) as u16;
    bytes[4..6].copy_from_slice(&size.to_be_bytes());
    bytes[40..42].copy_from_slice(&43000u16.to_be_bytes());
    bytes[42..44].copy_from_slice(&53u16.to_be_bytes());
    if protocol == 6 {
        bytes[52] = 0x50;
    }
    if protocol == 17 {
        bytes[44..46].copy_from_slice(&size.to_be_bytes());
    }
    if protocol == 58 {
        bytes[40] = 128;
        bytes[41] = 0;
    }
    bytes[60..].copy_from_slice(nonce);
    endpoints(
        bytes,
        if assigned {
            config.tunnel_ipv6().unwrap()
        } else {
            fixed().ipv6.unwrap()
        }
        .into(),
        if resolver {
            config.ipv6_gateway.unwrap()
        } else {
            "2001:db8:240::20".parse().unwrap()
        }
        .into(),
    )
}

async fn observed(observations: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), observations.recv())
        .await
        .unwrap()
        .unwrap()
}
async fn capture_bytes(capture: &CaptureLease) -> Vec<u8> {
    let mut reply = tokio::time::timeout(Duration::from_secs(2), capture.reply())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = None;
    assert!(matches!(
        reply.write(|packet| {
            bytes = Some(packet.to_vec());
            Ok(packet.len())
        }),
        RelayWriteOutcome::Written
    ));
    bytes.unwrap()
}

fn quoted_error(config: &Config, v6: bool, protocol: u8, inbound: bool, assigned: bool) -> Vec<u8> {
    let offset = if v6 { 40 } else { 20 };
    let icmp = if v6 { 58 } else { 1 };
    let mut outer = packet(config, v6, icmp, b"", assigned, false);
    let mut quoted = packet(
        config,
        v6,
        protocol,
        b"quoted-wire-payload",
        assigned,
        false,
    );
    if inbound {
        outer = application_reply(&outer);
    } else {
        quoted = application_reply(&quoted);
    }
    outer.truncate(offset + 8);
    outer[offset] = if v6 { 1 } else { 3 };
    outer[offset + 1] = 0;
    outer[offset + 4..offset + 8].fill(0);
    outer.extend_from_slice(&quoted[..offset + 8]);
    let length = (outer.len() - if v6 { 40 } else { 0 }) as u16;
    if v6 {
        outer[4..6].copy_from_slice(&length.to_be_bytes());
    } else {
        outer[2..4].copy_from_slice(&length.to_be_bytes());
    }
    fix_wire(&mut outer, offset, icmp);
    outer
}

#[tokio::test]
async fn translated_singlehop_and_multihop_consumers_see_both_address_domains() {
    for multihop in [false, true] {
        let (broker, _root, credit) = broker();
        let mut config = config();
        let (remote, mut observations, inject) = remote_controlled(&mut config, multihop).await;
        let source = projected(&broker, &config);
        let capture = bind(&broker);
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        assert!(
            capture
                .try_send(&packet(&config, false, 17, b"early", false, false))
                .is_err()
        );
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .unwrap();
        for v6 in [false, true] {
            for protocol in [6, 17, if v6 { 58 } else { 1 }, 47, 50, 132] {
                // SCTP's CRC is address independent, GRE/ESP stay opaque.
                let app = packet(
                    &config,
                    v6,
                    protocol,
                    b"crypto-consumer-nonce",
                    false,
                    false,
                );
                let wire = packet(&config, v6, protocol, b"crypto-consumer-nonce", true, false);
                capture.try_send(&app).unwrap();
                let actual = observed(&mut observations).await;
                assert_eq!(actual, wire);
                if [6, 17, 1, 58].contains(&protocol) {
                    assert_eq!(
                        wire_sum(&actual, if v6 { 40 } else { 20 }, protocol),
                        [0, 0]
                    );
                }
                assert_eq!(capture_bytes(&capture).await, application_reply(&app));
            }
            for protocol in [6, 17] {
                let app = packet(&config, v6, protocol, b"actual-resolver-tuple", false, true);
                capture.try_send(&app).unwrap();
                assert_eq!(
                    observed(&mut observations).await,
                    packet(&config, v6, protocol, b"actual-resolver-tuple", true, true)
                );
                assert_eq!(capture_bytes(&capture).await, application_reply(&app));
            }
        }
        // A supported extension is walked, not rejected merely for being IPv6.
        let app = packet(&config, true, 17, b"extension-nonce", false, false);
        let mut extension = app[..40].to_vec();
        extension[6] = 0;
        extension.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        extension.extend_from_slice(&app[40..]);
        let size = (extension.len() - 40) as u16;
        extension[4..6].copy_from_slice(&size.to_be_bytes());
        capture.try_send(&extension).unwrap();
        let expected = endpoints(
            extension.clone(),
            config.tunnel_ipv6().unwrap().into(),
            "2001:db8:240::20".parse().unwrap(),
        );
        assert_eq!(observed(&mut observations).await, expected);
        assert_eq!(capture_bytes(&capture).await, application_reply(&extension));

        // Both directions and families, with absent TCP checksum words and
        // present UDP checksum words in legal, independently generated quotes.
        for v6 in [false, true] {
            for protocol in [6, 17] {
                let error = quoted_error(&config, v6, protocol, false, false);
                capture.try_send(&error).unwrap();
                assert_eq!(
                    observed(&mut observations).await,
                    quoted_error(&config, v6, protocol, false, true)
                );
                let error = quoted_error(&config, v6, protocol, true, true);
                inject
                    .send(Packet::<[u8]>::copy_from(&error).try_into_ip().unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    capture_bytes(&capture).await,
                    quoted_error(&config, v6, protocol, true, false)
                );
            }
        }

        // Same private tuple/id/sequence, but not its secret, remains app data.
        let mut public = packet(&config, false, 1, &[0x83; 30], false, true);
        public[24..26].copy_from_slice(&owner.id.to_be_bytes());
        let counter = owner.ledger.lock().unwrap().highest;
        public[26..28].copy_from_slice(&(counter as u16).to_be_bytes());
        fix_wire(&mut public, 20, 1);
        capture.try_send(&public).unwrap();
        assert_eq!(capture_bytes(&capture).await, application_reply(&public));
        client.shutdown().await;
        drop((check, owner, client));
        assert_eq!(credit.used(), 0);
        remote.stop().await;
    }
}

#[tokio::test]
async fn directional_pmtu_feedback_reaches_the_original_sender_through_crypto() {
    for multihop in [false, true] {
        let (broker, _root, credit) = broker();
        let mut config = config();
        let (remote, mut observations, inject) = remote_controlled(&mut config, multihop).await;
        let source = projected(&broker, &config);
        let capture = bind(&broker);
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .unwrap();
        for v6 in [false, true] {
            let mut app = packet(&config, v6, 17, &vec![0x96; 1600], false, false);
            if !v6 {
                app[6] = 0x40;
                fix_wire(&mut app, 20, 17);
            }
            capture.try_send(&app).unwrap();
            let feedback = capture_bytes(&capture).await;
            let offset = if v6 { 40 } else { 20 };
            assert!(feedback.len() <= if v6 { 1280 } else { 576 });
            assert_eq!(wire_sum(&feedback, offset, if v6 { 58 } else { 1 }), [0, 0]);
            assert_eq!(&feedback[offset + 8..], &app[..feedback.len() - offset - 8]);
            assert_eq!(&feedback[offset + 6..offset + 8], &config.mtu.to_be_bytes());
            assert!(
                tokio::time::timeout(Duration::from_millis(30), observations.recv())
                    .await
                    .is_err()
            );
            let mut inbound =
                application_reply(&packet(&config, v6, 17, &vec![0x75; 1400], true, false));
            if !v6 {
                inbound[6] = 0x40;
                fix_wire(&mut inbound, 20, 17);
            }
            inject
                .send(Packet::<[u8]>::copy_from(&inbound).try_into_ip().unwrap())
                .await
                .unwrap();
            let feedback = observed(&mut observations).await;
            assert!(feedback.len() <= if v6 { 1280 } else { 576 });
            assert_eq!(wire_sum(&feedback, offset, if v6 { 58 } else { 1 }), [0, 0]);
            assert_eq!(&feedback[offset + 6..offset + 8], &1280u16.to_be_bytes());
            assert_eq!(
                &feedback[offset + 8..],
                &inbound[..feedback.len() - offset - 8]
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(30), capture.reply())
                    .await
                    .is_err(),
                "target PMTU sent to app"
            );
        }
        client.shutdown().await;
        drop((owner, check, client));
        assert_eq!(credit.used(), 0);
        remote.stop().await;
    }
}

fn fragments(bytes: &[u8], quantum: usize) -> Vec<Vec<u8>> {
    let v4 = bytes[0] >> 4 == 4;
    let prefix = if v4 { 20 } else { 40 };
    bytes[prefix..]
        .chunks(quantum)
        .enumerate()
        .map(|(index, piece)| {
            let offset = index * quantum;
            let more = prefix + offset + piece.len() < bytes.len();
            let mut packet = bytes[..prefix].to_vec();
            if v4 {
                packet[2..4].copy_from_slice(&((prefix + piece.len()) as u16).to_be_bytes());
                packet[6..8].copy_from_slice(
                    &((offset as u16 / 8) | if more { 0x2000 } else { 0 }).to_be_bytes(),
                );
                packet[10..12].fill(0);
                let sum = internet_checksum::checksum(&packet);
                packet[10..12].copy_from_slice(&sum);
            } else {
                packet[6] = 44;
                packet[4..6].copy_from_slice(&((8 + piece.len()) as u16).to_be_bytes());
                packet.extend_from_slice(&[bytes[6], 0]);
                packet.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
                packet.extend_from_slice(&0x24681357u32.to_be_bytes());
            }
            packet.extend_from_slice(piece);
            packet
        })
        .collect()
}
fn rejoin(mut packets: Vec<Vec<u8>>) -> Vec<u8> {
    let v4 = packets[0][0] >> 4 == 4;
    let offset = |packet: &Vec<u8>| {
        if v4 {
            usize::from(u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff) * 8
        } else {
            usize::from(u16::from_be_bytes([packet[42], packet[43]]) & 0xfff8)
        }
    };
    packets.sort_by_key(&offset);
    let mut result = packets[0][..if v4 { 20 } else { 40 }].to_vec();
    if !v4 {
        result[6] = packets[0][40];
    }
    let prefix = result.len();
    for packet in packets {
        assert_eq!(offset(&packet), result.len() - prefix);
        if v4 {
            assert_eq!(internet_checksum::checksum(&packet[..20]), [0, 0]);
        }
        result.extend_from_slice(&packet[if v4 { 20 } else { 48 }..]);
    }
    let length = result.len();
    if v4 {
        result[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        result[6..8].fill(0);
        result[10..12].fill(0);
        let sum = internet_checksum::checksum(&result[..20]);
        result[10..12].copy_from_slice(&sum);
    } else {
        result[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
    }
    result
}

#[tokio::test]
async fn translated_fragments_are_consumed_and_sized_in_both_crypto_directions() {
    for multihop in [false, true] {
        let (broker, _root, credit) = broker();
        let mut config = config();
        let (remote, mut observations, inject) = remote_controlled(&mut config, multihop).await;
        let source = projected(&broker, &config);
        let capture = bind(&broker);
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .unwrap();
        for (v6, source_fragmented) in [(false, false), (false, true), (true, true)] {
            let app = packet(&config, v6, 17, &vec![0x97; 1600], false, false);
            // IPv4 routers can fragment; IPv6 can only preserve source permission.
            if source_fragmented {
                for fragment in fragments(&app, 800).into_iter().rev() {
                    capture.try_send(&fragment).unwrap();
                }
            } else {
                capture.try_send(&app).unwrap();
            }
            let mut wire_fragments = vec![
                observed(&mut observations).await,
                observed(&mut observations).await,
            ];
            assert!(
                wire_fragments
                    .iter()
                    .all(|packet| packet.len() <= usize::from(config.mtu))
            );
            let wire = rejoin(std::mem::take(&mut wire_fragments));
            assert_eq!(
                wire,
                packet(&config, v6, 17, &vec![0x97; 1600], true, false)
            );
            assert_eq!(wire_sum(&wire, if v6 { 40 } else { 20 }, 17), [0, 0]);
            let inbound = application_reply(&wire);
            if source_fragmented {
                for fragment in fragments(&inbound, 800).into_iter().rev() {
                    inject
                        .send(Packet::<[u8]>::copy_from(&fragment).try_into_ip().unwrap())
                        .await
                        .unwrap();
                }
            } else {
                inject
                    .send(Packet::<[u8]>::copy_from(&inbound).try_into_ip().unwrap())
                    .await
                    .unwrap();
            }
            let captured = vec![capture_bytes(&capture).await, capture_bytes(&capture).await];
            assert!(captured.iter().all(|packet| packet.len() <= 1280));
            assert_eq!(rejoin(captured), application_reply(&app));
        }
        client.shutdown().await;
        drop((owner, check, client));
        assert_eq!(credit.used(), 0);
        remote.stop().await;
    }
}

#[tokio::test]
async fn unavailable_family_and_translation_refusals_never_reach_crypto_consumers() {
    let (broker, _root, credit) = broker();
    let mut config = config();
    config.tunnel.addresses.retain(|address| address.is_ipv4());
    config.ipv6_gateway = None;
    let (remote, mut observations, _inject) = remote_controlled(&mut config, false).await;
    let source = projected(&broker, &config);
    let capture = bind(&broker);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
        .await
        .unwrap();
    capture
        .try_send(&packet(&config, true, 17, b"no-v6-target", false, false))
        .unwrap();
    capture
        .try_send(&packet(
            &config,
            false,
            253,
            b"unknown-semantics",
            false,
            false,
        ))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), observations.recv())
            .await
            .is_err()
    );
    {
        let path = owner.path.lock().unwrap();
        assert_eq!(path.summary().refused(TranslationError::Family), 1);
        assert_eq!(
            path.summary()
                .refused(TranslationError::UnsupportedTranslation),
            1
        );
        assert_eq!(path.summary().refused(TranslationError::BackendRefused), 0);
    }
    let app = packet(&config, false, 17, b"supported-after-refusal", false, false);
    capture.try_send(&app).unwrap();
    observed(&mut observations).await;
    assert_eq!(capture_bytes(&capture).await, application_reply(&app));
    client.shutdown().await;
    drop((owner, check, client));
    assert_eq!(credit.used(), 0);
    remote.stop().await;
}

#[tokio::test]
async fn retired_translated_bytes_and_assembly_never_enter_an_identical_or_rotated_successor() {
    for rotate in [false, true] {
        let (broker, _root, credit) = broker();
        let mut config = config();
        let (remote, mut observations, _inject) = remote_controlled(&mut config, false).await;
        let source = projected(&broker, &config);
        let capture = bind(&broker);
        let session = capture.capability().unwrap();
        let sink = session.sink().unwrap();
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let old = owner.control.capability();
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .unwrap();
        let app = packet(&config, false, 17, b"blocked-old-return", false, false);
        capture.try_send(&app).unwrap();
        observed(&mut observations).await;
        let mut blocked = tokio::time::timeout(Duration::from_secs(2), capture.reply())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            blocked.write(|_| Err(io::ErrorKind::WouldBlock.into())),
            RelayWriteOutcome::Retry
        ));
        let incomplete = packet(&config, false, 17, &[0x79; 900], false, false);
        let pieces = fragments(&incomplete, 480);
        capture.try_send(&pieces[0]).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), observations.recv())
                .await
                .is_err()
        );
        client.shutdown().await;
        assert!(session.current());
        assert!(!old.current());
        assert!(
            owner.path.lock().unwrap().deadline().is_none(),
            "retired assembly retained its deadline"
        );
        drop((owner, check, client));
        assert_eq!(credit.used(), 0);
        remote.stop().await;

        if rotate {
            config.tunnel.addresses = vec![
                "10.12.34.57".parse().unwrap(),
                "fd00:1234::57".parse().unwrap(),
            ];
        }
        let (remote, mut observations, _inject) = remote_controlled(&mut config, false).await;
        let source = projected(&broker, &config);
        capture
            .acknowledge_request(&broker.pending_request().unwrap())
            .unwrap();
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        assert!(!old.same_attempt(&owner.control.capability()));
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .unwrap();
        assert!(matches!(
            blocked.write_to(&sink, |_| panic!("old bytes reached successor")),
            RelayWriteOutcome::Stale
        ));
        capture.try_send(&pieces[1]).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), observations.recv())
                .await
                .is_err(),
            "old first fragment entered successor assembly"
        );
        let app = packet(&config, false, 17, b"fresh-successor-nonce", false, false);
        capture.try_send(&app).unwrap();
        assert_eq!(
            observed(&mut observations).await,
            packet(&config, false, 17, b"fresh-successor-nonce", true, false)
        );
        assert_eq!(capture_bytes(&capture).await, application_reply(&app));
        // Local uses the same session and current sink, not the retired target.
        let (fd, consumer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        session
            .with_sink(&sink, || fd.send(b"local-stand-in"))
            .unwrap()
            .unwrap();
        consumer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut local = [0; 32];
        let count = consumer.recv(&mut local).unwrap();
        assert_eq!(&local[..count], b"local-stand-in");
        client.shutdown().await;
        drop((owner, check, client));
        assert_eq!(credit.used(), 0);
        remote.stop().await;
    }
}
