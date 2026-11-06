use super::*;
use crate::buffer_budget::BufferBudget;
use talpid_types::relay_flow::{RelayAttemptOwner, RelayCaptureGeneration, RelayCaptureOwner};

pub(super) const FIXED: RelaySources = RelaySources {
    ipv4: Some(std::net::Ipv4Addr::new(192, 0, 2, 2)),
    ipv6: Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
};
pub(super) const ASSIGNED: RelaySources = RelaySources {
    ipv4: Some(std::net::Ipv4Addr::new(10, 64, 0, 7)),
    ipv6: Some(std::net::Ipv6Addr::new(0xfc00, 0xbbbb, 0, 0, 0, 0, 0, 7)),
};

pub(super) fn address(pair: RelaySources, v4: bool) -> IpAddr {
    if v4 {
        pair.ipv4.unwrap().into()
    } else {
        pair.ipv6.unwrap().into()
    }
}
pub(super) fn remote(v4: bool) -> IpAddr {
    if v4 { "203.0.113.9" } else { "2001:db8:9::9" }
        .parse()
        .unwrap()
}

pub(super) fn mapper() -> (
    AddressTranslator,
    RelayCaptureOwner,
    RelayAttemptOwner,
    BufferBudget,
) {
    let budget = BufferBudget::new(22 * 1024 * 1024);
    let capture = RelayCaptureOwner::new(
        RelayCaptureGeneration::fresh().unwrap(),
        "tun0",
        17,
        FIXED,
        1280,
        &budget,
    )
    .unwrap();
    let attempt = capture.open_attempt(&budget).unwrap();
    attempt.activate().unwrap();
    let mapper = AddressTranslator::new(
        TargetConfig {
            target_id: 1,
            fixed: FIXED,
            assigned: ASSIGNED,
            mtu: 1380,
        },
        attempt.capability(),
        Arc::new(budget.clone()),
    )
    .unwrap();
    (mapper, capture, attempt, budget)
}

// Independent wire oracle: not the production checksum/delta implementation.
pub(super) fn oracle(bytes: &[u8]) -> u16 {
    let sum: u64 = bytes
        .chunks(2)
        .map(|part| u64::from(part[0]) * 256 + u64::from(*part.get(1).unwrap_or(&0)))
        .sum();
    let folded = (sum & 65535) + (sum >> 16);
    let folded = (folded & 65535) + (folded >> 16);
    !(folded as u16)
}

pub(super) fn wire_checksum(bytes: &[u8], offset: usize, protocol: u8) -> u16 {
    let mut input = Vec::new();
    if bytes[0] >> 4 == 4 {
        if protocol != 1 {
            input.extend_from_slice(&bytes[12..20]);
            input.extend_from_slice(&[0, protocol]);
            input.extend_from_slice(&((bytes.len() - offset) as u16).to_be_bytes());
        }
    } else {
        input.extend_from_slice(&bytes[8..40]);
        input.extend_from_slice(&((bytes.len() - offset) as u32).to_be_bytes());
        input.extend_from_slice(&[0, 0, 0, protocol]);
    }
    input.extend_from_slice(&bytes[offset..]);
    oracle(&input)
}

pub(super) fn fix_checksums(bytes: &mut [u8], offset: usize, protocol: u8) {
    if let Some(field) = match protocol {
        6 => Some(16),
        17 => Some(6),
        1 | 58 => Some(2),
        _ => None,
    } {
        bytes[offset + field..offset + field + 2].fill(0);
        let mut value = wire_checksum(bytes, offset, protocol);
        if protocol == 17 && value == 0 {
            value = 65535;
        }
        bytes[offset + field..offset + field + 2].copy_from_slice(&value.to_be_bytes());
    }
    if bytes[0] >> 4 == 4 {
        bytes[10..12].fill(0);
        let value = oracle(&bytes[..offset]);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
}

pub(super) fn packet(source: IpAddr, destination: IpAddr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let offset = if source.is_ipv4() { 20 } else { 40 };
    let mut bytes = vec![0; offset];
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            bytes[0] = 0x45;
            bytes[8] = 64;
            bytes[9] = protocol;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            bytes[0] = 0x60;
            bytes[6] = protocol;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
        }
        _ => panic!("test families"),
    }
    bytes.extend_from_slice(payload);
    let length = (if offset == 20 {
        bytes.len()
    } else {
        payload.len()
    }) as u16;
    if offset == 20 {
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
    } else {
        bytes[4..6].copy_from_slice(&length.to_be_bytes());
    }
    fix_checksums(&mut bytes, offset, protocol);
    bytes
}

pub(super) fn segment(protocol: u8) -> Vec<u8> {
    let mut segment = match protocol {
        6 => {
            let mut bytes = vec![0; 24];
            bytes[12] = 0x60;
            bytes[13] = 0x18;
            bytes[20..24].copy_from_slice(&[1, 1, 1, 1]);
            bytes
        }
        17 => vec![0; 8],
        1 | 58 => {
            let mut bytes = vec![0; 8];
            bytes[0] = if protocol == 1 { 8 } else { 128 };
            bytes
        }
        _ => vec![0; 16],
    };
    segment[..2].copy_from_slice(&[0x51, 0x52]);
    segment[2..4].copy_from_slice(&[0x53, 0x54]);
    if protocol == 1 || protocol == 58 {
        segment[0] = if protocol == 1 { 8 } else { 128 };
        segment[1] = 0;
        segment[4..8].copy_from_slice(&[0x23, 0x45, 0x67, 0x89]);
    }
    segment.extend_from_slice(b"independent receiver nonce");
    if protocol == 17 {
        let n = segment.len() as u16;
        segment[4..6].copy_from_slice(&n.to_be_bytes());
    }
    segment
}

#[test]
fn wire_receivers_see_assigned_source_fixed_destination_and_unchanged_tuple() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for protocol in [6, 17, if v4 { 1 } else { 58 }] {
            let fixed = address(FIXED, v4);
            let assigned = address(ASSIGNED, v4);
            let offset = if v4 { 20 } else { 40 };
            let original = packet(fixed, remote(v4), protocol, &segment(protocol));
            let translated = mapper.translate(&original, Direction::Outbound).unwrap();
            let view = translated.view();
            let wire = view.bytes();
            let expected = packet(assigned, remote(v4), protocol, &segment(protocol));
            assert_eq!(wire, expected);
            assert_eq!(wire_checksum(wire, offset, protocol), 0);
            if v4 {
                assert_eq!(oracle(&wire[..offset]), 0);
            }
            let wrong = {
                let mut wrong = original.clone();
                let value = address_bytes(assigned);
                let start = if v4 { 12 } else { 8 };
                wrong[start..start + value.len()].copy_from_slice(&value);
                wrong
            };
            if protocol == 1 {
                assert_eq!(wire_checksum(&wrong, offset, protocol), 0);
                assert_ne!(oracle(&wrong[..offset]), 0);
            } else {
                assert_ne!(wire_checksum(&wrong, offset, protocol), 0);
            }
            let incoming = packet(remote(v4), assigned, protocol, &segment(protocol));
            let translated = mapper.translate(&incoming, Direction::Inbound).unwrap();
            let view = translated.view();
            assert_eq!(
                view.bytes(),
                packet(remote(v4), fixed, protocol, &segment(protocol))
            );
            assert_eq!(wire_checksum(view.bytes(), offset, protocol), 0);
        }
    }
}

#[test]
fn checksum_seeds_bad_checksums_and_ipv6_udp_zero_are_not_wire_packets() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for protocol in [6, 17, if v4 { 1 } else { 58 }] {
            let mut bytes = packet(address(FIXED, v4), remote(v4), protocol, &segment(protocol));
            let offset = if v4 { 20 } else { 40 };
            let field = match protocol {
                6 => 16,
                17 => 6,
                _ => 2,
            };
            bytes[offset + field..offset + field + 2].copy_from_slice(&[0x12, 0x34]);
            assert!(matches!(
                mapper.translate(&bytes, Direction::Outbound),
                Err(TranslationError::Checksum)
            ));
        }
    }
    let mut bytes = packet(address(FIXED, false), remote(false), 17, &segment(17));
    bytes[46..48].fill(0);
    assert!(matches!(
        mapper.translate(&bytes, Direction::Outbound),
        Err(TranslationError::Checksum)
    ));
}

#[test]
fn udp_zero_is_preserved_in_ipv4_and_computed_zero_is_encoded_as_ffff() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    let mut bytes = packet(address(FIXED, true), remote(true), 17, &segment(17));
    bytes[26..28].fill(0);
    let translated = mapper.translate(&bytes, Direction::Outbound).unwrap();
    assert_eq!(&translated.view().bytes()[26..28], &[0, 0]);
    for v4 in [true, false] {
        let offset = if v4 { 20 } else { 40 };
        let mut wire = packet(
            address(ASSIGNED, v4),
            remote(v4),
            17,
            &[0, 1, 0, 2, 0, 10, 0, 0, 0, 0],
        );
        wire[offset + 6..offset + 8].fill(0);
        let correction = wire_checksum(&wire, offset, 17);
        wire[offset + 8..offset + 10].copy_from_slice(&correction.to_be_bytes());
        fix_checksums(&mut wire, offset, 17);
        assert_eq!(word(&wire, offset + 6), 65535);
        let original = packet(address(FIXED, v4), remote(v4), 17, &wire[offset..]);
        let translated = mapper.translate(&original, Direction::Outbound).unwrap();
        assert_eq!(translated.view().bytes(), wire);
    }
}

#[test]
fn gre_esp_sctp_payloads_are_opaque_and_unknown_or_ah_are_counted_precisely() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        let offset = if v4 { 20 } else { 40 };
        for protocol in [47, 50, 132] {
            let original = packet(address(FIXED, v4), remote(v4), protocol, &segment(protocol));
            let translated = mapper.translate(&original, Direction::Outbound).unwrap();
            assert_eq!(&translated.view().bytes()[offset..], &original[offset..]);
            assert_eq!(
                translated.view().bytes(),
                packet(
                    address(ASSIGNED, v4),
                    remote(v4),
                    protocol,
                    &segment(protocol)
                )
            );
        }
        for protocol in [51, 253] {
            let original = packet(address(FIXED, v4), remote(v4), protocol, &segment(protocol));
            assert!(matches!(
                mapper.translate(&original, Direction::Outbound),
                Err(TranslationError::UnsupportedTranslation)
            ));
        }
    }
    assert_eq!(
        mapper
            .summary()
            .refused(TranslationError::UnsupportedTranslation),
        4
    );
    assert_eq!(
        mapper.summary().refused(TranslationError::BackendRefused),
        0
    );
}

#[test]
fn quoted_errors_translate_both_directions_without_inventing_absent_tcp_bytes() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        let ip = if v4 { 20 } else { 40 };
        let icmp = if v4 { 1 } else { 58 };
        for direction in [Direction::Inbound, Direction::Outbound] {
            let before = address(
                if direction == Direction::Inbound {
                    ASSIGNED
                } else {
                    FIXED
                },
                v4,
            );
            let after = address(
                if direction == Direction::Inbound {
                    FIXED
                } else {
                    ASSIGNED
                },
                v4,
            );
            for protocol in [6, 17, icmp] {
                let payload = segment(protocol);
                let (quote_src, quote_dst) = if direction == Direction::Inbound {
                    (before, remote(v4))
                } else {
                    (remote(v4), before)
                };
                let (new_src, new_dst) = if direction == Direction::Inbound {
                    (after, remote(v4))
                } else {
                    (remote(v4), after)
                };
                let quoted = packet(quote_src, quote_dst, protocol, &payload);
                let expected = packet(new_src, new_dst, protocol, &payload);
                for length in [ip + 8, ip + 16, ip + 18, quoted.len()] {
                    for kind in if v4 {
                        vec![3, 11, 12]
                    } else {
                        vec![1, 2, 3, 4]
                    } {
                        let mut error = vec![kind, 0, 0, 0, 0, 0, 5, 0];
                        error.extend_from_slice(&quoted[..length]);
                        let (src, dst) = if direction == Direction::Inbound {
                            (remote(v4), before)
                        } else {
                            (before, remote(v4))
                        };
                        let original = packet(src, dst, icmp, &error);
                        let translated = mapper.translate(&original, direction).unwrap();
                        let view = translated.view();
                        let output = view.bytes();
                        assert_eq!(output.len(), original.len());
                        assert_eq!(&output[ip + 8..], &expected[..length]);
                        assert_eq!(wire_checksum(output, ip, icmp), 0);
                        assert_eq!(&output[ip + 4..ip + 8], &original[ip + 4..ip + 8]);
                        if v4 {
                            assert_eq!(oracle(&output[..ip]), 0);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn quotation_wrong_endpoint_nested_error_bad_length_and_truncations_refuse_without_panics() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        let protocol = if v4 { 1 } else { 58 };
        let quote = packet(remote(v4), remote(v4), 6, &segment(6));
        let mut error = vec![if v4 { 3 } else { 2 }, 0, 0, 0, 0, 0, 5, 0];
        error.extend_from_slice(&quote);
        let bytes = packet(remote(v4), address(ASSIGNED, v4), protocol, &error);
        assert!(matches!(
            mapper.translate(&bytes, Direction::Inbound),
            Err(TranslationError::Endpoint)
        ));
        for length in 0..bytes.len() {
            assert!(
                mapper
                    .translate(&bytes[..length], Direction::Inbound)
                    .is_err()
            );
        }
        let nested = packet(address(ASSIGNED, v4), remote(v4), protocol, &error);
        let mut outer_error = vec![if v4 { 3 } else { 2 }, 0, 0, 0, 0, 0, 5, 0];
        outer_error.extend_from_slice(&nested);
        let outer = packet(remote(v4), address(ASSIGNED, v4), protocol, &outer_error);
        assert!(matches!(
            mapper.translate(&outer, Direction::Inbound),
            Err(TranslationError::UnsupportedTranslation)
        ));
    }
}

#[test]
fn ipv4_options_and_ipv6_hop_destination_and_inactive_routing_headers_survive() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    let mut v4 = packet(address(FIXED, true), remote(true), 17, &segment(17));
    v4.splice(20..20, [148, 4, 0, 0]);
    v4[0] = 0x46;
    let n = v4.len() as u16;
    v4[2..4].copy_from_slice(&n.to_be_bytes());
    fix_checksums(&mut v4, 24, 17);
    let translated = mapper.translate(&v4, Direction::Outbound).unwrap();
    assert_eq!(&translated.view().bytes()[20..24], &[148, 4, 0, 0]);
    assert_eq!(oracle(&translated.view().bytes()[..24]), 0);
    let mut v6 = packet(address(FIXED, false), remote(false), 17, &segment(17));
    v6.splice(
        40..40,
        [
            60, 0, 5, 2, 0, 0, 0, 0, 43, 0, 1, 4, 0, 0, 0, 0, 17, 0, 2, 0, 0, 0, 0, 0,
        ],
    );
    v6[6] = 0;
    let n = (v6.len() - 40) as u16;
    v6[4..6].copy_from_slice(&n.to_be_bytes());
    let translated = mapper.translate(&v6, Direction::Outbound).unwrap();
    assert_eq!(&translated.view().bytes()[40..64], &v6[40..64]);
    assert_eq!(wire_checksum(translated.view().bytes(), 64, 17), 0);
    v6[59] = 1;
    assert!(matches!(
        mapper.translate(&v6, Direction::Outbound),
        Err(TranslationError::UnsupportedTranslation)
    ));
}

#[test]
fn full_and_retired_attempt_cannot_produce_or_handoff_bytes() {
    let (mut mapper, capture, attempt, budget) = mapper();
    let bytes = packet(address(FIXED, true), remote(true), 17, &segment(17));
    let before = budget.used();
    let all = budget.reserve(budget.limit() - before).unwrap();
    assert!(matches!(
        mapper.translate(&bytes, Direction::Outbound),
        Err(TranslationError::Full)
    ));
    drop(all);
    let packet = mapper.translate(&bytes, Direction::Outbound).unwrap();
    attempt.retire();
    assert!(matches!(
        packet.handoff(|_| panic!("retired handoff")),
        Err(RelayFlowError::Stale)
    ));
    assert!(matches!(
        mapper.translate(&bytes, Direction::Outbound),
        Err(TranslationError::Stale)
    ));
    assert_eq!(budget.used(), before);
    let successor = capture.open_attempt(&budget).unwrap();
    successor.activate().unwrap();
    assert!(matches!(
        mapper.translate(&bytes, Direction::Outbound),
        Err(TranslationError::Stale)
    ));
}
