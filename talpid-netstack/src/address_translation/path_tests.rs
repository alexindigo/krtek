use super::{tests::*, *};
use crate::{
    buffer_budget::BufferBudget,
    packet_sizing::{Emission, FeedbackSide},
};
use std::{
    io,
    time::{Duration, Instant},
};
use talpid_types::relay_flow::{RelayAttemptOwner, RelayCaptureOwner, RelayWriteOutcome};

#[path = "feedback_tests.rs"]
mod feedback_tests;

fn path() -> (
    TargetPacketPath,
    RelayCaptureOwner,
    RelayAttemptOwner,
    BufferBudget,
) {
    let (mapper, capture, attempt, budget) = mapper();
    let config = mapper.config();
    drop(mapper);
    (
        TargetPacketPath::new(config, attempt.capability(), Arc::new(budget.clone())).unwrap(),
        capture,
        attempt,
        budget,
    )
}

fn packets(outcome: TranslationOutcome) -> Emission {
    match outcome {
        TranslationOutcome::Packets(packets) => packets,
        _ => panic!("expected emission"),
    }
}

fn receive(mut emission: Emission) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    while let Some(mut packet) = emission.pop() {
        assert!(matches!(
            packet.write(|bytes| {
                output.push(bytes.to_vec());
                Ok(bytes.len())
            }),
            RelayWriteOutcome::Written
        ));
    }
    output
}

fn large(v4: bool, source: IpAddr, destination: IpAddr, df: bool) -> Vec<u8> {
    let mut payload = segment(17);
    payload.extend((0..3200).map(|n| (n % 251) as u8));
    let length = payload.len() as u16;
    payload[4..6].copy_from_slice(&length.to_be_bytes());
    let mut bytes = packet(source, destination, 17, &payload);
    if v4 && df {
        bytes[6] = 0x40;
        fix_checksums(&mut bytes, 20, 17);
    }
    bytes
}

// Independent source fragment encoder, intentionally not production sizing.
fn source_fragments(bytes: &[u8], quantum: usize, v6_boundary: usize) -> Vec<Vec<u8>> {
    let v4 = bytes[0] >> 4 == 4;
    let boundary = if v4 {
        usize::from(bytes[0] & 15) * 4
    } else {
        v6_boundary
    };
    let mut output = Vec::new();
    for (index, piece) in bytes[boundary..].chunks(quantum).enumerate() {
        let offset = index * quantum;
        let more = offset + piece.len() != bytes.len() - boundary;
        let mut fragment = bytes[..boundary].to_vec();
        if v4 {
            fragment[2..4].copy_from_slice(&((boundary + piece.len()) as u16).to_be_bytes());
            fragment[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
            fragment[6..8].copy_from_slice(
                &(((offset / 8) as u16) | if more { 0x2000 } else { 0 }).to_be_bytes(),
            );
            fragment[10..12].fill(0);
            let value = oracle(&fragment);
            fragment[10..12].copy_from_slice(&value.to_be_bytes());
        } else {
            let next = if boundary == 40 { 6 } else { 40 };
            let protocol = fragment[next];
            fragment[next] = 44;
            fragment.extend_from_slice(&[protocol, 0]);
            fragment.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
            fragment.extend_from_slice(&0x12345678u32.to_be_bytes());
            fragment[4..6]
                .copy_from_slice(&((boundary + 8 + piece.len() - 40) as u16).to_be_bytes());
        }
        fragment.extend_from_slice(piece);
        output.push(fragment);
    }
    output
}

// Independent receiver reconstructs by wire offsets, not translator round-trip.
fn rejoin(fragments: &[Vec<u8>], v6_boundary: usize) -> Vec<u8> {
    let v4 = fragments[0][0] >> 4 == 4;
    let mut parts = Vec::new();
    let mut prefix = Vec::new();
    for bytes in fragments {
        let boundary = if v4 {
            usize::from(bytes[0] & 15) * 4
        } else {
            v6_boundary
        };
        let offset = if v4 {
            usize::from(word(bytes, 6) & 0x1fff) * 8
        } else {
            usize::from(word(bytes, boundary + 2) & 0xfff8)
        };
        if v4 {
            assert_eq!(oracle(&bytes[..boundary]), 0);
        }
        if offset == 0 {
            prefix = bytes[..boundary].to_vec();
            if !v4 {
                prefix[if boundary == 40 { 6 } else { 40 }] = bytes[boundary];
            }
        }
        parts.push((offset, bytes[boundary + if v4 { 0 } else { 8 }..].to_vec()));
    }
    parts.sort_by_key(|part| part.0);
    let mut expected = 0;
    for (offset, data) in parts {
        assert_eq!(offset, expected);
        expected += data.len();
        prefix.extend_from_slice(&data);
    }
    let length = prefix.len();
    if v4 {
        prefix[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        prefix[6..8].fill(0);
        prefix[10..12].fill(0);
        let size = usize::from(prefix[0] & 15) * 4;
        let value = oracle(&prefix[..size]);
        prefix[10..12].copy_from_slice(&value.to_be_bytes());
    } else {
        prefix[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
    }
    prefix
}

#[test]
fn out_of_order_split_transport_fragments_reach_independent_receiver_in_both_directions() {
    let (mut path, _capture, _attempt, _) = path();
    let now = Instant::now();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (source, destination) = if direction == Direction::Outbound {
                (address(FIXED, v4), remote(v4))
            } else {
                (remote(v4), address(ASSIGNED, v4))
            };
            let original = packet(source, destination, 6, &segment(6));
            let pieces = source_fragments(&original, 8, 40);
            let mut final_packet = None;
            for piece in pieces.iter().rev() {
                let result = path.process(piece, direction, 1280, now).unwrap();
                match result {
                    TranslationOutcome::Packets(output) => final_packet = Some(receive(output)),
                    TranslationOutcome::PendingFragments => (),
                    _ => panic!("no feedback"),
                }
            }
            let output = final_packet.unwrap();
            assert_eq!(output.len(), 1);
            let offset = if v4 { 20 } else { 40 };
            assert_eq!(wire_checksum(&output[0], offset, 6), 0);
            assert_eq!(
                &output[0][offset..offset + 16],
                &original[offset..offset + 16]
            );
            assert_eq!(&output[0][offset + 18..], &original[offset + 18..]);
            let expected = if direction == Direction::Outbound {
                packet(address(ASSIGNED, v4), remote(v4), 6, &segment(6))
            } else {
                packet(remote(v4), address(FIXED, v4), 6, &segment(6))
            };
            assert_eq!(&output[0][offset..], &expected[offset..]);
        }
    }
}

#[test]
fn overlap_conflict_tombstones_expire_at_original_deadline_and_do_not_extend() {
    let (mut path, _capture, _attempt, _) = path();
    let now = Instant::now();
    let original = large(true, address(FIXED, true), remote(true), false);
    let pieces = source_fragments(&original, 512, 40);
    assert!(matches!(
        path.process(&pieces[0], Direction::Outbound, 1280, now),
        Ok(TranslationOutcome::PendingFragments)
    ));
    let deadline = path.deadline().unwrap();
    assert!(matches!(
        path.process(
            &pieces[0],
            Direction::Outbound,
            1280,
            now + Duration::from_secs(10)
        ),
        Err(TranslationError::RejectedFragment)
    ));
    assert_eq!(path.deadline(), Some(deadline));
    assert!(matches!(
        path.process(
            &pieces[1],
            Direction::Outbound,
            1280,
            deadline - Duration::from_nanos(1)
        ),
        Err(TranslationError::RejectedFragment)
    ));
    path.maintain(deadline);
    assert_eq!(path.deadline(), None);
    let mut last = None;
    for piece in &pieces {
        last = Some(
            path.process(piece, Direction::Outbound, 1280, deadline)
                .unwrap(),
        );
    }
    assert!(matches!(last, Some(TranslationOutcome::Packets(_))));
}

#[test]
fn output_mtu_is_directional_and_ptb_quotes_the_sender_view() {
    let (mut path, _capture, _attempt, _) = path();
    let now = Instant::now();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (source, destination) = if direction == Direction::Outbound {
                (address(FIXED, v4), remote(v4))
            } else {
                (remote(v4), address(ASSIGNED, v4))
            };
            let original = large(v4, source, destination, true);
            let side = if direction == Direction::Outbound {
                FeedbackSide::App
            } else {
                FeedbackSide::Target
            };
            assert!(
                matches!(path.process(&original, direction, 1280, now), Ok(TranslationOutcome::FeedbackQueued(actual)) if actual == side)
            );
            let mut feedback = path.take_feedback().unwrap();
            assert_eq!(feedback.side(), side);
            let mut wire = Vec::new();
            assert!(matches!(
                feedback.write(|bytes| {
                    wire.extend_from_slice(bytes);
                    Ok(bytes.len())
                }),
                RelayWriteOutcome::Written
            ));
            let ip = if v4 { 20 } else { 40 };
            assert!(wire.len() <= if v4 { 576 } else { 1280 });
            assert_eq!(wire_checksum(&wire, ip, if v4 { 1 } else { 58 }), 0);
            assert_eq!(&wire[ip + 8..], &original[..wire.len() - ip - 8]);
            let mtu = if direction == Direction::Outbound {
                1380
            } else {
                1280
            };
            if v4 {
                assert_eq!(word(&wire, 26), mtu);
                assert_eq!(oracle(&wire[..20]), 0);
            } else {
                assert_eq!(
                    u32::from_be_bytes(wire[44..48].try_into().unwrap()),
                    u32::from(mtu)
                );
            }
            let header = Header::parse(&wire, false).unwrap();
            assert_eq!(header.destination, source);
            assert_eq!(
                header.source,
                if v4 && side == FeedbackSide::App {
                    assert_ne!(header.source, source, "feedback source is local to the app");
                    destination
                } else {
                    address(
                        if side == FeedbackSide::App {
                            FIXED
                        } else {
                            ASSIGNED
                        },
                        v4,
                    )
                }
            );
        }
    }
}

#[test]
fn ipv4_fragments_and_ipv6_source_fragment_boundaries_survive_mtu_sizing() {
    let (mut path, _capture, _attempt, _) = path();
    let now = Instant::now();
    for v4 in [true, false] {
        let mut original = large(v4, address(FIXED, v4), remote(v4), false);
        let boundary = if v4 { 20 } else { 48 };
        if !v4 {
            original.splice(40..40, [17, 0, 5, 2, 0, 0, 0, 0]);
            original[6] = 0;
            let length = (original.len() - 40) as u16;
            original[4..6].copy_from_slice(&length.to_be_bytes());
        }
        let output = if v4 {
            receive(packets(
                path.process(&original, Direction::Outbound, 1280, now)
                    .unwrap(),
            ))
        } else {
            let inputs = source_fragments(&original, 1024, boundary);
            let mut emitted = Vec::new();
            for piece in inputs.iter().rev() {
                match path.process(piece, Direction::Outbound, 1280, now).unwrap() {
                    TranslationOutcome::Packets(packets) => emitted = receive(packets),
                    TranslationOutcome::PendingFragments => (),
                    _ => panic!("source fragments must survive"),
                }
            }
            emitted
        };
        assert!(output.len() > 1 && output.iter().all(|p| p.len() <= 1380));
        let complete = rejoin(&output, boundary);
        assert_eq!(wire_checksum(&complete, boundary, 17), 0);
        assert_eq!(&complete[boundary + 8..], &original[boundary + 8..]);
        assert_eq!(
            Header::parse(&complete, false).unwrap().source,
            address(ASSIGNED, v4)
        );
        if !v4 {
            assert_eq!(&complete[40..48], &original[40..48]);
        }
    }
}

#[test]
fn blocked_feedback_full_rate_limit_and_retirement_retain_charges_and_exact_authority() {
    let (mut path, capture, attempt, budget) = path();
    let now = Instant::now();
    let before = budget.used();
    let original = large(true, remote(true), address(ASSIGNED, true), true);
    let mut held = Vec::new();
    for index in 0..16 {
        let time = now + Duration::from_secs(index / 8);
        assert!(matches!(
            path.process(&original, Direction::Inbound, 1280, time),
            Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::Target))
        ));
        held.push(path.take_feedback().unwrap());
        if index == 7 {
            assert!(matches!(
                path.process(&original, Direction::Inbound, 1280, time),
                Err(TranslationError::RateLimited)
            ));
        }
    }
    assert!(matches!(
        path.process(
            &original,
            Direction::Inbound,
            1280,
            now + Duration::from_secs(2)
        ),
        Err(TranslationError::FeedbackFull)
    ));
    assert!(matches!(
        held[0].write(|_| Err(io::ErrorKind::WouldBlock.into())),
        RelayWriteOutcome::Retry
    ));
    assert_eq!(budget.used(), before);
    attempt.retire();
    let successor = capture.open_attempt(&budget).unwrap();
    successor.activate().unwrap();
    assert!(matches!(
        held[0].write(|_| panic!("old feedback into successor")),
        RelayWriteOutcome::Stale
    ));
    assert!(matches!(
        path.process(&original, Direction::Inbound, 1280, now),
        Err(TranslationError::Stale)
    ));
    drop(path);
    drop(held);
    drop(successor);
    drop(attempt);
    drop(capture);
    assert_eq!(budget.used(), 0);
}

#[test]
fn feedback_suppresses_errors_and_ipv4_multicast_but_keeps_ipv6_multicast_ptb_exception() {
    let (mut path, _capture, _attempt, _) = path();
    let now = Instant::now();
    for v4 in [true, false] {
        let quoted = large(v4, remote(v4), address(FIXED, v4), false);
        let mut body = vec![if v4 { 3 } else { 2 }, 0, 0, 0, 0, 0, 5, 0];
        body.extend_from_slice(&quoted);
        let error = packet(
            address(FIXED, v4),
            remote(v4),
            if v4 { 1 } else { 58 },
            &body,
        );
        let mut error = error;
        if v4 {
            error[6] = 0x40;
            fix_checksums(&mut error, 20, 1);
        }
        assert!(matches!(
            path.process(&error, Direction::Outbound, 1280, now),
            Err(TranslationError::Suppressed)
        ));
    }
    let v4 = large(
        true,
        address(FIXED, true),
        "239.1.1.1".parse().unwrap(),
        true,
    );
    assert!(matches!(
        path.process(&v4, Direction::Outbound, 1280, now),
        Err(TranslationError::Suppressed)
    ));
    let v6 = large(
        false,
        address(FIXED, false),
        "ff02::1".parse().unwrap(),
        false,
    );
    assert!(matches!(
        path.process(&v6, Direction::Outbound, 1280, now),
        Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::App))
    ));
}

#[test]
fn reassembly_limit_refuses_without_eviction_and_expiry_drop_refunds_the_region() {
    let (mut path, _capture, _attempt, budget) = path();
    let now = Instant::now();
    let before = budget.used();
    let bytes = large(true, address(FIXED, true), remote(true), false);
    let mut piece = source_fragments(&bytes, 512, 40).remove(0);
    let mut admitted = 0;
    for id in 0u16..64 {
        piece[4..6].copy_from_slice(&id.to_be_bytes());
        piece[10..12].fill(0);
        let value = oracle(&piece[..20]);
        piece[10..12].copy_from_slice(&value.to_be_bytes());
        match path.process(&piece, Direction::Outbound, 1280, now) {
            Ok(TranslationOutcome::PendingFragments) => admitted += 1,
            Err(TranslationError::Full) => (),
            _ => panic!("capacity must refuse precisely"),
        }
        assert_eq!(budget.used(), before);
    }
    assert!(admitted > 0 && admitted < 64);
    let small = packet(address(FIXED, true), remote(true), 17, &segment(17));
    assert_eq!(
        receive(packets(
            path.process(&small, Direction::Outbound, 1280, now)
                .unwrap()
        ))
        .len(),
        1
    );
    assert_eq!(path.deadline(), Some(now + Duration::from_secs(15)));
    path.maintain(now + Duration::from_secs(15));
    assert_eq!(path.deadline(), None);
    assert!(matches!(
        path.process(
            &piece,
            Direction::Outbound,
            1280,
            now + Duration::from_secs(15)
        ),
        Ok(TranslationOutcome::PendingFragments)
    ));
}

#[test]
fn reserved_feedback_progress_survives_exhausted_application_credit() {
    let (mut path, _capture, _attempt, budget) = path();
    let now = Instant::now();
    let all = budget.reserve(budget.limit() - budget.used()).unwrap();
    let original = large(true, remote(true), address(ASSIGNED, true), true);
    assert!(matches!(
        path.process(&original, Direction::Inbound, 1280, now),
        Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::Target))
    ));
    let small = packet(address(FIXED, true), remote(true), 17, &segment(17));
    assert!(matches!(
        path.process(&small, Direction::Outbound, 1280, now),
        Err(TranslationError::Full)
    ));
    drop(all);
    assert_eq!(
        receive(packets(
            path.process(&small, Direction::Outbound, 1280, now)
                .unwrap()
        ))
        .len(),
        1
    );
}

#[test]
fn fragment_attempt_retirement_and_conflicting_headers_cannot_mix_with_successor() {
    let (mut path, capture, attempt, budget) = path();
    let now = Instant::now();
    let original = large(false, address(FIXED, false), remote(false), false);
    let pieces = source_fragments(&original, 512, 40);
    assert!(matches!(
        path.process(&pieces[0], Direction::Outbound, 1280, now),
        Ok(TranslationOutcome::PendingFragments)
    ));
    let mut conflicting = pieces[1].clone();
    conflicting[40] = 6;
    assert!(matches!(
        path.process(&conflicting, Direction::Outbound, 1280, now),
        Err(TranslationError::RejectedFragment)
    ));
    attempt.retire();
    let successor = capture.open_attempt(&budget).unwrap();
    successor.activate().unwrap();
    let mut next = TargetPacketPath::new(
        path.config(),
        successor.capability(),
        Arc::new(budget.clone()),
    )
    .unwrap();
    assert!(matches!(
        path.process(&pieces[1], Direction::Outbound, 1280, now),
        Err(TranslationError::Stale)
    ));
    for piece in pieces.iter().skip(1) {
        assert!(matches!(
            next.process(piece, Direction::Outbound, 1280, now),
            Ok(TranslationOutcome::PendingFragments)
        ));
    }
    assert!(matches!(
        next.process(&pieces[0], Direction::Outbound, 1280, now),
        Ok(TranslationOutcome::Packets(_))
    ));
}

#[test]
fn ipv4_emission_keeps_first_options_and_only_copied_options_on_later_fragments() {
    let (mut path, _capture, _attempt, _) = path();
    let mut original = large(true, address(FIXED, true), remote(true), false);
    original.splice(20..20, [7, 7, 4, 0, 0, 0, 0, 1, 148, 4, 0, 0]);
    original[0] = 0x48;
    let n = original.len() as u16;
    original[2..4].copy_from_slice(&n.to_be_bytes());
    fix_checksums(&mut original, 32, 17);
    let output = receive(packets(
        path.process(&original, Direction::Outbound, 1280, Instant::now())
            .unwrap(),
    ));
    assert!(output.len() > 1);
    assert_eq!(&output[0][20..32], &original[20..32]);
    for fragment in output.iter().skip(1) {
        assert_eq!(fragment[0] & 15, 6);
        assert_eq!(&fragment[20..24], &[148, 4, 0, 0]);
    }
    let joined = rejoin(&output, 40);
    assert_eq!(wire_checksum(&joined, 32, 17), 0);
    assert_eq!(&joined[40..], &original[40..]);
}

#[test]
fn atomic_ipv6_fragment_does_not_grant_router_fragment_permission() {
    let (mut path, _capture, _attempt, _) = path();
    let now = Instant::now();
    let large = large(false, address(FIXED, false), remote(false), false);
    let atomic = source_fragments(&large, 65528, 40).remove(0);
    assert!(matches!(
        path.process(&atomic, Direction::Outbound, 1280, now),
        Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::App))
    ));
    let small = packet(address(FIXED, false), remote(false), 6, &segment(6));
    let atomic = source_fragments(&small, 65528, 40).remove(0);
    let output = receive(packets(
        path.process(&atomic, Direction::Outbound, 1280, now)
            .unwrap(),
    ));
    assert_eq!(output.len(), 1);
    assert_eq!(output[0][6], 6);
    assert_eq!(wire_checksum(&output[0], 40, 6), 0);
}

#[test]
fn overflow_fragment_is_tombstoned_before_later_valid_pieces_can_restart_it() {
    let (mut path, _capture, _attempt, _) = path();
    let now = Instant::now();
    let original = large(true, address(FIXED, true), remote(true), false);
    let pieces = source_fragments(&original, 512, 40);
    let mut overflow = pieces[0].clone();
    overflow[6..8].copy_from_slice(&0x3fffu16.to_be_bytes());
    overflow[10..12].fill(0);
    let sum = oracle(&overflow[..20]);
    overflow[10..12].copy_from_slice(&sum.to_be_bytes());
    assert!(matches!(
        path.process(&overflow, Direction::Outbound, 1280, now),
        Err(TranslationError::Malformed)
    ));
    assert!(matches!(
        path.process(&pieces[0], Direction::Outbound, 1280, now),
        Err(TranslationError::RejectedFragment)
    ));
    assert_eq!(path.deadline(), Some(now + Duration::from_secs(15)));
}

#[test]
fn other_protocols_keep_valid_checksum_domains_at_the_final_sink() {
    fn crc32c(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82f63b78 } else { 0 };
            }
        }
        !crc
    }
    let (mut path, _capture, _attempt, _) = path();
    let inner = packet(address(FIXED, false), remote(false), 17, &segment(17));
    let mut gre = vec![0x80, 0, 0x86, 0xdd, 0, 0, 0, 0];
    gre.extend_from_slice(&inner);
    let value = oracle(&gre);
    gre[4..6].copy_from_slice(&value.to_be_bytes());
    assert_eq!(oracle(&gre), 0);
    let mut sctp = vec![0x12, 0x34, 0, 80, 0, 1, 0, 1, 0, 0, 0, 0];
    sctp.extend_from_slice(&[0, 3, 0, 20, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4]);
    let crc = crc32c(&sctp);
    sctp[8..12].copy_from_slice(&crc.to_le_bytes());
    let mut esp = vec![0, 0, 0, 1, 0, 0, 0, 1];
    // Opaque passthrough (tunnel-mode IPsec works; transport mode without NAT-T
    // is not supported). This proves byte preservation, not IPsec mode/repair.
    esp.extend_from_slice(&[0x5a; 32]);
    for v4 in [true, false] {
        for (protocol, payload) in [(47, &gre), (50, &esp), (132, &sctp)] {
            for direction in [Direction::Outbound, Direction::Inbound] {
                let (source, destination) = if direction == Direction::Outbound {
                    (address(FIXED, v4), remote(v4))
                } else {
                    (remote(v4), address(ASSIGNED, v4))
                };
                let original = packet(source, destination, protocol, payload);
                let output = receive(packets(
                    path.process(&original, direction, 1280, Instant::now())
                        .unwrap(),
                ));
                let offset = if v4 { 20 } else { 40 };
                let received = &output[0][offset..];
                assert_eq!(received, payload);
                if protocol == 47 {
                    assert_eq!(oracle(received), 0);
                    assert_eq!(wire_checksum(&received[8..], 40, 17), 0);
                } else if protocol == 132 {
                    let expected = u32::from_le_bytes(received[8..12].try_into().unwrap());
                    let mut checked = received.to_vec();
                    checked[8..12].fill(0);
                    assert_eq!(crc32c(&checked), expected);
                    assert_eq!(word(received, 14), 20);
                } else {
                    assert_eq!(&received[..8], &[0, 0, 0, 1, 0, 0, 0, 1]);
                }
            }
        }
    }
}
