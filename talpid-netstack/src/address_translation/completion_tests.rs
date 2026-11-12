use super::*;

fn datagram(v4: bool, direction: Direction, value: u8) -> Vec<u8> {
    let (source, destination) = if direction == Direction::Outbound {
        (address(FIXED, v4), remote(v4))
    } else {
        (remote(v4), address(ASSIGNED, v4))
    };
    let mut bytes = packet(source, destination, 17, &segment(17));
    let ip = if v4 { 20 } else { 40 };
    bytes[ip + 8..].fill(value);
    fix_checksums(&mut bytes, ip, 17);
    if v4 {
        // Legal IPv4 UDP with no transport checksum cannot detect mixed payload.
        bytes[ip + 6..ip + 8].fill(0);
    }
    bytes
}

fn identified(pieces: &[Vec<u8>], v4: bool, id: u16) -> Vec<Vec<u8>> {
    pieces
        .iter()
        .map(|piece| {
            let mut piece = piece.clone();
            if v4 {
                piece[4..6].copy_from_slice(&id.to_be_bytes());
                piece[10..12].fill(0);
                let sum = oracle(&piece[..20]);
                piece[10..12].copy_from_slice(&sum.to_be_bytes());
            } else {
                piece[44..48].copy_from_slice(&u32::from(id).to_be_bytes());
            }
            piece
        })
        .collect()
}

fn complete(
    path: &mut TargetPacketPath,
    pieces: &[Vec<u8>],
    direction: Direction,
    now: Instant,
) -> Vec<u8> {
    let mut output = Vec::new();
    for piece in pieces {
        match path.process(piece, direction, 1280, now).unwrap() {
            TranslationOutcome::PendingFragments => (),
            TranslationOutcome::Packets(packets) => output.extend(receive(packets)),
            _ => panic!("unexpected feedback"),
        }
    }
    assert_eq!(output.len(), 1);
    output.remove(0)
}

#[test]
fn completed_keys_reject_late_fragments_until_completion_guard_expires() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, budget) = path();
            let now = Instant::now();
            let before = budget.used();
            let a = source_fragments(&datagram(v4, direction, b'a'), 24, 40);
            let b = source_fragments(&datagram(v4, direction, b'b'), 24, 40);
            assert_eq!(a.len(), 2);
            assert!(matches!(
                path.process(&a[0], direction, 1280, now),
                Ok(TranslationOutcome::PendingFragments)
            ));
            let completed = now + Duration::from_secs(1);
            assert_eq!(
                receive(packets(
                    path.process(&a[1], direction, 1280, completed).unwrap()
                ))
                .len(),
                1
            );
            let expiry = completed + Duration::from_secs(15);
            assert!(matches!(
                path.process(&a[1], direction, 1280, completed),
                Err(TranslationError::RejectedFragment)
            ));
            assert!(matches!(
                path.process(&b[0], direction, 1280, expiry - Duration::from_nanos(1)),
                Err(TranslationError::RejectedFragment)
            ));
            assert_eq!(
                path.deadline(),
                Some(expiry),
                "late arrivals must not extend the guard"
            );
            path.maintain(expiry);
            assert_eq!(path.deadline(), None);
            let wire = complete(&mut path, &b, direction, expiry);
            let ip = if v4 { 20 } else { 40 };
            assert!(wire[ip + 8..].iter().all(|byte| *byte == b'b'));
            if v4 {
                assert_eq!(word(&wire, ip + 6), 0);
            } else {
                assert_eq!(wire_checksum(&wire, ip, 17), 0);
            }
            assert_eq!(budget.used(), before);
        }
    }
}

#[test]
fn late_checksum_free_ipv4_udp_fragments_cannot_emit_a_mixed_reused_datagram() {
    for direction in [Direction::Outbound, Direction::Inbound] {
        let (mut path, _capture, _attempt, _) = path();
        let now = Instant::now();
        let a = source_fragments(&datagram(true, direction, b'a'), 24, 40);
        let b = source_fragments(&datagram(true, direction, b'b'), 24, 40);
        assert!(
            complete(&mut path, &a, direction, now)[28..]
                .iter()
                .all(|byte| *byte == b'a')
        );
        let late = path.process(&a[1], direction, 1280, now);
        assert!(matches!(
            late,
            Err(TranslationError::RejectedFragment) | Ok(TranslationOutcome::PendingFragments)
        ));
        let reuse = path.process(&b[0], direction, 1280, now);
        if let Ok(TranslationOutcome::Packets(output)) = reuse {
            let wire = receive(output);
            assert!(
                wire[0][28..].iter().all(|byte| *byte == b'b'),
                "mixed old payload reached consumer"
            );
            panic!("reused key was emitted during completion guard");
        }
        assert!(matches!(reuse, Err(TranslationError::RejectedFragment)));
    }
}

#[test]
fn full_completion_guard_evicts_oldest_key_without_limiting_fragment_admission() {
    // Strictly increasing expiries also distinguish oldest-key replacement
    // from repeatedly replacing index zero after swap_remove reorders the Vec.
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, budget) = path();
            let now = Instant::now();
            let before = budget.used();
            let original = datagram(v4, direction, b'x');
            let pieces = source_fragments(&original, 24, 40);
            let rejected = identified(&pieces, v4, u16::MAX);
            assert!(matches!(
                path.process(&rejected[0], direction, 1280, now),
                Ok(TranslationOutcome::PendingFragments)
            ));
            assert!(matches!(
                path.process(&rejected[0], direction, 1280, now),
                Err(TranslationError::RejectedFragment)
            ));
            for id in 0..1024 {
                complete(
                    &mut path,
                    &identified(&pieces, v4, id),
                    direction,
                    now + Duration::from_millis(u64::from(id)),
                );
            }
            let admitted = identified(&pieces, v4, 60000);
            let pressure = now + Duration::from_millis(1024);
            assert!(matches!(
                path.process(&admitted[0], direction, 1280, pressure),
                Ok(TranslationOutcome::PendingFragments)
            ));
            // Admission itself does not discard a protected identity.
            let first = identified(&pieces, v4, 0);
            assert!(matches!(
                path.process(&first[1], direction, 1280, pressure),
                Err(TranslationError::RejectedFragment)
            ));
            for id in 1024..1100 {
                complete(
                    &mut path,
                    &identified(&pieces, v4, id),
                    direction,
                    now + Duration::from_millis(u64::from(id)),
                );
            }
            assert_eq!(
                receive(packets(
                    path.process(
                        &admitted[1],
                        direction,
                        1280,
                        now + Duration::from_millis(1100)
                    )
                    .unwrap()
                ))
                .len(),
                1
            );
            let later = now + Duration::from_secs(14);
            for id in [77, 1024, 60000] {
                let guarded = identified(&pieces, v4, id);
                assert!(
                    matches!(
                        path.process(&guarded[1], direction, 1280, later),
                        Err(TranslationError::RejectedFragment)
                    ),
                    "newer completed key must still be guarded"
                );
            }
            // Exactly keys 0..=76 have been evicted after 77 newer completions.
            // Their tails can start new work before their original guard expiry.
            for id in [76, 0] {
                let evicted = identified(&pieces, v4, id);
                assert!(
                    matches!(
                        path.process(&evicted[1], direction, 1280, later),
                        Ok(TranslationOutcome::PendingFragments)
                    ),
                    "oldest completed key was not evicted"
                );
                let wire = receive(packets(
                    path.process(&evicted[0], direction, 1280, later).unwrap(),
                ));
                assert_eq!(wire.len(), 1);
                assert!(
                    wire[0][if v4 { 28 } else { 48 }..]
                        .iter()
                        .all(|byte| *byte == b'x')
                );
            }
            assert_eq!(
                receive(packets(
                    path.process(&original, direction, 1280, later).unwrap()
                ))
                .len(),
                1
            );
            if !v4 {
                let atomic = identified(&source_fragments(&original, 65528, 40), false, 1024);
                assert_eq!(
                    complete(&mut path, &atomic, direction, later).len(),
                    original.len()
                );
            }
            let expiry = now + Duration::from_secs(15);
            assert!(
                matches!(
                    path.process(
                        &rejected[1],
                        direction,
                        1280,
                        expiry - Duration::from_nanos(1)
                    ),
                    Err(TranslationError::RejectedFragment)
                ),
                "completion eviction must not evict genuine rejection tombstones"
            );
            assert_eq!(path.deadline(), Some(expiry));
            complete(&mut path, &rejected, direction, expiry);
            path.maintain(now + Duration::from_secs(31));
            assert_eq!(path.deadline(), None);
            assert_eq!(budget.used(), before);
            drop(path);
            drop(_attempt);
            drop(_capture);
            assert_eq!(budget.used(), 0);
        }
    }
}
