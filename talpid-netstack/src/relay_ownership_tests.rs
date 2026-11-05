use crate::buffer_budget::BufferBudget;
use std::{io, sync::Arc, time::Duration};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBuffer, RelayCaptureGeneration, RelayCaptureOwner, RelayFlowError,
    RelaySources, RelayWriteOutcome,
};

fn capture(budget: &BufferBudget) -> RelayCaptureOwner {
    RelayCaptureOwner::new(
        RelayCaptureGeneration::fresh().unwrap(),
        "tun0",
        0x1234_5678_0000_0063,
        RelaySources {
            ipv4: Some("10.64.0.2".parse().unwrap()),
            ipv6: Some("fc00::2".parse().unwrap()),
        },
        1420,
        budget,
    )
    .unwrap()
}

#[test]
fn capture_identity_is_immutable_full_width_and_replacement_is_distinct() {
    let budget = BufferBudget::new(4096);
    let first = capture(&budget);
    let second = capture(&budget);
    assert_ne!(first.identity().generation, second.identity().generation);
    assert_eq!(first.identity().interface, "tun0");
    assert_eq!(first.identity().network_handle, 0x1234_5678_0000_0063);
    assert_eq!(first.identity().mtu, 1420);
    assert!(
        first
            .identity()
            .sources
            .contains("10.64.0.2".parse().unwrap())
    );
    assert!(
        first
            .identity()
            .sources
            .contains("fc00::2".parse().unwrap())
    );
    assert!(
        !first
            .identity()
            .sources
            .contains("10.64.0.3".parse().unwrap())
    );
    drop(first);
    drop(second);
    assert_eq!(budget.used(), 0);
}

#[test]
fn pending_attempt_cannot_produce_or_handoff_application_bytes() {
    let budget = BufferBudget::new(4096);
    let capture = capture(&budget);
    let owner = capture.open_attempt(&budget).unwrap();
    let attempt = owner.capability();
    assert!(!attempt.current());
    assert!(matches!(
        attempt.with_current(|| panic!("pending write")),
        Err(RelayFlowError::Stale)
    ));
    assert!(matches!(
        attempt.packet(RelayBuffer::copy_from(b"app", &budget).unwrap()),
        Err(RelayFlowError::Stale)
    ));
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);
    assert!(capture.open_attempt(&budget).is_err());
    owner.activate().unwrap();
    let packet = attempt
        .packet(RelayBuffer::copy_from(b"app", &budget).unwrap())
        .unwrap();
    let mut consumer = Vec::new();
    packet
        .handoff(|bytes| consumer.extend_from_slice(bytes))
        .unwrap();
    assert_eq!(consumer, b"app");
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);
}

#[test]
fn blocked_queue_retains_old_authority_and_charge_across_identical_replacement() {
    let budget = BufferBudget::new(4096);
    let capture = capture(&budget);
    let old = capture.open_attempt(&budget).unwrap();
    old.activate().unwrap();
    let mut packet = old
        .capability()
        .packet(RelayBuffer::copy_from(b"old", &budget).unwrap())
        .unwrap();
    let view = packet.view();
    assert!(matches!(
        packet.write(|_| Err(io::ErrorKind::WouldBlock.into())),
        RelayWriteOutcome::Retry
    ));
    let blocked_charge = budget.used();
    old.retire();
    let replacement = capture.open_attempt(&budget).unwrap();
    replacement.activate().unwrap();
    drop(old);
    assert!(replacement.capability().current());
    assert_eq!(budget.used(), blocked_charge + BUFFER_OVERHEAD);
    assert!(matches!(
        packet.write(|_| panic!("old bytes reached replacement")),
        RelayWriteOutcome::Stale
    ));
    drop(packet);
    assert_eq!(budget.used(), blocked_charge + BUFFER_OVERHEAD);
    assert_eq!(view.bytes(), b"old");
    assert!(!view.attempt().current());
    drop(view);
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);
    let mut fresh = replacement
        .capability()
        .packet(RelayBuffer::copy_from(b"fresh", &budget).unwrap())
        .unwrap();
    let mut consumer = Vec::new();
    assert!(matches!(
        fresh.write(|bytes| {
            consumer.extend_from_slice(bytes);
            Ok(bytes.len())
        }),
        RelayWriteOutcome::Written
    ));
    assert_eq!(consumer, b"fresh");
    assert!(matches!(
        fresh.write(|_| panic!("duplicate write")),
        RelayWriteOutcome::Stale
    ));
    drop(fresh);
    drop(replacement);
    drop(capture);
    assert_eq!(budget.used(), 0);
}

#[test]
fn retired_capture_cannot_inject_into_identically_configured_successor() {
    let budget = BufferBudget::new(4096);
    let first = capture(&budget);
    let old = first.open_attempt(&budget).unwrap();
    old.activate().unwrap();
    let packet = old
        .capability()
        .packet(RelayBuffer::copy_from(b"old capture", &budget).unwrap())
        .unwrap();
    first.retire();
    assert!(first.open_attempt(&budget).is_err());
    let second = capture(&budget);
    let next = second.open_attempt(&budget).unwrap();
    next.activate().unwrap();
    assert!(matches!(
        packet.handoff(|_| panic!("stale handoff")),
        Err(RelayFlowError::Stale)
    ));
    drop(first);
    drop(old);
    assert!(next.capability().current());
    drop(next);
    drop(second);
    assert_eq!(budget.used(), 0);
}

#[test]
fn last_view_keeps_actual_storage_and_owners_charged_after_lifecycle_cancellation() {
    let budget = BufferBudget::new(4096);
    let capture = capture(&budget);
    let owner = capture.open_attempt(&budget).unwrap();
    owner.activate().unwrap();
    let packet = owner
        .capability()
        .packet(RelayBuffer::copy_from(b"retained", &budget).unwrap())
        .unwrap();
    let view = packet.view();
    let last = view.clone();
    let used = budget.used();
    drop(owner);
    drop(capture);
    drop(packet);
    drop(view);
    assert_eq!(budget.used(), used);
    assert_eq!(last.bytes(), b"retained");
    assert!(!last.attempt().current());
    drop(last);
    assert_eq!(budget.used(), 0);
}

#[test]
fn retry_rechecks_authority_and_short_zero_fatal_writes_retire_only_their_owner() {
    for kind in 0..3 {
        let budget = BufferBudget::new(4096);
        let capture = capture(&budget);
        let owner = capture.open_attempt(&budget).unwrap();
        owner.activate().unwrap();
        let mut packet = owner
            .capability()
            .packet(RelayBuffer::copy_from(b"whole packet", &budget).unwrap())
            .unwrap();
        assert!(matches!(
            packet.write(|_| Err(io::ErrorKind::WouldBlock.into())),
            RelayWriteOutcome::Retry
        ));
        let outcome = packet.write(|bytes| match kind {
            0 => Ok(0),
            1 => Ok(bytes.len() - 1),
            _ => Err(io::ErrorKind::BrokenPipe.into()),
        });
        match outcome {
            RelayWriteOutcome::Fatal(error) => assert_eq!(
                error.kind(),
                if kind < 2 {
                    io::ErrorKind::WriteZero
                } else {
                    io::ErrorKind::BrokenPipe
                }
            ),
            other => panic!("unexpected write: {other:?}"),
        }
        assert!(!owner.capability().current());
        assert!(matches!(
            packet.write(|_| panic!("partial retry")),
            RelayWriteOutcome::Stale
        ));
        let next = capture.open_attempt(&budget).unwrap();
        next.activate().unwrap();
        drop(owner);
        assert!(next.capability().current());
    }
}

#[test]
fn budget_refuses_before_copy_and_views_do_not_mint_credit() {
    let budget = BufferBudget::new(3 * BUFFER_OVERHEAD + 8);
    let capture = capture(&budget);
    let owner = capture.open_attempt(&budget).unwrap();
    owner.activate().unwrap();
    let packet = owner
        .capability()
        .packet(RelayBuffer::copy_from(b"12345678", &budget).unwrap())
        .unwrap();
    let used = budget.used();
    let view = packet.view();
    let last = view.clone();
    assert_eq!(budget.used(), used);
    assert!(matches!(
        RelayBuffer::copy_from(b"another", &budget),
        Err(RelayFlowError::Full)
    ));
    drop(packet);
    drop(view);
    assert_eq!(budget.used(), used);
    drop(last);
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);
    assert!(RelayBuffer::copy_from(b"recovery", &budget).is_ok());
}

#[test]
fn capture_and_attempt_retirement_are_ordered_after_inflight_checked_operation() {
    for retire_capture in [false, true] {
        let budget = BufferBudget::new(4096);
        let capture = Arc::new(capture(&budget));
        let owner = Arc::new(capture.open_attempt(&budget).unwrap());
        owner.activate().unwrap();
        let attempt = owner.capability();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            attempt.with_current(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (retired_tx, retired_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let c = capture.clone();
        let a = owner.clone();
        let retire = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            if retire_capture {
                c.retire();
            } else {
                a.retire();
            }
            retired_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(retired_rx.recv_timeout(Duration::from_millis(100)).is_err());
        release_tx.send(()).unwrap();
        worker.join().unwrap().unwrap();
        retired_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        retire.join().unwrap();
        assert!(!owner.capability().current());
    }
}
