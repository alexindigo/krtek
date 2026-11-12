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

#[cfg(target_os = "linux")]
#[test]
fn authority_records_follow_actual_activation_sink_switches_and_retirement() {
    use std::sync::{
        Mutex, Once,
        atomic::{AtomicU64, Ordering},
    };
    struct Logger {
        session: AtomicU64,
        records: Mutex<Vec<String>>,
    }
    impl log::Log for Logger {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn flush(&self) {}
        fn log(&self, record: &log::Record<'_>) {
            if record.target() != "talpid_types::relay_flow" {
                return;
            }
            let text = record.args().to_string();
            if text.starts_with(&format!(
                "target-authority session={} ",
                self.session.load(Ordering::Relaxed)
            )) {
                let mut records = self.records.lock().unwrap();
                assert!(records.len() < 16);
                records.push(text);
            }
        }
    }
    static LOGGER: Logger = Logger {
        session: AtomicU64::new(0),
        records: Mutex::new(Vec::new()),
    };
    static START: Once = Once::new();
    START.call_once(|| {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);
    });
    let budget = BufferBudget::new(8192);
    let owner = capture(&budget);
    LOGGER
        .session
        .store(owner.identity().generation.get(), Ordering::Relaxed);
    let target = owner.open_attempt(&budget).unwrap();
    target.activate().unwrap();
    target.activate().unwrap(); // no duplicate ready
    let sink = owner.capability().sink().unwrap();
    owner.suspend_sink(&sink).unwrap();
    owner.resume_sink(&sink).unwrap();
    owner.retire();
    target.retire(); // no duplicate retirement
    let records = LOGGER.records.lock().unwrap();
    assert_eq!(records.len(), 5);
    let mut revision = 0;
    let mut stamp = 0;
    let mut attempt = None;
    for (record, ready) in records.iter().zip([false, true, false, true, false]) {
        let field = |key: &str| {
            record
                .split_whitespace()
                .find_map(|word| word.strip_prefix(key))
                .unwrap()
        };
        assert_eq!(field("clock="), "CLOCK_BOOTTIME");
        assert_eq!(field("clock_valid="), "true");
        assert_eq!(field("ready="), if ready { "true" } else { "false" });
        assert_eq!(field("target="), "1");
        let next = field("revision=").parse::<u64>().unwrap();
        assert!(next > revision);
        revision = next;
        let now = field("boottime_ns=").parse::<u64>().unwrap();
        assert!(now >= stamp && now > 0);
        stamp = now;
        let serial = field("attempt=");
        assert_eq!(*attempt.get_or_insert(serial), serial);
    }
}

#[test]
fn capture_identity_is_immutable_full_width_and_replacement_is_distinct() {
    let budget = BufferBudget::new(4096);
    let first = capture(&budget);
    let second = capture(&budget);
    assert_ne!(first.identity().generation, second.identity().generation);
    let sink = first.capability().sink().unwrap();
    assert_eq!(sink.identity().interface, "tun0");
    assert_eq!(sink.identity().network_handle, Some(0x1234_5678_0000_0063));
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
    drop(sink);
    assert_eq!(budget.used(), 0);
}

#[test]
fn sink_handover_preserves_session_and_exact_target_but_never_old_sink_authority() {
    let budget = BufferBudget::new(8192);
    let owner = capture(&budget);
    let local = owner.capability();
    let first = local.sink().unwrap();
    let target = owner.open_attempt(&budget).unwrap();
    target.activate().unwrap();
    let attempt = target.capability();
    let sources = owner.identity().sources;
    let session = owner.identity().generation.get();
    let mut consumer = Vec::new();
    local
        .with_sink(&first, || consumer.extend_from_slice(b"before"))
        .unwrap();

    owner.suspend_sink(&first).unwrap();
    assert!(local.current(), "expected fd loss retired Local's session");
    assert!(
        !attempt.current(),
        "target ran without a checked current sink"
    );
    assert!(
        local
            .with_sink(&first, || panic!("suspended fd write"))
            .is_err()
    );
    // Positive pre-establish retention may restore only this exact predecessor.
    owner.resume_sink(&first).unwrap();
    assert!(attempt.current());
    owner.suspend_sink(&first).unwrap();
    let invalid_sources = RelaySources {
        ipv4: None,
        ipv6: sources.ipv6,
    };
    assert!(
        owner
            .bind_sink(
                RelayCaptureGeneration::fresh().unwrap(),
                "tun1",
                Some(42),
                invalid_sources,
                1420,
                &budget
            )
            .is_err()
    );
    assert!(
        owner
            .bind_sink(
                RelayCaptureGeneration::fresh().unwrap(),
                "tun1",
                Some(42),
                sources,
                1280,
                &budget
            )
            .is_err()
    );
    assert!(
        owner
            .bind_sink(
                RelayCaptureGeneration::fresh().unwrap(),
                "tun1",
                Some(0),
                sources,
                1420,
                &budget
            )
            .is_err()
    );
    let next = owner
        .bind_sink(
            RelayCaptureGeneration::fresh().unwrap(),
            "tun1",
            Some(0x8765_4321_0000_0042),
            sources,
            1420,
            &budget,
        )
        .unwrap();
    assert_eq!(owner.identity().generation.get(), session);
    assert_eq!(owner.identity().sources, sources);
    assert!(attempt.current());
    assert_eq!(attempt.sink().unwrap().identity().interface, "tun1");
    assert_eq!(next.identity().network_handle, Some(0x8765_4321_0000_0042));
    assert!(
        owner.suspend_sink(&first).is_err(),
        "late old cleanup suspended successor"
    );
    assert!(owner.resume_sink(&first).is_err(), "old epoch resurrected");
    assert!(
        local
            .with_sink(&first, || panic!("old sink received successor bytes"))
            .is_err()
    );
    local
        .with_sink(&next, || consumer.extend_from_slice(b"after"))
        .unwrap();
    assert_eq!(consumer, b"beforeafter");
    owner.suspend_sink(&next).unwrap();
    assert!(
        owner.resume_sink(&first).is_err(),
        "old epoch resumed after a successor existed"
    );
    owner.resume_sink(&next).unwrap();
    let packet = attempt
        .packet(RelayBuffer::copy_from(b"old-target", &budget).unwrap())
        .unwrap();
    target.retire();
    let replacement = owner.open_attempt(&budget).unwrap();
    replacement.activate().unwrap();
    assert!(
        packet
            .handoff(|_| panic!("old target revived by sink change"))
            .is_err()
    );
    owner.retire();
    assert!(!local.current());
    assert!(owner.resume_sink(&next).is_err());
    assert!(
        local
            .with_sink(&next, || panic!("retired session write"))
            .is_err()
    );
    drop(replacement);
    drop(target);
    drop(attempt);
    drop(owner);
    drop(local);
    assert!(budget.used() > 0, "retained sink metadata lost its charge");
    drop(first);
    drop(next);
    assert_eq!(budget.used(), 0);
}

#[test]
fn partial_sink_has_no_managed_handle_and_sink_reservations_are_bounded() {
    let budget = BufferBudget::new(8 * BUFFER_OVERHEAD);
    let sources = RelaySources {
        ipv4: Some("192.0.2.2".parse().unwrap()),
        ipv6: None,
    };
    let owner = RelayCaptureOwner::session(
        RelayCaptureGeneration::fresh().unwrap(),
        sources,
        1280,
        &budget,
    )
    .unwrap();
    let local = owner.capability();
    assert!(local.current());
    assert!(local.sink().is_none());
    let mut held = Vec::new();
    loop {
        match owner.bind_sink(
            RelayCaptureGeneration::fresh().unwrap(),
            "tun-partial",
            None,
            sources,
            1280,
            &budget,
        ) {
            Ok(sink) => {
                assert_eq!(sink.identity().network_handle, None);
                owner.suspend_sink(&sink).unwrap();
                held.push(sink);
            }
            Err(RelayFlowError::Full) => break,
            other => panic!("unexpected binding: {other:?}"),
        }
    }
    assert!(!held.is_empty());
    assert!(budget.used() <= 8 * BUFFER_OVERHEAD);
    drop(held);
    let sink = owner
        .bind_sink(
            RelayCaptureGeneration::fresh().unwrap(),
            "tun-partial",
            None,
            sources,
            1280,
            &budget,
        )
        .unwrap();
    local.with_sink(&sink, || ()).unwrap();
    drop(sink);
    drop(local);
    drop(owner);
    assert_eq!(budget.used(), 0);
}

#[cfg(unix)]
#[test]
fn sink_selection_waits_for_inflight_checked_write_then_refuses_old_descriptor() {
    use std::sync::mpsc;
    let budget = BufferBudget::new(8192);
    let owner = Arc::new(capture(&budget));
    let session = owner.capability();
    let sink = session.sink().unwrap();
    let (entered, in_write) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (output, consumed) = std::os::unix::net::UnixDatagram::pair().unwrap();
    consumed
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let writer = session.clone();
    let selected = sink.clone();
    let write = std::thread::spawn(move || {
        writer.with_sink(&selected, || {
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
            output.send(b"inflight-sink-nonce").unwrap();
        })
    });
    in_write.recv_timeout(Duration::from_secs(2)).unwrap();
    let switcher = owner.clone();
    let old = sink.clone();
    let (attempted, attempt) = mpsc::channel();
    let (suspended, suspension) = mpsc::channel();
    let switch = std::thread::spawn(move || {
        attempted.send(()).unwrap();
        switcher.suspend_sink(&old).unwrap();
        suspended.send(()).unwrap();
    });
    attempt.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(suspension.recv_timeout(Duration::from_millis(50)).is_err());
    release.send(()).unwrap();
    write.join().unwrap().unwrap();
    let mut bytes = [0; 64];
    let count = consumed.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"inflight-sink-nonce");
    suspension.recv_timeout(Duration::from_secs(2)).unwrap();
    switch.join().unwrap();
    assert!(session.current());
    assert!(
        session
            .with_sink(&sink, || panic!("old fd wrote after suspension"))
            .is_err()
    );
    drop(session);
    drop(sink);
    drop(owner);
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
