use super::*;
use talpid_types::relay_flow::{BUFFER_OVERHEAD, MAX_RELAY_PACKET_SIZE, RelayBuffer};

#[test]
fn split_absorb_shrink_refund_exactly() {
    let budget = BufferBudget::new(1000);
    let mut a = budget.reserve(1000).unwrap();
    assert!(budget.reserve(1).is_err());
    let mut b = a.split(400).unwrap();
    assert_eq!((a.bytes(), b.bytes(), budget.used()), (600, 400, 1000));
    assert!(a.split(601).is_err());
    assert!(a.shrink(601).is_err());
    assert_eq!(budget.used(), 1000);
    a.absorb(&mut b).unwrap();
    assert_eq!((a.bytes(), b.bytes(), budget.used()), (1000, 0, 1000));
    a.shrink(123).unwrap();
    assert_eq!(budget.used(), 123);
    drop((a, b));
    assert_eq!(budget.used(), 0);
}

#[test]
fn foreign_and_lent_credit_cannot_be_mutated_or_partitioned() {
    let root = BufferBudget::new(4096);
    let mut a = root.reserve(2048).unwrap();
    let foreign = BufferBudget::new(4096);
    let mut b = foreign.reserve(100).unwrap();
    assert_eq!(a.absorb(&mut b), Err(RelayFlowError::Invalid));
    assert_eq!(
        (a.bytes(), b.bytes(), root.used(), foreign.used()),
        (2048, 100, 2048, 100)
    );
    let child = a.region().unwrap();
    assert!(a.split(1).is_err());
    assert!(a.shrink(1).is_err());
    assert!(a.absorb(&mut root.reserve(1).unwrap()).is_err());
    let a = Arc::new(a);
    assert!(a.clone().partition(&[1]).is_err());
    assert_eq!(root.used(), 2048);
    assert!(a.partition(&[1]).is_err());
    assert_eq!(
        root.used(),
        2048,
        "child retains parent after refused consuming operation"
    );
    drop(child);
    assert_eq!(root.used(), 0);
}

#[test]
fn child_handles_share_one_credit_and_last_bytes_retain_parent() {
    let root = BufferBudget::new(4096);
    let parent = root.reserve(4096).unwrap();
    let a = parent.region().unwrap();
    let b = parent.region().unwrap();
    let retained = a.reserve(4096 - REGION_OVERHEAD).unwrap();
    assert!(b.reserve(1).is_err());
    drop((parent, a, b));
    assert_eq!(root.used(), 4096);
    drop(retained);
    assert_eq!(root.used(), 0);
}

#[test]
fn partition_consumes_peak_and_refunds_unused_bytes() {
    let root = BufferBudget::new(4096);
    let peak = root.try_reserve(4096).unwrap();
    let mut parts = peak.partition(&[100, 200, 300]).unwrap();
    assert_eq!(root.used(), 600);
    drop(parts.pop());
    assert_eq!(root.used(), 300);
    drop(parts);
    assert_eq!(root.used(), 0);
    assert!(
        root.try_reserve(1)
            .unwrap()
            .partition(&[usize::MAX, 1])
            .is_err()
    );
    assert_eq!(root.used(), 0);
}

#[test]
fn checked_overflow_refuses_without_counter_change() {
    let root = BufferBudget::new(usize::MAX);
    let all = root.reserve(usize::MAX).unwrap();
    assert!(root.reserve(1).is_err());
    assert_eq!(root.used(), usize::MAX);
    drop(all);
    assert_eq!(root.used(), 0);
}

#[test]
fn concurrent_reserve_never_overdraws_and_refunds_exactly() {
    let root = BufferBudget::new(4096);
    let entered = Arc::new(std::sync::Barrier::new(16));
    let held = Arc::new(std::sync::Barrier::new(16));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let (budget, entered, held) = (root.clone(), entered.clone(), held.clone());
            std::thread::spawn(move || {
                entered.wait();
                let charge = budget.reserve(1024).ok();
                held.wait();
                assert_eq!(budget.used(), 4096);
                entered.wait();
                charge.is_some()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        4
    );
    assert_eq!(root.used(), 0);
}

#[test]
fn owned_buffers_keep_actual_capacity_charged_across_moves() {
    let root = BufferBudget::new(8192);
    let bytes = Vec::with_capacity(2048);
    let charge = root.try_reserve(2048 + BUFFER_OVERHEAD).unwrap();
    let buffer = RelayBuffer::from_reservation(bytes, charge).unwrap();
    let moved = vec![buffer];
    assert_eq!(root.used(), 2048 + BUFFER_OVERHEAD);
    drop(moved);
    let mut copied = RelayBuffer::copy_from(b"consumer nonce", &root).unwrap();
    copied[0] = b'C';
    assert_eq!(copied.as_slice(), b"Consumer nonce");
    assert_eq!(root.used(), copied.len() + BUFFER_OVERHEAD);
    drop(copied);
    assert_eq!(root.used(), 0);
}

#[test]
fn shared_ticket_oversize_and_insufficient_capacity_refuse() {
    let root = BufferBudget::new(8192);
    let charge = root.try_reserve(4096).unwrap();
    assert!(RelayBuffer::from_reservation(vec![1], charge.clone()).is_err());
    assert_eq!(root.used(), 4096);
    assert!(RelayBuffer::from_reservation(Vec::with_capacity(4096), charge).is_err());
    assert_eq!(root.used(), 0);
    assert!(RelayBuffer::copy_from(&vec![0; MAX_RELAY_PACKET_SIZE + 1], &root).is_err());
    assert_eq!(root.used(), 0);
    let pressure = root.reserve(8192).unwrap();
    assert!(RelayBuffer::copy_from(b"no copy admitted", &root).is_err());
    assert_eq!(root.used(), 8192);
    drop(pressure);
}

#[test]
fn encoder_peak_remains_charged_during_region_conversion() {
    let root = BufferBudget::new(4096);
    let peak = root.try_reserve(1024).unwrap();
    let bytes = vec![42; 100];
    let retained = RelayBuffer::from_region(bytes, &root, &*peak).unwrap();
    assert_eq!(root.used(), 1024 + 100 + BUFFER_OVERHEAD);
    drop(peak);
    assert_eq!(&*retained, &[42; 100]);
    assert_eq!(root.used(), 100 + BUFFER_OVERHEAD);
    drop(retained);
    assert_eq!(root.used(), 0);
}
