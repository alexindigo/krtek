use crate::address_translation::{tests::*, *};
use crate::{buffer_budget::BufferBudget, packet_sizing::FeedbackSide};
use std::time::Instant;
use std::{net::IpAddr, sync::Arc};
use talpid_types::relay_flow::{RelayAttemptOwner, RelayCaptureOwner, RelayWriteOutcome};

fn path(
    mtu: u16,
) -> (
    TargetPacketPath,
    RelayCaptureOwner,
    RelayAttemptOwner,
    BufferBudget,
) {
    let (mapper, capture, attempt, budget) = mapper();
    let mut config = mapper.config();
    config.mtu = mtu;
    drop(mapper);
    (
        TargetPacketPath::new(config, attempt.capability(), Arc::new(budget.clone())).unwrap(),
        capture,
        attempt,
        budget,
    )
}

fn endpoints(direction: Direction) -> (IpAddr, IpAddr) {
    if direction == Direction::Outbound {
        (address(FIXED, false), remote(false))
    } else {
        (remote(false), address(ASSIGNED, false))
    }
}

fn udp(source: IpAddr, destination: IpAddr, size: usize) -> Vec<u8> {
    let mut body = vec![0; 8 + size];
    body[..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    let length = body.len() as u16;
    body[4..6].copy_from_slice(&length.to_be_bytes());
    for (index, byte) in body[8..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    packet(source, destination, 17, &body)
}

fn feedback(path: &mut TargetPacketPath, original: &[u8], direction: Direction, mtu: u16) {
    let side = if direction == Direction::Outbound {
        FeedbackSide::App
    } else {
        FeedbackSide::Target
    };
    let mut feedback = path.take_feedback().expect("queued PMTU feedback");
    assert_eq!(feedback.side(), side);
    let mut output = Vec::new();
    assert!(matches!(
        feedback.write(|bytes| {
            output.extend_from_slice(bytes);
            Ok(bytes.len())
        }),
        RelayWriteOutcome::Written
    ));
    assert!(output.len() <= 1280);
    assert_eq!(&output[40..42], &[2, 0]);
    assert_eq!(
        u32::from_be_bytes(output[44..48].try_into().unwrap()),
        u32::from(mtu)
    );
    assert_eq!(wire_checksum(&output, 40, 58), 0);
    assert_eq!(&output[48..], &original[..output.len() - 48]);
    let outer = Header::parse(&output, false).unwrap();
    assert_eq!(
        outer.source,
        address(
            if side == FeedbackSide::App {
                FIXED
            } else {
                ASSIGNED
            },
            false
        )
    );
    assert_eq!(
        outer.destination,
        Header::parse_fragment(original).unwrap().source
    );
}

#[test]
fn atomic_pmtu_feedback_quotes_the_received_packet_not_its_normalization() {
    for direction in [Direction::Outbound, Direction::Inbound] {
        let (mut path, _capture, _attempt, _) = path(1380);
        let (source, destination) = endpoints(direction);
        let mut original = udp(source, destination, 3000);
        original.splice(40..40, [17, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]);
        original[6] = 44;
        let length = (original.len() - 40) as u16;
        original[4..6].copy_from_slice(&length.to_be_bytes());
        assert!(matches!(
            path.process(&original, direction, 1280, Instant::now()),
            Ok(TranslationOutcome::FeedbackQueued(_))
        ));
        feedback(
            &mut path,
            &original,
            direction,
            if direction == Direction::Outbound {
                1380
            } else {
                1280
            },
        );
    }
}

fn source_fragments(direction: Direction) -> (Vec<u8>, Vec<u8>) {
    let (source, destination) = endpoints(direction);
    let datagram = udp(source, destination, 32);
    fragment_packet(&datagram, 17)
}

fn fragment_packet(datagram: &[u8], protocol: u8) -> (Vec<u8>, Vec<u8>) {
    let mut prefix = datagram[..40].to_vec();
    prefix[6] = 0;
    let mut extension = vec![0; 1240];
    extension[0] = 44;
    extension[1] = 154;
    prefix.extend_from_slice(&extension);
    let mut fragments = Vec::new();
    for (offset, body, more) in [(0, &datagram[40..48], true), (8, &datagram[48..], false)] {
        let mut fragment = prefix.clone();
        fragment.extend_from_slice(&[protocol, 0]);
        fragment.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
        fragment.extend_from_slice(&0x12345678u32.to_be_bytes());
        fragment.extend_from_slice(body);
        let length = (fragment.len() - 40) as u16;
        fragment[4..6].copy_from_slice(&length.to_be_bytes());
        fragments.push(fragment);
    }
    (fragments.remove(0), fragments.remove(0))
}

#[test]
fn source_fragment_pmtu_feedback_keeps_the_original_first_fragment_view() {
    for direction in [Direction::Outbound, Direction::Inbound] {
        let (mut path, _capture, _attempt, _) = path(if direction == Direction::Outbound {
            1280
        } else {
            1380
        });
        let (first, last) = source_fragments(direction);
        let now = Instant::now();
        assert!(matches!(
            path.process(&last, direction, 1280, now),
            Ok(TranslationOutcome::PendingFragments)
        ));
        assert!(matches!(
            path.process(&first, direction, 1280, now),
            Ok(TranslationOutcome::FeedbackQueued(_))
        ));
        feedback(&mut path, &first, direction, 1280);
    }
}

#[test]
fn retained_first_fragment_prefix_is_bounded_and_keeps_its_region_charged() {
    use crate::fragment_state::{Datagram, FragmentState};
    let budget = BufferBudget::new(22 * 1024 * 1024);
    let mut fragments = FragmentState::new(&budget).unwrap();
    let (first, last) = source_fragments(Direction::Inbound);
    let now = Instant::now();
    assert!(
        fragments
            .ingest(&first, Direction::Inbound, now)
            .unwrap()
            .is_none()
    );
    let Datagram {
        bytes, invoking, ..
    } = fragments
        .ingest(&last, Direction::Inbound, now)
        .unwrap()
        .unwrap();
    assert_eq!(invoking.len(), 1280);
    assert_eq!(&invoking[..], &first[..1280]);
    drop(fragments);
    assert_eq!(budget.used(), 4 * 1024 * 1024);
    drop(bytes);
    assert_eq!(budget.used(), 4 * 1024 * 1024);
    drop(invoking);
    assert_eq!(budget.used(), 0);
}

#[test]
fn truncated_original_fragment_prefix_does_not_hide_error_suppression() {
    let (mut path, _capture, _attempt, _) = path(1380);
    let quote = packet(address(ASSIGNED, false), remote(false), 6, &segment(6));
    let mut body = vec![2, 0, 0, 0, 0, 0, 5, 0];
    body.extend_from_slice(&quote);
    let error = packet(remote(false), address(ASSIGNED, false), 58, &body);
    let (first, last) = fragment_packet(&error, 58);
    let now = Instant::now();
    assert!(matches!(
        path.process(&last, Direction::Inbound, 1280, now),
        Ok(TranslationOutcome::PendingFragments)
    ));
    assert!(matches!(
        path.process(&first, Direction::Inbound, 1280, now),
        Err(TranslationError::Suppressed)
    ));
    assert!(path.take_feedback().is_none());
}
