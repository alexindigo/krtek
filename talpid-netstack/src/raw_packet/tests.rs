use super::*;
use crate::buffer_budget::BufferBudget;
use gotatun::tun::MtuWatcher;
use std::{io, net::IpAddr};
use talpid_types::relay_flow::{
    RelayAttemptOwner, RelayCaptureGeneration, RelayCaptureOwner, RelaySources, RelayWriteOutcome,
};

const SOURCE4: [u8; 4] = [10, 64, 0, 2];
const SOURCE6: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const PUBLIC4: [u8; 4] = [1, 1, 1, 1];
const PUBLIC6: [u8; 16] = [
    0x26, 6, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
];

fn sources() -> RelaySources {
    RelaySources {
        ipv4: Some(SOURCE4.into()),
        ipv6: Some(SOURCE6.into()),
    }
}

fn owners(budget: &BufferBudget, sources: RelaySources) -> (RelayCaptureOwner, RelayAttemptOwner) {
    let capture = RelayCaptureOwner::new(
        RelayCaptureGeneration::fresh().unwrap(),
        "tun9",
        0x1234_5678_0000_0064,
        sources,
        1500,
        budget,
    )
    .unwrap();
    let attempt = capture.open_attempt(budget).unwrap();
    attempt.activate().unwrap();
    (capture, attempt)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4(protocol: u8, payload: &[u8], destination: [u8; 4], fragment: u16) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0] = 0x45;
    bytes[1] = 0x2c;
    bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&0x4321u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
    bytes[8] = 59;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&SOURCE4);
    bytes[16..20].copy_from_slice(&destination);
    let sum = checksum(&bytes);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv6(protocol: u8, payload: &[u8], destination: [u8; 16]) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[..4].copy_from_slice(&0x62c54321u32.to_be_bytes());
    bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[6] = protocol;
    bytes[7] = 59;
    bytes[8..24].copy_from_slice(&SOURCE6);
    bytes[24..40].copy_from_slice(&destination);
    bytes.extend_from_slice(payload);
    bytes
}

fn transport(
    v6: bool,
    protocol: u8,
    destination: &[u8],
    mut payload: Vec<u8>,
    checksum_at: usize,
) -> Vec<u8> {
    let mut pseudo = Vec::new();
    if v6 {
        pseudo.extend_from_slice(&SOURCE6);
        pseudo.extend_from_slice(destination);
        pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, protocol]);
    } else if protocol != 1 {
        pseudo.extend_from_slice(&SOURCE4);
        pseudo.extend_from_slice(destination);
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    pseudo.extend_from_slice(&payload);
    let sum = checksum(&pseudo);
    payload[checksum_at..checksum_at + 2].copy_from_slice(&sum.to_be_bytes());
    payload
}

/// Independently exercise native Packet::try_into_ip plus SourceFilter's exact
/// source predicate. Do not use inspect() to define the expected acceptance.
fn native_accepts(bytes: &[u8], allowed: RelaySources) -> bool {
    Packet::copy_from(bytes)
        .try_into_ip()
        .ok()
        .and_then(|p| p.source())
        .is_some_and(|source| match source {
            IpAddr::V4(ip) => allowed.ipv4 == Some(ip),
            IpAddr::V6(ip) => allowed.ipv6 == Some(ip),
        })
}

/// Observe actual consumers at both final boundaries, not just intermediate
/// parsing or queue admission. Return addresses need not match outbound sources.
fn roundtrip(bytes: &[u8]) {
    let budget = BufferBudget::new(1024 * 1024);
    let (_capture, owner) = owners(&budget, sources());
    let attempt = owner.capability();
    let mut mtu = MtuWatcher::new(attempt.identity().mtu);
    assert_eq!(mtu.get(), 1500);
    assert!(native_accepts(bytes, sources()));
    let packet = outbound(bytes, &attempt, &budget).unwrap();
    assert_eq!(packet.view().bytes(), bytes);
    let mut wire_consumer = Vec::new();
    handoff(packet, &budget, |native| {
        wire_consumer.extend_from_slice(native.as_bytes());
        assert!(budget.used() >= 2 * (bytes.len() + BUFFER_OVERHEAD) + 2 * BUFFER_OVERHEAD);
    })
    .unwrap();
    assert_eq!(wire_consumer, bytes);
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);

    let native = Packet::copy_from(bytes).try_into_ip().unwrap();
    let mut inbound = authenticated_return(native, &attempt, &budget).unwrap();
    let charge = budget.used();
    assert!(matches!(
        inbound.write(|_| Err(io::ErrorKind::WouldBlock.into())),
        RelayWriteOutcome::Retry
    ));
    assert_eq!(budget.used(), charge);
    let mut capture_consumer = Vec::new();
    assert!(matches!(
        inbound.write(|bytes| {
            capture_consumer.extend_from_slice(bytes);
            Ok(bytes.len())
        }),
        RelayWriteOutcome::Written
    ));
    assert_eq!(capture_consumer, bytes);
    drop(inbound);
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);
}

#[test]
fn tcp_udp_and_real_dns_addresses_reach_both_raw_consumers_unchanged() {
    for v6 in [false, true] {
        for protocol in [6, 17] {
            let mut payload = if protocol == 6 {
                vec![0; 24]
            } else {
                vec![0; 8]
            };
            payload[..4].copy_from_slice(&[0xc0, 0x01, 0x01, 0xbb]);
            let at = if protocol == 6 {
                payload[12] = 0x60;
                payload[13] = 0x18;
                16
            } else {
                6
            };
            payload.extend_from_slice(b"ordinary application bytes");
            if protocol == 17 {
                let len = payload.len() as u16;
                payload[4..6].copy_from_slice(&len.to_be_bytes());
            }
            let destination: &[u8] = if v6 { &PUBLIC6 } else { &PUBLIC4 };
            let payload = transport(v6, protocol, destination, payload, at);
            roundtrip(&if v6 {
                ipv6(protocol, &payload, PUBLIC6)
            } else {
                ipv4(protocol, &payload, PUBLIC4, 0)
            });
        }
        let mut dns = vec![0xc0, 0x02, 0, 53, 0, 0, 0, 0];
        dns.extend_from_slice(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01");
        let len = dns.len() as u16;
        dns[4..6].copy_from_slice(&len.to_be_bytes());
        let gateway4 = [10, 64, 0, 1];
        let mut gateway6 = SOURCE6;
        gateway6[15] = 1;
        let destination: &[u8] = if v6 { &gateway6 } else { &gateway4 };
        let payload = transport(v6, 17, destination, dns, 6);
        roundtrip(&if v6 {
            ipv6(17, &payload, gateway6)
        } else {
            ipv4(17, &payload, gateway4, 0)
        });
    }
}

#[test]
fn public_icmp_echo_errors_and_quotations_are_opaque() {
    for v6 in [false, true] {
        let protocol = if v6 { 58 } else { 1 };
        let destination: &[u8] = if v6 { &PUBLIC6 } else { &PUBLIC4 };
        for error in [false, true] {
            let mut icmp = vec![
                if error {
                    if v6 { 2 } else { 3 }
                } else if v6 {
                    128
                } else {
                    8
                },
                0,
                0,
                0,
                0x42,
                0x17,
                0x23,
                0x19,
            ];
            if error {
                let quoted = if v6 {
                    ipv6(17, b"quotation retains its original endpoints", PUBLIC6)
                } else {
                    ipv4(17, b"quotation retains its original endpoints", PUBLIC4, 0)
                };
                icmp.extend_from_slice(&quoted);
            } else {
                icmp.extend_from_slice(b"random echo payload, not a private pinger grant");
            }
            let payload = transport(v6, protocol, destination, icmp, 2);
            roundtrip(&if v6 {
                ipv6(protocol, &payload, PUBLIC6)
            } else {
                ipv4(protocol, &payload, PUBLIC4, 0)
            });
        }
    }
}

#[test]
fn every_native_accepted_next_protocol_remains_accepted_without_dispatch() {
    for protocol in 0..=255 {
        roundtrip(&ipv4(protocol, b"opaque next protocol", PUBLIC4, 0));
        roundtrip(&ipv6(protocol, b"opaque next protocol", PUBLIC6));
    }
}

#[test]
fn fragments_options_and_ipv6_extension_chains_are_not_reassembled_or_normalized() {
    for fragment in [0x2000, 0x2001, 0x0002] {
        roundtrip(&ipv4(17, b"one independent fragment", PUBLIC4, fragment));
    }
    let mut options = ipv4(253, b"opaque IP options and payload", PUBLIC4, 0);
    options.splice(20..20, [1, 1, 1, 0]);
    options[0] = 0x46;
    let len = options.len() as u16;
    options[2..4].copy_from_slice(&len.to_be_bytes());
    options[10..12].fill(0);
    let sum = checksum(&options[..24]);
    options[10..12].copy_from_slice(&sum.to_be_bytes());
    roundtrip(&options);
    for fragment in [1u16, 9, 16] {
        let mut extensions = vec![60, 0, 1, 0, 0, 0, 0, 0, 44, 0, 1, 0, 0, 0, 0, 0, 253, 0];
        extensions.extend_from_slice(&fragment.to_be_bytes());
        extensions.extend_from_slice(&0xabcdef01u32.to_be_bytes());
        extensions.extend_from_slice(b"opaque fragment after hop and destination options");
        roundtrip(&ipv6(0, &extensions, PUBLIC6));
    }
}

#[test]
fn carrier_preserves_large_packets_through_native_maximum_and_actual_mtu_metadata() {
    for size in [1281, 1500, 4096, 65_535] {
        roundtrip(&ipv4(253, &vec![0x7b; size - 20], PUBLIC4, 0));
    }
    roundtrip(&ipv6(253, &vec![0xa7; 65_535], PUBLIC6));
    let budget = BufferBudget::new(1024 * 1024);
    let (_capture, owner) = owners(&budget, sources());
    let too_large = ipv6(253, &vec![0; 65_536], PUBLIC6);
    let before = budget.used();
    assert!(matches!(
        outbound(&too_large, &owner.capability(), &budget),
        Err(RelayFlowError::Invalid)
    ));
    assert_eq!(budget.used(), before);
}

#[test]
fn malformed_and_wrong_family_sources_match_native_packet_and_source_filter_boundary() {
    let mut vectors = vec![
        vec![],
        vec![0x45; 19],
        vec![0; 40],
        vec![0x60; 20],
        vec![0x60; 39],
    ];
    vectors.push(ipv4(253, b"valid", PUBLIC4, 0));
    vectors.push(ipv6(253, b"valid", PUBLIC6));
    let mut bad_source = ipv4(17, b"old address", PUBLIC4, 0);
    bad_source[15] = 3;
    vectors.push(bad_source);
    let mut bad_source = ipv6(17, b"old address", PUBLIC6);
    bad_source[23] = 3;
    vectors.push(bad_source);
    // These odd headers are native-TUN accepted. Do not introduce stricter
    // IHL/length/checksum/transport validation in the managed-only path.
    let mut odd = ipv4(6, b"bad TCP checksum is still opaque", PUBLIC4, 0);
    odd[0] = 0x40;
    odd[2..4].copy_from_slice(&1u16.to_be_bytes());
    odd[10] ^= 0xff;
    vectors.push(odd);
    let mut odd = ipv6(17, b"payload length differs", PUBLIC6);
    odd[4..6].fill(0xff);
    vectors.push(odd);
    for allowed in [
        sources(),
        RelaySources {
            ipv4: None,
            ..sources()
        },
        RelaySources {
            ipv6: None,
            ..sources()
        },
    ] {
        let budget = BufferBudget::new(1024 * 1024);
        let (_capture, owner) = owners(&budget, allowed);
        for bytes in &vectors {
            let before = budget.used();
            let managed = outbound(bytes, &owner.capability(), &budget);
            assert_eq!(
                managed.is_ok(),
                native_accepts(bytes, allowed),
                "vector {bytes:?}"
            );
            if let Ok(packet) = managed {
                assert_eq!(packet.view().bytes(), bytes);
                drop(packet);
            }
            assert_eq!(budget.used(), before);
        }
    }
}

#[test]
fn authenticated_return_does_not_apply_outbound_source_filter_or_rewrite_bytes() {
    let budget = BufferBudget::new(4096);
    let (_capture, owner) = owners(&budget, sources());
    let mut bytes = ipv4(1, b"authenticated remote return", SOURCE4, 0);
    bytes[12..16].copy_from_slice(&PUBLIC4);
    assert!(!native_accepts(&bytes, sources()));
    let native = Packet::copy_from(bytes.as_slice()).try_into_ip().unwrap();
    let mut packet = authenticated_return(native, &owner.capability(), &budget).unwrap();
    let mut consumer = Vec::new();
    assert!(matches!(
        packet.write(|bytes| {
            consumer.extend_from_slice(bytes);
            Ok(bytes.len())
        }),
        RelayWriteOutcome::Written
    ));
    assert_eq!(consumer, bytes);
}

#[test]
fn native_copy_refusal_and_stale_handoff_never_reach_wire_consumer() {
    let budget = BufferBudget::new(3 * BUFFER_OVERHEAD + 64);
    let (_capture, owner) = owners(&budget, sources());
    let bytes = ipv4(253, b"budgeted", PUBLIC4, 0);
    let packet = outbound(&bytes, &owner.capability(), &budget).unwrap();
    assert!(matches!(
        handoff(packet, &budget, |_| panic!("unfunded handoff")),
        Err(RelayFlowError::Full)
    ));
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);
    let packet = outbound(&bytes, &owner.capability(), &budget).unwrap();
    let retained = packet.view();
    owner.retire();
    assert!(matches!(
        handoff(packet, &budget, |_| panic!("stale handoff")),
        Err(RelayFlowError::Stale)
    ));
    assert_eq!(retained.bytes(), bytes);
    assert!(budget.used() > 2 * BUFFER_OVERHEAD);
    drop(retained);
    assert_eq!(budget.used(), 2 * BUFFER_OVERHEAD);
}
