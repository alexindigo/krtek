use super::{tests::*, *};

fn endpoints(v4: bool, direction: Direction) -> (IpAddr, IpAddr, IpAddr, IpAddr) {
    let old = address(
        if direction == Direction::Inbound {
            ASSIGNED
        } else {
            FIXED
        },
        v4,
    );
    let new = address(
        if direction == Direction::Inbound {
            FIXED
        } else {
            ASSIGNED
        },
        v4,
    );
    if direction == Direction::Inbound {
        (old, remote(v4), new, remote(v4))
    } else {
        (remote(v4), old, remote(v4), new)
    }
}

fn error(quote: &[u8], v4: bool, direction: Direction) -> Vec<u8> {
    let old = address(
        if direction == Direction::Inbound {
            ASSIGNED
        } else {
            FIXED
        },
        v4,
    );
    let mut body = vec![
        if v4 { 3 } else { 2 },
        if v4 { 4 } else { 0 },
        0,
        0,
        0,
        0,
        5,
        0,
    ];
    body.extend_from_slice(quote);
    let (source, destination) = if direction == Direction::Inbound {
        (remote(v4), old)
    } else {
        (old, remote(v4))
    };
    packet(source, destination, if v4 { 1 } else { 58 }, &body)
}

fn check_quote(
    mapper: &mut AddressTranslator,
    original: &[u8],
    expected: &[u8],
    v4: bool,
    direction: Direction,
) {
    let input = error(original, v4, direction);
    let output = mapper
        .translate(&input, direction)
        .expect("legal partial quotation");
    let view = output.view();
    let ip = if v4 { 20 } else { 40 };
    let icmp = if v4 { 1 } else { 58 };
    assert_eq!(view.bytes().len(), input.len());
    assert_eq!(&view.bytes()[ip + 8..], expected);
    assert_eq!(&view.bytes()[ip..ip + 2], &input[ip..ip + 2]);
    assert_eq!(&view.bytes()[ip + 4..ip + 8], &input[ip + 4..ip + 8]);
    assert_eq!(wire_checksum(view.bytes(), ip, icmp), 0);
    if v4 {
        assert_eq!(oracle(&view.bytes()[..20]), 0);
    }
    let header = Header::parse(view.bytes(), false).unwrap();
    let changed = address(
        if direction == Direction::Inbound {
            FIXED
        } else {
            ASSIGNED
        },
        v4,
    );
    assert_eq!(
        if direction == Direction::Inbound {
            header.destination
        } else {
            header.source
        },
        changed
    );
}

fn first_fragment(mut bytes: Vec<u8>, v4: bool) -> Vec<u8> {
    if v4 {
        bytes.truncate(28);
        bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        bytes[10..12].fill(0);
        let sum = oracle(&bytes[..20]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    } else {
        bytes.truncate(48);
        bytes[6] = 44;
        bytes.splice(40..40, [6, 0, 0, 1, 0x12, 0x34, 0x56, 0x78]);
        bytes[4..6].copy_from_slice(&16u16.to_be_bytes());
    }
    bytes
}

#[test]
fn quoted_first_fragments_do_not_require_an_absent_complete_tcp_header() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let (src, dst, new_src, new_dst) = endpoints(v4, direction);
            let original = first_fragment(packet(src, dst, 6, &segment(6)), v4);
            let expected = first_fragment(packet(new_src, new_dst, 6, &segment(6)), v4);
            check_quote(&mut mapper, &original, &expected, v4, direction);
            if !v4 {
                for end in 40..48 {
                    check_quote(
                        &mut mapper,
                        &original[..end],
                        &expected[..end],
                        false,
                        direction,
                    );
                }
            }
        }
    }
}

fn long_extension(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut extension = vec![0; 1192];
    extension[0] = 6;
    extension[1] = 148;
    bytes.splice(40..40, extension);
    bytes[6] = 60;
    let length = (bytes.len() - 40) as u16;
    bytes[4..6].copy_from_slice(&length.to_be_bytes());
    bytes
}

#[test]
fn legal_ipv6_quotes_can_end_inside_extensions_or_before_any_transport_byte() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for direction in [Direction::Inbound, Direction::Outbound] {
        let (src, dst, new_src, new_dst) = endpoints(false, direction);
        let original = long_extension(packet(src, dst, 6, &segment(6)[..24]));
        let expected = long_extension(packet(new_src, new_dst, 6, &segment(6)[..24]));
        assert_eq!(original.len(), 1256);
        for end in [40, 41, 42, 43, 47, 48, 1200, 1231, 1232] {
            check_quote(
                &mut mapper,
                &original[..end],
                &expected[..end],
                false,
                direction,
            );
        }
        let outer = error(&original[..1232], false, direction);
        assert_eq!(outer.len(), 1280);
    }
}

#[test]
fn only_complete_present_checksum_words_are_adjusted_in_short_quotes() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        let ip = if v4 { 20 } else { 40 };
        for direction in [Direction::Inbound, Direction::Outbound] {
            let (src, dst, new_src, new_dst) = endpoints(v4, direction);
            for protocol in [6, 17, if v4 { 1 } else { 58 }] {
                let original = packet(src, dst, protocol, &segment(protocol));
                let expected = packet(new_src, new_dst, protocol, &segment(protocol));
                let checksum_end = match protocol {
                    6 => 18,
                    17 => 8,
                    _ => 4,
                };
                for available in 0..=20 {
                    let mut prefix = expected[..ip + available].to_vec();
                    if available < checksum_end {
                        prefix[ip..].copy_from_slice(&original[ip..ip + available]);
                    }
                    check_quote(
                        &mut mapper,
                        &original[..ip + available],
                        &prefix,
                        v4,
                        direction,
                    );
                }
            }
            if v4 {
                let with_options = |source, destination| {
                    let mut bytes = packet(source, destination, 6, &segment(6));
                    bytes.splice(20..20, [148, 4, 0, 0]);
                    bytes[0] = 0x46;
                    let length = bytes.len() as u16;
                    bytes[2..4].copy_from_slice(&length.to_be_bytes());
                    fix_checksums(&mut bytes, 24, 6);
                    bytes
                };
                let original = with_options(src, dst);
                let expected = with_options(new_src, new_dst);
                for end in 20..=24 {
                    check_quote(
                        &mut mapper,
                        &original[..end],
                        &expected[..end],
                        true,
                        direction,
                    );
                }
            }
        }
    }
}

#[test]
fn partial_quotes_keep_endpoint_and_genuinely_invalid_or_unsupported_refusals() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    let quote = long_extension(packet(
        address(ASSIGNED, false),
        remote(false),
        6,
        &segment(6)[..24],
    ));
    let mut malformed = quote[..42].to_vec();
    malformed[4..6].copy_from_slice(&8u16.to_be_bytes());
    assert!(matches!(
        mapper.translate(
            &error(&malformed, false, Direction::Inbound),
            Direction::Inbound
        ),
        Err(TranslationError::Malformed)
    ));
    let mut wrong = quote[..42].to_vec();
    wrong[23] ^= 1;
    assert!(matches!(
        mapper.translate(
            &error(&wrong, false, Direction::Inbound),
            Direction::Inbound
        ),
        Err(TranslationError::Endpoint)
    ));
    let mut unsupported = quote[..43].to_vec();
    unsupported[42] = 201; // Home Address option has address-dependent semantics.
    assert!(matches!(
        mapper.translate(
            &error(&unsupported, false, Direction::Inbound),
            Direction::Inbound
        ),
        Err(TranslationError::UnsupportedTranslation)
    ));
}
