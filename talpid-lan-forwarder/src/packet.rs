//! Strict packet boundaries and checksums, using the same wire types as the stack.

use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket,
    },
};
use std::net::SocketAddr;

/// Largest ordinary IPv6 packet (40-byte header plus a 16-bit payload length).
pub const MAX_PACKET_SIZE: usize = 65_575;

/// The complete original application tuple. Physical scope IDs never replace it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Flow {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub transport: Transport,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRefusal {
    Malformed,
    Fragment,
    UnsupportedProtocol,
    Checksum,
}

/// TCP control flags needed to admit, close or reset a flow.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

/// Validated metadata and a payload borrowed directly from the input packet.
#[derive(Debug, Eq, PartialEq)]
pub struct Packet<'a> {
    pub flow: Flow,
    pub tcp_flags: Option<TcpFlags>,
    pub payload: &'a [u8],
}

/// Parse exactly one IP packet, without accepting trailing bytes or jumbograms.
pub fn parse(bytes: &[u8]) -> Result<Packet<'_>, PacketRefusal> {
    use PacketRefusal::{Checksum, Fragment, Malformed};

    if bytes.len() > MAX_PACKET_SIZE {
        return Err(Malformed);
    }
    let (source, destination, protocol, segment) = match bytes.first().map(|b| b >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(bytes).map_err(|_| Malformed)?;
            if usize::from(ip.total_len()) != bytes.len() {
                return Err(Malformed);
            }
            if !ip.verify_checksum() {
                return Err(Checksum);
            }
            if ip.more_frags() || ip.frag_offset() != 0 {
                return Err(Fragment);
            }
            (
                ip.src_addr().into(),
                ip.dst_addr().into(),
                ip.next_header(),
                ip.payload(),
            )
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(bytes).map_err(|_| Malformed)?;
            if ip.total_len() != bytes.len() {
                return Err(Malformed);
            }
            if ip.next_header() == IpProtocol::Ipv6Frag {
                return Err(Fragment);
            }
            (
                ip.src_addr().into(),
                ip.dst_addr().into(),
                ip.next_header(),
                ip.payload(),
            )
        }
        _ => return Err(Malformed),
    };
    parse_transport(source, destination, protocol, segment)
}

fn parse_transport(
    source: IpAddress,
    destination: IpAddress,
    protocol: IpProtocol,
    segment: &[u8],
) -> Result<Packet<'_>, PacketRefusal> {
    use PacketRefusal::{Checksum, Malformed, UnsupportedProtocol};

    let (source_port, destination_port, transport, tcp_flags, payload) = match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(segment).map_err(|_| Malformed)?;
            if !tcp.verify_checksum(&source, &destination) {
                return Err(Checksum);
            }
            (
                tcp.src_port(),
                tcp.dst_port(),
                Transport::Tcp,
                Some(TcpFlags {
                    syn: tcp.syn(),
                    ack: tcp.ack(),
                    fin: tcp.fin(),
                    rst: tcp.rst(),
                }),
                tcp.payload(),
            )
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(segment).map_err(|_| Malformed)?;
            if usize::from(udp.len()) != segment.len() {
                return Err(Malformed);
            }
            // smoltcp's low-level verifier accepts zero for either family;
            // IPv6 requires a checksum even when the computed value is zero.
            if (matches!(source, IpAddress::Ipv6(_)) && udp.checksum() == 0)
                || !udp.verify_checksum(&source, &destination)
            {
                return Err(Checksum);
            }
            (
                udp.src_port(),
                udp.dst_port(),
                Transport::Udp,
                None,
                udp.payload(),
            )
        }
        _ => return Err(UnsupportedProtocol),
    };
    Ok(Packet {
        flow: Flow {
            source: SocketAddr::new(source.into(), source_port),
            destination: SocketAddr::new(destination.into(), destination_port),
            transport,
        },
        tcp_flags,
        payload,
    })
}

/// Return a complete UDP reply on the original tuple, in the opposite direction.
pub fn udp_reply(flow: Flow, payload: &[u8]) -> Result<Vec<u8>, PacketRefusal> {
    if flow.transport != Transport::Udp {
        return Err(PacketRefusal::UnsupportedProtocol);
    }
    let segment_len = payload
        .len()
        .checked_add(8)
        .ok_or(PacketRefusal::Malformed)?;
    let (mut bytes, offset) =
        ip_packet(flow.destination, flow.source, IpProtocol::Udp, segment_len)?;
    let mut udp = UdpPacket::new_unchecked(&mut bytes[offset..]);
    udp.set_src_port(flow.destination.port());
    udp.set_dst_port(flow.source.port());
    udp.set_len(segment_len as u16);
    udp.payload_mut().copy_from_slice(payload);
    udp.fill_checksum(&flow.destination.ip().into(), &flow.source.ip().into());
    Ok(bytes)
}

fn ip_packet(
    source: SocketAddr,
    destination: SocketAddr,
    protocol: IpProtocol,
    segment_len: usize,
) -> Result<(Vec<u8>, usize), PacketRefusal> {
    match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            if segment_len > usize::from(u16::MAX) - 20 {
                return Err(PacketRefusal::Malformed);
            }
            let mut bytes = vec![0; 20 + segment_len];
            Ipv4Repr {
                src_addr: *source.ip(),
                dst_addr: *destination.ip(),
                next_header: protocol,
                payload_len: segment_len,
                hop_limit: 64,
            }
            .emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            Ok((bytes, 20))
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            if segment_len > usize::from(u16::MAX) {
                return Err(PacketRefusal::Malformed);
            }
            let mut bytes = vec![0; 40 + segment_len];
            Ipv6Repr {
                src_addr: *source.ip(),
                dst_addr: *destination.ip(),
                next_header: protocol,
                payload_len: segment_len,
                hop_limit: 64,
            }
            .emit(&mut Ipv6Packet::new_unchecked(&mut bytes));
            Ok((bytes, 40))
        }
        _ => Err(PacketRefusal::Malformed),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use smoltcp::wire::TcpSeqNumber;

    pub(crate) fn flow(ipv6: bool, transport: Transport) -> Flow {
        Flow {
            source: if ipv6 {
                "[fd00::2]:40123"
            } else {
                "192.168.7.2:40123"
            }
            .parse()
            .unwrap(),
            destination: if ipv6 {
                "[fd00::3]:8080"
            } else {
                "192.168.7.3:8080"
            }
            .parse()
            .unwrap(),
            transport,
        }
    }

    pub(crate) fn tcp_packet(flow: Flow, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
        let (mut bytes, offset) = ip_packet(
            flow.source,
            flow.destination,
            IpProtocol::Tcp,
            20 + payload.len(),
        )
        .unwrap();
        let mut tcp = TcpPacket::new_unchecked(&mut bytes[offset..]);
        tcp.set_src_port(flow.source.port());
        tcp.set_dst_port(flow.destination.port());
        tcp.set_header_len(20);
        tcp.set_seq_number(TcpSeqNumber(1234));
        tcp.set_ack_number(TcpSeqNumber(5678));
        tcp.set_window_len(4096);
        tcp.set_syn(flags.syn);
        tcp.set_ack(flags.ack);
        tcp.set_fin(flags.fin);
        tcp.set_rst(flags.rst);
        tcp.payload_mut().copy_from_slice(payload);
        tcp.fill_checksum(&flow.source.ip().into(), &flow.destination.ip().into());
        bytes
    }

    pub(crate) fn udp_packet(flow: Flow, payload: &[u8]) -> Vec<u8> {
        udp_reply(
            Flow {
                source: flow.destination,
                destination: flow.source,
                ..flow
            },
            payload,
        )
        .unwrap()
    }

    fn syn(ipv6: bool) -> Vec<u8> {
        tcp_packet(
            flow(ipv6, Transport::Tcp),
            TcpFlags {
                syn: true,
                ..TcpFlags::default()
            },
            b"",
        )
    }

    fn check_tcp(ipv6: bool) {
        let bytes = syn(ipv6);
        let packet = parse(&bytes).unwrap();
        assert_eq!(packet.flow, flow(ipv6, Transport::Tcp));
        assert_eq!(
            packet.tcp_flags,
            Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
        );
        assert!(packet.payload.is_empty());
    }

    fn check_udp(ipv6: bool) {
        let bytes = udp_packet(flow(ipv6, Transport::Udp), b"nonce");
        let packet = parse(&bytes).unwrap();
        assert_eq!(packet.flow, flow(ipv6, Transport::Udp));
        assert_eq!(packet.tcp_flags, None);
        assert_eq!(packet.payload, b"nonce");
        assert_eq!(packet.payload.as_ptr(), bytes[bytes.len() - 5..].as_ptr());
    }

    #[test]
    fn ipv4_tcp_syn() {
        check_tcp(false);
    }
    #[test]
    fn ipv6_tcp_syn() {
        check_tcp(true);
    }
    #[test]
    fn ipv4_udp_datagram() {
        check_udp(false);
    }
    #[test]
    fn ipv6_udp_datagram() {
        check_udp(true);
    }

    #[test]
    fn tcp_control_flags_and_payload() {
        let flags = TcpFlags {
            syn: false,
            ack: true,
            fin: true,
            rst: true,
        };
        for ipv6 in [false, true] {
            let bytes = tcp_packet(flow(ipv6, Transport::Tcp), flags, b"odd");
            let packet = parse(&bytes).unwrap();
            assert_eq!(packet.tcp_flags, Some(flags));
            assert_eq!(packet.payload, b"odd");
        }
    }

    #[test]
    fn ipv4_header_checksum_is_required() {
        let mut bytes = syn(false);
        bytes[8] ^= 1;
        assert_eq!(parse(&bytes), Err(PacketRefusal::Checksum));
    }

    #[test]
    fn transport_checksums_cover_both_families_and_protocols() {
        for ipv6 in [false, true] {
            let mut tcp = syn(ipv6);
            let offset = if ipv6 { 40 } else { 20 };
            tcp[offset + 4] ^= 1;
            assert_eq!(parse(&tcp), Err(PacketRefusal::Checksum));
            let mut udp = udp_packet(flow(ipv6, Transport::Udp), b"checksum");
            *udp.last_mut().unwrap() ^= 1;
            assert_eq!(parse(&udp), Err(PacketRefusal::Checksum));
        }
    }

    #[test]
    fn ipv4_udp_checksum_may_be_omitted() {
        let mut bytes = udp_packet(flow(false, Transport::Udp), b"nonce");
        UdpPacket::new_unchecked(&mut bytes[20..]).set_checksum(0);
        assert_eq!(parse(&bytes).unwrap().payload, b"nonce");
    }

    #[test]
    fn ipv6_udp_checksum_cannot_be_omitted() {
        let mut bytes = udp_packet(flow(true, Transport::Udp), b"nonce");
        UdpPacket::new_unchecked(&mut bytes[40..]).set_checksum(0);
        assert_eq!(parse(&bytes), Err(PacketRefusal::Checksum));
    }

    #[test]
    fn ipv4_fragments_are_refused() {
        for (more, offset) in [(true, 0), (false, 8), (true, 16)] {
            let mut bytes = syn(false);
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
            ip.set_more_frags(more);
            ip.set_frag_offset(offset);
            ip.fill_checksum();
            assert_eq!(parse(&bytes), Err(PacketRefusal::Fragment));
        }
    }

    #[test]
    fn ipv6_fragment_header_is_refused() {
        let mut bytes = syn(true);
        Ipv6Packet::new_unchecked(&mut bytes).set_next_header(IpProtocol::Ipv6Frag);
        assert_eq!(parse(&bytes), Err(PacketRefusal::Fragment));
    }

    #[test]
    fn other_ipv6_next_headers_are_not_traversed() {
        for protocol in [0, 43, 50, 51, 58, 59, 60, 255] {
            let mut bytes = syn(true);
            Ipv6Packet::new_unchecked(&mut bytes).set_next_header(protocol.into());
            assert_eq!(parse(&bytes), Err(PacketRefusal::UnsupportedProtocol));
        }
    }

    #[test]
    fn other_ipv4_protocols_are_refused() {
        for protocol in [1, 2, 47, 255] {
            let mut bytes = syn(false);
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
            ip.set_next_header(protocol.into());
            ip.fill_checksum();
            assert_eq!(parse(&bytes), Err(PacketRefusal::UnsupportedProtocol));
        }
    }

    #[test]
    fn ip_lengths_must_match_the_entire_input() {
        for ipv6 in [false, true] {
            let bytes = syn(ipv6);
            assert_eq!(
                parse(&bytes[..bytes.len() - 1]),
                Err(PacketRefusal::Malformed)
            );
            let mut extra = bytes.clone();
            extra.push(0);
            assert_eq!(parse(&extra), Err(PacketRefusal::Malformed));
        }
    }

    #[test]
    fn malformed_ipv4_header_lengths() {
        for ihl in [0, 4, 15] {
            let mut bytes = syn(false);
            bytes[0] = 0x40 | ihl;
            assert_eq!(parse(&bytes), Err(PacketRefusal::Malformed));
        }
    }

    #[test]
    fn malformed_udp_lengths() {
        for ipv6 in [false, true] {
            for len in [0, 7, 8, 12, 14] {
                let mut bytes = udp_packet(flow(ipv6, Transport::Udp), b"nonce");
                let offset = if ipv6 { 40 } else { 20 };
                UdpPacket::new_unchecked(&mut bytes[offset..]).set_len(len);
                assert_eq!(parse(&bytes), Err(PacketRefusal::Malformed));
            }
        }
    }

    #[test]
    fn malformed_tcp_data_offsets() {
        for ipv6 in [false, true] {
            for len in [0, 16, 24, 60] {
                let mut bytes = syn(ipv6);
                let offset = if ipv6 { 40 } else { 20 };
                TcpPacket::new_unchecked(&mut bytes[offset..]).set_header_len(len);
                assert_eq!(parse(&bytes), Err(PacketRefusal::Malformed));
            }
        }
    }

    #[test]
    fn truncated_transport_headers_are_refused() {
        for ipv6 in [false, true] {
            for (protocol, length) in [(IpProtocol::Tcp, 19), (IpProtocol::Udp, 7)] {
                let flow = flow(ipv6, Transport::Tcp);
                let (bytes, _) =
                    ip_packet(flow.source, flow.destination, protocol, length).unwrap();
                assert_eq!(parse(&bytes), Err(PacketRefusal::Malformed));
            }
        }
    }

    #[test]
    fn udp_replies_reverse_the_tuple_with_ttl_64() {
        for ipv6 in [false, true] {
            let flow = flow(ipv6, Transport::Udp);
            for payload in [b"".as_slice(), b"echo nonce".as_slice()] {
                let bytes = udp_reply(flow, payload).unwrap();
                let packet = parse(&bytes).unwrap();
                assert_eq!(
                    packet.flow,
                    Flow {
                        source: flow.destination,
                        destination: flow.source,
                        ..flow
                    }
                );
                assert_eq!(packet.payload, payload);
                if ipv6 {
                    assert_eq!(Ipv6Packet::new_checked(&bytes).unwrap().hop_limit(), 64);
                } else {
                    assert_eq!(Ipv4Packet::new_checked(&bytes).unwrap().hop_limit(), 64);
                }
            }
        }
    }

    #[test]
    fn udp_reply_size_boundaries() {
        for ipv6 in [false, true] {
            let max_payload = usize::from(u16::MAX) - 8 - if ipv6 { 0 } else { 20 };
            let payload = vec![7; max_payload];
            let bytes = udp_reply(flow(ipv6, Transport::Udp), &payload).unwrap();
            assert_eq!(parse(&bytes).unwrap().payload, payload);
            assert_eq!(
                udp_reply(flow(ipv6, Transport::Udp), &vec![7; max_payload + 1]),
                Err(PacketRefusal::Malformed)
            );
        }
    }

    #[test]
    fn replies_refuse_mixed_families_and_wrong_transport() {
        let mut mixed = flow(false, Transport::Udp);
        mixed.destination = flow(true, Transport::Udp).destination;
        assert_eq!(udp_reply(mixed, b""), Err(PacketRefusal::Malformed));
        assert_eq!(
            udp_reply(flow(false, Transport::Tcp), b""),
            Err(PacketRefusal::UnsupportedProtocol)
        );
    }

    #[test]
    fn invalid_family_and_overlarge_input() {
        assert_eq!(parse(&[]), Err(PacketRefusal::Malformed));
        for version in [0, 3, 5, 7, 15] {
            let mut bytes = syn(false);
            bytes[0] = version << 4 | 5;
            assert_eq!(parse(&bytes), Err(PacketRefusal::Malformed));
        }
        assert_eq!(
            parse(&vec![0; MAX_PACKET_SIZE + 1]),
            Err(PacketRefusal::Malformed)
        );
    }

    #[test]
    fn every_truncation_and_single_byte_mutation_is_panic_free() {
        for ipv6 in [false, true] {
            for bytes in [
                syn(ipv6),
                udp_packet(flow(ipv6, Transport::Udp), b"odd payload"),
            ] {
                for end in 0..bytes.len() {
                    assert!(parse(&bytes[..end]).is_err());
                }
                for index in 0..bytes.len() {
                    for value in 0..=u8::MAX {
                        let mut changed = bytes.clone();
                        changed[index] = value;
                        let _ = parse(&changed);
                    }
                }
            }
        }
    }
}
