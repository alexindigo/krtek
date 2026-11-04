//! Bounded IP device and the application-facing TCP state machine.

use super::{OUTPUT_PACKETS, STREAM_BUFFER};
use crate::packet::{self, Flow};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, TcpPacket, TcpRepr, TcpSeqNumber},
};
use std::{
    collections::{VecDeque, hash_map::RandomState},
    hash::BuildHasher,
    sync::Arc,
};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
};

pub(super) struct Stack {
    pub interface: Interface,
    pub sockets: SocketSet<'static>,
    pub device: PacketDevice,
}

impl Stack {
    pub fn new(
        mtu: usize,
        input: Arc<dyn RelayBufferAllocator>,
        output: Arc<dyn RelayBufferAllocator>,
    ) -> Self {
        let mut device = PacketDevice {
            incoming: None,
            outgoing: VecDeque::with_capacity(OUTPUT_PACKETS),
            mtu,
            input,
            output,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = RandomState::new().hash_one("local TCP sequence seed");
        let mut interface = Interface::new(config, &mut device, Instant::ZERO);
        let v4 = "192.0.2.1".parse().expect("internal IPv4");
        let v6 = "2001:db8::1".parse().expect("internal IPv6");
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(v4), 32))
                .expect("IPv4 slot");
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(v6), 128))
                .expect("IPv6 slot");
        });
        interface.set_any_ip(true);
        interface
            .routes_mut()
            .add_default_ipv4_route(v4)
            .expect("IPv4 route slot");
        interface
            .routes_mut()
            .add_default_ipv6_route(v6)
            .expect("IPv6 route slot");
        Self {
            interface,
            sockets: SocketSet::new(Vec::with_capacity(super::TCP_FLOWS)),
            device,
        }
    }

    // Never expose a destination-only listener to the owner. Installation is a
    // transaction: feed the held SYN and verify the exact local/remote tuple
    // before another listener may be installed, or remove it on every failure.
    pub fn accept_syn(&mut self, flow: Flow, syn: &[u8], now: Instant) -> Option<SocketHandle> {
        if packet::parse(syn).ok()?.flow != flow || !valid_syn(syn) {
            return None;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; STREAM_BUFFER]),
            tcp::SocketBuffer::new(vec![0; STREAM_BUFFER]),
        );
        socket.set_ack_delay(None);
        socket.listen(flow.destination).ok()?;
        let handle = self.sockets.add(socket);
        let received = self.receive(syn, now);
        let endpoint = self.sockets.get::<tcp::Socket<'_>>(handle);
        if received
            && endpoint.state() == tcp::State::SynReceived
            && endpoint.local_endpoint() == Some(flow.destination.into())
            && endpoint.remote_endpoint() == Some(flow.source.into())
        {
            Some(handle)
        } else {
            self.sockets.remove(handle);
            None
        }
    }

    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> bool {
        if self.device.outgoing.len() == OUTPUT_PACKETS {
            return false;
        }
        let Ok(bytes) = RelayBuffer::copy_from(bytes, &*self.device.input) else {
            return false;
        };
        self.device.incoming = Some(bytes);
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        // A full output queue can defer ingress; never retain unowned input.
        self.device.incoming.take();
        true
    }

    pub fn poll(&mut self, now: Instant) {
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
    }
}

/// Cheap admission validation agrees with smoltcp's wire representation, while
/// accept_syn additionally checks the state machine's actual tuple acceptance.
pub(super) fn valid_syn(bytes: &[u8]) -> bool {
    let Ok(parsed) = packet::parse(bytes) else {
        return false;
    };
    if !parsed
        .tcp_flags
        .is_some_and(|f| f.syn && !f.ack && !f.fin && !f.rst)
    {
        return false;
    }
    let offset = if bytes[0] >> 4 == 4 {
        usize::from(bytes[0] & 15) * 4
    } else {
        40
    };
    let Ok(tcp) = TcpPacket::new_checked(&bytes[offset..]) else {
        return false;
    };
    TcpRepr::parse(
        &tcp,
        &parsed.flow.source.ip().into(),
        &parsed.flow.destination.ip().into(),
        &phy::ChecksumCapabilities::default(),
    )
    .is_ok()
}

#[derive(Clone, Copy)]
pub(super) struct Segment {
    pub seq: TcpSeqNumber,
    pub end: TcpSeqNumber,
    pub ack: Option<TcpSeqNumber>,
    pub syn: bool,
    pub rst: bool,
}

pub(super) fn segment(bytes: &[u8]) -> Option<Segment> {
    let parsed = packet::parse(bytes).ok()?;
    let flags = parsed.tcp_flags?;
    let offset = if bytes[0] >> 4 == 4 {
        usize::from(bytes[0] & 15) * 4
    } else {
        40
    };
    let tcp = TcpPacket::new_checked(&bytes[offset..]).ok()?;
    Some(Segment {
        seq: tcp.seq_number(),
        end: tcp.seq_number()
            + parsed.payload.len()
            + usize::from(flags.syn)
            + usize::from(flags.fin),
        ack: flags.ack.then(|| tcp.ack_number()),
        syn: flags.syn,
        rst: flags.rst,
    })
}

pub(super) struct PacketDevice {
    incoming: Option<RelayBuffer>,
    pub outgoing: VecDeque<RelayBuffer>,
    mtu: usize,
    input: Arc<dyn RelayBufferAllocator>,
    output: Arc<dyn RelayBufferAllocator>,
}
pub(super) struct Rx(RelayBuffer);
pub(super) struct Tx<'a> {
    outgoing: &'a mut VecDeque<RelayBuffer>,
    charge: Arc<dyn RelayBufferReservation>,
    mtu: usize,
}
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        assert!(len <= self.mtu, "stack output exceeds advertised MTU");
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        let bytes =
            RelayBuffer::from_reservation(bytes, self.charge).expect("precharged stack output");
        self.outgoing.push_back(bytes);
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if self.outgoing.len() == OUTPUT_PACKETS {
            return None;
        }
        let charge = self.output.try_reserve(self.mtu + BUFFER_OVERHEAD).ok()?;
        Some((
            Rx(self.incoming.take()?),
            Tx {
                outgoing: &mut self.outgoing,
                charge,
                mtu: self.mtu,
            },
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        if self.outgoing.len() == OUTPUT_PACKETS {
            return None;
        }
        let charge = self.output.try_reserve(self.mtu + BUFFER_OVERHEAD).ok()?;
        Some(Tx {
            outgoing: &mut self.outgoing,
            charge,
            mtu: self.mtu,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// RFC 9293 reset response. Never answer a reset with another reset.
pub(super) fn reset(bytes: &[u8]) -> Option<Vec<u8>> {
    let parsed = packet::parse(bytes).ok()?;
    let flags = parsed.tcp_flags?;
    if flags.rst {
        return None;
    }
    let offset = match bytes[0] >> 4 {
        4 => usize::from(bytes[0] & 15) * 4,
        _ => 40,
    };
    let original = TcpPacket::new_checked(&bytes[offset..]).ok()?;
    let flow = parsed.flow;
    let (mut reply, offset) =
        packet::ip_packet(flow.destination, flow.source, IpProtocol::Tcp, 20).ok()?;
    let mut tcp = TcpPacket::new_unchecked(&mut reply[offset..]);
    tcp.set_header_len(20);
    tcp.set_src_port(flow.destination.port());
    tcp.set_dst_port(flow.source.port());
    tcp.set_rst(true);
    if flags.ack {
        tcp.set_seq_number(original.ack_number());
    } else {
        tcp.set_seq_number(TcpSeqNumber(0));
        tcp.set_ack(true);
        tcp.set_ack_number(
            original.seq_number()
                + parsed.payload.len()
                + usize::from(flags.syn)
                + usize::from(flags.fin),
        );
    }
    tcp.fill_checksum(&flow.destination.ip().into(), &flow.source.ip().into());
    Some(reply)
}
