//! Checked emission and sender-side PMTU feedback, using application credit.
use crate::{
    address_translation::{
        Header, TranslationError, checksum, is_icmp_error, set_transport_checksum, word,
    },
    fragment_state::{Fragmentation, copied_options},
};
use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayAttempt, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
    RelayPacket, RelaySink, RelayWriteOutcome,
};

pub struct Emission {
    packets: VecDeque<RelayPacket>,
    _metadata: Arc<dyn RelayBufferReservation>,
}

impl Emission {
    pub fn pop(&mut self) -> Option<RelayPacket> {
        self.packets.pop_front()
    }
    pub fn len(&self) -> usize {
        self.packets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

pub(crate) fn emit(
    bytes: &[u8],
    mtu: u16,
    fragmentation: Option<Fragmentation>,
    attempt: &RelayAttempt,
    buffers: &dyn RelayBufferAllocator,
) -> Result<Emission, TranslationError> {
    let header = Header::parse(bytes, false)?;
    let mtu = usize::from(mtu);
    let too_big = bytes.len() > mtu;
    if too_big
        && ((header.ipv4 && word(bytes, 6) & 0x4000 != 0)
            || (!header.ipv4 && fragmentation.is_none()))
    {
        return Err(TranslationError::PacketTooBig);
    }
    let (prefix, next_field, id) = if header.ipv4 {
        (header.transport, 9, 0)
    } else if let Some(fragment) = fragmentation {
        (fragment.boundary, fragment.next_field, fragment.id)
    } else {
        (40, 6, 0)
    };
    let (options, option_length) = if header.ipv4 {
        copied_options(&bytes[..prefix])?
    } else {
        ([0; 40], 0)
    };
    let overhead = prefix + if header.ipv4 { 0 } else { 8 };
    let quantum = if too_big {
        mtu.checked_sub(overhead)
            .ok_or(TranslationError::PacketTooBig)?
            / 8
            * 8
    } else {
        bytes.len()
    };
    if quantum == 0 {
        return Err(TranslationError::PacketTooBig);
    }
    let count = if too_big {
        (bytes.len() - prefix).div_ceil(quantum)
    } else {
        1
    };
    let metadata =
        buffers.try_reserve(count * std::mem::size_of::<RelayPacket>() + BUFFER_OVERHEAD)?;
    let mut packets = VecDeque::with_capacity(count);
    if !too_big {
        packets.push_back(attempt.packet(RelayBuffer::copy_from(bytes, buffers)?)?);
        return Ok(Emission {
            packets,
            _metadata: metadata,
        });
    }
    let payload = &bytes[prefix..];
    let mut offset = 0;
    while offset < payload.len() {
        let prefix_length = if header.ipv4 && offset != 0 {
            20 + option_length
        } else {
            prefix
        };
        let overhead = prefix_length + if header.ipv4 { 0 } else { 8 };
        let capacity = mtu
            .checked_sub(overhead)
            .ok_or(TranslationError::PacketTooBig)?;
        let remaining = payload.len() - offset;
        let length = if remaining > capacity {
            capacity / 8 * 8
        } else {
            remaining
        };
        if length == 0 {
            return Err(TranslationError::PacketTooBig);
        }
        let charge = buffers.try_reserve(overhead + length + BUFFER_OVERHEAD)?;
        let mut output = vec![0; overhead + length];
        if header.ipv4 && offset != 0 {
            output[..20].copy_from_slice(&bytes[..20]);
            output[20..prefix_length].copy_from_slice(&options[..option_length]);
            output[0] = 0x40 | (prefix_length / 4) as u8;
        } else {
            output[..prefix_length].copy_from_slice(&bytes[..prefix_length]);
        }
        let more = offset + length < payload.len();
        if header.ipv4 {
            output[2..4].copy_from_slice(&((overhead + length) as u16).to_be_bytes());
            output[6..8].copy_from_slice(
                &(((offset / 8) as u16) | if more { 0x2000 } else { 0 }).to_be_bytes(),
            );
            output[10..12].fill(0);
            let sum = checksum(&[&output[..prefix_length]]);
            output[10..12].copy_from_slice(&sum.to_be_bytes());
        } else {
            output[next_field] = 44;
            output[prefix_length] = bytes[next_field];
            output[prefix_length + 2..prefix_length + 4]
                .copy_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
            output[prefix_length + 4..prefix_length + 8].copy_from_slice(&id.to_be_bytes());
            output[4..6].copy_from_slice(&((overhead + length - 40) as u16).to_be_bytes());
        }
        output[overhead..].copy_from_slice(&payload[offset..offset + length]);
        packets.push_back(attempt.packet(RelayBuffer::from_reservation(output, charge)?)?);
        offset += length;
    }
    Ok(Emission {
        packets,
        _metadata: metadata,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackSide {
    App,
    Target,
}

pub(crate) struct FeedbackRoute {
    pub source: IpAddr,
    pub mtu: u16,
    pub return_mtu: u16,
    pub side: FeedbackSide,
}

struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Private construction is the feedback producer capability. App bytes cannot
/// label themselves as assigned-source feedback. Writes retain authority/credit.
pub struct Feedback {
    packet: RelayPacket,
    side: FeedbackSide,
    _slot: Slot,
    buffers: Arc<dyn RelayBufferAllocator>,
}
impl Feedback {
    pub fn buffers(&self) -> Arc<dyn RelayBufferAllocator> {
        self.buffers.clone()
    }
    pub fn attempt(&self) -> RelayAttempt {
        self.packet.view().attempt().clone()
    }
    pub fn side(&self) -> FeedbackSide {
        self.side
    }
    /// The consumer must also check the current output sink/session in `write`.
    /// This callback is the final whole-packet syscall or target handoff.
    pub fn write(&mut self, write: impl FnOnce(&[u8]) -> io::Result<usize>) -> RelayWriteOutcome {
        self.packet.write(write)
    }
    pub fn write_to(
        &mut self,
        sink: &RelaySink,
        write: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        self.packet.write_to(sink, write)
    }
    pub fn handoff<T>(
        self,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, talpid_types::relay_flow::RelayFlowError> {
        self.packet.handoff(operation)
    }
}

pub(crate) struct FeedbackQueue {
    pending: VecDeque<Feedback>,
    slots: Arc<AtomicUsize>,
    buffers: Arc<dyn RelayBufferAllocator>,
    tokens: u8,
    refill: Option<Instant>,
    _metadata: Arc<dyn RelayBufferReservation>,
}

const REFILL: Duration = Duration::from_millis(125);

impl FeedbackQueue {
    pub fn new(application: &dyn RelayBufferAllocator) -> Result<Self, TranslationError> {
        let region = application.try_reserve(64 * 1024)?;
        let buffers = region.allocator()?;
        let metadata =
            buffers.try_reserve(16 * std::mem::size_of::<Feedback>() + 2 * BUFFER_OVERHEAD)?;
        Ok(Self {
            pending: VecDeque::with_capacity(16),
            slots: Arc::new(AtomicUsize::new(0)),
            buffers,
            tokens: 8,
            refill: None,
            _metadata: metadata,
        })
    }
    pub fn pop(&mut self) -> Option<Feedback> {
        self.pending.pop_front()
    }
    pub fn pop_side(&mut self, side: FeedbackSide) -> Option<Feedback> {
        let index = self
            .pending
            .iter()
            .position(|feedback| feedback.side == side)?;
        self.pending.remove(index)
    }
    pub fn clear(&mut self) {
        self.pending.clear();
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.refill
    }
    pub fn maintain(&mut self, now: Instant) {
        if let Some(deadline) = self.refill.filter(|deadline| *deadline <= now) {
            let steps = 1 + now.duration_since(deadline).as_nanos() / REFILL.as_nanos();
            self.tokens = (u128::from(self.tokens) + steps).min(8) as u8;
            self.refill = if self.tokens == 8 {
                None
            } else {
                Some(deadline + REFILL * steps as u32)
            };
        }
    }
    pub fn generate(
        &mut self,
        invoking: &[u8],
        validated_datagram: &[u8],
        route: FeedbackRoute,
        attempt: &RelayAttempt,
        now: Instant,
    ) -> Result<(), TranslationError> {
        let FeedbackRoute {
            source,
            mtu,
            return_mtu,
            side,
        } = route;
        let header = Header::parse(invoking, true)?;
        let datagram = Header::parse(validated_datagram, false)?;
        if header.ipv4 != datagram.ipv4
            || header.source != datagram.source
            || header.destination != datagram.destination
        {
            return Err(TranslationError::Endpoint);
        }
        // The quote can end before ICMP's type or even its extension chain.
        // Suppression uses the validated full datagram; non-initial provenance
        // remains a refusal even if somebody supplies a normalized first header.
        if header.non_initial || suppress(validated_datagram, &datagram) {
            return Err(TranslationError::Suppressed);
        }
        self.maintain(now);
        if self.slots.load(Ordering::Acquire) >= 16 {
            return Err(TranslationError::FeedbackFull);
        }
        if self.tokens == 0 {
            return Err(TranslationError::RateLimited);
        }
        let ip = if header.ipv4 { 20 } else { 40 };
        let bound = usize::from(return_mtu).min(if header.ipv4 { 576 } else { 1280 });
        let quote = invoking.len().min(
            bound
                .checked_sub(ip + 8)
                .ok_or(TranslationError::PacketTooBig)?,
        );
        let required = if header.ipv4 {
            header.transport + 8
        } else {
            40
        };
        if quote < required {
            return Err(TranslationError::PacketTooBig);
        }
        let length = ip + 8 + quote;
        let charge = self.buffers.try_reserve(length + BUFFER_OVERHEAD)?;
        let mut output = vec![0; length];
        match (source, header.source) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                output[0] = 0x45;
                output[2..4].copy_from_slice(&(length as u16).to_be_bytes());
                output[8] = 64;
                output[9] = 1;
                output[12..16].copy_from_slice(&source.octets());
                output[16..20].copy_from_slice(&destination.octets());
                output[20] = 3;
                output[21] = 4;
                output[26..28].copy_from_slice(&mtu.to_be_bytes());
                let sum = checksum(&[&output[..20]]);
                output[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                output[0] = 0x60;
                output[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
                output[6] = 58;
                output[7] = 64;
                output[8..24].copy_from_slice(&source.octets());
                output[24..40].copy_from_slice(&destination.octets());
                output[40] = 2;
                output[44..48].copy_from_slice(&u32::from(mtu).to_be_bytes());
            }
            _ => return Err(TranslationError::Family),
        }
        output[ip + 8..].copy_from_slice(&invoking[..quote]);
        let outer = Header::parse(&output, false)?;
        set_transport_checksum(&mut output, &outer);
        let packet = attempt.packet(RelayBuffer::from_reservation(output, charge)?)?;
        self.slots.fetch_add(1, Ordering::AcqRel);
        self.pending.push_back(Feedback {
            packet,
            side,
            _slot: Slot(self.slots.clone()),
            buffers: self.buffers.clone(),
        });
        self.tokens -= 1;
        if self.refill.is_none() {
            self.refill = Some(now + REFILL);
        }
        Ok(())
    }
}

fn suppress(bytes: &[u8], header: &Header) -> bool {
    if is_icmp_error(bytes, header) || header.non_initial {
        return true;
    }
    match (header.source, header.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            source.octets()[0] == 0
                || source.is_loopback()
                || source.octets()[0] >= 224
                || destination.is_multicast()
                || destination.is_broadcast()
        }
        (IpAddr::V6(source), _) => {
            // PTB is the RFC4443 multicast-destination exception. Multicast
            // sources, other errors and Redirect never generate another error.
            source.is_unspecified()
                || source.is_multicast()
                || source.is_loopback()
                || (header.protocol == 58
                    && bytes
                        .get(header.transport)
                        .is_some_and(|kind| *kind < 128 || *kind == 137))
        }
        _ => true,
    }
}
