//! Opaque managed relay IP, with the same boundary as native GotaTun TUN input.
//! Only Local enters the separate TCP/UDP parser. This adapter neither translates
//! addresses nor validates transport protocols, checksums, extensions or flows.
use bytes::BytesMut;
use gotatun::packet::{Decoder, Ip, IpDecoder, Packet};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, MAX_RELAY_PACKET_SIZE, RelayAttempt, RelayBuffer, RelayBufferAllocator,
    RelayFlowError, RelayPacket,
};
use zerocopy::IntoBytes;

/// GotaTun's TunIpRecv uses Packet::try_into_ip (minimum length only), followed
/// by SourceFilter's source extraction. Use those same operations without an
/// allocation. In particular, try_into_ipvx would add length validation and
/// truncate bytes, so it is not the native outbound boundary.
pub fn inspect(bytes: &[u8]) -> Result<&Ip, RelayFlowError> {
    if bytes.len() > MAX_RELAY_PACKET_SIZE {
        return Err(RelayFlowError::Invalid);
    }
    let ip = IpDecoder {
        version: false,
        min_length: true,
    }
    .decode_ref(bytes)
    .map_err(|_| RelayFlowError::Invalid)?;
    ip.source().ok_or(RelayFlowError::Invalid)?;
    Ok(ip)
}

/// Capture bytes are copied only after native-equivalent source validation and
/// reservation. Assigned source identity is immutable for this exact attempt.
/// This does not replace WireGuard's SourceFilter, which remains in place.
pub fn outbound(
    bytes: &[u8],
    attempt: &RelayAttempt,
    buffers: &dyn RelayBufferAllocator,
) -> Result<RelayPacket, RelayFlowError> {
    if !attempt.current() {
        return Err(RelayFlowError::Stale);
    }
    let ip = inspect(bytes)?;
    if !ip
        .source()
        .is_some_and(|source| attempt.identity().sources.contains(source))
    {
        return Err(RelayFlowError::Invalid);
    }
    attempt.packet(RelayBuffer::copy_from(bytes, buffers)?)
}

/// Item 5's authenticated return demultiplexer injects the exact live attempt
/// capability after private pinger matching. No application-origin boolean can
/// grant this authority. Return IP is not filtered by the outbound source set.
pub fn authenticated_return(
    packet: Packet<Ip>,
    attempt: &RelayAttempt,
    buffers: &dyn RelayBufferAllocator,
) -> Result<RelayPacket, RelayFlowError> {
    if !attempt.current() {
        return Err(RelayFlowError::Stale);
    }
    let bytes = packet.as_bytes();
    inspect(bytes)?;
    attempt.packet(RelayBuffer::copy_from(bytes, buffers)?)
}

/// Convert only at the actual synchronous WireGuard handoff. All queues before
/// this boundary retain RelayPacket, not Packet<Ip>. Both copies and authority
/// remain retained through the callback, including the transient native buffer.
/// The callback must hand off immediately, without awaiting or broker/lifecycle
/// reentry. Native-owned allocations after handoff are outside our byte budget.
pub fn handoff<T>(
    packet: RelayPacket,
    buffers: &dyn RelayBufferAllocator,
    operation: impl FnOnce(Packet<Ip>) -> T,
) -> Result<T, RelayFlowError> {
    packet.handoff(|bytes| {
        let charge = buffers.try_reserve(bytes.len() + BUFFER_OVERHEAD)?;
        let native = BytesMut::from(bytes);
        if native.capacity() + BUFFER_OVERHEAD > charge.bytes() {
            return Err(RelayFlowError::Full);
        }
        let native = Packet::from_bytes(native)
            .try_into_ip()
            .map_err(|_| RelayFlowError::Invalid)?;
        let result = operation(native);
        drop(charge);
        Ok(result)
    })?
}

#[cfg(test)]
mod tests;
