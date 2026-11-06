//! One-to-one address translation owned by one tunnel target attempt.
//!
//! Input is one plain IP wire packet, with complete checksums, not a TUN PI,
//! virtio/GSO object or partial checksum seed. Platform capture admission must
//! establish that representation before using this boundary. Local bypasses it.
//! ESP is opaque passthrough (tunnel-mode IPsec works; transport mode without
//! NAT-T is not supported). NAT-T UDP 4500 uses the ordinary UDP path.
use std::{net::IpAddr, sync::Arc};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, MAX_RELAY_PACKET_SIZE, RelayAttempt, RelayBuffer, RelayBufferAllocator,
    RelayBufferReservation, RelayFlowError, RelayPacket, RelaySources,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Outbound,
    Inbound,
}

/// Configuration is not authority. The retained attempt is checked separately.
#[derive(Clone, Copy, Debug)]
pub struct TargetConfig {
    pub target_id: u64,
    pub fixed: RelaySources,
    pub assigned: RelaySources,
    pub mtu: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum TranslationError {
    Malformed,
    Checksum,
    Endpoint,
    Family,
    UnsupportedTranslation,
    BackendRefused,
    Fragment,
    Full,
    Stale,
}

impl From<RelayFlowError> for TranslationError {
    fn from(error: RelayFlowError) -> Self {
        match error {
            RelayFlowError::Full => Self::Full,
            RelayFlowError::Stale | RelayFlowError::Closed => Self::Stale,
            RelayFlowError::Invalid => Self::Malformed,
        }
    }
}

/// Fixed-size, saturating per-attempt counters; no per-packet log or status RPC.
#[derive(Clone, Debug, Default)]
pub struct TranslationSummary {
    pub translated: u64,
    refusals: [u64; 9],
}

impl TranslationSummary {
    pub fn refused(&self, reason: TranslationError) -> u64 {
        self.refusals[reason as usize]
    }

    pub(crate) fn refuse(&mut self, reason: TranslationError) {
        let count = &mut self.refusals[reason as usize];
        *count = count.saturating_add(1);
    }
}

pub struct AddressTranslator {
    config: TargetConfig,
    attempt: RelayAttempt,
    buffers: Arc<dyn RelayBufferAllocator>,
    summary: TranslationSummary,
    _metadata: Arc<dyn RelayBufferReservation>,
}

impl AddressTranslator {
    pub fn new(
        config: TargetConfig,
        attempt: RelayAttempt,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Result<Self, TranslationError> {
        if config.target_id == 0
            || config.mtu < 68
            || (config.assigned.ipv6.is_some() && config.mtu < 1280)
            || (config.assigned.ipv4.is_none() && config.assigned.ipv6.is_none())
            || (config.assigned.ipv4.is_some() && config.fixed.ipv4.is_none())
            || (config.assigned.ipv6.is_some() && config.fixed.ipv6.is_none())
        {
            return Err(TranslationError::Malformed);
        }
        let metadata = buffers.try_reserve(BUFFER_OVERHEAD)?;
        Ok(Self {
            config,
            attempt,
            buffers,
            summary: TranslationSummary::default(),
            _metadata: metadata,
        })
    }

    pub fn config(&self) -> TargetConfig {
        self.config
    }

    pub fn summary(&self) -> &TranslationSummary {
        &self.summary
    }

    /// Call only for a real refusal by the selected backend, after translation.
    pub fn backend_refused(&mut self) {
        self.summary.refuse(TranslationError::BackendRefused);
    }

    pub fn translate(
        &mut self,
        bytes: &[u8],
        direction: Direction,
    ) -> Result<RelayPacket, TranslationError> {
        let result = self
            .translate_buffer(bytes, direction)
            .and_then(|bytes| self.attempt.packet(bytes).map_err(TranslationError::from));
        match &result {
            Ok(_) => self.summary.translated = self.summary.translated.saturating_add(1),
            Err(reason) => self.summary.refuse(*reason),
        }
        result
    }

    pub(crate) fn translate_buffer(
        &self,
        bytes: &[u8],
        direction: Direction,
    ) -> Result<RelayBuffer, TranslationError> {
        if !self.attempt.current() {
            return Err(TranslationError::Stale);
        }
        let header = Header::parse(bytes, false)?;
        let (old, new) = self.endpoints(&header, direction)?;
        validate_transport(bytes, &header)?;
        // Quotations are validated before any output allocation too.
        let quote = crate::icmp_quotation::inspect(bytes, &header, direction, old, new)?;
        let mut output = RelayBuffer::copy_from(bytes, self.buffers.as_ref())?;
        rewrite_endpoint(&mut output, &header, direction == Direction::Outbound, new)?;
        if let Some(quote) = quote {
            crate::icmp_quotation::rewrite(&mut output, &quote, old, new)?;
            // Quotation mutations change the ICMP body, not just its pseudoheader.
            set_transport_checksum(&mut output, &header);
        } else if let Some(offset) = checksum_field(&header, bytes)? {
            let value = word(bytes, offset);
            if !(header.protocol == 17 && header.ipv4 && value == 0)
                && !(header.protocol == 1 && header.ipv4)
            {
                let mut value = adjusted(value, &address_bytes(old), &address_bytes(new));
                if header.protocol == 17 && value == 0 {
                    value = u16::MAX;
                }
                output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
            }
        }
        if !self.attempt.current() {
            return Err(TranslationError::Stale);
        }
        Ok(output)
    }

    pub(crate) fn endpoints(
        &self,
        header: &Header,
        direction: Direction,
    ) -> Result<(IpAddr, IpAddr), TranslationError> {
        let address = |sources: RelaySources| {
            if header.ipv4 {
                sources.ipv4.map(IpAddr::V4)
            } else {
                sources.ipv6.map(IpAddr::V6)
            }
        };
        let fixed = address(self.config.fixed).ok_or(TranslationError::Family)?;
        let assigned = address(self.config.assigned).ok_or(TranslationError::Family)?;
        let (actual, old, new) = match direction {
            Direction::Outbound => (header.source, fixed, assigned),
            Direction::Inbound => (header.destination, assigned, fixed),
        };
        if actual != old {
            return Err(TranslationError::Endpoint);
        }
        Ok((old, new))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub ipv4: bool,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub transport: usize,
    /// False when a quotation ends before the upper-layer boundary is known.
    pub transport_known: bool,
    pub protocol: u8,
    pub declared: usize,
    pub non_initial: bool,
    pub fragmented: bool,
}

impl Header {
    /// Quotes may end before the original datagram; never pad absent bytes.
    pub(crate) fn parse(bytes: &[u8], quoted: bool) -> Result<Self, TranslationError> {
        let malformed = TranslationError::Malformed;
        if bytes.len() > MAX_RELAY_PACKET_SIZE {
            return Err(malformed);
        }
        let mut header = match bytes.first().map(|byte| byte >> 4) {
            Some(4) if bytes.len() >= 20 => {
                let size = usize::from(bytes[0] & 15) * 4;
                let declared = usize::from(word(bytes, 2));
                if !(20..=60).contains(&size) || (!quoted && size > bytes.len()) || declared < size
                {
                    return Err(malformed);
                }
                if size <= bytes.len() && checksum(&[&bytes[..size]]) != 0 {
                    return Err(TranslationError::Checksum);
                }
                validate_options(&bytes[20..size.min(bytes.len())], true, size - 20, quoted)?;
                let flags = word(bytes, 6);
                if flags & 0x8000 != 0 || flags & 0x6000 == 0x6000 {
                    return Err(malformed);
                }
                Self {
                    ipv4: true,
                    source: <[u8; 4]>::try_from(&bytes[12..16]).unwrap().into(),
                    destination: <[u8; 4]>::try_from(&bytes[16..20]).unwrap().into(),
                    transport: size,
                    transport_known: size <= bytes.len(),
                    protocol: bytes[9],
                    declared,
                    non_initial: flags & 0x1fff != 0,
                    fragmented: flags & 0x3fff != 0,
                }
            }
            Some(6) if bytes.len() >= 40 => Self {
                ipv4: false,
                source: <[u8; 16]>::try_from(&bytes[8..24]).unwrap().into(),
                destination: <[u8; 16]>::try_from(&bytes[24..40]).unwrap().into(),
                transport: 40,
                transport_known: true,
                protocol: bytes[6],
                declared: 40 + usize::from(word(bytes, 4)),
                non_initial: false,
                fragmented: false,
            },
            _ => return Err(malformed),
        };
        if (!quoted && header.declared != bytes.len()) || header.declared < header.transport {
            return Err(malformed);
        }
        if !header.ipv4 {
            let end = bytes.len().min(header.declared);
            let mut extensions = 0;
            while matches!(header.protocol, 0 | 43 | 44 | 60) {
                extensions += 1;
                if extensions > 8 || header.transport + 8 > header.declared {
                    return Err(malformed);
                }
                let offset = header.transport;
                let protocol = header.protocol;
                if offset + 2 > end {
                    if !quoted {
                        return Err(malformed);
                    }
                    header.transport_known = false;
                    break;
                }
                let length = if protocol == 44 {
                    8
                } else {
                    (usize::from(bytes[offset + 1]) + 1) * 8
                };
                if offset + length > header.declared || (protocol == 0 && offset != 40) {
                    return Err(malformed);
                }
                let present = length.min(end - offset);
                match protocol {
                    0 | 60 => validate_options(
                        &bytes[offset + 2..offset + present],
                        false,
                        length - 2,
                        quoted,
                    )?,
                    43 if present >= 4 && bytes[offset + 3] != 0 => {
                        return Err(TranslationError::UnsupportedTranslation);
                    }
                    44 => {
                        if header.fragmented
                            || bytes[offset + 1] != 0
                            || (present >= 4 && word(bytes, offset + 2) & 6 != 0)
                        {
                            return Err(malformed);
                        }
                        header.non_initial = present >= 4 && word(bytes, offset + 2) & 0xfff8 != 0;
                        header.fragmented = true;
                    }
                    _ => (),
                }
                if present < length {
                    if !quoted {
                        return Err(malformed);
                    }
                    header.transport_known = false;
                    break;
                }
                header.protocol = bytes[offset];
                header.transport += length;
                if header.non_initial {
                    break;
                }
            }
        }
        if header.fragmented && !quoted {
            return Err(TranslationError::Fragment);
        }
        Ok(header)
    }
}

fn validate_options(
    bytes: &[u8],
    ipv4: bool,
    declared: usize,
    quoted: bool,
) -> Result<(), TranslationError> {
    let mut offset = 0;
    while offset < declared {
        if offset >= bytes.len() {
            return if quoted {
                Ok(())
            } else {
                Err(TranslationError::Malformed)
            };
        }
        let kind = bytes[offset];
        if ipv4 && kind == 0 {
            break;
        }
        if (ipv4 && kind == 1) || (!ipv4 && kind == 0) {
            offset += 1;
            continue;
        }
        // A visible unsupported kind is a semantic refusal even if its tail is
        // absent. Missing bytes of a supported option are not malformed bytes.
        if !(if ipv4 {
            matches!(kind, 7 | 68 | 148)
        } else {
            matches!(kind, 1 | 5)
        }) {
            return Err(TranslationError::UnsupportedTranslation);
        }
        if offset + 2 > declared {
            return Err(TranslationError::Malformed);
        }
        let Some(extra) = bytes.get(offset + 1) else {
            return if quoted {
                Ok(())
            } else {
                Err(TranslationError::Malformed)
            };
        };
        let extra = usize::from(*extra);
        let length = if ipv4 { extra } else { extra + 2 };
        if length < 2 || offset + length > declared {
            return Err(TranslationError::Malformed);
        }
        // RR, Timestamp, Router Alert do not change the pseudoheader endpoint.
        // Source routes and Home Address options do, and are not transparent.
        if (ipv4
            && match kind {
                148 => length != 4,
                7 => length < 3 || (length - 3) % 4 != 0,
                68 => length < 4,
                _ => false,
            })
            || (!ipv4 && kind == 5 && extra != 2)
        {
            return Err(TranslationError::Malformed);
        }
        offset += length;
    }
    Ok(())
}

pub(crate) fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub(crate) fn checksum(parts: &[&[u8]]) -> u16 {
    gotatun::packet::checksum(parts)
}

pub(crate) fn address_bytes(address: IpAddr) -> VecAddress {
    match address {
        IpAddr::V4(value) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&value.octets());
            VecAddress { bytes, length: 4 }
        }
        IpAddr::V6(value) => VecAddress {
            bytes: value.octets(),
            length: 16,
        },
    }
}

pub(crate) struct VecAddress {
    bytes: [u8; 16],
    length: usize,
}

impl std::ops::Deref for VecAddress {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// RFC1624, valid for complete checksum words even in truncated quotations.
pub(crate) fn adjusted(value: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!value);
    for (old, new) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        sum += u32::from(!u16::from_be_bytes([old[0], old[1]]));
        sum += u32::from(u16::from_be_bytes([new[0], new[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn rewrite_endpoint(
    bytes: &mut [u8],
    header: &Header,
    source: bool,
    address: IpAddr,
) -> Result<(), TranslationError> {
    let start = match (header.ipv4, source, address) {
        (true, true, IpAddr::V4(_)) => 12,
        (true, false, IpAddr::V4(_)) => 16,
        (false, true, IpAddr::V6(_)) => 8,
        (false, false, IpAddr::V6(_)) => 24,
        _ => return Err(TranslationError::Family),
    };
    let address = address_bytes(address);
    bytes[start..start + address.len()].copy_from_slice(&address);
    if header.ipv4 {
        // A quoted IPv4 header can end inside options. Updating its complete
        // checksum word needs only the changed addresses, not the absent tail.
        let old = address_bytes(if source {
            header.source
        } else {
            header.destination
        });
        let value = adjusted(word(bytes, 10), &old, &address);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

pub(crate) fn is_icmp_error(bytes: &[u8], header: &Header) -> bool {
    header.transport_known
        && bytes.get(header.transport).is_some_and(|kind| {
            (header.ipv4 && header.protocol == 1 && matches!(kind, 3 | 11 | 12))
                || (!header.ipv4 && header.protocol == 58 && matches!(kind, 1..=4))
        })
}

pub(crate) fn checksum_field(
    header: &Header,
    bytes: &[u8],
) -> Result<Option<usize>, TranslationError> {
    if !header.transport_known {
        return Ok(None);
    }
    let offset = match header.protocol {
        6 => 16,
        17 => 6,
        1 if header.ipv4 => 2,
        58 if !header.ipv4 => 2,
        // GRE checksums and SCTP CRC32c exclude the outer IP addresses.
        47 | 132 => return Ok(None),
        // Opaque passthrough (tunnel-mode IPsec works; transport mode without
        // NAT-T is not supported). NAT-T UDP 4500 follows ordinary UDP.
        50 => return Ok(None),
        _ => return Err(TranslationError::UnsupportedTranslation),
    };
    if header.non_initial {
        return Ok(None);
    }
    Ok(
        (header.transport + offset + 2 <= bytes.len().min(header.declared))
            .then_some(header.transport + offset),
    )
}

pub(crate) fn transport_checksum(bytes: &[u8], header: &Header) -> u16 {
    let length = (bytes.len() - header.transport) as u32;
    if header.ipv4 && header.protocol == 1 {
        checksum(&[&bytes[header.transport..]])
    } else if header.ipv4 {
        checksum(&[
            &bytes[12..20],
            &[0, header.protocol],
            &(length as u16).to_be_bytes(),
            &bytes[header.transport..],
        ])
    } else {
        checksum(&[
            &bytes[8..40],
            &length.to_be_bytes(),
            &[0, 0, 0, header.protocol],
            &bytes[header.transport..],
        ])
    }
}

pub(crate) fn set_transport_checksum(bytes: &mut [u8], header: &Header) {
    let offset = header.transport + 2;
    bytes[offset..offset + 2].fill(0);
    let value = transport_checksum(bytes, header);
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn validate_transport(bytes: &[u8], header: &Header) -> Result<(), TranslationError> {
    let segment = &bytes[header.transport..];
    let malformed = TranslationError::Malformed;
    match header.protocol {
        6 => {
            if segment.len() < 20 {
                return Err(malformed);
            }
            let length = usize::from(segment[12] >> 4) * 4;
            if length < 20 || length > segment.len() {
                return Err(malformed);
            }
        }
        17 => {
            if segment.len() < 8 || usize::from(word(segment, 4)) != segment.len() {
                return Err(malformed);
            }
            if word(segment, 6) == 0 {
                return if header.ipv4 {
                    Ok(())
                } else {
                    Err(TranslationError::Checksum)
                };
            }
        }
        1 if header.ipv4 => {
            if segment.len() < 8 {
                return Err(malformed);
            }
            let minimum = match segment[0] {
                0 | 8 | 15 | 16 => 8,
                13 | 14 => 20,
                17 | 18 => 12,
                3 | 11 | 12 => 8,
                _ => return Err(TranslationError::UnsupportedTranslation),
            };
            if segment.len() < minimum {
                return Err(malformed);
            }
            if !is_icmp_error(bytes, header) && segment[1] != 0 {
                return Err(malformed);
            }
        }
        58 if !header.ipv4 => {
            if segment.len() < 8 {
                return Err(malformed);
            }
            if !matches!(segment[0], 1..=4 | 128 | 129) {
                return Err(TranslationError::UnsupportedTranslation);
            }
            if matches!(segment[0], 128 | 129) && segment[1] != 0 {
                return Err(malformed);
            }
        }
        47 | 50 | 132 => {
            let minimum = match header.protocol {
                47 => 4,
                50 => 8,
                _ => 12,
            };
            return if segment.len() >= minimum {
                Ok(())
            } else {
                Err(malformed)
            };
        }
        _ => return Err(TranslationError::UnsupportedTranslation),
    }
    if transport_checksum(bytes, header) != 0 {
        return Err(TranslationError::Checksum);
    }
    Ok(())
}

#[cfg(test)]
mod quotation_tests;
#[cfg(test)]
mod tests;
