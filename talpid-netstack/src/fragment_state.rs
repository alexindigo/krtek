//! One bounded reassembly ledger per target attempt. No worker or flow table.
use crate::address_translation::{Direction, Header, TranslationError, checksum, word};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
};

const LIMIT: usize = 4 * 1024 * 1024;
const COUNT: usize = 64;
const PAYLOAD: usize = 65_535;
const LIFETIME: Duration = Duration::from_secs(15);
// Both feedback families quote less than this. Retain the received view, never
// rebuild it from the checksum datagram or keep another full-size packet.
const INVOKING_PREFIX: usize = 1280;

/// Only the reassembler can issue IPv6 source-fragment authority.
#[derive(Clone, Copy)]
pub(crate) struct Fragmentation {
    pub boundary: usize,
    pub next_field: usize,
    pub id: u32,
}

#[derive(Eq, PartialEq)]
struct Key {
    direction: Direction,
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    id: u32,
}

struct Assembly {
    key: Key,
    expiry: Instant,
    prefix: Vec<u8>,
    prefix_length: usize,
    next_field: usize,
    protocol: u8,
    data: Vec<u8>,
    blocks: [u64; 128],
    received: usize,
    total: Option<usize>,
    first: bool,
    rejected: bool,
    charge: Option<Arc<dyn RelayBufferReservation>>,
    invoking: Option<RelayBuffer>,
}

impl Assembly {
    fn tombstone(key: Key, expiry: Instant) -> Self {
        Self {
            key,
            expiry,
            prefix: Vec::new(),
            prefix_length: 0,
            next_field: 0,
            protocol: 0,
            data: Vec::new(),
            blocks: [0; 128],
            received: 0,
            total: None,
            first: false,
            rejected: true,
            charge: None,
            invoking: None,
        }
    }
    fn reject(&mut self) {
        // Retain identity and the original expiry, never extend a tombstone.
        self.prefix = Vec::new();
        self.data = Vec::new();
        self.charge = None;
        self.invoking = None;
        self.rejected = true;
    }
}

pub(crate) enum DatagramBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(RelayBuffer),
}
impl std::ops::Deref for DatagramBytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

pub(crate) struct Datagram<'a> {
    pub bytes: DatagramBytes<'a>,
    /// Original unfragmented/atomic input, or the received offset-zero fragment.
    /// This has its own representation and retained charge across normalization.
    pub invoking: DatagramBytes<'a>,
    pub fragmentation: Option<Fragmentation>,
}

pub(crate) struct FragmentState {
    entries: Vec<Assembly>,
    buffers: Arc<dyn RelayBufferAllocator>,
    _metadata: Arc<dyn RelayBufferReservation>,
}

impl FragmentState {
    pub fn new(application: &dyn RelayBufferAllocator) -> Result<Self, TranslationError> {
        let region = application.try_reserve(LIMIT)?;
        let buffers = region.allocator()?;
        // Includes the inline overlap bitmap and tombstone metadata for all slots.
        let metadata =
            buffers.try_reserve(COUNT * std::mem::size_of::<Assembly>() + BUFFER_OVERHEAD)?;
        let entries = Vec::with_capacity(COUNT);
        Ok(Self {
            entries,
            buffers,
            _metadata: metadata,
        })
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.entries.iter().map(|a| a.expiry).min()
    }
    pub fn maintain(&mut self, now: Instant) {
        self.entries.retain(|a| a.expiry > now);
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn ingest<'a>(
        &mut self,
        bytes: &'a [u8],
        direction: Direction,
        now: Instant,
    ) -> Result<Option<Datagram<'a>>, TranslationError> {
        self.maintain(now);
        let header = Header::parse_fragment(bytes)?;
        let (offset, more, id, boundary, next_field, protocol) = if header.ipv4 {
            let flags = word(bytes, 6);
            if flags & 0x3fff == 0 {
                return Ok(Some(Datagram {
                    bytes: DatagramBytes::Borrowed(bytes),
                    invoking: DatagramBytes::Borrowed(bytes),
                    fragmentation: None,
                }));
            }
            if flags & 0x4000 != 0 {
                return Err(TranslationError::Malformed);
            }
            (
                usize::from(flags & 0x1fff) * 8,
                flags & 0x2000 != 0,
                u32::from(word(bytes, 4)),
                header.transport,
                9,
                header.protocol,
            )
        } else if let Some(fragment) = header.fragment {
            (
                fragment.offset,
                fragment.more,
                fragment.id,
                fragment.boundary,
                fragment.next_field,
                header.protocol,
            )
        } else {
            return Ok(Some(Datagram {
                bytes: DatagramBytes::Borrowed(bytes),
                invoking: DatagramBytes::Borrowed(bytes),
                fragmentation: None,
            }));
        };
        let payload_start = boundary + if header.ipv4 { 0 } else { 8 };
        let payload = &bytes[payload_start..];
        let end = offset
            .checked_add(payload.len())
            .ok_or(TranslationError::Malformed)?;
        let key = Key {
            direction,
            source: header.source,
            destination: header.destination,
            protocol: if header.ipv4 { protocol } else { 0 },
            id,
        };
        let invalid = payload.is_empty()
            || end > PAYLOAD
            || (more && !payload.len().is_multiple_of(8))
            || (header.ipv4 && boundary + end > PAYLOAD);
        let existing = self.entries.iter().position(|a| a.key == key);
        if invalid {
            if let Some(index) = existing {
                self.entries[index].reject();
            } else if self.entries.len() < COUNT {
                self.entries.push(Assembly::tombstone(key, now + LIFETIME));
            }
            return Err(TranslationError::Malformed);
        }
        // Atomic IPv6 fragments have no reassembly identity and no permission to
        // fragment an originally unfragmented datagram (RFC6946).
        if !header.ipv4 && offset == 0 && !more {
            let mut output =
                RelayBuffer::copy_from(&bytes[..bytes.len() - 8], self.buffers.as_ref())?;
            output[..boundary].copy_from_slice(&bytes[..boundary]);
            output[boundary..].copy_from_slice(payload);
            output[next_field] = protocol;
            let length = (output.len() - 40) as u16;
            output[4..6].copy_from_slice(&length.to_be_bytes());
            return Ok(Some(Datagram {
                bytes: DatagramBytes::Owned(output),
                invoking: DatagramBytes::Borrowed(bytes),
                fragmentation: None,
            }));
        }
        let index = if let Some(index) = existing {
            index
        } else {
            if self.entries.len() == COUNT {
                return Err(TranslationError::Full);
            }
            let prefix_size = if header.ipv4 { 60 } else { boundary };
            let charge = self
                .buffers
                .try_reserve(PAYLOAD + prefix_size + 2 * BUFFER_OVERHEAD)?;
            let mut prefix = vec![0; prefix_size];
            prefix[..boundary].copy_from_slice(&bytes[..boundary]);
            self.entries.push(Assembly {
                key,
                expiry: now + LIFETIME,
                prefix,
                prefix_length: boundary,
                next_field,
                protocol,
                data: vec![0; PAYLOAD],
                blocks: [0; 128],
                received: 0,
                total: None,
                first: false,
                rejected: false,
                charge: Some(charge),
                invoking: None,
            });
            self.entries.len() - 1
        };
        let assembly = &mut self.entries[index];
        if assembly.rejected {
            return Err(TranslationError::RejectedFragment);
        }
        let conflict = assembly.protocol != protocol
            || assembly.next_field != next_field
            || if header.ipv4 {
                assembly.prefix[1] != bytes[1]
                    || assembly.prefix[8] != bytes[8]
                    || copied_options(&assembly.prefix[..assembly.prefix_length])?
                        != copied_options(&bytes[..boundary])?
            } else {
                assembly.prefix_length != boundary
                    || assembly
                        .prefix
                        .iter()
                        .zip(&bytes[..boundary])
                        .enumerate()
                        .any(|(i, (a, b))| !matches!(i, 4 | 5) && a != b)
            };
        let first_block = offset / 8;
        let last_block = end.div_ceil(8);
        let overlap = (first_block..last_block)
            .any(|block| assembly.blocks[block / 64] & (1 << (block % 64)) != 0);
        if conflict
            || overlap
            || assembly
                .total
                .is_some_and(|n| end > n || (!more && end != n))
            || (!more
                && (last_block..8192)
                    .any(|block| assembly.blocks[block / 64] & (1 << (block % 64)) != 0))
        {
            assembly.reject();
            return Err(TranslationError::RejectedFragment);
        }
        if offset == 0 {
            let invoking = match RelayBuffer::copy_from(
                &bytes[..bytes.len().min(INVOKING_PREFIX)],
                self.buffers.as_ref(),
            ) {
                Ok(invoking) => invoking,
                Err(error) => {
                    assembly.reject();
                    return Err(error.into());
                }
            };
            assembly.invoking = Some(invoking);
            assembly.prefix[..boundary].copy_from_slice(&bytes[..boundary]);
            assembly.prefix_length = boundary;
            assembly.first = true;
        }
        if !more {
            assembly.total = Some(end);
        }
        for block in first_block..last_block {
            assembly.blocks[block / 64] |= 1 << (block % 64);
        }
        assembly.data[offset..end].copy_from_slice(payload);
        assembly.received += payload.len();
        let Some(total) = assembly
            .total
            .filter(|total| assembly.first && *total == assembly.received)
        else {
            return Ok(None);
        };
        let length = assembly.prefix_length + total;
        if (if header.ipv4 { length } else { length - 40 }) > PAYLOAD {
            assembly.reject();
            return Err(TranslationError::Malformed);
        }
        // Both the assembly and encoder peak remain inside the 4 MiB child.
        let ticket = match self.buffers.try_reserve(length + BUFFER_OVERHEAD) {
            Ok(ticket) => ticket,
            Err(error) => {
                assembly.reject();
                return Err(error.into());
            }
        };
        let mut output = vec![0; length];
        output[..assembly.prefix_length]
            .copy_from_slice(&assembly.prefix[..assembly.prefix_length]);
        output[assembly.prefix_length..].copy_from_slice(&assembly.data[..total]);
        let fragmentation = if header.ipv4 {
            output[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            output[6..8].fill(0);
            output[10..12].fill(0);
            let sum = checksum(&[&output[..assembly.prefix_length]]);
            output[10..12].copy_from_slice(&sum.to_be_bytes());
            None
        } else {
            output[assembly.next_field] = assembly.protocol;
            output[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
            Some(Fragmentation {
                boundary: assembly.prefix_length,
                next_field: assembly.next_field,
                id,
            })
        };
        let bytes = RelayBuffer::from_reservation(output, ticket)?;
        let invoking = assembly
            .invoking
            .take()
            .ok_or(TranslationError::Malformed)?;
        assembly.reject(); // Complete ID cannot absorb delayed pieces before expiry.
        Ok(Some(Datagram {
            bytes: DatagramBytes::Owned(bytes),
            invoking: DatagramBytes::Owned(invoking),
            fragmentation,
        }))
    }
}

/// Canonical copied options, including their order, with no heap allocation.
pub(crate) fn copied_options(header: &[u8]) -> Result<([u8; 40], usize), TranslationError> {
    let mut result = [0; 40];
    let mut length = 0;
    let mut offset = 20;
    while offset < header.len() {
        let kind = header[offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }
        let size = usize::from(*header.get(offset + 1).ok_or(TranslationError::Malformed)?);
        if size < 2 || offset + size > header.len() {
            return Err(TranslationError::Malformed);
        }
        if kind & 0x80 != 0 {
            result[length..length + size].copy_from_slice(&header[offset..offset + size]);
            length += size;
        }
        offset += size;
    }
    let padded = length.div_ceil(4) * 4;
    Ok((result, padded))
}
