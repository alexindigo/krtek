//! A quotation is a view of the original packet, never a zero-padded datagram.
//! Only complete fields present on the wire are updated. Nested errors are
//! refused rather than recursing through attacker-controlled quotations.
use crate::address_translation::{
    Direction, Header, TranslationError, address_bytes, adjusted, checksum_field, is_icmp_error,
    rewrite_endpoint, word,
};
use std::net::IpAddr;

pub(crate) struct Quotation {
    start: usize,
    header: Header,
    source: bool,
    checksum: Option<usize>,
}

pub(crate) fn inspect(
    bytes: &[u8],
    outer: &Header,
    direction: Direction,
    old: IpAddr,
    _new: IpAddr,
) -> Result<Option<Quotation>, TranslationError> {
    if !is_icmp_error(bytes, outer) {
        return Ok(None);
    }
    let icmp = &bytes[outer.transport..];
    let valid_code = match (outer.ipv4, icmp[0]) {
        (true, 3) => icmp[1] <= 15,
        (true, 11) => icmp[1] <= 1,
        (true, 12) => icmp[1] <= 2,
        (false, 1) => icmp[1] <= 7,
        (false, 2) => icmp[1] == 0,
        (false, 3) => icmp[1] <= 1,
        (false, 4) => icmp[1] <= 2,
        _ => false,
    };
    if !valid_code {
        return Err(TranslationError::Malformed);
    }
    let start = outer.transport + 8;
    let quoted = &bytes[start..];
    let header = Header::parse(quoted, true)?;
    if header.ipv4 != outer.ipv4 {
        return Err(TranslationError::Family);
    }
    let source = direction == Direction::Inbound;
    if (if source {
        header.source
    } else {
        header.destination
    }) != old
    {
        return Err(TranslationError::Endpoint);
    }
    // An outbound error returns to the sender of the quoted incoming packet.
    if !source && header.source != outer.destination {
        return Err(TranslationError::Endpoint);
    }
    let available = quoted.len().min(header.declared);
    if header.transport_known && !header.non_initial {
        if is_icmp_error(&quoted[..available], &header) {
            return Err(TranslationError::UnsupportedTranslation);
        }
        let transport = &quoted[header.transport..available];
        let minimum = match header.protocol {
            6 => 20,
            1 | 17 | 58 | 50 => 8,
            47 => 4,
            132 => 12,
            _ => 0,
        };
        if !header.fragmented && header.declared - header.transport < minimum {
            return Err(TranslationError::Malformed);
        }
        match header.protocol {
            6 => {
                if (!header.fragmented && header.declared < header.transport + 20)
                    || (transport.len() > 12
                        && (transport[12] >> 4 < 5
                            || (!header.fragmented
                                && usize::from(transport[12] >> 4) * 4
                                    > header.declared - header.transport)))
                {
                    return Err(TranslationError::Malformed);
                }
            }
            17 if transport.len() >= 6
                && !header.fragmented
                && usize::from(word(transport, 4)) != header.declared - header.transport =>
            {
                return Err(TranslationError::Malformed);
            }
            17 if transport.len() >= 6 && word(transport, 4) < 8 => {
                return Err(TranslationError::Malformed);
            }
            1 if header.ipv4
                && ((!transport.is_empty() && !matches!(transport[0], 0 | 8 | 13..=18))
                    || (transport.len() >= 2 && transport[1] != 0)) =>
            {
                return Err(TranslationError::UnsupportedTranslation);
            }
            58 if !header.ipv4
                && ((!transport.is_empty() && !matches!(transport[0], 128 | 129))
                    || (transport.len() >= 2 && transport[1] != 0)) =>
            {
                return Err(TranslationError::UnsupportedTranslation);
            }
            _ => (),
        }
        if header.protocol == 17 && !header.ipv4 && transport.len() >= 8 && word(transport, 6) == 0
        {
            return Err(TranslationError::Checksum);
        }
    }
    let checksum = checksum_field(&header, quoted)?;
    Ok(Some(Quotation {
        start,
        header,
        source,
        checksum,
    }))
}

pub(crate) fn rewrite(
    bytes: &mut [u8],
    quote: &Quotation,
    old: IpAddr,
    new: IpAddr,
) -> Result<(), TranslationError> {
    let quoted = &mut bytes[quote.start..];
    if let Some(offset) = quote.checksum {
        let previous = word(quoted, offset);
        if !(quote.header.ipv4
            && (quote.header.protocol == 1 || (quote.header.protocol == 17 && previous == 0)))
        {
            let mut value = adjusted(previous, &address_bytes(old), &address_bytes(new));
            if quote.header.protocol == 17 && value == 0 {
                value = u16::MAX;
            }
            quoted[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
    }
    rewrite_endpoint(quoted, &quote.header, quote.source, new)
}
