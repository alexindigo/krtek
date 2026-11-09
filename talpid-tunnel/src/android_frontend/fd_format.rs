//! Plain packet representation required before capture admission. The Android
//! Builder creator uses TUN|NO_PI and never enables TUNSETOFFLOAD. Together with
//! that creation contract, this borrowed TUNGETIFF check excludes PI/virtio/GSO
//! objects; unsupported offloads are completed by the kernel transmit stack.
use std::{fmt, io, os::fd::BorrowedFd};

/// Read-only evidence from the actual fd, retained in its readiness receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureFormat {
    flags: u16,
}

#[derive(Debug)]
pub struct UnsupportedCaptureFormat {
    flags: Option<u16>,
    source: Option<io::Error>,
}

impl fmt::Display for UnsupportedCaptureFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UnsupportedCaptureFormat: TUNGETIFF flags={:?}",
            self.flags
        )
    }
}

impl std::error::Error for UnsupportedCaptureFormat {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

impl CaptureFormat {
    /// Linux/Android UAPI if_tun.h. NOFILTER aliases NO_PI on readback; the
    /// service's sole creator must also retain its explicit NO_PI/no-offload
    /// contract. Flags alone do not attest an arbitrary external fd creator.
    pub fn from_flags(flags: u16) -> io::Result<Self> {
        const TYPE_MASK: u16 = 0x000f;
        const TUN: u16 = 0x0001;
        const NO_PI: u16 = 0x1000;
        const VNET_HDR: u16 = 0x4000;
        const DETACH_QUEUE: u16 = 0x0400;
        if flags & TYPE_MASK != TUN || flags & NO_PI == 0 || flags & (VNET_HDR | DETACH_QUEUE) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                UnsupportedCaptureFormat {
                    flags: Some(flags),
                    source: None,
                },
            ));
        }
        Ok(Self { flags })
    }

    pub fn flags(self) -> u16 {
        self.flags
    }
}

pub(super) fn capture_format(fd: BorrowedFd<'_>) -> io::Result<CaptureFormat> {
    let flags = super::fd_name::flags(fd).map_err(|error| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            UnsupportedCaptureFormat {
                flags: None,
                source: Some(error),
            },
        )
    })?;
    CaptureFormat::from_flags(flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsFd, unix::net::UnixDatagram};

    #[test]
    fn metadata_and_non_ip_descriptor_formats_are_typed_refusals() {
        for flags in [0, 1, 2, 0x1002, 0x1003, 0x5001, 0x1401, 0x4001] {
            let error = CaptureFormat::from_flags(flags).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<UnsupportedCaptureFormat>()
                    .unwrap()
                    .flags,
                Some(flags)
            );
        }
        for flags in [0x1001, 0x3001, 0x1801] {
            assert_eq!(CaptureFormat::from_flags(flags).unwrap().flags(), flags);
        }
        let (fd, peer) = UnixDatagram::pair().unwrap();
        let error = capture_format(fd.as_fd()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let typed = error
            .get_ref()
            .unwrap()
            .downcast_ref::<UnsupportedCaptureFormat>()
            .unwrap();
        assert!(typed.flags.is_none() && typed.source.is_some());
        fd.send(b"sole descriptor still live").unwrap();
        let mut bytes = [0; 64];
        let len = peer.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"sole descriptor still live");
    }
}
