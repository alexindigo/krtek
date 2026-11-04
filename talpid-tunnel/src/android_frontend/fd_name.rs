//! The platform query borrows the sole owned capture descriptor. In particular,
//! tun 0.8.14's Android tun_name implementation cannot supply this identity.
use nix::libc;
use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

pub fn interface_name(fd: BorrowedFd<'_>) -> io::Result<String> {
    query(fd, |fd, request| {
        // SAFETY: request is the installed target ABI's complete writable ifreq.
        // TUNGETIFF is read-only; fd stays borrowed, without dup/adoption/closure.
        let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, request) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

fn query(
    fd: BorrowedFd<'_>,
    operation: impl FnOnce(BorrowedFd<'_>, &mut libc::ifreq) -> io::Result<()>,
) -> io::Result<String> {
    // SAFETY: ifreq is a C POD of integer/byte fields, pointers and a union;
    // all-zero is a valid initial representation for this output-only ioctl.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    operation(fd, &mut request)?;
    let bytes = request.ifr_name.map(|value| value as u8);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .filter(|length| *length > 0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid capture interface name")
        })?;
    let name = std::str::from_utf8(&bytes[..end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if name == "."
        || name == ".."
        || name
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'/')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Malformed capture interface name",
        ));
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsFd, unix::net::UnixDatagram};

    #[test]
    fn borrowed_query_keeps_exact_fd_and_validates_complete_kernel_name() {
        let (capture, consumer) = UnixDatagram::pair().unwrap();
        let raw = capture.as_raw_fd();
        for name in [b"tun7\0".as_slice(), b"abcdefghijklmn0\0"] {
            let result = query(capture.as_fd(), |borrowed, request| {
                assert_eq!(borrowed.as_raw_fd(), raw);
                assert_eq!(request.ifr_name.len(), libc::IFNAMSIZ);
                for (target, byte) in request.ifr_name.iter_mut().zip(name) {
                    *target = *byte as libc::c_char;
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(result.as_bytes(), &name[..name.len() - 1]);
        }
        for invalid in [
            vec![],
            vec![b'x'; libc::IFNAMSIZ],
            vec![0xff, 0],
            b"bad/name\0".to_vec(),
            b"bad name\0".to_vec(),
        ] {
            assert_eq!(
                query(capture.as_fd(), |_, request| {
                    for (target, byte) in request.ifr_name.iter_mut().zip(&invalid) {
                        *target = *byte as libc::c_char;
                    }
                    Ok(())
                })
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            query(capture.as_fd(), |_, _| Err(
                io::ErrorKind::PermissionDenied.into()
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        // A real non-TUN descriptor must fail, and the original descriptor must
        // still deliver afterwards. No second owning wrapper can close it.
        assert!(interface_name(capture.as_fd()).is_err());
        capture.send(b"still owned").unwrap();
        let mut buffer = [0; 32];
        let len = consumer.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"still owned");
    }
}
