//! Privileged kernel consumer proof, run only in an isolated network namespace.
use super::*;
use std::{net::UdpSocket, os::fd::AsRawFd, time::Instant};
use talpid_netstack::{
    address_translation::{Direction, TargetConfig, TargetPacketPath, TranslationOutcome},
    buffer_budget::BufferBudget,
    packet_sizing::FeedbackSide,
};
use talpid_types::relay_flow::RelaySources;

fn socket_option(socket: &UdpSocket, option: i32) -> i32 {
    use nix::libc;
    let mut value = 0i32;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: the socket is live, and both output pointers have their declared sizes.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                option,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    value
}

#[tokio::test]
#[ignore = "requires isolated network namespace, /dev/net/tun and CAP_NET_ADMIN"]
async fn ipv4_pmtu_feedback_crosses_the_capture_writer_and_updates_the_kernel_socket() {
    use nix::libc;
    let fixed = "192.0.2.2".parse::<std::net::Ipv4Addr>().unwrap();
    let remote = "203.0.113.9".parse::<std::net::Ipv4Addr>().unwrap();
    let mut configuration = tun::Configuration::default();
    configuration
        .tun_name("krtek-pmtu")
        .address(fixed)
        .destination(remote)
        .netmask("255.255.255.255")
        .mtu(9000)
        .up();
    let device = tun::create(&configuration).expect("isolated kernel TUN");
    device.set_nonblock().unwrap();
    for interface in ["all", "krtek-pmtu"] {
        let value =
            std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{interface}/accept_local"))
                .unwrap();
        assert_eq!(value.trim(), "0", "test must not enable accept_local");
    }
    let socket = UdpSocket::bind((fixed, 0)).unwrap();
    socket.connect((remote, 42042)).unwrap();
    let discover = libc::IP_PMTUDISC_DO;
    // SAFETY: the live socket reads one initialized integer of the declared size.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                (&discover as *const i32).cast(),
                std::mem::size_of_val(&discover) as libc::socklen_t,
            )
        },
        0
    );
    assert_eq!(socket_option(&socket, libc::IP_MTU), 9000);
    socket.send(&vec![0x5a; 3000]).unwrap();
    // SAFETY: device retains ownership until after the reactor is dropped.
    let borrowed = unsafe { BorrowedFd::borrow_raw(device.as_raw_fd()) };
    let descriptor = AsyncFd::new(borrowed).unwrap();
    let mut input = vec![0; 9000];
    let length = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let mut ready = descriptor.readable().await.unwrap();
            if let Ok(result) = ready
                .try_io(|fd| nix::unistd::read(fd.get_ref(), &mut input).map_err(io::Error::from))
            {
                let length = result.unwrap();
                // Ignore interface IPv6 discovery; wait for the actual UDP
                // invocation whose socket must consume the feedback.
                if length >= 28 && input[0] >> 4 == 4 && input[9] == 17 {
                    break length;
                }
            }
        }
    })
    .await
    .unwrap();
    input.truncate(length);
    assert_eq!(input[0] >> 4, 4);
    assert_ne!(
        u16::from_be_bytes(input[6..8].try_into().unwrap()) & 0x4000,
        0
    );

    let root = BufferBudget::new(64 * 1024 * 1024);
    let buffers = || Arc::new(root.reserve(16 * 1024 * 1024).unwrap().region().unwrap());
    let broker = AttachmentBroker::new(buffers(), buffers(), buffers()).unwrap();
    broker
        .set_mode(crate::packet_attachment::AttachmentMode::ManagedRequired)
        .unwrap();
    let sources = RelaySources {
        ipv4: Some(fixed),
        ipv6: None,
    };
    let mut config = crate::tun_provider::blocking_config();
    config.addresses = vec![fixed.into()];
    config.ipv6_gateway = None;
    config.mtu = 9000;
    let mut request = broker.request_capture(config).unwrap();
    let pending = broker.pending_request().unwrap();
    let capture = broker.open_capture(Some(&pending)).unwrap();
    let receipt = capture
        .bind_observed_identity("krtek-pmtu", 71_u64 << 32, sources, 9000)
        .unwrap();
    broker.acknowledge(&pending, &receipt).unwrap();
    request.configured().await.unwrap();
    let pair = broker.acquire(&receipt).unwrap();
    pair.control.activate().unwrap();
    let mut path = TargetPacketPath::new(
        TargetConfig {
            target_id: 1,
            fixed: sources,
            assigned: RelaySources {
                ipv4: Some("10.64.0.7".parse().unwrap()),
                ipv6: None,
            },
            mtu: 1280,
        },
        pair.control.capability(),
        broker.application_buffers(),
    )
    .unwrap();
    assert!(matches!(
        path.process(&input, Direction::Outbound, 9000, Instant::now()),
        Ok(TranslationOutcome::FeedbackQueued(FeedbackSide::App))
    ));
    pair.send
        .try_send_feedback(path.take_feedback().unwrap())
        .unwrap();
    let mut reply = Some(capture.reply().await.unwrap());
    let sink = pair.control.capability().sink().unwrap();
    let _writable = descriptor.writable().await.unwrap();
    assert!(drain_reply(&descriptor, &sink, &mut reply).unwrap());
    assert!(reply.is_none());
    // This observes the final kernel socket, not just bytes written into TUN.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while socket_option(&socket, libc::IP_MTU) != 1280 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("kernel socket did not learn the advertised PMTU");
    assert_eq!(
        socket.send(&vec![0x5a; 3000]).unwrap_err().raw_os_error(),
        Some(libc::EMSGSIZE)
    );
}
