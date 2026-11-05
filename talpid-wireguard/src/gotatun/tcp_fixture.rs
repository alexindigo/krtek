//! Independent loopback GotaTun peers, adapted from the archived crypto fixture.
//! The capture and remote consumers compare full raw bytes, never tunnel status.
use super::super::*;
use super::*;
use crate::connectivity::{CancelToken, Check};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    x25519::StaticSecret,
};
use std::{io, time::Duration};
use talpid_net::bypass::NoopBypass;
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_tunnel::packet_attachment::{AttachmentBroker, AttachmentMode, CaptureLease};
use talpid_types::{
    net::wireguard::{PrivateKey, TunnelConfig},
    relay_flow::{RelaySources, RelayWriteOutcome},
};
use tokio::sync::mpsc;

fn config() -> Config {
    let private_key = PrivateKey::new_from_random();
    Config {
        entry_peer: PeerConfig {
            public_key: private_key.public_key(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            endpoint: "127.0.0.1:9".parse().unwrap(),
            psk: None,
            constant_packet_size: false,
        },
        tunnel: TunnelConfig {
            private_key,
            addresses: vec![
                "10.12.34.56".parse().unwrap(),
                "fd00:1234::56".parse().unwrap(),
            ],
        },
        exit_peer: None,
        ipv4_gateway: "10.12.34.1".parse().unwrap(),
        ipv6_gateway: Some("fd00:1234::1".parse().unwrap()),
        mtu: 1420,
        #[cfg(target_os = "linux")]
        fwmark: None,
        #[cfg(target_os = "linux")]
        enable_ipv6: true,
        obfuscator_config: None,
        obfuscation_mtu: 1500,
        quantum_resistant: false,
        daita: false,
        routes: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
    }
}

fn tun_config(config: &Config) -> tun_provider::TunConfig {
    let mut tun = tun_provider::blocking_config();
    tun.addresses = config.tunnel.addresses.clone();
    tun.mtu = config.mtu;
    tun.ipv4_gateway = config.ipv4_gateway;
    tun.ipv6_gateway = config.ipv6_gateway;
    tun.routes = config.routes.clone();
    tun.dns_servers = Some(vec![config.ipv4_gateway.into()]);
    tun
}

fn broker() -> (AttachmentBroker, BufferBudget, BufferBudget) {
    let root = BufferBudget::new(64 * 1024 * 1024);
    let application = root.reserve(22 * 1024 * 1024).unwrap().region().unwrap();
    let control = root.reserve(8 * 1024 * 1024).unwrap().region().unwrap();
    let capture = root.reserve(2 * 1024 * 1024).unwrap().region().unwrap();
    let broker = AttachmentBroker::new(
        Arc::new(application),
        Arc::new(capture),
        Arc::new(control.clone()),
    )
    .unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    (broker, root, control)
}

fn acknowledge(broker: &AttachmentBroker, config: &Config) -> CaptureLease {
    let request = broker.pending_request().unwrap();
    let capture = broker.open_capture(Some(&request)).unwrap();
    let receipt = capture
        .bind_observed_identity(
            "tun17",
            0xf123_4567_0000_0063,
            RelaySources {
                ipv4: config.tunnel_ipv4(),
                ipv6: config.tunnel_ipv6(),
            },
            config.mtu,
        )
        .unwrap();
    broker.acknowledge(&request, &receipt).unwrap();
    capture
}

fn echo_reply(request: &[u8]) -> Vec<u8> {
    let mut reply = request.to_vec();
    reply[12..16].copy_from_slice(&request[16..20]);
    reply[16..20].copy_from_slice(&request[12..16]);
    reply[20] = 0;
    reply[22..24].fill(0);
    let checksum = internet_checksum::checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&checksum);
    reply[10..12].fill(0);
    let checksum = internet_checksum::checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&checksum);
    reply
}

struct RemoteSend {
    output: mpsc::Sender<Packet<Ip>>,
    observed: mpsc::Sender<Vec<u8>>,
    gateway: Ipv4Addr,
}
struct RemoteReceive(mpsc::Receiver<Packet<Ip>>);
impl IpSend for RemoteSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        let private = bytes.len() == 70
            && bytes[0] == 0x45
            && bytes[9] == 1
            && bytes[16..20] == self.gateway.octets()
            && bytes[20] == 8;
        let returned = if private {
            echo_reply(&bytes)
        } else {
            self.observed
                .try_send(bytes.to_vec())
                .map_err(|_| io::ErrorKind::WouldBlock)?;
            bytes.to_vec()
        };
        self.output
            .try_send(Packet::<[u8]>::copy_from(&returned).try_into_ip().unwrap())
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
}
impl IpRecv for RemoteReceive {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        Ok(std::iter::once(
            self.0.recv().await.ok_or(io::ErrorKind::BrokenPipe)?,
        ))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}

enum Remote {
    Single(
        Device<(
            gotatun::udp::socket::UdpSocketFactory,
            RemoteSend,
            RemoteReceive,
        )>,
    ),
    Multi {
        exit: Device<(UdpChannelFactory, RemoteSend, RemoteReceive)>,
        entry: Device<(
            gotatun::udp::socket::UdpSocketFactory,
            TunChannelTx,
            TunChannelRx,
        )>,
    },
}
impl Remote {
    async fn stop(self) {
        match self {
            Self::Single(device) => device.stop().await,
            Self::Multi { exit, entry } => {
                exit.stop().await;
                entry.stop().await;
            }
        }
    }
}

async fn remote(config: &mut Config, multihop: bool) -> (Remote, mpsc::Receiver<Vec<u8>>) {
    let key = PrivateKey::new_from_random();
    config.entry_peer.public_key = key.public_key();
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    config.entry_peer.endpoint = (Ipv4Addr::LOCALHOST, port).into();
    let (output, input) = mpsc::channel(512);
    let (observed, observations) = mpsc::channel(512);
    let send = RemoteSend {
        output,
        observed,
        gateway: config.ipv4_gateway,
    };
    let receive = RemoteReceive(input);
    let peer = PeerConfig {
        public_key: config.tunnel.private_key.public_key(),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
        endpoint: "127.0.0.1:9".parse().unwrap(),
        psk: None,
        constant_packet_size: false,
    };
    let remote = if multihop {
        let exit_key = PrivateKey::new_from_random();
        let exit_address: Ipv4Addr = "10.12.34.2".parse().unwrap();
        config.entry_peer.allowed_ips = vec!["10.12.34.2/32".parse().unwrap()];
        config.exit_peer = Some(PeerConfig {
            public_key: exit_key.public_key(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            endpoint: (exit_address, 51820).into(),
            psk: None,
            constant_packet_size: false,
        });
        let (entry_send, entry_receive, exit_transport) = new_udp_tun_channel(
            32,
            exit_address,
            Ipv6Addr::UNSPECIFIED,
            MtuWatcher::new(1500),
        );
        let exit = DeviceBuilder::new()
            .with_udp(exit_transport)
            .with_listen_port(51820)
            .with_private_key(StaticSecret::from(exit_key.to_bytes()))
            .with_peer(to_gotatun_peer(&peer, None))
            .with_ip_pair(send, receive)
            .build()
            .await
            .unwrap();
        let entry = DeviceBuilder::new()
            .with_default_udp()
            .with_listen_port(port)
            .with_private_key(StaticSecret::from(key.to_bytes()))
            .with_peer(to_gotatun_peer(&peer, None))
            .with_ip_pair(entry_send, entry_receive)
            .build()
            .await
            .unwrap();
        Remote::Multi { exit, entry }
    } else {
        Remote::Single(
            DeviceBuilder::new()
                .with_default_udp()
                .with_listen_port(port)
                .with_private_key(StaticSecret::from(key.to_bytes()))
                .with_peer(to_gotatun_peer(&peer, None))
                .with_ip_pair(send, receive)
                .build()
                .await
                .unwrap(),
        )
    };
    (remote, observations)
}

fn ipv4(protocol: u8, nonce: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40 + nonce.len()];
    bytes[0] = 0x45;
    let length = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&length.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&[10, 12, 34, 56]);
    bytes[16..20].copy_from_slice(&[203, 0, 113, 20]);
    bytes[20..22].copy_from_slice(&43000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[40..].copy_from_slice(nonce);
    let checksum = internet_checksum::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum);
    bytes
}

async fn establish_and_observe(
    check: &mut Check,
    client: &GotaTun,
    owner: &ManagedControl,
    final_setup: impl std::future::Future<Output = Result<(), crate::CloseMsg>>,
) -> Result<(), crate::CloseMsg> {
    use futures::StreamExt;
    let (send, mut events) = futures::channel::mpsc::unbounded();
    let hook = talpid_tunnel::EventHook::new(send);
    let event = talpid_tunnel::TunnelEvent::Up {
        metadata: crate::tunnel_metadata(client.get_interface_name(), &config()),
        selected_obfuscation: None,
    };
    let result = crate::establish_and_activate(check, client, Some(owner), final_setup, |()| {
        hook.enqueue(event.clone())
    })
    .await;
    match result {
        Ok(Some(acknowledged)) => {
            let (received, acknowledgement) = events.next().await.unwrap();
            assert_eq!(received, event);
            // Reading current authority here also proves publication released
            // its guards before the asynchronous consumer acknowledgement.
            assert!(owner.control.current());
            acknowledgement.send(()).unwrap();
            acknowledged.await.unwrap();
            Ok(())
        }
        Ok(None) => panic!("live event consumer was not queued"),
        Err(error) => {
            assert!(events.try_recv().is_err(), "failed setup queued Up");
            Err(error)
        }
    }
}

#[tokio::test]
async fn singlehop_raw_ip_reaches_independent_crypto_and_capture_consumers() {
    crypto(false).await;
}
#[tokio::test]
async fn multihop_exit_raw_ip_reaches_independent_crypto_and_capture_consumers() {
    crypto(true).await;
}

async fn crypto(multihop: bool) {
    let (broker, _root, control) = broker();
    let mut config = config();
    let (remote, mut observed) = remote(&mut config, multihop).await;
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    assert_eq!(client.get_interface_name(), "tun17");
    let owner = client.managed().unwrap();
    let (cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    assert!(!broker.snapshot().ordinary_ready);
    assert!(capture.try_send(&ipv4(17, b"early-must-drop")).is_err());
    tokio::time::timeout(
        Duration::from_secs(5),
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(broker.snapshot().ordinary_ready);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), capture.reply())
            .await
            .is_err(),
        "private reply leaked"
    );
    let mut vectors = vec![
        ipv4(6, b"tcp-nonce"),
        ipv4(17, b"dns-udp-nonce"),
        ipv4(1, b"public-icmp-nonce"),
        ipv4(253, b"unknown-protocol"),
    ];
    let mut configured_dns = ipv4(17, b"actual-configured-dns-tuple");
    configured_dns[16..20].copy_from_slice(&config.ipv4_gateway.octets());
    let udp_length = (configured_dns.len() - 20) as u16;
    configured_dns[24..26].copy_from_slice(&udp_length.to_be_bytes());
    configured_dns[10..12].fill(0);
    let checksum = internet_checksum::checksum(&configured_dns[..20]);
    configured_dns[10..12].copy_from_slice(&checksum);
    assert_eq!(
        tun_config(&config).dns_servers,
        Some(vec![config.ipv4_gateway.into()])
    );
    vectors.push(configured_dns);
    let mut fragment = ipv4(17, b"fragment-without-reassembly");
    fragment[6..8].copy_from_slice(&0x2001u16.to_be_bytes());
    vectors.push(fragment);
    let mut quotation = ipv4(1, b"icmp-error-quotation");
    quotation[20] = 3;
    vectors.push(quotation);
    let mut v6 = vec![0; 64];
    v6[0] = 0x60;
    v6[4..6].copy_from_slice(&24u16.to_be_bytes());
    v6[6] = 0; // native-accepted hop-by-hop extension
    v6[7] = 64;
    v6[8..24].copy_from_slice(&config.tunnel_ipv6().unwrap().octets());
    v6[24..40].copy_from_slice(&"2001:db8:240::20".parse::<Ipv6Addr>().unwrap().octets());
    v6[40] = 253;
    v6[48..64].copy_from_slice(b"ipv6-extension!!");
    vectors.push(v6);
    vectors.push(ipv4(17, &vec![0x95; 1350]));
    for bytes in vectors {
        capture.try_send(&bytes).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), observed.recv())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
        let mut reply = tokio::time::timeout(Duration::from_secs(2), capture.reply())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            reply.write(|received| {
                assert_eq!(received, bytes);
                Ok(received.len())
            }),
            RelayWriteOutcome::Written
        ));
    }
    // Fill ordinary return storage while its capture consumer is blocked. The
    // private pinger still reaches its authenticated return consumer under load.
    for sequence in 0..talpid_tunnel::packet_attachment::PACKET_CAPACITY {
        capture
            .try_send(&ipv4(17, &sequence.to_be_bytes()))
            .unwrap();
    }
    for _ in 0..talpid_tunnel::packet_attachment::PACKET_CAPACITY {
        tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let prior = owner.ledger.lock().unwrap().highest;
    assert!(check.establish_connectivity(&client).await.unwrap());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            {
                let ledger = owner.ledger.lock().unwrap();
                if ledger.highest > prior && ledger.live.is_empty() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("ordinary backpressure starved private authenticated replies");
    // The same real readiness function refuses a cancelled already-successful
    // Check, and receipt loss revokes ordinary traffic synchronously.
    cancel.close();
    assert!(
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .is_err()
    );
    capture.retire();
    assert!(!broker.snapshot().ordinary_ready);
    assert!(capture.try_send(&ipv4(17, b"retired")).is_err());
    tokio::time::timeout(Duration::from_secs(2), client.shutdown())
        .await
        .unwrap();
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
    tokio::time::timeout(Duration::from_secs(2), remote.stop())
        .await
        .unwrap();
}

#[tokio::test]
async fn real_request_without_matching_receipt_never_creates_application_source() {
    let (broker, _root, control) = broker();
    let config = config();
    let mut pending = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), pending.create(&config))
            .await
            .is_err()
    );
    assert!(!broker.snapshot().ordinary_ready);
    assert_eq!(control.used(), 0);
    let capture = acknowledge(&broker, &config);
    capture.retire();
    assert!(pending.create(&config).await.is_err());
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn private_matching_rejects_replay_and_does_not_claim_application_icmp() {
    let (broker, _root, control) = broker();
    let config = config();
    let mut pending = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let _capture = acknowledge(&broker, &config);
    let mut pair = pending.create(&config).await.unwrap();
    let mut pinger = pair.owner.pinger().unwrap();
    use crate::connectivity::Pinger;
    pinger.send_icmp().await.unwrap();
    let mut pool = PacketBufPool::new(1);
    let request = pair
        .receive
        .recv(&mut pool)
        .await
        .unwrap()
        .next()
        .unwrap()
        .into_bytes();
    let good = echo_reply(&request);
    let mut bad = good.clone();
    bad[69] ^= 1;
    // A malformed checksum cannot satisfy the private consumer.
    pair.send
        .send(Packet::<[u8]>::copy_from(&bad).try_into_ip().unwrap())
        .await
        .unwrap();
    assert_eq!(pair.owner.ledger.lock().unwrap().live.len(), 1);
    pair.send
        .send(Packet::<[u8]>::copy_from(&good).try_into_ip().unwrap())
        .await
        .unwrap();
    assert_eq!(pair.owner.ledger.lock().unwrap().live.len(), 0);
    assert!(matches!(pair.owner.reply(&good), Reply::Discard));
    // A guessed tuple with a different, valid-checksummed payload is raw IP.
    let mut application = good.clone();
    application[28] ^= 1;
    application[22..24].fill(0);
    let checksum = internet_checksum::checksum(&application[20..]);
    application[22..24].copy_from_slice(&checksum);
    assert!(matches!(pair.owner.reply(&application), Reply::Application));
    pinger.send_icmp().await.unwrap();
    let request = pair
        .receive
        .recv(&mut pool)
        .await
        .unwrap()
        .next()
        .unwrap()
        .into_bytes();
    pair.owner.ledger.lock().unwrap().live[0].1 = Instant::now() - REQUEST_LIFETIME;
    assert!(matches!(
        pair.owner.reply(&echo_reply(&request)),
        Reply::Discard
    ));
    pair.send
        .send(Packet::<[u8]>::copy_from(&good).try_into_ip().unwrap())
        .await
        .unwrap();
    assert_eq!(pair.owner.ledger.lock().unwrap().live.len(), 0);
    assert!(!broker.snapshot().ordinary_ready);
    // Before device installation, even valid peer statistics cannot activate.
    assert!(pair.owner.activate().is_err());
    pair.owner.stop().await;
    assert!(pair.receive.recv(&mut pool).await.is_err());
    drop((pair, pinger, pending));
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn readiness_refuses_unauthenticated_peer_even_with_installed_source_and_receipt() {
    let (broker, _root, control) = broker();
    let config = config(); // port 9 has no fixture peer/key
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) }),
    )
    .await
    .unwrap();
    assert!(outcome.is_err());
    assert!(!broker.snapshot().ordinary_ready);
    assert!(capture.try_send(&ipv4(17, b"no-auth-no-output")).is_err());
    client.shutdown().await;
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn receipt_loss_and_cancel_after_authenticated_check_refuse_activation() {
    for lose_receipt in [false, true] {
        let (broker, _root, control) = broker();
        let mut config = config();
        let (remote, _observed) = remote(&mut config, false).await;
        let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let capture = acknowledge(&broker, &config);
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let (cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        let (passed, reached) = tokio::sync::oneshot::channel();
        {
            let setup = establish_and_observe(&mut check, &client, &owner, async {
                passed.send(()).unwrap();
                std::future::pending::<Result<(), crate::CloseMsg>>().await
            });
            tokio::pin!(setup);
            tokio::select! {
                _ = reached => {},
                result = &mut setup => panic!("setup ended before final barrier: {result:?}"),
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("real authenticated Check did not complete"),
            }
            assert!(!broker.snapshot().ordinary_ready);
            if lose_receipt {
                capture.retire();
            } else {
                cancel.close();
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(1), setup)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        assert!(!broker.snapshot().ordinary_ready);
        assert!(capture.try_send(&ipv4(17, b"lost-factor")).is_err());
        client.shutdown().await;
        drop((check, owner, client));
        assert_eq!(control.used(), 0);
        remote.stop().await;
    }
}

#[tokio::test]
async fn up_enqueue_is_checked_against_retirement_after_activation() {
    let (broker, _root, control) = broker();
    let mut config = config();
    let (remote, _observed) = remote(&mut config, false).await;
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
        .await
        .unwrap();
    let (send, mut events) = futures::channel::mpsc::unbounded();
    let hook = talpid_tunnel::EventHook::new(send);
    let event = talpid_tunnel::TunnelEvent::Up {
        metadata: crate::tunnel_metadata(client.get_interface_name(), &config),
        selected_obfuscation: None,
    };
    // A real authenticated Check and a configured pair do not substitute for
    // installation of that pair in a GotaTun device. Observe the actual Up queue.
    let (uninstalled_broker, _uninstalled_root, uninstalled_credit) = self::broker();
    let mut pending =
        PendingManaged::request(uninstalled_broker.clone(), tun_config(&config)).unwrap();
    let uninstalled_capture = acknowledge(&uninstalled_broker, &config);
    let uninstalled = pending.create(&config).await.unwrap();
    assert!(
        establish_and_observe(&mut check, &client, &uninstalled.owner, async { Ok(()) })
            .await
            .is_err()
    );
    assert!(
        uninstalled_capture
            .try_send(&ipv4(17, b"not-installed"))
            .is_err()
    );
    uninstalled.owner.stop().await;
    drop(uninstalled);
    assert_eq!(uninstalled_credit.used(), 0);
    // Deterministic activation -> loss -> actual enqueue ordering. Replacing
    // the checked publication with a direct callback makes this assertion fail.
    capture.retire();
    assert!(owner.publish(|| hook.enqueue(event)).is_err());
    assert!(events.try_recv().is_err());
    assert!(!broker.snapshot().ordinary_ready);
    client.shutdown().await;
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
    remote.stop().await;
}

#[cfg(unix)]
struct FirstBindEnobufs {
    broker: AttachmentBroker,
    attempts: Mutex<Vec<(u64, u64)>>,
}
#[cfg(unix)]
impl SocketBypass for FirstBindEnobufs {
    fn bypass_socket(
        &self,
        _: socket2::SockRef<'_>,
        _: &talpid_net::bypass::BypassToken,
    ) -> io::Result<()> {
        let snapshot = self.broker.snapshot();
        let mut attempts = self.attempts.lock().unwrap();
        attempts.push((
            snapshot.capture_generation.unwrap(),
            snapshot.attachment.unwrap(),
        ));
        if attempts.len() == 1 {
            Err(io::Error::from_raw_os_error(
                nix::errno::Errno::ENOBUFS as i32,
            ))
        } else {
            Ok(())
        }
    }
    fn revoke_bypass(
        &self,
        _: socket2::SockRef<'_>,
        _: &talpid_net::bypass::BypassToken,
    ) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn actual_enobufs_bind_retries_with_fresh_request_capture_attempt_and_control() {
    let (broker, _root, control) = broker();
    let mut config = config();
    let (remote, mut observed) = remote(&mut config, false).await;
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let first_capture = acknowledge(&broker, &config);
    let actor_broker = broker.clone();
    let actor_config = config.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let actor = tokio::spawn(async move {
        let mut capture = first_capture;
        let mut changes = actor_broker.changes();
        tokio::pin!(stopped);
        loop {
            let state = *changes.borrow_and_update();
            if state.request.is_some() && state.capture_generation.is_none() {
                capture = acknowledge(&actor_broker, &actor_config);
            }
            tokio::select! { _ = &mut stopped => return capture, result = changes.changed() => result.unwrap() }
        }
    });
    let bypass = Arc::new(FirstBindEnobufs {
        broker: broker.clone(),
        attempts: Mutex::new(Vec::new()),
    });
    let mut client = tokio::time::timeout(
        Duration::from_secs(5),
        GotaTun::new(
            PlaintextSource::Managed(source),
            bypass.clone(),
            None,
            &config,
            None,
            String::new(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let attempts = bypass.attempts.lock().unwrap().clone();
    assert!(attempts.len() >= 2);
    assert_ne!(attempts[0].0, attempts[1].0, "old capture receipt reused");
    assert_ne!(
        attempts[0].1, attempts[1].1,
        "consumed attempt/queues reused"
    );
    assert_eq!(control.used(), CONTROL_STORAGE);
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
        .await
        .unwrap();
    stop.send(()).unwrap();
    let capture = actor.await.unwrap();
    let bytes = ipv4(17, b"fresh-enobufs-attempt-nonce");
    capture.try_send(&bytes).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap(),
        bytes
    );
    let mut reply = tokio::time::timeout(Duration::from_secs(2), capture.reply())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        reply.write(|received| {
            assert_eq!(received, bytes);
            Ok(received.len())
        }),
        RelayWriteOutcome::Written
    ));
    client.shutdown().await;
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
    remote.stop().await;
}

#[tokio::test]
async fn cancelled_setup_owner_and_cancelled_shutdown_keep_joined_cleanup() {
    let (broker, _root, control) = broker();
    let config = config();
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    // The external caller is cancelled while its worker awaits the real receipt.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            GotaTun::new(
                PlaintextSource::Managed(source),
                Arc::new(NoopBypass),
                None,
                &config,
                None,
                String::new()
            )
        )
        .await
        .is_err()
    );
    let _capture = acknowledge(&broker, &config);
    // An unclaimed completed tunnel is dropped by its supervised setup owner,
    // which revokes and joins both GotaTun and control work before refund.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if broker.snapshot().capture_generation.is_none() && control.used() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert!(!broker.snapshot().ordinary_ready);
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let _next_capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    {
        use std::{
            future::{Future, poll_fn},
            task::Poll,
        };
        let stop = client.shutdown();
        tokio::pin!(stop);
        poll_fn(|cx| {
            assert!(stop.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert!(client.cleanup.is_some());
    assert_eq!(control.used(), CONTROL_STORAGE);
    client.shutdown().await;
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn native_monitor_disconnect_aborts_pending_ephemeral_negotiation_promptly() {
    let mut config = config();
    config.quantum_resistant = true;
    let (ready, pending) = tokio::sync::oneshot::channel();
    let (completed, completion) = tokio::sync::oneshot::channel();
    let monitor = tokio::spawn(async move {
        let bypass: Arc<dyn SocketBypass> = Arc::new(NoopBypass);
        let negotiation = crate::ephemeral::negotiate_ephemeral_peers(&config, 3, None, &bypass);
        tokio::pin!(negotiation);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(negotiation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        ready.send(()).unwrap();
        let _ = negotiation.await;
        let _ = completed.send(());
    });
    tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    let (close, close_rx) = futures::channel::oneshot::channel();
    let (events, event_rx) = std::sync::mpsc::channel();
    let (cancellation, _receiver) = CancelToken::new();
    let observed_cancellation = cancellation.clone();
    close.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_millis(250),
        crate::close_android_monitor(false, close_rx, cancellation, monitor, events),
    )
    .await
    .expect("Native disconnect waited for negotiation");
    assert!(!observed_cancellation.is_closed());
    assert!(matches!(event_rx.try_recv(), Ok(crate::CloseMsg::Stop)));
    assert!(
        tokio::time::timeout(Duration::from_millis(250), completion)
            .await
            .unwrap()
            .is_err(),
        "negotiation finished instead of being aborted"
    );
}

#[tokio::test]
async fn managed_monitor_disconnect_waits_for_cancelled_owner_and_actual_joined_cleanup() {
    let (broker, _root, control) = broker();
    let config = config();
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let _capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let (cancellation, mut receiver) = CancelToken::new();
    let (noticed, cancelled) = tokio::sync::oneshot::channel();
    let (release, cleanup) = tokio::sync::oneshot::channel();
    let monitor = tokio::spawn(async move {
        receiver.cancelled().await;
        noticed.send(()).unwrap();
        cleanup.await.unwrap();
        client.shutdown().await;
    });
    let (close, close_rx) = futures::channel::oneshot::channel();
    let (events, event_rx) = std::sync::mpsc::channel();
    let shutdown = tokio::spawn(crate::close_android_monitor(
        true,
        close_rx,
        cancellation,
        monitor,
        events,
    ));
    close.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), cancelled)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        control.used(),
        CONTROL_STORAGE,
        "cancel refunded a live producer"
    );
    assert!(matches!(
        event_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event_rx.try_recv(), Ok(crate::CloseMsg::Stop)));
    assert_eq!(
        control.used(),
        0,
        "Stop preceded actual control/device joins"
    );
    assert!(!broker.snapshot().ordinary_ready);
}

// Independent endpoint/device from the archived TCP fixture. This is ordinary
// application TCP, not a control stream and not a production adapter hook.
#[derive(Default)]
struct TcpPackets {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
struct TcpRx(Vec<u8>);
struct TcpTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl smoltcp::phy::RxToken for TcpRx {
    fn consume<R, F>(self, operation: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        operation(&self.0)
    }
}
impl smoltcp::phy::TxToken for TcpTx<'_> {
    fn consume<R, F>(self, length: usize, operation: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0; length];
        let value = operation(&mut bytes);
        self.0.push_back(bytes);
        value
    }
}
impl smoltcp::phy::Device for TcpPackets {
    type RxToken<'a> = TcpRx;
    type TxToken<'a> = TcpTx<'a>;
    fn receive(
        &mut self,
        _: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        Some((TcpRx(self.input.pop_front()?), TcpTx(&mut self.output)))
    }
    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TcpTx(&mut self.output))
    }
    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = 1420;
        caps
    }
}
struct TcpEndpoint {
    device: TcpPackets,
    interface: smoltcp::iface::Interface,
    sockets: smoltcp::iface::SocketSet<'static>,
    socket: smoltcp::iface::SocketHandle,
    started: Instant,
    output: mpsc::Sender<Packet<Ip>>,
    received: Vec<u8>,
    response: Vec<u8>,
    sent: usize,
}
impl TcpEndpoint {
    fn new(output: mpsc::Sender<Packet<Ip>>, response: Vec<u8>) -> Self {
        use smoltcp::{
            iface::{Config, Interface, SocketSet},
            socket::tcp,
            wire::{HardwareAddress, IpCidr},
        };
        let address: Ipv4Addr = "203.0.113.20".parse().unwrap();
        let mut device = TcpPackets::default();
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::from_millis(0),
        );
        interface
            .update_ip_addrs(|addresses| addresses.push(IpCidr::new(address.into(), 32)).unwrap());
        interface
            .routes_mut()
            .add_default_ipv4_route(address)
            .unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 32768]),
            tcp::SocketBuffer::new(vec![0; 32768]),
        );
        socket.set_ack_delay(None);
        socket.listen(443).unwrap();
        let socket = sockets.add(socket);
        Self {
            device,
            interface,
            sockets,
            socket,
            started: Instant::now(),
            output,
            received: Vec::new(),
            response,
            sent: 0,
        }
    }
    fn pump(&mut self) -> io::Result<()> {
        use smoltcp::socket::tcp;
        let now = smoltcp::time::Instant::from_millis(self.started.elapsed().as_millis() as i64);
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        let socket = self.sockets.get_mut::<tcp::Socket<'_>>(self.socket);
        let mut buffer = [0; 4096];
        if socket.can_recv() {
            let count = socket.recv_slice(&mut buffer).unwrap();
            self.received.extend_from_slice(&buffer[..count]);
        }
        if !self.received.is_empty() && socket.can_send() && self.sent < self.response.len() {
            self.sent += socket.send_slice(&self.response[self.sent..]).unwrap();
        }
        if self.sent == self.response.len() && socket.state() == tcp::State::CloseWait {
            socket.close();
        }
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        while let Some(bytes) = self.device.output.pop_front() {
            self.output
                .try_send(Packet::<[u8]>::copy_from(&bytes).try_into_ip().unwrap())
                .map_err(|_| io::ErrorKind::WouldBlock)?;
        }
        Ok(())
    }
}
struct TcpRemoteSend(Arc<Mutex<TcpEndpoint>>);
struct TcpRemoteReceive {
    endpoint: Arc<Mutex<TcpEndpoint>>,
    input: mpsc::Receiver<Packet<Ip>>,
}
impl IpSend for TcpRemoteSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        let mut endpoint = self.0.lock().unwrap();
        if bytes[9] == 1 {
            let reply = echo_reply(&bytes);
            return endpoint
                .output
                .try_send(Packet::<[u8]>::copy_from(&reply).try_into_ip().unwrap())
                .map_err(|_| io::ErrorKind::WouldBlock.into());
        }
        assert_eq!(bytes[9], 6);
        assert_eq!(&bytes[12..16], &[10, 12, 34, 56]);
        assert_eq!(&bytes[16..20], &[203, 0, 113, 20]);
        endpoint.device.input.push_back(bytes.to_vec());
        endpoint.pump()
    }
}
impl IpRecv for TcpRemoteReceive {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            tokio::select! {
                packet = self.input.recv() => return Ok(std::iter::once(packet.ok_or(io::ErrorKind::BrokenPipe)?)),
                _ = tokio::time::sleep(Duration::from_millis(2)) => self.endpoint.lock().unwrap().pump()?,
            }
        }
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}

#[tokio::test]
async fn ordinary_tcp_stream_consumers_receive_full_nonces_through_real_crypto() {
    use talpid_netstack::smoltcp_network::{SmoltcpNetworkConfig, smoltcp_network};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (broker, _root, control) = broker();
    let mut config = config();
    config.tunnel.addresses.retain(|address| address.is_ipv4());
    config.ipv6_gateway = None;
    let key = PrivateKey::new_from_random();
    config.entry_peer.public_key = key.public_key();
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    config.entry_peer.endpoint = (Ipv4Addr::LOCALHOST, port).into();
    let (output, input) = mpsc::channel(64);
    let request: Vec<_> = b"ordinary-application-request-nonce"
        .iter()
        .copied()
        .cycle()
        .take(12305)
        .collect();
    let response: Vec<_> = b"independent-peer-response-nonce"
        .iter()
        .copied()
        .cycle()
        .take(16371)
        .collect();
    let endpoint = Arc::new(Mutex::new(TcpEndpoint::new(output, response.clone())));
    let peer = PeerConfig {
        public_key: config.tunnel.private_key.public_key(),
        allowed_ips: vec!["10.12.34.56/32".parse().unwrap()],
        endpoint: "127.0.0.1:9".parse().unwrap(),
        psk: None,
        constant_packet_size: false,
    };
    let remote = DeviceBuilder::new()
        .with_default_udp()
        .with_listen_port(port)
        .with_private_key(StaticSecret::from(key.to_bytes()))
        .with_peer(to_gotatun_peer(&peer, None))
        .with_ip_pair(
            TcpRemoteSend(endpoint.clone()),
            TcpRemoteReceive {
                endpoint: endpoint.clone(),
                input,
            },
        )
        .build()
        .await
        .unwrap();
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
        .await
        .unwrap();
    let (application, mut app_output, mut app_input, mut app_guard) =
        smoltcp_network(SmoltcpNetworkConfig {
            ipv4_addr: config.tunnel_ipv4().unwrap(),
            ipv6_addr: None,
            mtu: config.mtu,
        });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let bridge = tokio::spawn(async move {
        let mut pool = PacketBufPool::new(4);
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                _ = &mut stopped => return capture,
                packets = app_output.recv(&mut pool) => {
                    for packet in packets.unwrap() {
                        capture.try_send(&packet.into_bytes()).unwrap();
                    }
                }
                reply = capture.reply() => {
                    let mut reply = reply.unwrap();
                    let mut bytes = None;
                    assert!(matches!(reply.write(|packet| { bytes = Some(packet.to_vec()); Ok(packet.len()) }), RelayWriteOutcome::Written));
                    app_input.send(Packet::<[u8]>::copy_from(&bytes.unwrap()).try_into_ip().unwrap()).await.unwrap();
                }
            }
        }
    });
    let mut stream = application
        .clone()
        .tcp_connect("203.0.113.20:443".parse().unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(&request))
        .await
        .unwrap()
        .unwrap();
    let mut received = vec![0; response.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, response);
    tokio::time::timeout(Duration::from_secs(2), async {
        while endpoint.lock().unwrap().received.len() < request.len() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(endpoint.lock().unwrap().received, request);
    stop.send(()).unwrap();
    let capture = bridge.await.unwrap();
    drop((stream, application));
    app_guard.stop().await;
    client.shutdown().await;
    drop((owner, check, client, capture));
    assert_eq!(control.used(), 0);
    remote.stop().await;
}
