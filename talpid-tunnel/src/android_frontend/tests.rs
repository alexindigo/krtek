use super::*;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::tcp,
    time::Instant as StackInstant,
    wire::{HardwareAddress, IpCidr},
};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst},
    },
    time::{Duration, Instant},
};
use talpid_lan_forwarder::{Disposition, Flow, Refused, Transport, packet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
};

fn routes() -> Vec<String> {
    vec!["10.0.2.2/32".into(), "fd42::/64".into()]
}
fn pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
    )
    .unwrap()
}
#[derive(Default)]
struct Platform {
    next: Mutex<Option<OwnedFd>>,
    history: Mutex<Vec<String>>,
    opened: AtomicUsize,
    closed: AtomicUsize,
    release_fails: AtomicBool,
    active: AtomicBool,
    descriptor: Mutex<Option<(std::path::PathBuf, std::path::PathBuf)>>,
}
impl Platform {
    fn new() -> (Arc<Self>, AsyncFd<OwnedFd>) {
        let (fd, peer) = pair();
        let platform = Arc::new(Self::default());
        *platform.next.lock().unwrap() = Some(fd);
        (platform, AsyncFd::new(peer).unwrap())
    }
}
impl FrontendPlatform for Platform {
    fn open(&self, routes: &[String]) -> io::Result<OwnedFd> {
        if self.active.swap(true, SeqCst) {
            return Err(io::Error::other("platform still owned"));
        }
        let fd = self
            .next
            .lock()
            .unwrap()
            .take()
            .expect("one descriptor per open");
        let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
        *self.descriptor.lock().unwrap() = Some((path.clone(), std::fs::read_link(path)?));
        self.history
            .lock()
            .unwrap()
            .push(format!("open:{routes:?}"));
        self.opened.fetch_add(1, SeqCst);
        Ok(fd)
    }
    fn closed(&self) -> io::Result<()> {
        let descriptor = self.descriptor.lock().unwrap();
        let (path, old) = descriptor.as_ref().unwrap();
        assert_ne!(
            std::fs::read_link(path).ok(),
            Some(old.clone()),
            "platform hook preceded descriptor close"
        );
        self.history.lock().unwrap().push("closed".into());
        self.closed.fetch_add(1, SeqCst);
        if self.release_fails.load(SeqCst) {
            return Err(io::Error::other("platform release failed"));
        }
        self.active.store(false, SeqCst);
        Ok(())
    }
}
// Test convenience only. Production consumers retain the owner before readiness
// and keep it on errors, rather than discarding the pending-release obligation.
async fn start<A: LocalAuthority>(
    platform: Arc<dyn FrontendPlatform>,
    routes: Vec<String>,
    forwarder: Forwarder<A>,
    updates: watch::Receiver<u64>,
) -> io::Result<FrontendOwner> {
    let mut owner = FrontendOwner::start(platform, routes, forwarder, updates)?;
    if let Err(error) = owner.ready().await {
        owner.stop().await?;
        return Err(error);
    }
    Ok(owner)
}
struct Authority {
    available: AtomicBool,
    drop: AtomicBool,
    revision: AtomicU64,
    prepares: AtomicUsize,
    checks: AtomicUsize,
    pause: Option<Arc<Pause>>,
    pause_after: usize,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            available: AtomicBool::new(true),
            drop: AtomicBool::new(false),
            revision: AtomicU64::new(0),
            prepares: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
            pause: None,
            pause_after: 0,
        }
    }
}
impl LocalAuthority for Authority {
    type Grant = u64;
    fn disposition(&self, _: IpAddr) -> Disposition {
        if self.drop.load(SeqCst) {
            Disposition::Drop
        } else {
            Disposition::Local
        }
    }
    fn authorize(&self, _: Flow) -> Result<u64, Refused> {
        if self.available.load(SeqCst) {
            Ok(self.revision.load(SeqCst))
        } else {
            Err(Refused::Denied)
        }
    }
    fn prepare(&self, _: &socket2::Socket, _: &u64) -> Result<(), Refused> {
        let prepared = self.prepares.fetch_add(1, SeqCst);
        if let Some(pause) = &self.pause
            && prepared >= self.pause_after
        {
            pause.enter();
        }
        if self.available.load(SeqCst) {
            Ok(())
        } else {
            Err(Refused::Stale)
        }
    }
    fn current(&self, grant: &u64) -> bool {
        self.checks.fetch_add(1, SeqCst);
        self.available.load(SeqCst) && *grant == self.revision.load(SeqCst)
    }
    fn physical_destination(&self, _: &u64, flow: Flow) -> SocketAddr {
        flow.destination
    }
}
async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("consumer deadline")
}
async fn send(fd: &AsyncFd<OwnedFd>, bytes: &[u8]) {
    loop {
        let _ = fd.writable().await.unwrap();
        match fd.try_io(Interest::WRITABLE, |fd| {
            nix::unistd::write(fd, bytes).map_err(io::Error::from)
        }) {
            Ok(n) => {
                assert_eq!(n, bytes.len());
                return;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("test send: {e}"),
        }
    }
}
async fn receive(fd: &AsyncFd<OwnedFd>) -> Vec<u8> {
    let mut bytes = vec![0; MAX_PACKET_SIZE];
    loop {
        let _ = fd.readable().await.unwrap();
        match fd.try_io(Interest::READABLE, |fd| {
            nix::unistd::read(fd, &mut bytes).map_err(io::Error::from)
        }) {
            Ok(n) => {
                bytes.truncate(n);
                return bytes;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("test receive: {e}"),
        }
    }
}
fn flow(destination: SocketAddr, transport: Transport, port: u16) -> Flow {
    Flow {
        source: SocketAddr::new(
            if destination.is_ipv6() {
                "fd00::2".parse().unwrap()
            } else {
                "10.5.0.2".parse().unwrap()
            },
            port,
        ),
        destination,
        transport,
    }
}
fn udp(flow: Flow, bytes: &[u8]) -> Vec<u8> {
    packet::udp_reply(
        Flow {
            source: flow.destination,
            destination: flow.source,
            transport: Transport::Udp,
        },
        bytes,
    )
    .unwrap()
}
async fn udp_echo(ipv6: bool) -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>, JoinHandle<()>) {
    let socket = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let (hits, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 1280];
        while let Ok((len, peer)) = socket.recv_from(&mut bytes).await {
            hits.send(bytes[..len].to_vec()).unwrap();
            socket.send_to(&bytes[..len], peer).await.unwrap();
        }
    });
    (address, rx, task)
}
async fn tcp_echo(ipv6: bool) -> (SocketAddr, mpsc::UnboundedReceiver<()>, JoinHandle<()>) {
    let listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            accepted.send(()).unwrap();
            tokio::spawn(async move {
                let mut bytes = [0; 4096];
                while let Ok(len) = socket.read(&mut bytes).await {
                    if len == 0 {
                        break;
                    }
                    if socket.write_all(&bytes[..len]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (address, rx, task)
}

// Genuine application TCP stack, with no path to the peer other than the fake TUN.
#[derive(Default)]
struct Packets {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}
impl Device for Packets {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(Rx, Tx<'_>)> {
        Some((Rx(self.incoming.pop_front()?), Tx(&mut self.outgoing)))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<Tx<'_>> {
        assert!(self.outgoing.len() < 1024);
        Some(Tx(&mut self.outgoing))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1280;
        c
    }
}
struct App {
    interface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    device: Packets,
    started: Instant,
}
impl App {
    fn new(flow: Flow) -> Self {
        let mut device = Packets::default();
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            StackInstant::ZERO,
        );
        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(
                flow.source.ip().into(),
                if flow.source.is_ipv6() { 128 } else { 32 },
            ))
            .unwrap();
        });
        if flow.source.is_ipv6() {
            interface
                .routes_mut()
                .add_default_ipv6_route(match flow.source.ip() {
                    IpAddr::V6(ip) => ip,
                    _ => unreachable!(),
                })
                .unwrap();
        } else {
            interface
                .routes_mut()
                .add_default_ipv4_route(match flow.source.ip() {
                    IpAddr::V4(ip) => ip,
                    _ => unreachable!(),
                })
                .unwrap();
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        socket.set_ack_delay(None);
        socket
            .connect(interface.context(), flow.destination, flow.source)
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        Self {
            interface,
            sockets,
            handle,
            device,
            started: Instant::now(),
        }
    }
    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(self.handle)
    }
    async fn until(&mut self, fd: &AsyncFd<OwnedFd>, mut condition: impl FnMut(&mut Self) -> bool) {
        bounded(async {
            loop {
                let mut bytes = vec![0; MAX_PACKET_SIZE];
                loop {
                    match fd.try_io(Interest::READABLE, |fd| nix::unistd::read(fd, &mut bytes).map_err(io::Error::from)) {
                        Ok(0) => panic!("interface closed during TCP exchange"),
                        Ok(n) => self.device.incoming.push_back(bytes[..n].to_vec()),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("TCP app read: {e}"),
                    }
                }
                let now = StackInstant::from_millis(self.started.elapsed().as_millis() as i64);
                self.interface.poll(now, &mut self.device, &mut self.sockets);
                while let Some(packet) = self.device.outgoing.pop_front() { send(fd, &packet).await; }
                if condition(self) { return; }
                let delay = self.interface.poll_delay(now, &self.sockets).map(|d| Duration::from_millis(d.total_millis()));
                tokio::select! {
                    r = fd.readable() => { let _ = r.unwrap(); }
                    _ = async { if let Some(delay) = delay { tokio::time::sleep(delay).await; } else { std::future::pending::<()>().await; } } => {}
                }
            }
        }).await;
    }
    async fn nonce(&mut self, fd: &AsyncFd<OwnedFd>, nonce: &[u8]) {
        self.until(fd, |app| app.socket().can_send()).await;
        assert_eq!(self.socket().send_slice(nonce).unwrap(), nonce.len());
        let mut received = Vec::new();
        self.until(fd, |app| {
            while app.socket().can_recv() {
                app.socket()
                    .recv(|bytes| {
                        received.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            received.len() >= nonce.len()
        })
        .await;
        assert_eq!(received, nonce);
    }
}

#[tokio::test]
async fn tcp_and_udp_nonces_return_through_the_owned_interface() {
    for ipv6 in [false, true] {
        let (platform, peer) = Platform::new();
        let authority = Arc::new(Authority::default());
        let (_tx, rx) = watch::channel(0);
        let mut owner = start(platform.clone(), routes(), Forwarder::new(authority), rx)
            .await
            .unwrap();
        let (tcp, mut accepts, server) = tcp_echo(ipv6).await;
        let mut app = App::new(flow(tcp, Transport::Tcp, 40000));
        app.nonce(&peer, b"frontend-tcp-consumer-nonce").await;
        bounded(accepts.recv()).await.unwrap();
        app.socket().close();
        app.until(&peer, |app| !app.socket().is_open()).await;
        let (udp_peer, mut hits, echo) = udp_echo(ipv6).await;
        let request = flow(udp_peer, Transport::Udp, 40001);
        send(&peer, &udp(request, b"frontend-udp-consumer-nonce")).await;
        let reply = bounded(receive(&peer)).await;
        let parsed = packet::parse(&reply).unwrap();
        assert_eq!(parsed.payload, b"frontend-udp-consumer-nonce");
        assert_eq!(parsed.flow.source, request.destination);
        assert_eq!(parsed.flow.destination, request.source);
        assert_eq!(
            bounded(hits.recv()).await.unwrap(),
            b"frontend-udp-consumer-nonce"
        );
        owner.stop().await.unwrap();
        assert_eq!(bounded(receive(&peer)).await, Vec::<u8>::new());
        assert_eq!(platform.closed.load(SeqCst), 1);
        server.abort();
        echo.abort();
    }
}

#[tokio::test]
async fn drop_packets_never_prepare_or_reach_the_peer() {
    let (platform, peer) = Platform::new();
    let authority = Arc::new(Authority::default());
    authority.drop.store(true, SeqCst);
    let (_tx, rx) = watch::channel(0);
    let mut owner = start(platform, routes(), Forwarder::new(authority.clone()), rx)
        .await
        .unwrap();
    let (address, mut hits, echo) = udp_echo(false).await;
    send(
        &peer,
        &udp(flow(address, Transport::Udp, 40002), b"drop-nonce"),
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receive(&peer))
            .await
            .is_err()
    );
    assert!(hits.try_recv().is_err());
    assert_eq!(authority.prepares.load(SeqCst), 0);
    owner.stop().await.unwrap();
    echo.abort();
}

#[tokio::test]
async fn stop_drop_eof_and_route_replacement_preserve_single_descriptor_ownership() {
    let (platform, peer) = Platform::new();
    let (_tx, rx) = watch::channel(0);
    assert!(
        start(
            platform.clone(),
            vec![],
            Forwarder::new(Arc::new(Authority::default())),
            rx.clone()
        )
        .await
        .is_err()
    );
    assert_eq!(platform.opened.load(SeqCst), 0);
    let mut owner = start(
        platform.clone(),
        routes(),
        Forwarder::new(Arc::new(Authority::default())),
        rx.clone(),
    )
    .await
    .unwrap();
    let state = owner.state();
    owner.stop().await.unwrap();
    assert_eq!(*state.borrow(), FrontendState::Stopped);
    assert!(bounded(receive(&peer)).await.is_empty());
    let (next, next_peer) = pair();
    *platform.next.lock().unwrap() = Some(next);
    let replacement = vec!["169.254.0.0/16".to_owned(), "fe80::/10".to_owned()];
    let owner = start(
        platform.clone(),
        replacement.clone(),
        Forwarder::new(Arc::new(Authority::default())),
        rx,
    )
    .await
    .unwrap();
    let mut state = owner.state();
    drop(owner);
    bounded(state.wait_for(|s| *s == FrontendState::Stopped))
        .await
        .unwrap();
    assert_eq!(platform.closed.load(SeqCst), 2);
    assert_eq!(
        *platform.history.lock().unwrap(),
        vec![
            format!("open:{:?}", routes()),
            "closed".into(),
            format!("open:{replacement:?}"),
            "closed".into()
        ]
    );
    drop(next_peer);

    let (platform, peer) = Platform::new();
    let (_tx, rx) = watch::channel(0);
    let mut owner = start(
        platform.clone(),
        routes(),
        Forwarder::new(Arc::new(Authority::default())),
        rx,
    )
    .await
    .unwrap();
    let mut state = owner.state();
    drop(peer);
    bounded(state.wait_for(|s| *s == FrontendState::Failed))
        .await
        .unwrap();
    assert_eq!(platform.closed.load(SeqCst), 1);
    owner.stop().await.unwrap();
}

#[tokio::test]
async fn observation_loss_revokes_both_protocols_without_replacing_the_interface() {
    let (platform, peer) = Platform::new();
    let authority = Arc::new(Authority::default());
    authority.available.store(false, SeqCst);
    let (updates, rx) = watch::channel(0);
    let mut owner = start(
        platform.clone(),
        routes(),
        Forwarder::new(authority.clone()),
        rx,
    )
    .await
    .unwrap();
    let (tcp, mut accepts, tcp_server) = tcp_echo(false).await;
    let (udp_peer, mut hits, udp_server) = udp_echo(false).await;
    let request = flow(udp_peer, Transport::Udp, 41000);
    send(&peer, &udp(request, b"absent")).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receive(&peer))
            .await
            .is_err()
    );
    assert_eq!(authority.prepares.load(SeqCst), 0);
    for (round, nonce) in [b"initial".as_slice(), b"restored".as_slice()]
        .into_iter()
        .enumerate()
    {
        authority.available.store(true, SeqCst);
        authority.revision.fetch_add(1, SeqCst);
        updates.send(round as u64 * 2 + 1).unwrap();
        let mut app = App::new(flow(tcp, Transport::Tcp, 41001 + round as u16));
        app.nonce(&peer, nonce).await;
        bounded(accepts.recv()).await.unwrap();
        send(&peer, &udp(request, nonce)).await;
        let reply = bounded(receive(&peer)).await;
        assert_eq!(packet::parse(&reply).unwrap().payload, nonce);
        assert_eq!(bounded(hits.recv()).await.unwrap(), nonce);
        let prepared = authority.prepares.load(SeqCst);
        authority.available.store(false, SeqCst);
        authority.revision.fetch_add(1, SeqCst);
        updates.send(round as u64 * 2 + 2).unwrap();
        app.until(&peer, |app| !app.socket().is_open()).await;
        send(&peer, &udp(request, b"unavailable")).await;
        let mut denied = App::new(flow(tcp, Transport::Tcp, 42001 + round as u16));
        denied
            .until(&peer, |app| app.socket().state() == tcp::State::Closed)
            .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receive(&peer))
                .await
                .is_err()
        );
        assert!(hits.try_recv().is_err());
        assert!(accepts.try_recv().is_err());
        assert_eq!(authority.prepares.load(SeqCst), prepared);
        assert_eq!(platform.opened.load(SeqCst), 1);
        assert_eq!(platform.closed.load(SeqCst), 0);
        assert_eq!(*owner.state().borrow(), FrontendState::Running);
    }
    owner.stop().await.unwrap();
    tcp_server.abort();
    udp_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_interface_loop_has_no_progress_for_one_real_second() {
    let (fd, _peer) = pair();
    let (_updates, rx) = watch::channel(0);
    let (stop, stopped) = oneshot::channel();
    let polls = Arc::new(AtomicUsize::new(0));
    let count = polls.clone();
    let future = tokio::spawn(async move {
        let capture = AsyncFd::new(fd.as_fd()).unwrap();
        let mut forwarder = Forwarder::new(Arc::new(Authority::default()));
        let mut driven = Box::pin(drive(&capture, &mut forwarder, rx, stopped));
        poll_fn(move |cx| {
            count.fetch_add(1, SeqCst);
            driven.as_mut().poll(cx)
        })
        .await
    });
    let monitor = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = polls.load(SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(polls.load(SeqCst), before);
        stop.send(()).unwrap();
    };
    let (terminal, ()) = bounded(async { tokio::join!(future, monitor) }).await;
    assert_eq!(terminal.unwrap(), FrontendState::Stopped);
}

async fn blocked_sink(revoke: bool, stop_while_blocked: bool) {
    let (platform, peer) = Platform::new();
    let filler = b"full-interface-filler";
    let mut filled = 0;
    {
        let lock = platform.next.lock().unwrap();
        let fd = lock.as_ref().unwrap();
        loop {
            match nix::unistd::write(fd, filler) {
                Ok(n) => {
                    assert_eq!(n, filler.len());
                    filled += 1;
                }
                Err(nix::errno::Errno::EAGAIN) => break,
                Err(e) => panic!("fill: {e}"),
            }
        }
    }
    assert!(filled > 1);
    let authority = Arc::new(Authority::default());
    let (updates, rx) = watch::channel(0);
    let mut owner = start(
        platform.clone(),
        routes(),
        Forwarder::new(authority.clone()),
        rx,
    )
    .await
    .unwrap();
    let (address, mut hits, echo) = udp_echo(false).await;
    let request = flow(address, Transport::Udp, 43000);
    let nonces = [b"blocked-0", b"blocked-1", b"blocked-2", b"blocked-3"];
    for nonce in nonces {
        send(&peer, &udp(request, nonce)).await;
    }
    for nonce in nonces {
        assert_eq!(bounded(hits.recv()).await.unwrap(), nonce);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let checks = authority.checks.load(SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        authority.checks.load(SeqCst),
        checks,
        "blocked AsyncFd sink spun"
    );
    if revoke {
        authority.available.store(false, SeqCst);
        authority.revision.fetch_add(1, SeqCst);
    }
    updates.send(1).unwrap();
    bounded(async {
        while authority.checks.load(SeqCst) == checks {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if stop_while_blocked {
        tokio::time::timeout(Duration::from_secs(1), owner.stop())
            .await
            .unwrap()
            .unwrap();
        for _ in 0..filled {
            assert_eq!(bounded(receive(&peer)).await, filler);
        }
        assert!(bounded(receive(&peer)).await.is_empty());
    } else {
        for _ in 0..filled {
            assert_eq!(bounded(receive(&peer)).await, filler);
        }
        if revoke {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), receive(&peer))
                    .await
                    .is_err()
            );
        } else {
            for nonce in nonces {
                let packet = bounded(receive(&peer)).await;
                assert_eq!(packet::parse(&packet).unwrap().payload, nonce);
            }
        }
        owner.stop().await.unwrap();
    }
    assert_eq!(platform.closed.load(SeqCst), 1);
    echo.abort();
}
#[tokio::test]
async fn blocked_asyncfd_backlog_drains_exact_nonces_without_spinning() {
    blocked_sink(false, false).await;
}
#[tokio::test]
async fn blocked_asyncfd_retries_discard_revoked_replies() {
    blocked_sink(true, false).await;
}
#[tokio::test]
async fn stop_joins_before_a_blocked_asyncfd_becomes_writable() {
    blocked_sink(false, true).await;
}

#[tokio::test]
async fn blocking_descriptor_is_closed_before_failed_start_returns() {
    let (platform, _peer) = Platform::new();
    {
        let lock = platform.next.lock().unwrap();
        fcntl(lock.as_ref().unwrap(), FcntlArg::F_SETFL(OFlag::empty())).unwrap();
    }
    let (_updates, rx) = watch::channel(0);
    assert!(
        start(
            platform.clone(),
            routes(),
            Forwarder::new(Arc::new(Authority::default())),
            rx
        )
        .await
        .is_err()
    );
    assert_eq!(platform.closed.load(SeqCst), 1);
}

#[derive(Default)]
struct Pause {
    released: Mutex<bool>,
    release: Condvar,
    entered: tokio::sync::Notify,
}
impl Pause {
    fn enter(&self) {
        self.entered.notify_one();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.release.wait(released).unwrap();
        }
    }
    fn unblock(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
}
struct Release(Arc<Pause>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.unblock();
    }
}

#[tokio::test]
async fn physical_preparations_join_before_descriptor_close_and_stop_acknowledgement() {
    let (platform, peer) = Platform::new();
    let pause = Arc::new(Pause::default());
    let _release = Release(pause.clone());
    let authority = Arc::new(Authority {
        pause: Some(pause.clone()),
        ..Authority::default()
    });
    let (_updates, rx) = watch::channel(0);
    let mut owner = start(platform.clone(), routes(), Forwarder::new(authority), rx)
        .await
        .unwrap();
    let (address, mut hits, echo) = udp_echo(false).await;
    send(
        &peer,
        &udp(flow(address, Transport::Udp, 44000), b"held-preparation"),
    )
    .await;
    bounded(pause.entered.notified()).await;
    let stopping = tokio::spawn(async move { owner.stop().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receive(&peer))
            .await
            .is_err(),
        "descriptor closed before preparation joined"
    );
    assert!(!stopping.is_finished());
    assert_eq!(platform.closed.load(SeqCst), 0);
    pause.unblock();
    bounded(stopping).await.unwrap().unwrap();
    assert!(bounded(receive(&peer)).await.is_empty());
    assert_eq!(platform.closed.load(SeqCst), 1);
    assert!(hits.try_recv().is_err());
    echo.abort();
}

struct PausedPlatform {
    inner: Arc<Platform>,
    pause: Arc<Pause>,
}
impl FrontendPlatform for PausedPlatform {
    fn open(&self, routes: &[String]) -> io::Result<OwnedFd> {
        let fd = self.inner.open(routes)?;
        self.pause.enter();
        Ok(fd)
    }
    fn closed(&self) -> io::Result<()> {
        self.inner.closed()
    }
}

#[tokio::test]
async fn cancelled_start_still_joins_open_and_finishes_the_detached_descriptor() {
    let (platform, peer) = Platform::new();
    let pause = Arc::new(Pause::default());
    let _release = Release(pause.clone());
    let paused = Arc::new(PausedPlatform {
        inner: platform.clone(),
        pause: pause.clone(),
    });
    let (_updates, rx) = watch::channel(0);
    let opening = tokio::spawn(start(
        paused,
        routes(),
        Forwarder::new(Arc::new(Authority::default())),
        rx,
    ));
    bounded(pause.entered.notified()).await;
    opening.abort();
    match opening.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("start was not cancelled"),
    }
    assert_eq!(platform.closed.load(SeqCst), 0);
    pause.unblock();
    bounded(async {
        while platform.closed.load(SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(bounded(receive(&peer)).await.is_empty());
    assert_eq!(platform.opened.load(SeqCst), 1);
    assert_eq!(platform.closed.load(SeqCst), 1);
}

#[tokio::test]
async fn actual_wouldblock_clears_cached_writability_and_keeps_the_grant_until_retry() {
    let (fd, peer) = pair();
    let capture = AsyncFd::new(fd.as_fd()).unwrap();
    let peer = AsyncFd::new(peer).unwrap();
    let authority = Arc::new(Authority::default());
    let mut forwarder = Forwarder::new(authority.clone());
    let (address, mut hits, echo) = udp_echo(false).await;
    forwarder.ingest(&udp(
        flow(address, Transport::Udp, 45000),
        b"cached-ready-revoked-nonce",
    ));
    bounded(async {
        while !forwarder.has_output() {
            forwarder.wait().await;
        }
    })
    .await;
    assert_eq!(
        bounded(hits.recv()).await.unwrap(),
        b"cached-ready-revoked-nonce"
    );
    // First cache a true writable event, then make that event stale by filling
    // the actual kernel packet queue before the production adapter's write.
    let _ = capture.writable().await.unwrap();
    let mut filled = 0;
    loop {
        match nix::unistd::write(&fd, b"filler") {
            Ok(_) => filled += 1,
            Err(nix::errno::Errno::EAGAIN) => break,
            Err(error) => panic!("fill failed: {error}"),
        }
    }
    assert!(filled > 0);
    drain_output(&capture, &mut forwarder).unwrap();
    assert!(
        forwarder.has_output(),
        "WouldBlock consumed the queued packet"
    );
    assert_eq!(
        capture
            .try_io(Interest::WRITABLE, |_| -> io::Result<()> {
                panic!("actual WouldBlock did not clear cached readiness")
            })
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    authority.available.store(false, SeqCst);
    forwarder.revalidate();
    for _ in 0..filled {
        assert_eq!(bounded(receive(&peer)).await, b"filler");
    }
    let _ = capture.writable().await.unwrap();
    drain_output(&capture, &mut forwarder).unwrap();
    assert!(!forwarder.has_output());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receive(&peer))
            .await
            .is_err(),
        "revoked payload reached the interface consumer"
    );
    forwarder.close_all().await;
    echo.abort();
}

#[tokio::test]
async fn release_failure_retains_ownership_until_explicit_joined_retry() {
    // All successful-open exits owe release, including startup validation and EOF.
    for exit in ["stop", "startup", "eof"] {
        let (platform, peer) = Platform::new();
        platform.release_fails.store(true, SeqCst);
        if exit == "startup" {
            let fd = platform.next.lock().unwrap();
            fcntl(fd.as_ref().unwrap(), FcntlArg::F_SETFL(OFlag::empty())).unwrap();
        }
        let (_updates, rx) = watch::channel(0);
        let mut owner = FrontendOwner::start(
            platform.clone(),
            routes(),
            Forwarder::new(Arc::new(Authority::default())),
            rx.clone(),
        )
        .unwrap();
        let mut state = owner.state();
        assert!(owner.retry_release().is_err(), "release raced live owner");
        assert_eq!(owner.ready().await.is_err(), exit == "startup");
        if exit == "eof" {
            drop(peer);
            bounded(state.wait_for(|s| *s == FrontendState::Failed))
                .await
                .unwrap();
        }
        assert!(
            owner.stop().await.is_err(),
            "release failure acknowledged handoff"
        );
        assert_eq!(*state.borrow(), FrontendState::Failed);
        assert_eq!(platform.closed.load(SeqCst), 1);
        assert!(platform.active.load(SeqCst), "platform ownership was lost");
        // Stop is an acknowledgement check, never an automatic retry loop.
        assert!(owner.stop().await.is_err());
        assert_eq!(platform.closed.load(SeqCst), 1);
        assert!(
            platform.open(&routes()).is_err(),
            "replacement admitted before release"
        );
        let mut connect_acknowledged = false;
        if owner.stop().await.is_ok() {
            connect_acknowledged = true;
        }
        assert!(!connect_acknowledged);
        assert!(owner.retry_release().is_err());
        assert_eq!(platform.closed.load(SeqCst), 2);
        platform.release_fails.store(false, SeqCst);
        owner.retry_release().unwrap();
        owner.stop().await.unwrap();
        assert!(!platform.active.load(SeqCst));
        assert_eq!(platform.closed.load(SeqCst), 3);
        // The recovered acknowledgement now allows Connect or a replacement.
        connect_acknowledged = owner.stop().await.is_ok();
        assert!(connect_acknowledged);
        let (fd, replacement_peer) = pair();
        *platform.next.lock().unwrap() = Some(fd);
        let mut replacement = start(
            platform.clone(),
            routes(),
            Forwarder::new(Arc::new(Authority::default())),
            rx,
        )
        .await
        .unwrap();
        owner.retry_release().unwrap();
        assert_eq!(
            platform.closed.load(SeqCst),
            3,
            "old owner released its replacement"
        );
        assert!(platform.active.load(SeqCst));
        replacement.stop().await.unwrap();
        drop(replacement_peer);
    }
}

#[tokio::test]
async fn cancelled_readiness_and_stop_keep_the_recovery_owner() {
    let (platform, peer) = Platform::new();
    platform.release_fails.store(true, SeqCst);
    let pause = Arc::new(Pause::default());
    let _release = Release(pause.clone());
    let (_updates, rx) = watch::channel(0);
    let mut owner = FrontendOwner::start(
        Arc::new(PausedPlatform {
            inner: platform.clone(),
            pause: pause.clone(),
        }),
        routes(),
        Forwarder::new(Arc::new(Authority::default())),
        rx,
    )
    .unwrap();
    bounded(pause.entered.notified()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), owner.ready())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), owner.stop())
            .await
            .is_err()
    );
    assert!(owner.task.is_some());
    assert_eq!(platform.closed.load(SeqCst), 0);
    pause.unblock();
    assert!(bounded(owner.stop()).await.is_err());
    assert!(bounded(receive(&peer)).await.is_empty());
    assert_eq!(*owner.state().borrow(), FrontendState::Failed);
    platform.release_fails.store(false, SeqCst);
    owner.retry_release().unwrap();
    owner.stop().await.unwrap();
    assert_eq!(platform.closed.load(SeqCst), 2);
}

#[tokio::test]
async fn fatal_sink_write_joins_physical_work_before_close_release_and_failed_publication() {
    let (platform, peer) = Platform::new();
    let pause = Arc::new(Pause::default());
    let _release = Release(pause.clone());
    let authority = Arc::new(Authority {
        pause: Some(pause.clone()),
        pause_after: 1,
        ..Authority::default()
    });
    let mut forwarder = Forwarder::new(authority);
    let (address, mut hits, echo) = udp_echo(false).await;
    forwarder.ingest(&udp(
        flow(address, Transport::Udp, 46000),
        b"fatal-sink-nonce",
    ));
    bounded(async {
        while !forwarder.has_output() {
            forwarder.wait().await;
        }
    })
    .await;
    assert_eq!(bounded(hits.recv()).await.unwrap(), b"fatal-sink-nonce");
    forwarder.ingest(&udp(flow(address, Transport::Udp, 46001), b"pending-work"));
    bounded(pause.entered.notified()).await;
    // Read half only: writes fail EPIPE, but the owner's read half has no EOF.
    nix::sys::socket::shutdown(peer.get_ref().as_raw_fd(), nix::sys::socket::Shutdown::Read)
        .unwrap();
    let (_updates, rx) = watch::channel(0);
    let mut owner = start(platform.clone(), routes(), forwarder, rx)
        .await
        .unwrap();
    let mut state = owner.state();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), state.changed())
            .await
            .is_err()
    );
    assert_eq!(*state.borrow(), FrontendState::Running);
    assert_eq!(platform.closed.load(SeqCst), 0);
    let (path, target) = platform.descriptor.lock().unwrap().clone().unwrap();
    assert_eq!(
        std::fs::read_link(path).unwrap(),
        target,
        "fatal write skipped join"
    );
    pause.unblock();
    bounded(state.wait_for(|s| *s == FrontendState::Failed))
        .await
        .unwrap();
    assert_eq!(platform.closed.load(SeqCst), 1);
    assert!(!platform.active.load(SeqCst));
    owner.stop().await.unwrap();
    // The physical preparation completed, but cleanup never delivered its nonce.
    assert!(hits.try_recv().is_err());
    echo.abort();
}

#[tokio::test]
async fn short_and_zero_packet_writes_are_fatal_at_the_checked_sink_boundary() {
    for short in [false, true] {
        let mut forwarder = Forwarder::new(Arc::new(Authority::default()));
        let (address, mut hits, echo) = udp_echo(false).await;
        forwarder.ingest(&udp(
            flow(address, Transport::Udp, 47000),
            b"checked-write-nonce",
        ));
        bounded(async {
            while !forwarder.has_output() {
                forwarder.wait().await;
            }
        })
        .await;
        assert_eq!(bounded(hits.recv()).await.unwrap(), b"checked-write-nonce");
        let mut calls = 0;
        let error = forwarder
            .write_output(|bytes| {
                calls += 1;
                assert_eq!(
                    packet::parse(bytes).unwrap().payload,
                    b"checked-write-nonce"
                );
                Ok(if short { bytes.len() - 1 } else { 0 })
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(calls, 1);
        assert!(forwarder.has_output(), "partial packet was acknowledged");
        forwarder.close_all().await;
        assert!(!forwarder.has_output());
        echo.abort();
    }
}
