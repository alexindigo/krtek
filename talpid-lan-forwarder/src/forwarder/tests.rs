use super::*;
use crate::packet::{
    TcpFlags,
    tests::{flow, tcp_packet, udp_packet},
};
use smoltcp::wire::{IpProtocol, Ipv4Packet};
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

fn test_forwarder(authority: Arc<Authority>) -> Forwarder<Authority> {
    Forwarder::new(
        authority,
        Arc::new(talpid_netstack::buffer_budget::BufferBudget::new(
            128 * 1024 * 1024,
        )),
    )
    .unwrap()
}

// Test-only convenience consumer. Production can only write through the checked
// callback, keeping the grant inside the forwarder even across WouldBlock.
impl Forwarder<Authority> {
    fn next_output(&mut self) -> Option<Vec<u8>> {
        let mut packet = None;
        self.write_output(|bytes| {
            packet = Some(bytes.to_vec());
            Ok(bytes.len())
        })
        .unwrap();
        packet
    }
}

#[derive(Default)]
struct Authority {
    drop: AtomicBool,
    deny: AtomicBool,
    revoked: AtomicBool,
    authorizations: AtomicUsize,
    preparations: AtomicUsize,
    results: Mutex<VecDeque<Result<(), Refused>>>,
    blocked: Mutex<bool>,
    release: Condvar,
    #[cfg(unix)]
    descriptors: Mutex<Vec<(std::path::PathBuf, std::path::PathBuf)>>,
}
impl Authority {
    fn hold(self: &Arc<Self>) -> Unblock {
        *self.blocked.lock().unwrap() = true;
        Unblock(self.clone())
    }
    fn unblock(&self) {
        *self.blocked.lock().unwrap() = false;
        self.release.notify_all();
    }
    fn results(&self, results: impl IntoIterator<Item = Result<(), Refused>>) {
        self.results.lock().unwrap().extend(results);
    }
}
struct Unblock(Arc<Authority>);
impl Drop for Unblock {
    fn drop(&mut self) {
        self.0.unblock();
    }
}
impl LocalAuthority for Authority {
    type Grant = ();
    fn disposition(&self, _: std::net::IpAddr) -> Disposition {
        if self.drop.load(Ordering::SeqCst) {
            Disposition::Drop
        } else {
            Disposition::Local
        }
    }
    fn authorize(&self, _: Flow) -> Result<(), Refused> {
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        if self.deny.load(Ordering::SeqCst) {
            Err(Refused::Denied)
        } else {
            Ok(())
        }
    }
    fn prepare(&self, socket: &Socket, _: &()) -> Result<(), Refused> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", socket.as_raw_fd()));
            let link = std::fs::read_link(&path).unwrap();
            self.descriptors.lock().unwrap().push((path, link));
        }
        self.preparations.fetch_add(1, Ordering::SeqCst);
        let mut blocked = self.blocked.lock().unwrap();
        while *blocked {
            blocked = self.release.wait(blocked).unwrap();
        }
        self.results.lock().unwrap().pop_front().unwrap_or(Ok(()))
    }
    fn current(&self, _: &()) -> bool {
        !self.revoked.load(Ordering::SeqCst)
    }
    fn physical_destination(&self, _: &(), flow: Flow) -> std::net::SocketAddr {
        flow.destination
    }
}

fn syn(flow: Flow) -> Vec<u8> {
    tcp_packet(
        flow,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    )
}
fn loopback(ipv6: bool) -> &'static str {
    if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }
}
fn target(destination: std::net::SocketAddr, transport: Transport) -> Flow {
    Flow {
        destination,
        ..flow(destination.is_ipv6(), transport)
    }
}
fn settled(forwarder: &Forwarder<Authority>) -> bool {
    forwarder.pending.is_empty() && forwarder.udp.values().all(|entry| entry.held.is_empty())
}
async fn until<A: LocalAuthority>(
    forwarder: &mut Forwarder<A>,
    predicate: impl Fn(&Forwarder<A>) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            forwarder.process();
            if predicate(forwarder) {
                break;
            }
            forwarder.wait().await;
        }
    })
    .await
    .expect("forwarder progress deadline");
}
async fn prepare_started(authority: &Authority, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while authority.preparations.load(Ordering::SeqCst) < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn read(stream: &TcpStream, bytes: &mut [u8]) -> usize {
    loop {
        stream.readable().await.unwrap();
        match stream.try_read(bytes) {
            Ok(n) => return n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("peer read: {e}"),
        }
    }
}
async fn write(stream: &TcpStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        stream.writable().await.unwrap();
        match stream.try_write(bytes) {
            Ok(n) => {
                assert!(n > 0);
                bytes = &bytes[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("peer write: {e}"),
        }
    }
}

/// A genuine second TCP stack; its only path to the real peer is the forwarder.
struct App {
    stack: Stack,
    handle: SocketHandle,
}
impl App {
    fn new(flow: Flow) -> Self {
        let budget = Arc::new(talpid_netstack::buffer_budget::BufferBudget::new(
            128 * 1024 * 1024,
        ));
        let mut stack = Stack::new(1280, budget.clone(), budget);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; STREAM_BUFFER]),
            tcp::SocketBuffer::new(vec![0; STREAM_BUFFER]),
        );
        socket.set_ack_delay(None);
        socket
            .connect(stack.interface.context(), flow.destination, flow.source)
            .unwrap();
        let handle = stack.sockets.add(socket);
        Self { stack, handle }
    }
    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.stack.sockets.get_mut(self.handle)
    }
    fn exchange(&mut self, forwarder: &mut Forwarder<Authority>) {
        self.exchange_observed(forwarder, |_| {}, |_| {});
    }
    fn exchange_observed(
        &mut self,
        forwarder: &mut Forwarder<Authority>,
        mut application: impl FnMut(&[u8]),
        mut response: impl FnMut(&[u8]),
    ) {
        // Every iteration moves a packet or ends. The finite packet allowance
        // catches accidental feedback instead of hiding it behind a sleep.
        for _ in 0..1024 {
            self.stack.poll(forwarder.stack_now());
            let mut moved = false;
            while let Some(bytes) = self.stack.device.outgoing.pop_front() {
                moved = true;
                application(&bytes);
                forwarder.ingest(&bytes);
            }
            forwarder.process();
            while let Some(bytes) = forwarder.next_output() {
                moved = true;
                response(&bytes);
                assert!(self.stack.receive(&bytes, forwarder.stack_now()));
            }
            if !moved {
                return;
            }
        }
        panic!("packet feedback loop");
    }
    async fn until(
        &mut self,
        forwarder: &mut Forwarder<Authority>,
        mut predicate: impl FnMut(&mut Self, &Forwarder<Authority>) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                self.exchange(forwarder);
                if predicate(self, forwarder) { break; }
                let delay = self.stack.interface.poll_delay(forwarder.stack_now(), &self.stack.sockets);
                tokio::select! {
                    _ = forwarder.wait() => {},
                    _ = async {
                        if let Some(delay) = delay { tokio::time::sleep_until(Instant::now() + Duration::from_millis(delay.total_millis())).await; }
                        else { std::future::pending::<()>().await; }
                    } => {},
                }
            }
        }).await.expect("application TCP progress deadline");
    }
}

async fn tcp_echo(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut all = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let n = read(&stream, &mut buffer).await;
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buffer[..n]);
            write(&stream, &buffer[..n]).await;
        }
        all
    });
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    // A distinct patterned nonce larger than either endpoint ring exercises
    // backpressure and wrapping in both directions, not just the handshake.
    let nonce: Vec<_> = (0..STREAM_BUFFER * 3 + 17)
        .map(|n| (n % 251) as u8)
        .collect();
    let mut sent = 0;
    let mut received = Vec::new();
    app.until(&mut forwarder, |app, _| {
        if sent < nonce.len() && app.socket().can_send() {
            sent += app.socket().send_slice(&nonce[sent..]).unwrap();
        }
        let mut bytes = [0; 64];
        while app.socket().can_recv() {
            let n = app.socket().recv_slice(&mut bytes).unwrap();
            received.extend_from_slice(&bytes[..n]);
        }
        sent == nonce.len() && received.len() == nonce.len()
    })
    .await;
    assert_eq!(
        received, nonce,
        "nonce must reach the app, not just the physical socket"
    );
    app.socket().close();
    app.until(&mut forwarder, |app, forwarder| {
        !app.socket().is_open() && forwarder.stats().tcp_flows == 0
    })
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap(),
        nonce
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn tcp_nonce_reaches_application_and_both_sockets_close() {
    tcp_echo(false).await;
}
#[tokio::test]
async fn ipv6_tcp_nonce_reaches_application() {
    tcp_echo(true).await;
}

#[tokio::test]
async fn full_local_region_preserves_existing_tcp_udp_consumers_in_both_families() {
    use talpid_netstack::buffer_budget::BufferBudget;
    for ipv6 in [false, true] {
        let root = BufferBudget::new(64 * 1024 * 1024);
        let local = root.reserve(30 * 1024 * 1024).unwrap().region().unwrap();
        let control = root.reserve(8 * 1024 * 1024).unwrap().region().unwrap();
        let authority = Arc::new(Authority::default());
        let mut forwarder = Forwarder::new(authority.clone(), Arc::new(local.clone())).unwrap();
        let baseline = local.used();
        assert!(
            baseline < 8 * 1024 * 1024,
            "startup is MTU-sized, not a maximum-packet arena per output slot"
        );
        let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
        let tcp_flow = target(listener.local_addr().unwrap(), Transport::Tcp);
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 1024];
            loop {
                let n = read(&stream, &mut bytes).await;
                if n == 0 {
                    break;
                }
                write(&stream, &bytes[..n]).await;
            }
        });
        let mut app = App::new(tcp_flow);
        app.until(&mut forwarder, |app, _| app.socket().can_send())
            .await;
        let udp = UdpSocket::bind(loopback(ipv6)).await.unwrap();
        let udp_flow = target(udp.local_addr().unwrap(), Transport::Udp);
        forwarder.ingest(&udp_packet(udp_flow, b"admit udp"));
        until(&mut forwarder, settled).await;
        let mut bytes = [0; 256];
        let (n, address) = udp.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"admit udp");
        let pressure = local.reserve(local.limit() - local.used()).unwrap();
        assert_eq!(local.used(), local.limit());
        let preparations = authority.preparations.load(Ordering::SeqCst);
        for transport in [Transport::Tcp, Transport::Udp] {
            let mut refused_flow = if transport == Transport::Tcp {
                tcp_flow
            } else {
                udp_flow
            };
            refused_flow.source.set_port(50001);
            forwarder.ingest(&if transport == Transport::Tcp {
                syn(refused_flow)
            } else {
                udp_packet(refused_flow, b"must not arrive")
            });
            assert!(!forwarder.pending.contains_key(&refused_flow));
        }
        assert_eq!(authority.preparations.load(Ordering::SeqCst), preparations);
        let nonce: Vec<_> = (0..STREAM_BUFFER * 3 + 17)
            .map(|n| (n % 251) as u8)
            .collect();
        let (mut sent, mut received) = (0, Vec::new());
        app.until(&mut forwarder, |app, _| {
            if sent < nonce.len() && app.socket().can_send() {
                sent += app.socket().send_slice(&nonce[sent..]).unwrap();
            }
            while app.socket().can_recv() {
                let n = app.socket().recv_slice(&mut bytes).unwrap();
                received.extend_from_slice(&bytes[..n]);
            }
            received.len() == nonce.len()
        })
        .await;
        assert_eq!(
            received, nonce,
            "existing TCP consumer under full input budget"
        );
        forwarder.ingest(&udp_packet(udp_flow, b"udp under full budget"));
        until(&mut forwarder, settled).await;
        let (n, from) = udp.recv_from(&mut bytes).await.unwrap();
        assert_eq!(from, address);
        assert_eq!(&bytes[..n], b"udp under full budget");
        udp.send_to(&bytes[..n], from).await.unwrap();
        until(&mut forwarder, Forwarder::has_output).await;
        let reply = forwarder.next_output().unwrap();
        assert_eq!(
            packet::parse(&reply).unwrap().payload,
            b"udp under full budget"
        );
        assert_eq!(control.used(), 0);
        let private = control.reserve(4096).unwrap();
        drop(private);
        assert_eq!(local.used(), local.limit());
        drop(pressure);
        forwarder.close_all().await;
        assert_eq!(local.used(), baseline);
        drop(forwarder);
        assert_eq!(local.used(), 0);
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        drop((local, control));
        assert_eq!(root.used(), 0);
    }
}

#[tokio::test]
async fn budget_refusal_has_no_real_time_progress_loop_and_recovers() {
    use talpid_netstack::buffer_budget::BufferBudget;
    let budget = BufferBudget::new(30 * 1024 * 1024);
    let authority = Arc::new(Authority::default());
    let mut forwarder = Forwarder::new(authority.clone(), Arc::new(budget.clone())).unwrap();
    let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    forwarder.ingest(&udp_packet(flow, b"refused"));
    assert_eq!(authority.preparations.load(Ordering::SeqCst), 0);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), forwarder.wait())
            .await
            .is_err()
    );
    assert!(forwarder.pending.is_empty() && forwarder.udp.is_empty());
    drop(pressure);
    forwarder.ingest(&udp_packet(flow, b"recovered nonce"));
    until(&mut forwarder, settled).await;
    let mut bytes = [0; 64];
    let (n, address) = peer.recv_from(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..n], b"recovered nonce");
    peer.send_to(&bytes[..n], address).await.unwrap();
    until(&mut forwarder, Forwarder::has_output).await;
    assert_eq!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .payload,
        b"recovered nonce"
    );
    forwarder.close_all().await;
    drop(forwarder);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn expired_and_cancelled_preparation_keeps_credit_until_join() {
    use talpid_netstack::buffer_budget::BufferBudget;
    let budget = BufferBudget::new(30 * 1024 * 1024);
    let authority = Arc::new(Authority::default());
    let mut forwarder = Forwarder::new(authority.clone(), Arc::new(budget.clone())).unwrap();
    let baseline = budget.used();
    let held = authority.hold();
    forwarder.ingest(&udp_packet(flow(false, Transport::Udp), b"pending"));
    prepare_started(&authority, 1).await;
    let charged = budget.used();
    assert!(charged > baseline);
    forwarder.pending.values_mut().next().unwrap().deadline = Instant::now();
    forwarder.process();
    assert_eq!(budget.used(), charged);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), forwarder.close_all())
            .await
            .is_err()
    );
    assert_eq!(budget.used(), charged);
    assert_eq!(forwarder.stats().udp_flows, 1);
    drop(held);
    forwarder.close_all().await;
    assert_eq!(budget.used(), baseline);
    drop(forwarder);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn blocked_output_retains_storage_until_revoked_discard() {
    use talpid_netstack::buffer_budget::BufferBudget;
    let budget = BufferBudget::new(30 * 1024 * 1024);
    let authority = Arc::new(Authority::default());
    let mut forwarder = Forwarder::new(authority.clone(), Arc::new(budget.clone())).unwrap();
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    forwarder.ingest(&udp_packet(flow, b"queued nonce"));
    until(&mut forwarder, settled).await;
    let mut bytes = [0; 64];
    let (n, address) = peer.recv_from(&mut bytes).await.unwrap();
    peer.send_to(&bytes[..n], address).await.unwrap();
    until(&mut forwarder, Forwarder::has_output).await;
    let all = (2 * OUTPUT_PACKETS + 2) * (forwarder.mtu + BUFFER_OVERHEAD);
    assert!(forwarder.replies.try_reserve(all).is_err());
    assert_eq!(
        forwarder
            .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(forwarder.replies.try_reserve(all).is_err());
    authority.revoked.store(true, Ordering::SeqCst);
    assert!(
        !forwarder
            .write_output(|_| panic!("revoked payload reached consumer"))
            .unwrap()
    );
    drop(forwarder.replies.try_reserve(all).unwrap());
    forwarder.close_all().await;
    drop(forwarder);
    assert_eq!(budget.used(), 0);
}

// Keep a genuine application TCP state machine, but translate its wire sequence
// space so reuse and wraparound are deterministic, independent of the RNG seed.
struct IncarnationApp {
    app: App,
    isn: i32,
    shift: Option<i32>,
    sent: Vec<Vec<u8>>,
    replays: Vec<Vec<u8>>,
}
impl IncarnationApp {
    fn new(flow: Flow, isn: i32) -> Self {
        Self {
            app: App::new(flow),
            isn,
            shift: None,
            sent: Vec::new(),
            replays: Vec::new(),
        }
    }
    fn ingress(&mut self, forwarder: &mut Forwarder<Authority>) {
        self.app.stack.poll(forwarder.stack_now());
        while let Some(mut bytes) = self.app.stack.device.outgoing.pop_front() {
            let parsed = packet::parse(&bytes).unwrap();
            let source = parsed.flow.source.ip().into();
            let destination = parsed.flow.destination.ip().into();
            let offset = if bytes[0] >> 4 == 4 {
                usize::from(bytes[0] & 15) * 4
            } else {
                40
            };
            let mut tcp = smoltcp::wire::TcpPacket::new_checked(&mut bytes[offset..]).unwrap();
            let shift = *self
                .shift
                .get_or_insert_with(|| self.isn.wrapping_sub(tcp.seq_number().0));
            tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(
                tcp.seq_number().0.wrapping_add(shift),
            ));
            tcp.fill_checksum(&source, &destination);
            self.sent.push(bytes.to_vec());
            forwarder.ingest(&bytes);
        }
    }
    fn receive(&mut self, bytes: &[u8], now: StackInstant) {
        let parsed = packet::parse(bytes).unwrap();
        assert!(
            !parsed.tcp_flags.unwrap().rst,
            "incarnation received an unexpected reset"
        );
        let source = parsed.flow.source.ip().into();
        let destination = parsed.flow.destination.ip().into();
        let mut bytes = bytes.to_vec();
        let offset = if bytes[0] >> 4 == 4 {
            usize::from(bytes[0] & 15) * 4
        } else {
            40
        };
        let mut tcp = smoltcp::wire::TcpPacket::new_checked(&mut bytes[offset..]).unwrap();
        if tcp.ack() {
            tcp.set_ack_number(smoltcp::wire::TcpSeqNumber(
                tcp.ack_number().0.wrapping_sub(self.shift.unwrap()),
            ));
        }
        tcp.fill_checksum(&source, &destination);
        assert!(self.app.stack.receive(&bytes, now));
    }
    fn exchange(&mut self, forwarder: &mut Forwarder<Authority>) {
        for _ in 0..1024 {
            for bytes in &self.replays {
                forwarder.ingest(bytes);
            }
            let before = self.sent.len();
            self.ingress(forwarder);
            forwarder.process();
            let mut moved = self.sent.len() != before;
            while let Some(bytes) = forwarder.next_output() {
                moved = true;
                self.receive(&bytes, forwarder.stack_now());
            }
            if !moved {
                return;
            }
        }
        panic!("incarnation packet feedback loop");
    }
    async fn until(
        &mut self,
        forwarder: &mut Forwarder<Authority>,
        mut predicate: impl FnMut(&mut Self, &Forwarder<Authority>) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                self.exchange(forwarder);
                if predicate(self, forwarder) {
                    return;
                }
                forwarder.wait().await;
            }
        })
        .await
        .expect("incarnation application progress deadline");
    }
    async fn echo_eof(&mut self, forwarder: &mut Forwarder<Authority>, nonce: &[u8]) {
        self.until(forwarder, |app, _| app.app.socket().can_send())
            .await;
        self.app.socket().send_slice(nonce).unwrap();
        self.app.socket().close();
        let mut received = Vec::new();
        self.until(forwarder, |app, f| {
            let mut buffer = [0; 256];
            while app.app.socket().can_recv() {
                let n = app.app.socket().recv_slice(&mut buffer).unwrap();
                received.extend_from_slice(&buffer[..n]);
            }
            if !app.app.socket().may_recv() && f.tcp.is_empty() {
                assert_eq!(
                    received, nonce,
                    "exact incarnation reply must reach application"
                );
                assert_eq!(
                    app.app.socket().recv_slice(&mut buffer),
                    Err(tcp::RecvError::Finished)
                );
                true
            } else {
                false
            }
        })
        .await;
    }
}

fn control_at(
    flow: Flow,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    fin: bool,
    rst: bool,
) -> Vec<u8> {
    let mut bytes = tcp_packet(
        flow,
        TcpFlags {
            ack: ack.is_some(),
            fin,
            rst,
            ..TcpFlags::default()
        },
        b"",
    );
    let offset = if flow.source.is_ipv6() { 40 } else { 20 };
    let mut tcp = smoltcp::wire::TcpPacket::new_checked(&mut bytes[offset..]).unwrap();
    tcp.set_seq_number(seq);
    if let Some(ack) = ack {
        tcp.set_ack_number(ack);
    }
    tcp.fill_checksum(&flow.source.ip().into(), &flow.destination.ip().into());
    bytes
}

async fn time_wait_overlap(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let first = b"A crosses the signed sequence boundary";
    let second = b"B starts immediately after A's FIN";
    let peer = tokio::spawn(async move {
        for nonce in [first.as_slice(), second.as_slice()] {
            let (stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 256];
            loop {
                let n = read(&stream, &mut buffer).await;
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(request, nonce);
            write(&stream, nonce).await;
            socket2::SockRef::from(&stream)
                .shutdown(Shutdown::Write)
                .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    });
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut a = IncarnationApp::new(flow, i32::MAX - 16);
    a.echo_eof(&mut forwarder, first).await;
    let old = forwarder.retired_tcp[0];
    let next = old.incarnation.application_next;
    // Review's distinct-but-overlapping ISN, at the old FIN, must not admit.
    let mut overlapping = IncarnationApp::new(flow, (next - 1).0);
    overlapping.ingress(&mut forwarder);
    assert_eq!(
        authority.authorizations.load(Ordering::SeqCst),
        1,
        "overlapping TIME-WAIT SYN admitted"
    );
    assert_eq!(forwarder.retired_tcp, vec![old]);
    assert!(!forwarder.has_output());
    let hold = authority.hold();
    let mut b = IncarnationApp::new(flow, next.0);
    b.ingress(&mut forwarder);
    prepare_started(&authority, 2).await;
    assert!(
        forwarder.retired_tcp.is_empty(),
        "new owner must remove A's tombstone immediately"
    );
    let stale = [
        control_at(flow, next - 1, old.incarnation.peer_next, true, false),
        control_at(flow, next, None, false, true),
    ];
    for bytes in &stale {
        forwarder.ingest(bytes);
    }
    assert!(
        !forwarder.pending[&flow].expired,
        "stale FIN/RST cancelled pending B"
    );
    forwarder.ingest(&control_at(flow, next + 1, None, false, true));
    assert!(
        forwarder.pending[&flow].expired,
        "B's own cancellation was swallowed"
    );
    drop(hold);
    until(&mut forwarder, |f| !f.pending.contains_key(&flow)).await;
    let mut b = IncarnationApp::new(flow, next.0);
    b.until(&mut forwarder, |b, _| b.app.socket().can_send())
        .await;
    assert!(forwarder.retired_tcp.is_empty());
    for bytes in &stale {
        forwarder.ingest(bytes);
    }
    b.replays = stale.to_vec();
    b.echo_eof(&mut forwarder, second).await;
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 3);
    assert_eq!(authority.preparations.load(Ordering::SeqCst), 3);
    peer.await.unwrap();
    forwarder.close_all().await;
}

#[tokio::test]
async fn time_wait_ipv4_overlap_handshake_pending_cancel_and_stale_controls() {
    time_wait_overlap(false).await;
}
#[tokio::test]
async fn time_wait_ipv6_overlap_handshake_pending_cancel_and_stale_controls() {
    time_wait_overlap(true).await;
}

async fn time_wait_rejected_ack(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let nonce = b"valid stream after rejected handshake ACK";
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 256];
        loop {
            let n = read(&stream, &mut buffer).await;
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(request, nonce);
        write(&stream, nonce).await;
        socket2::SockRef::from(&stream)
            .shutdown(Shutdown::Write)
            .unwrap();
    });
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let mut app = IncarnationApp::new(flow, -32);
    app.ingress(&mut forwarder);
    until(&mut forwarder, |f| {
        f.tcp.contains_key(&flow) && f.has_output()
    })
    .await;
    let syn_ack = forwarder.next_output().unwrap();
    let before = forwarder.tcp[&flow].incarnation;
    app.receive(&syn_ack, forwarder.stack_now());
    forwarder.ingest(&control_at(
        flow,
        before.application_next,
        Some(before.peer_isn.unwrap() + 1_000_000),
        false,
        false,
    ));
    let reset = forwarder
        .next_output()
        .expect("rejected ACK must produce protocol reset");
    assert!(stack::segment(&reset).unwrap().rst);
    assert_eq!(
        forwarder
            .stack
            .sockets
            .get::<tcp::Socket<'_>>(forwarder.tcp[&flow].handle)
            .state(),
        tcp::State::SynReceived
    );
    assert_eq!(
        forwarder.tcp[&flow].incarnation, before,
        "protocol reset poisoned stream metadata"
    );
    app.echo_eof(&mut forwarder, nonce).await;
    let retired = forwarder.retired_tcp.clone();
    for bytes in &app.sent {
        forwarder.ingest(bytes);
        assert!(
            !forwarder.has_output(),
            "terminal replay after rejected handshake ACK produced reset"
        );
    }
    assert_eq!(forwarder.retired_tcp, retired);
    peer.await.unwrap();
    forwarder.close_all().await;
}

#[tokio::test]
async fn time_wait_ipv4_rejected_handshake_ack_cannot_poison_terminal_replay() {
    time_wait_rejected_ack(false).await;
}
#[tokio::test]
async fn time_wait_ipv6_rejected_handshake_ack_cannot_poison_terminal_replay() {
    time_wait_rejected_ack(true).await;
}

async fn same_tuple_incarnations(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let a_nonce = b"incarnation A exact graceful nonce";
    let b_nonce = b"incarnation B distinct graceful nonce";
    let peer = tokio::spawn(async move {
        for nonce in [a_nonce.as_slice(), b_nonce.as_slice()] {
            let (physical, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 256];
            loop {
                let n = read(&physical, &mut buffer).await;
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(
                request, nonce,
                "nonce must reach its own physical connection"
            );
            write(&physical, nonce).await;
            socket2::SockRef::from(&physical)
                .shutdown(Shutdown::Write)
                .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err(),
            "old replay opened a phantom connection"
        );
    });
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut a = IncarnationApp::new(flow, -16); // data and FIN cross u32::MAX
    a.echo_eof(&mut forwarder, a_nonce).await;
    assert!(!forwarder.tcp.contains_key(&flow));
    let terminal: Vec<_> = a
        .sent
        .iter()
        .filter(|bytes| {
            let packet = packet::parse(bytes).unwrap();
            let flags = packet.tcp_flags.unwrap();
            flags.syn || flags.fin || (flags.ack && packet.payload.is_empty())
        })
        .cloned()
        .collect();
    let mut terminal = terminal;
    let mut reset = terminal.last().unwrap().clone();
    let offset = if ipv6 { 40 } else { 20 };
    let mut tcp = smoltcp::wire::TcpPacket::new_checked(&mut reset[offset..]).unwrap();
    tcp.set_rst(true);
    tcp.set_fin(false);
    tcp.fill_checksum(&flow.source.ip().into(), &flow.destination.ip().into());
    terminal.push(reset);
    let deadline = forwarder
        .retired_tcp
        .iter()
        .find(|entry| entry.flow == flow)
        .unwrap()
        .deadline;
    for bytes in &terminal {
        forwarder.ingest(bytes);
        assert!(
            forwarder.next_output().is_none(),
            "old replay generated output"
        );
    }
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 1);
    let old_id = forwarder.retired_tcp[0].incarnation.id;
    let hold = authority.hold();
    let mut b = IncarnationApp::new(flow, 1_000_000);
    b.ingress(&mut forwarder);
    assert_eq!(
        authority.authorizations.load(Ordering::SeqCst),
        2,
        "fresh same-tuple SYN must reach authorization before old expiry"
    );
    prepare_started(&authority, 2).await;
    for bytes in &terminal {
        forwarder.ingest(bytes);
    }
    assert!(
        !forwarder.pending[&flow].expired,
        "old controls cancelled pending B"
    );
    assert!(forwarder.retired_tcp.is_empty());
    forwarder.output.push_front(Output {
        bytes: RelayBuffer::copy_from(terminal.last().unwrap(), &*forwarder.replies).unwrap(),
        grant: None,
        tcp: Some(TcpOutput {
            flow,
            id: old_id,
            fin: false,
            reset: true,
        }),
    });
    assert!(
        !forwarder
            .write_output(|_| panic!("A protocol reset reached pending B"))
            .unwrap()
    );
    drop(hold);
    b.until(&mut forwarder, |b, _| b.app.socket().can_send())
        .await;
    for bytes in &terminal {
        forwarder.ingest(bytes);
    }
    b.replays = terminal.clone();
    b.echo_eof(&mut forwarder, b_nonce).await;
    // After admission B is the only tuple owner, including in TIME-WAIT.
    let completed_b = forwarder.retired_tcp.clone();
    for bytes in &terminal {
        forwarder.ingest(bytes);
        assert!(forwarder.next_output().is_none());
    }
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 2);
    assert_eq!(authority.preparations.load(Ordering::SeqCst), 2);
    assert_eq!(forwarder.retired_tcp, completed_b);
    assert_eq!(completed_b.len(), 1);
    assert_ne!(completed_b[0].incarnation.id, old_id);
    assert!(completed_b[0].deadline >= deadline);
    peer.await.unwrap();
    forwarder.close_all().await;
}

#[tokio::test]
async fn incarnation_ipv4_same_tuple_fresh_syn_and_stale_controls() {
    same_tuple_incarnations(false).await;
}
#[tokio::test]
async fn incarnation_ipv6_same_tuple_fresh_syn_and_stale_controls() {
    same_tuple_incarnations(true).await;
}

async fn finished_incarnation_replacement(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let a_nonce = b"A peer-first closing nonce";
    let b_nonce = b"B after blocked final ACK";
    let peer = tokio::spawn(async move {
        for nonce in [a_nonce.as_slice(), b_nonce.as_slice()] {
            let (physical, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 256];
            let mut request = Vec::new();
            while request.len() < nonce.len() {
                let n = read(&physical, &mut buffer).await;
                assert!(n > 0);
                request.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(request, nonce);
            write(&physical, nonce).await;
            socket2::SockRef::from(&physical)
                .shutdown(Shutdown::Write)
                .unwrap();
            assert_eq!(read(&physical, &mut buffer).await, 0);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    });
    let mut a = IncarnationApp::new(flow, i32::MAX - 8);
    a.until(&mut forwarder, |a, _| a.app.socket().can_send())
        .await;
    a.app.socket().send_slice(a_nonce).unwrap();
    let mut received = Vec::new();
    a.until(&mut forwarder, |a, _| {
        let mut buffer = [0; 256];
        while a.app.socket().can_recv() {
            let n = a.app.socket().recv_slice(&mut buffer).unwrap();
            received.extend_from_slice(&buffer[..n]);
        }
        !a.app.socket().may_recv()
    })
    .await;
    assert_eq!(received, a_nonce);
    assert_eq!(
        a.app.socket().recv_slice(&mut [0]),
        Err(tcp::RecvError::Finished)
    );
    a.app.socket().close();
    a.ingress(&mut forwarder);
    forwarder.process();
    assert!(forwarder.graceful_tcp_finished(&forwarder.tcp[&flow]));
    assert!(forwarder.tcp[&flow].fin_delivered);
    let final_output = forwarder
        .output
        .front()
        .expect("finished A still owns final ACK")
        .bytes
        .to_vec();
    let old_owner = forwarder.output.front().unwrap().tcp.unwrap();
    assert_eq!(
        forwarder
            .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        forwarder.output.front().unwrap().bytes.as_slice(),
        final_output
    );
    let mut b = IncarnationApp::new(flow, forwarder.tcp[&flow].incarnation.application_next.0);
    b.ingress(&mut forwarder);
    assert_eq!(
        authority.authorizations.load(Ordering::SeqCst),
        2,
        "fresh SYN must replace finished A despite blocked final output"
    );
    assert!(
        !forwarder
            .output
            .iter()
            .any(|output| output.bytes.as_slice() == final_output),
        "replacement retained A output"
    );
    for packet in &a.sent {
        forwarder.ingest(packet);
    }
    b.until(&mut forwarder, |b, _| b.app.socket().can_send())
        .await;
    // Even a delayed A FIN callback cannot inherit B's grant or acknowledge B's
    // FIN. Use the actual old identity at this private owner boundary.
    forwarder.output.push_front(Output {
        bytes: RelayBuffer::copy_from(&final_output, &*forwarder.replies).unwrap(),
        grant: Some(Arc::new(())),
        tcp: Some(TcpOutput {
            fin: true,
            ..old_owner
        }),
    });
    assert!(
        !forwarder
            .write_output(|_| panic!("old incarnation reached checked sink"))
            .unwrap()
    );
    assert!(!forwarder.tcp[&flow].fin_delivered);
    b.replays = a.sent;
    b.echo_eof(&mut forwarder, b_nonce).await;
    peer.await.unwrap();
    forwarder.close_all().await;
}

#[tokio::test]
async fn incarnation_ipv4_finished_owner_with_blocked_final_output() {
    finished_incarnation_replacement(false).await;
}
#[tokio::test]
async fn incarnation_ipv6_finished_owner_with_blocked_final_output() {
    finished_incarnation_replacement(true).await;
}

async fn same_tuple_budget(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let nonce = b"one metadata reservation per incarnation";
    let peer = tokio::spawn(async move {
        for _ in 0..TCP_TOMBSTONES {
            let (physical, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 256];
            let mut request = Vec::new();
            loop {
                let n = read(&physical, &mut buffer).await;
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(request, nonce);
            write(&physical, nonce).await;
            socket2::SockRef::from(&physical)
                .shutdown(Shutdown::Write)
                .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    });
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut original = Vec::new();
    for index in 0..TCP_TOMBSTONES {
        let mut app = IncarnationApp::new(flow, (index as i32) * 1_000_000);
        if index + 1 == TCP_TOMBSTONES {
            let hold = authority.hold();
            app.ingress(&mut forwarder);
            prepare_started(&authority, TCP_TOMBSTONES).await;
            assert!(forwarder.retired_tcp.is_empty());
            assert_eq!(forwarder.flow_count(Transport::Tcp), 1);
            assert_eq!(
                authority.authorizations.load(Ordering::SeqCst),
                TCP_TOMBSTONES
            );
            drop(hold);
        }
        app.echo_eof(&mut forwarder, nonce).await;
        assert_eq!(forwarder.retired_tcp.len(), 1);
        assert_eq!(
            forwarder.retired_tcp[0].incarnation.application_isn,
            TcpSeqNumber((index as i32) * 1_000_000)
        );
        if index == 0 {
            original = app.sent;
        }
    }
    let before = forwarder.retired_tcp.clone();
    for bytes in &original {
        forwarder.ingest(bytes);
    }
    assert!(forwarder.next_output().is_none());
    assert_eq!(forwarder.stats().full, 0);
    assert_eq!(
        authority.authorizations.load(Ordering::SeqCst),
        TCP_TOMBSTONES
    );
    assert_eq!(
        forwarder.retired_tcp, before,
        "old SYN cannot replace or refresh the latest TIME-WAIT record"
    );
    assert!(forwarder.next_output().is_none());
    peer.await.unwrap();
    forwarder.close_all().await;
}

#[tokio::test]
async fn incarnation_ipv4_same_tuple_churn_reserves_each_record() {
    same_tuple_budget(false).await;
}
#[tokio::test]
async fn incarnation_ipv6_same_tuple_churn_reserves_each_record() {
    same_tuple_budget(true).await;
}

async fn incarnation_expiry(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let nonce = b"wrapping incarnation fixed expiry";
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 256];
        let mut request = Vec::new();
        loop {
            let n = read(&stream, &mut buffer).await;
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(request, nonce);
        write(&stream, nonce).await;
        socket2::SockRef::from(&stream)
            .shutdown(Shutdown::Write)
            .unwrap();
        listener
    });
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut app = IncarnationApp::new(flow, -8);
    app.echo_eof(&mut forwarder, nonce).await;
    let _listener = peer.await.unwrap();
    let deadline = forwarder.retired_tcp[0].deadline;
    let terminal = app.sent.last().unwrap();
    tokio::time::pause();
    tokio::time::advance(deadline - Instant::now() - Duration::from_millis(1)).await;
    for bytes in &app.sent {
        forwarder.ingest(bytes);
    }
    assert_eq!(forwarder.retired_tcp[0].deadline, deadline);
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 1);
    assert!(!forwarder.has_output());
    forwarder.wait().await;
    assert!(Instant::now() >= deadline && Instant::now() - deadline < Duration::from_millis(2));
    assert!(forwarder.retired_tcp.is_empty());
    forwarder.ingest(terminal);
    let reset = forwarder.next_output().unwrap();
    assert!(packet::parse(&reset).unwrap().tcp_flags.unwrap().rst);
    // Never answer a reset with a reset, including after record expiry.
    let reverse = Flow {
        source: flow.destination,
        destination: flow.source,
        ..flow
    };
    let reset_of_reset = stack::reset(&tcp_packet(
        reverse,
        TcpFlags {
            ack: true,
            ..TcpFlags::default()
        },
        b"",
    ))
    .unwrap();
    forwarder.ingest(&reset_of_reset);
    assert!(!forwarder.has_output());
    forwarder.close_all().await;
}

#[tokio::test]
async fn incarnation_ipv4_wraparound_deadline_and_expired_unknown_controls() {
    incarnation_expiry(false).await;
}
#[tokio::test]
async fn incarnation_ipv6_wraparound_deadline_and_expired_unknown_controls() {
    incarnation_expiry(true).await;
}

async fn incarnation_revoke_blocked_reply(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut app = IncarnationApp::new(flow, -32);
    app.until(&mut forwarder, |app, _| app.app.socket().can_send())
        .await;
    let (physical, _) = listener.accept().await.unwrap();
    let nonce = b"current incarnation revoked while checked output is blocked";
    write(&physical, nonce).await;
    until(&mut forwarder, |f| {
        f.output
            .iter()
            .any(|output| !packet::parse(&output.bytes).unwrap().payload.is_empty())
    })
    .await;
    assert_eq!(
        forwarder
            .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    authority.revoked.store(true, Ordering::SeqCst);
    forwarder.revalidate();
    assert!(forwarder.tcp.is_empty() && forwarder.retired_tcp.is_empty());
    let mut resets = 0;
    while let Some(bytes) = forwarder.next_output() {
        let packet = packet::parse(&bytes).unwrap();
        assert!(
            packet.payload.is_empty(),
            "revoked payload reached application"
        );
        assert!(!packet.tcp_flags.unwrap().fin);
        resets += usize::from(packet.tcp_flags.unwrap().rst);
        // This is a deliberate reset control, so use the untranslated stack
        // only to inspect state after adjusting the ACK into its sequence space.
        let mut bytes = bytes;
        let offset = if ipv6 { 40 } else { 20 };
        let mut tcp = smoltcp::wire::TcpPacket::new_checked(&mut bytes[offset..]).unwrap();
        tcp.set_ack_number(smoltcp::wire::TcpSeqNumber(
            tcp.ack_number().0.wrapping_sub(app.shift.unwrap()),
        ));
        tcp.fill_checksum(&flow.destination.ip().into(), &flow.source.ip().into());
        assert!(app.app.stack.receive(&bytes, forwarder.stack_now()));
    }
    assert_eq!(resets, 1);
    assert_eq!(
        app.app.socket().recv_slice(&mut [0; 256]),
        Err(tcp::RecvError::InvalidState)
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn incarnation_ipv4_revocation_discards_blocked_reply() {
    incarnation_revoke_blocked_reply(false).await;
}
#[tokio::test]
async fn incarnation_ipv6_revocation_discards_blocked_reply() {
    incarnation_revoke_blocked_reply(true).await;
}

// Preserve the observed physical-reply -> ECONNRESET abort ordering. A reset
// peer is never entitled to a clean-EOF assertion, even after sending bytes.
async fn physical_reply_then_reset(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let nonce: Vec<u8> = (0..45).map(|n| b'A' + n % 26).collect();
    let expected = nonce.clone();
    let (seen, request_seen) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 256];
        loop {
            let n = read(&stream, &mut buffer).await;
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(request, expected);
        seen.send(()).unwrap();
        released.await.unwrap();
        write(&stream, &request).await;
        socket2::SockRef::from(&stream)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(stream);
    });
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    app.socket().send_slice(&nonce).unwrap();
    app.stack.poll(forwarder.stack_now());
    let mut payloads = 0;
    while let Some(bytes) = app.stack.device.outgoing.pop_front() {
        let packet = packet::parse(&bytes).unwrap();
        assert!(!packet.tcp_flags.unwrap().fin);
        payloads += usize::from(!packet.payload.is_empty());
        forwarder.ingest(&bytes);
    }
    assert_eq!(payloads, 1);
    app.socket().close();
    let mut fins = 0;
    app.exchange_observed(
        &mut forwarder,
        |bytes| {
            let packet = packet::parse(bytes).unwrap();
            if packet.tcp_flags.unwrap().fin {
                assert!(packet.payload.is_empty());
                fins += 1;
            }
        },
        |_| {},
    );
    assert_eq!(fins, 1);
    let entry = &forwarder.tcp[&flow];
    assert!(entry.application_fin && entry.application_eof && !entry.physical_eof);
    assert_eq!(
        forwarder
            .stack
            .sockets
            .get::<tcp::Socket<'_>>(entry.handle)
            .state(),
        tcp::State::CloseWait
    );
    tokio::time::timeout(Duration::from_secs(2), request_seen)
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    let mut peek = [0; 256];
    let n = tokio::time::timeout(
        Duration::from_secs(2),
        forwarder.tcp[&flow].physical.peek(&mut peek),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&peek[..n], nonce);
    forwarder.process();
    assert!(forwarder.tcp.is_empty() && forwarder.retired_tcp.is_empty());
    let head = forwarder.output.front().unwrap().bytes.to_vec();
    assert_eq!(
        forwarder
            .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(forwarder.output.front().unwrap().bytes.as_slice(), head);
    let mut resets = 0;
    while let Some(bytes) = forwarder.next_output() {
        let packet = packet::parse(&bytes).unwrap();
        assert!(packet.payload.is_empty(), "aborted queued reply escaped");
        assert!(!packet.tcp_flags.unwrap().fin, "real reset became fake EOF");
        resets += usize::from(packet.tcp_flags.unwrap().rst);
        assert!(app.stack.receive(&bytes, forwarder.stack_now()));
    }
    assert_eq!(resets, 1);
    assert_eq!(
        app.socket().recv_slice(&mut [0; 256]),
        Err(tcp::RecvError::InvalidState)
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn ipv4_physical_reply_then_genuine_reset_aborts_without_payload_escape() {
    physical_reply_then_reset(false).await;
}
#[tokio::test]
async fn ipv6_physical_reply_then_genuine_reset_aborts_without_payload_escape() {
    physical_reply_then_reset(true).await;
}

async fn consumer_app_first_echo_then_close(ipv6: bool, echo_after_fin: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let nonce: &[u8] = b"krtek-m3-00000000-0000-4000-8000-000000000000";
    let (release, released) = tokio::sync::oneshot::channel();
    let (seen, observed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 256];
        while request.len() < nonce.len() {
            let n = read(&stream, &mut buffer).await;
            assert!(n > 0);
            request.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(request, nonce);
        seen.send(()).unwrap();
        if echo_after_fin {
            released.await.unwrap();
            assert_eq!(read(&stream, &mut buffer).await, 0);
        }
        write(&stream, nonce).await;
        if !echo_after_fin {
            assert_eq!(read(&stream, &mut buffer).await, 0);
        }
        socket2::SockRef::from(&stream)
            .shutdown(Shutdown::Write)
            .unwrap();
    });
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    app.socket().send_slice(nonce).unwrap();
    app.exchange(&mut forwarder);
    tokio::time::timeout(Duration::from_secs(2), observed)
        .await
        .unwrap()
        .unwrap();
    assert!(!forwarder.tcp[&flow].application_fin);
    app.socket().close();
    let mut saw_application_fin = false;
    let mut saw_response_fin = false;
    let mut received = Vec::new();
    let mut release = Some(release);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            app.exchange_observed(
                &mut forwarder,
                |bytes| {
                    let packet = packet::parse(bytes).unwrap();
                    if packet.tcp_flags.unwrap().fin {
                        assert!(packet.payload.is_empty());
                        saw_application_fin = true;
                    }
                },
                |bytes| {
                    let flags = packet::parse(bytes).unwrap().tcp_flags.unwrap();
                    assert!(!flags.rst);
                    saw_response_fin |= flags.fin;
                },
            );
            if echo_after_fin && release.is_some() {
                let entry = &forwarder.tcp[&flow];
                assert!(saw_application_fin && entry.application_fin && entry.application_eof);
                assert_eq!(
                    forwarder
                        .stack
                        .sockets
                        .get::<tcp::Socket<'_>>(entry.handle)
                        .state(),
                    tcp::State::CloseWait
                );
                assert!(!entry.physical_eof && received.is_empty());
                release.take().unwrap().send(()).unwrap();
            }
            let mut buffer = [0; 256];
            while app.socket().can_recv() {
                let n = app.socket().recv_slice(&mut buffer).unwrap();
                received.extend_from_slice(&buffer[..n]);
            }
            if !app.socket().may_recv() {
                assert_eq!(received, nonce);
                assert!(saw_application_fin && saw_response_fin);
                assert_eq!(
                    app.socket().recv_slice(&mut buffer),
                    Err(tcp::RecvError::Finished)
                );
                break;
            }
            forwarder.wait().await;
        }
    })
    .await
    .expect("consumer app-first echo/close deadline");
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    forwarder.close_all().await;
}

#[tokio::test]
async fn consumer_app_first_ipv4_echo_after_processed_fin_reaches_clean_eof() {
    consumer_app_first_echo_then_close(false, true).await;
}
#[tokio::test]
async fn consumer_app_first_ipv6_echo_after_processed_fin_reaches_clean_eof() {
    consumer_app_first_echo_then_close(true, true).await;
}
#[tokio::test]
async fn consumer_app_first_ipv4_racing_echo_and_close_reaches_clean_eof() {
    consumer_app_first_echo_then_close(false, false).await;
}
#[tokio::test]
async fn consumer_app_first_ipv6_racing_echo_and_close_reaches_clean_eof() {
    consumer_app_first_echo_then_close(true, false).await;
}

async fn echoed_tcp_eof(
    ipv6: bool,
    forwarder: &mut Forwarder<Authority>,
    source_port: u16,
) -> (Flow, Vec<Vec<u8>>) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let mut flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    flow.source.set_port(source_port);
    let nonce: &[u8] = b"krtek graceful TCP reply must precede clean EOF";
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buffer = [0; 256];
        while received.len() < nonce.len() {
            let n = read(&stream, &mut buffer).await;
            assert!(n > 0);
            received.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(received, nonce);
        write(&stream, nonce).await;
        // A real peer closes after its echo, just like the device peer.
        drop(stream);
    });
    let mut app = App::new(flow);
    let mut terminal_segments = Vec::new();
    app.exchange_observed(
        forwarder,
        |bytes| terminal_segments.push(bytes.to_vec()),
        |_| {},
    );
    app.until(forwarder, |app, _| app.socket().can_send()).await;
    app.socket().send_slice(nonce).unwrap();
    app.socket().close();
    let mut received = Vec::new();
    let mut saw_fin = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            app.exchange_observed(
                forwarder,
                |bytes| {
                    let packet = packet::parse(bytes).unwrap();
                    let flags = packet.tcp_flags.unwrap();
                    if flags.fin || (flags.ack && !flags.syn && packet.payload.is_empty()) {
                        terminal_segments.push(bytes.to_vec());
                    }
                },
                |bytes| {
                    let flags = packet::parse(bytes).unwrap().tcp_flags.unwrap();
                    assert!(!flags.rst, "graceful close sent an RST to the application");
                    saw_fin |= flags.fin;
                },
            );
            let mut bytes = [0; 256];
            while app.socket().can_recv() {
                let n = app.socket().recv_slice(&mut bytes).unwrap();
                received.extend_from_slice(&bytes[..n]);
            }
            if !app.socket().may_recv() {
                assert_eq!(received, nonce, "application must receive every reply byte");
                assert!(saw_fin, "retirement must follow FIN delivery, not an abort");
                assert_eq!(
                    app.socket().recv_slice(&mut bytes),
                    Err(tcp::RecvError::Finished),
                    "application must observe clean EOF after its reply",
                );
                break;
            }
            forwarder.wait().await;
        }
    })
    .await
    .expect("graceful TCP EOF deadline");
    peer.await.unwrap();
    assert!(
        terminal_segments
            .iter()
            .any(|bytes| { packet::parse(bytes).unwrap().tcp_flags.unwrap().fin })
    );
    (flow, terminal_segments)
}

async fn graceful_tcp_eof_and_late_segments(ipv6: bool) {
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let (flow, terminal_segments) = echoed_tcp_eof(ipv6, &mut forwarder, 49152).await;
    assert!(!forwarder.tcp.contains_key(&flow));
    // Re-deliver the actual final ACK/FIN after the flow has finished. These
    // are owned closing-tuple segments, not previously unknown connections.
    for bytes in terminal_segments {
        forwarder.ingest(&bytes);
        forwarder.process();
        while let Some(reply) = forwarder.next_output() {
            assert!(
                !packet::parse(&reply).unwrap().tcp_flags.unwrap().rst,
                "late graceful ACK/FIN was reset as an unknown flow",
            );
        }
    }
    let unknown = Flow {
        source: std::net::SocketAddr::new(flow.source.ip(), flow.source.port() + 1),
        ..flow
    };
    forwarder.ingest(&tcp_packet(
        unknown,
        TcpFlags {
            ack: true,
            ..TcpFlags::default()
        },
        b"",
    ));
    assert!(
        packet::parse(
            &forwarder
                .next_output()
                .expect("unknown tuple still needs RST")
        )
        .unwrap()
        .tcp_flags
        .unwrap()
        .rst
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn graceful_tcp_reply_reaches_clean_eof_and_late_segments_are_not_reset() {
    graceful_tcp_eof_and_late_segments(false).await;
}

#[tokio::test]
async fn ipv6_graceful_tcp_reply_reaches_clean_eof_and_late_segments_are_not_reset() {
    graceful_tcp_eof_and_late_segments(true).await;
}

#[tokio::test]
async fn retired_tcp_deadline_is_fixed_and_wait_expires_it_without_polling() {
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let (flow, terminal) = echoed_tcp_eof(false, &mut forwarder, 49152).await;
    let deadline = forwarder
        .retired_tcp
        .iter()
        .find(|entry| entry.flow == flow)
        .unwrap()
        .deadline;
    assert_eq!(forwarder.deadline(), Some(deadline));
    let authorized = authority.authorizations.load(Ordering::SeqCst);
    let prepared = authority.preparations.load(Ordering::SeqCst);
    authority.revoked.store(true, Ordering::SeqCst);
    forwarder.revalidate();
    // Replay the actual old SYN and terminal sequence space, not an unrelated
    // hard-coded ISN. Fresh ISNs now have separate admission coverage above.
    let last = terminal.last().unwrap();
    let segment = stack::segment(last).unwrap();
    let mut late_reset = tcp_packet(
        flow,
        TcpFlags {
            rst: true,
            ack: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let offset = if flow.source.is_ipv6() { 40 } else { 20 };
    let mut tcp = smoltcp::wire::TcpPacket::new_checked(&mut late_reset[offset..]).unwrap();
    tcp.set_seq_number(segment.seq);
    tcp.set_ack_number(segment.ack.unwrap());
    tcp.fill_checksum(&flow.source.ip().into(), &flow.destination.ip().into());
    // Includes actual original SYN, payload+FIN, closing ACK and a reset in A's
    // terminal sequence space. None can refresh the fixed deadline.
    for bytes in terminal.iter().chain(std::iter::once(&late_reset)) {
        forwarder.ingest(bytes);
        forwarder.process();
        assert!(forwarder.next_output().is_none());
        assert_eq!(
            forwarder
                .retired_tcp
                .iter()
                .find(|entry| entry.flow == flow)
                .unwrap()
                .deadline,
            deadline
        );
    }
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), authorized);
    assert_eq!(authority.preparations.load(Ordering::SeqCst), prepared);
    tokio::time::pause();
    tokio::time::advance(deadline - Instant::now() - Duration::from_millis(1)).await;
    forwarder.ingest(terminal.last().unwrap());
    assert!(forwarder.next_output().is_none());
    assert_eq!(forwarder.deadline(), Some(deadline));
    forwarder.wait().await;
    assert!(Instant::now() >= deadline && Instant::now() - deadline < Duration::from_millis(2));
    assert!(forwarder.retired_tcp.is_empty());
    forwarder.ingest(terminal.last().unwrap());
    assert!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .tcp_flags
            .unwrap()
            .rst
    );
    forwarder.close_all().await;
    assert_eq!(forwarder.deadline(), None);
}

#[tokio::test]
async fn terminal_tuple_budget_is_reserved_and_full_admission_never_evicts() {
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut first = None;
    for index in 0..TCP_TOMBSTONES {
        // Distinct application ports keep tuples unique even if the kernel
        // chooses a recently released physical-listener port again.
        let (flow, terminal) = echoed_tcp_eof(false, &mut forwarder, 49152 + index as u16).await;
        assert!(!forwarder.tcp.contains_key(&flow));
        assert_eq!(forwarder.retired_tcp.len(), index + 1);
        first.get_or_insert((flow, terminal));
    }
    let before = forwarder.retired_tcp.clone();
    let authorized = authority.authorizations.load(Ordering::SeqCst);
    let (flow, terminal) = first.unwrap();
    for bytes in terminal {
        forwarder.ingest(&bytes);
        assert!(forwarder.next_output().is_none());
    }
    let unknown = Flow {
        source: std::net::SocketAddr::new(flow.source.ip(), 49152 + TCP_TOMBSTONES as u16),
        ..flow
    };
    forwarder.ingest(&syn(unknown));
    assert_eq!(forwarder.stats().full, 1);
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), authorized);
    assert_eq!(forwarder.retired_tcp, before);
    assert!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .tcp_flags
            .unwrap()
            .rst
    );
    assert_eq!(forwarder.stats().tcp_flows, 0);
    forwarder.close_all().await;
    assert!(forwarder.retired_tcp.is_empty());
    assert_eq!(forwarder.deadline(), None);
}

async fn fin_delivery_under_sink_backpressure(ipv6: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    let (physical, _) = listener.accept().await.unwrap();
    let nonce = b"FIN must cross the checked sink before retirement";
    app.socket().send_slice(nonce).unwrap();
    app.socket().close();
    app.exchange(&mut forwarder);
    let mut bytes = [0; 256];
    let mut request = Vec::new();
    while request.len() < nonce.len() {
        let n = read(&physical, &mut bytes).await;
        assert!(n > 0);
        request.extend_from_slice(&bytes[..n]);
    }
    assert_eq!(request, nonce);
    write(&physical, nonce).await;
    drop(physical);
    let mut blocked_fin = false;
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            app.stack.poll(forwarder.stack_now());
            while let Some(bytes) = app.stack.device.outgoing.pop_front() {
                forwarder.ingest(&bytes);
            }
            forwarder.process();
            let mut moved = false;
            while forwarder.has_output() {
                let fin = forwarder
                    .output
                    .front()
                    .unwrap()
                    .tcp
                    .is_some_and(|tcp| tcp.fin);
                if fin && !blocked_fin {
                    let head = forwarder.output.front().unwrap().bytes.to_vec();
                    assert_eq!(
                        forwarder
                            .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::WouldBlock,
                    );
                    forwarder.process();
                    assert_eq!(forwarder.output.front().unwrap().bytes.as_slice(), head);
                    assert!(!forwarder.tcp[&flow].fin_delivered);
                    assert!(!forwarder.retired_tcp.iter().any(|entry| entry.flow == flow));
                    blocked_fin = true;
                }
                let now = forwarder.stack_now();
                forwarder
                    .write_output(|packet| {
                        assert!(!packet::parse(packet).unwrap().tcp_flags.unwrap().rst);
                        assert!(app.stack.receive(packet, now));
                        Ok(packet.len())
                    })
                    .unwrap();
                moved = true;
                if fin {
                    assert!(
                        forwarder
                            .tcp
                            .get(&flow)
                            .is_some_and(|entry| entry.fin_delivered)
                            || forwarder.retired_tcp.iter().any(|entry| entry.flow == flow)
                    );
                }
            }
            while app.socket().can_recv() {
                let n = app.socket().recv_slice(&mut bytes).unwrap();
                received.extend_from_slice(&bytes[..n]);
            }
            if !app.socket().may_recv() && forwarder.tcp.is_empty() {
                assert_eq!(received, nonce);
                assert_eq!(
                    app.socket().recv_slice(&mut bytes),
                    Err(tcp::RecvError::Finished)
                );
                assert!(
                    blocked_fin && forwarder.retired_tcp.iter().any(|entry| entry.flow == flow)
                );
                break;
            }
            if !moved {
                forwarder.wait().await;
            }
        }
    })
    .await
    .expect("blocked FIN/EOF progress deadline");
    forwarder.close_all().await;
}

#[tokio::test]
async fn graceful_fin_is_not_retired_until_checked_sink_delivery_in_both_families() {
    fin_delivery_under_sink_backpressure(false).await;
    fin_delivery_under_sink_backpressure(true).await;
}

async fn udp_echo(ipv6: bool) {
    let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let nonce = b"krtek UDP consumer nonce";
    forwarder.ingest(&udp_packet(flow, nonce));
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 256];
        let (n, address) = peer.recv_from(&mut bytes).await.unwrap();
        peer.send_to(&bytes[..n], address).await.unwrap();
        bytes[..n].to_vec()
    });
    until(&mut forwarder, |f| !f.output.is_empty()).await;
    let reply = forwarder.next_output().unwrap();
    let packet = packet::parse(&reply).unwrap();
    assert_eq!(packet.payload, nonce);
    assert_eq!(packet.flow.source, flow.destination);
    assert_eq!(packet.flow.destination, flow.source);
    assert_eq!(echo.await.unwrap(), nonce);
    forwarder.close_all().await;
}
#[tokio::test]
async fn udp_nonce_reaches_application() {
    udp_echo(false).await;
}
#[tokio::test]
async fn ipv6_udp_nonce_reaches_application() {
    udp_echo(true).await;
}

#[tokio::test]
async fn drop_never_authorizes_and_denied_local_never_prepares() {
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let bytes = syn(flow(false, Transport::Tcp));
    authority.drop.store(true, Ordering::SeqCst);
    forwarder.ingest(&bytes);
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(forwarder.stats().dropped_disposition, 1);
    assert!(forwarder.next_output().is_none());
    authority.drop.store(false, Ordering::SeqCst);
    authority.deny.store(true, Ordering::SeqCst);
    forwarder.ingest(&bytes);
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(authority.preparations.load(Ordering::SeqCst), 0);
    assert_eq!(forwarder.stats().tcp_flows, 0);
    assert!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .tcp_flags
            .unwrap()
            .rst
    );
}

#[tokio::test]
async fn prepare_failure_never_connects_and_answers_reset() {
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let authority = Arc::new(Authority::default());
    authority.results([Err(Refused::PreparationFailed)]);
    let mut forwarder = test_forwarder(authority.clone());
    forwarder.ingest(&syn(flow));
    until(&mut forwarder, settled).await;
    assert_eq!(forwarder.stats().preparation_failed, 1);
    #[cfg(unix)]
    for (path, old_link) in authority.descriptors.lock().unwrap().iter() {
        assert_ne!(
            std::fs::read_link(path).ok().as_ref(),
            Some(old_link),
            "refused prepared descriptor remained open"
        );
    }
    assert!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .tcp_flags
            .unwrap()
            .rst
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn revocation_resets_tcp_removes_udp_and_suppresses_queued_data() {
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut app = App::new(target(listener.local_addr().unwrap(), Transport::Tcp));
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    let (physical, _) = listener.accept().await.unwrap();
    forwarder.ingest(&udp_packet(
        target(peer.local_addr().unwrap(), Transport::Udp),
        b"queued",
    ));
    until(&mut forwarder, settled).await;
    let mut bytes = [0; 256];
    let (n, addr) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    peer.send_to(&bytes[..n], addr).await.unwrap();
    until(&mut forwarder, |f| !f.output.is_empty()).await;
    authority.revoked.store(true, Ordering::SeqCst);
    forwarder.revalidate();
    assert_eq!(
        (forwarder.stats().tcp_flows, forwarder.stats().udp_flows),
        (0, 0)
    );
    let output = forwarder.next_output().unwrap();
    assert!(packet::parse(&output).unwrap().tcp_flags.unwrap().rst);
    assert!(
        forwarder.retired_tcp.is_empty(),
        "aborted flows are not graceful tombstones"
    );
    assert!(forwarder.next_output().is_none());
    assert_eq!(forwarder.stats().stale_reply, 1);
    assert!(app.stack.receive(&output, forwarder.stack_now()));
    assert_eq!(app.socket().state(), tcp::State::Closed);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), read(&physical, &mut bytes))
            .await
            .unwrap(),
        0
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn fixed_flow_ceilings_refuse_without_evicting_earlier_flows() {
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let mut app = App::new(target(listener.local_addr().unwrap(), Transport::Tcp));
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    let (physical, _) = listener.accept().await.unwrap();
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let live_udp = target(peer.local_addr().unwrap(), Transport::Udp);
    forwarder.ingest(&udp_packet(live_udp, b"before full"));
    until(&mut forwarder, settled).await;
    let mut buffer = [0; 64];
    tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let _hold = authority.hold();
    let tcp = flow(false, Transport::Tcp);
    let udp = flow(false, Transport::Udp);
    for port in 1..=TCP_FLOWS {
        let flow = Flow {
            source: std::net::SocketAddr::new(tcp.source.ip(), port as u16),
            ..tcp
        };
        forwarder.ingest(&syn(flow));
    }
    for port in 1..=UDP_FLOWS {
        let flow = Flow {
            source: std::net::SocketAddr::new(udp.source.ip(), port as u16),
            ..udp
        };
        forwarder.ingest(&udp_packet(flow, b"held"));
    }
    assert_eq!(
        (forwarder.stats().tcp_flows, forwarder.stats().udp_flows),
        (TCP_FLOWS, UDP_FLOWS)
    );
    assert_eq!(forwarder.stats().full, 2);
    assert_eq!(
        authority.authorizations.load(Ordering::SeqCst),
        TCP_FLOWS + UDP_FLOWS
    );
    assert!(forwarder.pending.contains_key(&Flow {
        source: std::net::SocketAddr::new(tcp.source.ip(), 1),
        ..tcp
    }));
    assert!(forwarder.pending.contains_key(&Flow {
        source: std::net::SocketAddr::new(udp.source.ip(), 1),
        ..udp
    }));
    // Capacity refusal must preserve delivery on both already-live flows.
    let echo = tokio::spawn(async move {
        let mut buffer = [0; 64];
        let n = read(&physical, &mut buffer).await;
        write(&physical, &buffer[..n]).await;
        (buffer[..n].to_vec(), physical)
    });
    let nonce = b"TCP still works when full";
    app.socket().send_slice(nonce).unwrap();
    let mut received = Vec::new();
    app.until(&mut forwarder, |app, _| {
        if app.socket().can_recv() {
            let mut bytes = [0; 64];
            let n = app.socket().recv_slice(&mut bytes).unwrap();
            received.extend_from_slice(&bytes[..n]);
        }
        received.len() == nonce.len()
    })
    .await;
    assert_eq!(received, nonce);
    let (echoed, _physical) = echo.await.unwrap();
    assert_eq!(echoed, nonce);
    forwarder.ingest(&udp_packet(live_udp, b"UDP still works when full"));
    until(&mut forwarder, |f| f.udp[&live_udp].held.is_empty()).await;
    let (n, address) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], b"UDP still works when full");
    peer.send_to(&buffer[..n], address).await.unwrap();
    until(&mut forwarder, |f| !f.output.is_empty()).await;
    assert_eq!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .payload,
        b"UDP still works when full"
    );
    authority.unblock();
    forwarder.close_all().await;
    assert_eq!(
        (forwarder.stats().tcp_flows, forwarder.stats().udp_flows),
        (0, 0)
    );
}

#[tokio::test]
async fn malformed_fragments_icmp_and_checksums_never_authorize() {
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let mut bytes = syn(flow(false, Transport::Tcp));
    forwarder.ingest(&bytes[..10]);
    bytes[8] ^= 1;
    forwarder.ingest(&bytes);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    ip.set_more_frags(true);
    ip.fill_checksum();
    forwarder.ingest(&bytes);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    ip.set_more_frags(false);
    ip.set_next_header(IpProtocol::Icmp);
    ip.fill_checksum();
    forwarder.ingest(&bytes);
    let stats = forwarder.stats();
    assert_eq!(
        (
            stats.malformed,
            stats.bad_checksum,
            stats.fragments,
            stats.unsupported_protocol
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn empty_forwarder_has_no_tick_for_one_real_second() {
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let started = std::time::Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), forwarder.wait())
            .await
            .is_err()
    );
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(forwarder.deadline(), None);
}

#[tokio::test]
async fn idle_udp_expires_at_its_real_deadline() {
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    forwarder.ingest(&udp_packet(
        target(peer.local_addr().unwrap(), Transport::Udp),
        b"idle",
    ));
    until(&mut forwarder, settled).await;
    let mut bytes = [0; 16];
    tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    tokio::time::pause();
    let deadline = forwarder.udp.values().next().unwrap().last_activity + IDLE_LIMIT;
    assert_eq!(forwarder.deadline(), Some(deadline));
    forwarder.wait().await;
    // Tokio sleep_until is millisecond-granular, not a nanosecond timer.
    assert!(Instant::now() >= deadline && Instant::now() - deadline < Duration::from_millis(2));
    assert_eq!(forwarder.stats().udp_flows, 0);
    assert_eq!(forwarder.stats().expired, 1);
}

#[tokio::test]
async fn oversized_udp_reply_is_counted_and_not_output() {
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    forwarder.ingest(&udp_packet(
        target(peer.local_addr().unwrap(), Transport::Udp),
        b"large",
    ));
    until(&mut forwarder, settled).await;
    let mut bytes = [0; 16];
    let (_, addr) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    peer.send_to(&vec![3; 1280], addr).await.unwrap();
    until(&mut forwarder, |f| f.stats().oversized_reply == 1).await;
    assert!(forwarder.next_output().is_none());
    forwarder.close_all().await;
}

#[tokio::test]
async fn stale_tcp_prepare_is_silent_and_retransmitted_syn_reauthorizes() {
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let authority = Arc::new(Authority::default());
    authority.results([Err(Refused::Stale), Ok(())]);
    let mut forwarder = test_forwarder(authority.clone());
    forwarder.ingest(&syn(flow));
    until(&mut forwarder, |f| f.pending.is_empty()).await;
    assert!(forwarder.next_output().is_none());
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 2);
    assert_eq!(forwarder.stats().stale, 1);
    forwarder.close_all().await;
}

#[tokio::test]
async fn pending_udp_holds_four_datagrams_in_order_and_drops_fifth() {
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    let authority = Arc::new(Authority::default());
    let _hold = authority.hold();
    let mut forwarder = test_forwarder(authority.clone());
    for n in 0..5 {
        forwarder.ingest(&udp_packet(flow, &[n]));
    }
    prepare_started(&authority, 1).await;
    assert_eq!(forwarder.stats().full, 1);
    assert_eq!(forwarder.pending[&flow].held.len(), 4);
    authority.unblock();
    until(&mut forwarder, settled).await;
    for n in 0..4 {
        let mut bytes = [0; 16];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len], &[n]);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut [0; 64]))
            .await
            .is_err()
    );
    forwarder.close_all().await;
}

async fn stale_udp(second_stale: bool, update_before_completion: bool) {
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    let authority = Arc::new(Authority::default());
    authority.results([
        Err(Refused::Stale),
        if second_stale {
            Err(Refused::Stale)
        } else {
            Ok(())
        },
    ]);
    let _hold = authority.hold();
    let mut forwarder = test_forwarder(authority.clone());
    forwarder.ingest(&udp_packet(flow, b"single attempt nonce"));
    prepare_started(&authority, 1).await;
    if update_before_completion {
        forwarder.revalidate();
    }
    authority.unblock();
    if !update_before_completion {
        until(&mut forwarder, |f| {
            f.pending
                .get(&flow)
                .is_some_and(|p| matches!(p.work, Work::Waiting))
        })
        .await;
        assert_eq!(forwarder.pending[&flow].held.len(), 1);
        assert_eq!(authority.authorizations.load(Ordering::SeqCst), 1);
        forwarder.revalidate();
    }
    until(&mut forwarder, settled).await;
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 2);
    assert_eq!(forwarder.stats().stale, if second_stale { 2 } else { 1 });
    if second_stale {
        assert_eq!(forwarder.stats().udp_flows, 0);
    } else {
        let mut bytes = [0; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..n], b"single attempt nonce");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut [0; 64]))
            .await
            .is_err()
    );
    forwarder.close_all().await;
}
#[tokio::test]
async fn stale_udp_retries_once_after_revalidation_and_delivers_once() {
    stale_udp(false, false).await;
}
#[tokio::test]
async fn stale_udp_retries_immediately_when_update_already_arrived() {
    stale_udp(false, true).await;
}
#[tokio::test]
async fn second_stale_udp_prepare_drops_held_datagram() {
    stale_udp(true, false).await;
}

#[tokio::test]
async fn stale_udp_without_update_expires_at_original_two_second_limit() {
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    let authority = Arc::new(Authority::default());
    authority.results([Err(Refused::Stale)]);
    let mut forwarder = test_forwarder(authority.clone());
    forwarder.ingest(&udp_packet(flow, b"held"));
    until(&mut forwarder, |f| {
        f.pending
            .get(&flow)
            .is_some_and(|p| matches!(p.work, Work::Waiting))
    })
    .await;
    tokio::time::pause();
    let deadline = forwarder.pending[&flow].deadline;
    assert_eq!(forwarder.deadline(), Some(deadline));
    forwarder.wait().await;
    assert!(Instant::now() >= deadline && Instant::now() - deadline < Duration::from_millis(2));
    assert_eq!(forwarder.stats().udp_flows, 0);
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 1);
    assert!(peer.try_recv(&mut [0; 16]).is_err());
}

#[tokio::test]
async fn notification_wakes_an_empty_owner() {
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let signal = forwarder.revalidation_signal();
    signal.notify_one();
    tokio::time::timeout(Duration::from_secs(1), forwarder.wait())
        .await
        .unwrap();
    assert_eq!(forwarder.revision, 1);
}

#[tokio::test]
async fn unknown_tcp_segments_reset_but_resets_never_answer_resets() {
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let flow = flow(false, Transport::Tcp);
    forwarder.ingest(&tcp_packet(
        flow,
        TcpFlags {
            ack: true,
            ..TcpFlags::default()
        },
        b"data",
    ));
    assert!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .tcp_flags
            .unwrap()
            .rst
    );
    forwarder.ingest(&tcp_packet(
        flow,
        TcpFlags {
            rst: true,
            ..TcpFlags::default()
        },
        b"",
    ));
    assert!(forwarder.next_output().is_none());
}

#[tokio::test]
async fn expired_blocking_prepare_retains_its_slot_and_cannot_deliver() {
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    let authority = Arc::new(Authority::default());
    let _hold = authority.hold();
    let mut forwarder = test_forwarder(authority.clone());
    forwarder.ingest(&udp_packet(flow, b"expired pending nonce"));
    prepare_started(&authority, 1).await;
    tokio::time::pause();
    // A running spawn_blocking explicitly inhibits Tokio's auto-advance.
    tokio::time::advance(CONNECT_LIMIT + Duration::from_millis(2)).await;
    forwarder.wait().await;
    assert_eq!(forwarder.stats().expired, 1);
    assert_eq!(
        forwarder.stats().udp_flows,
        1,
        "still-owned blocking task keeps its slot"
    );
    assert!(forwarder.pending[&flow].held.is_empty());
    assert_eq!(forwarder.deadline(), None);
    tokio::time::resume();
    authority.unblock();
    until(&mut forwarder, settled).await;
    assert_eq!(forwarder.stats().udp_flows, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut [0; 64]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cancelled_close_all_keeps_prepares_owned_until_joined() {
    let authority = Arc::new(Authority::default());
    let _hold = authority.hold();
    let mut forwarder = test_forwarder(authority.clone());
    forwarder.ingest(&syn(flow(false, Transport::Tcp)));
    prepare_started(&authority, 1).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), forwarder.close_all())
            .await
            .is_err()
    );
    assert_eq!(forwarder.stats().tcp_flows, 1);
    authority.unblock();
    tokio::time::timeout(Duration::from_secs(2), forwarder.close_all())
        .await
        .unwrap();
    assert_eq!(forwarder.stats().tcp_flows, 0);
    assert!(forwarder.next_output().is_none());
    #[cfg(unix)]
    for (path, old_link) in authority.descriptors.lock().unwrap().iter() {
        assert_ne!(std::fs::read_link(path).ok().as_ref(), Some(old_link));
    }
}

#[tokio::test]
async fn refused_syn_output_queue_is_bounded_and_recovers_after_dequeue() {
    let authority = Arc::new(Authority::default());
    authority.deny.store(true, Ordering::SeqCst);
    let mut forwarder = test_forwarder(authority);
    let syn = syn(flow(false, Transport::Tcp));
    for _ in 0..=OUTPUT_PACKETS {
        forwarder.ingest(&syn);
    }
    assert_eq!(forwarder.output.len(), OUTPUT_PACKETS);
    assert_eq!(forwarder.stats().full, 1);
    assert!(forwarder.next_output().is_some());
    forwarder.ingest(&syn);
    assert_eq!(forwarder.output.len(), OUTPUT_PACKETS);
    assert_eq!(forwarder.stats().full, 1);
}

#[tokio::test]
async fn failed_physical_tcp_connect_resets_application() {
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    drop(listener);
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    forwarder.ingest(&syn(flow));
    until(&mut forwarder, settled).await;
    assert_eq!(forwarder.stats().tcp_flows, 0);
    assert_eq!(forwarder.stats().preparation_failed, 1);
    assert!(
        packet::parse(&forwarder.next_output().unwrap())
            .unwrap()
            .tcp_flags
            .unwrap()
            .rst
    );
}

#[tokio::test]
async fn application_reset_cancels_held_syn_without_a_physical_connect() {
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let authority = Arc::new(Authority::default());
    let _hold = authority.hold();
    let mut forwarder = test_forwarder(authority.clone());
    let opening = syn(flow);
    let next = stack::segment(&opening).unwrap().end;
    forwarder.ingest(&opening);
    prepare_started(&authority, 1).await;
    // A sent SYN consumed its sequence number; cancellation uses SND.NXT.
    forwarder.ingest(&control_at(flow, next, None, false, true));
    assert!(forwarder.pending[&flow].held.is_empty());
    authority.unblock();
    until(&mut forwarder, settled).await;
    assert!(forwarder.next_output().is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn application_reset_aborts_the_physical_tcp_socket() {
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    let (physical, _) = listener.accept().await.unwrap();
    app.socket().abort();
    app.exchange(&mut forwarder);
    assert_eq!(forwarder.stats().tcp_flows, 0);
    let error = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            physical.readable().await.unwrap();
            match physical.try_read(&mut [0; 64]) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => break e,
                Ok(n) => panic!("reset was mapped to a graceful close ({n})"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn physical_tcp_reset_reaches_the_application() {
    let listener = TcpListener::bind(loopback(false)).await.unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    let (physical, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&physical)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(physical);
    app.until(&mut forwarder, |app, f| {
        app.socket().state() == tcp::State::Closed && f.stats().tcp_flows == 0
    })
    .await;
}

// Fill the actual nonblocking physical send queue while its peer is not reading.
// The prefix is deliberately part of the peer's exact-byte assertion, so no
// bytes are silently discarded to arrange the backpressure ordering.
async fn block_physical_write(forwarder: &Forwarder<Authority>, flow: Flow) -> Vec<u8> {
    let stream = &forwarder.tcp[&flow].physical;
    socket2::SockRef::from(stream)
        .set_send_buffer_size(4096)
        .unwrap();
    stream.writable().await.unwrap();
    let chunk = [0x5a; 65536];
    let mut prefix = Vec::new();
    loop {
        match stream.try_write(&chunk) {
            Ok(n) => {
                assert!(n > 0 && prefix.len() < 8 * 1024 * 1024);
                prefix.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("filling physical send queue: {e}"),
        }
    }
    assert!(!prefix.is_empty());
    prefix
}

async fn half_close_with_blocked_write(ipv6: bool, peer_first: bool) {
    let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
    // Bound the peer's advertised receive window before the handshake, so
    // buffered filler cannot all drain into its kernel while it is not reading.
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(4096)
        .unwrap();
    let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    let mut app = App::new(flow);
    app.until(&mut forwarder, |app, _| app.socket().can_send())
        .await;
    let (physical, _) = listener.accept().await.unwrap();
    if peer_first {
        socket2::SockRef::from(&physical)
            .shutdown(Shutdown::Write)
            .unwrap();
        app.until(&mut forwarder, |app, _| {
            app.socket().state() == tcp::State::CloseWait
        })
        .await;
    }
    let mut expected = block_physical_write(&forwarder, flow).await;
    let nonce = b"final application payload and FIN behind physical backpressure";
    expected.extend_from_slice(nonce);
    app.socket().send_slice(nonce).unwrap();
    app.socket().close();
    app.exchange(&mut forwarder);
    if !peer_first {
        socket2::SockRef::from(&physical)
            .shutdown(Shutdown::Write)
            .unwrap();
        app.until(&mut forwarder, |app, _| !app.socket().is_open())
            .await;
    }
    let endpoint = forwarder
        .stack
        .sockets
        .get::<tcp::Socket<'_>>(forwarder.tcp[&flow].handle);
    assert!(
        endpoint.can_recv(),
        "accepted final bytes must still be backpressured"
    );
    assert!(
        matches!(endpoint.state(), tcp::State::TimeWait | tcp::State::Closed),
        "exercise a terminal protocol state with undelivered rx bytes"
    );
    let peer = tokio::spawn(async move {
        let mut received = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let n = read(&physical, &mut buffer).await;
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..n]);
        }
        received
    });
    app.until(&mut forwarder, |_, f| f.tcp.is_empty()).await;
    let actual = tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        actual.len(),
        expected.len(),
        "all accepted bytes must precede physical EOF"
    );
    assert!(
        actual == expected,
        "physical peer must receive exact bytes before EOF"
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn peer_first_half_close_drains_final_payload_and_fin_under_backpressure() {
    half_close_with_blocked_write(false, true).await;
    half_close_with_blocked_write(true, true).await;
}

#[tokio::test]
async fn application_first_half_close_drains_before_physical_eof_under_backpressure() {
    half_close_with_blocked_write(false, false).await;
    half_close_with_blocked_write(true, false).await;
}

#[tokio::test]
async fn blocked_output_backlog_does_not_wake_internal_wait() {
    let authority = Arc::new(Authority::default());
    authority.deny.store(true, Ordering::SeqCst);
    let mut forwarder = test_forwarder(authority);
    for _ in 0..4 {
        forwarder.ingest(&syn(flow(false, Transport::Tcp)));
    }
    assert_eq!(forwarder.output.len(), 4);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), forwarder.wait())
            .await
            .is_err(),
        "queued output is not internal readiness while its sink is blocked"
    );
    forwarder.close_all().await;
}

fn option_syn(flow: Flow, option: [u8; 4]) -> Vec<u8> {
    let (mut bytes, offset) =
        packet::ip_packet(flow.source, flow.destination, IpProtocol::Tcp, 24).unwrap();
    let mut tcp = smoltcp::wire::TcpPacket::new_unchecked(&mut bytes[offset..]);
    tcp.set_header_len(24);
    tcp.set_src_port(flow.source.port());
    tcp.set_dst_port(flow.destination.port());
    tcp.set_syn(true);
    tcp.set_window_len(4096);
    tcp.options_mut().copy_from_slice(&option);
    tcp.fill_checksum(&flow.source.ip().into(), &flow.destination.ip().into());
    bytes
}

#[tokio::test]
async fn refused_syn_cannot_leave_a_listener_to_claim_another_tuple() {
    for ipv6 in [false, true] {
        let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
        let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
        let mut forwarder = test_forwarder(Arc::new(Authority::default()));
        // Zero MSS is wire-valid and even TcpRepr-valid, but socket-tcp refuses it.
        let invalid = option_syn(flow, [2, 4, 0, 0]);
        assert!(packet::parse(&invalid).is_ok());
        forwarder.ingest(&invalid);
        until(&mut forwarder, |f| f.pending.is_empty()).await;
        let (rejected, _) = listener.accept().await.unwrap();
        let next_flow = Flow {
            source: std::net::SocketAddr::new(flow.source.ip(), flow.source.port() + 1),
            ..flow
        };
        let mut app = App::new(next_flow);
        app.until(&mut forwarder, |app, _| app.socket().can_send())
            .await;
        let (correct, _) = listener.accept().await.unwrap();
        let nonce = b"only the second original tuple may reach this physical connection";
        app.socket().send_slice(nonce).unwrap();
        app.exchange(&mut forwarder);
        let mut bytes = [0; 128];
        let n = tokio::time::timeout(Duration::from_secs(1), read(&correct, &mut bytes))
            .await
            .unwrap();
        assert_eq!(&bytes[..n], nonce);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), read(&rejected, &mut bytes))
                .await
                .unwrap(),
            0
        );
        forwarder.close_all().await;
    }
}

#[tokio::test]
async fn invalid_syn_wire_representations_never_prepare() {
    for ipv6 in [false, true] {
        let authority = Arc::new(Authority::default());
        let mut forwarder = test_forwarder(authority.clone());
        let flow = flow(ipv6, Transport::Tcp);
        let zero_port = Flow {
            source: std::net::SocketAddr::new(flow.source.ip(), 0),
            ..flow
        };
        for bytes in [
            syn(zero_port),
            option_syn(flow, [2, 1, 0, 0]),
            tcp_packet(
                flow,
                TcpFlags {
                    syn: true,
                    fin: true,
                    ..TcpFlags::default()
                },
                b"",
            ),
        ] {
            assert!(packet::parse(&bytes).is_ok(), "wire-valid reproduction");
            forwarder.ingest(&bytes);
        }
        assert_eq!(authority.authorizations.load(Ordering::SeqCst), 0);
        assert_eq!(authority.preparations.load(Ordering::SeqCst), 0);
        assert_eq!(forwarder.stats().malformed, 3);
        assert!(!forwarder.has_output());
        forwarder.close_all().await;
    }
}

#[tokio::test]
async fn concurrent_tcp_tuples_at_one_destination_keep_physical_ownership() {
    for ipv6 in [false, true] {
        let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
        let first = target(listener.local_addr().unwrap(), Transport::Tcp);
        let second = Flow {
            source: std::net::SocketAddr::new(first.source.ip(), first.source.port() + 1),
            ..first
        };
        let mut forwarder = test_forwarder(Arc::new(Authority::default()));
        // Admit both held SYNs before either connect completes.
        let mut apps = [(first, App::new(first)), (second, App::new(second))];
        for (_, app) in &mut apps {
            app.stack.poll(forwarder.stack_now());
            while let Some(bytes) = app.stack.device.outgoing.pop_front() {
                forwarder.ingest(&bytes);
            }
        }
        until(&mut forwarder, |f| f.pending.is_empty()).await;
        let mut peers = Vec::new();
        for _ in 0..2 {
            peers.push(listener.accept().await.unwrap().0);
        }
        // Identify the physical connection by its original owner, independent
        // of HashMap iteration/connect completion/accept order.
        let peer_index = |f: &Forwarder<Authority>, flow| {
            peers
                .iter()
                .position(|p| p.peer_addr().unwrap() == f.tcp[&flow].physical.local_addr().unwrap())
                .unwrap()
        };
        let indices = [
            peer_index(&forwarder, first),
            peer_index(&forwarder, second),
        ];
        assert_ne!(indices[0], indices[1]);
        let nonces: [&[u8]; 2] = [
            b"first concurrent connection nonce",
            b"second concurrent connection nonce",
        ];
        let mut sent = [false; 2];
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                for (i, (_, app)) in apps.iter_mut().enumerate() {
                    if !sent[i] && app.socket().can_send() {
                        app.socket().send_slice(nonces[i]).unwrap();
                        sent[i] = true;
                    }
                    app.stack.poll(forwarder.stack_now());
                    while let Some(bytes) = app.stack.device.outgoing.pop_front() {
                        forwarder.ingest(&bytes);
                    }
                }
                forwarder.process();
                while let Some(bytes) = forwarder.next_output() {
                    let destination = packet::parse(&bytes).unwrap().flow.destination;
                    let (_, app) = apps
                        .iter_mut()
                        .find(|(flow, _)| flow.source == destination)
                        .unwrap();
                    assert!(app.stack.receive(&bytes, forwarder.stack_now()));
                }
                if sent.iter().all(|s| *s)
                    && forwarder.tcp.values().all(|e| {
                        !forwarder
                            .stack
                            .sockets
                            .get::<tcp::Socket<'_>>(e.handle)
                            .can_recv()
                    })
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for i in 0..2 {
            let mut actual = Vec::new();
            let mut buffer = [0; 128];
            while actual.len() < nonces[i].len() {
                let n = tokio::time::timeout(
                    Duration::from_secs(1),
                    read(&peers[indices[i]], &mut buffer),
                )
                .await
                .unwrap();
                assert!(n > 0);
                actual.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(actual, nonces[i]);
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(30),
                    read(&peers[indices[i]], &mut buffer)
                )
                .await
                .is_err(),
                "another tuple's bytes reached this peer"
            );
        }
        forwarder.close_all().await;
    }
}

#[cfg(unix)]
enum SinkCommand {
    Revalidate(tokio::sync::oneshot::Sender<()>),
    Stop,
}

#[cfg(unix)]
async fn sink_backpressure(revoke: bool, stop_while_blocked: bool) {
    let authority = Arc::new(Authority::default());
    let mut forwarder = test_forwarder(authority.clone());
    let peer = UdpSocket::bind(loopback(false)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    forwarder.ingest(&udp_packet(flow, b"request"));
    until(&mut forwarder, settled).await;
    let (_, address) = peer.recv_from(&mut [0; 128]).await.unwrap();
    let nonces: Vec<_> = (0..4)
        .map(|n| format!("blocked interface reply nonce {n}").into_bytes())
        .collect();
    for nonce in &nonces {
        peer.send_to(nonce, address).await.unwrap();
    }
    until(&mut forwarder, |f| f.output.len() == 4).await;

    // A real packet-oriented fake interface with actual kernel WouldBlock.
    let (sink, consumer) = tokio::net::UnixDatagram::pair().unwrap();
    sink.writable().await.unwrap();
    let filler = [0x7b; 1024];
    let mut filled = 0;
    loop {
        match sink.try_send(&filler) {
            Ok(n) => {
                assert_eq!(n, filler.len());
                filled += 1;
                assert!(filled < 4096);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("filling fake interface: {e}"),
        }
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(AtomicUsize::new(0));
    let (commands, mut receive) = tokio::sync::mpsc::channel(2);
    let (started, start) = tokio::sync::oneshot::channel();
    let task_attempts = attempts.clone();
    let task_events = events.clone();
    let owner = tokio::spawn(async move {
        let mut started = Some(started);
        loop {
            loop {
                match forwarder.write_output(|bytes| {
                    task_attempts.fetch_add(1, Ordering::SeqCst);
                    sink.try_send(bytes)
                }) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("interface write: {e}"),
                }
            }
            if let Some(started) = started.take() {
                started.send(()).unwrap();
            }
            let output = forwarder.has_output();
            tokio::select! {
                _ = forwarder.wait() => {},
                result = sink.writable(), if output => result.unwrap(),
                command = receive.recv() => match command.unwrap() {
                    SinkCommand::Revalidate(ack) => { forwarder.revalidate(); ack.send(()).unwrap(); },
                    SinkCommand::Stop => break,
                },
            }
            task_events.fetch_add(1, Ordering::SeqCst);
        }
        forwarder.close_all().await;
        forwarder.stats()
    });
    tokio::time::timeout(Duration::from_secs(1), start)
        .await
        .unwrap()
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(100), std::future::pending::<()>()).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "bounded attempts while blocked"
    );
    assert_eq!(
        events.load(Ordering::SeqCst),
        0,
        "no internal wake spin behind backlog"
    );
    let (ack, acknowledged) = tokio::sync::oneshot::channel();
    authority.revoked.store(revoke, Ordering::SeqCst);
    commands.send(SinkCommand::Revalidate(ack)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), acknowledged)
        .await
        .unwrap()
        .unwrap();
    if stop_while_blocked {
        // Do not drain even the filler until stop has joined the owner. This
        // proves cancellation responsiveness independently of future writability.
        commands.send(SinkCommand::Stop).await.unwrap();
        let stats = tokio::time::timeout(Duration::from_secs(1), owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.udp_flows, 0);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        let mut bytes = [0; 2048];
        for _ in 0..filled {
            let n = consumer.recv(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], filler);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), consumer.recv(&mut bytes))
                .await
                .is_err()
        );
        return;
    }
    let mut bytes = [0; 2048];
    for _ in 0..filled {
        let n = tokio::time::timeout(Duration::from_secs(1), consumer.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..n], filler);
    }
    if revoke {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), consumer.recv(&mut bytes))
                .await
                .is_err(),
            "revoked payload reached interface consumer"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "revocation must discard before sink callback"
        );
    } else {
        for nonce in nonces {
            let n = tokio::time::timeout(Duration::from_secs(1), consumer.recv(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(packet::parse(&bytes[..n]).unwrap().payload, nonce);
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 6); // initial block, revalidation block, four writes
    }
    commands.send(SinkCommand::Stop).await.unwrap();
    let stats = tokio::time::timeout(Duration::from_secs(1), owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stats.udp_flows, 0);
    assert_eq!(stats.stale_reply, if revoke { 4 } else { 0 });
}

#[cfg(unix)]
#[tokio::test]
async fn blocked_sink_rechecks_grants_before_writable_retry() {
    sink_backpressure(true, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn blocked_sink_backlog_waits_then_delivers_promptly_and_stops() {
    sink_backpressure(false, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn blocked_sink_stop_is_responsive_before_writability() {
    sink_backpressure(false, true).await;
}
