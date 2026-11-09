//! Single native owner of a packet-oriented Android capture descriptor.
//!
//! Announcements are immutable inputs. Authority changes affect delivery, never
//! interface ownership. The forwarder retains all output grants across backpressure.

#[cfg(target_os = "android")]
mod android;
mod fd_name;
pub use fd_name::interface_name;
mod fd_format;
pub use fd_format::{CaptureFormat, UnsupportedCaptureFormat};
mod config;
mod observation;
mod owner;
pub use config::{CaptureConfig, CaptureDisposition, CaptureDropReason};
use observation::Observation;

use crate::packet_attachment::{AttachmentBroker, AttachmentReply};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{Arc, Mutex},
};
use talpid_lan_forwarder::{Forwarder, LocalAuthority};
use talpid_types::capture_network::{CaptureExpectation, CaptureNetworkFeed};
use talpid_types::relay_flow::{RelayCapture, RelaySink, RelayWriteOutcome};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

pub trait FrontendPlatform: Send + Sync + 'static {
    fn open(&self, generation: i64, config: &CaptureConfig) -> io::Result<OwnedFd>;
    /// Same owner, at most two epochs. Retention requires positive platform
    /// evidence that establish was never entered; an unknown JNI result is loss.
    fn handover(
        &self,
        predecessor: i64,
        generation: i64,
        config: &CaptureConfig,
    ) -> CaptureHandover;
    fn capture_format(&self, fd: BorrowedFd<'_>) -> io::Result<CaptureFormat> {
        fd_format::capture_format(fd)
    }
    fn capture_feed(&self) -> Arc<CaptureNetworkFeed>;
    fn expectation(
        &self,
        config: &CaptureConfig,
        interface: String,
    ) -> io::Result<CaptureExpectation>;
    fn interface_name(&self, fd: BorrowedFd<'_>) -> io::Result<String> {
        interface_name(fd)
    }
    fn bind(&self, generation: i64, interface: &str) -> io::Result<bool>;
    /// Release platform ownership after descriptor closure. Must be idempotent:
    /// an error may mean the call never arrived, or that its acknowledgement failed.
    fn closed(&self, generation: i64) -> io::Result<()>;
}

pub struct CaptureHandover {
    pub descriptor: io::Result<OwnedFd>,
    pub predecessor_retained: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontendState {
    Running,
    Stopped,
    Failed,
}

pub struct FrontendOwner {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
    ready: Option<oneshot::Receiver<io::Result<()>>>,
    state: watch::Receiver<FrontendState>,
    platform: Arc<dyn FrontendPlatform>,
    releases: Arc<owner::Releases>,
    commands: mpsc::Sender<owner::Command>,
}

impl FrontendOwner {
    /// Obtain ownership before awaiting `ready`. Keep this handle through startup
    /// errors and cancellation, then join `stop` before any replacement or Connect.
    pub fn start<A: LocalAuthority>(
        platform: Arc<dyn FrontendPlatform>,
        config: CaptureConfig,
        forwarder: Forwarder<A>,
        revalidate: watch::Receiver<u64>,
        broker: AttachmentBroker,
    ) -> io::Result<Self> {
        owner::start(platform, config, forwarder, revalidate, broker)
    }

    /// Enqueue one configuration change; `ready` awaits this exact epoch. The
    /// actor remains responsive to Stop and joins platform work on cancellation.
    pub fn handover(&mut self, config: CaptureConfig) -> io::Result<()> {
        self.command(|ready| owner::Command::Handover(config, ready))
    }

    pub fn retry_handover_release(&mut self) -> io::Result<()> {
        self.command(owner::Command::RetryRelease)
    }

    fn command(
        &mut self,
        make: impl FnOnce(oneshot::Sender<io::Result<()>>) -> owner::Command,
    ) -> io::Result<()> {
        if self.ready.is_some() || self.stop.is_none() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let (sender, receiver) = oneshot::channel();
        self.commands
            .try_send(make(sender))
            .map_err(io::Error::other)?;
        self.ready = Some(receiver);
        Ok(())
    }

    /// Cancellation-safe. An error does not consume the cleanup/release owner.
    pub async fn ready(&mut self) -> io::Result<()> {
        let ready = self
            .ready
            .as_mut()
            .ok_or_else(|| io::Error::other("Readiness already received"))?;
        let result = ready.await.map_err(io::Error::other)?;
        self.ready.take();
        result
    }

    pub fn state(&self) -> watch::Receiver<FrontendState> {
        self.state.clone()
    }

    pub fn release_failed(&self) -> bool {
        self.releases.failed()
            || self.releases.pending() && self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Join physical cleanup and the initial platform release attempt. Cancellation
    /// and errors retain this owner. Release errors require explicit `retry_release`.
    pub async fn stop(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            let result = task.await;
            self.task.take();
            result.map_err(io::Error::other)??;
        }
        if self.releases.pending() {
            return Err(io::Error::other("Frontend platform release is pending"));
        }
        Ok(())
    }

    /// Explicit external-event retry after `stop` has joined. A successful retry
    /// cannot call the platform again, including after a replacement has opened.
    /// `Failed` stays historical; successful `stop` is the handoff acknowledgement.
    pub fn retry_release(&mut self) -> io::Result<()> {
        if self.task.is_some() {
            return Err(io::Error::other("Join frontend before retrying release"));
        }
        self.releases.retry(self.platform.as_ref())
    }
}

impl Drop for FrontendOwner {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[cfg(test)]
async fn drive<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
    mut revalidate: watch::Receiver<u64>,
    mut stop: oneshot::Receiver<()>,
    session: Option<(&CaptureConfig, &Observation)>,
    packet: talpid_types::relay_flow::RelayBuffer,
) -> FrontendState {
    let (_sender, mut commands) = mpsc::channel(1);
    let mut buffers = DriveBuffers {
        packet,
        reply: None,
        raw_first: false,
    };
    match drive_epoch(
        capture,
        forwarder,
        (&mut revalidate, &mut stop),
        session,
        &mut buffers,
        &mut commands,
        &mut None,
    )
    .await
    {
        owner::Event::Terminal(state) => state,
        _ => unreachable!("no owner commands in standalone reactor"),
    }
}

struct DriveBuffers {
    packet: talpid_types::relay_flow::RelayBuffer,
    reply: Option<AttachmentReply>,
    raw_first: bool,
}

async fn drive_epoch<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
    signals: (&mut watch::Receiver<u64>, &mut oneshot::Receiver<()>),
    session: Option<(&CaptureConfig, &Observation)>,
    buffers: &mut DriveBuffers,
    commands: &mut mpsc::Receiver<owner::Command>,
    cleanup: &mut Option<JoinHandle<io::Result<()>>>,
) -> owner::Event {
    let (revalidate, stop) = signals;
    let DriveBuffers {
        packet,
        reply,
        raw_first,
    } = buffers;
    let mut updates_open = true;
    let mut observation_updates = session.and_then(|(_, o)| o.updates.clone());
    let mut broker_updates = session.and_then(|(c, _)| match c {
        CaptureConfig::Secured { broker, .. } => Some(broker.changes()),
        _ => None,
    });
    let lease = session.map(|(_, o)| o.lease.as_ref());
    let local_capture = lease.and_then(|lease| lease.capability());
    loop {
        if session.is_some_and(|(_, observation)| !observation.current()) {
            return owner::Event::Terminal(FrontendState::Failed);
        }
        let wants_write = forwarder.has_output() || reply.is_some();
        tokio::select! {
            _ = &mut *stop => return owner::Event::Terminal(FrontendState::Stopped),
            command = commands.recv() => match command {
                Some(command) => return owner::Event::Command(command),
                None => return owner::Event::Terminal(FrontendState::Stopped),
            },
            result = async { match cleanup { Some(task) => task.await, None => std::future::pending().await } } => {
                return owner::Event::Released(result.map_err(io::Error::other).and_then(|result| result));
            },
            _ = async { match &mut observation_updates { Some(updates) => { let _ = updates.changed().await; }, None => std::future::pending().await } } => {},
            _ = async { match &mut broker_updates { Some(updates) => { let _ = updates.changed().await; }, None => std::future::pending().await } } => { forwarder.revalidate(); },
            result = async { match lease { Some(lease) => lease.reply().await, None => std::future::pending().await } }, if reply.is_none() => {
                match result { Ok(packet) => *reply = Some(packet), Err(_) => return owner::Event::Terminal(FrontendState::Failed) }
            },
            result = revalidate.changed(), if updates_open => {
                if result.is_ok() { forwarder.revalidate(); }
                else { updates_open = false; }
            }
            result = capture.readable() => {
                let Ok(mut ready) = result else { return owner::Event::Terminal(FrontendState::Failed); };
                // A continuously readable interface cannot monopolize stop or
                // authority updates. Readiness is retained when this allowance ends.
                for _ in 0..64 {
                    match ready.try_io(|fd| nix::unistd::read(fd.get_ref(), packet).map_err(io::Error::from)) {
                        Ok(Ok(0)) => return owner::Event::Terminal(FrontendState::Failed),
                        Ok(Ok(len)) => {
                            ingest(forwarder, &packet[..len], session);
                        },
                        Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                        Ok(Err(_)) => return owner::Event::Terminal(FrontendState::Failed),
                    }
                }
            }
            _ = forwarder.wait() => {}
            ready = capture.writable(), if wants_write => {
                if ready.is_err() { return owner::Event::Terminal(FrontendState::Failed); }
            }
        }
        if session.is_some_and(|(_, observation)| !observation.current()) {
            return owner::Event::Terminal(FrontendState::Failed);
        }
        forwarder.process();
        // Rotate priority after actual progress. Blocked/spurious wakes cannot
        // reset the next class; every owned pending class gets one checked write.
        let output = match session {
            Some((_, observation)) => drain_fair(
                capture,
                forwarder,
                observation,
                local_capture.as_ref(),
                reply,
                raw_first,
            ),
            None => drain_output(capture, forwarder),
        };
        if output.is_err() {
            return owner::Event::Terminal(FrontendState::Failed);
        }
    }
}

fn drain_checked_local<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
    session: Option<(&RelayCapture, &RelaySink)>,
) -> io::Result<bool> {
    let write = |bytes: &[u8]| {
        capture.try_io(Interest::WRITABLE, |fd| {
            nix::unistd::write(fd, bytes).map_err(io::Error::from)
        })
    };
    match forwarder.write_output(|bytes| match session {
        Some((session, sink)) => session
            .with_sink(sink, || write(bytes))
            .map_err(|_| io::Error::other("Capture session retired"))?,
        None => write(bytes),
    }) {
        Ok(written) => Ok(written),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

fn ingest<A: LocalAuthority>(
    forwarder: &mut Forwarder<A>,
    bytes: &[u8],
    session: Option<(&CaptureConfig, &Observation)>,
) {
    let Some((config, observation)) = session else {
        forwarder.ingest(bytes);
        return;
    };
    let Ok(ip) = talpid_netstack::raw_packet::inspect(bytes) else {
        return;
    };
    if !ip
        .source()
        .is_some_and(|ip| observation.sources.contains(ip))
    {
        return;
    }
    match config {
        CaptureConfig::Partial(_) => forwarder.ingest(bytes),
        CaptureConfig::Secured { disposition, .. } => {
            match ip.destination().map(|ip| disposition(ip)) {
                Some(CaptureDisposition::Local) => forwarder.ingest(bytes),
                Some(CaptureDisposition::Tunnel(target)) => {
                    let _ = observation.lease.try_send_to(target, bytes);
                }
                _ => {}
            }
        }
    }
}

fn drain_reply(
    capture: &AsyncFd<BorrowedFd<'_>>,
    sink: &RelaySink,
    reply: &mut Option<AttachmentReply>,
) -> io::Result<bool> {
    let Some(packet) = reply.as_mut() else {
        return Ok(false);
    };
    match packet.write_to(sink, |bytes| {
        capture.try_io(Interest::WRITABLE, |fd| {
            nix::unistd::write(fd, bytes).map_err(io::Error::from)
        })
    }) {
        RelayWriteOutcome::Written => {
            reply.take();
            Ok(true)
        }
        RelayWriteOutcome::Stale => {
            reply.take();
            Ok(false)
        }
        RelayWriteOutcome::Retry => Ok(false),
        RelayWriteOutcome::Fatal(error) => Err(error),
    }
}

fn drain_fair<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
    observation: &Observation,
    local_capture: Option<&RelayCapture>,
    reply: &mut Option<AttachmentReply>,
    raw_first: &mut bool,
) -> io::Result<()> {
    let sink = observation
        .sink()
        .ok_or_else(|| io::Error::other("Capture sink unavailable"))?;
    for raw in if *raw_first {
        [true, false]
    } else {
        [false, true]
    } {
        let written = if raw {
            observation
                .checked(|| drain_reply(capture, &sink, reply))
                .ok_or_else(|| io::Error::other("Capture lost"))??
        } else {
            match local_capture {
                None => Ok(false),
                Some(session) => observation
                    .checked(|| drain_checked_local(capture, forwarder, Some((session, &sink))))
                    .unwrap_or_else(|| Err(io::Error::other("Capture lost"))),
            }?
        };
        if written {
            *raw_first = !raw;
        }
    }
    Ok(())
}

fn drain_output<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
) -> io::Result<()> {
    for _ in 0..256 {
        if !drain_checked_local(capture, forwarder, None)? {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
