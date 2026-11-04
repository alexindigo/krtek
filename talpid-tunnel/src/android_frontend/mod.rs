//! Single native owner of a packet-oriented Android capture descriptor.
//!
//! Announcements are immutable inputs. Authority changes affect delivery, never
//! interface ownership. The forwarder retains all output grants across backpressure.

#[cfg(target_os = "android")]
mod android;
mod fd_name;
pub use fd_name::interface_name;
mod config;
mod observation;
pub use config::{CaptureConfig, CaptureDisposition};
use observation::Observation;

use crate::packet_attachment::AttachmentReply;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use talpid_lan_forwarder::{Forwarder, LocalAuthority};
use talpid_types::capture_network::{CaptureExpectation, CaptureNetworkFeed};
use talpid_types::relay_flow::{RelayAttempt, RelayWriteOutcome};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::{oneshot, watch},
    task::JoinHandle,
};

pub trait FrontendPlatform: Send + Sync + 'static {
    fn open(&self, generation: i64, config: &CaptureConfig) -> io::Result<OwnedFd>;
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
    fn closed(&self) -> io::Result<()>;
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
    release_pending: Arc<AtomicBool>,
}

impl FrontendOwner {
    /// Obtain ownership before awaiting `ready`. Keep this handle through startup
    /// errors and cancellation, then join `stop` before any replacement or Connect.
    pub fn start<A: LocalAuthority>(
        platform: Arc<dyn FrontendPlatform>,
        config: CaptureConfig,
        mut forwarder: Forwarder<A>,
        revalidate: watch::Receiver<u64>,
    ) -> io::Result<Self> {
        let mut observation = match &config {
            CaptureConfig::Partial(routes) if routes.is_empty() => {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            CaptureConfig::Partial(_) => None,
            CaptureConfig::Secured { .. } => Some(Observation::begin(platform.as_ref(), &config)?),
        };
        let generation = match &observation {
            Some(observation) => observation.generation,
            None => i64::try_from(
                talpid_types::relay_flow::RelayCaptureGeneration::fresh()
                    .map_err(|error| io::Error::other(format!("{error:?}")))?
                    .get(),
            )
            .map_err(io::Error::other)?,
        };
        let (stop, stopped) = oneshot::channel();
        let (state_tx, state) = watch::channel(FrontendState::Running);
        let (started, ready) = oneshot::channel();
        // Once opening starts a failed JNI acknowledgement can still owe release.
        // Keep the obligation even when no descriptor was returned to Rust.
        let release_pending = Arc::new(AtomicBool::new(true));
        let pending = release_pending.clone();
        let task_platform = platform.clone();
        let task = tokio::spawn(async move {
            // The task owns opening, including when readiness is cancelled. Blocking
            // platform work is always joined before the stop acknowledgement.
            let opener = task_platform.clone();
            let open_config = config.clone();
            let opened = tokio::task::spawn_blocking(move || {
                let fd = opener.open(generation, &open_config);
                let bound = match &fd {
                    Ok(fd) => match &mut observation {
                        Some(observation) => {
                            observation.bind(opener.as_ref(), &open_config, fd.as_fd())
                        }
                        None => Ok(()),
                    },
                    Err(_) => Ok(()),
                };
                (fd, bound, observation)
            })
            .await;
            let (fd, mut terminal, observation) = match opened {
                Ok((Ok(fd), bound, observation)) => {
                    let result = run(
                        fd,
                        &mut forwarder,
                        revalidate,
                        stopped,
                        started,
                        (&config, observation.as_ref()),
                        bound,
                    )
                    .await;
                    (Some(result.0), result.1, observation)
                }
                result => {
                    let (error, observation) = match result {
                        Ok((Err(error), _, observation)) => (error, observation),
                        Err(error) => (io::Error::other(error), None),
                        Ok((Ok(_), _, _)) => unreachable!(),
                    };
                    let _ = started.send(Err(error));
                    (None, FrontendState::Failed, observation)
                }
            };
            if let Some(observation) = &observation {
                observation.retire();
            }
            forwarder.close_all().await;
            drop(fd);
            let released = task_platform.closed();
            if released.is_ok() {
                pending.store(false, Ordering::Release);
            } else {
                terminal = FrontendState::Failed;
            }
            state_tx.send_replace(terminal);
            released
        });
        Ok(Self {
            stop: Some(stop),
            task: Some(task),
            ready: Some(ready),
            state,
            platform,
            release_pending,
        })
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
        if self.release_pending.load(Ordering::Acquire) {
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
        if self.release_pending.load(Ordering::Acquire) {
            self.platform.closed()?;
            self.release_pending.store(false, Ordering::Release);
        }
        Ok(())
    }
}

impl Drop for FrontendOwner {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

// Keep the descriptor outside the reactor wrapper until shutdown has joined all
// physical work. Even an invalid/nonblocking-check failure follows close-before-hook.
async fn run<A: LocalAuthority>(
    fd: OwnedFd,
    forwarder: &mut Forwarder<A>,
    revalidate: watch::Receiver<u64>,
    mut stop: oneshot::Receiver<()>,
    started: oneshot::Sender<io::Result<()>>,
    session: (&CaptureConfig, Option<&Observation>),
    bound: io::Result<()>,
) -> (OwnedFd, FrontendState) {
    let (config, observation) = session;
    if let Err(error) = bound {
        let _ = started.send(Err(error));
        return (fd, FrontendState::Failed);
    }
    let flags = fcntl(&fd, FcntlArg::F_GETFL).map(OFlag::from_bits_retain);
    if !matches!(flags, Ok(flags) if flags.contains(OFlag::O_NONBLOCK)) {
        let _ = started.send(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Frontend descriptor is not nonblocking",
        )));
        return (fd, FrontendState::Failed);
    }
    // Borrow rather than move the fd: an AsyncFd registration error must not
    // close it before close_all has joined the physical preparations.
    let terminal = match AsyncFd::new(fd.as_fd()) {
        Ok(capture) => {
            // Install the reactor and reserve read progress before issuing a
            // broker receipt that a transport could use immediately.
            match forwarder.read_buffer() {
                Ok(packet) => {
                    let readiness = match observation {
                        Some(observation) => {
                            let mut updates = observation.updates.clone();
                            observation.wait_ready(&mut updates, &mut stop).await
                        }
                        None => Ok(()),
                    };
                    match readiness {
                        Ok(()) => {
                            let _ = started.send(Ok(()));
                            drive(
                                &capture,
                                forwarder,
                                revalidate,
                                stop,
                                observation.map(|observation| (config, observation)),
                                packet,
                            )
                            .await
                        }
                        Err(error) => {
                            let stopped = error.kind() == io::ErrorKind::Interrupted;
                            let _ = started.send(Err(error));
                            if stopped {
                                FrontendState::Stopped
                            } else {
                                FrontendState::Failed
                            }
                        }
                    }
                }
                Err(_) => {
                    let _ = started.send(Err(io::Error::other("Capture read storage unavailable")));
                    FrontendState::Failed
                }
            }
        }
        Err(error) => {
            let _ = started.send(Err(error));
            FrontendState::Failed
        }
    };
    (fd, terminal)
}

async fn drive<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
    mut revalidate: watch::Receiver<u64>,
    mut stop: oneshot::Receiver<()>,
    session: Option<(&CaptureConfig, &Observation)>,
    mut packet: talpid_types::relay_flow::RelayBuffer,
) -> FrontendState {
    let mut updates_open = true;
    let mut observation_updates = session.map(|(_, o)| o.updates.clone());
    let mut broker_updates = session.and_then(|(c, _)| match c {
        CaptureConfig::Secured { broker, .. } => Some(broker.changes()),
        _ => None,
    });
    let lease = session.and_then(|(_, o)| o.lease.as_deref());
    let mut reply: Option<AttachmentReply> = None;
    let mut local_attempt: Option<RelayAttempt> = None;
    let mut raw_first = false;
    loop {
        if session.is_some_and(|(_, observation)| !observation.current()) {
            return FrontendState::Failed;
        }
        if local_attempt
            .as_ref()
            .is_some_and(|attempt| !attempt.current())
        {
            return FrontendState::Failed;
        }
        if local_attempt.is_none() {
            local_attempt = lease.and_then(|lease| lease.ordinary_attempt());
        }
        let wants_write = (forwarder.has_output() && (lease.is_none() || local_attempt.is_some()))
            || reply.is_some();
        tokio::select! {
            _ = &mut stop => return FrontendState::Stopped,
            _ = async { match &mut observation_updates { Some(updates) => { let _ = updates.changed().await; }, None => std::future::pending().await } } => {},
            _ = async { match &mut broker_updates { Some(updates) => { let _ = updates.changed().await; }, None => std::future::pending().await } } => { forwarder.revalidate(); },
            result = async { match lease { Some(lease) => lease.reply().await, None => std::future::pending().await } }, if reply.is_none() => {
                match result { Ok(packet) => reply = Some(packet), Err(_) => return FrontendState::Failed }
            },
            result = revalidate.changed(), if updates_open => {
                if result.is_ok() { forwarder.revalidate(); }
                else { updates_open = false; }
            }
            result = capture.readable() => {
                let Ok(mut ready) = result else { return FrontendState::Failed; };
                // A continuously readable interface cannot monopolize stop or
                // authority updates. Readiness is retained when this allowance ends.
                for _ in 0..64 {
                    match ready.try_io(|fd| nix::unistd::read(fd.get_ref(), &mut packet).map_err(io::Error::from)) {
                        Ok(Ok(0)) => return FrontendState::Failed,
                        Ok(Ok(len)) => {
                            if local_attempt.is_none() { local_attempt = lease.and_then(|lease| lease.ordinary_attempt()); }
                            ingest(forwarder, &packet[..len], session, local_attempt.as_ref());
                        },
                        Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                        Ok(Err(_)) => return FrontendState::Failed,
                    }
                }
            }
            _ = forwarder.wait() => {}
            ready = capture.writable(), if wants_write => {
                if ready.is_err() { return FrontendState::Failed; }
            }
        }
        if session.is_some_and(|(_, observation)| !observation.current()) {
            return FrontendState::Failed;
        }
        if local_attempt.is_none() {
            local_attempt = lease.and_then(|lease| lease.ordinary_attempt());
        }
        forwarder.process();
        // Rotate priority after actual progress. Blocked/spurious wakes cannot
        // reset the next class; every owned pending class gets one checked write.
        let output = match session {
            Some((_, observation)) => drain_fair(
                capture,
                forwarder,
                observation,
                local_attempt.as_ref(),
                &mut reply,
                &mut raw_first,
            ),
            None => drain_output(capture, forwarder),
        };
        if output.is_err() {
            return FrontendState::Failed;
        }
    }
}

fn drain_checked_local<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
    attempt: Option<&RelayAttempt>,
) -> io::Result<bool> {
    let write = |bytes: &[u8]| {
        capture.try_io(Interest::WRITABLE, |fd| {
            nix::unistd::write(fd, bytes).map_err(io::Error::from)
        })
    };
    match forwarder.write_output(|bytes| match attempt {
        Some(attempt) => attempt
            .with_current(|| write(bytes))
            .map_err(|_| io::Error::other("Capture attempt retired"))?,
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
    attempt: Option<&RelayAttempt>,
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
            // Local is paused until the transport's authenticated readiness.
            if !attempt.is_some_and(RelayAttempt::current) {
                return;
            }
            match ip.destination().map(|ip| disposition(ip)) {
                Some(CaptureDisposition::Local) => forwarder.ingest(bytes),
                Some(CaptureDisposition::Relay) => {
                    let _ = observation
                        .lease
                        .as_ref()
                        .expect("managed lease")
                        .try_send(bytes);
                }
                _ => {}
            }
        }
    }
}

fn drain_reply(
    capture: &AsyncFd<BorrowedFd<'_>>,
    reply: &mut Option<AttachmentReply>,
) -> io::Result<bool> {
    let Some(packet) = reply.as_mut() else {
        return Ok(false);
    };
    match packet.write(|bytes| {
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
    local_attempt: Option<&RelayAttempt>,
    reply: &mut Option<AttachmentReply>,
    raw_first: &mut bool,
) -> io::Result<()> {
    for raw in if *raw_first {
        [true, false]
    } else {
        [false, true]
    } {
        let written = if raw {
            drain_reply(capture, reply)?
        } else {
            match local_attempt {
                None => Ok(false),
                Some(attempt) => observation
                    .checked(|| drain_checked_local(capture, forwarder, Some(attempt)))
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
