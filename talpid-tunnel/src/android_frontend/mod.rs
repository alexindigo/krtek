//! Single native owner of a packet-oriented Android capture descriptor.
//!
//! Announcements are immutable inputs. Authority changes affect delivery, never
//! interface ownership. The forwarder retains all output grants across backpressure.

#[cfg(target_os = "android")]
mod android;

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use talpid_lan_forwarder::{Forwarder, LocalAuthority, packet::MAX_PACKET_SIZE};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::{oneshot, watch},
    task::JoinHandle,
};

pub trait FrontendPlatform: Send + Sync + 'static {
    fn open(&self, routes: &[String]) -> io::Result<OwnedFd>;
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
        routes: Vec<String>,
        mut forwarder: Forwarder<A>,
        revalidate: watch::Receiver<u64>,
    ) -> io::Result<Self> {
        if routes.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let (stop, stopped) = oneshot::channel();
        let (state_tx, state) = watch::channel(FrontendState::Running);
        let (started, ready) = oneshot::channel();
        let release_pending = Arc::new(AtomicBool::new(false));
        let pending = release_pending.clone();
        let task_platform = platform.clone();
        let task = tokio::spawn(async move {
            // The task owns opening, including when readiness is cancelled. Blocking
            // platform work is always joined before the stop acknowledgement.
            let opener = task_platform.clone();
            let opened = tokio::task::spawn_blocking(move || opener.open(&routes)).await;
            let mut released = Ok(());
            let terminal = match opened {
                Ok(Ok(fd)) => {
                    pending.store(true, Ordering::Release);
                    let result = run(fd, &mut forwarder, revalidate, stopped, started).await;
                    forwarder.close_all().await;
                    // run returns its descriptor on every exit, after loop teardown.
                    let (fd, terminal) = result;
                    drop(fd);
                    released = task_platform.closed();
                    if released.is_ok() {
                        pending.store(false, Ordering::Release);
                        terminal
                    } else {
                        FrontendState::Failed
                    }
                }
                result => {
                    let error = match result {
                        Ok(Err(error)) => error,
                        Err(error) => io::Error::other(error),
                        Ok(Ok(_)) => unreachable!(),
                    };
                    let _ = started.send(Err(error));
                    forwarder.close_all().await;
                    FrontendState::Failed
                }
            };
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
    stop: oneshot::Receiver<()>,
    started: oneshot::Sender<io::Result<()>>,
) -> (OwnedFd, FrontendState) {
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
            let _ = started.send(Ok(()));
            drive(&capture, forwarder, revalidate, stop).await
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
) -> FrontendState {
    let mut packet = vec![0; MAX_PACKET_SIZE];
    let mut updates_open = true;
    loop {
        let wants_write = forwarder.has_output();
        tokio::select! {
            _ = &mut stop => return FrontendState::Stopped,
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
                        Ok(Ok(len)) => forwarder.ingest(&packet[..len]),
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
        forwarder.process();
        if drain_output(capture, forwarder).is_err() {
            return FrontendState::Failed;
        }
    }
}

fn drain_output<A: LocalAuthority>(
    capture: &AsyncFd<BorrowedFd<'_>>,
    forwarder: &mut Forwarder<A>,
) -> io::Result<()> {
    // No borrowed bytes leave this call. Every retry rechecks the grant,
    // and only an actual syscall WouldBlock clears writable readiness.
    for _ in 0..256 {
        match forwarder.write_output(|bytes| {
            capture.try_io(Interest::WRITABLE, |fd| {
                nix::unistd::write(fd, bytes).map_err(io::Error::from)
            })
        }) {
            Ok(true) => continue,
            Ok(false) => break,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
