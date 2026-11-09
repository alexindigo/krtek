//! One actor owns the logical lease, Local engine and at most two fd epochs.
use super::*;
use crate::packet_attachment::{CaptureEpochChange, CaptureLease};
use observation::failure;

pub(super) enum Command {
    Handover(CaptureConfig, oneshot::Sender<io::Result<()>>),
    RetryRelease(oneshot::Sender<io::Result<()>>),
}
pub(super) enum Event {
    Terminal(FrontendState),
    Command(Command),
    Released(io::Result<()>),
}

/// Fixed storage, including lost JNI acknowledgements. Never hold this lock
/// across platform work. Only the actor releases while live; external retry is
/// allowed only after joining it.
#[derive(Clone, Copy)]
struct ReleaseRecord {
    generation: i64,
    failed: bool,
}
#[derive(Default)]
pub(super) struct Releases(Mutex<[Option<ReleaseRecord>; 2]>);
impl Releases {
    fn add(&self, generation: i64) -> io::Result<()> {
        let mut slots = self.0.lock().expect("capture releases");
        let slot = slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| io::Error::other("Predecessor release is pending"))?;
        *slot = Some(ReleaseRecord {
            generation,
            failed: false,
        });
        Ok(())
    }
    fn remove(&self, generation: i64) {
        for slot in self.0.lock().expect("capture releases").iter_mut() {
            if slot.is_some_and(|record| record.generation == generation) {
                *slot = None;
            }
        }
    }
    fn generations(&self) -> [Option<i64>; 2] {
        self.0
            .lock()
            .expect("capture releases")
            .map(|slot| slot.map(|record| record.generation))
    }
    fn fail(&self, generation: i64) {
        for record in self
            .0
            .lock()
            .expect("capture releases")
            .iter_mut()
            .flatten()
        {
            if record.generation == generation {
                record.failed = true;
            }
        }
    }
    pub fn failed(&self) -> bool {
        self.0
            .lock()
            .expect("capture releases")
            .iter()
            .flatten()
            .any(|record| record.failed)
    }
    pub fn pending(&self) -> bool {
        self.generations().iter().any(Option::is_some)
    }
    pub fn retry(&self, platform: &dyn FrontendPlatform) -> io::Result<()> {
        for generation in self.generations().into_iter().flatten() {
            if let Err(error) = platform.closed(generation) {
                self.fail(generation);
                return Err(error);
            }
            self.remove(generation);
        }
        Ok(())
    }
}

struct Epoch {
    config: CaptureConfig,
    observation: Observation,
    fd: Option<OwnedFd>,
}
struct Retained {
    change: CaptureEpochChange,
    old: Option<Epoch>,
    generation: i64,
    retry: Option<oneshot::Sender<io::Result<()>>>,
    retry_after_join: bool,
}

pub(super) fn start<A: LocalAuthority>(
    platform: Arc<dyn FrontendPlatform>,
    config: CaptureConfig,
    forwarder: Forwarder<A>,
    revalidate: watch::Receiver<u64>,
    broker: AttachmentBroker,
) -> io::Result<FrontendOwner> {
    validate(&config, &broker)?;
    let lease = Arc::new(broker.open_capture(config.request()).map_err(failure)?);
    let observation = Observation::begin(platform.as_ref(), &config, lease.clone(), None, None)?;
    let epoch = Epoch {
        config,
        observation,
        fd: None,
    };
    let (stop, stopped) = oneshot::channel();
    let (started, ready) = oneshot::channel();
    let (state_tx, state) = watch::channel(FrontendState::Running);
    let (commands, receiver) = mpsc::channel(1);
    let releases = Arc::new(Releases::default());
    let task = tokio::spawn(run(Actor {
        platform: platform.clone(),
        broker,
        lease,
        initial: epoch,
        forwarder,
        revalidate,
        stop: stopped,
        started,
        commands: receiver,
        state: state_tx,
        releases: releases.clone(),
    }));
    Ok(FrontendOwner {
        stop: Some(stop),
        task: Some(task),
        ready: Some(ready),
        state,
        platform,
        releases,
        commands,
    })
}

fn validate(config: &CaptureConfig, broker: &AttachmentBroker) -> io::Result<()> {
    match config {
        CaptureConfig::Partial(routes) if routes.is_empty() => {
            Err(io::ErrorKind::InvalidInput.into())
        }
        CaptureConfig::Secured {
            broker: selected, ..
        } if !broker.same_broker(selected) => Err(io::ErrorKind::InvalidInput.into()),
        _ => Ok(()),
    }
}

/// Blocking establish/bind is always joined, even if Stop/readiness is cancelled.
/// During it there is no predecessor reactor in the select and no sink selected.
async fn establish<A: LocalAuthority>(
    platform: Arc<dyn FrontendPlatform>,
    mut epoch: Epoch,
    predecessor: Option<i64>,
    forwarder: &mut Forwarder<A>,
    revalidate: &mut watch::Receiver<u64>,
    stop: &mut oneshot::Receiver<()>,
    cancelled: &mut bool,
) -> io::Result<(Epoch, io::Result<()>, bool)> {
    let mut task = tokio::task::spawn_blocking(move || {
        let generation = epoch.observation.generation;
        let (descriptor, retained) = match predecessor {
            Some(old) => {
                let result = platform.handover(old, generation, &epoch.config);
                (result.descriptor, result.predecessor_retained)
            }
            None => (platform.open(generation, &epoch.config), false),
        };
        let result = match descriptor {
            Ok(fd) => {
                epoch.fd = Some(fd);
                let fd = epoch.fd.as_ref().expect("adopted once");
                platform.capture_format(fd.as_fd()).and_then(|format| {
                    log::info!("capture-format generation={generation} representation=plain-ip flags={:#06x}", format.flags());
                    epoch.observation.bind(platform.as_ref(), &epoch.config, fd.as_fd(), format)
                })
            }
            Err(error) => Err(error),
        };
        (epoch, result, retained)
    });
    let mut updates_open = true;
    loop {
        tokio::select! {
            result = &mut task => return result.map_err(io::Error::other),
            _ = &mut *stop, if !*cancelled => { *cancelled = true; },
            result = revalidate.changed(), if updates_open => {
                updates_open = result.is_ok();
                forwarder.revalidate();
            },
            _ = forwarder.wait() => { forwarder.process(); },
        }
    }
}

fn reactor(epoch: &Epoch) -> io::Result<AsyncFd<BorrowedFd<'_>>> {
    let fd = epoch
        .fd
        .as_ref()
        .ok_or_else(|| io::Error::other("No capture descriptor"))?;
    let flags = fcntl(fd, FcntlArg::F_GETFL).map(OFlag::from_bits_retain)?;
    if !flags.contains(OFlag::O_NONBLOCK) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Frontend descriptor is not nonblocking",
        ));
    }
    AsyncFd::new(fd.as_fd())
}

async fn finish_epoch(
    platform: Arc<dyn FrontendPlatform>,
    releases: Arc<Releases>,
    epoch: Epoch,
) -> io::Result<()> {
    if let Some(request) = epoch.config.request() {
        request.wait_release().await;
    }
    let generation = epoch.observation.generation;
    epoch.observation.retire();
    drop(epoch); // reactor already joined; close the sole fd before platform finish
    release(platform, releases, generation).await
}
async fn release(
    platform: Arc<dyn FrontendPlatform>,
    releases: Arc<Releases>,
    generation: i64,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        if let Err(error) = platform.closed(generation) {
            releases.fail(generation);
            return Err(error);
        }
        releases.remove(generation);
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

struct Actor<A: LocalAuthority> {
    platform: Arc<dyn FrontendPlatform>,
    broker: AttachmentBroker,
    lease: Arc<CaptureLease>,
    initial: Epoch,
    forwarder: Forwarder<A>,
    revalidate: watch::Receiver<u64>,
    stop: oneshot::Receiver<()>,
    started: oneshot::Sender<io::Result<()>>,
    commands: mpsc::Receiver<Command>,
    state: watch::Sender<FrontendState>,
    releases: Arc<Releases>,
}

async fn run<A: LocalAuthority>(actor: Actor<A>) -> io::Result<()> {
    let Actor {
        platform,
        broker,
        lease,
        initial,
        mut forwarder,
        mut revalidate,
        mut stop,
        started,
        mut commands,
        state,
        releases,
    } = actor;
    releases.add(initial.observation.generation)?;
    let mut cancelled = false;
    let (mut epoch, mut bound, _) = establish(
        platform.clone(),
        initial,
        None,
        &mut forwarder,
        &mut revalidate,
        &mut stop,
        &mut cancelled,
    )
    .await?;
    let mut ready = Some(started);
    let mut retained: Option<Retained> = None;
    let mut cleanup = None;
    let mut buffers = forwarder.read_buffer().map(|packet| DriveBuffers {
        packet,
        reply: None,
        raw_first: false,
    });
    let mut terminal = loop {
        let event = {
            let capture = reactor(&epoch);
            if let Some(ready) = ready.take() {
                let result = if cancelled {
                    Err(io::ErrorKind::Interrupted.into())
                } else if bound.is_err() {
                    std::mem::replace(&mut bound, Ok(()))
                } else if let Err(error) = &capture {
                    Err(io::Error::new(error.kind(), error.to_string()))
                } else if buffers.is_err() {
                    Err(io::Error::other("Capture read storage unavailable"))
                } else {
                    let wait = epoch.observation.wait_ready(
                        &epoch.config,
                        retained.as_ref().map(|old| &old.change),
                        &mut stop,
                    );
                    tokio::pin!(wait);
                    let mut updates_open = true;
                    loop {
                        tokio::select! {
                            result = &mut wait => break result,
                            result = revalidate.changed(), if updates_open => {
                                updates_open = result.is_ok();
                                forwarder.revalidate();
                            },
                            _ = forwarder.wait() => {},
                        }
                    }
                };
                let failed = result.is_err();
                let stopped = result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::Interrupted);
                let _ = ready.send(result);
                if failed {
                    break if stopped {
                        FrontendState::Stopped
                    } else {
                        FrontendState::Failed
                    };
                }
                if let Some(old) = retained.as_mut().and_then(|old| old.old.take()) {
                    cleanup = Some(tokio::spawn(finish_epoch(
                        platform.clone(),
                        releases.clone(),
                        old,
                    )));
                }
            }
            let Ok(capture) = capture else {
                break FrontendState::Failed;
            };
            drive_epoch(
                &capture,
                &mut forwarder,
                (&mut revalidate, &mut stop),
                Some((&epoch.config, &epoch.observation)),
                buffers.as_mut().expect("reserved before readiness"),
                &mut commands,
                &mut cleanup,
            )
            .await
        }; // joins the predecessor reactor before any rebind/release
        match event {
            Event::Terminal(state) => break state,
            Event::Released(result) => {
                cleanup.take();
                let old = retained.as_mut().expect("cleanup transaction");
                let result = result.and_then(|()| old.change.finish().map_err(failure));
                let success = result.is_ok();
                // Failure publication can precede this completion event. An
                // explicit retry received in that window joins the exact old
                // task, then retries once; it cannot race into WouldBlock or
                // turn into an autonomous retry loop.
                if !success && old.retry_after_join {
                    old.retry_after_join = false;
                    cleanup = Some(tokio::spawn(release(
                        platform.clone(),
                        releases.clone(),
                        old.generation,
                    )));
                    continue;
                }
                if let Some(ack) = old.retry.take() {
                    let _ = ack.send(result);
                }
                if success {
                    retained.take();
                }
                state.send_replace(FrontendState::Running);
            }
            Event::Command(Command::RetryRelease(ack)) => {
                if cleanup.is_some() {
                    let old = retained.as_mut().expect("cleanup transaction");
                    old.retry = Some(ack);
                    old.retry_after_join = true;
                    continue;
                }
                if let Some(old) = &mut retained {
                    cleanup = Some(tokio::spawn(release(
                        platform.clone(),
                        releases.clone(),
                        old.generation,
                    )));
                    old.retry = Some(ack);
                } else {
                    // A pre-establish rollback may still owe exact successor cleanup.
                    let mut result = Ok(());
                    for generation in releases
                        .generations()
                        .into_iter()
                        .flatten()
                        .filter(|g| *g != epoch.observation.generation)
                    {
                        result = release(platform.clone(), releases.clone(), generation).await;
                        if result.is_err() {
                            break;
                        }
                    }
                    let _ = ack.send(result);
                }
            }
            Event::Command(Command::Handover(config, ack)) => {
                if retained.is_some() || releases.generations().iter().flatten().count() != 1 {
                    let _ = ack.send(Err(io::ErrorKind::WouldBlock.into()));
                    continue;
                }
                if let Err(error) = validate(&config, &broker) {
                    let _ = ack.send(Err(error));
                    continue;
                }
                let mut change =
                    match lease.begin_handover(config.request(), config.sources(), config.mtu()) {
                        Ok(change) => change,
                        Err(error) => {
                            let _ = ack.send(Err(failure(error)));
                            continue;
                        }
                    };
                let observation = match Observation::begin(
                    platform.as_ref(),
                    &config,
                    lease.clone(),
                    Some(&epoch.observation),
                    Some(&change),
                ) {
                    Ok(observation) => observation,
                    Err(error) => {
                        let rollback = change.rollback();
                        let _ = ack.send(Err(error));
                        if rollback.is_err() {
                            break FrontendState::Failed;
                        }
                        continue;
                    }
                };
                let generation = observation.generation;
                releases.add(generation)?;
                let next = Epoch {
                    config,
                    observation,
                    fd: None,
                };
                let (next, result, predecessor_retained) = establish(
                    platform.clone(),
                    next,
                    Some(epoch.observation.generation),
                    &mut forwarder,
                    &mut revalidate,
                    &mut stop,
                    &mut cancelled,
                )
                .await?;
                if result.is_err()
                    && predecessor_retained
                    && !cancelled
                    && epoch.observation.rollback_feed(&next.observation)
                    && change.rollback().is_ok()
                {
                    let released = finish_epoch(platform.clone(), releases.clone(), next).await;
                    let _ = ack.send(result.and(released));
                    continue;
                }
                let old_generation = epoch.observation.generation;
                let old = std::mem::replace(&mut epoch, next);
                retained = Some(Retained {
                    change,
                    old: Some(old),
                    generation: old_generation,
                    retry: None,
                    retry_after_join: false,
                });
                bound = result;
                ready = Some(ack);
            }
        }
    };
    // Actual loss/stop revokes the logical session, then joins all physical and
    // target work. A handover never enters this epilogue merely for old-fd loss.
    lease.retire();
    epoch.observation.retire();
    forwarder.close_all().await;
    if terminal == FrontendState::Failed {
        state.send_replace(terminal);
    }
    drop(buffers);
    let mut result = Ok(());
    if let Some(task) = cleanup {
        result = task.await.map_err(io::Error::other).and_then(|r| r);
    }
    if let Some(old) = retained.as_mut().and_then(|old| old.old.take()) {
        let released = finish_epoch(platform.clone(), releases.clone(), old).await;
        if released.is_err() {
            result = released;
        }
    }
    let released = finish_epoch(platform, releases.clone(), epoch).await;
    if released.is_err() {
        result = released;
    }
    if result.is_err() || releases.pending() {
        terminal = FrontendState::Failed;
    }
    state.send_replace(terminal);
    result
}
