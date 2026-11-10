use super::{CaptureConfig, CaptureFormat, FrontendPlatform};
use crate::packet_attachment::{CaptureEpochChange, CaptureLease};
use std::{
    io,
    os::fd::BorrowedFd,
    sync::{Arc, Mutex},
    time::Duration,
};
use talpid_types::{
    capture_network::{CaptureNetworkFeed, CaptureNetworkState, CaptureRoute},
    relay_flow::{RelaySink, RelaySources},
};
use tokio::sync::{oneshot, watch};

pub(super) fn failure(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

/// Epoch-only observation. The owner retains the logical lease across drops of
/// these records; an old observer can invalidate only its own feed generation.
pub(super) struct Observation {
    pub generation: i64,
    feed: Option<Arc<CaptureNetworkFeed>>,
    pub updates: Option<watch::Receiver<CaptureNetworkState>>,
    pub lease: Arc<CaptureLease>,
    pub sources: RelaySources,
    mtu: u16,
    requested_routes: Vec<CaptureRoute>,
    lifecycle: Mutex<Option<(i64, String, String)>>,
    format: Option<CaptureFormat>,
    interface: String,
    sink: Mutex<Option<RelaySink>>,
}

impl Observation {
    pub fn begin(
        platform: &dyn FrontendPlatform,
        config: &CaptureConfig,
        lease: Arc<CaptureLease>,
        predecessor: Option<&Observation>,
        change: Option<&CaptureEpochChange>,
    ) -> io::Result<Self> {
        let generation = i64::try_from(
            change.map_or_else(|| lease.generation(), CaptureEpochChange::generation),
        )
        .map_err(io::Error::other)?;
        let managed = config.secured_config().is_some();
        let feed = managed.then(|| platform.capture_feed());
        let updates = match predecessor.and_then(|old| old.feed.as_ref().map(|feed| (old, feed))) {
            Some((old, feed)) => feed
                .begin_handover(old.generation, managed.then_some(generation))
                .ok_or_else(|| io::Error::other("Capture observation handover unavailable"))?,
            None => match &feed {
                Some(feed) => Some(
                    feed.begin(generation)
                        .ok_or_else(|| io::Error::other("Capture observation unavailable"))?,
                ),
                None => None,
            },
        };
        Ok(Self {
            generation,
            feed,
            updates,
            lease,
            sources: config.sources(),
            mtu: config.mtu(),
            requested_routes: Vec::new(),
            lifecycle: Mutex::new(None),
            format: None,
            interface: String::new(),
            sink: Mutex::new(None),
        })
    }

    // Joined blocking work on the borrowed sole fd. Partial performs only native
    // queries and never asks for SDK, owner UID, routes or a managed observer.
    pub fn bind(
        &mut self,
        platform: &dyn FrontendPlatform,
        config: &CaptureConfig,
        fd: BorrowedFd<'_>,
        format: CaptureFormat,
    ) -> io::Result<()> {
        self.format = Some(format);
        self.interface = platform.interface_name(fd)?;
        if let Some(feed) = &self.feed {
            let expected = platform.expectation(config, self.interface.clone())?;
            if expected.addresses.len()
                != usize::from(self.sources.ipv4.is_some())
                    + usize::from(self.sources.ipv6.is_some())
                || expected
                    .addresses
                    .iter()
                    .any(|p| !self.sources.contains(p.address))
                || !feed.bind(self.generation, expected.clone())
                || !platform.bind(self.generation, &self.interface)?
            {
                return Err(io::Error::other("Capture interface binding failed"));
            }
            self.requested_routes = expected.routes;
        }
        Ok(())
    }

    pub async fn wait_ready(
        &self,
        config: &CaptureConfig,
        change: Option<&CaptureEpochChange>,
        stop: &mut oneshot::Receiver<()>,
    ) -> io::Result<()> {
        let mut updates = self.updates.clone();
        let mut broker_updates = self.lease.changes();
        let wait = async {
            loop {
                let snapshot = *broker_updates.borrow();
                if snapshot.closed || snapshot.capture_generation != Some(self.generation as u64) {
                    return Err(io::Error::other(
                        "Capture epoch retired before acknowledgement",
                    ));
                }
                if let CaptureConfig::Secured {
                    broker, request, ..
                } = config
                {
                    let snapshot = broker.snapshot();
                    if snapshot.capture_generation != Some(self.generation as u64)
                        || snapshot.request != Some(request.id())
                    {
                        return Err(io::Error::other("Capture request cancelled or replaced"));
                    }
                }
                match updates
                    .as_mut()
                    .map(|updates| updates.borrow_and_update().clone())
                {
                    None | Some(CaptureNetworkState::Ready(_)) => {
                        return self.acknowledge(config, change);
                    }
                    Some(CaptureNetworkState::Lost) => {
                        return Err(io::Error::other("Capture observation lost"));
                    }
                    Some(CaptureNetworkState::Pending) => {}
                }
                tokio::select! {
                    result = async { updates.as_mut().expect("managed updates").changed().await } => result.map_err(io::Error::other)?,
                    _ = broker_updates.changed() => {},
                }
            }
        };
        tokio::select! {
            _ = stop => Err(io::ErrorKind::Interrupted.into()),
            result = tokio::time::timeout(Duration::from_secs(15), wait) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Capture observation timed out"))?,
        }
    }

    fn acknowledge(
        &self,
        config: &CaptureConfig,
        change: Option<&CaptureEpochChange>,
    ) -> io::Result<()> {
        let bind = |handle| {
            let receipt = match change {
                Some(change) => {
                    change.bind_identity(&self.interface, handle, self.sources, self.mtu)
                }
                None => match handle {
                    Some(handle) => self.lease.bind_observed_identity(
                        &self.interface,
                        handle,
                        self.sources,
                        self.mtu,
                    ),
                    None => {
                        self.lease
                            .bind_partial_identity(&self.interface, self.sources, self.mtu)
                    }
                },
            }
            .map_err(failure)?;
            if let CaptureConfig::Secured {
                broker, request, ..
            } = config
            {
                broker.acknowledge(request, &receipt).map_err(failure)?;
            }
            *self.sink.lock().expect("capture sink") =
                self.lease.capability().and_then(|session| session.sink());
            Ok(())
        };
        match &self.feed {
            None => bind(None),
            Some(feed) => {
                let revoke: Arc<dyn Fn() + Send + Sync> = match change {
                    Some(change) => Arc::new(change.revoker()),
                    None => Arc::new(self.lease.revoker()),
                };
                feed.acknowledge(self.generation, revoke, |observed| {
                    bind(Some(observed.network_handle as u64))?;
                    log::info!("capture-ready generation={} handle={} network={} interface={} requested_routes={:?} observed_routes={:?} api={} owner_uid={:?} mtu={:?} route_types_reported={} representation=plain-ip tun_flags={:#06x}",
                        self.generation, observed.network_handle, observed.network, observed.interface_name,
                        self.requested_routes, observed.routes, observed.api_level, observed.owner_uid, observed.mtu,
                        observed.api_level >= 33, self.format.expect("bound format").flags());
                    *self.lifecycle.lock().expect("capture lifecycle") = Some((observed.network_handle, observed.network.clone(), observed.interface_name.clone()));
                    Ok(())
                }).ok_or_else(|| io::Error::other("Capture no longer ready"))?
            }
        }
    }

    pub fn rollback_feed(&self, successor: &Observation) -> bool {
        match &self.feed {
            Some(feed) => feed.rollback_handover(self.generation),
            None => {
                successor.retire();
                true
            }
        }
    }

    pub fn current(&self) -> bool {
        self.checked(|| {
            self.lease.capability().is_some_and(|session| {
                self.sink()
                    .is_some_and(|sink| session.with_sink(&sink, || ()).is_ok())
            })
        })
        .unwrap_or(false)
    }

    pub fn checked<T>(&self, operation: impl FnOnce() -> T) -> Option<T> {
        match &self.feed {
            Some(feed) => feed.with_ready(self.generation, operation),
            None => Some(operation()),
        }
    }
    pub fn sink(&self) -> Option<RelaySink> {
        self.sink.lock().expect("capture sink").clone()
    }
    pub fn retire(&self) {
        if let Some(feed) = &self.feed {
            feed.invalidate(self.generation);
        }
        if let Some((handle, network, interface)) =
            self.lifecycle.lock().expect("capture lifecycle").take()
        {
            log::info!(
                "capture-lost generation={} handle={handle} network={network} interface={interface} requested_routes={:?} last_ready_routes={:?}",
                self.generation,
                self.requested_routes,
                self.requested_routes
            );
        }
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        self.retire();
    }
}
