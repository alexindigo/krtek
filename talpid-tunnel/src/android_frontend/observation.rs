use super::{CaptureConfig, FrontendPlatform};
use crate::packet_attachment::{AttachmentBroker, CaptureLease, PendingCaptureRequest};
use std::{
    io,
    os::fd::BorrowedFd,
    sync::{Arc, Mutex},
    time::Duration,
};
use talpid_types::{
    capture_network::{CaptureNetworkFeed, CaptureNetworkState, CaptureRoute},
    relay_flow::{RelayCaptureGeneration, RelaySources},
};
use tokio::sync::{oneshot, watch};

fn failure(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

pub(super) struct Observation {
    pub generation: i64,
    feed: Arc<CaptureNetworkFeed>,
    pub updates: watch::Receiver<CaptureNetworkState>,
    pub lease: Option<Arc<CaptureLease>>,
    managed: Option<(AttachmentBroker, PendingCaptureRequest)>,
    pub sources: RelaySources,
    requested_routes: Vec<CaptureRoute>,
    lifecycle: Mutex<Option<(i64, String, String)>>,
}

impl Observation {
    pub fn begin(platform: &dyn FrontendPlatform, config: &CaptureConfig) -> io::Result<Self> {
        let (lease, managed) = match config {
            CaptureConfig::Partial(_) => return Err(io::ErrorKind::InvalidInput.into()),
            CaptureConfig::Secured {
                broker, request, ..
            } => (
                Some(Arc::new(
                    broker.open_capture(Some(request)).map_err(failure)?,
                )),
                Some((broker.clone(), request.clone())),
            ),
        };
        let generation = match &lease {
            Some(lease) => lease.generation(),
            None => RelayCaptureGeneration::fresh().map_err(failure)?.get(),
        };
        let generation = i64::try_from(generation).map_err(io::Error::other)?;
        let feed = platform.capture_feed();
        let updates = feed
            .begin(generation)
            .ok_or_else(|| io::Error::other("Capture observation unavailable"))?;
        Ok(Self {
            generation,
            feed,
            updates,
            lease,
            managed,
            requested_routes: Vec::new(),
            lifecycle: Mutex::new(None),
            sources: RelaySources {
                ipv4: None,
                ipv6: None,
            },
        })
    }

    // This runs in joined blocking work, on the borrowed sole descriptor. Bind
    // native expectations before Kotlin can publish its buffered observations.
    pub fn bind(
        &mut self,
        platform: &dyn FrontendPlatform,
        config: &CaptureConfig,
        fd: BorrowedFd<'_>,
    ) -> io::Result<()> {
        let interface = platform.interface_name(fd)?;
        let expected = platform.expectation(config, interface.clone())?;
        self.requested_routes = expected.routes.clone();
        self.sources = RelaySources {
            ipv4: expected.addresses.iter().find_map(|p| match p.address {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            }),
            ipv6: expected.addresses.iter().find_map(|p| match p.address {
                std::net::IpAddr::V6(ip) => Some(ip),
                _ => None,
            }),
        };
        if expected.addresses.len()
            != usize::from(self.sources.ipv4.is_some()) + usize::from(self.sources.ipv6.is_some())
            || !self.feed.bind(self.generation, expected)
            || !platform.bind(self.generation, &interface)?
        {
            return Err(io::Error::other("Capture interface binding failed"));
        }
        Ok(())
    }

    pub async fn wait_ready(
        &self,
        updates: &mut watch::Receiver<CaptureNetworkState>,
        stop: &mut oneshot::Receiver<()>,
    ) -> io::Result<()> {
        let mut broker_updates = self.managed.as_ref().map(|(broker, _)| broker.changes());
        let wait = async {
            loop {
                if self.managed.as_ref().is_some_and(|(broker, request)| {
                    let snapshot = broker.snapshot();
                    snapshot.capture_generation != Some(self.generation as u64)
                        || snapshot.request != Some(request.id())
                }) {
                    return Err(io::Error::other("Capture request cancelled or replaced"));
                }
                let state = updates.borrow_and_update().clone();
                match state {
                    CaptureNetworkState::Ready(_) => return self.acknowledge(),
                    CaptureNetworkState::Lost => {
                        return Err(io::Error::other("Capture observation lost"));
                    }
                    CaptureNetworkState::Pending => {}
                }
                tokio::select! {
                    result = updates.changed() => result.map_err(io::Error::other)?,
                    _ = async { match &mut broker_updates { Some(updates) => { let _ = updates.changed().await; }, None => std::future::pending().await } } => {},
                }
            }
        };
        tokio::select! {
            _ = stop => Err(io::ErrorKind::Interrupted.into()),
            result = tokio::time::timeout(Duration::from_secs(15), wait) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Capture observation timed out"))?,
        }
    }

    fn acknowledge(&self) -> io::Result<()> {
        let revoke: Arc<dyn Fn() + Send + Sync> = match &self.lease {
            Some(lease) => Arc::new(lease.revoker()),
            None => Arc::new(|| {}),
        };
        self.feed
            .acknowledge(self.generation, revoke, |observed| {
                if let Some((broker, request)) = &self.managed {
                    let receipt = self
                        .lease
                        .as_ref()
                        .expect("managed lease")
                        .bind_observed_identity(
                            &observed.interface_name,
                            observed.network_handle as u64,
                            self.sources,
                            request.config().mtu,
                        )
                        .map_err(failure)?;
                    broker.acknowledge(request, &receipt).map_err(failure)?;
                }
                log::info!("capture-ready generation={} handle={} network={} interface={} requested_routes={:?} observed_routes={:?} api={} owner_uid={:?} mtu={:?} route_types_reported={}",
                    self.generation, observed.network_handle, observed.network, observed.interface_name,
                    self.requested_routes, observed.routes, observed.api_level, observed.owner_uid, observed.mtu, observed.api_level >= 33);
                *self.lifecycle.lock().expect("capture lifecycle") = Some((observed.network_handle, observed.network.clone(), observed.interface_name.clone()));
                Ok(())
            })
            .ok_or_else(|| io::Error::other("Capture no longer ready"))?
    }

    pub fn current(&self) -> bool {
        matches!(*self.updates.borrow(), CaptureNetworkState::Ready(_))
            && self.managed.as_ref().is_none_or(|(broker, _)| {
                let snapshot = broker.snapshot();
                snapshot.capture_generation == Some(self.generation as u64)
                    && snapshot.capture_ready
            })
    }

    pub fn checked<T>(&self, operation: impl FnOnce() -> T) -> Option<T> {
        self.feed.with_ready(self.generation, operation)
    }

    pub fn retire(&self) {
        self.feed.invalidate(self.generation);
        if let Some(lease) = &self.lease {
            lease.retire();
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
