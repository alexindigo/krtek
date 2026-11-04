//! Daemon-owned delivery decisions and joined frontend reconciliation.
use mullvad_types::{
    settings::local_network_access::{
        LocalNetworkAccess,
        eligibility::{NetworkLease, NetworkObservation, evaluate},
        status::ForwardingAvailability,
    },
    states::TargetState,
};
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};
use talpid_lan_forwarder::{Disposition, Flow, LocalAuthority, Refused};
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation};
use tokio::sync::watch;

/// One root per runtime, retained across frontend replacements. Other regions
/// remain protected until managed relay/control/capture consumers are installed.
pub struct DeliveryBuffers {
    pub local: Arc<dyn RelayBufferAllocator>,
    pub _application: Arc<dyn RelayBufferAllocator>,
    pub _control: Arc<dyn RelayBufferAllocator>,
    pub _capture: Arc<dyn RelayBufferAllocator>,
    _root: BufferBudget,
    _metadata: Arc<dyn RelayBufferReservation>,
}
impl DeliveryBuffers {
    pub fn new() -> Self {
        let root = BufferBudget::new(64 * 1024 * 1024);
        let region = |mib: usize| {
            root.reserve(mib * 1024 * 1024)
                .expect("fixed root partition")
                .region()
                .expect("region metadata")
        };
        Self {
            local: Arc::new(region(30)),
            _application: Arc::new(region(22)),
            _control: Arc::new(region(8)),
            _capture: Arc::new(region(2)),
            _metadata: root.try_reserve(512).expect("root metadata"),
            _root: root,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerState {
    Running,
    #[cfg(any(target_os = "android", test))]
    Stopped,
    Failed,
}

pub fn frontend_wanted(
    rules_on: bool,
    has_routes: bool,
    target: TargetState,
    tunnel_disconnected: bool,
) -> bool {
    rules_on && has_routes && target == TargetState::Unsecured && tunnel_disconnected
}

pub fn availability(
    platform_supported: bool,
    rules_on: bool,
    has_routes: bool,
    target: TargetState,
    tunnel_disconnected: bool,
    owner: Option<OwnerState>,
    last_start_failed: bool,
) -> ForwardingAvailability {
    use ForwardingAvailability::*;
    if !platform_supported {
        NotAvailable
    } else if !rules_on || !has_routes {
        Off
    } else if !frontend_wanted(rules_on, has_routes, target, tunnel_disconnected) {
        PausedWhileConnected
    } else if !last_start_failed && owner == Some(OwnerState::Running) {
        Active
    } else {
        Failed
    }
}

pub type SocketPreparer =
    dyn Fn(&socket2::Socket, &NetworkLease) -> Result<(), Refused> + Send + Sync;

struct Inputs {
    policy: LocalNetworkAccess,
    observation: Option<NetworkObservation>,
}

pub struct DeliveryAuthority {
    inputs: RwLock<Inputs>,
    preparer: Arc<SocketPreparer>,
    revalidate: watch::Sender<u64>,
}

impl DeliveryAuthority {
    pub fn new(policy: &LocalNetworkAccess, preparer: Arc<SocketPreparer>) -> Self {
        Self {
            inputs: RwLock::new(Inputs {
                policy: policy.clone(),
                observation: None,
            }),
            preparer,
            revalidate: watch::channel(0).0,
        }
    }

    /// Publish the new authority before waking any owner. A missing record is not
    /// an empty/default observation and can never retain an old lease.
    pub fn update(&self, policy: &LocalNetworkAccess, observation: Option<NetworkObservation>) {
        *self.inputs.write().unwrap() = Inputs {
            policy: policy.clone(),
            observation,
        };
        self.revalidate.send_modify(|revision| {
            *revision = revision
                .checked_add(1)
                .expect("delivery revision exhausted");
        });
    }

    #[cfg(any(target_os = "android", test))]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revalidate.subscribe()
    }
}

impl LocalAuthority for DeliveryAuthority {
    type Grant = NetworkLease;

    fn disposition(&self, destination: IpAddr) -> Disposition {
        let inputs = self.inputs.read().unwrap();
        if inputs.policy.enabled
            && inputs.policy.validate().is_ok()
            && !destination.is_unspecified()
            && !destination.is_loopback()
            && !destination.is_multicast()
            && !matches!(destination, IpAddr::V4(ip) if ip.is_broadcast())
            && inputs.policy.matching_rules(destination).next().is_some()
        {
            Disposition::Local
        } else {
            Disposition::Drop
        }
    }

    fn authorize(&self, flow: Flow) -> Result<NetworkLease, Refused> {
        if !matches!(flow.source.ip(),
            IpAddr::V4(ip) if ip == Ipv4Addr::new(192, 0, 2, 2))
            && !matches!(flow.source.ip(),
                IpAddr::V6(ip) if ip == Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        {
            return Err(Refused::Denied);
        }
        let inputs = self.inputs.read().unwrap();
        let observation = inputs.observation.as_ref().ok_or(Refused::Denied)?;
        evaluate(&inputs.policy, observation, flow.destination.ip()).map_err(|_| Refused::Denied)
    }

    fn prepare(&self, socket: &socket2::Socket, lease: &NetworkLease) -> Result<(), Refused> {
        (self.preparer)(socket, lease)
    }

    fn current(&self, lease: &NetworkLease) -> bool {
        let inputs = self.inputs.read().unwrap();
        inputs
            .observation
            .as_ref()
            .is_some_and(|observation| lease.is_current(&inputs.policy, observation))
    }

    fn physical_destination(&self, lease: &NetworkLease, flow: Flow) -> SocketAddr {
        let mut destination = flow.destination;
        if let SocketAddr::V6(address) = &mut destination {
            address.set_scope_id(lease.scope_id);
        }
        destination
    }
}

// The lifecycle is host-compiled over the same ownership protocol as the native
// owner. Fakes implement this boundary only in tests; there is no runtime hook.
pub trait DeliveryOwner {
    fn ready(&mut self) -> impl Future<Output = io::Result<()>> + Send;
    fn stop(&mut self) -> impl Future<Output = io::Result<()>> + Send;
    fn retry_release(&mut self) -> io::Result<()>;
    fn state(&self) -> OwnerState;
    fn changed(&mut self) -> impl Future<Output = ()> + Send;
}

pub trait FrontendFactory: Send + Sync {
    type Owner: DeliveryOwner + Send;
    fn supported(&self) -> bool;
    fn start(
        &self,
        routes: Vec<String>,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> io::Result<Self::Owner>;
}

pub struct Delivery<F: FrontendFactory> {
    factory: F,
    pub authority: Arc<DeliveryAuthority>,
    owner: Option<F::Owner>,
    applied_routes: Vec<String>,
    last_start_failed: bool,
    release_outstanding: bool,
    owner_ready: bool,
    buffers: Arc<dyn RelayBufferAllocator>,
}

impl<F: FrontendFactory> Delivery<F> {
    pub fn new(
        factory: F,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Self {
        Self {
            factory,
            authority,
            owner: None,
            applied_routes: vec![],
            last_start_failed: false,
            release_outstanding: false,
            owner_ready: false,
            buffers,
        }
    }

    pub fn has_owner(&self) -> bool {
        // Terminal and unreleased owners still exclude every replacement/Connect.
        self.owner.is_some()
    }

    pub fn availability(
        &self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) -> ForwardingAvailability {
        availability(
            self.factory.supported(),
            policy.enabled,
            !policy.announced_routes().is_empty(),
            target,
            disconnected,
            self.owner.as_ref().map(DeliveryOwner::state),
            self.last_start_failed || !self.owner_ready,
        )
    }

    pub async fn changed(&mut self) {
        match self.owner.as_mut() {
            Some(owner) => owner.changed().await,
            None => std::future::pending().await,
        }
    }

    pub fn owner_changed(&mut self) {
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.state() == OwnerState::Failed)
        {
            self.last_start_failed = true;
        }
        // No maintain/retry here: only an external event can grant another attempt.
    }

    pub async fn maintain(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) {
        let retry_allowed = self.can_retry_release();
        self.last_start_failed = false;
        let routes: Vec<String> = policy
            .announced_routes()
            .iter()
            .map(ToString::to_string)
            .collect();
        let wanted = self.factory.supported()
            && frontend_wanted(policy.enabled, !routes.is_empty(), target, disconnected);
        let healthy = self.owner_ready
            && self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.state() == OwnerState::Running);
        if self.has_owner()
            && (!wanted || self.applied_routes != routes || !healthy)
            && self.stop_owner(retry_allowed).await.is_err()
        {
            self.last_start_failed = true;
            return;
        }
        if wanted && !self.has_owner() {
            match self
                .factory
                .start(routes.clone(), self.authority.clone(), self.buffers.clone())
            {
                Ok(owner) => {
                    // Acquire the recovery handle before the first suspension.
                    self.owner = Some(owner);
                    self.owner_ready = false;
                    self.applied_routes = routes;
                    if self.owner.as_mut().unwrap().ready().await.is_err() {
                        self.last_start_failed = true;
                        // First failed release is retained, not retried in this event.
                        let _ = self.stop_owner(false).await;
                    } else {
                        self.owner_ready = true;
                    }
                }
                Err(_) => self.last_start_failed = true,
            }
        }
    }

    async fn stop_owner(&mut self, retry_allowed: bool) -> io::Result<()> {
        let Some(owner) = self.owner.as_mut() else {
            return Ok(());
        };
        if let Err(error) = owner.stop().await {
            self.release_outstanding = true;
            if !retry_allowed {
                return Err(error);
            }
            owner.retry_release()?;
            owner.stop().await?;
        }
        self.owner = None;
        self.owner_ready = false;
        self.applied_routes.clear();
        self.release_outstanding = false;
        Ok(())
    }

    pub async fn stop(&mut self) -> io::Result<()> {
        let result = self.stop_owner(self.can_retry_release()).await;
        if result.is_err() {
            self.last_start_failed = true;
        }
        result
    }

    fn can_retry_release(&self) -> bool {
        self.last_start_failed
            || self.release_outstanding
            || self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.state() == OwnerState::Failed)
    }
}

#[cfg(target_os = "android")]
mod platform {
    use super::*;
    use std::os::fd::AsRawFd;
    use talpid_lan_forwarder::Forwarder;
    use talpid_tunnel::{
        android_frontend::{FrontendOwner, FrontendState},
        tun_provider::local_network::{LocalNetworkPlatform, PrepareError},
    };

    pub struct PlatformFactory(pub Arc<LocalNetworkPlatform>);
    pub struct PlatformOwner {
        owner: FrontendOwner,
        receiver: watch::Receiver<FrontendState>,
        open: bool,
    }

    pub fn preparer(platform: Arc<LocalNetworkPlatform>) -> Arc<SocketPreparer> {
        Arc::new(move |socket, lease| {
            platform
                .prepare(
                    socket.as_raw_fd(),
                    lease.network_handle,
                    lease.sequence,
                    lease.needs_wifi_name,
                )
                .map_err(|error| match error {
                    PrepareError::Stale => Refused::Stale,
                    _ => Refused::PreparationFailed,
                })
        })
    }

    impl FrontendFactory for PlatformFactory {
        type Owner = PlatformOwner;
        fn supported(&self) -> bool {
            true
        }
        fn start(
            &self,
            routes: Vec<String>,
            authority: Arc<DeliveryAuthority>,
            buffers: Arc<dyn RelayBufferAllocator>,
        ) -> io::Result<PlatformOwner> {
            let updates = authority.subscribe();
            let forwarder = Forwarder::new(authority, buffers)
                .map_err(|_| io::Error::other("Local storage budget full"))?;
            let owner = FrontendOwner::start(
                self.0.clone(),
                talpid_tunnel::android_frontend::CaptureConfig::Partial(routes),
                forwarder,
                updates,
            )?;
            let receiver = owner.state();
            Ok(PlatformOwner {
                owner,
                receiver,
                open: true,
            })
        }
    }

    impl DeliveryOwner for PlatformOwner {
        async fn ready(&mut self) -> io::Result<()> {
            self.owner.ready().await
        }
        async fn stop(&mut self) -> io::Result<()> {
            self.owner.stop().await
        }
        fn retry_release(&mut self) -> io::Result<()> {
            self.owner.retry_release()
        }
        fn state(&self) -> OwnerState {
            match *self.receiver.borrow() {
                FrontendState::Running => OwnerState::Running,
                FrontendState::Stopped => OwnerState::Stopped,
                FrontendState::Failed => OwnerState::Failed,
            }
        }
        async fn changed(&mut self) {
            if self.open {
                if self.receiver.changed().await.is_err() {
                    self.open = false;
                }
            } else {
                std::future::pending().await
            }
        }
    }
}

#[cfg(not(target_os = "android"))]
mod platform {
    use super::*;
    pub struct PlatformFactory;
    pub enum PlatformOwner {}
    pub fn preparer() -> Arc<SocketPreparer> {
        Arc::new(|_, _| Err(Refused::PreparationFailed))
    }
    impl FrontendFactory for PlatformFactory {
        type Owner = PlatformOwner;
        fn supported(&self) -> bool {
            false
        }
        fn start(
            &self,
            _: Vec<String>,
            _: Arc<DeliveryAuthority>,
            _: Arc<dyn RelayBufferAllocator>,
        ) -> io::Result<PlatformOwner> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    impl DeliveryOwner for PlatformOwner {
        async fn ready(&mut self) -> io::Result<()> {
            match *self {}
        }
        async fn stop(&mut self) -> io::Result<()> {
            match *self {}
        }
        fn retry_release(&mut self) -> io::Result<()> {
            match *self {}
        }
        fn state(&self) -> OwnerState {
            match *self {}
        }
        async fn changed(&mut self) {
            match *self {}
        }
    }
}
pub use platform::{PlatformFactory, preparer};

#[cfg(test)]
mod tests;
