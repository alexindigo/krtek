//! Daemon-owned delivery decisions and joined frontend reconciliation.
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess,
    eligibility::{NetworkLease, NetworkObservation, evaluate},
    status::ForwardingAvailability,
};
#[cfg(test)]
use mullvad_types::states::TargetState;
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};
use talpid_lan_forwarder::{Disposition, Flow, LocalAuthority, Refused};
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_tunnel::packet_attachment::{AttachmentBroker, AttachmentMode, PendingCaptureRequest};
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

#[cfg(test)]
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
    endpoint: bool,
    owner: Option<OwnerState>,
    last_start_failed: bool,
) -> ForwardingAvailability {
    use ForwardingAvailability::*;
    if !platform_supported {
        NotAvailable
    } else if !rules_on || !has_routes {
        Off
    } else if last_start_failed || owner == Some(OwnerState::Failed) {
        Failed
    } else if endpoint && owner == Some(OwnerState::Running) {
        Active
    } else {
        PausedWhileConnected
    }
}

pub type SocketPreparer =
    dyn Fn(&socket2::Socket, &NetworkLease) -> Result<(), Refused> + Send + Sync;

struct Inputs {
    policy: LocalNetworkAccess,
    observation: Option<NetworkObservation>,
    capture: Option<CaptureAuthority>,
    endpoint: bool,
}

/// Immutable source ownership for one frontend incarnation. Physical network
/// identity alone cannot authorize a reply into a replacement VPN interface.
#[derive(Clone)]
struct CaptureAuthority {
    identity: u64,
    sources: Vec<IpAddr>,
    managed: Option<AttachmentBroker>,
    reserved: Vec<ipnetwork::IpNetwork>,
}

impl CaptureAuthority {
    fn new(
        sources: Vec<IpAddr>,
        managed: Option<AttachmentBroker>,
        reserved: Vec<ipnetwork::IpNetwork>,
    ) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let identity = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("capture authority identity exhausted");
        Self {
            identity,
            sources,
            managed,
            reserved,
        }
    }

    fn partial() -> Self {
        Self::new(
            vec![
                Ipv4Addr::new(192, 0, 2, 2).into(),
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).into(),
            ],
            None,
            vec![],
        )
    }

    fn generation(&self) -> Result<Option<u64>, Refused> {
        match &self.managed {
            None => Ok(None),
            Some(broker) => {
                let state = broker.snapshot();
                if state.mode != AttachmentMode::ManagedRequired || !state.capture_ready {
                    return Err(Refused::Stale);
                }
                state.capture_generation.map(Some).ok_or(Refused::Stale)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryGrant {
    pub physical: NetworkLease,
    capture: u64,
    generation: Option<u64>,
    source: IpAddr,
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
                capture: Some(CaptureAuthority::partial()),
                endpoint: true,
            }),
            preparer,
            revalidate: watch::channel(0).0,
        }
    }

    /// Publish the new authority before waking any owner. A missing record is not
    /// an empty/default observation and can never retain an old lease.
    pub fn update(&self, policy: &LocalNetworkAccess, observation: Option<NetworkObservation>) {
        let mut inputs = self.inputs.write().unwrap();
        inputs.policy = policy.clone();
        inputs.observation = observation;
        drop(inputs);
        self.wake();
    }

    fn wake(&self) {
        self.revalidate.send_modify(|revision| {
            *revision = revision
                .checked_add(1)
                .expect("delivery revision exhausted");
        });
    }

    fn install(&self, capture: CaptureAuthority) {
        self.inputs.write().unwrap().capture = Some(capture);
        self.wake();
    }

    pub fn revoke(&self) {
        self.inputs.write().unwrap().capture = None;
        self.wake();
    }

    pub fn endpoint(&self, ready: bool) {
        let mut inputs = self.inputs.write().unwrap();
        if inputs.endpoint != ready {
            inputs.endpoint = ready;
            drop(inputs);
            self.wake();
        }
    }

    #[cfg(any(target_os = "android", test))]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revalidate.subscribe()
    }
}

impl LocalAuthority for DeliveryAuthority {
    type Grant = DeliveryGrant;

    fn disposition(&self, destination: IpAddr) -> Disposition {
        let inputs = self.inputs.read().unwrap();
        if inputs.policy.enabled
            && inputs.policy.validate().is_ok()
            && !inputs.capture.as_ref().is_some_and(|capture| {
                capture
                    .reserved
                    .iter()
                    .any(|prefix| prefix.contains(destination))
            })
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

    fn authorize(&self, flow: Flow) -> Result<DeliveryGrant, Refused> {
        let inputs = self.inputs.read().unwrap();
        let capture = inputs.capture.as_ref().ok_or(Refused::Denied)?;
        if !inputs.endpoint
            || !capture.sources.contains(&flow.source.ip())
            || capture
                .reserved
                .iter()
                .any(|prefix| prefix.contains(flow.destination.ip()))
        {
            return Err(Refused::Denied);
        }
        let generation = capture.generation()?;
        let observation = inputs.observation.as_ref().ok_or(Refused::Denied)?;
        let physical = evaluate(&inputs.policy, observation, flow.destination.ip())
            .map_err(|_| Refused::Denied)?;
        Ok(DeliveryGrant {
            physical,
            capture: capture.identity,
            generation,
            source: flow.source.ip(),
        })
    }

    fn prepare(&self, socket: &socket2::Socket, grant: &DeliveryGrant) -> Result<(), Refused> {
        if !self.current(grant) {
            return Err(Refused::Stale);
        }
        (self.preparer)(socket, &grant.physical)?;
        if self.current(grant) {
            Ok(())
        } else {
            Err(Refused::Stale)
        }
    }

    fn current(&self, grant: &DeliveryGrant) -> bool {
        let inputs = self.inputs.read().unwrap();
        inputs.endpoint
            && inputs.capture.as_ref().is_some_and(|capture| {
                capture.identity == grant.capture
                    && capture.sources.contains(&grant.source)
                    && capture.generation() == Ok(grant.generation)
                    && !capture
                        .reserved
                        .iter()
                        .any(|prefix| prefix.contains(grant.physical.destination))
            })
            && inputs
                .observation
                .as_ref()
                .is_some_and(|observation| grant.physical.is_current(&inputs.policy, observation))
    }

    fn physical_destination(&self, grant: &DeliveryGrant, flow: Flow) -> SocketAddr {
        let mut destination = flow.destination;
        if let SocketAddr::V6(address) = &mut destination {
            address.set_scope_id(grant.physical.scope_id);
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
    fn release_failed(&self) -> bool;
    fn changed(&mut self) -> impl Future<Output = ()> + Send;
}

pub trait FrontendFactory: Send + Sync {
    type Owner: DeliveryOwner + Send;
    fn supported(&self) -> bool;
    fn start(
        &self,
        config: DeliveryConfig,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> io::Result<Self::Owner>;
}

#[derive(Clone)]
pub enum DeliveryConfig {
    Partial(Vec<String>),
    Secured {
        broker: AttachmentBroker,
        request: PendingCaptureRequest,
    },
}

impl DeliveryConfig {
    fn same_capture(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Partial(a), Self::Partial(b)) => a == b,
            (Self::Secured { request: a, .. }, Self::Secured { request: b, .. }) => {
                a.id() == b.id()
            }
            _ => false,
        }
    }

    fn authority(&self) -> CaptureAuthority {
        match self {
            Self::Partial(_) => CaptureAuthority::partial(),
            Self::Secured { broker, request } => {
                let config = request.config();
                let reserved = config
                    .gateways()
                    .into_iter()
                    .map(ipnetwork::IpNetwork::from)
                    .chain([talpid_tunnel::tun_provider::SOCKS_PROXIES])
                    .collect();
                CaptureAuthority::new(config.addresses.clone(), Some(broker.clone()), reserved)
            }
        }
    }

    #[cfg(any(target_os = "android", test))]
    fn mtu(&self) -> u16 {
        match self {
            Self::Partial(_) => 1280,
            Self::Secured { request, .. } => request.config().mtu,
        }
    }

    #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
    fn into_frontend(
        self,
        classifier: Arc<DeliveryAuthority>,
    ) -> talpid_tunnel::android_frontend::CaptureConfig {
        use talpid_tunnel::android_frontend::{CaptureConfig, CaptureDisposition};
        match self {
            Self::Partial(routes) => CaptureConfig::Partial(routes),
            Self::Secured { broker, request } => CaptureConfig::Secured {
                broker,
                request,
                disposition: Arc::new(move |destination| {
                    if classifier.disposition(destination) == Disposition::Local {
                        CaptureDisposition::Local
                    } else {
                        CaptureDisposition::Tunnel(talpid_types::relay_flow::RelayTargetId::MULLVAD)
                    }
                }),
            },
        }
    }
}

pub struct Delivery<F: FrontendFactory> {
    factory: F,
    pub authority: Arc<DeliveryAuthority>,
    owner: Option<F::Owner>,
    applied: Option<DeliveryConfig>,
    last_start_failed: bool,
    release_outstanding: bool,
    owner_ready: bool,
    buffers: Arc<dyn RelayBufferAllocator>,
}

impl<F: FrontendFactory> Delivery<F> {
    pub fn supported(&self) -> bool {
        self.factory.supported()
    }

    pub fn applied_config(&self) -> Option<DeliveryConfig> {
        self.applied.clone()
    }
    pub fn release_ready(&self) -> bool {
        match &self.applied {
            Some(DeliveryConfig::Secured { request, .. }) => request.release_ready(),
            _ => true,
        }
    }
    pub fn defer_release(&self) {
        if let Some(DeliveryConfig::Secured { request, .. }) = &self.applied {
            request.defer_release();
        }
    }
    pub fn transport_joined(&self) {
        if let Some(DeliveryConfig::Secured { request, .. }) = &self.applied {
            request.handover_joined();
        }
    }
    pub fn new(
        factory: F,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Self {
        Self {
            factory,
            authority,
            owner: None,
            applied: None,
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

    #[cfg(test)]
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
            self.ready()
                && frontend_wanted(
                    policy.enabled,
                    !policy.announced_routes().is_empty(),
                    target,
                    disconnected,
                ),
            self.owner.as_ref().map(DeliveryOwner::state),
            self.failed(),
        )
    }

    pub async fn changed(&mut self) {
        match self.owner.as_mut() {
            Some(owner) if !self.owner_ready && !self.last_start_failed => {
                match owner.ready().await {
                    Ok(()) => self.owner_ready = true,
                    Err(_) => {
                        self.last_start_failed = true;
                        self.authority.revoke();
                    }
                }
            }
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
            self.authority.revoke();
        }
        // No maintain/retry here: only an external event can grant another attempt.
    }

    #[cfg(test)]
    pub async fn maintain(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) {
        let routes: Vec<_> = policy
            .announced_routes()
            .iter()
            .map(ToString::to_string)
            .collect();
        let wanted = self.factory.supported()
            && frontend_wanted(policy.enabled, !routes.is_empty(), target, disconnected);
        self.maintain_config(wanted.then_some(DeliveryConfig::Partial(routes)))
            .await;
    }

    pub async fn maintain_config(&mut self, wanted: Option<DeliveryConfig>) {
        use futures::FutureExt;
        let retry_allowed = self.can_retry_release();
        let healthy = self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.state() == OwnerState::Running);
        let same = wanted
            .as_ref()
            .zip(self.applied.as_ref())
            .is_some_and(|(a, b)| a.same_capture(b));
        if self.has_owner() && (!same || !healthy || retry_allowed) && !self.release_ready() {
            self.authority.revoke();
            return;
        }
        self.last_start_failed = false;
        if self.has_owner()
            && (!same || !healthy || retry_allowed)
            && self.stop_owner(retry_allowed).await.is_err()
        {
            self.last_start_failed = true;
            return;
        }
        if let Some(config) = wanted.filter(|_| self.factory.supported() && !self.has_owner()) {
            self.authority.install(config.authority());
            match self
                .factory
                .start(config.clone(), self.authority.clone(), self.buffers.clone())
            {
                Ok(owner) => {
                    // Acquire the recovery handle before the first suspension.
                    self.owner = Some(owner);
                    self.owner_ready = false;
                    self.applied = Some(config);
                    // Never hold the daemon actor waiting for an Android callback
                    // or transport request. Retain pending readiness for select.
                    match self.owner.as_mut().unwrap().ready().now_or_never() {
                        Some(Ok(())) => self.owner_ready = true,
                        Some(Err(_)) => {
                            self.last_start_failed = true;
                            if self.release_ready() {
                                let _ = self.stop_owner(false).await;
                            }
                        }
                        None => {}
                    }
                }
                Err(_) => {
                    self.last_start_failed = true;
                    self.authority.revoke();
                }
            }
        }
    }

    async fn stop_owner(&mut self, retry_allowed: bool) -> io::Result<()> {
        self.authority.revoke();
        if !self.release_ready() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Transport teardown is not joined",
            ));
        }
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
        self.applied = None;
        self.release_outstanding = false;
        Ok(())
    }

    pub async fn stop(&mut self) -> io::Result<()> {
        let result = self.stop_owner(self.can_retry_release()).await;
        if !result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            self.last_start_failed = result.is_err();
        }
        result
    }

    pub fn fail(&mut self) {
        self.last_start_failed = true;
        self.authority.revoke();
    }

    fn can_retry_release(&self) -> bool {
        self.release_outstanding
            || self
                .owner
                .as_ref()
                .is_some_and(DeliveryOwner::release_failed)
    }

    pub fn failed(&self) -> bool {
        self.last_start_failed
            || self.release_outstanding
            || self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.state() == OwnerState::Failed)
    }

    pub fn release_failed(&self) -> bool {
        self.release_outstanding
            || self
                .owner
                .as_ref()
                .is_some_and(DeliveryOwner::release_failed)
    }

    pub fn ready(&self) -> bool {
        self.owner_ready
            && !self.failed()
            && self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.state() == OwnerState::Running)
    }

    pub fn owner_state(&self) -> Option<OwnerState> {
        self.owner.as_ref().map(DeliveryOwner::state)
    }

    pub fn partial_ready(&self) -> bool {
        self.ready() && matches!(self.applied, Some(DeliveryConfig::Partial(_)))
    }

    pub fn managed_ready(&self) -> bool {
        self.ready() && matches!(self.applied, Some(DeliveryConfig::Secured { .. }))
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
            config: DeliveryConfig,
            authority: Arc<DeliveryAuthority>,
            buffers: Arc<dyn RelayBufferAllocator>,
        ) -> io::Result<PlatformOwner> {
            let updates = authority.subscribe();
            let mtu = config.mtu();
            let classifier = authority.clone();
            let forwarder = Forwarder::with_mtu(authority, buffers, usize::from(mtu))
                .map_err(|_| io::Error::other("Local storage budget full"))?;
            let config = config.into_frontend(classifier);
            let owner = FrontendOwner::start(self.0.clone(), config, forwarder, updates)?;
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
        fn release_failed(&self) -> bool {
            self.owner.release_failed()
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
            _: DeliveryConfig,
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
        fn release_failed(&self) -> bool {
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
