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
#[cfg(test)]
use talpid_tunnel::packet_attachment::AttachmentMode;
use talpid_tunnel::packet_attachment::{AttachmentBroker, PendingCaptureRequest};
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

/// Logical capture ownership, independent of descriptor/observation epochs.
/// Physical network identity alone cannot authorize a reply into a new session.
#[derive(Clone)]
struct CaptureAuthority {
    identity: u64,
    sources: Vec<IpAddr>,
    broker: Option<AttachmentBroker>,
    reserved: Vec<ipnetwork::IpNetwork>,
}

impl CaptureAuthority {
    fn new(
        mut sources: Vec<IpAddr>,
        broker: Option<AttachmentBroker>,
        reserved: Vec<ipnetwork::IpNetwork>,
    ) -> Self {
        sources.sort();
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let identity = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("capture authority identity exhausted");
        Self {
            identity,
            sources,
            broker,
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
        match &self.broker {
            None => Ok(None),
            Some(broker) => {
                let state = broker.snapshot();
                state.session_generation.map(Some).ok_or(Refused::Stale)
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

    /// Only the retained owner can reconcile an epoch without minting a new
    /// permission identity. During establish, protect both reserved sets.
    fn reconcile_capture(&self, capture: CaptureAuthority, establishing: bool) {
        let mut inputs = self.inputs.write().unwrap();
        if let Some(current) = inputs.capture.as_mut() {
            assert_eq!(current.sources, capture.sources);
            assert!(
                current
                    .broker
                    .as_ref()
                    .zip(capture.broker.as_ref())
                    .is_some_and(|(a, b)| a.same_broker(b))
            );
            if establishing {
                for prefix in capture.reserved {
                    if !current.reserved.contains(&prefix) {
                        current.reserved.push(prefix);
                    }
                }
            } else {
                current.reserved = capture.reserved;
            }
        }
        drop(inputs);
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
    fn handover(&mut self, config: DeliveryConfig) -> io::Result<()>;
    fn retry_handover_release(&mut self) -> io::Result<()>;
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
        broker: AttachmentBroker,
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

    fn authority(&self, broker: &AttachmentBroker) -> CaptureAuthority {
        match self {
            Self::Partial(_) => {
                let mut authority = CaptureAuthority::partial();
                authority.broker = Some(broker.clone());
                authority
            }
            Self::Secured { request, .. } => {
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

    fn compatible(&self, other: &Self, broker: &AttachmentBroker) -> bool {
        let sources = |config: &Self| {
            let mut sources = config.authority(broker).sources;
            sources.sort();
            sources
        };
        let own_broker = |config: &Self| match config {
            Self::Partial(_) => true,
            Self::Secured {
                broker: selected, ..
            } => broker.same_broker(selected),
        };
        own_broker(self)
            && own_broker(other)
            && sources(self) == sources(other)
            && self.mtu() == other.mtu()
    }

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
    pending: Option<Readiness>,
    desired: Option<DeliveryConfig>,
    handover_failed: bool,
    // A coalesced external retry belongs to the pending operation, not to an
    // internal readiness/state notification. Consume it only after that join.
    retry_requested: bool,
    // TSM release authority is not configuration/readiness authority. Keep both
    // exact requests through pending readiness and predecessor cleanup.
    releases: [Option<PendingCaptureRequest>; 2],
    buffers: Arc<dyn RelayBufferAllocator>,
    broker: AttachmentBroker,
}

enum Readiness {
    Initial,
    Handover {
        config: DeliveryConfig,
        predecessor: Option<u64>,
    },
    Release,
}

impl<F: FrontendFactory> Delivery<F> {
    pub fn supported(&self) -> bool {
        self.factory.supported()
    }

    pub fn applied_config(&self) -> Option<DeliveryConfig> {
        self.applied.clone()
    }
    pub fn release_ready(&self) -> bool {
        self.releases
            .iter()
            .flatten()
            .all(PendingCaptureRequest::release_ready)
    }
    pub fn defer_release(&self) {
        for request in self.releases.iter().flatten() {
            request.defer_release();
        }
    }
    pub fn transport_joined(&self) {
        for request in self.releases.iter().flatten() {
            request.handover_joined();
        }
    }

    fn retain_release(&mut self, config: &DeliveryConfig) -> io::Result<()> {
        let applied = match &self.applied {
            Some(DeliveryConfig::Secured { request, .. }) => Some(request.id()),
            _ => None,
        };
        // A joined predecessor no longer needs a future TSM acknowledgement.
        // Keep the applied request even when no target has acquired it yet.
        for slot in &mut self.releases {
            if slot
                .as_ref()
                .is_some_and(|request| Some(request.id()) != applied && request.release_ready())
            {
                *slot = None;
            }
        }
        if let DeliveryConfig::Secured { request, .. } = config {
            if self
                .releases
                .iter()
                .flatten()
                .any(|held| held.id() == request.id())
            {
                return Ok(());
            }
            let slot = self
                .releases
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            *slot = Some(request.clone());
        }
        Ok(())
    }
    pub fn new(
        factory: F,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        broker: AttachmentBroker,
    ) -> Self {
        Self {
            factory,
            authority,
            owner: None,
            applied: None,
            last_start_failed: false,
            release_outstanding: false,
            owner_ready: false,
            pending: None,
            desired: None,
            handover_failed: false,
            retry_requested: false,
            releases: [None, None],
            buffers,
            broker,
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
        let reconcile = match self.owner.as_mut() {
            Some(owner) if self.pending.is_some() => {
                let result = owner.ready().await;
                let success = result.is_ok();
                self.received_ready(result);
                success
            }
            Some(owner) => {
                owner.changed().await;
                true
            }
            None => std::future::pending().await,
        };
        // A settings event may supersede the in-flight request. Reconcile the
        // latest intent after its exact acknowledgement, without another event
        // or a closed-channel readiness loop. Failures wait for an external retry.
        if self.retry_requested || reconcile && !self.failed() {
            self.reconcile_config(self.desired.clone()).await;
        }
    }

    fn received_ready(&mut self, result: io::Result<()>) {
        match self.pending.take().expect("retained readiness owner") {
            Readiness::Initial => {
                self.owner_ready = result.is_ok();
                if result.is_err() {
                    self.last_start_failed = true;
                    self.authority.revoke();
                }
            }
            Readiness::Handover {
                config,
                predecessor,
            } => {
                if result.is_ok() {
                    self.authority
                        .reconcile_capture(config.authority(&self.broker), false);
                    self.applied = Some(config);
                } else {
                    self.handover_failed = !result
                        .as_ref()
                        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock);
                    let snapshot = self.broker.snapshot();
                    if snapshot.capture_ready && snapshot.capture_generation == predecessor {
                        self.authority.reconcile_capture(
                            self.applied.as_ref().unwrap().authority(&self.broker),
                            false,
                        );
                    } else {
                        self.last_start_failed = true;
                        self.authority.revoke();
                    }
                }
            }
            Readiness::Release => {
                self.handover_failed = result.is_err();
            }
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
        self.maintain_config_inner(wanted, true).await;
    }

    pub async fn reconcile_config(&mut self, wanted: Option<DeliveryConfig>) {
        self.maintain_config_inner(wanted, false).await;
    }

    async fn maintain_config_inner(&mut self, wanted: Option<DeliveryConfig>, external: bool) {
        use futures::FutureExt;
        if wanted.as_ref().is_some_and(|config| {
            matches!(config,
            DeliveryConfig::Secured { broker, .. } if !self.broker.same_broker(broker))
        }) {
            self.handover_failed = true;
            return;
        }
        self.desired = wanted.clone();
        if self.pending.is_some() {
            self.retry_requested |= external;
            return;
        }
        let external_retry = std::mem::take(&mut self.retry_requested) || external;
        self.handover_failed = false;
        let retry_allowed = external_retry && self.can_retry_release();
        let healthy = self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.state() == OwnerState::Running);
        let same = wanted
            .as_ref()
            .zip(self.applied.as_ref())
            .is_some_and(|(a, b)| a.same_capture(b));
        if healthy && self.owner_ready {
            let compatible = wanted
                .as_ref()
                .zip(self.applied.as_ref())
                .is_some_and(|(a, b)| a.compatible(b, &self.broker));
            if compatible {
                if self.retain_release(wanted.as_ref().unwrap()).is_err() {
                    return;
                }
                let owner = self.owner.as_mut().unwrap();
                if owner.release_failed() {
                    if external_retry && owner.retry_handover_release().is_ok() {
                        self.pending = Some(Readiness::Release);
                    }
                } else if !same {
                    let config = wanted.as_ref().unwrap();
                    let predecessor = self.broker.snapshot().capture_generation;
                    // The owner can run on another runtime thread immediately
                    // after dispatch. Publish restrictive policy first, without
                    // retaining the authority lock over the command boundary.
                    self.authority
                        .reconcile_capture(config.authority(&self.broker), true);
                    if owner.handover(config.clone()).is_ok() {
                        self.pending = Some(Readiness::Handover {
                            config: config.clone(),
                            predecessor,
                        });
                    } else {
                        self.authority.reconcile_capture(
                            self.applied.as_ref().unwrap().authority(&self.broker),
                            false,
                        );
                    }
                }
                if self.pending.is_some()
                    && let Some(result) = self.owner.as_mut().unwrap().ready().now_or_never()
                {
                    self.received_ready(result);
                }
                return;
            }
        }
        if self.can_retry_release() && !external_retry {
            return;
        }
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
            // Retain before dispatch: the native actor can establish/acknowledge
            // on another runtime thread before Delivery receives readiness.
            self.retain_release(&config)
                .expect("no owner retains a release");
            self.authority.install(config.authority(&self.broker));
            match self.factory.start(
                config.clone(),
                self.authority.clone(),
                self.buffers.clone(),
                self.broker.clone(),
            ) {
                Ok(owner) => {
                    // Acquire the recovery handle before the first suspension.
                    self.owner = Some(owner);
                    self.owner_ready = false;
                    self.pending = Some(Readiness::Initial);
                    self.applied = Some(config);
                    // Never hold the daemon actor waiting for an Android callback
                    // or transport request. Retain pending readiness for select.
                    if let Some(result) = self.owner.as_mut().unwrap().ready().now_or_never() {
                        let failed = result.is_err();
                        self.received_ready(result);
                        if failed && self.release_ready() {
                            let _ = self.stop_owner(false).await;
                        }
                    }
                }
                Err(_) => {
                    self.releases = [None, None];
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
        self.pending = None;
        self.applied = None;
        self.releases = [None, None];
        self.release_outstanding = false;
        Ok(())
    }

    pub async fn stop(&mut self) -> io::Result<()> {
        self.desired = None;
        self.retry_requested = false;
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
            || self.handover_failed
            || self.release_failed()
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
            && !self.last_start_failed
            && !self.release_outstanding
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
        authority: Arc<DeliveryAuthority>,
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
            broker: AttachmentBroker,
        ) -> io::Result<PlatformOwner> {
            let updates = authority.subscribe();
            let mtu = config.mtu();
            let classifier = authority.clone();
            let forwarder = Forwarder::with_mtu(authority.clone(), buffers, usize::from(mtu))
                .map_err(|_| io::Error::other("Local storage budget full"))?;
            let config = config.into_frontend(classifier);
            let owner = FrontendOwner::start(self.0.clone(), config, forwarder, updates, broker)?;
            let receiver = owner.state();
            Ok(PlatformOwner {
                owner,
                authority,
                receiver,
                open: true,
            })
        }
    }

    impl DeliveryOwner for PlatformOwner {
        fn handover(&mut self, config: DeliveryConfig) -> io::Result<()> {
            self.owner
                .handover(config.into_frontend(self.authority.clone()))
        }
        fn retry_handover_release(&mut self) -> io::Result<()> {
            self.owner.retry_handover_release()
        }
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
            _: AttachmentBroker,
        ) -> io::Result<PlatformOwner> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    impl DeliveryOwner for PlatformOwner {
        fn handover(&mut self, _: DeliveryConfig) -> io::Result<()> {
            match *self {}
        }
        fn retry_handover_release(&mut self) -> io::Result<()> {
            match *self {}
        }
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
