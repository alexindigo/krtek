//! Single actor-owned authority, frontend lifecycle and semantic status publisher.
use crate::local_delivery::{
    self, Delivery, DeliveryAuthority, DeliveryBuffers, DeliveryConfig, FrontendFactory,
    PlatformFactory, SocketPreparer,
};
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess, eligibility::NetworkObservation, status::LocalNetworkStatus,
};
use mullvad_types::states::TargetState;
use std::sync::Arc;
use talpid_tunnel::packet_attachment::{AttachmentBroker, AttachmentMode, BrokerSnapshot};
use talpid_types::local_network::{LocalNetworkFeed, LocalNetworkFeedState};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelPhase {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

impl From<&mullvad_types::states::TunnelState> for TunnelPhase {
    fn from(state: &mullvad_types::states::TunnelState) -> Self {
        use mullvad_types::states::TunnelState;
        match state {
            TunnelState::Disconnected { .. } => Self::Disconnected,
            TunnelState::Connecting { .. } => Self::Connecting,
            TunnelState::Connected { .. } => Self::Connected,
            TunnelState::Disconnecting(_) => Self::Disconnecting,
            TunnelState::Error(_) => Self::Error,
        }
    }
}

/// Normal handovers are continuations, never a nested receive loop. A later
/// target change is read at selection time, not captured in a reconnect future.
#[derive(Default)]
pub struct ConnectContinuation {
    requested: bool,
    resume_after_join: bool,
    observed_initial: bool,
    joined: bool,
    disconnecting: bool,
    routes: Vec<mullvad_types::settings::local_network_access::LocalCidr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectStep {
    Wait,
    Disconnect,
    Select { mode: AttachmentMode, connect: bool },
}

impl ConnectContinuation {
    pub fn joined(&self) -> bool {
        self.observed_initial && self.joined
    }
    #[cfg(any(target_os = "android", test))]
    pub fn connect(&mut self) {
        self.requested = true;
    }
    pub fn disconnect(&mut self) {
        self.requested = false;
        self.resume_after_join = false;
        self.disconnecting = !self.joined;
    }
    pub fn observe(&mut self, phase: TunnelPhase) {
        self.observed_initial = true;
        self.joined = phase == TunnelPhase::Disconnected;
        if self.joined {
            self.disconnecting = false;
        }
    }
    pub fn next(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        supported: bool,
        mode: AttachmentMode,
    ) -> ConnectStep {
        if !self.observed_initial {
            return ConnectStep::Wait;
        }
        let routes = policy.announced_routes();
        let desired = if supported && target == TargetState::Secured && !routes.is_empty() {
            AttachmentMode::ManagedRequired
        } else {
            AttachmentMode::Native
        };
        let changed = mode != desired
            || (desired == AttachmentMode::ManagedRequired && routes != self.routes);
        if !self.joined {
            if !self.disconnecting
                && (self.requested || changed || target == TargetState::Unsecured)
            {
                self.disconnecting = true;
                self.resume_after_join = target == TargetState::Secured;
                ConnectStep::Disconnect
            } else {
                ConnectStep::Wait
            }
        } else if self.requested || self.resume_after_join || changed || routes != self.routes {
            ConnectStep::Select {
                mode: desired,
                connect: target == TargetState::Secured
                    && (self.requested || self.resume_after_join || changed),
            }
        } else {
            ConnectStep::Wait
        }
    }
    pub fn selected(&mut self, policy: &LocalNetworkAccess, connect: bool) {
        self.routes = policy.announced_routes();
        self.requested = false;
        self.resume_after_join = false;
        if connect {
            self.joined = false;
        }
    }
}

#[cfg(test)]
impl From<bool> for TunnelPhase {
    fn from(disconnected: bool) -> Self {
        if disconnected {
            Self::Disconnected
        } else {
            Self::Connecting
        }
    }
}

pub struct LocalNetworkRuntime<F: FrontendFactory = PlatformFactory> {
    feed: Option<Arc<LocalNetworkFeed>>,
    receiver: Option<watch::Receiver<LocalNetworkFeedState>>,
    status: LocalNetworkStatus,
    observation: Option<NetworkObservation>,
    delivery: Delivery<F>,
    shutting_down: bool,
    _buffers: DeliveryBuffers,
    broker: AttachmentBroker,
    broker_updates: watch::Receiver<BrokerSnapshot>,
    release_updates: watch::Receiver<u64>,
    suspended: bool,
    phase: Option<TunnelPhase>,
}

impl LocalNetworkRuntime {
    pub fn new(
        policy: &LocalNetworkAccess,
        feed: Option<Arc<LocalNetworkFeed>>,
        #[cfg(target_os = "android")] platform: Arc<
            talpid_tunnel::tun_provider::local_network::LocalNetworkPlatform,
        >,
    ) -> Self {
        #[cfg(target_os = "android")]
        let (factory, preparer) = (
            PlatformFactory(platform.clone()),
            local_delivery::preparer(platform),
        );
        #[cfg(not(target_os = "android"))]
        let (factory, preparer) = (PlatformFactory, local_delivery::preparer());
        Self::with_factory(policy, feed, factory, preparer)
    }
}

impl<F: FrontendFactory> LocalNetworkRuntime<F> {
    pub(super) fn with_factory(
        policy: &LocalNetworkAccess,
        feed: Option<Arc<LocalNetworkFeed>>,
        factory: F,
        preparer: Arc<SocketPreparer>,
    ) -> Self {
        let receiver = feed.as_ref().and_then(|feed| feed.take_receiver());
        let buffers = DeliveryBuffers::new();
        let broker = AttachmentBroker::new(
            buffers._application.clone(),
            buffers._capture.clone(),
            buffers._control.clone(),
        )
        .expect("fixed runtime broker storage");
        let broker_updates = broker.changes();
        let release_updates = broker.capture_release_changes();
        let mut runtime = Self {
            feed: feed.filter(|_| receiver.is_some()),
            receiver,
            status: LocalNetworkStatus::from_observation(policy, None),
            observation: None,
            delivery: Delivery::new(
                factory,
                Arc::new(DeliveryAuthority::new(policy, preparer)),
                buffers.local.clone(),
            ),
            shutting_down: false,
            _buffers: buffers,
            broker,
            broker_updates,
            release_updates,
            suspended: false,
            phase: None,
        };
        runtime.observation = runtime.observation();
        // Startup reconciles before exposing real delivery availability. Do not
        // project a failed/not-yet-started owner from the constructor.
        runtime.status = LocalNetworkStatus::from_observation(policy, runtime.observation.as_ref());
        // The initial status is an observable sample even on unsupported platforms.
        runtime.status.revision = 1;
        runtime
    }

    pub fn notifications(
        &mut self,
    ) -> (
        impl Future<Output = ()> + Send + '_,
        impl Future<Output = ()> + Send + '_,
        impl Future<Output = ()> + Send + '_,
    ) {
        (
            feed_changed(&mut self.receiver),
            self.delivery.changed(),
            async {
                tokio::select! {
                    _ = self.broker_updates.changed() => {},
                    _ = self.release_updates.changed() => {},
                }
            },
        )
    }

    pub fn status(&self) -> &LocalNetworkStatus {
        &self.status
    }

    fn observation(&self) -> Option<NetworkObservation> {
        self.feed.as_ref().and_then(|feed| {
            let state = feed.latest();
            (!state.closed)
                .then(|| state.latest.as_deref().map(NetworkObservation::from))
                .flatten()
        })
    }

    pub async fn update<P: Into<TunnelPhase>>(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: P,
    ) -> Option<LocalNetworkStatus> {
        self.reconcile(policy, target, phase.into(), true).await
    }

    pub async fn internal_update(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: TunnelPhase,
    ) -> Option<LocalNetworkStatus> {
        self.reconcile(policy, target, phase, false).await
    }

    async fn reconcile(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: TunnelPhase,
        external: bool,
    ) -> Option<LocalNetworkStatus> {
        self.observation = self.observation();
        if self.feed.as_ref().is_some_and(|feed| feed.latest().closed) {
            self.receiver = None;
            self.feed = None;
        }
        self.delivery
            .authority
            .update(policy, self.observation.clone());
        let snapshot = self.broker.snapshot();
        let config = if self.shutting_down {
            None
        } else if target == TargetState::Unsecured && phase == TunnelPhase::Disconnected {
            let routes = policy
                .announced_routes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            (!routes.is_empty()).then_some(DeliveryConfig::Partial(routes))
        } else if target == TargetState::Secured
            && snapshot.mode == AttachmentMode::ManagedRequired
            && matches!(phase, TunnelPhase::Connecting | TunnelPhase::Connected)
        {
            self.broker
                .pending_request()
                .map(|request| DeliveryConfig::Secured {
                    broker: self.broker.clone(),
                    request,
                })
                .or_else(|| {
                    snapshot
                        .capture_generation
                        .and_then(|_| self.delivery.applied_config())
                })
        } else {
            None
        };
        let successor = self.broker.pending_request().is_some()
            && self.delivery.release_ready()
            && !self.delivery.release_failed();
        if !self.shutting_down && (external || !self.delivery.failed() || successor) {
            self.delivery.maintain_config(config).await;
        }
        self.set_endpoint(target, phase);
        self.publish(policy, target, phase)
    }

    pub fn owner_changed<P: Into<TunnelPhase>>(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: P,
    ) -> Option<LocalNetworkStatus> {
        let phase = phase.into();
        self.delivery.owner_changed();
        self.set_endpoint(target, phase);
        self.publish(policy, target, phase)
    }

    fn publish(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: TunnelPhase,
    ) -> Option<LocalNetworkStatus> {
        let mut sample = LocalNetworkStatus::from_observation(policy, self.observation.as_ref())
            .with_forwarding(self.availability(policy, target, phase));
        sample.revision = self.status.revision;
        if sample == self.status {
            return None;
        }
        sample.revision = sample
            .revision
            .checked_add(1)
            .expect("local status revision exhausted");
        self.status = sample.clone();
        Some(sample)
    }

    pub fn has_owner(&self) -> bool {
        self.delivery.has_owner()
    }

    fn set_endpoint(&mut self, target: TargetState, phase: TunnelPhase) {
        let ready = !self.shutting_down
            && ((target == TargetState::Unsecured
                && phase == TunnelPhase::Disconnected
                && self.delivery.partial_ready())
                || (target == TargetState::Secured
                    && phase == TunnelPhase::Connected
                    && self.delivery.managed_ready()
                    && self.broker.snapshot().ordinary_ready));
        if ready {
            self.suspended = false;
        }
        self.delivery.authority.endpoint(ready && !self.suspended);
    }

    fn availability(
        &self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: TunnelPhase,
    ) -> mullvad_types::settings::local_network_access::status::ForwardingAvailability {
        let endpoint = !self.shutting_down
            && ((target == TargetState::Unsecured
                && phase == TunnelPhase::Disconnected
                && self.delivery.partial_ready())
                || (target == TargetState::Secured
                    && phase == TunnelPhase::Connected
                    && self.delivery.managed_ready()
                    && self.broker.snapshot().ordinary_ready));
        let expected_teardown = self.suspended && !self.delivery.release_failed();
        local_delivery::availability(
            self.delivery.supported(),
            policy.enabled,
            !policy.announced_routes().is_empty(),
            endpoint && !self.suspended,
            if expected_teardown {
                None
            } else {
                self.delivery.owner_state()
            },
            self.delivery.failed() && !expected_teardown,
        )
    }

    #[cfg(any(target_os = "android", test))]
    pub fn broker(&self) -> AttachmentBroker {
        self.broker.clone()
    }

    /// Successful TSM spawn supplies a current state, not an initial transition.
    pub fn initialize_transport(&mut self, phase: TunnelPhase) -> ConnectContinuation {
        let mut continuation = ConnectContinuation::default();
        self.observe_transport(&mut continuation, phase);
        continuation
    }

    /// Shared actor continuation: return the actual TSM command only after its
    /// preceding ownership stage has completed. The daemon sends it and returns
    /// to its normal event select; tests exercise this same boundary.
    pub async fn continue_connect(
        &mut self,
        continuation: &mut ConnectContinuation,
        policy: &LocalNetworkAccess,
        target: TargetState,
    ) -> std::io::Result<Option<talpid_core::tunnel_state_machine::TunnelCommand>> {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        if self.is_shutting_down() {
            return Ok(None);
        }
        match continuation.next(
            policy,
            target,
            self.supported(),
            self.broker.snapshot().mode,
        ) {
            ConnectStep::Wait => Ok(None),
            ConnectStep::Disconnect => {
                self.suspend();
                Ok(Some(TunnelCommand::Disconnect))
            }
            ConnectStep::Select { mode, connect } => {
                self.stop().await?;
                let routes = policy
                    .announced_routes()
                    .iter()
                    .map(|cidr| cidr.network())
                    .collect();
                if let Err(error) = self
                    .broker
                    .set_mode(mode)
                    .and_then(|()| self.broker.set_local_routes(routes))
                {
                    self.selection_failed();
                    return Err(std::io::Error::other(format!(
                        "Transport selection refused: {error:?}"
                    )));
                }
                continuation.selected(policy, connect);
                Ok(connect.then_some(TunnelCommand::Connect))
            }
        }
    }

    pub fn observe_transport(
        &mut self,
        continuation: &mut ConnectContinuation,
        phase: TunnelPhase,
    ) {
        if phase == TunnelPhase::Disconnected
            || (self.phase == Some(TunnelPhase::Disconnecting)
                && phase != TunnelPhase::Disconnecting)
        {
            // TSM emits the next state only after its tunnel-close future joins.
            // This acknowledges the old applied request, never its successor.
            self.delivery.transport_joined();
        } else if phase == TunnelPhase::Disconnecting {
            self.delivery.defer_release();
        }
        self.phase = Some(phase);
        continuation.observe(phase);
    }

    pub fn request_disconnect(
        &mut self,
        continuation: &mut ConnectContinuation,
    ) -> talpid_core::tunnel_state_machine::TunnelCommand {
        continuation.disconnect();
        self.suspend();
        talpid_core::tunnel_state_machine::TunnelCommand::Disconnect
    }

    pub fn supported(&self) -> bool {
        self.delivery.supported()
    }
    pub fn failed(&self) -> bool {
        self.delivery.failed()
    }
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    pub fn suspend(&mut self) {
        self.suspended = true;
        self.delivery.defer_release();
        self.delivery.authority.endpoint(false);
        self.broker.pause_transport();
        if self.phase == Some(TunnelPhase::Disconnected) {
            self.delivery.transport_joined();
        }
    }

    pub fn selection_failed(&mut self) {
        self.suspended = false;
        self.delivery.fail();
    }

    pub fn begin_shutdown(&mut self) {
        if self.shutting_down {
            return;
        }
        self.shutting_down = true;
        self.suspended = true;
        self.delivery.defer_release();
        self.delivery.authority.revoke();
        // Preserve provider selection through joined TSM close, including Native.
        self.broker.pause_transport();
        if self.phase == Some(TunnelPhase::Disconnected) {
            self.delivery.transport_joined();
        }
    }

    pub async fn stop(&mut self) -> std::io::Result<()> {
        self.delivery.stop().await
    }

    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.begin_shutdown();
        if !self.delivery.release_ready() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Transport teardown is not joined",
            ));
        }
        self.broker.close();
        self.delivery.stop().await
    }
}

async fn feed_changed(receiver: &mut Option<watch::Receiver<LocalNetworkFeedState>>) {
    match receiver {
        Some(active) => {
            if active.changed().await.is_err() {
                *receiver = None;
            }
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mullvad_types::settings::local_network_access::{
        LocalBypassRule,
        status::{InactiveReason, RuleState},
    };
    use talpid_types::local_network::LocalNetworkSnapshot;

    fn policy() -> LocalNetworkAccess {
        LocalNetworkAccess {
            enabled: true,
            rules: vec![LocalBypassRule {
                id: "00000000-0000-0000-0000-000000000000".parse().unwrap(),
                name: String::new(),
                enabled: true,
                cidrs: vec!["10.0.0.0/8".parse().unwrap()],
                ssid_ids: vec![],
            }],
        }
    }

    #[test]
    fn mode_handover_waits_for_observed_join_and_latest_disconnect_wins() {
        use AttachmentMode::*;
        use ConnectStep::*;
        let mut intent = ConnectContinuation::default();
        intent.connect();
        assert_eq!(
            intent.next(&policy(), TargetState::Secured, true, Native),
            Wait
        );
        intent.observe(TunnelPhase::Disconnected);
        assert_eq!(
            intent.next(&policy(), TargetState::Secured, true, Native),
            Select {
                mode: ManagedRequired,
                connect: true
            }
        );
        intent.selected(&policy(), true);
        intent.observe(TunnelPhase::Connecting);
        assert_eq!(
            intent.next(&policy(), TargetState::Secured, true, ManagedRequired),
            Wait
        );
        intent.observe(TunnelPhase::Connected);
        let off = LocalNetworkAccess::default();
        assert_eq!(
            intent.next(&off, TargetState::Secured, true, ManagedRequired),
            Disconnect
        );
        // Every ordinary event can update intent while the TSM is tearing down.
        // Coalescing back to Managed does not authorize early selection.
        intent.connect();
        assert_eq!(
            intent.next(&policy(), TargetState::Secured, true, ManagedRequired),
            Wait
        );
        intent.observe(TunnelPhase::Disconnecting);
        intent.disconnect();
        assert_eq!(
            intent.next(&off, TargetState::Unsecured, true, ManagedRequired),
            Wait
        );
        intent.observe(TunnelPhase::Disconnected);
        assert_eq!(
            intent.next(&off, TargetState::Unsecured, true, ManagedRequired),
            Select {
                mode: Native,
                connect: false
            }
        );
        intent.selected(&off, false);
        assert_eq!(
            intent.next(&off, TargetState::Unsecured, true, Native),
            Wait
        );
    }

    #[tokio::test]
    async fn shutdown_preserves_native_close_selection_until_tsm_join() {
        let mut runtime = LocalNetworkRuntime::new(&LocalNetworkAccess::default(), None);
        let broker = runtime.broker();
        runtime.begin_shutdown();
        assert_eq!(broker.snapshot().mode, AttachmentMode::Native);
        assert!(!broker.snapshot().closed);
        let closed = std::cell::Cell::new(false);
        talpid_tunnel::tun_provider::transport::TransportMode::selected(Some(&broker))
            .close(|| closed.set(true));
        assert!(
            closed.get(),
            "Native's close callback must not become managed detach"
        );
        runtime.shutdown().await.unwrap();
        assert!(broker.snapshot().closed);
    }

    #[test]
    fn native_managed_startup_last_rule_routes_and_conditions_use_one_choke_point() {
        use AttachmentMode::*;
        use ConnectStep::*;
        for enabled in [false, true] {
            let mut configured = policy();
            configured.enabled = enabled;
            let expected = if enabled { ManagedRequired } else { Native };
            let mut intent = ConnectContinuation::default();
            intent.observe(TunnelPhase::Disconnected);
            intent.connect();
            assert_eq!(
                intent.next(&configured, TargetState::Secured, true, Native),
                Select {
                    mode: expected,
                    connect: true
                }
            );
            intent.selected(&configured, true);
            intent.observe(TunnelPhase::Connected);
            let mut conditions = configured.clone();
            conditions.rules[0].name = "renamed".into();
            conditions.rules[0].ssid_ids.push(
                mullvad_types::settings::local_network_access::SsidIdentity::from_bytes(
                    b"other".to_vec(),
                )
                .unwrap(),
            );
            assert_eq!(
                intent.next(&conditions, TargetState::Secured, true, expected),
                Wait
            );
            configured.enabled = !enabled;
            assert_eq!(
                intent.next(&configured, TargetState::Secured, true, expected),
                Disconnect
            );
            intent.observe(TunnelPhase::Disconnected);
            let replacement = if enabled { Native } else { ManagedRequired };
            assert_eq!(
                intent.next(&configured, TargetState::Secured, true, expected),
                Select {
                    mode: replacement,
                    connect: true
                }
            );
            intent.selected(&configured, true);
            intent.observe(TunnelPhase::Connected);
            configured.enabled = true;
            configured.rules.clear();
            if !enabled {
                assert_eq!(
                    intent.next(&configured, TargetState::Secured, true, replacement),
                    Disconnect
                );
            }
        }
        let mut intent = ConnectContinuation::default();
        intent.observe(TunnelPhase::Disconnected);
        intent.connect();
        intent.selected(&policy(), true);
        intent.observe(TunnelPhase::Connected);
        let mut routes = policy();
        routes.rules[0].cidrs = vec!["172.16.0.0/16".parse().unwrap()];
        assert_eq!(
            intent.next(&routes, TargetState::Secured, true, ManagedRequired),
            Disconnect
        );
    }

    #[tokio::test]
    async fn feed_notifications_and_settings_share_one_semantic_revision_owner() {
        let feed = LocalNetworkFeed::new(1);
        let mut policy = policy();
        let mut runtime = LocalNetworkRuntime::new(&policy, Some(feed.clone()));
        assert!(!runtime.status().observer_available);
        assert_eq!(
            runtime.status().rules[0].state,
            RuleState::Inactive(InactiveReason::ObserverUnavailable)
        );
        let first = runtime.status().revision;
        feed.publish(
            1,
            LocalNetworkSnapshot {
                sequence: 1,
                observer_running: true,
                local_ready: true,
                ..Default::default()
            },
        );
        runtime.notifications().0.await;
        let changed = runtime
            .update(&policy, TargetState::Unsecured, true)
            .await
            .unwrap();
        assert_eq!(changed.revision, first + 1);
        assert_eq!(
            changed.rules[0].state,
            RuleState::Inactive(InactiveReason::NoEligibleNetwork)
        );
        feed.publish(
            1,
            LocalNetworkSnapshot {
                sequence: 2,
                observer_running: true,
                local_ready: true,
                ..Default::default()
            },
        );
        runtime.notifications().0.await;
        assert!(
            runtime
                .update(&policy, TargetState::Unsecured, true)
                .await
                .is_none()
        );
        assert_eq!(runtime.status(), &changed);
        policy.enabled = false;
        assert_eq!(
            runtime
                .update(&policy, TargetState::Unsecured, true)
                .await
                .unwrap()
                .revision,
            first + 2
        );
        assert!(
            runtime
                .update(&policy, TargetState::Unsecured, true)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn closed_feed_discards_observations_and_publishes_unavailable_once() {
        let feed = LocalNetworkFeed::new(1);
        let mut runtime = LocalNetworkRuntime::new(&policy(), Some(feed.clone()));
        feed.publish(
            1,
            LocalNetworkSnapshot {
                sequence: 1,
                observer_running: true,
                ..Default::default()
            },
        );
        runtime
            .update(&policy(), TargetState::Unsecured, true)
            .await;
        feed.close();
        runtime.notifications().0.await;
        let status = runtime
            .update(&policy(), TargetState::Unsecured, true)
            .await
            .unwrap();
        assert!(!status.observer_available);
        assert_eq!(
            status.rules[0].state,
            RuleState::Inactive(InactiveReason::ObserverUnavailable)
        );
        assert!(
            runtime
                .update(&policy(), TargetState::Unsecured, true)
                .await
                .is_none()
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                runtime.notifications().0
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn unsupported_platform_returns_a_stable_unavailable_status() {
        let mut runtime = LocalNetworkRuntime::new(&policy(), None);
        assert_eq!(runtime.status().revision, 1);
        assert!(!runtime.status().observer_available);
        assert!(
            runtime
                .update(&policy(), TargetState::Unsecured, true)
                .await
                .is_none()
        );
    }
}
