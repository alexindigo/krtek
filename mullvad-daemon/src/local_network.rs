//! Single actor-owned authority, frontend lifecycle and semantic status publisher.
use crate::local_delivery::{
    self, Delivery, DeliveryAuthority, FrontendFactory, PlatformFactory, SocketPreparer,
};
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess, eligibility::NetworkObservation, status::LocalNetworkStatus,
};
use mullvad_types::states::TargetState;
use std::sync::Arc;
use talpid_types::local_network::{LocalNetworkFeed, LocalNetworkFeedState};
use tokio::sync::watch;

pub struct LocalNetworkRuntime<F: FrontendFactory = PlatformFactory> {
    feed: Option<Arc<LocalNetworkFeed>>,
    receiver: Option<watch::Receiver<LocalNetworkFeedState>>,
    status: LocalNetworkStatus,
    observation: Option<NetworkObservation>,
    delivery: Delivery<F>,
    shutting_down: bool,
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
        let mut runtime = Self {
            feed: feed.filter(|_| receiver.is_some()),
            receiver,
            status: LocalNetworkStatus::from_observation(policy, None),
            observation: None,
            delivery: Delivery::new(factory, Arc::new(DeliveryAuthority::new(policy, preparer))),
            shutting_down: false,
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
    ) {
        (feed_changed(&mut self.receiver), self.delivery.changed())
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

    pub async fn update(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) -> Option<LocalNetworkStatus> {
        self.observation = self.observation();
        if self.feed.as_ref().is_some_and(|feed| feed.latest().closed) {
            self.receiver = None;
            self.feed = None;
        }
        self.delivery
            .authority
            .update(policy, self.observation.clone());
        self.delivery
            .maintain(policy, target, disconnected && !self.shutting_down)
            .await;
        self.publish(policy, target, disconnected)
    }

    pub fn owner_changed(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) -> Option<LocalNetworkStatus> {
        self.delivery.owner_changed();
        self.publish(policy, target, disconnected)
    }

    fn publish(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) -> Option<LocalNetworkStatus> {
        let mut sample = LocalNetworkStatus::from_observation(policy, self.observation.as_ref())
            .with_forwarding(self.delivery.availability(policy, target, disconnected));
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

    pub async fn stop(&mut self) -> std::io::Result<()> {
        self.delivery.stop().await
    }

    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.shutting_down = true;
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
