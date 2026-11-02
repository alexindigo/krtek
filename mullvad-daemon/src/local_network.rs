//! Single actor-owned status publisher over the core's latest observation.
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess,
    eligibility::NetworkObservation,
    status::{ForwardingAvailability, LocalNetworkStatus},
};
use std::sync::Arc;
use talpid_types::local_network::{LocalNetworkFeed, LocalNetworkFeedState};
use tokio::sync::watch;

pub struct LocalNetworkRuntime {
    feed: Option<Arc<LocalNetworkFeed>>,
    receiver: Option<watch::Receiver<LocalNetworkFeedState>>,
    status: LocalNetworkStatus,
}

impl LocalNetworkRuntime {
    pub fn new(policy: &LocalNetworkAccess, feed: Option<Arc<LocalNetworkFeed>>) -> Self {
        let receiver = feed.as_ref().and_then(|feed| feed.take_receiver());
        let mut runtime = Self {
            feed: feed.filter(|_| receiver.is_some()),
            receiver,
            status: LocalNetworkStatus::from_observation(policy, None),
        };
        runtime.update(policy);
        // The initial status is an observable sample even on unsupported platforms.
        runtime.status.revision = 1;
        runtime
    }

    pub async fn changed(&mut self) {
        match &mut self.receiver {
            Some(receiver) => {
                if receiver.changed().await.is_err() {
                    self.receiver = None;
                    self.feed = None;
                }
            }
            None => std::future::pending().await,
        }
    }

    pub fn status(&self) -> &LocalNetworkStatus {
        &self.status
    }

    pub fn update(&mut self, policy: &LocalNetworkAccess) -> Option<LocalNetworkStatus> {
        let observation = self.feed.as_ref().and_then(|feed| {
            let state = feed.latest();
            (!state.closed).then(|| {
                state
                    .latest
                    .as_deref()
                    .map(NetworkObservation::from)
                    .unwrap_or_default()
            })
        });
        let mut sample = LocalNetworkStatus::from_observation(policy, observation.as_ref())
            .with_forwarding(ForwardingAvailability::NotAvailable);
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
        assert!(runtime.status().observer_available);
        assert_eq!(
            runtime.status().rules[0].state,
            RuleState::Inactive(InactiveReason::WaitingForNetworkDetails)
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
        runtime.changed().await;
        let changed = runtime.update(&policy).unwrap();
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
        runtime.changed().await;
        assert!(runtime.update(&policy).is_none());
        assert_eq!(runtime.status(), &changed);
        policy.enabled = false;
        assert_eq!(runtime.update(&policy).unwrap().revision, first + 2);
        assert!(runtime.update(&policy).is_none());
    }

    #[tokio::test]
    async fn closed_feed_discards_observations_and_publishes_unavailable_once() {
        let feed = LocalNetworkFeed::new(1);
        let mut runtime = LocalNetworkRuntime::new(&policy(), Some(feed.clone()));
        feed.close();
        runtime.changed().await;
        let status = runtime.update(&policy()).unwrap();
        assert!(!status.observer_available);
        assert_eq!(
            status.rules[0].state,
            RuleState::Inactive(InactiveReason::ObserverUnavailable)
        );
        assert!(runtime.update(&policy()).is_none());
    }

    #[test]
    fn unsupported_platform_returns_a_stable_unavailable_status() {
        let mut runtime = LocalNetworkRuntime::new(&policy(), None);
        assert_eq!(runtime.status().revision, 1);
        assert!(!runtime.status().observer_available);
        assert!(runtime.update(&policy()).is_none());
    }
}
