//! Runtime-only Android observations and a latest-value feed. Never persist these records.
#[cfg(target_os = "android")]
use jnix::FromJava;
use std::{
    fmt,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Clone, Default, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalNetworkSnapshot {
    pub sequence: i64,
    pub observer_running: bool,
    pub local_ready: bool,
    pub fine_ready: bool,
    pub background_ready: bool,
    pub location_enabled: bool,
    pub location_allowed: bool,
    pub networks: Vec<LocalPhysicalNetwork>,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalPhysicalNetwork {
    pub network_handle: i64,
    pub transport: i32,
    pub capabilities_fresh: bool,
    pub links_fresh: bool,
    pub blocked: bool,
    pub interface_index: i32,
    pub addresses: Vec<LocalPhysicalAddress>,
    pub routes: Vec<LocalPhysicalRoute>,
    pub ssid_hex: Option<String>,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalPhysicalAddress {
    pub prefix: LocalPhysicalPrefix,
    pub usable: bool,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalPhysicalRoute {
    pub destination: LocalPhysicalPrefix,
    pub gateway: Option<IpAddr>,
    pub interface_index: i32,
    pub route_type: i32,
}

/// The existing Kotlin InetNetwork representation, with observation-safe diagnostics.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(
    target_os = "android",
    jnix(class_name = "net.mullvad.talpid.model.InetNetwork")
)]
pub struct LocalPhysicalPrefix {
    pub address: IpAddr,
    pub prefix_length: i16,
}

impl fmt::Debug for LocalNetworkSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalNetworkSnapshot")
            .field("sequence", &self.sequence)
            .field("observer_running", &self.observer_running)
            .field("network_count", &self.networks.len())
            .finish()
    }
}

impl fmt::Debug for LocalPhysicalNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPhysicalNetwork")
            .field("transport", &self.transport)
            .field("address_count", &self.addresses.len())
            .field("route_count", &self.routes.len())
            .finish()
    }
}

impl fmt::Debug for LocalPhysicalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPhysicalAddress(redacted)")
    }
}

impl fmt::Debug for LocalPhysicalRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPhysicalRoute")
            .field("route_type", &self.route_type)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LocalPhysicalPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPhysicalPrefix(redacted)")
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalNetworkFeedState {
    pub latest: Option<Arc<LocalNetworkSnapshot>>,
    pub closed: bool,
}

/// One replaceable record, one notification receiver; no per-observation queue.
#[derive(Debug)]
pub struct LocalNetworkFeed {
    registration: i64,
    sender: watch::Sender<LocalNetworkFeedState>,
    receiver: Mutex<Option<watch::Receiver<LocalNetworkFeedState>>>,
}

impl LocalNetworkFeed {
    pub fn new(registration: i64) -> Arc<Self> {
        let (sender, receiver) = watch::channel(LocalNetworkFeedState {
            closed: registration <= 0,
            ..LocalNetworkFeedState::default()
        });
        Arc::new(Self {
            registration,
            sender,
            receiver: Mutex::new(Some(receiver)),
        })
    }

    pub fn registration(&self) -> i64 {
        self.registration
    }

    pub fn latest(&self) -> LocalNetworkFeedState {
        self.sender.borrow().clone()
    }

    /// The daemon owns this receiver. Clones of the feed cannot claim a second one.
    pub fn take_receiver(&self) -> Option<watch::Receiver<LocalNetworkFeedState>> {
        self.receiver.lock().unwrap().take()
    }

    /// Optional platform registration never prevents its caller from starting the daemon.
    /// jnix's preload/conversion APIs panic on missing Java classes, hence this boundary.
    pub fn register<E>(&self, attach: impl FnOnce(i64) -> Result<bool, E>) -> bool {
        let attached = self.registration > 0
            && !self.latest().closed
            && matches!(
                catch_unwind(AssertUnwindSafe(|| attach(self.registration))),
                Ok(Ok(true))
            );
        if !attached {
            self.close();
        }
        attached
    }

    pub fn publish(&self, registration: i64, snapshot: LocalNetworkSnapshot) -> bool {
        if registration != self.registration || snapshot.sequence <= 0 {
            return false;
        }
        self.sender.send_if_modified(|state| {
            if state.closed
                || state
                    .latest
                    .as_ref()
                    .is_some_and(|previous| previous.sequence >= snapshot.sequence)
            {
                return false;
            }
            if snapshot.observer_running {
                state.latest = Some(Arc::new(snapshot));
            } else {
                state.latest = None;
                state.closed = true;
            }
            true
        })
    }

    pub fn close(&self) {
        self.sender.send_if_modified(|state| {
            if state.closed {
                return false;
            }
            state.latest = None;
            state.closed = true;
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(sequence: i64) -> LocalNetworkSnapshot {
        LocalNetworkSnapshot {
            sequence,
            observer_running: true,
            ..LocalNetworkSnapshot::default()
        }
    }

    #[test]
    fn latest_record_and_single_receiver_coalesce_notifications() {
        let feed = LocalNetworkFeed::new(7);
        let mut receiver = feed.take_receiver().unwrap();
        assert!(feed.take_receiver().is_none());
        for sequence in 1..=100 {
            assert!(feed.publish(7, snapshot(sequence)));
        }
        assert!(receiver.has_changed().unwrap());
        assert_eq!(
            receiver
                .borrow_and_update()
                .latest
                .as_ref()
                .unwrap()
                .sequence,
            100
        );
        assert!(!receiver.has_changed().unwrap());
        assert_eq!(feed.latest().latest.unwrap().sequence, 100);
    }

    #[test]
    fn stale_registration_and_nonincreasing_sequences_are_ignored() {
        let feed = LocalNetworkFeed::new(7);
        let mut receiver = feed.take_receiver().unwrap();
        assert!(feed.publish(7, snapshot(2)));
        receiver.borrow_and_update();
        assert!(!feed.publish(6, snapshot(3)));
        assert!(!feed.publish(7, snapshot(0)));
        assert!(!feed.publish(7, snapshot(1)));
        assert!(!feed.publish(7, snapshot(2)));
        assert_eq!(feed.latest().latest.unwrap().sequence, 2);
        assert!(!receiver.has_changed().unwrap());
    }

    #[test]
    fn close_discards_private_record_notifies_once_and_cannot_reopen() {
        let feed = LocalNetworkFeed::new(7);
        let mut receiver = feed.take_receiver().unwrap();
        feed.publish(7, snapshot(1));
        receiver.borrow_and_update();
        feed.close();
        assert!(receiver.has_changed().unwrap());
        assert!(receiver.borrow_and_update().closed);
        assert!(feed.latest().latest.is_none());
        feed.close();
        assert!(!feed.publish(7, snapshot(2)));
        assert!(!receiver.has_changed().unwrap());
    }

    #[test]
    fn attach_error_returns_control_to_startup_with_a_closed_feed() {
        let feed = LocalNetworkFeed::new(7);
        let mut steps = vec!["registration"];
        let ready = feed.register(|registration| {
            assert_eq!(registration, 7);
            Err::<bool, _>("fake attach failed")
        });
        steps.push("daemon startup");
        assert_eq!(steps, ["registration", "daemon startup"]);
        assert!(!ready);
        assert!(feed.latest().closed);
        assert!(!feed.publish(7, snapshot(1)));
    }

    #[test]
    fn refused_or_panicking_registration_closes_but_success_stays_open() {
        let refused = LocalNetworkFeed::new(7);
        assert!(!refused.register(|_| Ok::<_, ()>(false)));
        assert!(refused.latest().closed);
        let panicking = LocalNetworkFeed::new(8);
        assert!(!panicking.register(|_| -> Result<bool, ()> { panic!("missing Java class") }));
        assert!(panicking.latest().closed);
        let ready = LocalNetworkFeed::new(9);
        assert!(ready.register(|_| Ok::<_, ()>(true)));
        assert!(!ready.latest().closed);
    }

    #[test]
    fn stopped_observation_and_invalid_registration_are_unavailable() {
        let feed = LocalNetworkFeed::new(7);
        feed.publish(7, snapshot(1));
        assert!(feed.publish(
            7,
            LocalNetworkSnapshot {
                sequence: 2,
                ..LocalNetworkSnapshot::default()
            }
        ));
        assert!(feed.latest().closed);
        assert!(feed.latest().latest.is_none());
        assert!(!feed.publish(7, snapshot(3)));
        let invalid = LocalNetworkFeed::new(0);
        assert!(!invalid.register(|_| -> Result<bool, ()> { panic!("must not attach") }));
        assert!(invalid.latest().closed);
    }

    #[test]
    fn every_observation_debug_and_feed_debug_redacts_identity_and_addresses() {
        let prefix = LocalPhysicalPrefix {
            address: "192.0.2.42".parse().unwrap(),
            prefix_length: 24,
        };
        let address = LocalPhysicalAddress {
            prefix: prefix.clone(),
            usable: true,
        };
        let route = LocalPhysicalRoute {
            destination: prefix.clone(),
            gateway: Some("192.0.2.1".parse().unwrap()),
            interface_index: 4,
            route_type: 1,
        };
        let network = LocalPhysicalNetwork {
            network_handle: 9,
            transport: 1,
            capabilities_fresh: true,
            links_fresh: true,
            blocked: false,
            interface_index: 4,
            addresses: vec![address.clone()],
            routes: vec![route.clone()],
            ssid_hex: Some("736563726574".into()),
        };
        let snapshot = LocalNetworkSnapshot {
            networks: vec![network.clone()],
            ..snapshot(1)
        };
        let feed = LocalNetworkFeed::new(7);
        feed.publish(7, snapshot.clone());
        let output = format!(
            "{prefix:?} {address:?} {route:?} {network:?} {snapshot:?} {feed:?} {:?}",
            feed.latest()
        );
        for secret in ["192.0.2.42", "192.0.2.1", "736563726574", "secret"] {
            assert!(!output.contains(secret));
        }
    }
}
