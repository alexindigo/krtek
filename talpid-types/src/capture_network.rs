//! Capture-owned VPN observations, separate from physical-network eligibility.
//! A generation is retired synchronously on mismatch/loss, before notifying its
//! async owner. No platform/JNI work is performed while holding the feed lock.
#[cfg(target_os = "android")]
use jnix::FromJava;
use std::{
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(
    target_os = "android",
    jnix(class_name = "net.mullvad.talpid.model.InetNetwork")
)]
pub struct CapturePrefix {
    pub address: IpAddr,
    pub prefix_length: i16,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct CaptureRoute {
    pub destination: CapturePrefix,
    pub gateway: Option<IpAddr>,
    pub interface_name: String,
    pub route_type: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct CaptureNetworkObservation {
    pub network_handle: i64,
    pub network: String,
    pub interface_name: String,
    pub owner_uid: Option<i32>,
    pub routes: Vec<CaptureRoute>,
    pub addresses: Vec<CapturePrefix>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<i32>,
    pub fresh: bool,
    pub lost: bool,
    pub api_level: i32,
}

#[derive(Clone, Debug)]
pub struct CaptureExpectation {
    pub interface_name: String,
    pub owner_uid: Option<i32>,
    pub api_level: i32,
    pub routes: Vec<CaptureRoute>,
    pub addresses: Vec<CapturePrefix>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<i32>,
}

impl CaptureExpectation {
    /// Android Vpn.makeLinkProperties binds every route to the interface and
    /// adds an unreachable default only for a completely unconfigured family.
    /// ConnectivityService.processLinkPropertiesFromAgent then calls
    /// LinkProperties.ensureDirectlyConnectedRoutes for each interface address.
    /// No other routes are permitted by this projection.
    pub fn requested(
        interface_name: String,
        owner_uid: i32,
        api_level: i32,
        addresses: &[IpAddr],
        routes: &[CapturePrefix],
        dns_servers: &[IpAddr],
        mtu: u16,
    ) -> Option<Self> {
        if interface_name.is_empty()
            || owner_uid < 0
            || api_level < 28
            || addresses.is_empty()
            || mtu < 1280
        {
            return None;
        }
        let addresses: Vec<_> = addresses
            .iter()
            .map(|ip| CapturePrefix {
                address: *ip,
                prefix_length: if ip.is_ipv4() { 32 } else { 128 },
            })
            .collect();
        let mut projected = Vec::new();
        for prefix in routes.iter().chain(&addresses) {
            let bits = u8::try_from(prefix.prefix_length).ok()?;
            let network = ipnetwork::IpNetwork::new(prefix.address, bits).ok()?;
            if network.network() != prefix.address {
                return None;
            }
            projected.push(CaptureRoute {
                destination: prefix.clone(),
                gateway: None,
                interface_name: interface_name.clone(),
                route_type: (api_level >= 33).then_some(1),
            });
        }
        for unspecified in [
            IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED),
            IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED),
        ] {
            let configured = addresses
                .iter()
                .chain(routes)
                .any(|p| p.address.is_ipv4() == unspecified.is_ipv4())
                || dns_servers
                    .iter()
                    .any(|ip| ip.is_ipv4() == unspecified.is_ipv4());
            if !configured {
                projected.push(CaptureRoute {
                    destination: CapturePrefix {
                        address: unspecified,
                        prefix_length: 0,
                    },
                    gateway: None,
                    interface_name: interface_name.clone(),
                    route_type: (api_level >= 33).then_some(7),
                });
            }
        }
        projected.sort();
        projected.dedup();
        Some(Self {
            interface_name,
            owner_uid: (api_level >= 30).then_some(owner_uid),
            api_level,
            routes: projected,
            addresses,
            dns_servers: dns_servers.to_vec(),
            mtu: (api_level >= 29).then_some(i32::from(mtu)),
        })
    }

    fn matches(&self, observation: &CaptureNetworkObservation) -> bool {
        fn same_set<T: Ord + Clone>(a: &[T], b: &[T]) -> bool {
            let mut a = a.to_vec();
            let mut b = b.to_vec();
            a.sort();
            b.sort();
            a.dedup();
            b.dedup();
            a == b
        }
        observation.fresh
            && !observation.lost
            && observation.api_level == self.api_level
            && observation.owner_uid == self.owner_uid
            && observation.interface_name == self.interface_name
            && observation.mtu == self.mtu
            && same_set(&self.routes, &observation.routes)
            && same_set(&self.addresses, &observation.addresses)
            && same_set(&self.dns_servers, &observation.dns_servers)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureNetworkState {
    Pending,
    Ready(Arc<CaptureNetworkObservation>),
    Lost,
}

struct Generation {
    id: i64,
    expected: Option<CaptureExpectation>,
    handle: Option<i64>,
    revoke: Option<Arc<dyn Fn() + Send + Sync>>,
    state: watch::Sender<CaptureNetworkState>,
}

struct State {
    closed: bool,
    last_generation: i64,
    generation: Option<Generation>,
}

pub struct CaptureNetworkFeed {
    registration: i64,
    state: Mutex<State>,
}

impl CaptureNetworkFeed {
    pub fn new(registration: i64) -> Arc<Self> {
        Arc::new(Self {
            registration,
            state: Mutex::new(State {
                closed: registration <= 0,
                last_generation: 0,
                generation: None,
            }),
        })
    }

    pub fn registration(&self) -> i64 {
        self.registration
    }

    pub fn register<E>(&self, attach: impl FnOnce(i64) -> Result<bool, E>) -> bool {
        let attached = !self.state.lock().expect("capture feed").closed
            && matches!(
                catch_unwind(AssertUnwindSafe(|| attach(self.registration))),
                Ok(Ok(true))
            );
        if !attached {
            self.close();
        }
        attached
    }

    /// Called before platform opening. A replacement cannot supersede an owner
    /// that still owes cleanup; invalidate must precede platform release.
    pub fn begin(&self, id: i64) -> Option<watch::Receiver<CaptureNetworkState>> {
        let mut state = self.state.lock().expect("capture feed");
        if state.closed || id <= state.last_generation || state.generation.is_some() {
            return None;
        }
        state.last_generation = id;
        let (sender, receiver) = watch::channel(CaptureNetworkState::Pending);
        state.generation = Some(Generation {
            id,
            expected: None,
            handle: None,
            revoke: None,
            state: sender,
        });
        Some(receiver)
    }

    /// After descriptor adoption and the borrowed TUNGETIFF query. Observations
    /// received before binding cannot acknowledge readiness or pin a handle.
    pub fn bind(&self, id: i64, expected: CaptureExpectation) -> bool {
        let mut state = self.state.lock().expect("capture feed");
        let Some(generation) = state.generation.as_mut().filter(|g| g.id == id) else {
            return false;
        };
        if generation.expected.is_some() || expected.interface_name.is_empty() {
            return false;
        }
        generation.expected = Some(expected);
        true
    }

    /// Issue the receipt and install its synchronous revoker in one feed turn.
    /// The operation may only bind/acknowledge native capabilities, never JNI,
    /// await, or reenter this feed. Publication cannot slip between them.
    pub fn acknowledge<T>(
        &self,
        id: i64,
        revoke: Arc<dyn Fn() + Send + Sync>,
        operation: impl FnOnce(&CaptureNetworkObservation) -> T,
    ) -> Option<T> {
        let mut state = self.state.lock().expect("capture feed");
        let generation = state.generation.as_mut().filter(|g| g.id == id)?;
        if generation.revoke.is_some() {
            return None;
        }
        let observation = match &*generation.state.borrow() {
            CaptureNetworkState::Ready(observation) => observation.clone(),
            _ => return None,
        };
        let result = operation(&observation);
        generation.revoke = Some(revoke);
        Some(result)
    }

    pub fn publish(
        &self,
        registration: i64,
        id: i64,
        mut observation: CaptureNetworkObservation,
    ) -> bool {
        if registration != self.registration {
            return false;
        }
        observation.routes.sort();
        observation.routes.dedup();
        observation.addresses.sort();
        observation.addresses.dedup();
        observation.dns_servers.sort();
        observation.dns_servers.dedup();
        let mut state = self.state.lock().expect("capture feed");
        let Some(generation) = state.generation.as_mut().filter(|g| g.id == id) else {
            return false;
        };
        // Registration/publication failures have no usable network identity.
        // They still retire their exact generation, including before fd binding.
        if observation.lost && observation.network_handle == 0 {
            Self::revoke(generation);
            return Self::set_state(generation, CaptureNetworkState::Lost);
        }
        let Some(expected) = &generation.expected else {
            return false;
        };
        if matches!(*generation.state.borrow(), CaptureNetworkState::Lost) {
            return false;
        }
        if let Some(handle) = generation.handle {
            if handle != observation.network_handle {
                return false;
            }
        } else {
            if observation.interface_name != expected.interface_name
                || observation.api_level != expected.api_level
                || observation.owner_uid != expected.owner_uid
                || !observation.fresh
                || observation.lost
                || observation.network_handle == 0
            {
                return false;
            }
            generation.handle = Some(observation.network_handle);
        }
        let next = if expected.matches(&observation) {
            CaptureNetworkState::Ready(Arc::new(observation))
        } else {
            Self::revoke(generation);
            CaptureNetworkState::Lost
        };
        Self::set_state(generation, next)
    }

    fn set_state(generation: &Generation, next: CaptureNetworkState) -> bool {
        generation.state.send_if_modified(|previous| {
            if *previous == next {
                false
            } else {
                *previous = next;
                true
            }
        })
    }

    fn revoke(generation: &mut Generation) {
        if let Some(revoke) = generation.revoke.take() {
            revoke();
        }
    }

    /// Serialize the final nonblocking Local sink operation with observation
    /// revocation. No JNI, await or feed reentry is permitted in the callback.
    pub fn with_ready<T>(&self, id: i64, operation: impl FnOnce() -> T) -> Option<T> {
        let state = self.state.lock().expect("capture feed");
        let generation = state.generation.as_ref().filter(|g| g.id == id)?;
        if !matches!(*generation.state.borrow(), CaptureNetworkState::Ready(_)) {
            return None;
        }
        Some(operation())
    }

    pub fn invalidate(&self, id: i64) {
        let mut state = self.state.lock().expect("capture feed");
        if state.generation.as_ref().is_some_and(|g| g.id == id) {
            let mut generation = state.generation.take().expect("matched generation");
            Self::revoke(&mut generation);
            Self::set_state(&generation, CaptureNetworkState::Lost);
        }
    }

    pub fn close(&self) {
        let mut state = self.state.lock().expect("capture feed");
        state.closed = true;
        if let Some(mut generation) = state.generation.take() {
            Self::revoke(&mut generation);
            Self::set_state(&generation, CaptureNetworkState::Lost);
        }
    }
}

#[cfg(test)]
mod tests;
