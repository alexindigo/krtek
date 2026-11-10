//! Android userspace transport selection, before any native descriptor operation.
use super::TunConfig;
use crate::packet_attachment::{
    AttachmentBroker, AttachmentError, AttachmentMode, ConfigurationRequest, TransportCleanup,
};

pub const ROUTER_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 0, 2, 2);
pub const ROUTER_IPV6: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
pub const ROUTER_MTU: u16 = 1280;

pub enum TransportMode {
    Native,
    Managed {
        broker: AttachmentBroker,
        cleanup: TransportCleanup,
    },
}

pub enum UserspaceTun<T> {
    Native(T),
    Managed(ManagedTun),
}

/// Configuration ownership only. No descriptor is acquired or retained here.
pub struct ManagedTun {
    pub broker: AttachmentBroker,
    /// Actual target assignment, before app-facing platform projection.
    pub config: TunConfig,
    pub capture_config: TunConfig,
    pub request: ConfigurationRequest,
}

impl ManagedTun {
    pub fn request(broker: AttachmentBroker, config: TunConfig) -> Result<Self, AttachmentError> {
        let target_config = config.clone();
        #[cfg(target_os = "android")]
        let config = router_config(&config, broker.local_routes());
        let request = broker.request_target_capture(target_config.clone(), config.clone())?;
        Ok(Self {
            broker,
            config: target_config,
            capture_config: config,
            request,
        })
    }
}

/// App-side projection only. The target retains its actual assignment and MTU.
/// Missing target families remain captured; the mapper refuses their ordinary
/// packets rather than letting Android fall back to the physical network.
pub fn router_config(target: &TunConfig, local_routes: Vec<ipnetwork::IpNetwork>) -> TunConfig {
    let mut config = target.clone();
    #[cfg(target_os = "android")]
    {
        let effective = super::VpnServiceConfig::new(target.clone());
        config.routes = effective
            .routes
            .iter()
            .map(ipnetwork::IpNetwork::from)
            .collect();
        config.dns_servers = Some(effective.dns_servers);
    }
    config.addresses = vec![ROUTER_IPV4.into(), ROUTER_IPV6.into()];
    config.mtu = ROUTER_MTU;
    for (ipv6, route) in [(false, "0.0.0.0/0"), (true, "::/0")] {
        if !target.addresses.iter().any(|ip| ip.is_ipv6() == ipv6) {
            config.routes.push(route.parse().expect("default route"));
        }
    }
    config.routes.extend(
        config
            .dns_servers
            .clone()
            .unwrap_or_else(|| config.gateways())
            .into_iter()
            .map(ipnetwork::IpNetwork::from),
    );
    config.routes.extend(local_routes);
    config.routes.sort();
    config.routes.dedup();
    config.allow_lan = false;
    config
}

/// Before target parameters exist, capture both families and a dummy resolver.
pub fn router_blocking_config(local_routes: Vec<ipnetwork::IpNetwork>) -> TunConfig {
    let mut config = super::blocking_config(
        #[cfg(target_os = "windows")]
        std::path::PathBuf::new(),
    );
    config.dns_servers = Some(vec!["192.0.2.1".parse().expect("dummy resolver")]);
    router_config(&config, local_routes)
}

impl TransportMode {
    pub fn selected(attachment: Option<&AttachmentBroker>) -> Self {
        match attachment {
            Some(broker)
                if {
                    let state = broker.snapshot();
                    state.closed || state.mode == AttachmentMode::ManagedRequired
                } =>
            {
                Self::Managed {
                    broker: broker.clone(),
                    cleanup: broker.transport_cleanup(),
                }
            }
            _ => Self::Native,
        }
    }

    pub fn open<T, E>(
        self,
        config: TunConfig,
        managed_error: impl FnOnce(AttachmentError) -> E,
        native: impl FnOnce() -> Result<T, E>,
    ) -> Result<UserspaceTun<T>, E> {
        match self {
            Self::Managed { broker, .. } => ManagedTun::request(broker, config)
                .map(UserspaceTun::Managed)
                .map_err(managed_error),
            Self::Native => native().map(UserspaceTun::Native),
        }
    }

    pub fn reconfigure<E>(
        self,
        forced: bool,
        native: impl FnOnce(bool) -> Result<(), E>,
    ) -> Result<(), E> {
        match self {
            Self::Managed { cleanup, .. } => {
                cleanup.cancel();
                Ok(())
            }
            Self::Native => native(forced),
        }
    }

    pub fn close(self, native: impl FnOnce()) {
        match self {
            Self::Managed { cleanup, .. } => cleanup.cancel(),
            Self::Native => native(),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{cell::Cell, os::fd::AsRawFd, os::unix::net::UnixStream, sync::Arc};
    use talpid_netstack::buffer_budget::BufferBudget;

    #[test]
    fn router_projection_separates_assignments_and_captures_resolvers_and_missing_families() {
        let mut target = super::super::blocking_config();
        target.addresses = vec!["10.64.2.3".parse().unwrap()];
        target.routes = vec!["0.0.0.0/0".parse().unwrap()];
        target.dns_servers = Some(vec!["10.0.2.53".parse().unwrap()]);
        target.excluded_packages = vec!["unrelated.excluded.app".into()];
        let saved = target.clone();
        let projected = router_config(&target, vec!["10.0.2.2/32".parse().unwrap()]);
        assert_eq!(target, saved, "projection mutated the target assignment");
        assert_eq!(
            projected.addresses,
            vec![
                "192.0.2.2".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8::2".parse().unwrap()
            ]
        );
        assert_eq!(projected.mtu, 1280);
        for route in ["::/0", "10.0.2.53/32", "10.0.2.2/32"] {
            assert!(
                projected.routes.contains(&route.parse().unwrap()),
                "missing {route}"
            );
        }
        assert_eq!(projected.dns_servers, target.dns_servers);
        assert_eq!(projected.excluded_packages, target.excluded_packages);
        target.addresses[0] = "10.64.9.8".parse().unwrap();
        target.mtu = 1420;
        assert_eq!(
            router_config(&target, vec!["10.0.2.2/32".parse().unwrap()]),
            projected,
            "target assignment rotation leaked into the capture"
        );
        let blocking = router_blocking_config(vec!["10.0.2.2/32".parse().unwrap()]);
        assert_eq!(blocking.addresses, projected.addresses);
        assert_eq!(blocking.mtu, 1280);
        for route in ["0.0.0.0/0", "::/0", "192.0.2.1/32"] {
            assert!(blocking.routes.contains(&route.parse().unwrap()));
        }
        assert_eq!(
            blocking.dns_servers.unwrap(),
            vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn managed_configuration_reconfigure_close_and_failure_exclude_native_fd_operations() {
        let root = BufferBudget::new(64 * 1024 * 1024);
        let broker = AttachmentBroker::new(
            Arc::new(root.reserve(22 * 1024 * 1024).unwrap().region().unwrap()),
            Arc::new(root.reserve(2 * 1024 * 1024).unwrap().region().unwrap()),
            Arc::new(root.reserve(8 * 1024 * 1024).unwrap().region().unwrap()),
        )
        .unwrap();
        let opens = Cell::new(0);
        let duplicates = Cell::new(0);
        let closes = Cell::new(0);
        let native = || -> Result<_, AttachmentError> {
            opens.set(opens.get() + 1);
            let (fd, peer) = UnixStream::pair().unwrap();
            let copy = fd.try_clone().unwrap();
            assert_ne!(fd.as_raw_fd(), copy.as_raw_fd());
            duplicates.set(duplicates.get() + 1);
            Ok((fd, copy, peer))
        };
        let config = super::super::blocking_config();
        // Native control really acquires and duplicates descriptors.
        let UserspaceTun::Native(fds) = TransportMode::selected(Some(&broker))
            .open(config.clone(), |error| error, native)
            .unwrap()
        else {
            panic!("native selection")
        };
        TransportMode::selected(Some(&broker))
            .reconfigure(false, |forced| {
                assert!(!forced);
                drop(native()?);
                Ok::<_, AttachmentError>(())
            })
            .unwrap();
        TransportMode::selected(Some(&broker))
            .reconfigure(true, |forced| {
                assert!(forced);
                drop(native()?);
                Ok::<_, AttachmentError>(())
            })
            .unwrap();
        TransportMode::selected(Some(&broker)).close(|| {
            drop(fds);
            closes.set(closes.get() + 1);
        });
        assert_eq!((opens.get(), duplicates.get(), closes.get()), (3, 3, 1));

        broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
        for forced in [false, true] {
            let UserspaceTun::Managed(mut source) = TransportMode::selected(Some(&broker))
                .open(config.clone(), |error| error, native)
                .unwrap()
            else {
                panic!("managed selection")
            };
            assert_eq!(broker.pending_request().unwrap().config(), &config);
            TransportMode::selected(Some(&broker))
                .reconfigure(forced, |_| {
                    drop(native()?);
                    Ok::<_, AttachmentError>(())
                })
                .unwrap();
            assert!(futures::executor::block_on(source.request.configured()).is_err());
            TransportMode::selected(Some(&broker)).close(|| closes.set(closes.get() + 1));
        }
        let UserspaceTun::Managed(mut source) = TransportMode::selected(Some(&broker))
            .open(config.clone(), |error| error, native)
            .unwrap()
        else {
            panic!("managed selection")
        };
        TransportMode::selected(Some(&broker)).close(|| closes.set(closes.get() + 1));
        assert!(futures::executor::block_on(source.request.configured()).is_err());
        broker.close();
        assert!(
            TransportMode::selected(Some(&broker))
                .open(config, |error| error, native)
                .is_err()
        );
        TransportMode::selected(Some(&broker)).close(|| closes.set(closes.get() + 1));
        assert_eq!((opens.get(), duplicates.get(), closes.get()), (3, 3, 1));
    }
}
