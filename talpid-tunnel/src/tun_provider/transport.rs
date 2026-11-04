//! Android userspace transport selection, before any native descriptor operation.
use super::TunConfig;
use crate::packet_attachment::{
    AttachmentBroker, AttachmentError, AttachmentMode, ConfigurationRequest,
};

pub enum TransportMode {
    Native,
    Managed(AttachmentBroker),
}

pub enum UserspaceTun<T> {
    Native(T),
    Managed(ManagedTun),
}

/// Configuration ownership only. No descriptor is acquired or retained here.
pub struct ManagedTun {
    pub broker: AttachmentBroker,
    pub config: TunConfig,
    pub request: ConfigurationRequest,
}

impl ManagedTun {
    pub fn request(broker: AttachmentBroker, config: TunConfig) -> Result<Self, AttachmentError> {
        #[cfg(target_os = "android")]
        let config = {
            // Apply Native's LAN/gateway/DNS/family projection first, then union
            // enabled local destinations. Do not subtract LAN a second time.
            let effective = super::VpnServiceConfig::new(config.clone());
            let mut config = config;
            config.routes = effective
                .routes
                .iter()
                .map(ipnetwork::IpNetwork::from)
                .collect();
            config.routes.extend(broker.local_routes());
            config.routes.sort();
            config.routes.dedup();
            config.allow_lan = false;
            config.dns_servers = Some(effective.dns_servers);
            config
        };
        let request = broker.request_capture(config.clone())?;
        Ok(Self {
            broker,
            config,
            request,
        })
    }
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
                Self::Managed(broker.clone())
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
            Self::Managed(broker) => ManagedTun::request(broker, config)
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
            Self::Managed(broker) => {
                broker.retire_transport();
                Ok(())
            }
            Self::Native => native(forced),
        }
    }

    pub fn close(self, native: impl FnOnce()) {
        match self {
            Self::Managed(broker) => broker.retire_transport(),
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
