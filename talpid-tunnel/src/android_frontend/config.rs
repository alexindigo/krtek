use crate::{
    packet_attachment::{AttachmentBroker, PendingCaptureRequest},
    tun_provider::TunConfig,
};
use std::{net::IpAddr, sync::Arc};
use talpid_types::relay_flow::{RelaySources, RelayTargetId};

/// Destination policy is supplied by the daemon, before the Local parser runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDisposition {
    Local,
    Tunnel(RelayTargetId),
    Drop(CaptureDropReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDropReason {
    Policy,
    NoTarget,
}

#[derive(Clone)]
pub enum CaptureConfig {
    Partial(crate::tun_provider::PartialConfig),
    /// Capture owned independently of any tunnel's configuration request.
    Router {
        config: TunConfig,
        disposition: Arc<dyn Fn(IpAddr) -> CaptureDisposition + Send + Sync>,
    },
    Secured {
        broker: AttachmentBroker,
        request: PendingCaptureRequest,
        disposition: Arc<dyn Fn(IpAddr) -> CaptureDisposition + Send + Sync>,
    },
}

impl CaptureConfig {
    pub fn sources(&self) -> RelaySources {
        match self.secured_config() {
            Some(config) => RelaySources {
                ipv4: config.addresses.iter().find_map(|ip| match ip {
                    IpAddr::V4(ip) => Some(*ip),
                    _ => None,
                }),
                ipv6: config.addresses.iter().find_map(|ip| match ip {
                    IpAddr::V6(ip) => Some(*ip),
                    _ => None,
                }),
            },
            None => RelaySources {
                ipv4: Some(crate::tun_provider::transport::ROUTER_IPV4),
                ipv6: Some(crate::tun_provider::transport::ROUTER_IPV6),
            },
        }
    }

    pub fn mtu(&self) -> u16 {
        self.secured_config()
            .map_or(crate::tun_provider::transport::ROUTER_MTU, |config| {
                config.mtu
            })
    }

    pub(super) fn request(&self) -> Option<&PendingCaptureRequest> {
        match self {
            Self::Partial(_) | Self::Router { .. } => None,
            Self::Secured { request, .. } => Some(request),
        }
    }

    pub fn secured_config(&self) -> Option<&TunConfig> {
        match self {
            Self::Partial(_) => None,
            Self::Router { config, .. } => Some(config),
            Self::Secured { request, .. } => Some(request.config()),
        }
    }
}
