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
    Partial(Vec<String>),
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
                ipv4: Some(std::net::Ipv4Addr::new(192, 0, 2, 2)),
                ipv6: Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            },
        }
    }

    pub fn mtu(&self) -> u16 {
        self.secured_config().map_or(1280, |config| config.mtu)
    }

    pub(super) fn request(&self) -> Option<&PendingCaptureRequest> {
        match self {
            Self::Partial(_) => None,
            Self::Secured { request, .. } => Some(request),
        }
    }

    pub fn secured_config(&self) -> Option<&TunConfig> {
        match self {
            Self::Partial(_) => None,
            Self::Secured { request, .. } => Some(request.config()),
        }
    }
}
