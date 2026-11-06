use crate::{
    packet_attachment::{AttachmentBroker, PendingCaptureRequest},
    tun_provider::TunConfig,
};
use std::{net::IpAddr, sync::Arc};
use talpid_types::relay_flow::RelayTargetId;

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
    pub fn secured_config(&self) -> Option<&TunConfig> {
        match self {
            Self::Partial(_) => None,
            Self::Secured { request, .. } => Some(request.config()),
        }
    }
}
