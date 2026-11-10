use super::{CaptureConfig, CaptureHandover, FrontendPlatform};
use crate::tun_provider::{
    VpnServiceConfig,
    local_network::{FrontendHandoverConfig, LocalNetworkPlatform},
};
use std::{io, os::fd::OwnedFd, sync::Arc};
use talpid_types::capture_network::{CaptureExpectation, CaptureNetworkFeed, CapturePrefix};

impl FrontendPlatform for LocalNetworkPlatform {
    fn open(&self, generation: i64, config: &CaptureConfig) -> io::Result<OwnedFd> {
        match config {
            CaptureConfig::Partial(config) => self.open_frontend(generation, config),
            CaptureConfig::Router { config, .. } => {
                self.open_secured_frontend(generation, config.clone())
            }
            CaptureConfig::Secured { request, .. } => {
                self.open_secured_frontend(generation, request.config().clone())
            }
        }
        .map_err(io::Error::other)
    }

    fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
        self.capture_network()
    }

    fn handover(
        &self,
        predecessor: i64,
        generation: i64,
        config: &CaptureConfig,
    ) -> CaptureHandover {
        let config = match config {
            CaptureConfig::Partial(config) => FrontendHandoverConfig::Partial(config),
            CaptureConfig::Router { config, .. } => FrontendHandoverConfig::Secured(config.clone()),
            CaptureConfig::Secured { request, .. } => {
                FrontendHandoverConfig::Secured(request.config().clone())
            }
        };
        let result = self.handover_frontend(predecessor, generation, config);
        CaptureHandover {
            descriptor: result.descriptor.map_err(io::Error::other),
            predecessor_retained: result.predecessor_retained,
        }
    }

    fn expectation(
        &self,
        config: &CaptureConfig,
        interface: String,
    ) -> io::Result<CaptureExpectation> {
        // SAFETY: geteuid is a read-only libc query with no pointer arguments.
        let uid = unsafe { nix::libc::geteuid() } as i32;
        let expected = match config.secured_config() {
            None => None,
            Some(config) => {
                // Exactly the same projection as open_secured_frontend, including
                // LAN subtraction, gateway/SOCKS exceptions and DNS filtering.
                let config = VpnServiceConfig::new(config.clone());
                let routes = config
                    .routes
                    .into_iter()
                    .map(|route| CapturePrefix {
                        address: route.address,
                        prefix_length: route.prefix_length,
                    })
                    .collect::<Vec<_>>();
                CaptureExpectation::requested(
                    interface,
                    uid,
                    self.capture_api_level().map_err(io::Error::other)?,
                    &config.addresses,
                    &routes,
                    &config.dns_servers,
                    config.mtu,
                )
            }
        };
        expected.ok_or_else(|| io::Error::other("Invalid capture projection"))
    }

    fn bind(&self, generation: i64, interface: &str) -> io::Result<bool> {
        self.bind_frontend(generation, interface)
            .map_err(io::Error::other)
    }

    fn closed(&self, generation: i64) -> io::Result<()> {
        self.finish_frontend(generation).map_err(io::Error::other)
    }
}
