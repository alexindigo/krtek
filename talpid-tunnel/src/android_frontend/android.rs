use super::FrontendPlatform;
use crate::tun_provider::local_network::LocalNetworkPlatform;
use std::{io, os::fd::OwnedFd};

impl FrontendPlatform for LocalNetworkPlatform {
    fn open(&self, routes: &[String]) -> io::Result<OwnedFd> {
        self.open_frontend(routes).map_err(io::Error::other)
    }

    fn closed(&self) -> io::Result<()> {
        self.finish_frontend().map_err(io::Error::other)
    }
}
