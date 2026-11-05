//! The consumer owns policy, network choice and socket protection/binding.

use crate::Flow;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Local,
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refused {
    Denied,
    Stale,
    Full,
    PreparationFailed,
}

pub trait LocalAuthority: Send + Sync + 'static {
    type Grant: Clone + Send + Sync + 'static;

    /// Cheap triage only; must not prepare sockets.
    fn disposition(&self, destination: IpAddr) -> Disposition;
    /// Decide without creating, preparing or connecting a socket.
    fn authorize(&self, flow: Flow) -> Result<Self::Grant, Refused>;
    /// Protect and bind under the platform's admission check. Runs off the owner task.
    fn prepare(&self, socket: &socket2::Socket, grant: &Self::Grant) -> Result<(), Refused>;
    /// Re-evaluate the grant against the latest inputs.
    fn current(&self, grant: &Self::Grant) -> bool;
    /// Physical endpoint, including any required IPv6 scope ID.
    fn physical_destination(&self, grant: &Self::Grant, flow: Flow) -> SocketAddr;
}
