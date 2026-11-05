//! Rule conditions only: readiness is not authorization or proof of delivery.
use super::{LocalBypassRule, SsidIdentity, status::InactiveReason};
use ipnetwork::IpNetwork;
use std::{collections::HashSet, fmt};
use talpid_types::local_network::{LocalNetworkSnapshot, LocalPhysicalRoute};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalTransport {
    Wifi,
    Ethernet,
    Other,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PhysicalAddress {
    pub prefix: IpNetwork,
    pub usable: bool,
}

impl fmt::Debug for PhysicalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhysicalAddress(redacted)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PhysicalNetwork {
    pub handle: i64,
    pub transport: PhysicalTransport,
    pub capabilities_fresh: bool,
    pub links_fresh: bool,
    pub blocked: bool,
    pub interface_index: i32,
    pub addresses: Vec<PhysicalAddress>,
    /// Retained observations, not consulted for condition readiness.
    pub routes: Vec<LocalPhysicalRoute>,
    pub ssid: Option<SsidIdentity>,
}

impl fmt::Debug for PhysicalNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhysicalNetwork")
            .field("transport", &self.transport)
            .field("address_count", &self.addresses.len())
            .field("route_count", &self.routes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PermissionState {
    pub local_network: bool,
    pub precise_location: bool,
    pub background_location: bool,
    pub location_enabled: bool,
    pub location_allowed: bool,
}

impl PermissionState {
    pub fn ssid_readiness(self) -> Result<(), InactiveReason> {
        if !self.precise_location {
            Err(InactiveReason::LocationPermissionMissing)
        } else if !self.background_location {
            Err(InactiveReason::BackgroundLocationMissing)
        } else if !self.location_enabled {
            Err(InactiveReason::LocationOff)
        } else if !self.location_allowed {
            Err(InactiveReason::LocationPermissionMissing)
        } else {
            Ok(())
        }
    }
}

/// The daemon's semantic view of its latest in-memory feed record. An open feed
/// without its first snapshot has no permission facts yet.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkObservation {
    pub permissions: Option<PermissionState>,
    pub networks: Vec<PhysicalNetwork>,
}

impl From<&LocalNetworkSnapshot> for NetworkObservation {
    fn from(snapshot: &LocalNetworkSnapshot) -> Self {
        Self {
            permissions: Some(PermissionState {
                local_network: snapshot.local_ready,
                precise_location: snapshot.fine_ready,
                background_location: snapshot.background_ready,
                location_enabled: snapshot.location_enabled,
                // AppOps can deny access because Location is off or the grant is
                // foreground-only. Keep that fact separate from permission grants
                // so both consumers report the actual missing prerequisite.
                location_allowed: snapshot.location_allowed,
            }),
            networks: snapshot
                .networks
                .iter()
                .map(|network| PhysicalNetwork {
                    handle: network.network_handle,
                    transport: match network.transport {
                        1 => PhysicalTransport::Wifi,
                        2 => PhysicalTransport::Ethernet,
                        _ => PhysicalTransport::Other,
                    },
                    capabilities_fresh: network.capabilities_fresh,
                    links_fresh: network.links_fresh,
                    blocked: network.blocked,
                    interface_index: network.interface_index,
                    addresses: network
                        .addresses
                        .iter()
                        .filter_map(|address| {
                            let prefix = u8::try_from(address.prefix.prefix_length).ok()?;
                            Some(PhysicalAddress {
                                prefix: IpNetwork::new(address.prefix.address, prefix).ok()?,
                                usable: address.usable,
                            })
                        })
                        .collect(),
                    routes: network.routes.clone(),
                    // Stale identities cannot survive a permission change, even if
                    // an adapter accidentally supplies an old name with new facts.
                    ssid: (snapshot.fine_ready
                        && snapshot.background_ready
                        && snapshot.location_enabled
                        && snapshot.location_allowed)
                        .then(|| {
                            network
                                .ssid_hex
                                .as_deref()
                                .and_then(SsidIdentity::from_encoded_bytes)
                        })
                        .flatten(),
                })
                .collect(),
        }
    }
}

pub fn condition_readiness(
    rule: &LocalBypassRule,
    networks: &[PhysicalNetwork],
    permissions: PermissionState,
) -> Result<(), InactiveReason> {
    use InactiveReason::*;
    if !rule.enabled {
        return Err(RuleOff);
    }
    if !permissions.local_network {
        return Err(LocalPermissionMissing);
    }
    if !rule.ssid_ids.is_empty() {
        permissions.ssid_readiness()?;
    }
    let mut seen = HashSet::new();
    let mut possible = 0;
    let mut ready = false;
    let mut unknown = false;
    let mut different = false;
    for network in networks {
        if !seen.insert(network.handle) {
            return Err(MultipleNetworks);
        }
        if network.blocked
            || network.transport == PhysicalTransport::Other
            || (!rule.ssid_ids.is_empty() && network.transport != PhysicalTransport::Wifi)
        {
            continue;
        }
        if !network.capabilities_fresh
            || !network.links_fresh
            || network.handle <= 0
            || network.interface_index <= 0
        {
            return Err(WaitingForNetworkDetails);
        }
        if !network.addresses.iter().any(|address| {
            let ip = address.prefix.ip();
            address.usable
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && rule
                    .cidrs
                    .iter()
                    .any(|cidr| cidr.network().is_ipv4() == ip.is_ipv4())
        }) {
            continue;
        }
        if !rule.ssid_ids.is_empty() {
            match &network.ssid {
                None => {
                    unknown = true;
                    possible += 1;
                    continue;
                }
                Some(ssid) if !rule.ssid_ids.contains(ssid) => {
                    different = true;
                    continue;
                }
                Some(_) => (),
            }
        }
        possible += 1;
        ready = true;
    }
    if possible > 1 {
        Err(MultipleNetworks)
    } else if ready {
        Ok(())
    } else if unknown {
        Err(WifiNameUnknown)
    } else if different {
        Err(DifferentWifi)
    } else {
        Err(NoEligibleNetwork)
    }
}
