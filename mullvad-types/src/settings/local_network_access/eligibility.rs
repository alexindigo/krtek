//! Pure decisions over the daemon's latest observation. Condition readiness is
//! separate from destination admission; neither is proof of socket delivery.
use super::{
    LocalBypassRule, LocalNetworkAccess, SsidIdentity, is_directed_broadcast,
    status::InactiveReason,
};
use ipnetwork::IpNetwork;
use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    net::IpAddr,
};
use talpid_types::local_network::{LocalNetworkSnapshot, LocalPhysicalRoute};
use uuid::Uuid;

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
    pub sequence: i64,
    pub permissions: Option<PermissionState>,
    pub networks: Vec<PhysicalNetwork>,
}

impl From<&LocalNetworkSnapshot> for NetworkObservation {
    fn from(snapshot: &LocalNetworkSnapshot) -> Self {
        Self {
            sequence: snapshot.sequence,
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

// AndroidLocalNetworkSource.linksEvent records RouteInfo.type on API 33+,
// and 0 where older APIs cannot prove it. These are Android's RTN_* values.
const RTN_UNICAST: i32 = 1;
const RTN_UNREACHABLE: i32 = 7;
const RTN_THROW: i32 = 9;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RouteDelivery {
    OnLink,
    Gateway(IpAddr),
    Unreachable,
    Throw,
    Unknown,
}

impl From<&LocalPhysicalRoute> for RouteDelivery {
    fn from(route: &LocalPhysicalRoute) -> Self {
        match route.route_type {
            RTN_UNICAST => route.gateway.map_or(Self::OnLink, Self::Gateway),
            RTN_UNREACHABLE => Self::Unreachable,
            RTN_THROW => Self::Throw,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Debug for RouteDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OnLink => "OnLink",
            Self::Gateway(_) => "Gateway(redacted)",
            Self::Unreachable => "Unreachable",
            Self::Throw => "Throw",
            Self::Unknown => "Unknown",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryRefusal {
    PolicyOff,
    NotUnicast,
    LocalPermissionMissing,
    NoMatchingRule,
    WaitingForNetworkDetails,
    DirectedBroadcast,
    RouteAmbiguous,
    RouteUnknown,
    WifiNameUnavailable,
    DifferentWifi,
    MultipleNetworks,
    NoEligibleNetwork,
}

#[derive(Clone, Eq, PartialEq)]
pub struct NetworkLease {
    pub destination: IpAddr,
    pub network_handle: i64,
    pub interface_index: i32,
    pub scope_id: u32,
    pub rule_ids: Vec<Uuid>,
    pub needs_wifi_name: bool,
    pub sequence: i64,
}

impl fmt::Debug for NetworkLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkLease")
            .field("rule_count", &self.rule_ids.len())
            .field("needs_wifi_name", &self.needs_wifi_name)
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl NetworkLease {
    /// Re-evaluate rather than migrating an existing flow to another grant.
    /// Bind-time admission separately requires the exact observation sequence.
    pub fn is_current(
        &self,
        policy: &LocalNetworkAccess,
        observation: &NetworkObservation,
    ) -> bool {
        evaluate(policy, observation, self.destination).is_ok_and(|mut current| {
            current.sequence = self.sequence;
            current == *self
        })
    }
}

fn unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
}

fn link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}

impl PhysicalNetwork {
    fn destination_route(
        &self,
        destination: IpAddr,
    ) -> Result<Option<&LocalPhysicalRoute>, DeliveryRefusal> {
        let mut longest = None;
        let mut conflict = false;
        for route in &self.routes {
            let prefix = u8::try_from(route.destination.prefix_length)
                .ok()
                .and_then(|prefix| IpNetwork::new(route.destination.address, prefix).ok())
                .ok_or(DeliveryRefusal::RouteUnknown)?;
            if !prefix.contains(destination) {
                continue;
            }
            match longest {
                None => {
                    longest = Some((prefix.prefix(), route));
                    conflict = false;
                }
                Some((length, _)) if prefix.prefix() > length => {
                    longest = Some((prefix.prefix(), route));
                    conflict = false;
                }
                Some((length, first)) if prefix.prefix() == length && route != first => {
                    conflict = true
                }
                _ => (),
            }
        }
        let Some((_, route)) = longest else {
            return Ok(None);
        };
        if conflict || route.interface_index != self.interface_index {
            return Err(DeliveryRefusal::RouteAmbiguous);
        }
        Ok(Some(route))
    }

    fn can_deliver(&self, destination: IpAddr) -> Result<bool, DeliveryRefusal> {
        if self.blocked || self.transport == PhysicalTransport::Other {
            return Ok(false);
        }
        if !self.capabilities_fresh
            || !self.links_fresh
            || self.handle <= 0
            || self.interface_index <= 0
        {
            return Err(DeliveryRefusal::WaitingForNetworkDetails);
        }
        let addresses: Vec<_> = self
            .addresses
            .iter()
            .filter(|address| {
                address.usable
                    && address.prefix.is_ipv4() == destination.is_ipv4()
                    && unicast(address.prefix.ip())
            })
            .map(|address| address.prefix)
            .collect();
        if addresses.is_empty() {
            return Ok(false);
        }
        let physical_links: Vec<_> = self
            .addresses
            .iter()
            .map(|address| address.prefix)
            .collect();
        if is_directed_broadcast(destination, &physical_links) {
            return Err(DeliveryRefusal::DirectedBroadcast);
        }
        let Some(route) = self.destination_route(destination)? else {
            return Ok(false);
        };
        let delivery = RouteDelivery::from(route);
        if delivery == RouteDelivery::Unknown {
            return Err(DeliveryRefusal::RouteUnknown);
        }
        if link_local(destination) {
            return Ok(addresses.iter().any(|address| link_local(address.ip()))
                && link_local(route.destination.address)
                && delivery == RouteDelivery::OnLink);
        }
        Ok(match delivery {
            RouteDelivery::OnLink => true,
            RouteDelivery::Gateway(gateway) => {
                gateway.is_ipv4() == destination.is_ipv4() && unicast(gateway)
            }
            RouteDelivery::Unreachable | RouteDelivery::Throw | RouteDelivery::Unknown => false,
        })
    }
}

/// Union enabled rule grants per physical network. Unresolved candidates still
/// contribute ambiguity; a known network cannot silently win over an unknown one.
pub fn evaluate(
    policy: &LocalNetworkAccess,
    observation: &NetworkObservation,
    destination: IpAddr,
) -> Result<NetworkLease, DeliveryRefusal> {
    use DeliveryRefusal::*;
    if !policy.enabled || policy.validate().is_err() {
        return Err(PolicyOff);
    }
    if !unicast(destination) {
        return Err(NotUnicast);
    }
    let permissions = observation
        .permissions
        .filter(|facts| facts.local_network)
        .ok_or(LocalPermissionMissing)?;
    let rules: Vec<_> = policy.matching_rules(destination).collect();
    if rules.is_empty() {
        return Err(NoMatchingRule);
    }
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    let mut wifi_unavailable = false;
    let mut different_wifi = false;
    for network in &observation.networks {
        if !seen.insert(network.handle) {
            return Err(MultipleNetworks);
        }
        let pending = match network.can_deliver(destination) {
            Ok(false) => continue,
            Ok(true) => None,
            Err(reason @ (RouteUnknown | RouteAmbiguous)) => Some(reason),
            Err(reason) => return Err(reason),
        };
        let mut rule_ids = BTreeSet::new();
        let mut unknown = false;
        let mut needs_wifi_name = true;
        for rule in &rules {
            if !rule.ssid_ids.is_empty() {
                if network.transport != PhysicalTransport::Wifi {
                    continue;
                }
                if permissions.ssid_readiness().is_err() {
                    wifi_unavailable = true;
                    continue;
                }
                match &network.ssid {
                    None => {
                        unknown = true;
                        wifi_unavailable = true;
                        continue;
                    }
                    Some(ssid) if !rule.ssid_ids.contains(ssid) => {
                        different_wifi = true;
                        continue;
                    }
                    Some(_) => (),
                }
            }
            needs_wifi_name &= !rule.ssid_ids.is_empty();
            rule_ids.insert(rule.id);
        }
        if !rule_ids.is_empty() || unknown {
            candidates.push((network, rule_ids, needs_wifi_name, pending));
        }
    }
    if candidates.len() > 1 {
        return Err(MultipleNetworks);
    }
    let Some((network, rule_ids, needs_wifi_name, pending)) = candidates.pop() else {
        return Err(if wifi_unavailable {
            WifiNameUnavailable
        } else if different_wifi {
            DifferentWifi
        } else {
            NoEligibleNetwork
        });
    };
    if let Some(reason) = pending {
        return Err(reason);
    }
    if rule_ids.is_empty() {
        return Err(WifiNameUnavailable);
    }
    Ok(NetworkLease {
        destination,
        network_handle: network.handle,
        interface_index: network.interface_index,
        scope_id: if destination.is_ipv6() && link_local(destination) {
            network.interface_index as u32
        } else {
            0
        },
        rule_ids: rule_ids.into_iter().collect(),
        needs_wifi_name,
        sequence: observation.sequence,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use talpid_types::local_network::LocalPhysicalPrefix;

    fn identity() -> SsidIdentity {
        SsidIdentity::from_bytes(b"synthetic-wifi".to_vec()).unwrap()
    }

    fn policy(conditioned: bool) -> LocalNetworkAccess {
        LocalNetworkAccess {
            enabled: true,
            rules: vec![LocalBypassRule {
                id: Uuid::from_u128(1),
                name: "synthetic-rule".into(),
                enabled: true,
                cidrs: [
                    "10.0.0.0/8",
                    "192.168.0.0/16",
                    "169.254.0.0/16",
                    "fc00::/7",
                    "fe80::/10",
                ]
                .iter()
                .map(|text| text.parse().unwrap())
                .collect(),
                ssid_ids: if conditioned {
                    vec![identity()]
                } else {
                    vec![]
                },
            }],
        }
    }

    fn route(prefix: &str, route_type: i32, gateway: Option<&str>) -> LocalPhysicalRoute {
        let prefix: IpNetwork = prefix.parse().unwrap();
        LocalPhysicalRoute {
            destination: LocalPhysicalPrefix {
                address: prefix.ip(),
                prefix_length: i16::from(prefix.prefix()),
            },
            route_type,
            gateway: gateway.map(|ip| ip.parse().unwrap()),
            interface_index: 15,
        }
    }

    fn observation() -> NetworkObservation {
        NetworkObservation {
            sequence: 71,
            permissions: Some(PermissionState {
                local_network: true,
                precise_location: true,
                background_location: true,
                location_enabled: true,
                location_allowed: true,
            }),
            networks: vec![PhysicalNetwork {
                handle: 987654321,
                transport: PhysicalTransport::Wifi,
                capabilities_fresh: true,
                links_fresh: true,
                blocked: false,
                interface_index: 15,
                addresses: vec![PhysicalAddress {
                    prefix: "10.0.2.16/24".parse().unwrap(),
                    usable: true,
                }],
                routes: vec![
                    route("10.0.2.0/24", RTN_UNICAST, None),
                    route("0.0.0.0/0", RTN_UNICAST, Some("10.0.2.2")),
                ],
                ssid: Some(identity()),
            }],
        }
    }

    fn result(
        policy: &LocalNetworkAccess,
        observation: &NetworkObservation,
        destination: &str,
    ) -> Result<NetworkLease, DeliveryRefusal> {
        evaluate(policy, observation, destination.parse().unwrap())
    }

    #[test]
    fn emulator_onlink_peer_gets_a_sequence_bound_lease() {
        let observed = observation();
        let lease = result(&policy(false), &observed, "10.0.2.2").unwrap();
        assert_eq!(lease.destination, "10.0.2.2".parse::<IpAddr>().unwrap());
        assert_eq!(lease.network_handle, observed.networks[0].handle);
        assert_eq!(lease.interface_index, 15);
        assert_eq!(lease.scope_id, 0);
        assert_eq!(lease.rule_ids, vec![Uuid::from_u128(1)]);
        assert!(!lease.needs_wifi_name);
        assert_eq!(lease.sequence, 71);
    }

    #[test]
    fn snapshot_sequence_is_retained_without_becoming_a_status_input() {
        let snapshot = LocalNetworkSnapshot {
            sequence: 97,
            ..Default::default()
        };
        assert_eq!(NetworkObservation::from(&snapshot).sequence, 97);
    }

    #[test]
    fn invalid_off_nonunicast_missing_permission_and_unmatched_are_refused() {
        let mut configured = policy(false);
        let mut observed = observation();
        configured.enabled = false;
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::PolicyOff)
        );
        configured.enabled = true;
        configured.rules.push(configured.rules[0].clone());
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::PolicyOff)
        );
        configured.rules.pop();
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "ff02::1",
        ] {
            assert_eq!(
                result(&configured, &observed, ip),
                Err(DeliveryRefusal::NotUnicast)
            );
        }
        observed.permissions = None;
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::LocalPermissionMissing)
        );
        observed.permissions = Some(PermissionState::default());
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::LocalPermissionMissing)
        );
        assert_eq!(
            result(&configured, &observation(), "1.1.1.1"),
            Err(DeliveryRefusal::NoMatchingRule)
        );
        configured.rules[0].enabled = false;
        assert_eq!(
            result(&configured, &observation(), "10.0.2.2"),
            Err(DeliveryRefusal::NoMatchingRule)
        );
    }

    #[test]
    fn plain_routed_private_grant_needs_no_location_or_wifi_transport() {
        let mut observed = observation();
        observed.permissions = Some(PermissionState {
            local_network: true,
            ..Default::default()
        });
        observed.networks[0].transport = PhysicalTransport::Ethernet;
        observed.networks[0].ssid = None;
        let lease = result(&policy(false), &observed, "192.168.3.27").unwrap();
        assert!(!lease.needs_wifi_name);
    }

    #[test]
    fn blocked_and_other_networks_are_skipped_but_stale_details_refuse() {
        for case in 0..6 {
            let mut observed = observation();
            let network = &mut observed.networks[0];
            match case {
                0 => network.capabilities_fresh = false,
                1 => network.links_fresh = false,
                2 => network.handle = 0,
                3 => network.handle = -1,
                4 => network.interface_index = 0,
                _ => network.interface_index = -1,
            }
            assert_eq!(
                result(&policy(false), &observed, "10.0.2.2"),
                Err(DeliveryRefusal::WaitingForNetworkDetails)
            );
            observed.networks[0].blocked = true;
            assert_eq!(
                result(&policy(false), &observed, "10.0.2.2"),
                Err(DeliveryRefusal::NoEligibleNetwork)
            );
            observed.networks[0].blocked = false;
            observed.networks[0].transport = PhysicalTransport::Other;
            assert_eq!(
                result(&policy(false), &observed, "10.0.2.2"),
                Err(DeliveryRefusal::NoEligibleNetwork)
            );
        }
    }

    #[test]
    fn usable_unicast_address_of_the_destination_family_is_required() {
        for prefix in [
            "0.0.0.0/0",
            "127.0.0.1/8",
            "224.0.0.1/4",
            "255.255.255.255/32",
            "fe80::1/64",
        ] {
            let mut observed = observation();
            observed.networks[0].addresses[0].prefix = prefix.parse().unwrap();
            assert_eq!(
                result(&policy(false), &observed, "10.0.2.2"),
                Err(DeliveryRefusal::NoEligibleNetwork)
            );
        }
        let mut observed = observation();
        observed.networks[0].addresses[0].usable = false;
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
        observed.networks[0].addresses.clear();
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
    }

    #[test]
    fn directed_broadcast_refuses_but_point_to_point_and_host_addresses_do_not() {
        let mut observed = observation();
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.255"),
            Err(DeliveryRefusal::DirectedBroadcast)
        );
        observed.networks[0].addresses.push(PhysicalAddress {
            prefix: "192.168.7.9/24".parse().unwrap(),
            usable: false,
        });
        assert_eq!(
            result(&policy(false), &observed, "192.168.7.255"),
            Err(DeliveryRefusal::DirectedBroadcast)
        );
        for prefix in ["10.0.2.254/31", "10.0.2.255/32"] {
            observed.networks[0].addresses[0].prefix = prefix.parse().unwrap();
            assert!(result(&policy(false), &observed, "10.0.2.255").is_ok());
        }
    }

    #[test]
    fn route_delivery_uses_proven_numeric_types_not_gateway_hints() {
        for (kind, gateway, expected) in [
            (1, None, RouteDelivery::OnLink),
            (
                1,
                Some("10.0.2.2"),
                RouteDelivery::Gateway("10.0.2.2".parse().unwrap()),
            ),
            (7, None, RouteDelivery::Unreachable),
            (9, None, RouteDelivery::Throw),
            (0, Some("10.0.2.2"), RouteDelivery::Unknown),
            (42, None, RouteDelivery::Unknown),
        ] {
            assert_eq!(
                RouteDelivery::from(&route("10.0.2.0/24", kind, gateway)),
                expected
            );
        }
    }

    #[test]
    fn longest_unknown_unreachable_and_throw_routes_never_fall_back_to_default() {
        for (kind, expected) in [
            (0, DeliveryRefusal::RouteUnknown),
            (7, DeliveryRefusal::NoEligibleNetwork),
            (9, DeliveryRefusal::NoEligibleNetwork),
        ] {
            let mut observed = observation();
            observed.networks[0]
                .routes
                .push(route("10.0.2.2/32", kind, None));
            assert_eq!(result(&policy(false), &observed, "10.0.2.2"), Err(expected));
        }
        let mut observed = observation();
        observed.networks[0].routes.clear();
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
    }

    #[test]
    fn equal_longest_conflicts_and_wrong_interface_are_not_guessed() {
        let mut observed = observation();
        let original = observed.networks[0].routes[0].clone();
        observed.networks[0].routes.push(original.clone());
        assert!(result(&policy(false), &observed, "10.0.2.2").is_ok());
        observed.networks[0]
            .routes
            .push(route("10.0.2.0/24", 1, Some("10.0.2.1")));
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::RouteAmbiguous)
        );
        observed.networks[0].routes = vec![original];
        observed.networks[0].routes[0].interface_index = 16;
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::RouteAmbiguous)
        );
        observed.networks[0]
            .routes
            .push(route("10.0.2.2/32", 1, None));
        assert!(result(&policy(false), &observed, "10.0.2.2").is_ok());
    }

    #[test]
    fn malformed_route_prefix_cannot_disappear_behind_a_default_route() {
        let mut observed = observation();
        observed.networks[0].routes[0].destination.prefix_length = 33;
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::RouteUnknown)
        );
    }

    #[test]
    fn gateway_must_be_same_family_unicast() {
        for gateway in [
            "::1",
            "fe80::2",
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let mut observed = observation();
            observed.networks[0].routes = vec![route("0.0.0.0/0", 1, Some(gateway))];
            assert_eq!(
                result(&policy(false), &observed, "192.168.3.27"),
                Err(DeliveryRefusal::NoEligibleNetwork)
            );
        }
    }

    #[test]
    fn ipv6_link_local_requires_link_local_address_onlink_route_and_scope() {
        let mut observed = observation();
        assert_eq!(
            result(&policy(false), &observed, "fe80::10"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
        observed.networks[0].addresses.push(PhysicalAddress {
            prefix: "fe80::100/64".parse().unwrap(),
            usable: true,
        });
        observed.networks[0]
            .routes
            .push(route("fe80::/64", 1, None));
        let lease = result(&policy(false), &observed, "fe80::10").unwrap();
        assert_eq!(lease.scope_id, 15);
        observed.networks[0].addresses[1].prefix = "fd42::100/64".parse().unwrap();
        assert_eq!(
            result(&policy(false), &observed, "fe80::10"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
        observed.networks[0].addresses[1].prefix = "fe80::100/64".parse().unwrap();
        observed.networks[0].routes[2] = route("::/0", 1, None);
        assert_eq!(
            result(&policy(false), &observed, "fe80::10"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
        observed.networks[0].routes[2] = route("fe80::/64", 1, Some("fe80::2"));
        assert_eq!(
            result(&policy(false), &observed, "fe80::10"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
    }

    #[test]
    fn ipv4_link_local_requires_link_local_onlink_delivery_without_scope() {
        let mut observed = observation();
        assert_eq!(
            result(&policy(false), &observed, "169.254.2.10"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
        observed.networks[0].addresses.push(PhysicalAddress {
            prefix: "169.254.2.16/16".parse().unwrap(),
            usable: true,
        });
        observed.networks[0]
            .routes
            .push(route("169.254.0.0/16", 1, None));
        assert_eq!(
            result(&policy(false), &observed, "169.254.2.10")
                .unwrap()
                .scope_id,
            0
        );
    }

    #[test]
    fn ipv6_global_onlink_and_routed_private_delivery_have_no_scope() {
        let mut observed = observation();
        observed.networks[0].addresses.push(PhysicalAddress {
            prefix: "fd42::100/64".parse().unwrap(),
            usable: true,
        });
        observed.networks[0]
            .routes
            .push(route("fd42::/64", 1, None));
        assert_eq!(
            result(&policy(false), &observed, "fd42::10")
                .unwrap()
                .scope_id,
            0
        );
        observed.networks[0]
            .routes
            .push(route("::/0", 1, Some("fe80::2")));
        assert_eq!(
            result(&policy(false), &observed, "fd43::10")
                .unwrap()
                .scope_id,
            0
        );
    }

    #[test]
    fn multiple_eligible_duplicate_or_unknown_wifi_networks_remain_ambiguous() {
        let mut observed = observation();
        let mut other = observed.networks[0].clone();
        other.handle += 1;
        observed.networks.push(other);
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::MultipleNetworks)
        );
        observed.networks[1].ssid = None;
        assert_eq!(
            result(&policy(true), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::MultipleNetworks)
        );
        observed.networks[1].handle = observed.networks[0].handle;
        assert_eq!(
            result(&policy(false), &observed, "10.0.2.2"),
            Err(DeliveryRefusal::MultipleNetworks)
        );
    }

    #[test]
    fn unknown_competitor_routes_contribute_ambiguity_in_either_network_order() {
        for kind in [0, 1] {
            let mut observed = observation();
            let mut other = observed.networks[0].clone();
            other.handle += 1;
            other.routes.push(route("10.0.2.2/32", kind, None));
            if kind == 1 {
                other.routes.last_mut().unwrap().interface_index = 0;
            }
            observed.networks.push(other);
            assert_eq!(
                result(&policy(false), &observed, "10.0.2.2"),
                Err(DeliveryRefusal::MultipleNetworks)
            );
            observed.networks.reverse();
            assert_eq!(
                result(&policy(false), &observed, "10.0.2.2"),
                Err(DeliveryRefusal::MultipleNetworks)
            );
        }
    }

    #[test]
    fn each_wifi_permission_failure_keeps_announcement_but_refuses_delivery() {
        let configured = policy(true);
        let routes = configured.announced_routes();
        for missing in 0..5 {
            let mut observed = observation();
            let facts = observed.permissions.as_mut().unwrap();
            match missing {
                0 => facts.local_network = false,
                1 => facts.precise_location = false,
                2 => facts.background_location = false,
                3 => facts.location_enabled = false,
                _ => facts.location_allowed = false,
            }
            assert_eq!(
                result(&configured, &observed, "10.0.2.2"),
                Err(if missing == 0 {
                    DeliveryRefusal::LocalPermissionMissing
                } else {
                    DeliveryRefusal::WifiNameUnavailable
                })
            );
            assert_eq!(configured.announced_routes(), routes);
        }
        assert_eq!(
            result(&configured, &NetworkObservation::default(), "10.0.2.2"),
            Err(DeliveryRefusal::LocalPermissionMissing)
        );
        assert_eq!(configured.announced_routes(), routes);
    }

    #[test]
    fn wifi_name_is_exact_unknown_or_different_never_becomes_plain() {
        let configured = policy(true);
        let original = configured.clone();
        let routes = configured.announced_routes();
        let mut observed = observation();
        assert!(
            result(&configured, &observed, "10.0.2.2")
                .unwrap()
                .needs_wifi_name
        );
        observed.networks[0].ssid = None;
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::WifiNameUnavailable)
        );
        observed.networks[0].ssid =
            Some(SsidIdentity::from_bytes(b"Synthetic-wifi".to_vec()).unwrap());
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::DifferentWifi)
        );
        observed.networks[0].transport = PhysicalTransport::Ethernet;
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
        assert_eq!(configured, original);
        assert_eq!(configured.announced_routes(), routes);
    }

    #[test]
    fn union_grants_are_sorted_and_plain_grants_do_not_depend_on_wifi() {
        let mut configured = policy(true);
        let mut plain = configured.rules[0].clone();
        plain.id = Uuid::nil();
        plain.ssid_ids.clear();
        configured.rules.push(plain);
        let lease = result(&configured, &observation(), "10.0.2.2").unwrap();
        assert_eq!(lease.rule_ids, vec![Uuid::nil(), Uuid::from_u128(1)]);
        assert!(!lease.needs_wifi_name);
        configured.rules.reverse();
        assert_eq!(
            result(&configured, &observation(), "10.0.2.2").unwrap(),
            lease
        );
        let mut observed = observation();
        observed.networks[0].ssid = None;
        let plain_only = result(&configured, &observed, "10.0.2.2").unwrap();
        assert_eq!(plain_only.rule_ids, vec![Uuid::nil()]);
        assert!(!plain_only.needs_wifi_name);
    }

    #[test]
    fn revalidation_ignores_only_sequence_and_refuses_changed_grant_fields() {
        let configured = policy(true);
        let observed = observation();
        let lease = result(&configured, &observed, "10.0.2.2").unwrap();
        let mut newer = observed.clone();
        newer.sequence += 1;
        assert!(lease.is_current(&configured, &newer));
        for change in 0..6 {
            let mut newer = observed.clone();
            match change {
                0 => newer.networks[0].handle += 1,
                1 => {
                    newer.networks[0].interface_index += 1;
                    for route in &mut newer.networks[0].routes {
                        route.interface_index += 1;
                    }
                }
                2 => newer.permissions.as_mut().unwrap().local_network = false,
                3 => newer.permissions.as_mut().unwrap().background_location = false,
                4 => newer.networks[0].ssid = None,
                _ => newer.networks[0].blocked = true,
            }
            assert!(!lease.is_current(&configured, &newer));
        }
        let mut changed = configured.clone();
        changed.rules[0].id = Uuid::nil();
        assert!(!lease.is_current(&changed, &observed));
        changed = configured.clone();
        changed.rules[0].ssid_ids.clear();
        assert!(!lease.is_current(&changed, &observed));
        changed = configured.clone();
        changed.rules[0].enabled = false;
        assert!(!lease.is_current(&changed, &observed));
        changed = configured.clone();
        changed.enabled = false;
        assert!(!lease.is_current(&changed, &observed));
        changed = configured.clone();
        changed.rules[0].cidrs = vec!["10.0.3.0/24".parse().unwrap()];
        assert!(!lease.is_current(&changed, &observed));
    }

    #[test]
    fn revalidation_checks_destination_scope_and_rule_set_equality() {
        let configured = policy(false);
        let observed = observation();
        let original = result(&configured, &observed, "10.0.2.2").unwrap();
        for change in 0..3 {
            let mut forged = original.clone();
            match change {
                0 => forged.scope_id = 15,
                1 => forged.rule_ids.clear(),
                _ => forged.needs_wifi_name = true,
            }
            assert!(!forged.is_current(&configured, &observed));
        }
        let mut changed = original;
        changed.destination = "1.1.1.1".parse().unwrap();
        assert!(!changed.is_current(&configured, &observed));
    }

    #[test]
    fn condition_readiness_does_not_authorize_an_unreachable_destination() {
        let configured = policy(false);
        let mut observed = observation();
        observed.networks[0]
            .routes
            .push(route("10.0.2.2/32", 7, None));
        assert_eq!(
            condition_readiness(
                &configured.rules[0],
                &observed.networks,
                observed.permissions.unwrap()
            ),
            Ok(())
        );
        assert_eq!(
            result(&configured, &observed, "10.0.2.2"),
            Err(DeliveryRefusal::NoEligibleNetwork)
        );
    }

    #[test]
    fn lease_refusal_and_route_debug_do_not_expose_addresses_handles_or_names() {
        let lease = result(&policy(true), &observation(), "10.0.2.2").unwrap();
        let debug = format!(
            "{lease:?} {:?} {:?}",
            DeliveryRefusal::RouteUnknown,
            RouteDelivery::Gateway("10.0.2.2".parse().unwrap())
        );
        for secret in ["10.0.2.2", "987654321", "synthetic-wifi", "synthetic-rule"] {
            assert!(!debug.contains(secret));
        }
    }
}
