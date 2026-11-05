//! Runtime status, deliberately separate from policy and forwarding authority.
use super::{
    LocalNetworkAccess, SsidIdentity,
    eligibility::{NetworkObservation, PhysicalTransport, condition_readiness},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InactiveReason {
    PolicyOff,
    RuleOff,
    LocalPermissionMissing,
    LocationPermissionMissing,
    BackgroundLocationMissing,
    LocationOff,
    NoEligibleNetwork,
    WaitingForNetworkDetails,
    DifferentWifi,
    WifiNameUnknown,
    MultipleNetworks,
    ObserverUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleState {
    ConditionsMet,
    Inactive(InactiveReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRuleStatus {
    pub id: Uuid,
    pub state: RuleState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ForwardingAvailability {
    #[default]
    NotAvailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiUnknownReason {
    PermissionMissing,
    LocationOff,
    NotOnWifi,
    MultipleWifi,
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectedWifi {
    Known(SsidIdentity),
    Unknown(WifiUnknownReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNetworkStatus {
    pub revision: u64,
    pub observer_available: bool,
    pub forwarding: ForwardingAvailability,
    pub current_wifi: ConnectedWifi,
    pub rules: Vec<LocalRuleStatus>,
}

pub fn rule_statuses(
    policy: &LocalNetworkAccess,
    observation: Option<&NetworkObservation>,
) -> Vec<LocalRuleStatus> {
    policy
        .rules
        .iter()
        .map(|rule| {
            let readiness = if !policy.enabled {
                Err(InactiveReason::PolicyOff)
            } else if !rule.enabled {
                Err(InactiveReason::RuleOff)
            } else {
                observation
                    .ok_or(InactiveReason::ObserverUnavailable)
                    .and_then(|observation| {
                        let permissions = observation
                            .permissions
                            .ok_or(InactiveReason::WaitingForNetworkDetails)?;
                        condition_readiness(rule, &observation.networks, permissions)
                    })
            };
            LocalRuleStatus {
                id: rule.id,
                state: match readiness {
                    Ok(()) => RuleState::ConditionsMet,
                    Err(reason) => RuleState::Inactive(reason),
                },
            }
        })
        .collect()
}

pub fn current_wifi(observation: Option<&NetworkObservation>) -> ConnectedWifi {
    use WifiUnknownReason::*;
    let unknown = ConnectedWifi::Unknown;
    let Some(observation) = observation else {
        return unknown(Pending);
    };
    let Some(permissions) = observation.permissions else {
        return unknown(Pending);
    };
    let wifi: Vec<_> = observation
        .networks
        .iter()
        .filter(|network| network.transport == PhysicalTransport::Wifi && !network.blocked)
        .collect();
    if wifi.is_empty() {
        return unknown(NotOnWifi);
    }
    if wifi.len() > 1 {
        return unknown(MultipleWifi);
    }
    if let Err(reason) = permissions.ssid_readiness() {
        return unknown(match reason {
            InactiveReason::LocationOff => LocationOff,
            _ => PermissionMissing,
        });
    }
    let network = wifi[0];
    if !network.capabilities_fresh
        || !network.links_fresh
        || network.handle <= 0
        || network.interface_index <= 0
    {
        return unknown(Pending);
    }
    network
        .ssid
        .clone()
        .map(ConnectedWifi::Known)
        .unwrap_or_else(|| unknown(Pending))
}

impl LocalNetworkStatus {
    /// Revision is assigned only by the daemon's single publication owner.
    pub fn from_observation(
        policy: &LocalNetworkAccess,
        observation: Option<&NetworkObservation>,
    ) -> Self {
        Self {
            revision: 0,
            observer_available: observation.is_some(),
            forwarding: ForwardingAvailability::NotAvailable,
            current_wifi: current_wifi(observation),
            rules: rule_statuses(policy, observation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        LocalBypassRule,
        eligibility::{PermissionState, PhysicalAddress, PhysicalNetwork},
    };
    use super::*;
    use talpid_types::local_network::{
        LocalNetworkSnapshot, LocalPhysicalAddress, LocalPhysicalNetwork, LocalPhysicalPrefix,
        LocalPhysicalRoute,
    };

    fn identity() -> SsidIdentity {
        SsidIdentity::from_bytes(b"synthetic wifi".to_vec()).unwrap()
    }
    fn policy(conditioned: bool) -> LocalNetworkAccess {
        LocalNetworkAccess {
            enabled: true,
            rules: vec![LocalBypassRule {
                id: Uuid::nil(),
                name: "synthetic rule".into(),
                enabled: true,
                cidrs: vec!["192.168.0.0/16".parse().unwrap()],
                ssid_ids: if conditioned {
                    vec![identity()]
                } else {
                    vec![]
                },
            }],
        }
    }
    fn observation() -> NetworkObservation {
        NetworkObservation {
            permissions: Some(PermissionState {
                local_network: true,
                precise_location: true,
                background_location: true,
                location_enabled: true,
                location_allowed: true,
            }),
            networks: vec![PhysicalNetwork {
                handle: 1,
                transport: PhysicalTransport::Wifi,
                capabilities_fresh: true,
                links_fresh: true,
                blocked: false,
                interface_index: 4,
                addresses: vec![PhysicalAddress {
                    prefix: "192.168.7.9/24".parse().unwrap(),
                    usable: true,
                }],
                routes: vec![],
                ssid: Some(identity()),
            }],
        }
    }
    fn state(policy: &LocalNetworkAccess, observation: Option<&NetworkObservation>) -> RuleState {
        let rows = rule_statuses(policy, observation);
        assert_eq!(rows.len(), policy.rules.len());
        assert_eq!(rows[0].id, policy.rules[0].id);
        rows[0].state.clone()
    }
    fn inactive(reason: InactiveReason) -> RuleState {
        RuleState::Inactive(reason)
    }

    #[test]
    fn conditions_met_is_not_forwarding_and_does_not_require_a_route() {
        for conditioned in [false, true] {
            let status =
                LocalNetworkStatus::from_observation(&policy(conditioned), Some(&observation()));
            assert_eq!(status.rules[0].state, RuleState::ConditionsMet);
            assert_eq!(status.forwarding, ForwardingAvailability::NotAvailable);
            assert_eq!(status.revision, 0);
            assert!(status.observer_available);
        }
    }

    #[test]
    fn policy_off_and_rule_off_precede_missing_observation() {
        let mut policy = policy(true);
        policy.enabled = false;
        policy.rules[0].enabled = false;
        assert_eq!(state(&policy, None), inactive(InactiveReason::PolicyOff));
        policy.enabled = true;
        assert_eq!(state(&policy, None), inactive(InactiveReason::RuleOff));
        policy.rules[0].enabled = true;
        assert_eq!(
            state(&policy, None),
            inactive(InactiveReason::ObserverUnavailable)
        );
        assert_eq!(
            state(&policy, Some(&NetworkObservation::default())),
            inactive(InactiveReason::WaitingForNetworkDetails)
        );
        assert!(!LocalNetworkStatus::from_observation(&policy, None).observer_available);
    }

    #[test]
    fn each_permission_reason_is_distinct_and_plain_rules_need_no_location() {
        for (permissions, reason) in [
            (
                PermissionState {
                    local_network: false,
                    ..observation().permissions.unwrap()
                },
                InactiveReason::LocalPermissionMissing,
            ),
            (
                PermissionState {
                    precise_location: false,
                    ..observation().permissions.unwrap()
                },
                InactiveReason::LocationPermissionMissing,
            ),
            (
                PermissionState {
                    background_location: false,
                    ..observation().permissions.unwrap()
                },
                InactiveReason::BackgroundLocationMissing,
            ),
            (
                PermissionState {
                    location_enabled: false,
                    ..observation().permissions.unwrap()
                },
                InactiveReason::LocationOff,
            ),
        ] {
            let mut observed = observation();
            observed.permissions = Some(permissions);
            assert_eq!(state(&policy(true), Some(&observed)), inactive(reason));
        }
        let mut observed = observation();
        observed.permissions = Some(PermissionState {
            local_network: true,
            ..Default::default()
        });
        observed.networks[0].transport = PhysicalTransport::Ethernet;
        observed.networks[0].ssid = None;
        assert_eq!(
            state(&policy(false), Some(&observed)),
            RuleState::ConditionsMet
        );
    }

    #[test]
    fn wifi_names_are_exact_and_unknown_never_becomes_unconditioned() {
        let mut observed = observation();
        observed.networks[0].ssid =
            Some(SsidIdentity::from_bytes(b"synthetic wifi ".to_vec()).unwrap());
        assert_eq!(
            state(&policy(true), Some(&observed)),
            inactive(InactiveReason::DifferentWifi)
        );
        observed.networks[0].ssid = None;
        assert_eq!(
            state(&policy(true), Some(&observed)),
            inactive(InactiveReason::WifiNameUnknown)
        );
        assert_eq!(
            state(&policy(false), Some(&observed)),
            RuleState::ConditionsMet
        );
    }

    #[test]
    fn unknown_competitors_and_duplicate_networks_preserve_ambiguity() {
        let mut observed = observation();
        let mut other = observed.networks[0].clone();
        other.handle = 2;
        other.ssid = None;
        observed.networks.push(other);
        for conditioned in [true, false] {
            assert_eq!(
                state(&policy(conditioned), Some(&observed)),
                inactive(InactiveReason::MultipleNetworks)
            );
        }
        observed.networks[1].handle = 1;
        assert_eq!(
            state(&policy(false), Some(&observed)),
            inactive(InactiveReason::MultipleNetworks)
        );
        observed.networks[1].handle = 2;
        observed.networks[1].ssid = Some(SsidIdentity::from_bytes(b"different".to_vec()).unwrap());
        assert_eq!(
            state(&policy(true), Some(&observed)),
            RuleState::ConditionsMet
        );
    }

    #[test]
    fn freshness_scope_transport_and_usable_family_are_required() {
        let policy = policy(false);
        for missing in 0..4 {
            let mut observed = observation();
            match missing {
                0 => observed.networks[0].capabilities_fresh = false,
                1 => observed.networks[0].links_fresh = false,
                2 => observed.networks[0].handle = 0,
                _ => observed.networks[0].interface_index = 0,
            }
            assert_eq!(
                state(&policy, Some(&observed)),
                inactive(InactiveReason::WaitingForNetworkDetails)
            );
        }
        for missing in 0..5 {
            let mut observed = observation();
            match missing {
                0 => observed.networks.clear(),
                1 => observed.networks[0].blocked = true,
                2 => observed.networks[0].transport = PhysicalTransport::Other,
                3 => observed.networks[0].addresses.clear(),
                _ => observed.networks[0].addresses[0].usable = false,
            }
            assert_eq!(
                state(&policy, Some(&observed)),
                inactive(InactiveReason::NoEligibleNetwork)
            );
        }
        for address in ["0.0.0.0/0", "127.0.0.1/8", "224.0.0.1/4", "fe80::1/64"] {
            let mut observed = observation();
            observed.networks[0].addresses[0].prefix = address.parse().unwrap();
            assert_eq!(
                state(&policy, Some(&observed)),
                inactive(InactiveReason::NoEligibleNetwork)
            );
        }
        let mut v6_policy = policy.clone();
        v6_policy.rules[0].cidrs = vec!["fe80::/10".parse().unwrap()];
        let mut observed = observation();
        observed.networks[0].addresses[0].prefix = "fe80::1/64".parse().unwrap();
        assert_eq!(state(&v6_policy, Some(&observed)), RuleState::ConditionsMet);
    }

    #[test]
    fn connected_wifi_covers_every_unknown_reason_and_redacts_debug() {
        assert_eq!(
            current_wifi(None),
            ConnectedWifi::Unknown(WifiUnknownReason::Pending)
        );
        for (case, reason) in [
            (0, WifiUnknownReason::PermissionMissing),
            (1, WifiUnknownReason::LocationOff),
            (2, WifiUnknownReason::NotOnWifi),
            (3, WifiUnknownReason::MultipleWifi),
            (4, WifiUnknownReason::Pending),
        ] {
            let mut observed = observation();
            match case {
                0 => observed.permissions.as_mut().unwrap().precise_location = false,
                1 => observed.permissions.as_mut().unwrap().location_enabled = false,
                2 => observed.networks[0].transport = PhysicalTransport::Ethernet,
                3 => observed.networks.push(observed.networks[0].clone()),
                _ => observed.networks[0].ssid = None,
            }
            assert_eq!(
                current_wifi(Some(&observed)),
                ConnectedWifi::Unknown(reason)
            );
        }
        let observed = observation();
        assert_eq!(
            current_wifi(Some(&observed)),
            ConnectedWifi::Known(identity())
        );
        let status = LocalNetworkStatus::from_observation(&policy(true), Some(&observed));
        let debug = format!("{status:?} {observed:?}");
        for secret in [
            "synthetic wifi",
            "synthetic rule",
            "192.168.7.9",
            &identity().encoded_bytes(),
        ] {
            assert!(!debug.contains(secret));
        }
    }

    fn snapshot() -> LocalNetworkSnapshot {
        let prefix = LocalPhysicalPrefix {
            address: "192.168.7.9".parse().unwrap(),
            prefix_length: 24,
        };
        let route = LocalPhysicalRoute {
            destination: prefix.clone(),
            gateway: None,
            interface_index: 4,
            route_type: 1,
        };
        LocalNetworkSnapshot {
            sequence: 1,
            observer_running: true,
            local_ready: true,
            fine_ready: true,
            background_ready: true,
            location_enabled: true,
            location_allowed: true,
            networks: vec![LocalPhysicalNetwork {
                network_handle: 1,
                transport: 1,
                capabilities_fresh: true,
                links_fresh: true,
                blocked: false,
                interface_index: 4,
                addresses: vec![LocalPhysicalAddress {
                    prefix,
                    usable: true,
                }],
                routes: vec![route],
                ssid_hex: Some(identity().encoded_bytes()),
            }],
        }
    }

    #[test]
    fn location_off_with_granted_permissions_is_not_a_missing_permission() {
        let mut snapshot = snapshot();
        snapshot.location_enabled = false;
        snapshot.location_allowed = false;
        let observed = NetworkObservation::from(&snapshot);
        assert!(observed.networks[0].ssid.is_none());
        assert_eq!(
            state(&policy(true), Some(&observed)),
            inactive(InactiveReason::LocationOff)
        );
        assert_eq!(
            current_wifi(Some(&observed)),
            ConnectedWifi::Unknown(WifiUnknownReason::LocationOff)
        );
        assert_eq!(
            state(&policy(false), Some(&observed)),
            RuleState::ConditionsMet
        );
    }

    #[test]
    fn foreground_only_location_reports_missing_background_access() {
        let mut snapshot = snapshot();
        snapshot.background_ready = false;
        snapshot.location_allowed = false;
        let observed = NetworkObservation::from(&snapshot);
        assert!(observed.networks[0].ssid.is_none());
        assert_eq!(
            state(&policy(true), Some(&observed)),
            inactive(InactiveReason::BackgroundLocationMissing)
        );
        assert_eq!(
            current_wifi(Some(&observed)),
            ConnectedWifi::Unknown(WifiUnknownReason::PermissionMissing)
        );
        assert_eq!(
            state(&policy(false), Some(&observed)),
            RuleState::ConditionsMet
        );
    }

    #[test]
    fn snapshot_mapping_keeps_routes_and_discards_unreadable_identity() {
        let mut snapshot = snapshot();
        let observed = NetworkObservation::from(&snapshot);
        assert_eq!(observed.networks[0].routes, snapshot.networks[0].routes);
        assert_eq!(
            state(&policy(true), Some(&observed)),
            RuleState::ConditionsMet
        );
        snapshot.location_allowed = false;
        let observed = NetworkObservation::from(&snapshot);
        assert!(observed.networks[0].ssid.is_none());
        assert_eq!(
            current_wifi(Some(&observed)),
            ConnectedWifi::Unknown(WifiUnknownReason::PermissionMissing)
        );
        assert_eq!(
            state(&policy(true), Some(&observed)),
            inactive(InactiveReason::LocationPermissionMissing)
        );
        assert_eq!(
            state(&policy(false), Some(&observed)),
            RuleState::ConditionsMet
        );
    }
}
