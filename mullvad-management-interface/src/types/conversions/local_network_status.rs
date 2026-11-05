use crate::types::{FromProtobufTypeError, proto};
use mullvad_types::settings::local_network_access::{SsidIdentity, status::*};

impl From<&LocalNetworkStatus> for proto::LocalNetworkStatus {
    fn from(status: &LocalNetworkStatus) -> Self {
        Self {
            revision: status.revision,
            observer_available: status.observer_available,
            forwarding: proto::local_network_status::ForwardingAvailability::from(status.forwarding)
                as i32,
            current_wifi: Some(proto::ConnectedWifi {
                identity: Some(match &status.current_wifi {
                    ConnectedWifi::Known(ssid) => {
                        proto::connected_wifi::Identity::Ssid(ssid.bytes().to_vec())
                    }
                    ConnectedWifi::Unknown(reason) => proto::connected_wifi::Identity::Unknown(
                        proto::connected_wifi::UnknownReason::from(*reason) as i32,
                    ),
                }),
            }),
            rules: status
                .rules
                .iter()
                .map(|rule| proto::LocalRuleStatus {
                    id: rule.id.to_string(),
                    state: match rule.state {
                        RuleState::ConditionsMet => proto::local_rule_status::State::ConditionsMet,
                        RuleState::Forwarding => proto::local_rule_status::State::Forwarding,
                        RuleState::Inactive(_) => proto::local_rule_status::State::Inactive,
                    } as i32,
                    reason: match rule.state {
                        RuleState::ConditionsMet | RuleState::Forwarding => None,
                        RuleState::Inactive(reason) => {
                            Some(proto::LocalRuleInactiveReason::from(reason) as i32)
                        }
                    },
                })
                .collect(),
        }
    }
}

impl TryFrom<proto::LocalNetworkStatus> for LocalNetworkStatus {
    type Error = FromProtobufTypeError;
    fn try_from(status: proto::LocalNetworkStatus) -> Result<Self, Self::Error> {
        let invalid = || FromProtobufTypeError::invalid_argument("invalid local network status");
        let forwarding =
            proto::local_network_status::ForwardingAvailability::try_from(status.forwarding)
                .map_err(|_| invalid())?
                .into();
        let current_wifi = match status
            .current_wifi
            .and_then(|wifi| wifi.identity)
            .ok_or_else(invalid)?
        {
            proto::connected_wifi::Identity::Ssid(bytes) => {
                ConnectedWifi::Known(SsidIdentity::from_bytes(bytes).ok_or_else(invalid)?)
            }
            proto::connected_wifi::Identity::Unknown(reason) => ConnectedWifi::Unknown(
                proto::connected_wifi::UnknownReason::try_from(reason)
                    .map_err(|_| invalid())?
                    .into(),
            ),
        };
        let rules = status
            .rules
            .into_iter()
            .map(|rule| {
                let state = match (
                    proto::local_rule_status::State::try_from(rule.state).map_err(|_| invalid())?,
                    rule.reason,
                ) {
                    (proto::local_rule_status::State::ConditionsMet, None) => {
                        RuleState::ConditionsMet
                    }
                    (proto::local_rule_status::State::Forwarding, None) => RuleState::Forwarding,
                    (proto::local_rule_status::State::Inactive, Some(reason)) => {
                        RuleState::Inactive(
                            proto::LocalRuleInactiveReason::try_from(reason)
                                .map_err(|_| invalid())?
                                .into(),
                        )
                    }
                    _ => return Err(invalid()),
                };
                Ok(LocalRuleStatus {
                    id: super::arg_from_str(&rule.id, "invalid local rule identifier")?,
                    state,
                })
            })
            .collect::<Result<_, FromProtobufTypeError>>()?;
        Ok(Self {
            revision: status.revision,
            observer_available: status.observer_available,
            forwarding,
            current_wifi,
            rules,
        })
    }
}

macro_rules! enum_conversion {
    ($domain:ty, $wire:ty, $($variant:ident),+ $(,)?) => {
        impl From<$domain> for $wire {
            fn from(value: $domain) -> Self { match value { $(<$domain>::$variant => Self::$variant),+ } }
        }
        impl From<$wire> for $domain {
            fn from(value: $wire) -> Self { match value { $(<$wire>::$variant => Self::$variant),+ } }
        }
    };
}
enum_conversion!(
    ForwardingAvailability,
    proto::local_network_status::ForwardingAvailability,
    NotAvailable,
    Off,
    Active,
    PausedWhileConnected,
    Failed
);
enum_conversion!(
    InactiveReason,
    proto::LocalRuleInactiveReason,
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
    ObserverUnavailable
);
enum_conversion!(
    WifiUnknownReason,
    proto::connected_wifi::UnknownReason,
    PermissionMissing,
    LocationOff,
    NotOnWifi,
    MultipleWifi,
    Pending
);

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn samples() -> Vec<LocalNetworkStatus> {
        let reasons = [
            InactiveReason::PolicyOff,
            InactiveReason::RuleOff,
            InactiveReason::LocalPermissionMissing,
            InactiveReason::LocationPermissionMissing,
            InactiveReason::BackgroundLocationMissing,
            InactiveReason::LocationOff,
            InactiveReason::NoEligibleNetwork,
            InactiveReason::WaitingForNetworkDetails,
            InactiveReason::DifferentWifi,
            InactiveReason::WifiNameUnknown,
            InactiveReason::MultipleNetworks,
            InactiveReason::ObserverUnavailable,
        ];
        let wifi = [
            ConnectedWifi::Known(SsidIdentity::from_bytes(vec![0, 255, 65, 32]).unwrap()),
            ConnectedWifi::Unknown(WifiUnknownReason::PermissionMissing),
            ConnectedWifi::Unknown(WifiUnknownReason::LocationOff),
            ConnectedWifi::Unknown(WifiUnknownReason::NotOnWifi),
            ConnectedWifi::Unknown(WifiUnknownReason::MultipleWifi),
            ConnectedWifi::Unknown(WifiUnknownReason::Pending),
        ];
        wifi.into_iter()
            .map(|current_wifi| LocalNetworkStatus {
                revision: u64::MAX,
                observer_available: true,
                forwarding: ForwardingAvailability::NotAvailable,
                current_wifi,
                rules: std::iter::once(LocalRuleStatus {
                    id: "00000000-0000-0000-0000-000000000000".parse().unwrap(),
                    state: RuleState::ConditionsMet,
                })
                .chain(reasons.into_iter().enumerate().map(|(i, reason)| {
                    LocalRuleStatus {
                        id: format!("00000000-0000-0000-0000-{:012x}", i + 1)
                            .parse()
                            .unwrap(),
                        state: RuleState::Inactive(reason),
                    }
                }))
                .collect(),
            })
            .collect()
    }

    #[test]
    fn local_status_all_variants_round_trip() {
        let fixtures = include_str!("../../../testdata/local-network-status.hex");
        let samples = samples();
        assert_eq!(fixtures.lines().count(), samples.len());
        for (sample, fixture) in samples.into_iter().zip(fixtures.lines()) {
            let wire = proto::LocalNetworkStatus::from(&sample);
            let encoded = wire.encode_to_vec();
            let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, fixture);
            let wire = proto::LocalNetworkStatus::decode(encoded.as_slice()).unwrap();
            assert_eq!(LocalNetworkStatus::try_from(wire.clone()).unwrap(), sample);
            let event = proto::DaemonEvent {
                event: Some(proto::daemon_event::Event::LocalNetworkStatus(wire)),
            };
            let event = proto::DaemonEvent::decode(event.encode_to_vec().as_slice()).unwrap();
            assert!(
                matches!(crate::client::DaemonEvent::try_from(event.event.unwrap()).unwrap(), crate::client::DaemonEvent::LocalNetworkStatus(status) if status == sample)
            );
        }
    }

    #[test]
    fn forwarding_values_and_rule_states_round_trip_without_changing_legacy_fixtures() {
        for availability in [
            ForwardingAvailability::NotAvailable,
            ForwardingAvailability::Off,
            ForwardingAvailability::Active,
            ForwardingAvailability::PausedWhileConnected,
            ForwardingAvailability::Failed,
        ] {
            for state in [
                RuleState::ConditionsMet,
                RuleState::Forwarding,
                RuleState::Inactive(InactiveReason::ObserverUnavailable),
            ] {
                let mut sample = samples().remove(0);
                sample.forwarding = availability;
                sample.rules[0].state = state;
                let encoded = proto::LocalNetworkStatus::from(&sample).encode_to_vec();
                let wire = proto::LocalNetworkStatus::decode(encoded.as_slice()).unwrap();
                assert_eq!(LocalNetworkStatus::try_from(wire).unwrap(), sample);
            }
        }
        let mut wire = proto::LocalNetworkStatus::from(&samples()[0]);
        wire.rules[0].state = proto::local_rule_status::State::Forwarding as i32;
        wire.rules[0].reason = Some(0);
        assert!(LocalNetworkStatus::try_from(wire).is_err());
    }

    #[test]
    fn local_status_rejects_incoherent_or_unknown_wire_values_without_payloads() {
        let original = proto::LocalNetworkStatus::from(&samples()[0]);
        for case in 0..6 {
            let mut wire = original.clone();
            match case {
                0 => wire.forwarding = 99,
                1 => wire.current_wifi = None,
                2 => {
                    wire.current_wifi.as_mut().unwrap().identity =
                        Some(proto::connected_wifi::Identity::Ssid(vec![]))
                }
                3 => wire.rules[0].reason = Some(0),
                4 => wire.rules[1].reason = None,
                _ => wire.rules[1].reason = Some(99),
            }
            let error = LocalNetworkStatus::try_from(wire).unwrap_err();
            assert!(!format!("{error:?}").contains("00ff"));
        }
    }
}
