use crate::types::{FromProtobufTypeError, proto};
use mullvad_types::settings::local_network_access::{
    LocalBypassRule, LocalNetworkAccess, MAX_CIDRS_PER_RULE, MAX_RULE_NAME_CHARS, MAX_RULES,
    MAX_SSIDS_PER_RULE, SsidIdentity,
};

impl From<&LocalNetworkAccess> for proto::LocalNetworkAccess {
    fn from(policy: &LocalNetworkAccess) -> Self {
        Self {
            enabled: policy.enabled,
            rules: policy
                .rules
                .iter()
                .map(proto::LocalBypassRule::from)
                .collect(),
        }
    }
}

impl From<&LocalBypassRule> for proto::LocalBypassRule {
    fn from(rule: &LocalBypassRule) -> Self {
        Self {
            id: rule.id.to_string(),
            name: rule.name.clone(),
            enabled: rule.enabled,
            cidrs: rule.cidrs.iter().map(ToString::to_string).collect(),
            ssid_ids: rule
                .ssid_ids
                .iter()
                .map(|ssid| ssid.bytes().to_vec())
                .collect(),
        }
    }
}

impl TryFrom<proto::LocalNetworkAccess> for LocalNetworkAccess {
    type Error = FromProtobufTypeError;

    fn try_from(policy: proto::LocalNetworkAccess) -> Result<Self, Self::Error> {
        // Refuse oversized repeated fields before allocating a second policy.
        if policy.rules.len() > MAX_RULES {
            return Err(FromProtobufTypeError::invalid_argument(
                "too many local rules",
            ));
        }
        let mut policy = Self {
            enabled: policy.enabled,
            rules: policy
                .rules
                .into_iter()
                .map(LocalBypassRule::try_from)
                .collect::<Result<_, _>>()?,
        };
        policy
            .validate()
            .map_err(|error| FromProtobufTypeError::invalid_argument(error.to_string()))?;
        policy.deduplicate();
        Ok(policy)
    }
}

impl TryFrom<proto::LocalBypassRule> for LocalBypassRule {
    type Error = FromProtobufTypeError;

    fn try_from(rule: proto::LocalBypassRule) -> Result<Self, Self::Error> {
        if rule.cidrs.len() > MAX_CIDRS_PER_RULE
            || rule.ssid_ids.len() > MAX_SSIDS_PER_RULE
            || rule.name.chars().count() > MAX_RULE_NAME_CHARS
        {
            return Err(FromProtobufTypeError::invalid_argument(
                "local rule exceeds input limits",
            ));
        }
        Ok(Self {
            id: super::arg_from_str(&rule.id, "invalid local rule identifier")?,
            name: rule.name,
            enabled: rule.enabled,
            // Parsing errors can contain suggested addresses. Never put their
            // payload into the RPC status or its diagnostic representation.
            cidrs: rule
                .cidrs
                .into_iter()
                .map(|text| super::arg_from_str(&text, "invalid local prefix"))
                .collect::<Result<_, _>>()?,
            ssid_ids: rule
                .ssid_ids
                .into_iter()
                .map(|bytes| {
                    SsidIdentity::from_bytes(bytes).ok_or_else(|| {
                        FromProtobufTypeError::invalid_argument("invalid SSID byte identity")
                    })
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn policy() -> LocalNetworkAccess {
        LocalNetworkAccess {
            enabled: true,
            rules: vec![LocalBypassRule {
                id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
                name: "test rule".into(),
                enabled: true,
                cidrs: vec![
                    "192.168.240.0/28".parse().unwrap(),
                    "fe80::10/128".parse().unwrap(),
                ],
                ssid_ids: vec![SsidIdentity::from_bytes(vec![0, 255, 65, 32]).unwrap()],
            }],
        }
    }

    #[test]
    fn wire_round_trip_preserves_policy_and_binary_identities() {
        let original = policy();
        let encoded = proto::LocalNetworkAccess::from(&original).encode_to_vec();
        let decoded = proto::LocalNetworkAccess::decode(encoded.as_slice()).unwrap();
        assert_eq!(LocalNetworkAccess::try_from(decoded).unwrap(), original);
    }

    #[test]
    fn settings_without_policy_default_and_reset_key_is_additive() {
        let mut settings = mullvad_types::settings::Settings::default();
        let mut wire = proto::Settings::from(&settings);
        wire.local_network_access = None;
        let parsed = mullvad_types::settings::Settings::try_from(wire).unwrap();
        assert_eq!(parsed.local_network_access, LocalNetworkAccess::default());
        settings.local_network_access = policy();
        let parsed =
            mullvad_types::settings::Settings::try_from(proto::Settings::from(&settings)).unwrap();
        assert_eq!(parsed.local_network_access, settings.local_network_access);
        let key = mullvad_types::settings::SettingsKey::LocalNetworkAccess;
        let wire_key = proto::SettingsKey::from(key.clone());
        assert_eq!(wire_key as i32, 13);
        assert_eq!(
            mullvad_types::settings::SettingsKey::try_from(wire_key).unwrap(),
            key
        );
    }

    #[test]
    fn invalid_wire_inputs_never_echo_values_in_status_or_debug() {
        for field in 0..4 {
            let mut wire = proto::LocalNetworkAccess::from(&policy());
            match field {
                0 => wire.rules[0].id = "secret-id".into(),
                1 => wire.rules[0].cidrs = vec!["secret-prefix".into()],
                2 => wire.rules[0].cidrs = vec!["192.168.241.27/24".into()],
                _ => {
                    wire.rules[0].ssid_ids =
                        vec![b"secret-ssid-that-is-over-thirty-two-bytes".to_vec()]
                }
            }
            let error = LocalNetworkAccess::try_from(wire).unwrap_err();
            let diagnostic = format!("{error} {error:?}");
            let status: crate::Status = error.into();
            assert_eq!(status.code(), crate::Code::InvalidArgument);
            for secret in ["secret-id", "secret-prefix", "192.168.241", "secret-ssid"] {
                assert!(!diagnostic.contains(secret));
                assert!(!status.message().contains(secret));
            }
        }
    }

    #[test]
    fn wire_limits_reject_excess_before_deduplication() {
        let original = proto::LocalNetworkAccess::from(&policy());
        for field in 0..4 {
            let mut wire = original.clone();
            let rule = &mut wire.rules[0];
            match field {
                0 => rule.cidrs = vec![rule.cidrs[0].clone(); MAX_CIDRS_PER_RULE + 1],
                1 => rule.ssid_ids = vec![rule.ssid_ids[0].clone(); MAX_SSIDS_PER_RULE + 1],
                2 => rule.name = "x".repeat(MAX_RULE_NAME_CHARS + 1),
                _ => wire.rules = vec![rule.clone(); MAX_RULES + 1],
            }
            assert!(LocalNetworkAccess::try_from(wire).is_err());
        }
    }

    #[test]
    fn wire_rejects_duplicate_ids_and_empty_enabled_rules_and_deduplicates_entries() {
        let mut wire = proto::LocalNetworkAccess::from(&policy());
        wire.rules.push(wire.rules[0].clone());
        assert!(LocalNetworkAccess::try_from(wire).is_err());
        let mut wire = proto::LocalNetworkAccess::from(&policy());
        wire.rules[0].cidrs.clear();
        assert!(LocalNetworkAccess::try_from(wire.clone()).is_err());
        wire.rules[0].enabled = false;
        assert_eq!(
            LocalNetworkAccess::try_from(wire).unwrap().rules[0]
                .ssid_ids
                .len(),
            1
        );
        let mut wire = proto::LocalNetworkAccess::from(&policy());
        let rule = &mut wire.rules[0];
        rule.cidrs.push(rule.cidrs[0].clone());
        rule.ssid_ids.push(rule.ssid_ids[0].clone());
        assert_eq!(LocalNetworkAccess::try_from(wire).unwrap(), policy());
    }
}
