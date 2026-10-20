//! Persisted local-network rules. Observed networks and permission state are not
//! part of the policy, so losing an observation cannot erase a Wi-Fi condition.

use ipnetwork::IpNetwork;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashSet, fmt, net::IpAddr, str::FromStr};
use uuid::Uuid;

const LOCAL_SCOPES: [&str; 6] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

pub const MAX_RULES: usize = 64;
pub const MAX_CIDRS_PER_RULE: usize = 32;
pub const MAX_SSIDS_PER_RULE: usize = 16;
pub const MAX_RULE_NAME_CHARS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CidrError {
    #[error("malformed local prefix")]
    Malformed,
    #[error("host bits are set; use canonical prefix {suggested}")]
    Noncanonical { suggested: IpNetwork },
    #[error("prefix is not entirely private or link-local unicast")]
    OutsideLocalScope,
}

/// A canonical prefix entirely contained within one private or link-local scope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocalCidr(IpNetwork);

impl LocalCidr {
    pub fn network(self) -> IpNetwork {
        self.0
    }

    pub fn contains(self, destination: IpAddr) -> bool {
        self.0.contains(destination)
    }
}

impl FromStr for LocalCidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = text.split_once('/').ok_or(CidrError::Malformed)?;
        // Accept numeric CIDR notation only, never names or dotted netmasks.
        let address: IpAddr = address.parse().map_err(|_| CidrError::Malformed)?;
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CidrError::Malformed);
        }
        let prefix = prefix.parse().map_err(|_| CidrError::Malformed)?;
        let candidate = IpNetwork::new(address, prefix).map_err(|_| CidrError::Malformed)?;
        if candidate.ip() != candidate.network() {
            return Err(CidrError::Noncanonical {
                suggested: IpNetwork::new(candidate.network(), prefix)
                    .map_err(|_| CidrError::Malformed)?,
            });
        }
        let local = LOCAL_SCOPES.iter().any(|scope| {
            let scope: IpNetwork = scope.parse().expect("constant local scope");
            candidate.is_ipv4() == scope.is_ipv4()
                && candidate.prefix() >= scope.prefix()
                && scope.contains(candidate.ip())
        });
        if !local {
            return Err(CidrError::OutsideLocalScope);
        }
        Ok(Self(candidate))
    }
}

impl fmt::Display for LocalCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for LocalCidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for LocalCidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// An exact IEEE 802.11 SSID byte identity, not normalized display text.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SsidIdentity(Vec<u8>);

impl SsidIdentity {
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        (1..=32).contains(&bytes.len()).then_some(Self(bytes))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn encoded_bytes(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub fn from_encoded_bytes(text: &str) -> Option<Self> {
        if !(2..=64).contains(&text.len()) || !text.len().is_multiple_of(2) {
            return None;
        }
        let bytes = text
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16)?;
                let low = char::from(pair[1]).to_digit(16)?;
                Some((high * 16 + low) as u8)
            })
            .collect::<Option<Vec<_>>>()?;
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for SsidIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SsidIdentity(redacted)")
    }
}

impl Serialize for SsidIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encoded_bytes())
    }
}

impl<'de> Deserialize<'de> for SsidIdentity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_encoded_bytes(&String::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid SSID byte identity"))
    }
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct LocalNetworkAccess {
    pub enabled: bool,
    pub rules: Vec<LocalBypassRule>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalBypassRule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub cidrs: Vec<LocalCidr>,
    #[serde(default)]
    pub ssid_ids: Vec<SsidIdentity>,
}

// Debug summaries intentionally contain no user names, SSIDs or addresses.
impl fmt::Debug for LocalNetworkAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalNetworkAccess")
            .field("enabled", &self.enabled)
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

impl fmt::Debug for LocalBypassRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalBypassRule")
            .field("id", &self.id)
            .field("enabled", &self.enabled)
            .field("cidr_count", &self.cidrs.len())
            .field("ssid_count", &self.ssid_ids.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PolicyError {
    #[error("local policy changed concurrently")]
    Conflict,
    #[error("duplicate local rule identifier")]
    DuplicateRuleId,
    #[error("enabled local rule has no prefixes")]
    EmptyEnabledRule,
    #[error("too many local rules")]
    TooManyRules,
    #[error("too many local prefixes in a rule")]
    TooManyCidrs,
    #[error("too many Wi-Fi identities in a rule")]
    TooManySsids,
    #[error("local rule name is too long")]
    NameTooLong,
}

impl LocalNetworkAccess {
    /// Validate updates before deduplication, including disabled rules. Loading
    /// existing settings uses the normal upstream deserialization path instead.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.rules.len() > MAX_RULES {
            return Err(PolicyError::TooManyRules);
        }
        let mut ids = HashSet::new();
        for rule in &self.rules {
            if !ids.insert(rule.id) {
                return Err(PolicyError::DuplicateRuleId);
            }
            if rule.name.chars().count() > MAX_RULE_NAME_CHARS {
                return Err(PolicyError::NameTooLong);
            }
            if rule.cidrs.len() > MAX_CIDRS_PER_RULE {
                return Err(PolicyError::TooManyCidrs);
            }
            if rule.ssid_ids.len() > MAX_SSIDS_PER_RULE {
                return Err(PolicyError::TooManySsids);
            }
            if rule.enabled && rule.cidrs.is_empty() {
                return Err(PolicyError::EmptyEnabledRule);
            }
        }
        Ok(())
    }

    /// Remove repeated entries without changing rule order or exact identities.
    pub fn deduplicate(&mut self) {
        for rule in &mut self.rules {
            let mut cidrs = HashSet::new();
            rule.cidrs.retain(|cidr| cidrs.insert(*cidr));
            let mut ssids = HashSet::new();
            rule.ssid_ids.retain(|ssid| ssids.insert(ssid.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> LocalNetworkAccess {
        LocalNetworkAccess {
            enabled: true,
            rules: vec![LocalBypassRule {
                id: Uuid::nil(),
                name: "test-rule".into(),
                enabled: true,
                cidrs: vec!["192.168.240.0/28".parse().unwrap()],
                ssid_ids: vec![SsidIdentity::from_bytes(b"test-wifi".to_vec()).unwrap()],
            }],
        }
    }

    #[test]
    fn prefixes_are_entirely_within_local_scopes() {
        for text in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "fc00::/7",
            "fe80::/10",
            "192.168.240.10/32",
            "fd42::10/124",
            "fe80::10/128",
        ] {
            let cidr: LocalCidr = text.parse().unwrap();
            assert!(cidr.contains(cidr.network().network()));
            assert!(cidr.contains(cidr.network().broadcast()));
        }
        for text in [
            "0.0.0.0/0",
            "10.0.0.0/7",
            "172.0.0.0/8",
            "192.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.1/32",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "::/0",
            "::1/128",
            "2001:db8::/32",
            "ff02::/16",
        ] {
            assert_eq!(
                text.parse::<LocalCidr>(),
                Err(CidrError::OutsideLocalScope),
                "{text}"
            );
        }
        let cidr: LocalCidr = "192.168.240.0/28".parse().unwrap();
        assert!(cidr.contains("192.168.240.15".parse().unwrap()));
        assert!(!cidr.contains("192.168.240.16".parse().unwrap()));
        assert!(!cidr.contains("fd42::1".parse().unwrap()));
    }

    #[test]
    fn prefixes_require_numeric_canonical_cidr_notation() {
        for text in [
            " 10.0.0.0/8",
            "10.0.0.0/8 ",
            "10.0.0.1",
            "localhost/32",
            "10.0.0.0/255.0.0.0",
            "10.0.0.0/+8",
            "10.0.0.0/33",
            "fc00::/129",
        ] {
            assert_eq!(
                text.parse::<LocalCidr>(),
                Err(CidrError::Malformed),
                "{text}"
            );
        }
        assert_eq!(
            "192.168.3.27/23".parse::<LocalCidr>(),
            Err(CidrError::Noncanonical {
                suggested: "192.168.2.0/23".parse().unwrap(),
            })
        );
    }

    #[test]
    fn archive_format_round_trips_exact_identities() {
        // Public synthetic data in the archive's field/string format, including
        // an SSID that cannot be represented as UTF-8 text.
        let value = serde_json::json!({
            "enabled": true,
            "rules": [{
                "id": "00000000-0000-0000-0000-000000000000",
                "name": "archive sample",
                "enabled": true,
                "cidrs": ["192.168.240.0/28", "fe80::10/128"],
                "ssid_ids": ["00ff4120", "746573742d77696669"]
            }]
        });
        let policy: LocalNetworkAccess = serde_json::from_value(value.clone()).unwrap();
        policy.validate().unwrap();
        assert_eq!(policy.rules[0].ssid_ids[0].bytes(), &[0, 255, 65, 32]);
        assert_eq!(serde_json::to_value(policy).unwrap(), value);
    }

    #[test]
    fn additive_defaults_do_not_grant_access() {
        let empty: LocalNetworkAccess = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, LocalNetworkAccess::default());
        assert!(!empty.enabled);
        assert!(empty.rules.is_empty());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["rules"][0]
            .as_object_mut()
            .unwrap()
            .remove("ssid_ids");
        let without_condition: LocalNetworkAccess = serde_json::from_value(value).unwrap();
        assert!(without_condition.rules[0].ssid_ids.is_empty());
    }

    #[test]
    fn ssid_bytes_have_no_text_normalization() {
        for bytes in [vec![0], vec![255; 32], b"test-wifi ".to_vec()] {
            let ssid = SsidIdentity::from_bytes(bytes.clone()).unwrap();
            assert_eq!(ssid.bytes(), bytes);
            assert_eq!(
                SsidIdentity::from_encoded_bytes(&ssid.encoded_bytes()),
                Some(ssid)
            );
        }
        assert_ne!(
            SsidIdentity::from_bytes(b"test-wifi".to_vec()),
            SsidIdentity::from_bytes(b"test-wifi ".to_vec())
        );
        assert_eq!(
            SsidIdentity::from_encoded_bytes("Ff"),
            SsidIdentity::from_bytes(vec![255])
        );
        assert!(SsidIdentity::from_bytes(vec![]).is_none());
        assert!(SsidIdentity::from_bytes(vec![0; 33]).is_none());
        for invalid in ["", "0", "zz", "secret-ssid", "é", &"00".repeat(33)] {
            assert!(SsidIdentity::from_encoded_bytes(invalid).is_none());
        }
    }

    #[test]
    fn diagnostics_do_not_expose_rule_contents() {
        let policy = policy();
        let diagnostic = format!(
            "{policy:?} {:?} {:?}",
            policy.rules, policy.rules[0].ssid_ids
        );
        for secret in [
            "test-rule",
            "test-wifi",
            "746573742d77696669",
            "192.168.240",
        ] {
            assert!(!diagnostic.contains(secret));
        }
        let error = serde_json::from_str::<SsidIdentity>("\"secret-ssid\"").unwrap_err();
        assert!(!error.to_string().contains("secret-ssid"));
    }

    #[test]
    fn deduplication_preserves_order_and_distinct_conditions() {
        let mut policy = policy();
        let rule = &mut policy.rules[0];
        let other_cidr = "fe80::10/128".parse().unwrap();
        let other_ssid = SsidIdentity::from_bytes(b"test-wifi ".to_vec()).unwrap();
        rule.cidrs.extend([other_cidr, rule.cidrs[0]]);
        rule.ssid_ids
            .extend([other_ssid.clone(), rule.ssid_ids[0].clone()]);
        policy.deduplicate();
        assert_eq!(
            policy.rules[0].cidrs,
            vec!["192.168.240.0/28".parse().unwrap(), other_cidr]
        );
        assert_eq!(
            policy.rules[0].ssid_ids,
            vec![
                SsidIdentity::from_bytes(b"test-wifi".to_vec()).unwrap(),
                other_ssid
            ]
        );
    }

    #[test]
    fn duplicate_ids_and_empty_enabled_rules_are_invalid() {
        let mut policy = policy();
        policy.rules.push(policy.rules[0].clone());
        assert_eq!(policy.validate(), Err(PolicyError::DuplicateRuleId));
        policy.rules.pop();
        policy.rules[0].cidrs.clear();
        assert_eq!(policy.validate(), Err(PolicyError::EmptyEnabledRule));
        policy.rules[0].enabled = false;
        policy.validate().unwrap();
        assert_eq!(policy.rules[0].ssid_ids.len(), 1);
    }

    #[test]
    fn input_limits_accept_boundaries_and_reject_excess_even_when_disabled() {
        let mut policy = policy();
        let rule = &mut policy.rules[0];
        rule.enabled = false;
        rule.name = "é".repeat(MAX_RULE_NAME_CHARS);
        rule.cidrs = vec![rule.cidrs[0]; MAX_CIDRS_PER_RULE];
        rule.ssid_ids = vec![rule.ssid_ids[0].clone(); MAX_SSIDS_PER_RULE];
        policy.validate().unwrap();
        policy.rules[0].name.push('é');
        assert_eq!(policy.validate(), Err(PolicyError::NameTooLong));
        policy.rules[0].name.pop();
        policy.rules[0].cidrs.push("10.0.0.0/8".parse().unwrap());
        assert_eq!(policy.validate(), Err(PolicyError::TooManyCidrs));
        policy.rules[0].cidrs.pop();
        policy.rules[0]
            .ssid_ids
            .push(SsidIdentity::from_bytes(vec![0]).unwrap());
        assert_eq!(policy.validate(), Err(PolicyError::TooManySsids));
        policy.rules[0].ssid_ids.pop();
        let rule = policy.rules[0].clone();
        policy.rules = (0..MAX_RULES)
            .map(|id| LocalBypassRule {
                id: Uuid::from_u128(id as u128),
                ..rule.clone()
            })
            .collect();
        policy.validate().unwrap();
        policy.rules.push(LocalBypassRule {
            id: Uuid::from_u128(MAX_RULES as u128),
            ..rule
        });
        assert_eq!(policy.validate(), Err(PolicyError::TooManyRules));
    }
}
