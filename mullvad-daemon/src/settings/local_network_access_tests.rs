use super::*;
use mullvad_types::settings::local_network_access::{
    LocalBypassRule, LocalNetworkAccess, SsidIdentity,
};

fn policy() -> LocalNetworkAccess {
    LocalNetworkAccess {
        enabled: true,
        rules: vec![LocalBypassRule {
            id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            name: "private-rule-marker".into(),
            enabled: true,
            cidrs: vec!["192.168.240.0/28".parse().unwrap()],
            ssid_ids: vec![SsidIdentity::from_bytes(b"private-wifi-marker".to_vec()).unwrap()],
        }],
    }
}

fn persister(path: PathBuf) -> SettingsPersister {
    SettingsPersister {
        path,
        settings: Settings {
            allow_lan: true,
            local_network_access: policy(),
            ..Settings::default()
        },
        on_change_listeners: vec![],
    }
}

#[test]
fn archive_format_settings_keep_unrelated_values_and_exact_conditions() {
    let bytes = br#"{
        "settings_version": 18,
        "allow_lan": true,
        "show_beta_releases": true,
        "local_network_access": {
            "enabled": true,
            "rules": [{
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "archive sample",
                "enabled": true,
                "cidrs": ["192.168.240.0/28"],
                "ssid_ids": ["00ff4120"]
            }]
        }
    }"#;
    let settings = SettingsPersister::load_from_bytes(bytes).unwrap();
    assert!(settings.allow_lan && settings.show_beta_releases);
    assert!(settings.local_network_access.enabled);
    assert_eq!(
        settings.local_network_access.rules[0].ssid_ids[0].bytes(),
        &[0, 255, 65, 32]
    );
    assert_eq!(
        SettingsPersister::load_from_bytes(&serde_json::to_vec(&settings).unwrap()).unwrap(),
        settings
    );
    let old = SettingsPersister::load_from_bytes(br#"{"allow_lan":true}"#).unwrap();
    assert!(old.allow_lan);
    assert_eq!(old.local_network_access, LocalNetworkAccess::default());
}

#[tokio::test]
async fn reset_preserves_policy_only_when_its_key_is_requested() {
    // Upstream reset skips its disk save under cfg(test); this checks the key
    // contract, not disk persistence of reset.
    let mut settings = persister(PathBuf::new());
    settings
        .reset(SettingsKeyList {
            keys: vec![SettingsKey::LocalNetworkAccess],
        })
        .await
        .unwrap();
    assert_eq!(settings.local_network_access, policy());
    assert!(!settings.allow_lan);
    settings.reset(SettingsKeyList::default()).await.unwrap();
    assert_eq!(settings.local_network_access, LocalNetworkAccess::default());
}

#[test]
fn settings_diagnostics_contain_counts_without_rule_contents() {
    let settings = persister(PathBuf::new());
    let diagnostic = format!("{} {:?}", settings.summary(), settings.to_settings());
    assert!(diagnostic.contains("local rules: 1"));
    for secret in [
        "private-rule-marker",
        "private-wifi-marker",
        "707269766174652d776966692d6d61726b6572",
        "192.168.240",
    ] {
        assert!(!diagnostic.contains(secret));
    }
}
