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

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("krtek-policy-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn settings(&self) -> SettingsPersister {
        let mut settings = persister(self.0.join(SETTINGS_FILE));
        settings.settings.local_network_access = LocalNetworkAccess::default();
        settings
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn committed_policy_is_read_back_before_notification_and_noop_is_silent() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    let path = settings.path.clone();
    settings.register_change_listener(move |updated| {
        let on_disk = SettingsPersister::load_from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk, *updated);
        assert_eq!(on_disk.local_network_access, policy());
        observer.fetch_add(1, Ordering::SeqCst);
    });
    assert!(
        settings
            .set_local_network_access(policy(), None)
            .await
            .unwrap()
    );
    let loaded = SettingsPersister::load_from_file(&settings.path)
        .await
        .unwrap();
    assert_eq!(loaded.local_network_access, policy());
    assert!(loaded.allow_lan);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        !settings
            .set_local_network_access(policy(), Some(policy()))
            .await
            .unwrap()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_policy_and_failed_write_preserve_memory_disk_and_notifications() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    settings
        .set_local_network_access(policy(), None)
        .await
        .unwrap();
    let path = settings.path.clone();
    let original = settings.to_settings();
    let bytes = std::fs::read(&path).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    settings.register_change_listener(move |_| {
        observer.fetch_add(1, Ordering::SeqCst);
    });
    let mut invalid = policy();
    invalid.rules[0].cidrs.clear();
    let error = settings
        .set_local_network_access(invalid, None)
        .await
        .unwrap_err();
    let status: mullvad_management_interface::Status = error.into();
    assert_eq!(
        status.code(),
        mullvad_management_interface::Code::InvalidArgument
    );
    assert_eq!(settings.to_settings(), original);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let forbidden = scratch.0.join("existing-directory");
    std::fs::create_dir(&forbidden).unwrap();
    settings.path = forbidden.clone();
    let error = settings
        .set_local_network_access(LocalNetworkAccess::default(), None)
        .await
        .unwrap_err();
    let status: mullvad_management_interface::Status = error.into();
    assert_eq!(
        status.code(),
        mullvad_management_interface::Code::FailedPrecondition
    );
    assert_eq!(settings.to_settings(), original);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(forbidden.is_dir());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stale_expected_cannot_overwrite_concurrent_policy_but_current_expected_can() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let stale = settings.local_network_access.clone();
    settings
        .set_local_network_access(policy(), None)
        .await
        .unwrap();
    let original = settings.to_settings();
    let bytes = std::fs::read(&settings.path).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    settings.register_change_listener(move |_| {
        observer.fetch_add(1, Ordering::SeqCst);
    });
    let error = settings
        .set_local_network_access(LocalNetworkAccess::default(), Some(stale))
        .await
        .unwrap_err();
    let status: mullvad_management_interface::Status = error.into();
    assert_eq!(status.code(), mullvad_management_interface::Code::Aborted);
    assert_eq!(settings.to_settings(), original);
    assert_eq!(std::fs::read(&settings.path).unwrap(), bytes);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    settings
        .set_local_network_access(LocalNetworkAccess::default(), Some(policy()))
        .await
        .unwrap();
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        LocalNetworkAccess::default()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn accepted_policy_is_deduplicated_before_persistence_without_losing_conditions() {
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let mut repeated = policy();
    let rule = &mut repeated.rules[0];
    rule.cidrs.push(rule.cidrs[0]);
    rule.ssid_ids.push(rule.ssid_ids[0].clone());
    settings
        .set_local_network_access(repeated, None)
        .await
        .unwrap();
    assert_eq!(settings.local_network_access, policy());
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        policy()
    );
}
