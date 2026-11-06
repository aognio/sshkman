use sshkma_config::{ClientConfig, ServerConfig};

#[test]
fn client_config_roundtrip() {
    let cfg = ClientConfig::default();
    let s = cfg.to_string_toml().unwrap();
    let parsed = ClientConfig::from_str(&s).unwrap();
    assert_eq!(cfg, parsed);
    parsed.validate().unwrap();
}

#[test]
fn server_config_validation() {
    let toml = r#"
[server]
hostname = "vault.example.com"
listen_address = "127.0.0.1"
port = 8080
public_url = "https://vault.example.com"

[storage]
root = "/var/lib/sshkmad"

[auth]
access_ttl = "15m"
refresh_ttl = "720h"
secret_file = "/etc/sshkma/secrets/session.key"

[logging]
level = "info"
format = "logfmt"
file = "/var/log/sshkmad/sshkmad.log"
security_file = "/var/log/sshkmad/security.log"
rotation = "daily"
retention_days = 30

[security]
require_https = true
max_login_attempts = 5
"#;
    let cfg = ServerConfig::from_str(toml).unwrap();
    cfg.validate().unwrap();
}

#[test]
fn server_config_rejects_http_public_url() {
    let mut cfg = ServerConfig::default();
    cfg.server.public_url = "http://example.com".into();
    cfg.security.require_https = true;
    assert!(cfg.validate().is_err());
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_client_config_toml_roundtrip(
        config_dir in "[a-zA-Z0-9_./~-]{1,32}",
        managed_dir in "[a-zA-Z0-9_./~-]{1,32}",
        keys_dir in "[a-zA-Z0-9_./~-]{1,32}",
    ) {
        let cfg = sshkma_config::ClientConfig {
            version: 1,
            vault: sshkma_config::VaultConfig { url: None, username: None },
            auth: sshkma_config::AuthConfig { storage: sshkma_config::AuthStorage::Toml },
            ssh: sshkma_config::SshPathsConfig {
                config_dir: config_dir.clone(),
                managed_dir: managed_dir.clone(),
                keys_dir: keys_dir.clone(),
            },
        };
        let s = cfg.to_string_toml().unwrap();
        let parsed = sshkma_config::ClientConfig::from_str(&s).unwrap();
        prop_assert_eq!(parsed, cfg);
    }

    #[test]
    fn prop_server_config_toml_roundtrip(retention in 0u32..1000u32) {
        let mut cfg = sshkma_config::ServerConfig::default();
        cfg.logging.retention_days = retention;
        let s = cfg.to_string_toml().unwrap();
        let parsed = sshkma_config::ServerConfig::from_str(&s).unwrap();
        prop_assert_eq!(parsed.logging.retention_days, retention);
    }
}
