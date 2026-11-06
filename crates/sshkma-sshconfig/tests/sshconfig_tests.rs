use ssh_key::PrivateKey;
use sshkma_domain::{HostAlias, Slug};
use sshkma_sshconfig::{
    ensure_managed_include, generate_host_config, plan_installation, remove_managed_include,
    ManagedHostParams, OriginalSshKeypair, SshConfigError,
};

#[test]
fn test_exact_keypair_preservation_and_validation() {
    let mut rng = rand::thread_rng();
    let priv_key = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
    let priv_bytes = priv_key
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .as_bytes()
        .to_vec();
    let pub_bytes = format!(
        "{} test-comment\n",
        priv_key.public_key().to_openssh().unwrap()
    )
    .into_bytes();

    let keypair = OriginalSshKeypair::validate_and_create(priv_bytes.clone(), pub_bytes.clone())
        .expect("valid keypair");

    assert_eq!(keypair.private_key_bytes(), &priv_bytes);
    assert_eq!(keypair.public_key_bytes(), &pub_bytes);
    assert_eq!(keypair.comment(), Some("test-comment"));
}

#[test]
fn test_mismatched_keypair_rejected() {
    let mut rng = rand::thread_rng();
    let priv1 = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
    let priv2 = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();

    let priv1_bytes = priv1
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .as_bytes()
        .to_vec();
    let pub2_bytes = priv2.public_key().to_openssh().unwrap().into_bytes();

    let res = OriginalSshKeypair::validate_and_create(priv1_bytes, pub2_bytes);
    assert!(matches!(res, Err(SshConfigError::KeyMismatch)));
}

#[test]
fn test_managed_include_insertion_and_idempotence() {
    let existing_config = "Host github.com\n    User git\n";
    let managed_path = "~/.ssh/managed/*.conf";

    let updated = ensure_managed_include(existing_config, managed_path).unwrap();
    assert!(updated.starts_with("# BEGIN SSHKMA MANAGED INCLUDES"));
    assert!(updated.contains("Include ~/.ssh/managed/*.conf"));
    assert!(updated.ends_with("Host github.com\n    User git\n"));

    // Idempotent second run
    let twice = ensure_managed_include(&updated, managed_path).unwrap();
    assert_eq!(updated, twice);

    // Remove
    let cleaned = remove_managed_include(&updated);
    assert_eq!(cleaned.trim(), existing_config.trim());
}

#[test]
fn test_generate_host_config() {
    let params = ManagedHostParams {
        slug: Slug::parse("bastion").unwrap(),
        host_alias: HostAlias::parse("jumpbox").unwrap(),
        hostname: Some("10.0.0.1".into()),
        user: Some("ubuntu".into()),
        port: Some(2222),
        identity_file: "~/.ssh/keys/bastion".into(),
        extra_directives: vec![("ForwardAgent".into(), "yes".into())],
    };

    let conf = generate_host_config(&params);
    assert!(conf.contains("Host jumpbox"));
    assert!(conf.contains("HostName 10.0.0.1"));
    assert!(conf.contains("User ubuntu"));
    assert!(conf.contains("Port 2222"));
    assert!(conf.contains("IdentityFile ~/.ssh/keys/bastion"));
    assert!(conf.contains("IdentitiesOnly yes"));
    assert!(conf.contains("ForwardAgent yes"));
}

#[test]
fn test_installation_planning() {
    let slug = Slug::parse("app-server").unwrap();
    let alias = HostAlias::parse("app").unwrap();
    let priv_bytes = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n".to_vec();
    let pub_bytes = b"ssh-ed25519 AAAAC3... app\n".to_vec();

    let plan = plan_installation(
        &slug,
        &alias,
        Some("1.2.3.4"),
        Some("admin"),
        Some(22),
        &priv_bytes,
        &pub_bytes,
        "~/.ssh/managed",
        "~/.ssh/keys",
    );

    assert_eq!(plan.actions().len(), 3); // config, private key, public key
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_ensure_include_idempotent(existing in ".*") {
        let managed_path = "~/.ssh/managed/*.conf";
        let first = ensure_managed_include(&existing, managed_path).unwrap();
        let second = ensure_managed_include(&first, managed_path).unwrap();
        prop_assert_eq!(first, second);
    }

    #[test]
    fn prop_ensure_then_remove_roundtrips(existing in "[^\n]*") {
        // existing without markers
        let managed_path = "~/.ssh/managed/*.conf";
        let ensured = ensure_managed_include(&existing, managed_path).unwrap();
        let removed = remove_managed_include(&ensured);
        prop_assert_eq!(removed.trim(), existing.trim());
    }

    #[test]
    fn prop_plan_preserves_private_bytes(priv_bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let slug = Slug::parse("app-server").unwrap();
        let alias = HostAlias::parse("app").unwrap();
        let pub_bytes = b"ssh-ed25519 AAAAC3... app\n".to_vec();
        let plan = plan_installation(
            &slug,
            &alias,
            Some("1.2.3.4"),
            Some("admin"),
            Some(22),
            &priv_bytes,
            &pub_bytes,
            "~/.ssh/managed",
            "~/.ssh/keys",
        );
        let mut found = false;
        for action in plan.actions() {
            if let sshkma_domain::FileAction::Create(f) = action {
                if f.content == priv_bytes {
                    found = true;
                }
            }
        }
        prop_assert!(found);
    }

    #[test]
    fn prop_plan_preserves_public_bytes(pub_bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let slug = Slug::parse("app-server").unwrap();
        let alias = HostAlias::parse("app").unwrap();
        let priv_bytes = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n".to_vec();
        let plan = plan_installation(
            &slug,
            &alias,
            Some("1.2.3.4"),
            Some("admin"),
            Some(22),
            &priv_bytes,
            &pub_bytes,
            "~/.ssh/managed",
            "~/.ssh/keys",
        );
        let mut found = false;
        for action in plan.actions() {
            if let sshkma_domain::FileAction::Create(f) = action {
                if f.content == pub_bytes {
                    found = true;
                }
            }
        }
        prop_assert!(found);
    }

    #[test]
    fn prop_generate_host_config_contains_alias(alias in "[a-zA-Z0-9_-]{1,32}") {
        let ha = HostAlias::parse(&alias).unwrap();
        let params = ManagedHostParams {
            slug: Slug::parse("s").unwrap(),
            host_alias: ha.clone(),
            hostname: Some("10.0.0.1".into()),
            user: Some("ubuntu".into()),
            port: Some(22),
            identity_file: "~/.ssh/keys/s".into(),
            extra_directives: vec![],
        };
        let conf = generate_host_config(&params);
        let expected = format!("Host {}", alias);
        prop_assert!(conf.contains(&expected));
    }
}
