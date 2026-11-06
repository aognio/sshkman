use sshkma_crypto::generate_vmk;
use sshkma_domain::{IdentityId, UserId};
use sshkma_vault::{
    check_revision, decrypt_identity_record, decrypt_manifest, encrypt_identity_record,
    encrypt_manifest, PlaintextIdentityRecord, VaultManifest,
};

#[test]
fn identity_record_roundtrip() {
    let vmk = generate_vmk();
    let user_id = UserId::new();
    let identity_id = IdentityId::new();
    let record = PlaintextIdentityRecord {
        slug: "prod".into(),
        host_alias: "prod".into(),
        hostname: Some("10.0.0.1".into()),
        user: Some("ubuntu".into()),
        port: Some(22),
        private_key_openssh: "PRIVATE".into(),
        public_key_openssh: "PUBLIC".into(),
        extra_ssh_directives: vec![],
        created_at: 1,
        updated_at: 2,
    };
    let enc = encrypt_identity_record(&record, &vmk, &user_id, &identity_id).unwrap();
    let dec = decrypt_identity_record(&enc, &vmk).unwrap();
    assert_eq!(record, dec);
}

#[test]
fn manifest_roundtrip() {
    let vmk = generate_vmk();
    let user_id = UserId::new();
    let mut m = VaultManifest::new();
    m.identity_ids.push(IdentityId::new());
    m.revision = 3;
    let bytes = encrypt_manifest(&m, &vmk, &user_id).unwrap();
    let dec = decrypt_manifest(&bytes, &vmk, &user_id).unwrap();
    assert_eq!(m, dec);
}

#[test]
fn revision_conflict() {
    assert!(check_revision(1, 2).is_err());
    assert!(check_revision(1, 1).is_ok());
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_identity_record_roundtrip(
        slug in "[a-zA-Z0-9_-]{1,16}",
        host_alias in "[a-zA-Z0-9_-]{1,16}",
        hostname in proptest::option::of("[a-zA-Z0-9.]{1,16}"),
        user in proptest::option::of("[a-zA-Z0-9_]{1,16}"),
        port in proptest::option::of(1u16..65535u16),
        priv_key in "[ -~]{0,64}",
        pub_key in "[ -~]{0,64}",
    ) {
        let vmk = generate_vmk();
        let user_id = UserId::new();
        let identity_id = IdentityId::new();
        let record = PlaintextIdentityRecord {
            slug: slug.clone(),
            host_alias: host_alias.clone(),
            hostname: hostname.clone(),
            user: user.clone(),
            port,
            private_key_openssh: priv_key.clone(),
            public_key_openssh: pub_key.clone(),
            extra_ssh_directives: vec![],
            created_at: 1,
            updated_at: 2,
        };
        let enc = encrypt_identity_record(&record, &vmk, &user_id, &identity_id).unwrap();
        let dec = decrypt_identity_record(&enc, &vmk).unwrap();
        prop_assert_eq!(record, dec);
    }

    #[test]
    fn prop_manifest_roundtrip(revision in 0u64..1000u64, n in 0usize..8usize) {
        let vmk = generate_vmk();
        let user_id = UserId::new();
        let mut m = VaultManifest::new();
        for _ in 0..n {
            m.identity_ids.push(IdentityId::new());
        }
        m.revision = revision;
        let bytes = encrypt_manifest(&m, &vmk, &user_id).unwrap();
        let dec = decrypt_manifest(&bytes, &vmk, &user_id).unwrap();
        prop_assert_eq!(m, dec);
    }

    #[test]
    fn prop_wrong_vmk_fails_to_decrypt(
        slug in "[a-zA-Z0-9_-]{1,8}",
    ) {
        let vmk1 = generate_vmk();
        let vmk2 = generate_vmk();
        let user_id = UserId::new();
        let identity_id = IdentityId::new();
        let record = PlaintextIdentityRecord {
            slug,
            host_alias: "h".into(),
            hostname: None,
            user: None,
            port: None,
            private_key_openssh: "P".into(),
            public_key_openssh: "Q".into(),
            extra_ssh_directives: vec![],
            created_at: 1,
            updated_at: 2,
        };
        let enc = encrypt_identity_record(&record, &vmk1, &user_id, &identity_id).unwrap();
        // decrypt with wrong vmk should fail
        let res = decrypt_identity_record(&enc, &vmk2);
        prop_assert!(res.is_err());
    }
}
