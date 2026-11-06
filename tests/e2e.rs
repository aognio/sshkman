use secrecy::SecretString;
use sshkma_client::VaultClient;
use sshkma_crypto::{
    derive_kek, generate_recovery_key, generate_vmk, wrap_vmk, wrap_vmk_with_recovery_key,
    Argon2Params, WrappedKeyEnvelope,
};
use sshkma_domain::{HostAlias, IdentityId, Slug};
use sshkma_server::{create_app_state, create_user};
use sshkma_vault::{
    decrypt_identity_record, encrypt_identity_record, encrypt_manifest, PlaintextIdentityRecord,
    VaultManifest,
};
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::net::TcpListener;

async fn start_server(root: std::path::PathBuf) -> (String, tokio::task::JoinHandle<()>) {
    let state = create_app_state(root);
    let app = sshkma_server::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle)
}

#[tokio::test]
async fn e2e_two_client_vault_sync_and_install() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();
    let (url, _handle) = start_server(root.clone()).await;

    // create user
    let uid = create_user(&root, "alice", "password123").unwrap();

    // client 1
    let mut c1 = VaultClient::new(url.clone());
    let lr1 = c1.login("alice", "password123").await.unwrap();
    assert_eq!(lr1.user_id, uid.as_str());

    // generate vault
    let vmk = generate_vmk();
    let salt = [0x11u8; 16];
    let password = SecretString::from("vaultpass".to_string());
    let kek = derive_kek(&password, &salt, &Argon2Params::interactive()).unwrap();
    let aad = format!("sshkma:vmk:v1:{}", uid.as_str());
    let wrapped = wrap_vmk(&vmk, &kek, aad.as_bytes()).unwrap();
    let recovery_key = generate_recovery_key();
    let recovery_salt = [0x22u8; 16];
    let recovery_aad = format!("sshkma:recovery:v1:{}", uid.as_str());
    let recovery_wrapped =
        wrap_vmk_with_recovery_key(&vmk, &recovery_key, &recovery_salt, recovery_aad.as_bytes())
            .unwrap();

    c1.vault_init(
        wrapped.clone(),
        recovery_wrapped.clone(),
        Some(hex::encode(salt)),
    )
    .await
    .unwrap();

    // import keypair
    let mut rng = rand::thread_rng();
    let priv_key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
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

    let keypair = sshkma_sshconfig::OriginalSshKeypair::validate_and_create(
        priv_bytes.clone(),
        pub_bytes.clone(),
    )
    .unwrap();
    assert_eq!(keypair.private_key_bytes(), &priv_bytes);

    let slug = Slug::parse("prod").unwrap();
    let host_alias = HostAlias::parse("prod").unwrap();
    let identity_id = IdentityId::new();
    let record = PlaintextIdentityRecord {
        slug: slug.as_str().to_string(),
        host_alias: host_alias.as_str().to_string(),
        hostname: Some("10.0.0.1".into()),
        user: Some("ubuntu".into()),
        port: Some(22),
        private_key_openssh: String::from_utf8(priv_bytes.clone()).unwrap(),
        public_key_openssh: String::from_utf8(pub_bytes.clone()).unwrap(),
        extra_ssh_directives: vec![],
        created_at: 1,
        updated_at: 2,
    };
    let enc = encrypt_identity_record(&record, &vmk, &uid, &identity_id).unwrap();
    c1.upload_identity(identity_id.as_str(), &enc.ciphertext)
        .await
        .unwrap();

    // manifest
    let mut manifest = VaultManifest::new();
    manifest.identity_ids.push(identity_id.clone());
    manifest.revision = 1;
    let manifest_bytes = encrypt_manifest(&manifest, &vmk, &uid).unwrap();
    c1.put_manifest(&manifest_bytes, 0).await.unwrap();

    // client 2
    let mut c2 = VaultClient::new(url.clone());
    c2.login("alice", "password123").await.unwrap();

    // unwrap vmk via password
    let wk = c2.get_wrapped_key().await.unwrap();
    let wrapped_env: WrappedKeyEnvelope =
        serde_json::from_value(wk["wrapped_key"].clone()).unwrap();
    let salt_hex = wk["salt"].as_str().unwrap();
    let salt_bytes: [u8; 16] = {
        let v = hex::decode(salt_hex).unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        a
    };
    let kek2 = derive_kek(&password, &salt_bytes, &Argon2Params::interactive()).unwrap();
    let aad2 = format!("sshkma:vmk:v1:{}", uid.as_str());
    let vmk2 = sshkma_crypto::unwrap_vmk(&wrapped_env, &kek2, aad2.as_bytes()).unwrap();
    assert_eq!(*vmk, *vmk2);

    // download identity
    let ct = c2.download_identity(identity_id.as_str()).await.unwrap();
    let enc2 = sshkma_vault::EncryptedIdentityRecord {
        identity_id: identity_id.clone(),
        user_id: uid.clone(),
        revision: 0,
        ciphertext: ct,
    };
    let dec = decrypt_identity_record(&enc2, &vmk2).unwrap();
    assert_eq!(dec.private_key_openssh, record.private_key_openssh);
    assert_eq!(dec.public_key_openssh, record.public_key_openssh);

    // manifest
    let (mbytes, rev) = c2.get_manifest().await.unwrap();
    assert_eq!(rev, 1);
    let mdec = sshkma_vault::decrypt_manifest(&mbytes, &vmk2, &uid).unwrap();
    assert_eq!(mdec.identity_ids, vec![identity_id.clone()]);

    // install locally
    let tmpssh = TempDir::new().unwrap();
    let managed_dir = tmpssh.path().join("managed");
    let keys_dir = tmpssh.path().join("keys");
    std::fs::create_dir_all(&managed_dir).unwrap();
    std::fs::create_dir_all(&keys_dir).unwrap();
    let managed_str = managed_dir.to_string_lossy().to_string();
    let keys_str = keys_dir.to_string_lossy().to_string();
    let plan = sshkma_sshconfig::plan_installation(
        &slug,
        &host_alias,
        Some("10.0.0.1"),
        Some("ubuntu"),
        Some(22),
        priv_bytes.as_slice(),
        pub_bytes.as_slice(),
        &managed_str,
        &keys_str,
    );
    // apply plan manually
    for action in plan.actions() {
        if let sshkma_domain::FileAction::Create(f) = action {
            let p = std::path::PathBuf::from(&f.path);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, &f.content).unwrap();
        }
    }
    // verify key preservation
    let written_priv = std::fs::read(keys_dir.join("prod")).unwrap();
    let written_pub = std::fs::read(keys_dir.join("prod.pub")).unwrap();
    assert_eq!(written_priv, priv_bytes);
    assert_eq!(written_pub, pub_bytes);

    // logout
    c1.logout(false).await.unwrap();
    // verify denied
    let r = c1.list_identities().await;
    assert!(r.is_err());

    // installed files remain
    assert!(keys_dir.join("prod").exists());
}
