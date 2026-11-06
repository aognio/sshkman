use sshkma_client::{load_token_store, save_token_store, TokenStore};
use tempfile::TempDir;

#[test]
fn token_store_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("tokens.toml");
    let ts = TokenStore {
        access_token: Some("abc".into()),
        refresh_token: Some("def".into()),
    };
    save_token_store(&p, &ts).unwrap();
    let loaded = load_token_store(&p).unwrap();
    assert_eq!(loaded, ts);
}

#[test]
fn token_store_missing_returns_default() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("missing.toml");
    let loaded = load_token_store(&p).unwrap();
    assert!(loaded.access_token.is_none());
}
