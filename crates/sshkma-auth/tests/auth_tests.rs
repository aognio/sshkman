use secrecy::SecretString;
use sshkma_auth::{generate_token, hash_password, hash_token, verify_password};

#[test]
fn password_hash_verify() {
    let pw = SecretString::from("correct horse".to_string());
    let hash = hash_password(&pw).unwrap();
    assert!(verify_password(&pw, &hash).unwrap());
    let wrong = SecretString::from("wrong".to_string());
    assert!(!verify_password(&wrong, &hash).unwrap());
}

#[test]
fn token_hash_deterministic() {
    let t = generate_token();
    assert_eq!(t.len(), 64);
    let h1 = hash_token(&t);
    let h2 = hash_token(&t);
    assert_eq!(h1, h2);
    assert_ne!(h1, t);
}
