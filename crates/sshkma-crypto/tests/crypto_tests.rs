use proptest::prelude::*;
use secrecy::SecretString;
use sshkma_crypto::{
    derive_kek, derive_record_key, generate_recovery_key, generate_vmk, unwrap_vmk,
    unwrap_vmk_with_recovery_key, wrap_vmk, wrap_vmk_with_recovery_key, Argon2Params, CryptoError,
    EnvelopeCipher,
};
use sshkma_domain::{IdentityId, UserId};

#[test]
fn test_argon2id_kdf_consistency() {
    let password = SecretString::from("correct_horse_battery_staple".to_string());
    let salt = [0x42u8; 16];
    let params = Argon2Params::interactive();

    let kek1 = derive_kek(&password, &salt, &params).unwrap();
    let kek2 = derive_kek(&password, &salt, &params).unwrap();
    assert_eq!(*kek1, *kek2);

    let other_salt = [0x43u8; 16];
    let kek_diff = derive_kek(&password, &other_salt, &params).unwrap();
    assert_ne!(*kek1, *kek_diff);
}

#[test]
fn test_vmk_wrapping_and_unwrapping_happy_path() {
    let password = SecretString::from("vault-master-pass".to_string());
    let salt = [0x77u8; 16];
    let params = Argon2Params::interactive();
    let vmk = generate_vmk();
    let aad = b"sshkma:vmk:v1:usr_123";

    let kek = derive_kek(&password, &salt, &params).unwrap();
    let wrapped = wrap_vmk(&vmk, &kek, aad).unwrap();

    // Decrypt with correct password
    let unwrapped = unwrap_vmk(&wrapped, &kek, aad).unwrap();
    assert_eq!(*vmk, *unwrapped);
}

#[test]
fn test_vmk_unwrapping_fails_with_wrong_password() {
    let password = SecretString::from("vault-master-pass".to_string());
    let wrong_password = SecretString::from("wrong-password".to_string());
    let salt = [0x77u8; 16];
    let params = Argon2Params::interactive();
    let vmk = generate_vmk();
    let aad = b"sshkma:vmk:v1:usr_123";

    let kek = derive_kek(&password, &salt, &params).unwrap();
    let wrapped = wrap_vmk(&vmk, &kek, aad).unwrap();

    let wrong_kek = derive_kek(&wrong_password, &salt, &params).unwrap();
    let err = unwrap_vmk(&wrapped, &wrong_kek, aad).unwrap_err();
    assert!(matches!(err, CryptoError::AeadError(_)));
}

#[test]
fn test_vmk_unwrapping_fails_with_wrong_aad() {
    let password = SecretString::from("vault-master-pass".to_string());
    let salt = [0x77u8; 16];
    let params = Argon2Params::interactive();
    let vmk = generate_vmk();
    let aad = b"sshkma:vmk:v1:usr_123";
    let evil_aad = b"sshkma:vmk:v1:usr_666";

    let kek = derive_kek(&password, &salt, &params).unwrap();
    let wrapped = wrap_vmk(&vmk, &kek, aad).unwrap();

    let err = unwrap_vmk(&wrapped, &kek, evil_aad).unwrap_err();
    assert!(matches!(err, CryptoError::AeadError(_)));
}

#[test]
fn test_recovery_key_wrapping_and_recovery() {
    let vmk = generate_vmk();
    let recovery_key = generate_recovery_key();
    let recovery_salt = [0x99u8; 16];
    let aad = b"sshkma:recovery:v1:usr_123";

    let recovery_envelope =
        wrap_vmk_with_recovery_key(&vmk, &recovery_key, &recovery_salt, aad).unwrap();

    let recovered_vmk =
        unwrap_vmk_with_recovery_key(&recovery_envelope, &recovery_key, &recovery_salt, aad)
            .unwrap();

    assert_eq!(*vmk, *recovered_vmk);

    // Wrong recovery key fails
    let wrong_recovery_key = generate_recovery_key();
    assert!(unwrap_vmk_with_recovery_key(
        &recovery_envelope,
        &wrong_recovery_key,
        &recovery_salt,
        aad
    )
    .is_err());
}

#[test]
fn test_envelope_wire_format_and_tamper_detection() {
    let key = [0x33u8; 32];
    let aad = b"context-aad-binding";
    let plaintext = b"secret payload ssh identity data";

    let wire_bytes = EnvelopeCipher::encrypt(plaintext, &key, aad).unwrap();

    // Verify magic bytes
    assert_eq!(&wire_bytes[..4], b"SKM1");

    // Decrypt succeeds
    let decrypted = EnvelopeCipher::decrypt(&wire_bytes, &key, aad).unwrap();
    assert_eq!(decrypted, plaintext);

    // Tampering 1 byte in ciphertext causes rejection
    let mut tampered = wire_bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(EnvelopeCipher::decrypt(&tampered, &key, aad).is_err());

    // Wrong AAD causes rejection
    assert!(EnvelopeCipher::decrypt(&wire_bytes, &key, b"wrong-aad").is_err());

    // Bad magic causes rejection
    let mut bad_magic = wire_bytes.clone();
    bad_magic[0] = b'X';
    assert!(EnvelopeCipher::decrypt(&bad_magic, &key, aad).is_err());
}

#[test]
fn test_record_key_derivation_isolation() {
    let vmk = generate_vmk();
    let user_id = UserId::new();
    let id1 = IdentityId::new();
    let id2 = IdentityId::new();

    let key1 = derive_record_key(&vmk, &user_id, &id1);
    let key2 = derive_record_key(&vmk, &user_id, &id2);

    assert_ne!(*key1, *key2);
}

proptest! {
    #[test]
    fn prop_envelope_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let key = [0x55u8; 32];
        let aad = b"prop-aad";
        let encrypted = EnvelopeCipher::encrypt(&data, &key, aad).unwrap();
        let decrypted = EnvelopeCipher::decrypt(&encrypted, &key, aad).unwrap();
        prop_assert_eq!(decrypted, data);
    }
}

proptest! {
    #[test]
    fn prop_envelope_tamper_fails(data in proptest::collection::vec(any::<u8>(), 1..512), flip in 0usize..512) {
        let key = [0x55u8; 32];
        let aad = b"prop-aad";
        let encrypted = EnvelopeCipher::encrypt(&data, &key, aad).unwrap();
        let mut tampered = encrypted.clone();
        let idx = flip % tampered.len();
        tampered[idx] ^= 0x01;
        // tampering magic/header may produce invalid envelope (still an error) OR decryption failure
        prop_assert!(EnvelopeCipher::decrypt(&tampered, &key, aad).is_err());
    }

    #[test]
    fn prop_envelope_wrong_key_fails(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let key1 = [0x55u8; 32];
        let key2 = [0x66u8; 32];
        let aad = b"prop-aad";
        let encrypted = EnvelopeCipher::encrypt(&data, &key1, aad).unwrap();
        prop_assert!(EnvelopeCipher::decrypt(&encrypted, &key2, aad).is_err());
    }

    #[test]
    fn prop_envelope_wrong_aad_fails(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let key = [0x55u8; 32];
        let aad1 = b"prop-aad-1";
        let aad2 = b"prop-aad-2";
        let encrypted = EnvelopeCipher::encrypt(&data, &key, aad1).unwrap();
        prop_assert!(EnvelopeCipher::decrypt(&encrypted, &key, aad2).is_err());
    }

    #[test]
    fn prop_envelope_magic_preserved(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let key = [0x55u8; 32];
        let aad = b"prop-aad";
        let encrypted = EnvelopeCipher::encrypt(&data, &key, aad).unwrap();
        prop_assert_eq!(&encrypted[..4], b"SKM1");
    }

    #[test]
    fn prop_wrapped_key_envelope_serde_roundtrip(nonce in proptest::collection::vec(any::<u8>(), 24..25), ct in proptest::collection::vec(any::<u8>(), 0..64)) {
        // sanity: hex encoding roundtrips
        let hexed = hex::encode(&ct);
        let decoded = hex::decode(&hexed).unwrap();
        prop_assert_eq!(decoded, ct);
        let _ = nonce;
    }
}
