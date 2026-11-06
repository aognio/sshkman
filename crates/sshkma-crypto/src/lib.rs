//! Cryptographic primitives, key derivation, and authenticated encryption for sshkma.
//!
//! Adheres to zero-knowledge guarantees:
//! - Argon2id KDF for password-based key encryption keys (KEK).
//! - XChaCha20-Poly1305 with 24-byte nonces for AEAD envelopes.
//! - HKDF-SHA256 for domain-separated record keys.
//! - Memory zeroization via `zeroize::Zeroizing`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sshkma_domain::{IdentityId, UserId};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC_BYTES: &[u8; 4] = b"SKM1";
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Cryptographic errors. Secrets are never printed in error messages.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failure: {0}")]
    KdfError(String),

    #[error("authenticated encryption / decryption failed")]
    AeadError(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("invalid recovery key format")]
    InvalidRecoveryKey,
}

/// Parameters for Argon2id key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// Fast parameters suitable for tests and interactive desktop unlocks.
    pub fn interactive() -> Self {
        Self {
            memory_cost_kib: 19456, // 19 MiB
            time_cost: 2,
            parallelism: 1,
        }
    }

    /// High security parameters for server-side auth or cold storage.
    pub fn high_security() -> Self {
        Self {
            memory_cost_kib: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 1,
        }
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::interactive()
    }
}

/// Serialized envelope containing a wrapped Vault Master Key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKeyEnvelope {
    pub version: u32,
    pub nonce: String,      // hex encoded 24 bytes
    pub ciphertext: String, // hex encoded
    pub tag: String,        // hex encoded 16 bytes
}

/// Generate a 256-bit CSPRNG Vault Master Key.
pub fn generate_vmk() -> Zeroizing<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Zeroizing::new(key)
}

/// Generate a 256-bit high-entropy recovery key formatted as a 64-character hex string.
pub fn generate_recovery_key() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let key = hex::encode(bytes);
    bytes.zeroize();
    key
}

/// Derive a 256-bit Key Encryption Key (KEK) using Argon2id.
pub fn derive_kek(
    password: &SecretString,
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let argon_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut kek)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    Ok(Zeroizing::new(kek))
}

/// Wrap the Vault Master Key using XChaCha20-Poly1305.
pub fn wrap_vmk(
    vmk: &[u8; 32],
    kek: &[u8; 32],
    aad: &[u8],
) -> Result<WrappedKeyEnvelope, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(kek)
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(&nonce, Payload { msg: vmk, aad })
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;

    if ciphertext_with_tag.len() < 16 {
        return Err(CryptoError::AeadError("ciphertext too short".into()));
    }

    let split_pos = ciphertext_with_tag.len() - 16;
    let ct = &ciphertext_with_tag[..split_pos];
    let tag = &ciphertext_with_tag[split_pos..];

    Ok(WrappedKeyEnvelope {
        version: 1,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ct),
        tag: hex::encode(tag),
    })
}

/// Unwrap the Vault Master Key using XChaCha20-Poly1305.
pub fn unwrap_vmk(
    envelope: &WrappedKeyEnvelope,
    kek: &[u8; 32],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad nonce hex: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidEnvelope("invalid nonce length".into()));
    }

    let ct = hex::decode(&envelope.ciphertext)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad ciphertext hex: {e}")))?;
    let tag = hex::decode(&envelope.tag)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad tag hex: {e}")))?;

    let mut combined = ct;
    combined.extend_from_slice(&tag);

    let cipher = XChaCha20Poly1305::new_from_slice(kek)
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;
    let nonce = XNonce::try_from(nonce_bytes.as_slice())
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad nonce: {e}")))?;

    let decrypted = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &combined,
                aad,
            },
        )
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;

    if decrypted.len() != KEY_LEN {
        return Err(CryptoError::AeadError("invalid VMK length".into()));
    }

    let mut vmk = [0u8; 32];
    vmk.copy_from_slice(&decrypted);
    Ok(Zeroizing::new(vmk))
}

/// Derive recovery KEK from recovery key string and salt via HKDF-SHA256.
fn derive_recovery_kek(
    recovery_key: &str,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let raw_key = hex::decode(recovery_key.trim()).map_err(|_| CryptoError::InvalidRecoveryKey)?;
    if raw_key.len() != 32 {
        return Err(CryptoError::InvalidRecoveryKey);
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), &raw_key);
    let mut kek = [0u8; 32];
    hk.expand(b"sshkma:recovery:kek:v1", &mut kek)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    Ok(Zeroizing::new(kek))
}

/// Wrap VMK with emergency recovery secret.
pub fn wrap_vmk_with_recovery_key(
    vmk: &[u8; 32],
    recovery_key: &str,
    salt: &[u8; 16],
    aad: &[u8],
) -> Result<WrappedKeyEnvelope, CryptoError> {
    let kek = derive_recovery_kek(recovery_key, salt)?;
    wrap_vmk(vmk, &kek, aad)
}

/// Unwrap VMK with emergency recovery secret.
pub fn unwrap_vmk_with_recovery_key(
    envelope: &WrappedKeyEnvelope,
    recovery_key: &str,
    salt: &[u8; 16],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let kek = derive_recovery_kek(recovery_key, salt)?;
    unwrap_vmk(envelope, &kek, aad)
}

/// Derive a per-record encryption key from the VMK, UserId, and IdentityId using HKDF-SHA256.
pub fn derive_record_key(
    vmk: &[u8; 32],
    user_id: &UserId,
    identity_id: &IdentityId,
) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(user_id.as_str().as_bytes()), vmk);
    let mut info = Vec::from(b"sshkma:identity:v1:".as_slice());
    info.extend_from_slice(identity_id.as_str().as_bytes());

    let mut record_key = [0u8; 32];
    hk.expand(&info, &mut record_key)
        .expect("32 bytes is valid length for HKDF-SHA256");

    Zeroizing::new(record_key)
}

/// Wire-format envelope cipher for binary payloads.
///
/// Layout: `[magic: 4B = "SKM1"] [nonce: 24B] [ciphertext + tag: N bytes]`
pub struct EnvelopeCipher;

impl EnvelopeCipher {
    pub fn encrypt(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::AeadError(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::AeadError(e.to_string()))?;

        let mut wire = Vec::with_capacity(MAGIC_BYTES.len() + NONCE_LEN + ciphertext.len());
        wire.extend_from_slice(MAGIC_BYTES);
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ciphertext);

        Ok(wire)
    }

    pub fn decrypt(wire_bytes: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let min_len = MAGIC_BYTES.len() + NONCE_LEN + 16;
        if wire_bytes.len() < min_len {
            return Err(CryptoError::InvalidEnvelope("payload too small".into()));
        }

        if &wire_bytes[..4] != MAGIC_BYTES {
            return Err(CryptoError::InvalidEnvelope(
                "invalid envelope magic".into(),
            ));
        }

        let nonce_bytes = &wire_bytes[4..4 + NONCE_LEN];
        let nonce = XNonce::try_from(nonce_bytes)
            .map_err(|e| CryptoError::InvalidEnvelope(format!("bad nonce: {e}")))?;
        let ciphertext = &wire_bytes[4 + NONCE_LEN..];

        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::AeadError(e.to_string()))?;

        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::AeadError(e.to_string()))
    }
}

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// A Vault Master Key wrapped to an asymmetric recipient (grant sharing).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantWrappedKeyEnvelope {
    pub version: u32,
    pub ephemeral_public: String, // hex 32 bytes
    pub nonce: String,            // hex 24 bytes
    pub ciphertext: String,       // hex (ct+tag)
}

/// Generate an X25519 keypair for grant-based vault sharing.
/// Returns (private_key_bytes, public_key_bytes).
pub fn generate_grant_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    use rand::RngCore;
    let mut secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let public = X25519PublicKey::from(&secret);
    let priv_out = Zeroizing::new(secret_bytes);
    (priv_out, public.to_bytes())
}

/// Wrap a VMK to a recipient's X25519 public key.
pub fn wrap_vmk_to_recipient(
    vmk: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<GrantWrappedKeyEnvelope, CryptoError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use rand::RngCore;

    let mut eph_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_bytes);
    let ephemeral_secret = StaticSecret::from(eph_bytes);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient = X25519PublicKey::from(*recipient_public);
    let shared = ephemeral_secret.diffie_hellman(&recipient);

    let hk = Hkdf::<Sha256>::new(Some(ephemeral_public.as_bytes()), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"sshkma:grant:kek:v1", &mut key)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let aad = b"sshkma:grant:vmk:v1";
    let ct = cipher
        .encrypt(&nonce, Payload { msg: vmk, aad })
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;

    Ok(GrantWrappedKeyEnvelope {
        version: 1,
        ephemeral_public: hex::encode(ephemeral_public.as_bytes()),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ct),
    })
}

/// Unwrap a VMK granted via an asymmetric envelope.
pub fn unwrap_vmk_from_grant(
    envelope: &GrantWrappedKeyEnvelope,
    recipient_private: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let eph_bytes = hex::decode(&envelope.ephemeral_public)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad eph hex: {e}")))?;
    if eph_bytes.len() != 32 {
        return Err(CryptoError::InvalidEnvelope("bad eph length".into()));
    }
    let mut eph_arr = [0u8; 32];
    eph_arr.copy_from_slice(&eph_bytes);
    let ephemeral_public = X25519PublicKey::from(eph_arr);

    let secret = StaticSecret::from(*recipient_private);
    let shared = secret.diffie_hellman(&ephemeral_public);

    let hk = Hkdf::<Sha256>::new(Some(&eph_bytes), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"sshkma:grant:kek:v1", &mut key)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad nonce hex: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidEnvelope("bad nonce length".into()));
    }
    let ct = hex::decode(&envelope.ciphertext)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad ct hex: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;
    let nonce = XNonce::try_from(nonce_bytes.as_slice())
        .map_err(|e| CryptoError::InvalidEnvelope(format!("bad nonce: {e}")))?;

    let aad = b"sshkma:grant:vmk:v1";
    let decrypted = cipher
        .decrypt(&nonce, Payload { msg: &ct, aad })
        .map_err(|e| CryptoError::AeadError(e.to_string()))?;

    if decrypted.len() != KEY_LEN {
        return Err(CryptoError::AeadError("invalid VMK length".into()));
    }
    let mut vmk = [0u8; 32];
    vmk.copy_from_slice(&decrypted);
    Ok(Zeroizing::new(vmk))
}
