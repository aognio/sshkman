//! Client-side encrypted vault records, manifest handling, and optimistic concurrency.

use serde::{Deserialize, Serialize};
use sshkma_crypto::{derive_record_key, EnvelopeCipher};
use sshkma_domain::{DomainError, IdentityId, UserId};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum VaultError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
    #[error("revision conflict: expected {expected}, found {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("domain error: {0}")]
    Domain(String),
}

impl From<sshkma_crypto::CryptoError> for VaultError {
    fn from(e: sshkma_crypto::CryptoError) -> Self {
        VaultError::Crypto(e.to_string())
    }
}

impl From<DomainError> for VaultError {
    fn from(e: DomainError) -> Self {
        VaultError::Domain(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextIdentityRecord {
    pub slug: String,
    pub host_alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub private_key_openssh: String,
    pub public_key_openssh: String,
    pub extra_ssh_directives: Vec<(String, String)>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIdentityRecord {
    pub identity_id: IdentityId,
    pub user_id: UserId,
    pub revision: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultManifest {
    pub version: u32,
    pub revision: u64,
    pub identity_ids: Vec<IdentityId>,
}

impl VaultManifest {
    pub fn new() -> Self {
        Self {
            version: 1,
            revision: 0,
            identity_ids: Vec::new(),
        }
    }
}

impl Default for VaultManifest {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encrypt_identity_record(
    record: &PlaintextIdentityRecord,
    vmk: &[u8; 32],
    user_id: &UserId,
    identity_id: &IdentityId,
) -> Result<EncryptedIdentityRecord, VaultError> {
    let record_key = derive_record_key(vmk, user_id, identity_id);
    let plaintext =
        serde_json::to_vec(record).map_err(|e| VaultError::Serialization(e.to_string()))?;
    let aad = format!(
        "sshkma:record:v1:{}:{}",
        user_id.as_str(),
        identity_id.as_str()
    );
    let ciphertext = EnvelopeCipher::encrypt(&plaintext, &record_key, aad.as_bytes())?;
    Ok(EncryptedIdentityRecord {
        identity_id: identity_id.clone(),
        user_id: user_id.clone(),
        revision: 0,
        ciphertext,
    })
}

pub fn decrypt_identity_record(
    enc: &EncryptedIdentityRecord,
    vmk: &[u8; 32],
) -> Result<PlaintextIdentityRecord, VaultError> {
    let record_key = derive_record_key(vmk, &enc.user_id, &enc.identity_id);
    let aad = format!(
        "sshkma:record:v1:{}:{}",
        enc.user_id.as_str(),
        enc.identity_id.as_str()
    );
    let plaintext = EnvelopeCipher::decrypt(&enc.ciphertext, &record_key, aad.as_bytes())?;
    let record: PlaintextIdentityRecord = serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Deserialization(e.to_string()))?;
    Ok(record)
}

pub fn encrypt_manifest(
    manifest: &VaultManifest,
    vmk: &[u8; 32],
    user_id: &UserId,
) -> Result<Vec<u8>, VaultError> {
    let plaintext =
        serde_json::to_vec(manifest).map_err(|e| VaultError::Serialization(e.to_string()))?;
    let aad = format!("sshkma:manifest:v1:{}", user_id.as_str());
    Ok(EnvelopeCipher::encrypt(&plaintext, vmk, aad.as_bytes())?)
}

pub fn decrypt_manifest(
    bytes: &[u8],
    vmk: &[u8; 32],
    user_id: &UserId,
) -> Result<VaultManifest, VaultError> {
    let aad = format!("sshkma:manifest:v1:{}", user_id.as_str());
    let plaintext = EnvelopeCipher::decrypt(bytes, vmk, aad.as_bytes())?;
    let manifest: VaultManifest = serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Deserialization(e.to_string()))?;
    Ok(manifest)
}

pub fn check_revision(expected: u64, actual: u64) -> Result<(), VaultError> {
    if expected != actual {
        return Err(VaultError::RevisionConflict { expected, actual });
    }
    Ok(())
}
