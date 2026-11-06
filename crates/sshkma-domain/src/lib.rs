//! Core domain primitives, identifiers, and typed errors for sshkma.
//!
//! This crate contains pure data types with zero I/O and zero async dependencies.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

/// Typed domain errors with strict prohibition against secret leakage.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum DomainError {
    #[error("invalid slug: {0}")]
    InvalidSlug(String),

    #[error("invalid host alias: {0}")]
    InvalidHostAlias(String),

    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("permission error: {0}")]
    PermissionError(String),

    #[error("conflict error: {0}")]
    Conflict(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("state error: {0}")]
    InvalidState(String),
}

macro_rules! define_opaque_id {
    ($name:ident, $prefix:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Generate a fresh random UUID v4 identifier.
            pub fn new() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            /// Parse an existing string representation.
            pub fn parse(s: &str) -> Result<Self, DomainError> {
                let parsed = Uuid::parse_str(s).map_err(|_| {
                    DomainError::InvalidIdentifier(format!(
                        "invalid {} UUID: {}",
                        stringify!($name),
                        s
                    ))
                })?;
                Ok(Self(parsed.to_string()))
            }

            /// Return as string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_opaque_id!(UserId, "usr");
define_opaque_id!(DeviceId, "dev");
define_opaque_id!(SessionId, "ses");
define_opaque_id!(IdentityId, "idn");
define_opaque_id!(OperationId, "op");

/// Validated local identity slug (`^[a-zA-Z0-9_-]{1,64}$`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Slug(String);

impl Slug {
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        if s.is_empty() {
            return Err(DomainError::InvalidSlug("slug cannot be empty".into()));
        }
        if s.len() > 64 {
            return Err(DomainError::InvalidSlug(
                "slug exceeds 64 characters limit".into(),
            ));
        }
        let valid = s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid {
            return Err(DomainError::InvalidSlug(
                "slug must contain only ASCII alphanumeric characters, hyphens, and underscores"
                    .into(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validated OpenSSH host alias (`^[a-zA-Z0-9_.-]{1,128}$`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostAlias(String);

impl HostAlias {
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        if s.is_empty() {
            return Err(DomainError::InvalidHostAlias(
                "host alias cannot be empty".into(),
            ));
        }
        if s.len() > 128 {
            return Err(DomainError::InvalidHostAlias(
                "host alias exceeds 128 characters limit".into(),
            ));
        }
        let valid = s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !valid {
            return Err(DomainError::InvalidHostAlias(
                "host alias must contain only ASCII alphanumeric characters, hyphens, underscores, and dots".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// SHA-256 fingerprint of managed file contents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileFingerprint(String);

impl FileFingerprint {
    pub fn compute(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hex::encode(hasher.finalize()))
    }

    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidIdentifier(
                "fingerprint must be a 64-character hex string".into(),
            ));
        }
        Ok(Self(s.to_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FileFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Managed file category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedFileType {
    SshConfig,
    SshPrivateKey,
    SshPublicKey,
}

/// Represents a file managed by sshkma on the local filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedFile {
    pub path: String,
    pub file_type: ManagedFileType,
    pub mode: u32,
    pub content: Vec<u8>,
    pub fingerprint: FileFingerprint,
}

impl ManagedFile {
    pub fn new(
        path: impl Into<String>,
        file_type: ManagedFileType,
        mode: u32,
        content: Vec<u8>,
    ) -> Self {
        let fingerprint = FileFingerprint::compute(&content);
        Self {
            path: path.into(),
            file_type,
            mode,
            content,
            fingerprint,
        }
    }

    pub fn fingerprint(&self) -> &FileFingerprint {
        &self.fingerprint
    }
}

/// Discrete action in an installation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAction {
    Create(ManagedFile),
    Update { old: ManagedFile, new: ManagedFile },
    Delete(ManagedFile),
    Unchanged(ManagedFile),
}

/// An execution plan detailing filesystem changes prior to execution.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationPlan {
    actions: Vec<FileAction>,
}

impl InstallationPlan {
    pub fn new(actions: Vec<FileAction>) -> Self {
        Self { actions }
    }

    pub fn add_action(&mut self, action: FileAction) {
        self.actions.push(action);
    }

    pub fn actions(&self) -> &[FileAction] {
        &self.actions
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Authentication state model.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthState {
    #[default]
    Unauthenticated,
    Authenticated {
        user_id: UserId,
        session_id: SessionId,
    },
}

/// Vault lock state.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultLockState {
    #[default]
    Locked,
    Unlocked,
}
