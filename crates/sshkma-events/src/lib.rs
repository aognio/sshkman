//! Commands, Effects, and Domain Events for sshkma.
//!
//! All external actions are requested via typed `Effect` descriptors carrying
//! an `OperationId` correlation token. All sensitive data is protected by `secrecy`.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sshkma_domain::{HostAlias, IdentityId, ManagedFile, OperationId, SessionId, Slug, UserId};
use std::fmt;

/// User intentions dispatched to the client engine.
#[derive(Clone)]
pub enum Command {
    Login {
        url: String,
        username: String,
        password: SecretString,
    },
    Logout {
        all_devices: bool,
    },
    Unlock {
        password: SecretString,
    },
    Lock,
    ImportKey {
        slug: Slug,
        host_alias: Option<HostAlias>,
        hostname: Option<String>,
        user: Option<String>,
        port: Option<u16>,
        private_key_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    },
    Install {
        slug: Slug,
        dry_run: bool,
    },
    Remove {
        slug: Slug,
        dry_run: bool,
    },
    Sync {
        dry_run: bool,
    },
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login { url, username, .. } => f
                .debug_struct("Login")
                .field("url", url)
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Logout { all_devices } => f
                .debug_struct("Logout")
                .field("all_devices", all_devices)
                .finish(),
            Self::Unlock { .. } => f
                .debug_struct("Unlock")
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Lock => write!(f, "Lock"),
            Self::ImportKey {
                slug,
                host_alias,
                hostname,
                user,
                port,
                ..
            } => f
                .debug_struct("ImportKey")
                .field("slug", slug)
                .field("host_alias", host_alias)
                .field("hostname", hostname)
                .field("user", user)
                .field("port", port)
                .field("private_key_bytes", &"[REDACTED]")
                .field("public_key_bytes", &"[REDACTED]")
                .finish(),
            Self::Install { slug, dry_run } => f
                .debug_struct("Install")
                .field("slug", slug)
                .field("dry_run", dry_run)
                .finish(),
            Self::Remove { slug, dry_run } => f
                .debug_struct("Remove")
                .field("slug", slug)
                .field("dry_run", dry_run)
                .finish(),
            Self::Sync { dry_run } => f.debug_struct("Sync").field("dry_run", dry_run).finish(),
        }
    }
}

/// External effect payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectPayload {
    SendHttpRequest {
        method: String,
        url: String,
        body: Option<Vec<u8>>,
        headers: Vec<(String, String)>,
    },
    ReadFile {
        path: String,
    },
    WriteManagedFile {
        file: ManagedFile,
    },
    DeleteManagedFile {
        path: String,
    },
    StoreKeyring {
        service: String,
        user: String,
        secret: String,
    },
    ReadKeyring {
        service: String,
        user: String,
    },
    DeleteKeyring {
        service: String,
        user: String,
    },
    PromptVaultPassword,
}

/// A requested external operation with correlation ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub operation_id: OperationId,
    pub payload: EffectPayload,
}

impl Effect {
    pub fn new(operation_id: OperationId, payload: EffectPayload) -> Self {
        Self {
            operation_id,
            payload,
        }
    }
}

/// Inbound completion result for an external effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectResult {
    HttpSuccess {
        operation_id: OperationId,
        status: u16,
        body: Vec<u8>,
        etag: Option<String>,
    },
    HttpFailure {
        operation_id: OperationId,
        status: u16,
        message: String,
    },
    FileReadSuccess {
        operation_id: OperationId,
        bytes: Vec<u8>,
    },
    FileWriteSuccess {
        operation_id: OperationId,
    },
    KeyringSuccess {
        operation_id: OperationId,
        secret: Option<String>,
    },
    OperationFailed {
        operation_id: OperationId,
        error: String,
    },
}

/// Domain events emitted upon completed state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum DomainEvent {
    Authenticated {
        user_id: UserId,
        session_id: SessionId,
    },
    LoggedOut {
        all_devices: bool,
    },
    VaultUnlocked,
    VaultLocked,
    IdentityImported {
        slug: Slug,
        identity_id: IdentityId,
    },
    IdentityInstalled {
        slug: Slug,
    },
    IdentityRemoved {
        slug: Slug,
    },
    SyncCompleted {
        applied_count: usize,
    },
}
