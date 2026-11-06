//! Sans-I/O state machines and transition logic for sshkma.

use secrecy::ExposeSecret;
use serde::Deserialize;
use sshkma_domain::{AuthState, OperationId, UserId, VaultLockState};
use sshkma_events::{Command, DomainEvent, Effect, EffectPayload, EffectResult};
use std::collections::VecDeque;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ProtocolError {
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("vault locked")]
    VaultLocked,
}

#[derive(Debug, Clone)]
pub struct ClientProtocol {
    pub auth_state: AuthState,
    pub vault_state: VaultLockState,
    pending: VecDeque<OperationId>,
}

impl Default for ClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientProtocol {
    pub fn new() -> Self {
        Self {
            auth_state: AuthState::Unauthenticated,
            vault_state: VaultLockState::Locked,
            pending: VecDeque::new(),
        }
    }

    pub fn auth_state(&self) -> &AuthState {
        &self.auth_state
    }

    pub fn vault_state(&self) -> &VaultLockState {
        &self.vault_state
    }

    pub fn dispatch(&mut self, cmd: Command) -> Vec<Effect> {
        match cmd {
            Command::Login {
                url,
                username,
                password,
            } => {
                let op = OperationId::new();
                self.pending.push_back(op.clone());
                let body = serde_json::json!({
                    "username": username,
                    "password": password.expose_secret(),
                })
                .to_string()
                .into_bytes();
                vec![Effect::new(
                    op,
                    EffectPayload::SendHttpRequest {
                        method: "POST".into(),
                        url: format!("{}/api/v1/auth/login", url.trim_end_matches('/')),
                        body: Some(body),
                        headers: vec![("content-type".into(), "application/json".into())],
                    },
                )]
            }
            Command::Logout { all_devices } => {
                let op = OperationId::new();
                self.pending.push_back(op.clone());
                self.auth_state = AuthState::Unauthenticated;
                self.vault_state = VaultLockState::Locked;
                vec![Effect::new(
                    op,
                    EffectPayload::SendHttpRequest {
                        method: "POST".into(),
                        url: "/api/v1/auth/logout".into(),
                        body: Some(
                            serde_json::json!({"all_devices": all_devices})
                                .to_string()
                                .into_bytes(),
                        ),
                        headers: vec![],
                    },
                )]
            }
            Command::Unlock { password: _ } => {
                // Client-side unlock requires fetching wrapped key; simplified.
                self.vault_state = VaultLockState::Unlocked;
                vec![]
            }
            Command::Lock => {
                self.vault_state = VaultLockState::Locked;
                vec![]
            }
            Command::ImportKey {
                slug,
                host_alias: _,
                hostname: _,
                user: _,
                port: _,
                private_key_bytes: _,
                public_key_bytes: _,
            } => {
                // Emit no effect in pure core; caller handles persistence.
                let _ = slug;
                vec![]
            }
            Command::Install {
                slug: _,
                dry_run: _,
            } => vec![],
            Command::Remove {
                slug: _,
                dry_run: _,
            } => vec![],
            Command::Sync { dry_run: _ } => vec![],
        }
    }

    pub fn complete(&mut self, result: EffectResult) -> Vec<DomainEvent> {
        match result {
            EffectResult::HttpSuccess {
                operation_id,
                status: _,
                body,
                etag: _,
            } => {
                self.pending.retain(|id| id != &operation_id);
                #[derive(Deserialize)]
                struct LoginResp {
                    user_id: String,
                    session_id: String,
                }
                if let Ok(resp) = serde_json::from_slice::<LoginResp>(&body) {
                    if let (Ok(uid), Ok(sid)) = (
                        UserId::parse(&resp.user_id),
                        sshkma_domain::SessionId::parse(&resp.session_id),
                    ) {
                        self.auth_state = AuthState::Authenticated {
                            user_id: uid,
                            session_id: sid,
                        };
                        return vec![DomainEvent::Authenticated {
                            user_id: self.auth_user_id().unwrap(),
                            session_id: self.auth_session_id().unwrap(),
                        }];
                    }
                }
                vec![]
            }
            EffectResult::HttpFailure { operation_id, .. } => {
                self.pending.retain(|id| id != &operation_id);
                vec![]
            }
            _ => vec![],
        }
    }

    fn auth_user_id(&self) -> Option<UserId> {
        match &self.auth_state {
            AuthState::Authenticated { user_id, .. } => Some(user_id.clone()),
            _ => None,
        }
    }

    fn auth_session_id(&self) -> Option<sshkma_domain::SessionId> {
        match &self.auth_state {
            AuthState::Authenticated { session_id, .. } => Some(session_id.clone()),
            _ => None,
        }
    }
}

// Re-exports for convenience.
pub use sshkma_domain::AuthState as ClientAuthState;
pub use sshkma_domain::VaultLockState as ClientVaultLockState;

// Aliases
pub type StateMachine = ClientProtocol;
pub type ClientStateMachine = ClientProtocol;
