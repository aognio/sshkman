use secrecy::SecretString;
use sshkma_domain::AuthState;
use sshkma_events::{Command, EffectPayload, EffectResult};
use sshkma_protocol::ClientProtocol;

#[test]
fn login_dispatch_produces_http_effect() {
    let mut p = ClientProtocol::new();
    let effects = p.dispatch(Command::Login {
        url: "http://localhost".into(),
        username: "alice".into(),
        password: SecretString::from("pass".to_string()),
    });
    assert_eq!(effects.len(), 1);
    assert!(matches!(
        effects[0].payload,
        EffectPayload::SendHttpRequest { .. }
    ));
}

#[test]
fn logout_resets_state() {
    let mut p = ClientProtocol::new();
    let _ = p.dispatch(Command::Logout { all_devices: false });
    assert!(matches!(p.auth_state(), AuthState::Unauthenticated));
    assert!(matches!(
        p.vault_state(),
        sshkma_domain::VaultLockState::Locked
    ));
}

#[test]
fn unlock_lock_toggle() {
    let mut p = ClientProtocol::new();
    let _ = p.dispatch(Command::Unlock {
        password: SecretString::from("p".to_string()),
    });
    assert!(matches!(
        p.vault_state(),
        sshkma_domain::VaultLockState::Unlocked
    ));
    let _ = p.dispatch(Command::Lock);
    assert!(matches!(
        p.vault_state(),
        sshkma_domain::VaultLockState::Locked
    ));
}

#[test]
fn login_complete_sets_authenticated() {
    let mut p = ClientProtocol::new();
    let effects = p.dispatch(Command::Login {
        url: "http://localhost".into(),
        username: "alice".into(),
        password: SecretString::from("pass".to_string()),
    });
    let op = effects[0].operation_id.clone();
    let uid = "550e8400-e29b-41d4-a716-446655440000";
    let sid = "660e8400-e29b-41d4-a716-446655440001";
    let body = serde_json::json!({"user_id": uid, "session_id": sid})
        .to_string()
        .into_bytes();
    let events = p.complete(EffectResult::HttpSuccess {
        operation_id: op,
        status: 200,
        body,
        etag: None,
    });
    assert!(!events.is_empty());
    assert!(matches!(p.auth_state(), AuthState::Authenticated { .. }));
}
