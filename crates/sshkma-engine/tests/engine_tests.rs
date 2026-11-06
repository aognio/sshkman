use secrecy::SecretString;
use sshkma_domain::AuthState;
use sshkma_engine::Engine;
use sshkma_events::{Command, EffectResult};

#[test]
fn engine_dispatch_and_complete() {
    let mut e = Engine::new();
    assert_eq!(e.now(), 0);
    e.set_time(42);
    assert_eq!(e.now(), 42);
    let effects = e.dispatch(Command::Login {
        url: "http://localhost".into(),
        username: "alice".into(),
        password: SecretString::from("pass".to_string()),
    });
    assert!(!effects.is_empty());
    assert!(!e.pending_effects().is_empty());
    assert!(!e.is_authenticated());
    let body = serde_json::json!({
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "session_id": "660e8400-e29b-41d4-a716-446655440001"
    })
    .to_string()
    .into_bytes();
    let op = effects[0].operation_id.clone();
    let events = e.complete(EffectResult::HttpSuccess {
        operation_id: op,
        status: 200,
        body,
        etag: None,
    });
    assert!(!events.is_empty());
    assert!(e.is_authenticated());
    assert!(matches!(e.auth_state(), AuthState::Authenticated { .. }));
    // poll event
    assert!(e.poll_event().is_some());
}

#[test]
fn engine_lock_unlock() {
    let mut e = Engine::with_time(7);
    assert_eq!(e.now(), 7);
    let _ = e.dispatch(Command::Unlock {
        password: SecretString::from("p".to_string()),
    });
    assert!(matches!(
        e.vault_state(),
        sshkma_domain::VaultLockState::Unlocked
    ));
    let _ = e.dispatch(Command::Lock);
    assert!(matches!(
        e.vault_state(),
        sshkma_domain::VaultLockState::Locked
    ));
}
