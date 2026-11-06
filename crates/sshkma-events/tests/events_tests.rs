use secrecy::SecretString;
use sshkma_domain::{OperationId, Slug};
use sshkma_events::{Command, DomainEvent, Effect, EffectPayload};

#[test]
fn test_command_redaction_in_debug() {
    let secret = SecretString::from("super_sensitive_password".to_string());
    let cmd = Command::Login {
        url: "https://vault.example.com".into(),
        username: "alice".into(),
        password: secret,
    };

    let debug_str = format!("{:?}", cmd);
    assert!(
        !debug_str.contains("super_sensitive_password"),
        "Plaintext password leaked into Debug string: {}",
        debug_str
    );
    assert!(debug_str.contains("[REDACTED]"));
}

#[test]
fn test_effects_have_correlation_operation_id() {
    let op_id = OperationId::new();
    let effect = Effect::new(
        op_id.clone(),
        EffectPayload::ReadFile {
            path: "/path/to/key".into(),
        },
    );

    assert_eq!(effect.operation_id, op_id);
    let debug_str = format!("{:?}", effect);
    assert!(debug_str.contains(op_id.as_str()));
}

#[test]
fn test_domain_events_serialization() {
    let slug = Slug::parse("my-key").unwrap();
    let evt = DomainEvent::IdentityInstalled { slug };
    let json = serde_json::to_string(&evt).expect("serialize domain event");
    assert!(json.contains("my-key"));
}
