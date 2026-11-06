//! Event-driven engine orchestrating pure protocol state machines.

use sshkma_events::{Command, DomainEvent, Effect, EffectResult};
use sshkma_protocol::ClientProtocol;
use std::collections::VecDeque;

#[derive(Debug, Default)]
pub struct Engine {
    protocol: ClientProtocol,
    pending_effects: VecDeque<Effect>,
    completed_events: VecDeque<DomainEvent>,
    now: u64,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_time(now: u64) -> Self {
        Self {
            now,
            ..Self::default()
        }
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn set_time(&mut self, now: u64) {
        self.now = now;
    }

    pub fn dispatch(&mut self, cmd: Command) -> Vec<Effect> {
        let effects = self.protocol.dispatch(cmd);
        for e in &effects {
            self.pending_effects.push_back(e.clone());
        }
        effects
    }

    pub fn complete(&mut self, result: EffectResult) -> Vec<DomainEvent> {
        let events = self.protocol.complete(result);
        for e in &events {
            self.completed_events.push_back(e.clone());
        }
        events
    }

    pub fn poll_event(&mut self) -> Option<DomainEvent> {
        self.completed_events.pop_front()
    }

    pub fn pending_effects(&self) -> &VecDeque<Effect> {
        &self.pending_effects
    }

    pub fn auth_state(&self) -> &sshkma_domain::AuthState {
        self.protocol.auth_state()
    }

    pub fn vault_state(&self) -> &sshkma_domain::VaultLockState {
        self.protocol.vault_state()
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(
            self.protocol.auth_state(),
            sshkma_domain::AuthState::Authenticated { .. }
        )
    }
}

// Aliases
pub type ClientEngine = Engine;
