# Event-First State Machines Without Event Sourcing

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Domain Events, State Modeling

## Context and Problem Statement

Complex client workflows (e.g. login -> token receipt -> vault fetch -> password prompt -> VMK unlock -> manifest download -> identity download -> installation diff -> installation apply) require distinct lifecycle stages, cancellation support, and error recovery.

We need an event-driven design that provides explicit state transitions and auditable domain events, but without introducing the complexity, append-only logs, and storage overhead of Event Sourcing or an event database.

## Decision Drivers

* Clear, explicit lifecycle modeling (pending, authorized, unlocked, syncing, committed).
* Testability: verifying that specific domain events occur only after corresponding effects succeed.
* Secret prevention: preventing sensitive keys or passwords from being stored in broad state snapshots or event journals.
* Minimal storage footprint and simple filesystem persistence.

## Considered Options

* Option 1: Full Event Sourcing (CQRS, append-only event log, event replay).
* Option 2: Implicit mutable state across async task spans.
* Option 3: Event-First State Machines (commands trigger transitions that produce typed domain events and required effects, mutating in-memory finite state without persistent event journals).

## Decision Outcome

Chosen option: Option 3 ("Event-First State Machines").

The engine maintains explicit state enums (e.g., `ClientState::Unauthenticated`, `ClientState::Authenticated`, `ClientState::Unlocked(DecryptedSession)`). Transitions are driven by `Command` inputs and `EffectResult` completions. Completed transitions emit lightweight, immutable `DomainEvent` records for observability and verification. No event log is persisted to disk.

Secrets (`VaultMasterKey`, `PrivateKeyBytes`) are wrapped in `Zeroizing` / `Secret` wrappers and cleared upon state exit or lock.

### Positive Consequences

* No dependency on event database or event serialization schemas.
* Deterministic state machines that can be exhaustively tested with mock effect sequences.
* Clear separation between operational tracing and business domain facts.

### Negative Consequences

* Application state cannot be rebuilt by replaying historical events; state is recovered from persistent files and fresh authentication.
