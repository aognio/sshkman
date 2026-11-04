# Sans-I/O and sansio::Protocol Usage Boundaries

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Architecture, Protocol Engine, Async Isolation

## Context and Problem Statement

Network protocols and command orchestration engines often intertwine socket I/O, disk writes, and timers directly into business logic, making deterministic testing and fault simulation difficult. The `sansio` architectural pattern decouples protocol state machines from external I/O effects.

We must decide how `webrtc-rs/sansio`'s `Protocol<Rin, Win, Ein>` trait maps to `sshkma`'s command workflows without shoehorning every simple transformation.

## Decision Drivers

* Deterministic testing: simulate network timeouts, retries, and corrupted responses without live sockets.
* Fidelity to `sansio` crate semantics without abusing `poll_write` as an arbitrary untyped side-channel.
* Keeping pure functions and simple data conversions as clean standalone units.

## Considered Options

* Option 1: Direct async orchestration in `tokio` (traditional Imperative Shell with direct network/disk calls).
* Option 2: Full `sansio::Protocol` applied to every single struct and pure helper.
* Option 3: Hybrid Architecture: Pure functional state machines in `sshkma-protocol` with an adapter implementing `sansio::Protocol<EffectResult, Effect, Command>` for the orchestration loop, while pure domain helpers (crypto wrapping, installation planning) remain direct functional transforms.

## Decision Outcome

Chosen option: Option 3 ("Hybrid Architecture").

We map `sansio::Protocol` as follows:
- `Ein` (Input Event): `Command` (e.g. `Login`, `Unlock`, `Import`, `Install`, `Sync`)
- `Eout` (Output Event): `DomainEvent` (e.g. `Authenticated`, `VaultUnlocked`, `IdentityInstalled`)
- `Win` (Write Input): None (`()`)
- `Wout` (Poll Write / Outbound): Typed `Effect` (e.g. `SendHttp`, `WriteFile`, `ReadKeyring`)
- `Rin` (Handle Read / Inbound): Typed `EffectResult` (e.g. `HttpResponse`, `FileReadSuccess`, `ErrorResult`)
- `Rout` (Poll Read): None (`()`)
- `Time`: Injected synthetic timestamps (`Instant` or `SystemTime`) passed to `handle_timeout()`

Simple functional policies (such as computing an `InstallationPlan` from an existing SSH configuration and identity list) are implemented as pure functions: `plan(existing: &Config, target: &[Identity]) -> InstallationPlan`.

### Positive Consequences

* Every sequence of commands, effects, network errors, and retries can be tested in deterministic unit tests.
* Zero external async runtime required for core logic verification.

### Negative Consequences

* Requires the imperative shell (`sshkma-client` / `sshkma-server`) to translate `Effect` enums to actual async calls.
