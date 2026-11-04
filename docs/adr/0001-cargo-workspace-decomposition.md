# Cargo Workspace and Library-First Decomposition

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Workspace Organization, Crate Boundaries

## Context and Problem Statement

`sshkma` (client) and `sshkmad` (server) share common cryptographic envelope definitions, domain identifiers, and configuration structures, but have completely separate runtime models (client CLI vs server HTTP daemon). Placing all logic in binary crates or a monolithic crate couples pure cryptographic policies to async runtimes (Axum, Tokio, Reqwest) and filesystem operations.

## Decision Drivers

* Clean/Hexagonal Architecture: core domain and cryptographic policies must have zero dependencies on network, Tokio, or filesystem.
* Fast compile times and clear boundary enforcement.
* Reusability of client and server libraries without requiring the CLI binaries.
* Strict prevention of secret leakage across crate boundaries.

## Considered Options

* Option 1: Monolithic single-crate with feature flags.
* Option 2: Fine-grained multi-crate workspace (Domain, Events, Crypto, Protocol, SSHConfig, Config, Vault, Storage, Auth, Engine, Client, Server, and binary apps).
* Option 3: Two large crates (`sshkma-client` and `sshkma-server`).

## Decision Outcome

Chosen option: Option 2 ("Fine-grained multi-crate workspace"), because it enforces strict compile-time architectural layers and prevents accidental leakage of I/O or server code into pure domain libraries.

The workspace crate hierarchy is:
- `crates/sshkma-domain`: Opaque IDs, validation, error types, domain models (Zero I/O, no async).
- `crates/sshkma-events`: Commands, effects, and domain events with correlation IDs.
- `crates/sshkma-crypto`: Argon2id, XChaCha20-Poly1305, HKDF, zeroize, envelope wrapping.
- `crates/sshkma-vault`: Vault manifest and encrypted identity envelope formats.
- `crates/sshkma-sshconfig`: OpenSSH config parsing, Managed Include directives, byte preservation.
- `crates/sshkma-config`: Client and server TOML configuration models and validation.
- `crates/sshkma-protocol`: Pure sans-I/O state machines and `sansio::Protocol` adapters.
- `crates/sshkma-engine`: Pure deterministic execution loop for events and effects.
- `crates/sshkma-storage`: Filesystem persistence, atomic replacement, file locking, fsync.
- `crates/sshkma-auth`: Server-side password hashing, token issuance, device tracking.
- `crates/sshkma-server`: Axum HTTP handlers, OpenAPI routes, logfmt tracing.
- `crates/sshkma-client`: HTTP client, OS keyring adapter, local OpenSSH executor.
- `apps/sshkma`: Client CLI binary.
- `apps/sshkmad`: Server CLI daemon binary.

### Positive Consequences

* Domain logic, crypto, and SSH config parsing are testable in milliseconds without mocks or disk I/O.
* Clear isolation ensures the server crate cannot accidentally access client vault decryption code.

### Negative Consequences

* Higher number of `Cargo.toml` files to maintain.
