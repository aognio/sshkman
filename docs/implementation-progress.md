# Implementation Progress Ledger

This document tracks autonomous execution through each gate defined in `.development/prompts/001.md`.

---

## Gate A: Discovery, Research & Architecture Checkpoint
*Status: COMPLETED (2026-11-04)*

- [x] Verified dependencies against crates.io and Rust 1.99 (`docs/research.md`).
- [x] Evaluated and mapped `webrtc-rs/sansio` `Protocol<Rin, Win, Ein>` trait.
- [x] Formulated zero-knowledge Threat Model (`docs/security/threat-model.md`).
- [x] Drafted and indexed MADR ADRs 0001 through 0012 (`docs/adr/`).
- [x] Scaffolding: root `Cargo.toml`, `rust-toolchain.toml`, `Makefile`, `AGENTS.md`, and 12 library crates + 2 application crates.
- [x] Verification: `cargo fmt`, `cargo clippy`, and `cargo test` pass across workspace.

---

## Gate B: Pure Libraries Implementation
*Status: IN PROGRESS*

Targeted Crates:
- `crates/sshkma-domain`: Strongly typed IDs (`UserId`, `DeviceId`, `SessionId`, `IdentityId`, `Slug`), key envelope models, typed error catalog.
- `crates/sshkma-events`: Commands, effects, domain events with correlation IDs.
- `crates/sshkma-crypto`: Argon2id KDF, XChaCha20-Poly1305 AEAD, HKDF key derivation, zeroization, secret redaction, test vectors.
- `crates/sshkma-sshconfig`: OpenSSH config parsing, Managed Include directives, byte-for-byte keypair preservation.
- `crates/sshkma-config`: Client and server TOML configuration models and validation.
- `crates/sshkma-vault`: Encrypted identity envelopes, vault manifest, optimistic concurrency checks.

---

## Gate C: Sans-I/O Engine Implementation
*Status: PENDING*

- Pure state machines for auth, unlock, sync, install.
- `sansio::Protocol` orchestrator adapter.
- Deterministic simulation tests without I/O.

---

## Gate D: File Store and Server Implementation
*Status: PENDING*

- `sshkma-storage`: Filesystem store, atomic tempfile rename, fsync, advisory locking.
- `sshkma-auth`: Password verifier, session & device state tracking.
- `sshkma-server`: Axum HTTP API handlers, OpenAPI contract, logfmt tracing.
- `apps/sshkmad`: Daemon CLI subcommands.

---

## Gate E: Client Implementation
*Status: PENDING*

- `sshkma-client`: HTTP client, OS keyring & TOML fallback, OpenSSH installer/remover with rollback & dry-run.
- `apps/sshkma`: Client CLI subcommands.

---

## Gate F: E2E and Hardening
*Status: PENDING*

- Multi-device sync E2E scenario.
- Property-based tests (`proptest`).
- Operational guides and final verification.
