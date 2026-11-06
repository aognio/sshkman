# Architecture Decision Records (ADRs)

We use [MADR (Markdown Architectural Decision Records)](https://adr.github.io/madr/) 4.0 to document significant architectural decisions.

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [ADR-0001](0001-cargo-workspace-decomposition.md) | Cargo Workspace and Library-First Decomposition | Accepted | 2026-11-04 |
| [ADR-0002](0002-sans-io-and-sansio-boundaries.md) | Sans-I/O and `sansio::Protocol` Usage Boundaries | Accepted | 2026-11-04 |
| [ADR-0003](0003-event-first-state-machines.md) | Event-First State Machines Without Event Sourcing | Accepted | 2026-11-04 |
| [ADR-0004](0004-file-only-persistence-and-storage.md) | File-Only Persistence and Git-Friendly Encrypted Vaults | Accepted | 2026-11-04 |
| [ADR-0005](0005-zero-knowledge-envelope-encryption.md) | Zero-Knowledge Threat Model and Envelope Encryption Format | Accepted | 2026-11-04 |
| [ADR-0006](0006-account-auth-vs-vault-unlock.md) | Account Authentication vs Vault Unlocking and Credential Storage | Accepted | 2026-11-04 |
| [ADR-0007](0007-client-configuration-and-xdg.md) | TOML and Platform-Native XDG Client Configuration | Accepted | 2026-11-04 |
| [ADR-0008](0008-server-configuration-and-fhs.md) | FHS `/etc/sshkma/sshkmad.toml` Server Configuration | Accepted | 2026-11-04 |
| [ADR-0009](0009-logfmt-logging-and-redaction.md) | Structured Logfmt Logging and Mandatory Secret Redaction | Accepted | 2026-11-04 |
| [ADR-0010](0010-openssh-managed-include-strategy.md) | OpenSSH Managed Include Strategy and File Ownership | Accepted | 2026-11-04 |
| [ADR-0011](0011-concurrency-atomic-writes-rollback.md) | Concurrency, Atomic Writes, and Rollback Limitations | Accepted | 2026-11-04 |
| [ADR-0012](0012-recovery-keys-and-revocation.md) | High-Entropy Recovery Keys, Device Revocation, and Limits | Accepted | 2026-11-04 |
| [ADR-0013](0013-shared-vault-access-and-roles.md) | Shared Vault Access, Roles, and Grant-Based Key Distribution | Proposed | 2026-11-06 |
