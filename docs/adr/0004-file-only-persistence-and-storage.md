# File-Only Persistence and Git-Friendly Encrypted Vaults

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Server Persistence, Storage Format

## Context and Problem Statement

`sshkmad` must persist user accounts, active sessions, registered devices, and encrypted vault records. Standard architectures often default to embedded databases such as SQLite or RocksDB. However, the system requirements mandate:
- No SQLite or SQL databases
- Filesystem-only persistence
- Human-inspectable TOML metadata
- Git-friendly backup workflows for encrypted vault records
- Crash resilience and atomic updates

## Decision Drivers

* Strict compliance with project principles (No SQLite).
* Operability: ability to backup, restore, inspect, or version vault records via standard Unix tools (rsync, tar, git).
* Security: operational state (sessions, auth tokens) must be isolated from Git-versioned vault data.
* Data integrity: zero corruptions from power failure or process crashes.

## Considered Options

* Option 1: SQLite or embedded key-value database (sled, redb).
* Option 2: Single monolithic JSON/TOML file for all server state.
* Option 3: Structured directory hierarchy with atomic TOML files for metadata and individual `.enc` binary files for encrypted envelopes.

## Decision Outcome

Chosen option: Option 3 ("Structured directory hierarchy").

Storage layout under `/var/lib/sshkmad` (or configurable root):
```text
users/<opaque-user-id>/
  account.toml             # Hashed auth password, status, created_at
  vault.toml               # Wrapped VMK, Argon2 params, salt, nonce, revision
  manifest.enc             # Encrypted vault index (slug-to-ID mapping)
  identities/
    <opaque-id>.enc        # Individual encrypted identity envelope
devices/
  <opaque-device-id>.toml  # Device metadata, last seen, status
sessions/
  <opaque-session-id>.toml # Active session tokens (hashed), expiration
```

All mutations use atomic replacement:
1. Write to temporary file in the same directory (`tempfile` in parent dir).
2. Call `fsync()` on the file.
3. Atomic `rename()` over the target path.
4. Call `fsync()` on the parent directory (on platforms where supported).
5. Cross-platform advisory file locking (`fs4`) prevents concurrent write races.

Git backup guidance:
A `.gitignore` template is provided for administrators wishing to track `/var/lib/sshkmad` with Git: `sessions/`, `logs/`, and temporary files are strictly ignored, ensuring only encrypted vault content and static account metadata are committed.

### Positive Consequences

* No database driver dependencies or migration locks.
* Safe concurrent updates with POSIX atomic rename semantics.
* Encrypted vaults can be backed up or mirrored with standard tools.

### Negative Consequences

* File I/O overhead on large numbers of identities (mitigated by fine-grained individual files and manifest caching).
