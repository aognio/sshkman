# Concurrency, Atomic Writes, and Rollback Limitations

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Concurrency, Storage Consistency, Rollback Protection

## Context and Problem Statement

Multiple clients or daemon threads may update vault records simultaneously. Without proper concurrency controls, concurrent updates lead to lost updates or corrupt intermediate states. In addition, an untrusted server could attempt a "rollback attack" by serving an older valid ciphertext revision.

We must define atomic write semantics, optimistic locking strategies, and state limitations regarding rollback prevention.

## Decision Drivers

* Atomicity: filesystem writes must either completely succeed or leave previous state intact.
* Lost-update prevention: prevent Client B from silently overwriting Client A's changes.
* Honesty about zero-knowledge limits: acknowledge that without external distributed consensus or trusted clocks, a malicious server can withhold newer updates.

## Considered Options

* Option 1: Last-Write-Wins (LWW) without revision checks.
* Option 2: Distributed consensus (Raft/Paxos).
* Option 3: Optimistic Concurrency Control (OCC) via revision counters and ETag/If-Match headers, backed by atomic file replacement and cross-platform advisory locking (`fs4`).

## Decision Outcome

Chosen option: Option 3 ("Optimistic Concurrency Control with Atomic Replacement").

### 1. Atomic Write Protocol
Every file modification follows a strict 4-step sequence:
1. Create temporary file `.<filename>.tmp.<pid>.<uuid>` in the exact target directory.
2. Write complete payload and call `sync_all()` (`fsync`).
3. Atomically rename temporary file to target path (`std::fs::rename`).
4. On Unix, open parent directory and call `fsync()` to persist directory inode changes.

### 2. Optimistic Concurrency Control
- Manifests and identity envelopes carry an integer `revision` (incremented on every mutation) and a SHA-256 fingerprint.
- HTTP API mutations require `If-Match: "<revision>"` header or request body `expected_revision`.
- If the server's current revision differs from the expected revision, the server rejects the request with HTTP `409 Conflict`.

### 3. Rollback Defense & Limitations
- Clients record the highest seen `revision` locally in `${XDG_CONFIG_HOME}/sshkma/state.toml`.
- If a server responds with a `revision` lower than the highest seen revision, the client halts with a critical rollback alert (`ERROR: Server attempted state rollback from rev X to rev Y`).
- Limitation: If a new client device joins without prior state history, it cannot independently detect whether the server served the latest revision or a past valid revision without out-of-band verification.

### Positive Consequences

* No corrupted files under unexpected power loss or crashes.
* Concurrency conflicts are detected deterministically and surfaced to the user.

### Negative Consequences

* File system operations require extra tempfile allocations and fsync calls.
