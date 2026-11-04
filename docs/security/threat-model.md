# Threat Model: sshkma & sshkmad

Date: 2026-11-04  
Status: Accepted  
Scope: Architecture, Cryptographic Envelopes, Client-Server Protocol, Storage

---

## 1. Overview & Trust Boundaries

`sshkma` is a client CLI and library for local OpenSSH key management.  
`sshkmad` is a self-hosted server daemon providing authentication, session coordination, and encrypted identity envelope storage.

```
+-----------------------------------------------------------------------------------------+
| TRUST BOUNDARY: CLIENT HOST                                                             |
|                                                                                         |
|   User Input (Vault Password, Recovery Key)                                             |
|       │                                                                                 |
|       ▼                                                                                 |
|   sshkma Client Core (Pure Sans-I/O Engine)                                             |
|       │  - Plaintext VMK (in-memory zeroized)                                           |
|       │  - Plaintext SSH keypairs (in-memory zeroized)                                  |
|       │  - Argon2id KEK derivation                                                      |
|       │  - XChaCha20-Poly1305 AEAD envelope encryption/decryption                       |
|       ├──────────────────────────────┬───────────────────────────────┐                  |
|       ▼                              ▼                               ▼                  |
|   OS Keyring                    ~/.ssh/managed/                 ~/.ssh/keys/            |
|   (Auth Tokens)                 (Include configs)               (Exported Keypairs)     |
+──────────────────────────────────────┼──────────────────────────────────────────────────+
                                       │ TLS 1.3 / HTTPS (Bearer Token, Ciphertext Only)
                                       │
+──────────────────────────────────────┼──────────────────────────────────────────────────+
| TRUST BOUNDARY: UNTRUSTED / ZERO-KNOWLEDGE SERVER HOST                                  |
|                                                                                         |
|   sshkmad Server Daemon                                                                 |
|       │  - Verifies account authentication (Argon2id user password hash)                |
|       │  - Issues / revokes short-lived access tokens & rotating refresh tokens         |
|       │  - NEVER receives: plaintext SSH keys, vault password, VMK, or plaintext slugs   |
|       ▼                                                                                 |
|   Filesystem Persistence (/var/lib/sshkmad)                                             |
|       ├── users/<user_id>/vault.toml (Wrapped VMK, Argon2 params, salts)                |
|       ├── users/<user_id>/identities/<opaque_id>.enc (Encrypted envelopes)              |
|       ├── devices/<device_id>.toml                                                      |
|       └── sessions/<session_id>.toml                                                    |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Threat Analysis by Actor & Vector

| Threat Vector | Description | Countermeasure / Mitigation | Residual Risk |
|---|---|---|---|
| **Compromised Server / File Store** | Attacker gains full read access to `/var/lib/sshkmad` (filesystem dump, backup breach). | All vault secrets, manifests, and identities are encrypted client-side with VMK via XChaCha20-Poly1305. The server only possesses wrapped keys (requiring client vault password via Argon2id). VMK is never transmitted. | Observable record counts, update timestamps, and ciphertext lengths. Traffic analysis across client syncs. |
| **Malicious Server / Ciphertext Tampering** | Malicious or compromised server alters ciphertext blobs or injects bogus envelopes. | Poly1305 AEAD tags on all records. Context-bound Associated Authenticated Data (AAD) prevents cross-user, cross-vault, or cross-record swap attacks. Tampered records fail AEAD verification and are rejected. | Denial of service (client cannot decrypt corrupted record). |
| **Ciphertext Replay / Rollback** | Server delivers stale ciphertext or rolls back manifest to an older revision. | Optimistic concurrency revision counters (`revision` in manifest and ETag headers). Manifest includes version and content hashes of all valid identities. Client warns on unexpected revision regressions. | An untrusted server without external consensus can conceal the newest updates from an isolated client. Rollback detection requires client state cache. |
| **Credential Stuffing / Brute Force on Auth** | Attacker attacks `/api/v1/auth/login` endpoint. | Server hashes authentication passwords with Argon2id. Server enforces rate limiting (e.g., max 5 consecutive failures per user/IP before exponential backoff). | Distributed dictionary attacks on weak passwords. |
| **Stolen API Access Token** | Attacker intercepts or extracts client Bearer access token. | Tokens are short-lived (15 minutes). Tokens allow access only to encrypted blobs; knowledge of the access token provides **zero access** to plaintext SSH keys. Refresh tokens rotate on every refresh with replay detection (reused token invalidates entire family). | Attacker can read/write encrypted blobs for up to 15 minutes or until revoked. |
| **Stolen Client Device / Local Malware** | Attacker obtains physical access to endpoint or executes code as client user. | Tokens stored in OS Keychain (or restrictive 0600 TOML file if opted in). VMK and decrypted keys exist only transiently in memory with `zeroize` on drop. Plaintext keys written to `~/.ssh/keys/` are restricted to `0600`. | If client machine is compromised at runtime, an attacker with root/user privileges can inspect memory or read `~/.ssh/keys/`. Zero-knowledge cannot defend against an attacker owning the execution endpoint. |
| **Path Traversal / Hostile Identifiers** | Malicious slug or identity ID contains `../` or invalid path characters. | Strict identifier grammar enforced on client and server: `^[a-zA-Z0-9_-]{1,64}$`. Path resolution verified with canonical containment assertions. Symlinks rejected in managed storage paths. | None. |
| **Concurrent Client Conflict** | Two clients update vault simultaneously. | Strong ETag / revision preconditions (`If-Match` or `expected_revision`). Conflicting updates yield HTTP 409 Conflict. Client prompts user to resolve or sync. | Last-write-wins if client blindly overwrites without checking revision. |
| **Admin Import Breach** | Server administrator attempts to import plaintext SSH key directly on server. | Server CLI explicitly rejects plaintext key import. Only pre-encrypted envelopes are accepted by `sshkmad keys import`. Zero-knowledge is preserved by design. | None. |

---

## 3. Explicit Non-Goals & Limitations

1. **Endpoint Key Protection**: Once `sshkma install` writes private keys to `~/.ssh/keys/` for OpenSSH use, those files are governed by OS permissions (`0600`) and the local environment. A zero-knowledge vault cannot protect keys after they are deployed in plaintext to the filesystem.
2. **Remote SSH Server Revocation**: Calling `sshkma logout` or `sshkma remove` unlinks local keys and revokes daemon sessions. It **does not and cannot** contact third-party remote SSH servers to remove public keys from remote `~/.ssh/authorized_keys`.
3. **Traffic & Metadata Leaks**: Server-visible identifiers are opaque random UUIDs, but cipher lengths correlate with key types (e.g., Ed25519 vs RSA 4096). Traffic timings reveal when sync occurs.
4. **Denial of Service**: A hostile server can always refuse requests, delete records, or return 500 errors.
