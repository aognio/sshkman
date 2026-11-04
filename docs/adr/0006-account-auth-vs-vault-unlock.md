# Account Authentication vs Vault Unlocking and Credential Storage

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Authentication, Session Tokens, Keychain vs TOML

## Context and Problem Statement

A fundamental zero-knowledge security principle requires separating **account authentication** from **vault decryption**. An API access token issued by the server must never grant the server or an eavesdropper the ability to decrypt the vault.

Furthermore, we must define how clients securely persist access and refresh tokens locally, balancing security (OS keyring) with simple non-interactive automation environments (opt-in TOML storage).

## Decision Drivers

* Principle of Least Privilege: authentication access != data decryption capability.
* Token security: short-lived access tokens (15m), rotating refresh tokens (30d) with replay detection.
* Credential storage: prefer OS keyring; allow strictly opted-in TOML file fallback with 0600 permissions.
* Zero plaintext passwords or master keys in persistent configuration files.

## Considered Options

* Option 1: Single master password that authenticates to server and decrypts vault.
* Option 2: Separate auth password and vault password, tokens saved in plain TOML.
* Option 3: Separate auth password and vault password. Short-lived Bearer tokens and rotating refresh tokens. Keyring storage by default; explicit `auth.storage = "toml"` fallback with strict permissions and warning.

## Decision Outcome

Chosen option: Option 3.

### 1. Separation of Passwords
- **Account Password**: Used solely for HTTP API authentication (`POST /api/v1/auth/login`). Server verifies against a salted Argon2id hash stored in `account.toml`. Never used to derive encryption keys.
- **Vault Password**: Known only to the user. Never transmitted over the network. Derives the KEK that unwraps the VMK locally on the client.

### 2. Token Lifecycle
- **Access Token**: Opaque 256-bit CSPRNG token (SHA-256 hashed on server). Expiration: 15 minutes.
- **Refresh Token**: Opaque 256-bit CSPRNG token. Expiration: 30 days. Rotated on every use. Replay detection: if an already-rotated refresh token is presented, the entire token family is revoked immediately.

### 3. Client Storage
- Default: OS Keyring (`keyring` crate) using service name `sshkma:<server-url>`.
- Fallback: Explicitly configured in client `config.toml` via `auth.storage = "toml"`. When enabled, tokens are saved in `${XDG_CONFIG_HOME}/sshkma/credentials.toml` with `0600` permissions. The CLI outputs a prominent warning regarding plaintext token storage.

### Positive Consequences

* Compromise of the server, server database, or client access token does not expose SSH private keys.
* Full support for headless CI/CD environments via explicit TOML token fallback.

### Negative Consequences

* Users must manage two passwords (or store them in a password manager).
