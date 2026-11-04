# High-Entropy Recovery Keys, Device Revocation, and Security Limitations

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Key Recovery, Device Revocation, Security Boundaries

## Context and Problem Statement

If a user forgets their vault master password, zero-knowledge storage means the server cannot recover the data. An emergency recovery secret is necessary to avoid permanent data loss.

Simultaneously, when a client device is retired or stolen, the user must be able to revoke that device's sessions immediately. We must specify the recovery key architecture, revocation lifecycle, and delineate the security boundaries between device revocation and SSH key revocation.

## Decision Drivers

* Resilience against password loss: user can restore VMK with high-entropy recovery secret.
* Instant revocation: compromised devices must be disconnected immediately.
* Clarity on boundaries: revoking an API session does NOT revoke SSH public keys installed on remote target servers.

## Considered Options

* Option 1: Server-escrowed master key (Violates zero-knowledge).
* Option 2: Split-secret Shamir threshold (Overly complex for single-tenant vault).
* Option 3: Local high-entropy recovery secret wrapping the VMK, plus server-side device and token revocation tables.

## Decision Outcome

Chosen option: Option 3 ("Dual-wrapping with Local Recovery Secret and Server Device Revocation").

### 1. Recovery Key Workflow
1. At vault creation, the client generates 256 bits of CSPRNG entropy as the `Recovery Secret`.
2. The recovery secret is formatted as a 64-character hex string (or Crockford Base32 with checksum).
3. The client derives a Recovery KEK using HKDF-SHA256 (or Argon2id with unique recovery salt) and wraps the identical VMK.
4. The wrapped recovery envelope is uploaded to the server alongside the standard wrapped VMK.
5. The CLI displays the recovery secret to the user exactly once and requires explicit acknowledgment before proceeding.
6. When recovering, the user enters the recovery secret, unwraps the VMK, enters a new master password, and re-wraps the VMK with a new KEK.

### 2. Device and Session Revocation
- Devices are registered with unique `device_id` and friendly name upon login.
- `sshkma logout`:
  - Remote request: `POST /api/v1/auth/logout` invalidates current session token.
  - Local cleanup: Deletes local session tokens from keyring/config.
  - Leaves installed SSH keys intact in `~/.ssh/keys/` and `~/.ssh/managed/` so ongoing terminal SSH sessions are not disrupted.
- `sshkma logout --all-devices`: Revokes all active sessions for the user account on the server.
- `sshkmad devices revoke <device-id>`: Admin command marking device revoked; immediately rejects any incoming access/refresh requests from that device.

### 3. Clear Security Boundary Notice
- Device revocation terminates access to the `sshkmad` server and prevents future vault syncs.
- Device revocation **does not remove** already-copied public keys from remote servers' `~/.ssh/authorized_keys`.
- To completely revoke remote SSH access, the user must remove the key from target servers or run `sshkmad keys remove <slug>` to rotate credentials.

### Positive Consequences

* Self-service recovery without compromising the zero-knowledge guarantee.
* Centralized device de-authorization.

### Negative Consequences

* If a user loses both their vault password and their recovery secret, all vault data is permanently unrecoverable.
