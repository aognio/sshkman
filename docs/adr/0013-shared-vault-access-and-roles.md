# Shared Vault Access, Roles, and Grant-Based Key Distribution

* Status: proposed
* Date: 2026-11-06
* Deciders: Principal Engineer & Security Architect
* Scope: Multi-user shared vaults, authorization, zero-knowledge preservation

## Context and Problem Statement

Today each account owns an isolated vault: the VMK is wrapped only by that account's KEK and recovery key, and identities are encrypted with per-record keys derived from that VMK. There is no notion of roles or sharing, so a "regular user" cannot consume keys an administrator provisions without receiving the admin's vault password (which would violate zero-knowledge and credential separation).

We want administrators to provision identities into a vault and grant selected users read/install access without exposing plaintext keys, VMKs, or passwords to the server or to other users.

## Decision Drivers

* Preserve the zero-knowledge invariant: the server must never receive plaintext keys, VMKs, vault passwords, or private grantee keys.
* Do not share passwords between users; each user keeps an independent account password and vault password.
* Support at least two roles: `admin` (provision, grant, revoke) and `reader` (download + install only).
* Allow revocation without re-encrypting every identity where practical.
* Keep storage filesystem-only, atomic, and lock-protected.

## Considered Options

* Option 1: Share the admin's vault password out-of-band so grantees unlock the same VMK.
* Option 2: Server-side re-encryption of identities for each grantee.
* Option 3: Client-side VMK wrapping to a grantee asymmetric public key, with grant records and role enforcement.

## Decision Outcome

Chosen option: Option 3.

### Role model

* `AccountRecord` gains `role: Role` where `Role ∈ {Admin, Reader}` (default `Admin` for the account creator; new accounts default `Reader` unless created by an admin with `--role`).
* `Reader` accounts may authenticate, download identities/manifest, and install locally.
* `Reader` accounts may NOT upload, delete, or modify identities, or create/revoke grants.
* `Admin` accounts retain full control of their vault and may grant access to readers.

### Sharing mechanism (VMK level)

1. The grantee generates a local asymmetric keypair (X25519) on first use and stores the private key in the OS keyring (or TOML fallback with warning). The public key is registered with the server as part of the account profile (public material only).
2. An admin client, holding the unwrapped VMK, wraps the VMK to the grantee's public key using an authenticated asymmetric scheme (e.g., X25519 + HKDF + XChaCha20-Poly1305, or an `age` recipient). Associated data binds the grant to `(grantor user id, grantee user id, vault id, grant id)`.
3. The admin uploads a `VaultGrant` record containing: grant id, grantor, grantee, permissions (`read`, `install`), the wrapped VMK envelope, grantee public key fingerprint, creation/expiration timestamps, and a grantor signature over the grant (to prevent server tampering).
4. The server stores the grant under `users/<grantee>/grants/<grant-id>.toml` and enforces that a reader may download identities/manifest only while a valid, non-expired, non-revoked grant exists from an admin who owns the source vault.

### Read path for a grantee

1. Grantee authenticates with their own account password and obtains a session.
2. Grantee client fetches the grant and the wrapped VMK envelope.
3. Grantee client unwraps the VMK using their X25519 private key.
4. Grantee client downloads the (shared) manifest and identity ciphertexts using the shared vault's opaque IDs, decrypts with per-record keys derived from the shared VMK, and installs locally with the existing managed-include flow.

### Revocation

* Revoking a grant deletes the grant record and wrapped VMK; the grantee can no longer fetch new ciphertext.
* For strong revocation (preventing use of previously downloaded keys), the admin rotates the VMK: re-wraps the VMK for all remaining grantees and re-encrypts the manifest. Existing identity ciphertexts remain valid under the old VMK, so the admin should also re-encrypt identities or accept that revoked users retain copies of keys they already downloaded (consistent with the documented limitation that zero-knowledge is not endpoint protection).
* Device/session revocation remains independent and unchanged.

### Server enforcement

* Endpoints gain a permission check: `upload_identity`, `delete_identity`, `put_manifest`, and grant management require `Admin` (or ownership of the source vault).
* `download_identity`, `get_manifest`, and grant fetch require either ownership or a valid grant.
* `stats` counts grants but reveals no plaintext metadata.

### Wire/storage additions

* `AccountRecord.role`
* `VaultGrant` TOML schema under `users/<grantee>/grants/`.
* New endpoints: `POST /api/v1/grants`, `GET /api/v1/grants`, `DELETE /api/v1/grants/{id}`, `GET /api/v1/grants/{id}/wrapped-key`.
* CLI: `sshkmad users set-role`, `sshkma grants create/list/revoke`, `sshkma unlock --grant <id>`.

### Consequences

* Positive: preserves zero-knowledge; no password sharing; readers get install-only access; revocation is explicit.
* Negative: requires asymmetric crypto primitives and grant lifecycle management; VMK rotation is costly; record sizes and access patterns remain observable (existing limitation).
* Risks: grantor signature verification must be implemented carefully; grantee private key loss means loss of shared access (recovery via new grant).

### Validation

* Unit tests for role parsing and grant serialization.
* Crypto tests for VMK wrapping/unwrapping to X25519 recipients.
* HTTP tests for permission enforcement (reader cannot upload/delete/grant).
* E2E test: admin provisions key, grants reader, reader installs, revoke, reader denied.

### References

* ADR-0005 (zero-knowledge envelope encryption)
* ADR-0006 (account auth vs vault unlock)
* ADR-0012 (recovery keys and revocation)
