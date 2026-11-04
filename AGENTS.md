# Agent Developer Guidelines & Operational Conventions

This repository contains `sshkma` (client) and `sshkmad` (server), a zero-knowledge SSH identity vault and OpenSSH provisioning system in Rust.

## Core Non-Negotiable Rules

1. **Zero-Knowledge Invariant**:
   - The server must NEVER receive:
     - Plaintext SSH private keys
     - Plaintext vault passwords
     - Unwrapped Vault Master Keys (VMK)
     - Plaintext identity records, slugs, hostnames, or usernames.
   - Any server-host import must accept ONLY pre-encrypted authenticated envelopes. Plaintext import on the server host is forbidden.

2. **Prohibition on Logging Secrets**:
   - Never log passwords, tokens, private keys, VMKs, KEKs, decrypted identity payloads, or Authorization headers.
   - All secret-bearing types must use `secrecy::Secret` or `zeroize::Zeroize` and must not print secrets in `Debug` or `Display`.
   - Logfmt logging must escape key-value pairs and redact sensitive fields.

3. **Exact Keypair Byte Preservation**:
   - Original SSH private key bytes and `.pub` key bytes must be preserved verbatim (including comments, whitespace, and formatting).

4. **Persistence Rules**:
   - Filesystem-only persistence under `/var/lib/sshkmad` (server) and XDG paths (client).
   - Absolutely NO SQLite or SQL engines.
   - All file writes must be atomic: write to a temporary file in the target directory, fsync, and atomic rename.
   - Advisory file locks (`fs4`) must protect concurrent file mutations.

5. **OpenSSH Configuration Safety**:
   - Never overwrite arbitrary user `~/.ssh/config` blocks.
   - Use managed include blocks (`Include ~/.ssh/managed/*.conf`) bounded by comment sentinels.
   - Write per-identity config to `~/.ssh/managed/<slug>.conf` and keys to `~/.ssh/keys/<slug>`.

---

## Verification Commands

Run before committing any code:

```bash
# Code formatting check
make fmt
# or: cargo fmt --all --check

# Strict clippy linter
make lint
# or: cargo clippy --workspace --all-targets -- -D warnings

# Run all unit, property, and integration tests
make test
# or: cargo test --workspace

# Full verification suite
make check
```

---

## Devnotes / Engineering Memory

This repository uses the `.development/` Engineering Memory System.
- Main project repository is on branch `wip`.
- Engineering memory is on branch `main` inside the `.development/` independent git repository.
- Record findings, investigations, and status progressively in `.development/` as work occurs.
