# OpenSSH Managed Include Strategy and File Ownership

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: OpenSSH Configuration, Host Aliases, Managed Directories

## Context and Problem Statement

`sshkma` must configure OpenSSH identities and host configurations locally. Rewriting arbitrary user `~/.ssh/config` files risks destroying custom user directives, comments, indentation, and conditional `Match` blocks. Furthermore, OpenSSH follows a "first-value-wins" directive precedence rule, meaning include order directly affects connection behavior.

## Decision Drivers

* Non-destructive OpenSSH integration: never alter or overwrite user-owned `Host` or `Match` blocks.
* Deterministic precedence: managed includes must appear near the top of `~/.ssh/config` before wildcard `Host *` blocks.
* Idempotent installation and safe cleanup.
* Key isolation: each managed identity has its own `.conf` file and designated keypair path.

## Considered Options

* Option 1: Inline manipulation of `~/.ssh/config` (parsing AST and rewriting whole file).
* Option 2: Standalone separate config file used via `ssh -F`.
* Option 3: Managed Include block in `~/.ssh/config` pointing to `~/.ssh/managed/*.conf`.

## Decision Outcome

Chosen option: Option 3 ("Managed Include block").

### 1. Structure
- Main config insertion: `sshkma` ensures an `Include ~/.ssh/managed/*.conf` directive is present at the top of `~/.ssh/config`, bounded by distinct sentinel markers:
  ```text
  # BEGIN SSHKMA MANAGED INCLUDES - DO NOT EDIT MANUALLY
  Include ~/.ssh/managed/*.conf
  # END SSHKMA MANAGED INCLUDES
  ```
- Individual host files: each installed identity writes its configuration to `~/.ssh/managed/<slug>.conf`.
- Managed key paths: keypairs are written to `~/.ssh/keys/<slug>` (mode `0600`) and `~/.ssh/keys/<slug>.pub` (mode `0644`).

### 2. Managed Host Directive Format
```text
# Managed by sshkma for identity slug: <slug>
Host <host-alias>
    HostName <hostname>
    User <user>
    Port <port>
    IdentityFile ~/.ssh/keys/<slug>
    IdentitiesOnly yes
```

### 3. Safety and Idempotence
- `sshkma install <slug>` checks whether `~/.ssh/managed/<slug>.conf` exists and matches the current vault record fingerprint.
- If an existing file was manually modified by the user, `sshkma` refuses to overwrite without an explicit `--force` flag.
- `sshkma remove <slug>` unlinks `~/.ssh/managed/<slug>.conf` and the associated keypair, but does NOT modify the remote server's authorized keys or other local identities.

### Positive Consequences

* User's existing configuration blocks remain 100% untouched.
* Clean uninstall: removing `sshkma` requires only deleting `~/.ssh/managed/` and removing the sentinel comment block.

### Negative Consequences

* Older OpenSSH versions (< 7.3) do not support the `Include` directive (documented as a prerequisite).
