# TOML and Platform-Native XDG Client Configuration

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Client Paths, Configuration Format

## Context and Problem Statement

`sshkma` runs across Linux, macOS, and Windows. It needs a reliable, human-editable configuration format and deterministic directory resolution adhering to operating system conventions.

## Decision Drivers

* Platform compliance: honor XDG specifications on Linux, native Application Support on macOS, and Known Folders/AppData on Windows.
* Human readability and auditability: TOML configuration format.
* Testability: allow explicit CLI overrides (`--config <path>`) and environment variable overrides for test isolation.

## Considered Options

* Option 1: Hardcoded `~/.sshkma/config.toml` on all operating systems.
* Option 2: Platform-native resolution using XDG Base Directory specification and native OS path adapters.

## Decision Outcome

Chosen option: Option 2 ("Platform-native resolution").

Default client configuration locations:
- Linux / BSD: `${XDG_CONFIG_HOME:-$HOME/.config}/sshkma/config.toml`
- macOS: `~/Library/Application Support/sshkma/config.toml` (or `${XDG_CONFIG_HOME}` if set)
- Windows: `%APPDATA%\sshkma\config.toml`

Schema:
```toml
version = 1

[vault]
url = "https://vault.example.com"
username = "admin"

[auth]
storage = "keyring" # or "toml"

[ssh]
config_dir = "~/.ssh"
managed_dir = "~/.ssh/managed"
keys_dir = "~/.ssh/keys"
```

Permissions:
On Unix systems, client configuration and credential files are validated and created with `0600` permissions, and directories with `0700`.

### Positive Consequences

* Conforms to native OS expectations.
* Simple TOML format permits easy programmatic and manual editing.

### Negative Consequences

* Cross-platform path differences must be normalized in tests using temporary directories.
