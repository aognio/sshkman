# FHS /etc/sshkma/sshkmad.toml Server Configuration

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Server Configuration, FHS Compliance

## Context and Problem Statement

`sshkmad` is a self-hosted daemon running on Linux/Unix servers. It requires a clear default configuration location that follows the Filesystem Hierarchy Standard (FHS) while allowing CLI flag overrides (`--config <path>`) for staging, testing, and containerized deployments.

## Decision Drivers

* FHS compliance: configuration in `/etc/sshkma/`, data in `/var/lib/sshkmad/`, logs in `/var/log/sshkmad/`.
* Security: safe default binding to `127.0.0.1` behind reverse proxy, mandatory TLS public URL enforcement.
* Redaction: server config must not display or log sensitive keys.

## Considered Options

* Option 1: In-tree configuration relative to binary location.
* Option 2: Environment variables only.
* Option 3: FHS `/etc/sshkma/sshkmad.toml` with CLI flag override and environment variable expansion.

## Decision Outcome

Chosen option: Option 3 ("FHS /etc/sshkma/sshkmad.toml").

Default path: `/etc/sshkma/sshkmad.toml`.
Override: `sshkmad serve --config /path/to/custom.toml`.

Standard configuration layout:
```toml
[server]
hostname = "vault.example.com"
listen_address = "127.0.0.1"
port = 8080
public_url = "https://vault.example.com"

[storage]
root = "/var/lib/sshkmad"

[auth]
access_ttl = "15m"
refresh_ttl = "720h"
secret_file = "/etc/sshkma/secrets/session.key"

[logging]
level = "info"
format = "logfmt"
file = "/var/log/sshkmad/sshkmad.log"
security_file = "/var/log/sshkmad/security.log"
rotation = "daily"
retention_days = 30

[security]
require_https = true
max_login_attempts = 5
```

Security enforcement:
- Daemon defaults to `127.0.0.1:8080` to prevent accidental public internet exposure without a TLS reverse proxy.
- Rejects binding if `require_https = true` and `public_url` starts with `http://` (unless hostname is `localhost` or `127.0.0.1`).

### Positive Consequences

* Clean, standard deployment model for systemd services and container runtimes.
* Pre-flight configuration validation fails fast before opening sockets.

### Negative Consequences

* Running without root requires `--config` pointing to user-owned path.
