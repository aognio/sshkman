# sshkma & sshkmad

A self-hosted, zero-knowledge SSH identity vault and OpenSSH provisioning system in Rust.

`sshkma` is the client CLI. `sshkmad` is the server daemon and administrative CLI. Persistence is filesystem-only (no SQLite), and the server never receives plaintext SSH private keys, vault passwords, unwrapped VMKs, or plaintext identity records.

## Quick Start

### Server

```bash
sshkmad init
sshkmad config check
sshkmad users add --username alice --password 'change-me'
sshkmad serve
```

Default config path: `/etc/sshkma/sshkmad.toml`. Override with `--config PATH`.

Example server config:

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

### Client

Default client config: `${XDG_CONFIG_HOME:-$HOME/.config}/sshkma/config.toml`.

```bash
sshkma login https://vault.example.com --username alice
sshkma unlock
sshkma keys add prod --private ~/.ssh/id_ed25519 --public ~/.ssh/id_ed25519.pub --host prod --hostname 10.0.0.1 --user ubuntu --port 22
sshkma install prod
sshkma sync
sshkma logout
```

Client config example:

```toml
version = 1

[vault]
url = "https://vault.example.com"
username = "alice"

[auth]
storage = "keyring" # or explicitly opted-in "toml"

[ssh]
config_dir = "~/.ssh"
managed_dir = "~/.ssh/managed"
keys_dir = "~/.ssh/keys"
```

## OpenSSH Integration

sshkma never rewrites arbitrary `~/.ssh/config` blocks. It inserts one managed include block:

```text
# BEGIN SSHKMA MANAGED INCLUDES
Include ~/.ssh/managed/*.conf
# END SSHKMA MANAGED INCLUDES
```

Each identity gets `~/.ssh/managed/<slug>.conf` and key material under `~/.ssh/keys/<slug>`.

## Administration

```bash
sshkmad users list
sshkmad users disable alice
sshkmad devices list
sshkmad devices revoke <device-id>
sshkmad sessions list
sshkmad sessions revoke <session-id>
sshkmad keys list
sshkmad keys import <identity-id> --file envelope.enc --user <user-id>
sshkmad stats
sshkmad doctor
```

`keys import` accepts only already-encrypted, authenticated envelope data.

## Bulk Import from SSH Config

Import every concrete `Host` entry in `~/.ssh/config` that has an `IdentityFile` with a matching `.pub`:

```bash
sshkma keys bulk-import --dry-run
sshkma keys bulk-import --glob 'prod-*' --dry-run
sshkma keys bulk-import --glob 'web-?' --yes
```

`--glob` uses shell-style matching (`*` any sequence, `?` single char, case-sensitive). A summary is printed before importing; confirm with `y` or pass `--yes`.

## Vault Environment Variables

- `SSHKMA_PASSWORD`: account password for noninteractive login.
- `SSHKMA_VAULT_PASSWORD`: vault master password.
- `SSHKMA_USER_ID`: opaque user ID for vault operations.

## Development

```bash
make help
make check
make e2e
```

## Documentation

- [Architecture Decision Records](docs/adr/README.md)
- [Threat Model](docs/security/threat-model.md)
- [Dependency Research](docs/research.md)
- [Agent Guidelines](AGENTS.md)
