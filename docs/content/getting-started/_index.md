+++
title = "Getting started"
+++

# Getting started

This tutorial builds one complete flow: initialize a server, create an account, log in from a client, import an SSH keypair, and install it into OpenSSH. The commands use local paths so you can run them without a production deployment.

## Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)
- `ssh` and `ssh-keygen` available for validation
- A temporary directory for server storage

## Initialize the server

```bash
sshkmad init --config /tmp/sshkman/server.toml
```

Edit the generated config so the storage root points at a writable directory:

```toml
[storage]
root = "/tmp/sshkman/data"
```

Validate the config:

```bash
sshkmad --config /tmp/sshkman/server.toml config check
```

## Create an account

```bash
sshkmad --config /tmp/sshkman/server.toml users add \
  --username alice \
  --password 'replace-with-a-strong-password'
```

## Start the server

```bash
sshkmad --config /tmp/sshkman/server.toml serve
```

The default listen address is `127.0.0.1:8080`.

## Configure the client

Create a client config:

```toml
version = 1

[vault]
url = "http://127.0.0.1:8080"
username = "alice"

[auth]
storage = "toml"

[ssh]
config_dir = "~/.ssh"
managed_dir = "~/.ssh/managed"
keys_dir = "~/.ssh/keys"
```

Save it under `${XDG_CONFIG_HOME:-$HOME/.config}/sshkma/config.toml`.

## Log in

```bash
SSHKMA_PASSWORD='replace-with-a-strong-password' \
  sshkma login http://127.0.0.1:8080 --username alice
```

The client stores a revocable session token. It never stores the vault password.

## Unlock the vault

```bash
SSHKMA_VAULT_PASSWORD='vault-master-password' sshkma unlock
```

On first use, create the vault through the client flow before unlocking. The vault password stays on the client.

## Import a keypair

```bash
sshkma keys add prod \
  --private ~/.ssh/id_ed25519 \
  --public ~/.ssh/id_ed25519.pub \
  --host prod \
  --hostname 10.0.0.1 \
  --user ubuntu \
  --port 22
```

The client validates that the private and public key material match, then encrypts the original bytes locally before upload.

## Install into OpenSSH

```bash
sshkma install prod
```

This writes `~/.ssh/managed/prod.conf`, `~/.ssh/keys/prod`, and `~/.ssh/keys/prod.pub`, and ensures the managed include block exists in `~/.ssh/config`.

## Verify

```bash
ssh -G prod | grep -E 'hostname|user|port|identityfile'
```

The original private key bytes are preserved verbatim, including comments and formatting.
