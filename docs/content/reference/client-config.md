+++
title = "Client configuration"
+++

# Client configuration

Default path: `${XDG_CONFIG_HOME:-$HOME/.config}/sshkma/config.toml`.

```toml
version = 1

[vault]
url = "https://vault.example.com"
username = "example"

[auth]
storage = "keyring" # or explicitly opted-in "toml"

[ssh]
config_dir = "~/.ssh"
managed_dir = "~/.ssh/managed"
keys_dir = "~/.ssh/keys"
```

`storage = "toml"` stores a revocable credential in the config directory with restrictive permissions. It never stores a raw vault password or vault master key.
