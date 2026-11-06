+++
title = "Server commands"
+++

# Server commands

```text
sshkmad init [--config <path>]
sshkmad serve [--config <path>]
sshkmad config check
sshkmad users add|list|disable
sshkmad devices list|revoke
sshkmad sessions list|revoke
sshkmad keys list|show|remove
sshkmad keys import <opaque-id> --file <encrypted-envelope> --user <user-id>
sshkmad stats
sshkmad doctor
sshkmad version
```

`keys import` accepts only already encrypted, authenticated envelope data.
