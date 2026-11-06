+++
title = "Client commands"
+++

# Client commands

```text
sshkma login <url> [--username <name>]
sshkma logout [--all-devices]
sshkma unlock
sshkma lock
sshkma status
sshkma list
sshkma keys add <slug> --private <path> --public <path> [--host <alias>] [--hostname <name>] [--user <name>] [--port <port>]
sshkma keys show <slug>
sshkma keys bulk-import [--config <path>] [--glob <pattern>] [--dry-run] [--yes]
sshkma keys bulk-remove [--glob <pattern>] [--remote] [--local] [--dry-run] [--yes]
sshkma keys remove <slug> [--remote]
sshkma install <slug> [--dry-run]
sshkma remove <slug> [--dry-run]
sshkma sync [--dry-run]
sshkma config show
sshkma config check
sshkma doctor
sshkma version
```

`keys remove` deletes from the server vault only with `--remote`. `remove` uninstalls local managed files only.


`bulk-import` scans the SSH config for concrete `Host` entries (no wildcards in the alias) that have an `IdentityFile` with a sibling `.pub`. `--glob` filters aliases using shell-style globs: `*` (any sequence), `?` (single char), case-sensitive. Examples:

```bash
sshkma keys bulk-import --dry-run
sshkma keys bulk-import --glob 'prod-*' --dry-run
sshkma keys bulk-import --glob 'web-?' --yes
```
