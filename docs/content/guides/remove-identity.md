+++
title = "Remove an installed identity"
+++

# Remove an installed identity

Local removal and remote removal are different operations.

- `sshkma remove <slug>` removes local managed files only. It does not revoke remote access.
- `sshkma keys remove <slug> --remote` deletes the encrypted identity from the server vault.

To remove an identity completely:

1. Run `sshkma remove <slug>` on every client that installed it.
2. Run `sshkma keys remove <slug> --remote` once.
3. Remove the public key from any remote SSH server `authorized_keys` files where it was authorized.

Removing a vault identity does not remove SSH authorization on remote servers.
