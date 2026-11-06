+++
title = "Troubleshooting"
+++

# Troubleshooting

## Config check fails

Run `sshkmad config check`. Ensure `public_url` is set and `storage.root` exists or can be created.

## Client cannot unlock

Confirm the vault password and user ID. The server cannot recover a vault password. Use the recovery key if the password is lost.

## OpenSSH does not use the managed key

Run `ssh -G <alias>` and check `identityfile`. Ensure `~/.ssh/config` contains the managed include block and that the alias file exists under `~/.ssh/managed`.
