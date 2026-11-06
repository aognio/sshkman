+++
title = "Synchronize a second client"
+++

# Synchronize a second client

Use this guide when you have imported a key on one machine and want to install it on another.

1. Log in on the second machine with the same account.
2. Unlock the vault with the same vault password.
3. Run `sshkma sync`.
4. Verify with `ssh -G <alias>`.

`sync` fetches every encrypted identity record, decrypts it locally, and applies the installation plan. It does not upload or change server state.

If a managed file was modified locally, review the diff before overwriting it. sshkma does not delete unknown files automatically.
