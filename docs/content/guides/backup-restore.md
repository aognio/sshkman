+++
title = "Back up and restore"
+++

# Back up and restore

Back up the server storage root, for example `/var/lib/sshkmad`. It contains account metadata, encrypted vault content, devices, and sessions.

Restore by stopping the server, replacing the storage root, and starting the server again. Keep file permissions intact.

Encrypted content remains encrypted at rest. Backups do not provide plaintext access without the client vault password. Old ciphertext in backups remains decryptable by anyone who later obtains the vault password, so protect backups accordingly.
