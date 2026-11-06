+++
title = "Use a recovery key"
+++

# Use a recovery key

The recovery key is generated locally when the vault is created. Store it offline. It provides an independent wrapping of the vault master key.

To recover access after losing the vault password:

1. Obtain the wrapped vault key from the server.
2. Run the recovery flow with the recovery key.
3. Set a new vault password and rewrap the vault master key.

The server never learns the recovery key or the vault master key. Keep the recovery key secret; anyone who has it can unwrap the vault master key.
