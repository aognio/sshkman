+++
title = "Server configuration"
+++

# Server configuration

Default path: `/etc/sshkma/sshkmad.toml`. Override with `--config PATH`.

See the example in the README. The server validates configuration before binding a socket. `public_url` must be non-empty. When `require_https` is true, an HTTP public URL is rejected except for localhost.
