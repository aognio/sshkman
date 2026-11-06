+++
title = "Run behind a reverse proxy"
+++

# Run behind a reverse proxy

Run `sshkmad` on a loopback address and terminate TLS in a reverse proxy.

```toml
[server]
listen_address = "127.0.0.1"
port = 8080
public_url = "https://vault.example.com"
```

Set `require_https = true` in production. Configure the proxy to forward to the loopback listener. Do not trust arbitrary forwarded headers unless the proxy is explicitly trusted.
