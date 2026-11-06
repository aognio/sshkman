+++
title = "Logging"
+++

# Logging

The server emits structured logfmt. Logs include event names, request identifiers, results, and latency. Secret material is redacted.

Log files rotate daily and retain 30 days by default. Adjust `retention_days` in the server config. Logs are operational records, not an event store.
