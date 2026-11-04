# Structured Logfmt Logging and Mandatory Secret Redaction

* Status: accepted
* Date: 2026-11-04
* Deciders: Principal Engineer & Security Architect
* Scope: Operational & Security Logging, Secret Redaction

## Context and Problem Statement

Security and operational logs are essential for auditing access, rate limiting, and incident response. However, JSON logs are overly verbose for terminal reading, and unstructured logs are difficult to parse in log aggregators. Most importantly, secrets (passwords, tokens, private keys, plaintext hostnames) must never leak into log files.

## Decision Drivers

* Strict prohibition against logging secret material, raw authorization tokens, or decrypted keys.
* Structured format readable by humans and machines: `logfmt` (`key=value` with quoting/escaping).
* Performance and zero-copy string formatting via `tracing`.

## Considered Options

* Option 1: Standard JSON logging (`tracing-subscriber::fmt::json`).
* Option 2: Human-formatted plain text console logging.
* Option 3: Dedicated Logfmt Formatter for `tracing` with built-in redaction filters.

## Decision Outcome

Chosen option: Option 3 ("Logfmt Formatter with Redaction").

Output format example:
```text
timestamp=2026-11-04T08:00:00Z level=INFO event=auth.login user_id="usr_01" device_id="dev_01" result=success request_id="req_981a"
```

Redaction rules:
1. All secret fields (`password`, `token`, `key`, `private_key`, `secret`, `vmk`, `kek`) are wrapped in `secrecy::Secret` or explicitly marked `[REDACTED]`.
2. Error types implement custom `Display` and `Debug` ensuring that internal crypto buffers or raw authentication payloads cannot be dumped by `?` formatters.
3. Plaintext hostnames and key comments from inside decrypted records are never logged in daemon or security logs.
4. HTTP authorization headers are redacted in all tracing spans.

### Positive Consequences

* Machine-parseable logs natively ingestible by Vector, Grafana Loki, and fluentbit without regex parsing.
* Guaranteed secret safety even during high-verbosity debug traces.

### Negative Consequences

* Requires custom `tracing_subscriber::FormatEvent` implementation to ensure strict logfmt escaping.
