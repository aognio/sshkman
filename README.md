# sshkma & sshkmad

A production-minded, self-hosted, zero-knowledge SSH identity vault and OpenSSH provisioning system in Rust.

## Architecture

- `sshkma`: Cross-platform client CLI for authentication, vault unlocking, importing original SSH public/private key pairs, listing, installing, editing, updating, and removing locally managed OpenSSH identities.
- `sshkmad`: Single server executable with `serve` and administrative CLI subcommands, backed entirely by a file-based store (`/var/lib/sshkmad`).

### Key Invariants
- **Zero Knowledge**: The server never receives raw SSH private keys, plaintext vault passwords, unwrapped vault master keys, or plaintext identity records over the network.
- **Key Preservation**: Verbatim byte preservation of original private keys and `.pub` keys (including comments and formatting).
- **Filesystem-Only**: No SQLite or SQL databases; atomic file updates with fsync and cross-platform advisory locking (`fs4`).
- **OpenSSH Compatibility**: Non-destructive integration via managed include directives (`Include ~/.ssh/managed/*.conf`).
- **Logfmt Structured Logging**: Operational and security logs in key=value logfmt format with mandatory secret redaction.

## Building & Verification

```bash
# Check formatting
make fmt

# Strict clippy linting
make lint

# Run all tests
make test
```

## Documentation

- [Architecture Decision Records (MADRs)](docs/adr/README.md)
- [Threat Model](docs/security/threat-model.md)
- [Dependency Research & APIs](docs/research.md)
- [Agent Guidelines](AGENTS.md)
