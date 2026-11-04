# Dependency Research and API Verification Checkpoint

Date: 2026-11-04  
Status: Verified against Rust 1.94.0 and crates.io  
Author: Principal Engineer & Security Architect

## 1. Verified Dependencies & Security Status

| Crate | Verified Version | Purpose & Rationale | Maintenance & Security Status |
|---|---|---|---|
| `sansio` | `1.0.1` | Sans-I/O protocol abstraction (`Protocol<Rin, Win, Ein>`). | Active; maintained by WebRTC-rs organization (Apache-2.0 / MIT). Clean trait without unsafe. |
| `clap` | `4.6.7` (with `derive`, `env`, `cargo`) | CLI argument parsing for `sshkma` and `sshkmad`. | De-facto standard CLI parser in Rust; active, strictly maintained. |
| `axum` | `0.8.9` (with `tokio`, `json`, `tower-log`) | HTTP API server daemon. | Official Tokio web framework; active, high ergonomics, standard for production services. |
| `tokio` | `1.54.1` (with `full`) | Async runtime for server and async client tasks. | Industry standard async runtime; maintained, stable. |
| `reqwest` | `0.12.12` (with `json`) | HTTP client for `sshkma` CLI communicating with `sshkmad`. | Standard HTTP client, backed by reqwest/hyper; actively maintained. |
| `serde` / `serde_json` | `1.0.229` (with `derive`) | Serialization/deserialization for API payloads and internal DTOs. | Universally audited Rust standard. |
| `toml` | `0.8.20` | Server and client TOML configuration parsing and serialization. | Actively maintained, safe, zero-unsafe parser. |
| `ssh-key` | `0.6.7` (with `ed25519`, `rsa`, `p256`, `encryption`, `std`) | OpenSSH key decoding/encoding, public key comment preservation, algorithm checks. | Maintained by RustCrypto team; handles RFC 4251/4253 and OpenSSH key formats. |
| `ssh2-config` | `0.9.0` | OpenSSH configuration parser for inspecting existing host configs. | Actively maintained by veeso; parses OpenSSH configuration syntax. |
| `argon2` | `0.6.0` (with `password-hash`, `zeroize`) | Password-based key derivation (Argon2id) for vault KEK and auth hashing. | RustCrypto team; pure Rust implementation of RFC 9106 Argon2id. |
| `chacha20poly1305` | `0.11.0` (with `alloc`, `zeroize`) | AEAD authenticated encryption (XChaCha20-Poly1305 with 24-byte nonces). | RustCrypto AEAD implementation; constant-time Poly1305, audited. |
| `hkdf` | `0.13.0` | HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869). | RustCrypto team; pure Rust, zero unsafe. |
| `sha2` | `0.10.9` | Cryptographic hashing for HKDF and token hashing. | RustCrypto team; audited, standard. |
| `secrecy` | `0.10.3` (with `serde`) | Secret wrapper types (`SecretString`, `SecretBox`) to prevent accidental leaks. | Maintained by iqlusion; automatically wipes memory on drop and suppresses `Debug`. |
| `zeroize` | `1.9.1` (with `derive`) | Memory zeroization primitives ensuring cryptographic keys are cleared. | RustCrypto team; guaranteed compiler-barrier zeroing. |
| `rand` / `rand_core` | `0.8.8` / `0.6.4` (with `std`) | Cryptographically secure random number generation (OsRng). | Standard Rust randomness libraries. |
| `keyring` | `4.2.0` | Cross-platform OS keychain / secret service integration. | Active community project supporting macOS Keychain, Windows Credential Manager, Linux Secret Service (via zbus). |
| `tracing` / `tracing-subscriber` | `0.1.41` / `0.3.19` | Structured logging and diagnostics. | Tokio project standard; fast, zero-allocation span tracking. |
| `fs4` | `1.1.0` (with `sync`) | Cross-platform advisory file locking (`flock` on Unix, `LockFileEx` on Windows). | Modern replacement for `fs2`, pure Rust based on `rustix` (no libc dependency). |
| `proptest` | `1.12.0` | Property-based testing and shrinking for formats, parsers, and envelopes. | Maintained by proptest-rs; robust test generation. |
| `thiserror` | `2.0.21` | Ergonomic domain and crate error definitions. | Standard Rust error derive crate. |
| `tempfile` | `3.17.1` | Ephemeral test fixtures and safe atomic file replacement staging. | Actively maintained, safe atomic file replacement support. |

---

## 2. Study of Sans-I/O Architecture & `sansio::Protocol`

### 2.1 The `sansio::Protocol` Trait

Inspection of `sansio = "1.0.1"` reveals the following core trait signature:

```rust
pub trait Protocol<Rin, Win, Ein> {
    type Rout;
    type Wout;
    type Eout;
    type Error;
    type Time;

    // Inbound processing
    fn handle_read(&mut self, msg: Rin) -> Result<(), Self::Error>;
    fn poll_read(&mut self) -> Option<Self::Rout>;

    // Outbound processing
    fn handle_write(&mut self, msg: Win) -> Result<(), Self::Error>;
    fn poll_write(&mut self) -> Option<Self::Wout>;

    // Event & lifecycle hooks
    fn handle_event(&mut self, _evt: Ein) -> Result<(), Self::Error>;
    fn poll_event(&mut self) -> Option<Self::Eout>;
    fn handle_timeout(&mut self, _now: Self::Time) -> Result<(), Self::Error>;
    fn poll_timeout(&mut self) -> Option<Self::Time>;
    fn close(&mut self) -> Result<(), Self::Error>;
}
```

### 2.2 Application Mapping for `sshkma`

In network tunnel protocols (such as Firezone's `sanstun`), `Rin` is incoming UDP/IP packets, `Rout` is decrypted TUN packets, `Win` is plaintext TUN writes, and `Wout` is encrypted UDP writes.

For `sshkma`'s client orchestration engine:
1. **Commands as `Ein` (Input Events)**: User intent (`Command::Login`, `Command::Unlock`, `Command::ImportKey`, `Command::Install`, `Command::Sync`).
2. **Effects as `Wout` (Poll Write / Outbound Effects)**: Pure state machines do not execute HTTP requests or write to disk. Instead, `poll_write()` emits typed `Effect` descriptors (e.g., `Effect::SendHttpRequest`, `Effect::WriteManagedFile`, `Effect::StoreKeyringToken`).
3. **Effect Results as `Rin` (Handle Read / Inbound Responses)**: Results from executed effects (e.g., `EffectResult::HttpResponse`, `EffectResult::FileReadSuccess`) enter the engine via `handle_read()`.
4. **Domain Events as `Eout` (Poll Event / Outbound Domain Events)**: Completed state transitions emit immutable facts via `poll_event()` (e.g., `ClientEvent::Authenticated`, `ClientEvent::VaultUnlocked`, `ClientEvent::IdentityInstalled`).
5. **Time as `Time`**: Synthetic or system timestamps (`std::time::Instant` or `SystemTime`) passed to `handle_timeout()` to drive token expiry and state timeouts without direct OS clock syscalls in the core.

### 2.3 Non-Shoehorned State Machines

As mandated by Section 0 and Section 1, pure helpers and self-contained transition machines (such as the Vault envelope unlocker, installation planner, and OpenSSH config patcher) are implemented as simple functional transformers (`State + Event -> (NextState, Vec<Effect>)`) without forcing unnecessary `Protocol` boilerplates where streaming I/O is not involved. An adapter implements `sansio::Protocol` at the orchestrator boundary.

---

## 3. Cryptographic Design Checkpoint

### 3.1 Vault Master Key (VMK) & KEK Derivation
- **VMK**: 256 bits (32 bytes) of CSPRNG entropy generated on client during vault initialization (`OsRng`).
- **Argon2id Parameters**:
  - `m_cost`: 19456 KiB (19 MiB default for fast verification, 65536 KiB in high-security mode)
  - `t_cost`: 2 iterations
  - `p_cost`: 1 lane
  - `salt`: 16 bytes unique random CSPRNG per vault/rewrap
  - Output: 32 bytes (256-bit KEK).
- **Wrapped VMK**:
  - Encrypted with `XChaCha20-Poly1305` using 24-byte random nonce.
  - Associated Authenticated Data (AAD): `sshkma:vmk:wrap:v1:<user_id>`.

### 3.2 Age Crate Compatibility Verification
Inspection confirms that the `age` crate password encryption implements the standard Age specification using `scrypt` as its KDF, *not* Argon2id. Therefore, adopting `age` for password-encrypted vaults would violate the Argon2id requirement or mislead regarding KDF choice. We select a native, audited `Argon2id + XChaCha20-Poly1305` authenticated envelope format, formally specified in ADR 0005.

### 3.3 Recovery Secret Flow
- Recovery secret: 32 bytes high-entropy secret, rendered in Bech32 / Base64 format with checksum.
- Recovery KEK derived via HKDF-SHA256 (or Argon2id with unique recovery salt).
- Secondary wrapped VMK envelope stored alongside primary wrapped VMK.
- Re-wrapping the VMK on password change requires only re-encrypting the VMK with the new KEK; identity records remain untouched.

### 3.4 OpenSSH Keypair Preservation
- Original private key bytes and original `.pub` bytes are retained verbatim.
- Key material is validated using `ssh-key` (confirming algorithm and public key consistency), but the exact byte streams (including comments, formatting, and line endings) are encrypted into the vault payload.
