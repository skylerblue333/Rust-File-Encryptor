# Sky File Crypto

A focused Rust command-line utility for local authenticated file encryption and decryption using AES-256-GCM.

## Product status

Engineering beta. The implementation is intentionally small and local; it is not a key-management platform, HSM/KMS, encrypted filesystem, backup system, compliance product, or production custody service.

## Implemented behavior

- AES-256-GCM authenticated encryption.
- Fresh 96-bit random nonce for every encryption.
- Versioned `SKYENC01` ciphertext envelope so unsupported formats fail closed.
- Authentication failure on tampered ciphertext or the wrong key.
- Exactly 32 bytes of key material supplied as 64 hexadecimal characters through `FILE_ENCRYPTOR_KEY`.
- Regular-file validation and a 64 MiB input ceiling to bound memory use.
- Exclusive output creation: existing output files are never overwritten.
- Failed writes are cleaned up rather than leaving a partial output.

```bash
export FILE_ENCRYPTOR_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
cargo run --release -- encrypt input.txt output.skyenc
cargo run --release -- decrypt output.skyenc recovered.txt
```

## Verification

The GitHub Actions gate runs Rust formatting, Clippy with warnings denied, locked tests, `cargo audit`, a release build, a real CLI encrypt/decrypt round trip, a container build, non-root verification, and a containerized round trip.

Local equivalents:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo audit
cargo build --locked --release
```

## Security boundaries

This utility does **not** implement password-based key derivation, key generation/custody, key rotation, secure deletion, streaming/chunked encryption for large files, filesystem metadata encryption, multi-recipient envelopes, digital signatures, access control, remote APIs, durable audit logs, or hardware-backed key storage. Environment variables can be exposed by incorrectly configured process/container tooling, so production key custody should use an independently reviewed secret-management design.

The 64 MiB ceiling is a deliberate engineering-beta bound because encryption/decryption currently reads the complete file into memory. AES-GCM authentication protects the encrypted payload and envelope-integrated nonce, but this repository has not undergone an independent cryptographic or security audit.

## Dependency provenance

Cryptography is provided by the RustCrypto `aes-gcm` crate declared in `Cargo.toml` and pinned through `Cargo.lock`. No external repository source was copied into this productization branch.
