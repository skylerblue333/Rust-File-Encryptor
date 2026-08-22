# Rust File Encryptor

A small, local command-line utility for authenticated file encryption and decryption using AES-256-GCM. It is a focused security component, not a complete key-management or enterprise-custody product.

## Implemented behavior

The binary supports `encrypt` and `decrypt` commands, generates a fresh 96-bit nonce for every encryption, authenticates ciphertext during decryption, rejects tampered or truncated files, refuses to overwrite an existing output, and requires a 32-byte key supplied through the `FILE_ENCRYPTOR_KEY` environment variable as 64 hexadecimal characters.

```bash
export FILE_ENCRYPTOR_KEY=0000000000000000000000000000000000000000000000000000000000000000
cargo run -- encrypt input.txt output.enc
cargo run -- decrypt output.enc recovered.txt
```

## Validation

```bash
cargo test
cargo build --release
```

The test suite covers byte-preserving round trips, tamper detection, and key-format validation. The release build has been compiled successfully in the current audit environment.

## Scope and limitations

The utility does not provide password-based key derivation, a hardware-backed keystore, key rotation, secure deletion, streaming encryption for very large files, metadata authentication beyond the ciphertext, or a production key-management service. Environment variables can be exposed by misconfigured process tooling; production deployments should use an approved secret manager. Do not treat this repository as proof of compliance or audited cryptographic security.

The previous “professional-grade,” “scalable,” and “cloud-native” claims were removed because the implementation is intentionally small and local.

## Dependency provenance

The cryptographic implementation uses the `aes-gcm` Rust crate from crates.io under its published license. No source code was copied from an external repository for this upgrade.
