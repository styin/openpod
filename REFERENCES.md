# OpenPod — Open-Source References

This file tracks all external open-source code, libraries, and algorithm references used in OpenPod.
**Continuously maintained** — update whenever borrowing code or adding dependencies for security-sensitive functionality.

## Direct Dependencies (Security-Sensitive)

| Component | Library | License | Source | What We Use |
|-----------|---------|---------|--------|-------------|
| Ed25519 keypair | `ed25519-dalek` | MIT/Apache-2.0 | [dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | `SigningKey::generate()`, PKCS#8 export for X.509 cert generation |
| X.509 cert generation | `rcgen` | MIT/Apache-2.0 | [rustls/rcgen](https://github.com/rustls/rcgen) | `CertificateParams::self_signed()` with `PKCS_ED25519` algorithm |
| SHA-256 (PodId derivation) | `sha2` | MIT/Apache-2.0 | [RustCrypto/hashes](https://github.com/RustCrypto/hashes) | `Sha256::digest()` for PodId = SHA-256(public key) |
| HMAC-SHA256 (SAS derivation) | `hmac` + `sha2` | MIT/Apache-2.0 | [RustCrypto/MACs](https://github.com/RustCrypto/MACs) | SAS = truncate(HMAC-SHA256(TLS exporter, randoms)) |
| Base32 encoding (PodId display) | `data-encoding` | MIT/Apache-2.0 | [docs.rs/data-encoding](https://docs.rs/data-encoding/) | `BASE32_NOPAD` for PodId human-readable format |
| QUIC transport | `quinn` 0.11 | MIT/Apache-2.0 | [quinn-rs/quinn](https://github.com/quinn-rs/quinn) | Server/client QUIC endpoints, mTLS, stream I/O, `export_keying_material()` for SAS |
| TLS configuration | `rustls` 0.23 | MIT/Apache-2.0 | [rustls/rustls](https://github.com/rustls/rustls) | Custom `ServerCertVerifier`/`ClientCertVerifier` for TOFU trust model |
| X.509 DER parsing | `x509-parser` 0.16 | MIT/Apache-2.0 | [rusticata/x509-parser](https://github.com/rusticata/x509-parser) | Extract Ed25519 public key from peer certificate after TLS handshake |
| Structured logging | `tracing` 0.1 | MIT | [tokio-rs/tracing](https://github.com/tokio-rs/tracing) | Per Manifesto §2.12 — structured fields (session_id, pod_id) |

## Algorithm References

| Algorithm | Reference | License | Notes |
|-----------|-----------|---------|-------|
| Luhn mod-32 check digits | [Syncthing device ID docs](https://docs.syncthing.net/dev/device-ids.html) | MPL-2.0 (Go) | Algorithm pattern only — no code copied. Rust implementation written from the public algorithm description. |
| TOFU + SAS pairing model | [Syncthing device discovery](https://docs.syncthing.net/), [iroh endpoint auth](https://github.com/n0-computer/iroh) | Various | Informed the pairing ceremony design (§2.7.3). |

## Design Pattern References

| Pattern | Project | License | What We Learned |
|---------|---------|---------|-----------------|
| Ed25519 as node identity | [iroh](https://github.com/n0-computer/iroh) | MIT/Apache-2.0 | NodeId = Ed25519 public key. Persistent keypair, ephemeral TLS certs. |
| SHA-256 peer identity | [libp2p](https://github.com/libp2p/rust-libp2p/tree/master/identity) | MIT/Apache-2.0 | PeerId = SHA-256(public key). Multihash encoding. |
| Keypair persistence | [libp2p-identity](https://docs.rs/libp2p-identity/latest/libp2p_identity/ed25519/struct.Keypair.html) | MIT/Apache-2.0 | `to_bytes()`/`from_bytes()` pattern for secret key serialization. |
| Custom TLS verifiers for P2P | [iroh](https://github.com/n0-computer/iroh), [libp2p-tls](https://github.com/libp2p/rust-libp2p/tree/master/transports/tls) | MIT/Apache-2.0 | Informed custom rustls verifier design: extract pubkey from self-signed cert, verify PodId against trust store. |
| Raw QUIC over WebTransport | [iroh](https://github.com/n0-computer/iroh) | MIT/Apache-2.0 | Validated approach: raw QUIC via quinn (no HTTP/3 framing) for focused transport. iroh moved from libp2p to quinn for same reasons. |
