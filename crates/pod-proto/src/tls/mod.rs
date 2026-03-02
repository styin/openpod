//! TLS configuration for QUIC mTLS connections.
//!
//! Provides shared TLS primitives used by both `pod-agent-core` and
//! `pod-client-core`:
//!
//! - Certificate key extraction (Ed25519 public key from X.509 DER)
//! - Custom rustls verifiers (TOFU trust model)
//! - TLS config builders (server and client)

pub mod cert_extract;
pub mod config;
pub mod verifier;
