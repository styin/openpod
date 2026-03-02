//! Error types and error code constants for the OpenPod protocol.
//!
//! Wire-format errors use the protobuf `Error` message (see [`crate::wire`]).
//! This module defines the Rust-native error types for use within crate
//! boundaries, plus the numeric error code constants from Manifesto §2.10.

use thiserror::Error;

/// Errors that can occur within the `pod-proto` crate.
#[derive(Debug, Error)]
pub enum ProtoError {
    // --- Identity ---
    #[error("failed to generate Ed25519 keypair: {0}")]
    KeyGeneration(String),

    #[error("invalid Ed25519 key bytes: {0}")]
    InvalidKeyBytes(String),

    #[error("failed to generate X.509 certificate: {0}")]
    CertificateGeneration(String),

    #[error("certificate has expired")]
    CertificateExpired,

    // --- PodId ---
    #[error("invalid PodId format: {0}")]
    InvalidPodId(String),

    #[error("PodId Luhn check digit mismatch")]
    PodIdChecksumMismatch,

    // --- SAS ---
    #[error("SAS derivation failed: {0}")]
    SasDerivation(String),

    // --- TLS / Verification ---
    #[error("certificate verification failed: {0}")]
    CertificateVerification(String),

    #[error("TLS configuration error: {0}")]
    TlsConfiguration(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    // --- I/O ---
    #[error("stream I/O error: {0}")]
    StreamIo(String),

    // --- Trust store ---
    #[error("peer denied by trust store: {0}")]
    PeerDenied(String),

    // --- Serialization ---
    #[error("protobuf encode error: {0}")]
    ProtobufEncode(#[from] prost::EncodeError),

    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),
}

/// Result type alias using [`ProtoError`].
pub type Result<T> = std::result::Result<T, ProtoError>;

// =========================================================================
// Error Code Constants (Manifesto §2.10)
//
// These constants are used when constructing wire-format `Error` messages.
// =========================================================================

/// Transport errors (1xxx): connection lost, timeout, stream reset.
pub mod transport {
    pub const CONNECTION_LOST: u32 = 1001;
    pub const CONNECTION_TIMEOUT: u32 = 1002;
    pub const STREAM_RESET: u32 = 1003;
}

/// Authentication errors (2xxx): cert rejected, pairing failed, PodId denied.
pub mod auth {
    pub const CERT_REJECTED: u32 = 2001;
    pub const PAIRING_FAILED: u32 = 2002;
    pub const POD_ID_DENIED: u32 = 2003;
    pub const POD_ID_REVOKED: u32 = 2004;
}

/// Session errors (3xxx): session not found, cache full.
pub mod session {
    pub const SESSION_NOT_FOUND: u32 = 3001;
    pub const CACHE_FULL: u32 = 3002;
    pub const RESUME_FAILED: u32 = 3003;
}

/// Protocol errors (4xxx): version mismatch, malformed message.
pub mod protocol {
    pub const VERSION_MISMATCH: u32 = 4001;
    pub const MALFORMED_MESSAGE: u32 = 4002;
    pub const UNKNOWN_CHANNEL: u32 = 4003;
    pub const UNEXPECTED_MESSAGE: u32 = 4004;
}

/// Gateway-forwarded errors (5xxx): errors originating from the Agent Gateway.
pub mod gateway {
    pub const GATEWAY_INTERNAL: u32 = 5001;
    pub const GATEWAY_UNAVAILABLE: u32 = 5002;
}
