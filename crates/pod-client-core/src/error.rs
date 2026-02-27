//! Error types for the client transport layer.

use thiserror::Error;

/// Errors that can occur in the client transport.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("endpoint creation failed: {0}")]
    Endpoint(String),

    #[error("connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("failed to extract peer identity: {0}")]
    PeerIdentity(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("stream I/O error: {0}")]
    StreamIo(String),

    #[error("protocol error: {0}")]
    Protocol(#[from] pod_proto::error::ProtoError),
}

pub type Result<T> = std::result::Result<T, ClientError>;
