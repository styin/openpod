//! Error types for the agent transport layer.

use thiserror::Error;

/// Errors that can occur in the agent transport.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("endpoint bind failed: {0}")]
    Bind(String),

    #[error("connection accept failed: {0}")]
    Accept(#[from] quinn::ConnectionError),

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

    #[error("quinn connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
}

pub type Result<T> = std::result::Result<T, AgentError>;
