//! QUIC server endpoint for the agent.
//!
//! `AgentEndpoint` wraps a quinn server endpoint, binding to a local address
//! and accepting incoming connections with mTLS verification.

use std::net::SocketAddr;
use std::sync::Arc;

use pod_proto::identity::{Certificate, Keypair};
use pod_proto::tls::config::build_server_tls_config;
use pod_proto::trust::{TrustPolicy, TrustStore};
use pod_proto::version;
use pod_proto::wire;
use tracing::info;

use crate::connection::PodConnection;
use crate::error::{AgentError, Result};
use crate::stream_io;

/// A QUIC server endpoint that accepts incoming Pod connections.
pub struct AgentEndpoint {
    endpoint: quinn::Endpoint,
}

impl AgentEndpoint {
    /// Bind a QUIC server to the given address.
    ///
    /// Uses the provided identity keypair and certificate for mTLS.
    /// The trust store and policy control which peers are accepted.
    pub fn bind(
        addr: SocketAddr,
        keypair: &Keypair,
        cert: &Certificate,
        trust_store: Arc<dyn TrustStore>,
        policy: TrustPolicy,
    ) -> Result<Self> {
        let rustls_config = build_server_tls_config(keypair, cert, trust_store, policy)?;

        let quic_server_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
                .map_err(|e| AgentError::TlsConfig(format!("rustls→quinn: {e}")))?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| AgentError::Bind(e.to_string()))?;

        info!(%addr, "agent endpoint bound");

        Ok(Self { endpoint })
    }

    /// Accept the next incoming connection and perform the handshake.
    ///
    /// Returns a verified `PodConnection` after:
    /// 1. TLS handshake completes (peer certificate verified by trust store)
    /// 2. Peer's PodId extracted from certificate
    /// 3. Protocol handshake: read `Handshake`, verify version, send `HandshakeResponse`
    pub async fn accept(&self) -> Result<PodConnection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| AgentError::Accept(quinn::ConnectionError::LocallyClosed))?;

        let quinn_conn = incoming.await?;

        let pod_conn = PodConnection::from_quinn(quinn_conn)?;

        info!(peer = %pod_conn.peer_pod_id(), "accepted connection");

        // Protocol handshake on a dedicated bidirectional stream.
        self.run_handshake(&pod_conn).await?;

        Ok(pod_conn)
    }

    /// Run the agent side of the protocol handshake.
    ///
    /// 1. Accept a bidirectional stream opened by the client.
    /// 2. Read the `Handshake` message.
    /// 3. Verify protocol version compatibility.
    /// 4. Send `HandshakeResponse`.
    async fn run_handshake(&self, conn: &PodConnection) -> Result<()> {
        let (mut send, mut recv) = conn
            .inner()
            .accept_bi()
            .await
            .map_err(|e| AgentError::Handshake(format!("accept stream: {e}")))?;

        let handshake: wire::Handshake = stream_io::read_message(&mut recv).await?;

        if !version::is_compatible(&handshake.protocol_version) {
            return Err(AgentError::Handshake(format!(
                "incompatible protocol version: {} (ours: {})",
                handshake.protocol_version,
                version::PROTOCOL_VERSION
            )));
        }

        let response = wire::HandshakeResponse {
            protocol_version: version::PROTOCOL_VERSION.to_string(),
            feature_flags: handshake.feature_flags, // Echo back intersection (no flags yet).
        };

        stream_io::write_message(&mut send, &response).await?;

        info!(
            peer = %conn.peer_pod_id(),
            version = %handshake.protocol_version,
            "handshake complete"
        );

        Ok(())
    }

    /// Returns the local address this endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| AgentError::Bind(e.to_string()))
    }

    /// Gracefully shut down the endpoint.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}
