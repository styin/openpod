//! QUIC client endpoint.
//!
//! `ClientEndpoint` wraps a quinn client endpoint, connecting to an agent
//! and performing the protocol handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use pod_proto::identity::{Certificate, Keypair};
use pod_proto::tls::config::build_client_tls_config;
use pod_proto::trust::{TrustPolicy, TrustStore};
use pod_proto::version;
use pod_proto::wire;
use tracing::info;

use crate::connection::PodConnection;
use crate::error::{ClientError, Result};
use crate::stream_io;

/// SNI server name used in the TLS handshake.
///
/// Our custom verifier ignores SNI (it verifies PodId instead), but quinn
/// requires a valid server name for `connect()`.
const SNI_SERVER_NAME: &str = "openpod";

/// A QUIC client endpoint that connects to Pod agents.
pub struct ClientEndpoint {
    endpoint: quinn::Endpoint,
}

impl ClientEndpoint {
    /// Create a new client endpoint bound to an ephemeral port.
    ///
    /// Uses the provided identity keypair and certificate for mTLS.
    /// The trust store and policy control which agents are accepted.
    pub fn new(
        keypair: &Keypair,
        cert: &Certificate,
        trust_store: Arc<dyn TrustStore>,
        policy: TrustPolicy,
    ) -> Result<Self> {
        let rustls_config = build_client_tls_config(keypair, cert, trust_store, policy)?;

        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| ClientError::TlsConfig(format!("rustls→quinn: {e}")))?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint =
            quinn::Endpoint::client(bind_addr).map_err(|e| ClientError::Endpoint(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Connect to an agent at the given address and perform the handshake.
    ///
    /// Returns a verified `PodConnection` after:
    /// 1. TLS handshake completes (agent certificate verified by trust store)
    /// 2. Agent's PodId extracted from certificate
    /// 3. Protocol handshake: send `Handshake`, read `HandshakeResponse`, verify version
    pub async fn connect(&self, agent_addr: SocketAddr) -> Result<PodConnection> {
        let connecting = self.endpoint.connect(agent_addr, SNI_SERVER_NAME)?;

        let quinn_conn = connecting.await?;

        let pod_conn = PodConnection::from_quinn(quinn_conn)?;

        info!(peer = %pod_conn.peer_pod_id(), "connected to agent");

        // Protocol handshake on a dedicated bidirectional stream.
        self.run_handshake(&pod_conn).await?;

        Ok(pod_conn)
    }

    /// Run the client side of the protocol handshake.
    ///
    /// 1. Open a bidirectional stream.
    /// 2. Send `Handshake` message.
    /// 3. Read `HandshakeResponse`.
    /// 4. Verify protocol version compatibility.
    async fn run_handshake(&self, conn: &PodConnection) -> Result<()> {
        let (mut send, mut recv) = conn
            .inner()
            .open_bi()
            .await
            .map_err(|e| ClientError::Handshake(format!("open stream: {e}")))?;

        let handshake = wire::Handshake {
            protocol_version: version::PROTOCOL_VERSION.to_string(),
            feature_flags: 0,
        };

        stream_io::write_message(&mut send, &handshake).await?;

        let response: wire::HandshakeResponse = stream_io::read_message(&mut recv).await?;

        if !version::is_compatible(&response.protocol_version) {
            return Err(ClientError::Handshake(format!(
                "incompatible agent protocol version: {} (ours: {})",
                response.protocol_version,
                version::PROTOCOL_VERSION
            )));
        }

        info!(
            peer = %conn.peer_pod_id(),
            version = %response.protocol_version,
            "handshake complete"
        );

        Ok(())
    }

    /// Gracefully shut down the endpoint.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}
