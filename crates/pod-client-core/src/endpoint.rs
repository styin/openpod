//! QUIC client endpoint.
//!
//! `ClientEndpoint` wraps a quinn client endpoint, connecting to an agent
//! and performing the protocol handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use pod_proto::identity::{Certificate, Keypair, PodId};
use pod_proto::tls::config::build_client_tls_config;
use pod_proto::trust::{TrustPolicy, TrustStore};
use pod_proto::version;
use pod_proto::wire;
use tracing::info;

use crate::connection::PodConnection;
use crate::error::{ClientError, Result};
use crate::session::{ClientSession, SessionInitOptions};
use crate::stream_io;

/// SNI server name used in the TLS handshake.
///
/// Our custom verifier ignores SNI (it verifies PodId instead), but quinn
/// requires a valid server name for `connect()`.
const SNI_SERVER_NAME: &str = "openpod";

/// A QUIC client endpoint that connects to Pod agents.
pub struct ClientEndpoint {
    endpoint: quinn::Endpoint,
    local_pod_id: PodId,
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

        let mut transport_config = quinn::TransportConfig::default();
        // Enable QUIC datagram receive buffer for Channel C and D.
        transport_config.datagram_receive_buffer_size(Some(65536));

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint =
            quinn::Endpoint::client(bind_addr).map_err(|e| ClientError::Endpoint(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            local_pod_id: PodId::from_public_key(&keypair.public_key_bytes()),
        })
    }

    /// Connect to an agent at the given address and perform only transport-level
    /// verification plus the protocol handshake.
    ///
    /// This is the lower-level primitive beneath `connect_session()`. Most
    /// production callers should prefer the session-aware API unless they are
    /// intentionally operating at the raw transport layer for tests, diagnostics,
    /// or future non-session helpers.
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

    /// Connect to an agent and establish a runtime session.
    pub async fn connect_session(&self, agent_addr: SocketAddr) -> Result<ClientSession> {
        self.connect_session_with_options(agent_addr, SessionInitOptions::default())
            .await
    }

    /// Connect to an agent and establish a runtime session with explicit
    /// session init options.
    pub async fn connect_session_with_options(
        &self,
        agent_addr: SocketAddr,
        options: SessionInitOptions,
    ) -> Result<ClientSession> {
        let conn = self.connect(agent_addr).await?;
        self.run_session_init(conn, options).await
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

    async fn run_session_init(
        &self,
        conn: PodConnection,
        options: SessionInitOptions,
    ) -> Result<ClientSession> {
        let (mut send, mut recv) = conn
            .inner()
            .open_bi()
            .await
            .map_err(|e| ClientError::Handshake(format!("open session stream: {e}")))?;

        let init = wire::SessionInit {
            client_pod_id: self.local_pod_id.as_bytes().to_vec(),
            resume_session_id: options.resume_session_id.unwrap_or_default(),
            last_ack_id: options.last_ack_id,
        };

        stream_io::write_message(&mut send, &init).await?;

        let ack: wire::SessionAck = stream_io::read_message(&mut recv).await?;
        if ack.session_id.is_empty() {
            return Err(ClientError::Handshake(
                "agent returned an empty session id".into(),
            ));
        }

        info!(
            peer = %conn.peer_pod_id(),
            session_id = %ack.session_id,
            agent_last_ack_id = ack.last_ack_id,
            "session established"
        );

        Ok(ClientSession::new(conn, ack.session_id, ack.last_ack_id))
    }

    /// Gracefully shut down the endpoint.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}
