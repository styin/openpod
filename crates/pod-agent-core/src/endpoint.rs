//! QUIC server endpoint for the agent.
//!
//! `AgentEndpoint` wraps a quinn server endpoint, binding to a local address
//! and accepting incoming connections with mTLS verification.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use pod_proto::identity::{Certificate, Keypair};
use pod_proto::tls::config::build_server_tls_config;
use pod_proto::trust::{TrustPolicy, TrustStore};
use pod_proto::version;
use pod_proto::wire;
use tracing::info;

use crate::connection::PodConnection;
use crate::error::{AgentError, Result};
use crate::session::AgentSession;
use crate::stream_io;

/// A QUIC server endpoint that accepts incoming Pod connections.
pub struct AgentEndpoint {
    endpoint: quinn::Endpoint,
    // Temporary in-memory allocator for runtime session ids.
    //
    // This is enough to establish session semantics on top of a live QUIC
    // connection, but it is not sufficient for manifesto-grade resumption:
    // ids are not persistent across process restarts and are not tied to a
    // durable session registry yet.
    next_session_id: AtomicU64,
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<StoredSessionState>>>>>,
    reconnection_window: Duration,
}

pub(crate) struct StoredSessionState {
    pub(crate) peer_pod_id: pod_proto::identity::PodId,
    pub(crate) last_agent_ack_id: u64,
    pub(crate) last_client_ack_id: u64,
    pub(crate) next_agent_seq_id: u64,
    pub(crate) outbound_buffer: VecDeque<wire::ChannelAEnvelope>,
    pub(crate) expires_at: Instant,
    /// `true` while an `AgentSession` is bound to this state on a live
    /// connection. Guards against concurrent resume from two connections.
    pub(crate) is_active: bool,
}

impl StoredSessionState {
    fn new(
        peer_pod_id: pod_proto::identity::PodId,
        now: Instant,
        reconnection_window: Duration,
    ) -> Self {
        Self {
            peer_pod_id,
            last_agent_ack_id: 0,
            last_client_ack_id: 0,
            next_agent_seq_id: 1,
            outbound_buffer: VecDeque::new(),
            expires_at: now + reconnection_window,
            is_active: false,
        }
    }

    pub(crate) fn prune_acked_messages(&mut self, ack_id: u64) {
        self.outbound_buffer
            .retain(|message| message.seq_id > ack_id);
        self.last_client_ack_id = self.last_client_ack_id.max(ack_id);
    }

    pub(crate) fn next_outbound_envelope(
        &mut self,
        payload: wire::channel_a_envelope::Payload,
    ) -> wire::ChannelAEnvelope {
        let envelope = wire::ChannelAEnvelope {
            seq_id: self.next_agent_seq_id,
            ack_id: self.last_agent_ack_id,
            payload: Some(payload),
        };
        self.next_agent_seq_id += 1;
        self.outbound_buffer.push_back(envelope.clone());
        envelope
    }
}

const DEFAULT_RECONNECTION_WINDOW: Duration = Duration::from_secs(5 * 60);

impl AgentEndpoint {
    /// Bind a QUIC server to the given address.
    ///
    /// Uses the provided identity keypair and certificate for mTLS.
    /// The trust store and policy control which peers are accepted.
    /// The reconnection window defaults to 5 minutes; use
    /// `bind_with_reconnection_window` to override it.
    pub fn bind(
        addr: SocketAddr,
        keypair: &Keypair,
        cert: &Certificate,
        trust_store: Arc<dyn TrustStore>,
        policy: TrustPolicy,
    ) -> Result<Self> {
        Self::bind_with_reconnection_window(
            addr,
            keypair,
            cert,
            trust_store,
            policy,
            DEFAULT_RECONNECTION_WINDOW,
        )
    }

    /// Bind a QUIC server with an explicit session reconnection window.
    ///
    /// Equivalent to `bind` but allows overriding the reconnection window
    /// (the duration a disconnected session is held in memory for resumption).
    /// Useful in tests and deployments with tighter latency requirements.
    pub fn bind_with_reconnection_window(
        addr: SocketAddr,
        keypair: &Keypair,
        cert: &Certificate,
        trust_store: Arc<dyn TrustStore>,
        policy: TrustPolicy,
        reconnection_window: Duration,
    ) -> Result<Self> {
        let rustls_config = build_server_tls_config(keypair, cert, trust_store, policy)?;

        let quic_server_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
                .map_err(|e| AgentError::TlsConfig(format!("rustls→quinn: {e}")))?;

        let mut transport_config = quinn::TransportConfig::default();
        // Enable QUIC datagram receive buffer for Channel C and D.
        transport_config.datagram_receive_buffer_size(Some(65536));

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(transport_config));

        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| AgentError::Bind(e.to_string()))?;

        info!(%addr, "agent endpoint bound");

        Ok(Self {
            endpoint,
            next_session_id: AtomicU64::new(1),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            reconnection_window,
        })
    }

    /// Accept the next incoming connection and perform only transport-level
    /// verification plus the protocol handshake.
    ///
    /// This is the lower-level primitive beneath `accept_session()`. Most
    /// production callers should prefer the session-aware API unless they are
    /// intentionally operating at the raw transport layer for tests or tooling.
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

    /// Accept the next incoming connection and establish a runtime session.
    ///
    /// After the protocol handshake completes, the agent reads `SessionInit`
    /// from a dedicated bidirectional stream, validates it against the mTLS
    /// peer identity, assigns a session id, and replies with `SessionAck`.
    pub async fn accept_session(&self) -> Result<AgentSession> {
        let conn = self.accept().await?;
        self.run_session_init(conn).await
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

    async fn run_session_init(&self, conn: PodConnection) -> Result<AgentSession> {
        let (mut send, mut recv) = conn
            .inner()
            .accept_bi()
            .await
            .map_err(|e| AgentError::Handshake(format!("accept session stream: {e}")))?;

        let init: wire::SessionInit = stream_io::read_message(&mut recv).await?;

        if init.client_pod_id.as_slice() != conn.peer_pod_id().as_bytes() {
            return Err(AgentError::Handshake(
                "session init PodId does not match TLS peer identity".into(),
            ));
        }

        let now = Instant::now();

        // Opportunistically remove sessions whose reconnection window has
        // expired. Prevents unbounded growth when clients disconnect and never
        // reconnect — expiry is otherwise only enforced on the resume path.
        self.sessions
            .lock()
            .expect("agent session registry poisoned")
            .retain(|_, state| {
                state
                    .lock()
                    .expect("agent session state poisoned")
                    .expires_at
                    > now
            });

        let (session_id, state) = if init.resume_session_id.is_empty() {
            let session_id = self.allocate_session_id();
            let state = Arc::new(Mutex::new(StoredSessionState::new(
                conn.peer_pod_id().clone(),
                now,
                self.reconnection_window,
            )));
            self.sessions
                .lock()
                .expect("agent session registry poisoned")
                .insert(session_id.clone(), state.clone());
            (session_id, state)
        } else {
            let registry = self
                .sessions
                .lock()
                .expect("agent session registry poisoned");
            let state = registry
                .get(&init.resume_session_id)
                .cloned()
                .ok_or_else(|| {
                    AgentError::Handshake(
                        "session resumption requested for unknown session id".into(),
                    )
                })?;
            drop(registry);

            {
                let mut state_guard = state.lock().expect("agent session state poisoned");
                if state_guard.peer_pod_id.as_bytes() != conn.peer_pod_id().as_bytes() {
                    return Err(AgentError::Handshake(
                        "session resumption PodId does not match original session owner".into(),
                    ));
                }
                if now > state_guard.expires_at {
                    self.sessions
                        .lock()
                        .expect("agent session registry poisoned")
                        .remove(&init.resume_session_id);
                    return Err(AgentError::Handshake(
                        "session resumption window has expired".into(),
                    ));
                }
                if state_guard.is_active {
                    return Err(AgentError::Handshake(
                        "session already has an active connection; concurrent resume rejected"
                            .into(),
                    ));
                }
                state_guard.prune_acked_messages(init.last_ack_id);
                state_guard.expires_at = now + self.reconnection_window;
            }

            (init.resume_session_id.clone(), state)
        };

        let last_ack_id = state
            .lock()
            .expect("agent session state poisoned")
            .last_agent_ack_id;
        let ack = wire::SessionAck {
            session_id: session_id.clone(),
            last_ack_id,
        };

        stream_io::write_message(&mut send, &ack).await?;

        state
            .lock()
            .expect("agent session state poisoned")
            .is_active = true;

        let session = AgentSession::new(
            conn,
            session_id.clone(),
            state,
            self.sessions.clone(),
            self.reconnection_window,
        );

        if !init.resume_session_id.is_empty() {
            session.replay_pending_messages().await?;
        }

        info!(
            peer = %session.connection().peer_pod_id(),
            session_id = %session_id,
            client_last_ack_id = init.last_ack_id,
            "session established"
        );

        Ok(session)
    }

    fn allocate_session_id(&self) -> String {
        let next = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        format!("sess-{next}")
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
