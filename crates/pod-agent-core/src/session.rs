//! Runtime session state for the agent transport.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pod_proto::wire::{SessionClose, SessionCloseAck, SessionCloseReason};
use quinn::SendStream;
use tracing::info;

use crate::connection::PodConnection;
use crate::endpoint::StoredSessionState;
use crate::error::{AgentError, Result};
use crate::stream_io;

/// A stream accepted from the peer after session establishment.
pub enum InboundStream {
    /// A Channel A envelope from the peer.
    Envelope(pod_proto::wire::ChannelAEnvelope),
    /// A graceful session close request from the peer.
    ///
    /// The caller must write `SessionCloseAck` via `acknowledge_close()` or
    /// manually on the returned `SendStream`.
    Close {
        close: SessionClose,
        send: SendStream,
    },
}

/// A live agent-side session scoped to a verified QUIC connection.
pub struct AgentSession {
    connection: PodConnection,
    session_id: String,
    state: Arc<Mutex<StoredSessionState>>,
    registry: Arc<Mutex<HashMap<String, Arc<Mutex<StoredSessionState>>>>>,
    reconnection_window: Duration,
}

impl AgentSession {
    pub(crate) fn new(
        connection: PodConnection,
        session_id: String,
        state: Arc<Mutex<StoredSessionState>>,
        registry: Arc<Mutex<HashMap<String, Arc<Mutex<StoredSessionState>>>>>,
        reconnection_window: Duration,
    ) -> Self {
        Self {
            connection,
            session_id,
            state,
            registry,
            reconnection_window,
        }
    }

    /// The assigned session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The last Channel A ack id reported by the client during session init.
    pub fn client_last_ack_id(&self) -> u64 {
        self.state
            .lock()
            .expect("agent session state poisoned")
            .last_client_ack_id
    }

    /// The last client seq_id processed by the agent.
    pub fn agent_last_ack_id(&self) -> u64 {
        self.state
            .lock()
            .expect("agent session state poisoned")
            .last_agent_ack_id
    }

    /// Access the underlying verified QUIC connection.
    pub fn connection(&self) -> &PodConnection {
        &self.connection
    }

    /// Send a Channel A envelope and retain it until the client acknowledges it.
    pub async fn send_envelope(
        &self,
        payload: pod_proto::wire::channel_a_envelope::Payload,
    ) -> Result<pod_proto::wire::ChannelAEnvelope> {
        let envelope = {
            let mut state = self.state.lock().expect("agent session state poisoned");
            state.expires_at = Instant::now() + self.reconnection_window;
            state.next_outbound_envelope(payload)
        };

        let (mut send, _recv) = self
            .connection
            .inner()
            .open_bi()
            .await
            .map_err(|e| AgentError::Handshake(format!("open Channel A stream: {e}")))?;

        stream_io::write_tagged_message(&mut send, stream_io::StreamTag::Envelope, &envelope)
            .await?;

        Ok(envelope)
    }

    /// Accept the next tagged stream from the peer.
    ///
    /// Calls `accept_bi()`, reads the 1-byte stream tag, and decodes the
    /// appropriate message type. Returns `InboundStream::Envelope` for
    /// Channel A envelopes or `InboundStream::Close` for session close
    /// requests.
    ///
    /// For `InboundStream::Close`, the caller is responsible for writing
    /// `SessionCloseAck` via [`acknowledge_close()`](Self::acknowledge_close).
    pub async fn accept_stream(&self) -> Result<InboundStream> {
        let (send, mut recv) = self
            .connection
            .inner()
            .accept_bi()
            .await
            .map_err(|e| AgentError::Handshake(format!("accept stream: {e}")))?;

        let tag = stream_io::read_stream_tag(&mut recv).await?;

        match tag {
            stream_io::StreamTag::Envelope => {
                let envelope: pod_proto::wire::ChannelAEnvelope =
                    stream_io::read_channel_a_message(&mut recv).await?;

                let mut state = self.state.lock().expect("agent session state poisoned");
                state.prune_acked_messages(envelope.ack_id);
                state.last_agent_ack_id = state.last_agent_ack_id.max(envelope.seq_id);
                state.expires_at = Instant::now() + self.reconnection_window;

                Ok(InboundStream::Envelope(envelope))
            }
            stream_io::StreamTag::Close => {
                let close: SessionClose = stream_io::read_message(&mut recv).await?;
                Ok(InboundStream::Close { close, send })
            }
        }
    }

    /// Acknowledge a received session close and clean up.
    ///
    /// Writes `SessionCloseAck` on the provided `SendStream` (from
    /// `InboundStream::Close`), logs, and unregisters the session from
    /// the resume registry.
    pub async fn acknowledge_close(
        &self,
        close: &SessionClose,
        mut send: SendStream,
    ) -> Result<()> {
        stream_io::write_message(&mut send, &SessionCloseAck {}).await?;

        info!(
            peer = %self.connection.peer_pod_id(),
            session_id = %self.session_id,
            reason = ?close.reason(),
            "session close acknowledged"
        );

        self.unregister();
        Ok(())
    }

    pub(crate) async fn replay_pending_messages(&self) -> Result<()> {
        let pending: VecDeque<_> = self
            .state
            .lock()
            .expect("agent session state poisoned")
            .outbound_buffer
            .clone();

        for envelope in pending {
            let (mut send, _recv) = self
                .connection
                .inner()
                .open_bi()
                .await
                .map_err(|e| AgentError::Handshake(format!("open replay stream: {e}")))?;
            stream_io::write_tagged_message(&mut send, stream_io::StreamTag::Envelope, &envelope)
                .await?;
        }

        Ok(())
    }

    /// Initiate graceful close for this session.
    pub async fn close(
        &self,
        reason: SessionCloseReason,
        message: impl Into<String>,
    ) -> Result<()> {
        let (mut send, mut recv) = self
            .connection
            .inner()
            .open_bi()
            .await
            .map_err(|e| AgentError::Handshake(format!("open close stream: {e}")))?;

        let close = SessionClose {
            reason: reason.into(),
            message: message.into(),
        };

        stream_io::write_tagged_message(&mut send, stream_io::StreamTag::Close, &close).await?;

        let _: SessionCloseAck = stream_io::read_message(&mut recv).await?;

        info!(
            peer = %self.connection.peer_pod_id(),
            session_id = %self.session_id,
            reason = ?reason,
            "session close completed"
        );

        self.connection
            .inner()
            .close(0u32.into(), b"session close completed");

        self.unregister();

        Ok(())
    }

    fn unregister(&self) {
        self.registry
            .lock()
            .expect("agent session registry poisoned")
            .remove(&self.session_id);
    }
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        // Clear is_active so the session can be resumed on a new connection
        // after an ungraceful disconnect (where close() / accept_close() are
        // never called and unregister() is never reached).
        if let Ok(mut state) = self.state.lock() {
            state.is_active = false;
        }
    }
}
