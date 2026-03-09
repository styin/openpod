//! Runtime session state for the agent transport.

use pod_proto::wire::{SessionClose, SessionCloseAck, SessionCloseReason};
use tracing::info;

use crate::connection::PodConnection;
use crate::error::{AgentError, Result};
use crate::stream_io;

/// A live agent-side session scoped to a verified QUIC connection.
pub struct AgentSession {
    connection: PodConnection,
    session_id: String,
    client_last_ack_id: u64,
}

impl AgentSession {
    pub(crate) fn new(connection: PodConnection, session_id: String, client_last_ack_id: u64) -> Self {
        Self {
            connection,
            session_id,
            client_last_ack_id,
        }
    }

    /// The assigned session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The last Channel A ack id reported by the client during session init.
    pub fn client_last_ack_id(&self) -> u64 {
        self.client_last_ack_id
    }

    /// Access the underlying verified QUIC connection.
    pub fn connection(&self) -> &PodConnection {
        &self.connection
    }

    /// Wait for the peer to initiate graceful close, acknowledge it, and close
    /// the QUIC connection.
    pub async fn accept_close(&self) -> Result<SessionClose> {
        let (mut send, mut recv) = self
            .connection
            .inner()
            .accept_bi()
            .await
            .map_err(|e| AgentError::Handshake(format!("accept close stream: {e}")))?;

        let close: SessionClose = stream_io::read_message(&mut recv).await?;
        stream_io::write_message(&mut send, &SessionCloseAck {}).await?;

        info!(
            peer = %self.connection.peer_pod_id(),
            session_id = %self.session_id,
            reason = ?close.reason(),
            "session close acknowledged"
        );

        Ok(close)
    }

    /// Initiate graceful close for this session.
    pub async fn close(&self, reason: SessionCloseReason, message: impl Into<String>) -> Result<()> {
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

        stream_io::write_message(&mut send, &close).await?;

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

        Ok(())
    }
}