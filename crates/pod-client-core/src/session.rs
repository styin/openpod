//! Runtime session state for the client transport.

use pod_proto::wire::{SessionClose, SessionCloseAck, SessionCloseReason};
use tracing::info;

use crate::connection::PodConnection;
use crate::error::{ClientError, Result};
use crate::stream_io;

/// Options carried in `SessionInit` when opening a session.
#[derive(Debug, Clone, Default)]
pub struct SessionInitOptions {
    /// Previous session id to resume. Empty by default.
    pub resume_session_id: Option<String>,
    /// Last Channel A ack id observed by the client.
    pub last_ack_id: u64,
}

/// A live client-side session scoped to a verified QUIC connection.
pub struct ClientSession {
    connection: PodConnection,
    session_id: String,
    agent_last_ack_id: u64,
}

impl ClientSession {
    pub(crate) fn new(connection: PodConnection, session_id: String, agent_last_ack_id: u64) -> Self {
        Self {
            connection,
            session_id,
            agent_last_ack_id,
        }
    }

    /// The session id assigned by the agent.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The last Channel A ack id reported by the agent in `SessionAck`.
    pub fn agent_last_ack_id(&self) -> u64 {
        self.agent_last_ack_id
    }

    /// Access the underlying verified QUIC connection.
    pub fn connection(&self) -> &PodConnection {
        &self.connection
    }

    /// Initiate graceful close for this session.
    pub async fn close(&self, reason: SessionCloseReason, message: impl Into<String>) -> Result<()> {
        let (mut send, mut recv) = self
            .connection
            .inner()
            .open_bi()
            .await
            .map_err(|e| ClientError::Handshake(format!("open close stream: {e}")))?;

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

    /// Wait for the peer to initiate graceful close, acknowledge it, and close
    /// the QUIC connection.
    pub async fn accept_close(&self) -> Result<SessionClose> {
        let (mut send, mut recv) = self
            .connection
            .inner()
            .accept_bi()
            .await
            .map_err(|e| ClientError::Handshake(format!("accept close stream: {e}")))?;

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
}