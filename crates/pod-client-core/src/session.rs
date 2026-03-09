//! Runtime session state for the client transport.

use std::collections::VecDeque;
use std::sync::Mutex;

use pod_proto::wire::{self, ChannelAEnvelope, SessionClose, SessionCloseAck, SessionCloseReason};
use quinn::SendStream;
use tracing::info;

use crate::connection::PodConnection;
use crate::error::{ClientError, Result};
use crate::stream_io;

/// A stream accepted from the peer after session establishment.
pub enum InboundStream {
    /// A Channel A envelope from the peer.
    Envelope(ChannelAEnvelope),
    /// A graceful session close request from the peer.
    ///
    /// The caller must write `SessionCloseAck` via `acknowledge_close()` or
    /// manually on the returned `SendStream`.
    Close {
        close: SessionClose,
        send: SendStream,
    },
}

struct ClientSessionState {
    last_agent_ack_id: u64,
    last_client_ack_id: u64,
    next_client_seq_id: u64,
    outbound_buffer: VecDeque<ChannelAEnvelope>,
}

impl ClientSessionState {
    fn new(last_agent_ack_id: u64) -> Self {
        Self {
            last_agent_ack_id,
            last_client_ack_id: 0,
            next_client_seq_id: 1,
            outbound_buffer: VecDeque::new(),
        }
    }

    fn from_resume_state(last_agent_ack_id: u64, resume_state: SessionResumeState) -> Self {
        Self {
            last_agent_ack_id,
            last_client_ack_id: resume_state.last_client_ack_id,
            next_client_seq_id: resume_state.next_client_seq_id,
            outbound_buffer: resume_state.outbound_buffer,
        }
    }

    fn next_outbound_envelope(
        &mut self,
        payload: wire::channel_a_envelope::Payload,
    ) -> ChannelAEnvelope {
        let envelope = ChannelAEnvelope {
            seq_id: self.next_client_seq_id,
            ack_id: self.last_client_ack_id,
            payload: Some(payload),
        };
        self.next_client_seq_id += 1;
        self.outbound_buffer.push_back(envelope.clone());
        envelope
    }

    fn prune_acked_messages(&mut self, ack_id: u64) {
        self.outbound_buffer
            .retain(|message| message.seq_id > ack_id);
        self.last_agent_ack_id = self.last_agent_ack_id.max(ack_id);
    }
}

/// Options carried in `SessionInit` when opening a session.
#[derive(Debug, Clone, Default)]
pub struct SessionInitOptions {
    /// Previous session id to resume. Empty by default.
    pub resume_session_id: Option<String>,
    /// Last Channel A ack id observed by the client.
    pub last_ack_id: u64,
}

/// Snapshot of client-side session state needed to resume after reconnect.
#[derive(Debug, Clone)]
pub struct SessionResumeState {
    session_id: String,
    last_client_ack_id: u64,
    next_client_seq_id: u64,
    outbound_buffer: VecDeque<ChannelAEnvelope>,
}

impl SessionResumeState {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn last_client_ack_id(&self) -> u64 {
        self.last_client_ack_id
    }
}

/// A live client-side session scoped to a verified QUIC connection.
pub struct ClientSession {
    connection: PodConnection,
    session_id: String,
    state: Mutex<ClientSessionState>,
}

impl ClientSession {
    pub(crate) fn new(
        connection: PodConnection,
        session_id: String,
        agent_last_ack_id: u64,
    ) -> Self {
        Self {
            connection,
            session_id,
            state: Mutex::new(ClientSessionState::new(agent_last_ack_id)),
        }
    }

    pub(crate) fn from_resume_state(
        connection: PodConnection,
        session_id: String,
        agent_last_ack_id: u64,
        resume_state: SessionResumeState,
    ) -> Self {
        Self {
            connection,
            session_id,
            state: Mutex::new(ClientSessionState::from_resume_state(
                agent_last_ack_id,
                resume_state,
            )),
        }
    }

    /// The session id assigned by the agent.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The last Channel A ack id reported by the agent in `SessionAck`.
    pub fn agent_last_ack_id(&self) -> u64 {
        self.state
            .lock()
            .expect("client session state poisoned")
            .last_agent_ack_id
    }

    /// Access the underlying verified QUIC connection.
    pub fn connection(&self) -> &PodConnection {
        &self.connection
    }

    /// Snapshot the current state required to resume this session after reconnect.
    pub fn resume_state(&self) -> SessionResumeState {
        let state = self.state.lock().expect("client session state poisoned");
        SessionResumeState {
            session_id: self.session_id.clone(),
            last_client_ack_id: state.last_client_ack_id,
            next_client_seq_id: state.next_client_seq_id,
            outbound_buffer: state.outbound_buffer.clone(),
        }
    }

    /// Send a Channel A envelope and retain it until the agent acknowledges it.
    pub async fn send_envelope(
        &self,
        payload: wire::channel_a_envelope::Payload,
    ) -> Result<ChannelAEnvelope> {
        let envelope = {
            let mut state = self.state.lock().expect("client session state poisoned");
            state.next_outbound_envelope(payload)
        };

        let (mut send, _recv) = self
            .connection
            .inner()
            .open_bi()
            .await
            .map_err(|e| ClientError::Handshake(format!("open Channel A stream: {e}")))?;

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
            .map_err(|e| ClientError::Handshake(format!("accept stream: {e}")))?;

        let tag = stream_io::read_stream_tag(&mut recv).await?;

        match tag {
            stream_io::StreamTag::Envelope => {
                let envelope: ChannelAEnvelope =
                    stream_io::read_channel_a_message(&mut recv).await?;

                let mut state = self.state.lock().expect("client session state poisoned");
                state.prune_acked_messages(envelope.ack_id);
                state.last_client_ack_id = state.last_client_ack_id.max(envelope.seq_id);

                Ok(InboundStream::Envelope(envelope))
            }
            stream_io::StreamTag::Close => {
                let close: SessionClose = stream_io::read_message(&mut recv).await?;
                Ok(InboundStream::Close { close, send })
            }
        }
    }

    /// Acknowledge a received session close.
    ///
    /// Writes `SessionCloseAck` on the provided `SendStream` (from
    /// `InboundStream::Close`) and logs.
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

        Ok(())
    }

    pub(crate) async fn prune_and_replay_pending_messages(&self) -> Result<()> {
        let pending = {
            let mut state = self.state.lock().expect("client session state poisoned");
            let ack_id = state.last_agent_ack_id;
            state.prune_acked_messages(ack_id);
            state.outbound_buffer.clone()
        };

        for envelope in pending {
            let (mut send, _recv) = self
                .connection
                .inner()
                .open_bi()
                .await
                .map_err(|e| ClientError::Handshake(format!("open replay stream: {e}")))?;
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
            .map_err(|e| ClientError::Handshake(format!("open close stream: {e}")))?;

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

        Ok(())
    }
}
