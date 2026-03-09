//! Async message read/write helpers for quinn streams.
//!
//! For the handshake, each side sends one message on a bidirectional stream
//! and then reads the response. The stream is used once and closed.

use prost::Message;
use quinn::{RecvStream, SendStream};

use crate::error::{ClientError, Result};

/// Maximum handshake message size (64 KiB). Handshake messages are small.
const MAX_HANDSHAKE_SIZE: usize = 64 * 1024;

/// Maximum Channel A runtime message size (16 MiB).
///
/// Channel A envelopes carry arbitrary JSON payloads and may be significantly
/// larger than handshake messages. This limit applies to `read_channel_a_message`.
pub const MAX_CHANNEL_A_SIZE: usize = 16 * 1024 * 1024;

/// Write a protobuf message to a send stream and signal completion.
///
/// Encodes the message, writes all bytes, and calls `finish()` to signal
/// that no more data will be sent on this half of the stream.
pub async fn write_message<M: Message>(send: &mut SendStream, msg: &M) -> Result<()> {
    let buf = msg.encode_to_vec();
    send.write_all(&buf)
        .await
        .map_err(|e| ClientError::StreamIo(format!("write: {e}")))?;
    send.finish()
        .map_err(|e| ClientError::StreamIo(format!("finish: {e}")))?;
    Ok(())
}

/// Read a protobuf message from a receive stream.
///
/// Reads until FIN (stream closed by peer), then decodes the protobuf message.
/// Uses `MAX_HANDSHAKE_SIZE` (64 KiB) — suitable for handshake and control
/// messages. Use `read_channel_a_message` for runtime Channel A envelopes.
pub async fn read_message<M: Message + Default>(recv: &mut RecvStream) -> Result<M> {
    let buf = recv
        .read_to_end(MAX_HANDSHAKE_SIZE)
        .await
        .map_err(|e| ClientError::StreamIo(format!("read: {e}")))?;

    M::decode(buf.as_slice()).map_err(|e| ClientError::StreamIo(format!("decode: {e}")))
}

/// Read a Channel A runtime envelope from a receive stream.
///
/// Like `read_message` but uses `MAX_CHANNEL_A_SIZE` (16 MiB) to accommodate
/// large JSON payloads carried by `ChannelAEnvelope`.
pub async fn read_channel_a_message<M: Message + Default>(recv: &mut RecvStream) -> Result<M> {
    let buf = recv
        .read_to_end(MAX_CHANNEL_A_SIZE)
        .await
        .map_err(|e| ClientError::StreamIo(format!("read: {e}")))?;

    M::decode(buf.as_slice()).map_err(|e| ClientError::StreamIo(format!("decode: {e}")))
}
