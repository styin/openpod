//! Async message read/write helpers for quinn streams.
//!
//! Provides tagged and untagged read/write primitives. Handshake and
//! session-init streams are untagged (sequential one-shots at connection
//! startup). All streams opened after session establishment carry a 1-byte
//! `StreamTag` prefix so the receiver can dispatch without racing.

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

/// 1-byte tag identifying the stream type for post-session-init streams.
///
/// Symmetric to the datagram channel tags (`0x01` = Channel C, `0x02` =
/// Channel D) but in a separate namespace — streams and datagrams are
/// different QUIC primitives and never need cross-disambiguation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamTag {
    /// Channel A envelope stream.
    Envelope = 0x01,
    /// Session close/ack stream.
    Close = 0x02,
}

impl StreamTag {
    /// Parse a tag byte, returning `None` for unknown tags.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Envelope),
            0x02 => Some(Self::Close),
            _ => None,
        }
    }
}

/// Write a stream-type tag followed by a protobuf message, then finish the
/// send half.
///
/// Used for all post-session-init streams. The tag byte is written first so
/// the receiver can dispatch before reading the protobuf body.
pub async fn write_tagged_message<M: Message>(
    send: &mut SendStream,
    tag: StreamTag,
    msg: &M,
) -> Result<()> {
    send.write_all(&[tag as u8])
        .await
        .map_err(|e| ClientError::StreamIo(format!("write tag: {e}")))?;
    let buf = msg.encode_to_vec();
    send.write_all(&buf)
        .await
        .map_err(|e| ClientError::StreamIo(format!("write: {e}")))?;
    send.finish()
        .map_err(|e| ClientError::StreamIo(format!("finish: {e}")))?;
    Ok(())
}

/// Read the 1-byte stream-type tag from a receive stream.
pub async fn read_stream_tag(recv: &mut RecvStream) -> Result<StreamTag> {
    let mut tag_buf = [0u8; 1];
    recv.read_exact(&mut tag_buf)
        .await
        .map_err(|e| ClientError::StreamIo(format!("read tag: {e}")))?;
    StreamTag::from_byte(tag_buf[0])
        .ok_or_else(|| ClientError::StreamIo(format!("unknown stream tag: 0x{:02x}", tag_buf[0])))
}

/// Write a protobuf message to a send stream and signal completion.
///
/// Encodes the message (without length-delimited framing — the stream
/// itself provides framing via FIN), writes all bytes, and calls `finish()`
/// to signal that no more data will be sent on this half of the stream.
///
/// Used for untagged streams (handshake, session-init) and for response
/// messages on already-tagged streams (e.g., `SessionCloseAck`).
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
