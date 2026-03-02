//! Async message read/write helpers for quinn streams.
//!
//! For the handshake, each side sends one message on a bidirectional stream
//! and then reads the response. The stream is used once and closed.

use prost::Message;
use quinn::{RecvStream, SendStream};

use crate::error::{ClientError, Result};

/// Maximum handshake message size (64 KiB). Handshake messages are small.
const MAX_HANDSHAKE_SIZE: usize = 64 * 1024;

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
pub async fn read_message<M: Message + Default>(recv: &mut RecvStream) -> Result<M> {
    let buf = recv
        .read_to_end(MAX_HANDSHAKE_SIZE)
        .await
        .map_err(|e| ClientError::StreamIo(format!("read: {e}")))?;

    M::decode(buf.as_slice()).map_err(|e| ClientError::StreamIo(format!("decode: {e}")))
}
