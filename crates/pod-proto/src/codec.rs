//! Length-delimited protobuf framing for QUIC streams.
//!
//! Each protobuf message is preceded by a varint-encoded length prefix.
//! This is the standard prost framing format, used to delimit messages
//! on QUIC bidirectional streams.
//!
//! These functions are synchronous and work on byte slices. Async wrappers
//! that read/write quinn streams live in the transport crates.

use bytes::BytesMut;
use prost::Message;

use crate::error::{ProtoError, Result};

/// Maximum allowed message size (1 MiB). Prevents unbounded allocation
/// from malformed length prefixes.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Encode a protobuf message with a varint length prefix.
///
/// Returns the encoded bytes: `[varint length][protobuf payload]`.
pub fn encode_length_delimited<M: Message>(msg: &M) -> Result<Vec<u8>> {
    let payload_len = msg.encoded_len();
    let varint_len = prost::length_delimiter_len(payload_len);
    let mut buf = Vec::with_capacity(varint_len + payload_len);
    prost::encode_length_delimiter(payload_len, &mut buf)?;
    msg.encode(&mut buf)?;
    Ok(buf)
}

/// Try to decode a length-delimited protobuf message from a buffer.
///
/// Returns `Ok(Some((message, bytes_consumed)))` if a complete message is
/// available, `Ok(None)` if the buffer doesn't contain a complete message
/// yet (need more data), or `Err` on malformed data.
pub fn decode_length_delimited<M: Message + Default>(buf: &[u8]) -> Result<Option<(M, usize)>> {
    let mut cursor = buf;

    // Try to read the varint length prefix.
    let payload_len = match prost::decode_length_delimiter(&mut cursor) {
        Ok(len) => len,
        Err(_) => return Ok(None), // Not enough bytes for the varint itself.
    };

    if payload_len > MAX_MESSAGE_SIZE {
        return Err(ProtoError::ProtobufDecode(prost::DecodeError::new(
            format!("message too large: {payload_len} bytes (max {MAX_MESSAGE_SIZE})"),
        )));
    }

    let varint_len = buf.len() - cursor.len();
    let total_needed = varint_len + payload_len;

    if buf.len() < total_needed {
        return Ok(None); // Have the length prefix but not the full payload yet.
    }

    let msg = M::decode(&buf[varint_len..total_needed])?;
    Ok(Some((msg, total_needed)))
}

/// Encode a protobuf message with a varint length prefix into a `BytesMut`.
///
/// Useful for building up multiple messages in a single buffer.
pub fn encode_into<M: Message>(msg: &M, buf: &mut BytesMut) -> Result<()> {
    let payload_len = msg.encoded_len();
    let varint_len = prost::length_delimiter_len(payload_len);
    buf.reserve(varint_len + payload_len);
    prost::encode_length_delimiter(payload_len, buf)?;
    msg.encode(buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;

    #[test]
    fn roundtrip_handshake() {
        let msg = wire::Handshake {
            protocol_version: "0.1.0".into(),
            feature_flags: 42,
        };

        let encoded = encode_length_delimited(&msg).expect("encode should succeed");
        let (decoded, consumed) = decode_length_delimited::<wire::Handshake>(&encoded)
            .expect("decode should succeed")
            .expect("should have complete message");

        assert_eq!(decoded.protocol_version, "0.1.0");
        assert_eq!(decoded.feature_flags, 42);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn roundtrip_envelope() {
        let msg = wire::ChannelAEnvelope {
            seq_id: 1,
            ack_id: 0,
            payload: Some(wire::channel_a_envelope::Payload::Semantic(
                wire::SemanticMessage {
                    json_payload: b"{\"text\":\"hello\"}".to_vec(),
                    pending_attachments: 0,
                },
            )),
        };

        let encoded = encode_length_delimited(&msg).expect("encode should succeed");
        let (decoded, consumed) = decode_length_delimited::<wire::ChannelAEnvelope>(&encoded)
            .expect("decode should succeed")
            .expect("should have complete message");

        assert_eq!(decoded.seq_id, 1);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn partial_data_returns_none() {
        let msg = wire::Handshake {
            protocol_version: "0.1.0".into(),
            feature_flags: 0,
        };

        let encoded = encode_length_delimited(&msg).expect("encode should succeed");

        // Only provide half the bytes.
        let half = &encoded[..encoded.len() / 2];
        let result = decode_length_delimited::<wire::Handshake>(half).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn empty_buffer_returns_none() {
        let result = decode_length_delimited::<wire::Handshake>(&[]).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn multiple_messages_in_buffer() {
        let msg1 = wire::Handshake {
            protocol_version: "0.1.0".into(),
            feature_flags: 1,
        };
        let msg2 = wire::Handshake {
            protocol_version: "0.2.0".into(),
            feature_flags: 2,
        };

        let enc1 = encode_length_delimited(&msg1).expect("encode 1");
        let enc2 = encode_length_delimited(&msg2).expect("encode 2");

        let mut combined = enc1.clone();
        combined.extend_from_slice(&enc2);

        // Decode first message.
        let (decoded1, consumed1) = decode_length_delimited::<wire::Handshake>(&combined)
            .expect("decode 1 should succeed")
            .expect("should have first message");
        assert_eq!(decoded1.feature_flags, 1);

        // Decode second message from remainder.
        let (decoded2, consumed2) =
            decode_length_delimited::<wire::Handshake>(&combined[consumed1..])
                .expect("decode 2 should succeed")
                .expect("should have second message");
        assert_eq!(decoded2.feature_flags, 2);
        assert_eq!(consumed1 + consumed2, combined.len());
    }

    #[test]
    fn encode_into_bytesmut() {
        let msg = wire::Handshake {
            protocol_version: "0.1.0".into(),
            feature_flags: 0,
        };

        let mut buf = BytesMut::new();
        encode_into(&msg, &mut buf).expect("encode should succeed");

        let (decoded, _) = decode_length_delimited::<wire::Handshake>(&buf)
            .expect("decode should succeed")
            .expect("should have complete message");
        assert_eq!(decoded.protocol_version, "0.1.0");
    }
}
