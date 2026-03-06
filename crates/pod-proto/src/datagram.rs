//! Datagram channel tag framing and AudioFrame codec.
//!
//! QUIC unreliable datagrams are shared between Channel C (control signals)
//! and Channel D (audio frames). A 1-byte tag prefix identifies the channel:
//!
//! | Tag    | Channel     | Payload                          |
//! |--------|-------------|----------------------------------|
//! | `0x01` | C (Control) | `ControlSignal` protobuf         |
//! | `0x02` | D (Audio)   | `AudioFrame` fixed binary        |
//!
//! AudioFrame uses a fixed binary layout (not protobuf) for minimal overhead
//! at 50 frames/second. See Manifesto §2.13.

use crate::error::{ProtoError, Result};

// =========================================================================
// Datagram channel tags
// =========================================================================

/// 1-byte tag identifying the datagram channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DatagramTag {
    /// Channel C — control signal (protobuf payload).
    Control = 0x01,
    /// Channel D — audio frame (fixed binary payload).
    Audio = 0x02,
}

impl DatagramTag {
    /// Parse a tag byte, returning `None` for unknown tags.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Control),
            0x02 => Some(Self::Audio),
            _ => None,
        }
    }
}

/// Prepend a channel tag to a payload, returning the tagged datagram.
pub fn tag_datagram(tag: DatagramTag, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(tag as u8);
    buf.extend_from_slice(payload);
    buf
}

/// Strip the channel tag from a datagram, returning the tag and payload.
///
/// Returns `Err` if the datagram is empty. Unknown tags return
/// `Ok((None, payload))` for forward compatibility — the caller should
/// silently drop unknown tags. Note: a 1-byte datagram (tag only) is
/// valid and produces an empty payload slice.
pub fn untag_datagram(data: &[u8]) -> Result<(Option<DatagramTag>, &[u8])> {
    if data.is_empty() {
        return Err(ProtoError::InvalidDatagram("empty datagram".into()));
    }
    let tag = DatagramTag::from_byte(data[0]);
    Ok((tag, &data[1..]))
}

// =========================================================================
// AudioFrame — Channel D fixed binary codec (Manifesto §2.13.1)
// =========================================================================

/// Minimum header size: seq (2) + timestamp (4) + flags (1) = 7 bytes.
const AUDIO_HEADER_SIZE: usize = 7;

/// AudioFrame flag: silence / DTX — no `audio_data` follows.
pub const FLAG_DTX: u8 = 0x01;

/// A single audio frame for Channel D transport.
///
/// Wire format (all multi-byte integers are big-endian):
/// ```text
/// ┌──────────┬──────────┬───────────┬──────────────┐
/// │ 2 bytes  │ 4 bytes  │ 1 byte    │ Variable     │
/// │ seq      │ timestamp│ flags     │ audio_data   │
/// │ (u16 BE) │ (u32 BE) │           │              │
/// └──────────┴──────────┴───────────┴──────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// Sequence number for loss detection. Wraps at 65535.
    pub seq: u16,
    /// RTP-style timestamp in sample units (48 kHz clock).
    pub timestamp: u32,
    /// Bitfield flags (see [`FLAG_DTX`]). Only DTX is defined at the
    /// transport layer — channel count is negotiated on Channel A and
    /// encapsulated natively in the codec bitstream.
    pub flags: u8,
    /// Opaque encoded audio bytes. Empty when DTX flag is set.
    /// Encoding details (codec, channels, sample rate) are determined
    /// by Channel A negotiation, not transport-layer flags.
    pub audio_data: Vec<u8>,
}

impl AudioFrame {
    /// Encode this frame into its fixed binary representation.
    ///
    /// Does **not** include the datagram channel tag — use [`encode_tagged`]
    /// for the single-allocation hot path, or [`tag_datagram`] to wrap
    /// the result separately.
    ///
    /// # Panics (debug builds)
    ///
    /// Panics if `FLAG_DTX` is set but `audio_data` is non-empty.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.flags & FLAG_DTX == 0 || self.audio_data.is_empty(),
            "DTX flag set but audio_data is non-empty — this frame will fail to decode"
        );
        let mut buf = Vec::with_capacity(AUDIO_HEADER_SIZE + self.audio_data.len());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(self.flags);
        buf.extend_from_slice(&self.audio_data);
        buf
    }

    /// Encode this frame with a prepended datagram channel tag in a
    /// **single allocation** — the hot-path method for real-time audio.
    ///
    /// Equivalent to `tag_datagram(tag, &self.encode())` but avoids the
    /// intermediate `Vec` and full-payload copy.
    ///
    /// # Panics (debug builds)
    ///
    /// Panics if `FLAG_DTX` is set but `audio_data` is non-empty.
    pub fn encode_tagged(&self, tag: DatagramTag) -> Vec<u8> {
        debug_assert!(
            self.flags & FLAG_DTX == 0 || self.audio_data.is_empty(),
            "DTX flag set but audio_data is non-empty — this frame will fail to decode"
        );
        let mut buf = Vec::with_capacity(1 + AUDIO_HEADER_SIZE + self.audio_data.len());
        buf.push(tag as u8);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(self.flags);
        buf.extend_from_slice(&self.audio_data);
        buf
    }

    /// Decode an `AudioFrame` from its fixed binary representation.
    ///
    /// The input should be the **payload after stripping the datagram tag**
    /// (i.e., the output of [`untag_datagram`] when the tag is [`DatagramTag::Audio`]).
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < AUDIO_HEADER_SIZE {
            return Err(ProtoError::AudioFrameDecode(format!(
                "need at least {AUDIO_HEADER_SIZE} bytes, got {}",
                data.len()
            )));
        }
        let seq = u16::from_be_bytes([data[0], data[1]]);
        let timestamp = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let flags = data[6];
        let audio_data = data[AUDIO_HEADER_SIZE..].to_vec();

        // If DTX flag is set, there should be no audio data.
        if flags & FLAG_DTX != 0 && !audio_data.is_empty() {
            return Err(ProtoError::AudioFrameDecode(
                "DTX flag set but audio_data is non-empty".into(),
            ));
        }

        Ok(Self {
            seq,
            timestamp,
            flags,
            audio_data,
        })
    }

    /// Returns `true` if the DTX (silence) flag is set.
    pub fn is_dtx(&self) -> bool {
        self.flags & FLAG_DTX != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DatagramTag tests ----

    #[test]
    fn tag_roundtrip_control() {
        let payload = b"some-control-payload";
        let tagged = tag_datagram(DatagramTag::Control, payload);
        assert_eq!(tagged[0], 0x01);
        let (tag, inner) = untag_datagram(&tagged).unwrap();
        assert_eq!(tag, Some(DatagramTag::Control));
        assert_eq!(inner, payload);
    }

    #[test]
    fn tag_roundtrip_audio() {
        let payload = b"opus-bytes";
        let tagged = tag_datagram(DatagramTag::Audio, payload);
        assert_eq!(tagged[0], 0x02);
        let (tag, inner) = untag_datagram(&tagged).unwrap();
        assert_eq!(tag, Some(DatagramTag::Audio));
        assert_eq!(inner, payload);
    }

    #[test]
    fn unknown_tag_returns_none() {
        let data = [0xFF, 0x01, 0x02];
        let (tag, payload) = untag_datagram(&data).unwrap();
        assert_eq!(tag, None);
        assert_eq!(payload, &[0x01, 0x02]);
    }

    #[test]
    fn empty_datagram_is_error() {
        assert!(untag_datagram(&[]).is_err());
    }

    // ---- AudioFrame tests ----

    #[test]
    fn audio_frame_roundtrip() {
        let frame = AudioFrame {
            seq: 42,
            timestamp: 960 * 100, // 100 frames at 20ms
            flags: 0,
            audio_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), 7 + 4); // header + audio
        let decoded = AudioFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn audio_frame_dtx_roundtrip() {
        let frame = AudioFrame {
            seq: 1,
            timestamp: 960,
            flags: FLAG_DTX,
            audio_data: vec![],
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), 7); // header only, no audio data
        let decoded = AudioFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
        assert!(decoded.is_dtx());
    }

    #[test]
    fn audio_frame_unknown_flags_preserved() {
        // Flags beyond FLAG_DTX are opaque at the transport layer.
        // Channel count is negotiated on Channel A and encoded in the
        // codec bitstream — the transport must not strip unknown flags.
        let frame = AudioFrame {
            seq: 0,
            timestamp: 0,
            flags: 0x42, // some future/unknown flag combination
            audio_data: vec![0x01],
        };
        let decoded = AudioFrame::decode(&frame.encode()).unwrap();
        assert_eq!(decoded.flags, 0x42);
        assert!(!decoded.is_dtx());
    }

    #[test]
    fn audio_frame_too_short() {
        let result = AudioFrame::decode(&[0x00; 6]);
        assert!(result.is_err());
    }

    #[test]
    fn audio_frame_exact_header_no_audio() {
        // 7 bytes = valid header with empty audio_data (non-DTX)
        let data = [0x00, 0x01, 0x00, 0x00, 0x03, 0xC0, 0x00];
        let frame = AudioFrame::decode(&data).unwrap();
        assert_eq!(frame.seq, 1);
        assert_eq!(frame.timestamp, 960);
        assert_eq!(frame.flags, 0);
        assert!(frame.audio_data.is_empty());
    }

    #[test]
    fn audio_frame_dtx_with_data_is_error() {
        let data = [0x00, 0x01, 0x00, 0x00, 0x03, 0xC0, FLAG_DTX, 0xFF];
        let result = AudioFrame::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn audio_frame_sequence_wrap() {
        let frame = AudioFrame {
            seq: u16::MAX,
            timestamp: u32::MAX,
            flags: 0,
            audio_data: vec![0xAB],
        };
        let decoded = AudioFrame::decode(&frame.encode()).unwrap();
        assert_eq!(decoded.seq, u16::MAX);
        assert_eq!(decoded.timestamp, u32::MAX);
    }

    #[test]
    fn full_tagged_audio_datagram_roundtrip() {
        let frame = AudioFrame {
            seq: 7,
            timestamp: 48000,
            flags: 0,
            audio_data: vec![0x01, 0x02, 0x03],
        };
        // Encode and tag
        let tagged = tag_datagram(DatagramTag::Audio, &frame.encode());

        // Untag and decode
        let (tag, payload) = untag_datagram(&tagged).unwrap();
        assert_eq!(tag, Some(DatagramTag::Audio));
        let decoded = AudioFrame::decode(payload).unwrap();
        assert_eq!(frame, decoded);
    }
}
