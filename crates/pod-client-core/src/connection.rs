//! Verified QUIC connection wrapper (client-side).
//!
//! After the TLS handshake succeeds, `PodConnection` wraps the raw
//! `quinn::Connection` and caches the verified peer PodId.

use bytes::Bytes;
use pod_proto::datagram::{self, AudioFrame, DatagramTag};
use pod_proto::identity::PodId;
use pod_proto::sas;
use pod_proto::wire::ControlSignal;
use prost::Message;
use rustls_pki_types::CertificateDer;

use crate::error::{ClientError, Result};

/// Demuxed datagram payload received from a peer.
#[derive(Debug)]
pub enum ReceivedDatagram {
    /// Channel C control signal (protobuf-decoded).
    Control(ControlSignal),
    /// Channel D audio frame (fixed binary-decoded).
    Audio(AudioFrame),
}

/// A verified QUIC connection with a known peer PodId.
pub struct PodConnection {
    inner: quinn::Connection,
    peer_pod_id: PodId,
}

impl PodConnection {
    /// Wrap a raw quinn connection, extracting and verifying the peer's PodId.
    pub fn from_quinn(conn: quinn::Connection) -> Result<Self> {
        let peer_pod_id = extract_peer_pod_id(&conn)?;
        Ok(Self {
            inner: conn,
            peer_pod_id,
        })
    }

    /// The verified PodId of the connected peer.
    pub fn peer_pod_id(&self) -> &PodId {
        &self.peer_pod_id
    }

    /// Access the underlying quinn connection.
    pub fn inner(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Export TLS keying material for SAS derivation.
    ///
    /// Returns 32 bytes derived from the TLS session using the
    /// `OPENPOD-SAS` label (RFC 8446 §7.5, RFC 9266).
    pub fn export_keying_material(&self) -> Result<Vec<u8>> {
        let mut output = vec![0u8; 32];
        self.inner
            .export_keying_material(&mut output, sas::SAS_EXPORTER_LABEL.as_bytes(), b"")
            .map_err(|e| ClientError::PeerIdentity(format!("keying material export: {e:?}")))?;
        Ok(output)
    }

    // --- Datagram send/receive (Channels C & D) ---

    /// Send a control signal as a tagged datagram (Channel C, tag `0x01`).
    pub fn send_control_datagram(&self, signal: &ControlSignal) -> Result<()> {
        let payload = signal.encode_to_vec();
        let tagged = datagram::tag_datagram(DatagramTag::Control, &payload);
        self.inner
            .send_datagram(Bytes::from(tagged))
            .map_err(|e| ClientError::Datagram(format!("send control: {e}")))?;
        Ok(())
    }

    /// Send an audio frame as a tagged datagram (Channel D, tag `0x02`).
    ///
    /// Uses single-allocation encoding to minimize hot-path overhead.
    pub fn send_audio_datagram(&self, frame: &AudioFrame) -> Result<()> {
        let tagged = frame.encode_tagged(DatagramTag::Audio);
        self.inner
            .send_datagram(Bytes::from(tagged))
            .map_err(|e| ClientError::Datagram(format!("send audio: {e}")))?;
        Ok(())
    }

    /// Receive and demux the next datagram from the peer.
    ///
    /// Blocks until a datagram arrives. Datagrams with unknown tags are
    /// silently dropped (forward compatibility) and the call retries.
    pub async fn recv_datagram(&self) -> Result<ReceivedDatagram> {
        loop {
            let raw = self
                .inner
                .read_datagram()
                .await
                .map_err(|e| ClientError::Datagram(format!("recv: {e}")))?;

            let (tag, payload) = datagram::untag_datagram(&raw)
                .map_err(|e| ClientError::Datagram(format!("untag: {e}")))?;

            match tag {
                Some(DatagramTag::Control) => {
                    let signal = ControlSignal::decode(payload)
                        .map_err(|e| ClientError::Datagram(format!("decode control: {e}")))?;
                    return Ok(ReceivedDatagram::Control(signal));
                }
                Some(DatagramTag::Audio) => {
                    let frame = AudioFrame::decode(payload)
                        .map_err(|e| ClientError::Datagram(format!("decode audio: {e}")))?;
                    return Ok(ReceivedDatagram::Audio(frame));
                }
                None => {
                    // Unknown tag — silently drop for forward compatibility.
                    continue;
                }
            }
        }
    }
}

/// Extract the peer's PodId from a quinn connection's TLS peer identity.
fn extract_peer_pod_id(conn: &quinn::Connection) -> Result<PodId> {
    let identity = conn
        .peer_identity()
        .ok_or_else(|| ClientError::PeerIdentity("no peer identity available".into()))?;

    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| ClientError::PeerIdentity("failed to downcast peer identity".into()))?;

    let leaf = certs
        .first()
        .ok_or_else(|| ClientError::PeerIdentity("peer certificate chain is empty".into()))?;

    let pubkey = pod_proto::tls::cert_extract::extract_ed25519_public_key(leaf)
        .map_err(|e| ClientError::PeerIdentity(format!("key extraction: {e}")))?;

    Ok(PodId::from_public_key(&pubkey))
}
