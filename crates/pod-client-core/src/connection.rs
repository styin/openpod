//! Verified QUIC connection wrapper (client-side).
//!
//! After the TLS handshake succeeds, `PodConnection` wraps the raw
//! `quinn::Connection` and caches the verified peer PodId.

use pod_proto::identity::PodId;
use pod_proto::sas;
use rustls_pki_types::CertificateDer;

use crate::error::{ClientError, Result};

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
    /// `OPENPOD-PAIRING` label (RFC 5705).
    pub fn export_keying_material(&self) -> Result<Vec<u8>> {
        let mut output = vec![0u8; 32];
        self.inner
            .export_keying_material(&mut output, sas::SAS_EXPORTER_LABEL.as_bytes(), b"")
            .map_err(|e| ClientError::PeerIdentity(format!("keying material export: {e:?}")))?;
        Ok(output)
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
