//! Custom rustls verifiers for the TOFU trust model.
//!
//! `PodServerCertVerifier` (client-side) and `PodClientCertVerifier`
//! (server-side) extract the peer's Ed25519 public key from the
//! presented certificate, derive the PodId, and check the trust store.
//!
//! Signature verification is delegated to the rustls ring crypto provider.
//! Only certificate chain validation is customized (TOFU vs Strict).
//!
//! Design references:
//! - iroh: Ed25519 identity + self-signed certs + custom verifiers over quinn
//! - libp2p-tls: custom `ClientCertVerifier` for P2P self-signed certs

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::identity::PodId;
use crate::tls::cert_extract::extract_ed25519_public_key;
use crate::trust::{TrustPolicy, TrustStore};

/// Verify a peer certificate against the trust store.
///
/// Shared logic used by both client-side and server-side verifiers.
/// Returns `Ok(())` if the peer is accepted, `Err(TlsError)` if rejected.
fn verify_peer_cert(
    end_entity: &CertificateDer<'_>,
    trust_store: &dyn TrustStore,
    policy: TrustPolicy,
) -> Result<(), TlsError> {
    // Extract Ed25519 public key from the certificate.
    let pubkey = extract_ed25519_public_key(end_entity)
        .map_err(|e| TlsError::General(format!("failed to extract Ed25519 key from cert: {e}")))?;

    let pod_id = PodId::from_public_key(&pubkey);

    // Always reject denied peers.
    if trust_store.is_denied(&pod_id) {
        return Err(TlsError::General(format!(
            "peer {} is denied",
            pod_id.short_id()
        )));
    }

    match policy {
        TrustPolicy::Strict => {
            if !trust_store.is_trusted(&pod_id) {
                return Err(TlsError::General(format!(
                    "peer {} is not trusted (strict mode)",
                    pod_id.short_id()
                )));
            }
        }
        TrustPolicy::PairingMode => {
            // TOFU: auto-trust unknown peers.
            if !trust_store.is_trusted(&pod_id) {
                trust_store.trust(pod_id);
            }
        }
    }

    Ok(())
}

/// Get the ring provider's supported signature verification algorithms.
fn ring_signature_algorithms() -> &'static rustls::crypto::WebPkiSupportedAlgorithms {
    use std::sync::LazyLock;
    static ALGORITHMS: LazyLock<rustls::crypto::WebPkiSupportedAlgorithms> = LazyLock::new(|| {
        rustls::crypto::ring::default_provider().signature_verification_algorithms
    });
    &ALGORITHMS
}

// ---------------------------------------------------------------------------
// Client-side: verifies the server's certificate
// ---------------------------------------------------------------------------

/// Custom server certificate verifier for the TOFU trust model.
///
/// Used by the client to verify the agent's certificate during TLS handshake.
/// Extracts the Ed25519 public key, derives the PodId, and checks the trust
/// store according to the configured policy.
#[derive(Debug)]
pub struct PodServerCertVerifier {
    trust_store: Arc<dyn TrustStore>,
    policy: TrustPolicy,
}

impl PodServerCertVerifier {
    pub fn new(trust_store: Arc<dyn TrustStore>, policy: TrustPolicy) -> Self {
        Self {
            trust_store,
            policy,
        }
    }
}

impl std::fmt::Debug for dyn TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("dyn TrustStore")
    }
}

impl ServerCertVerifier for PodServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        verify_peer_cert(end_entity, &*self.trust_store, self.policy)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, ring_signature_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, ring_signature_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring_signature_algorithms().supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Server-side: verifies the client's certificate
// ---------------------------------------------------------------------------

/// Custom client certificate verifier for the TOFU trust model.
///
/// Used by the agent to verify the client's certificate during mTLS handshake.
/// Extracts the Ed25519 public key, derives the PodId, and checks the trust
/// store according to the configured policy.
#[derive(Debug)]
pub struct PodClientCertVerifier {
    trust_store: Arc<dyn TrustStore>,
    policy: TrustPolicy,
}

impl PodClientCertVerifier {
    pub fn new(trust_store: Arc<dyn TrustStore>, policy: TrustPolicy) -> Self {
        Self {
            trust_store,
            policy,
        }
    }
}

impl ClientCertVerifier for PodClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No CA roots — self-signed certificates. Return empty.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        verify_peer_cert(end_entity, &*self.trust_store, self.policy)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, ring_signature_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, ring_signature_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring_signature_algorithms().supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Certificate, Keypair};
    use crate::trust::MemoryTrustStore;

    const JAN_1_2025: i64 = 1735689600;

    fn make_cert_der() -> (Keypair, Vec<u8>) {
        let kp = Keypair::generate();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert gen");
        (kp, cert.der().to_vec())
    }

    #[test]
    fn pairing_mode_auto_trusts_unknown_peer() {
        let store = Arc::new(MemoryTrustStore::new());
        let (kp, cert_der) = make_cert_der();
        let pod_id = PodId::from_public_key(&kp.public_key_bytes());

        assert!(!store.is_trusted(&pod_id));

        let cert = CertificateDer::from(cert_der);
        let result = verify_peer_cert(&cert, &*store, TrustPolicy::PairingMode);
        assert!(result.is_ok());
        assert!(store.is_trusted(&pod_id));
    }

    #[test]
    fn strict_rejects_unknown_peer() {
        let store = Arc::new(MemoryTrustStore::new());
        let (_kp, cert_der) = make_cert_der();

        let cert = CertificateDer::from(cert_der);
        let result = verify_peer_cert(&cert, &*store, TrustPolicy::Strict);
        assert!(result.is_err());
    }

    #[test]
    fn strict_accepts_trusted_peer() {
        let store = Arc::new(MemoryTrustStore::new());
        let (kp, cert_der) = make_cert_der();
        let pod_id = PodId::from_public_key(&kp.public_key_bytes());

        store.trust(pod_id);

        let cert = CertificateDer::from(cert_der);
        let result = verify_peer_cert(&cert, &*store, TrustPolicy::Strict);
        assert!(result.is_ok());
    }

    #[test]
    fn denied_peer_rejected_in_pairing_mode() {
        let store = Arc::new(MemoryTrustStore::new());
        let (kp, cert_der) = make_cert_der();
        let pod_id = PodId::from_public_key(&kp.public_key_bytes());

        store.deny(pod_id);

        let cert = CertificateDer::from(cert_der);
        let result = verify_peer_cert(&cert, &*store, TrustPolicy::PairingMode);
        assert!(result.is_err());
    }

    #[test]
    fn denied_peer_rejected_in_strict_mode() {
        let store = Arc::new(MemoryTrustStore::new());
        let (kp, cert_der) = make_cert_der();
        let pod_id = PodId::from_public_key(&kp.public_key_bytes());

        // Trust first, then deny (deny should override trust).
        store.trust(pod_id.clone());
        store.deny(pod_id);

        let cert = CertificateDer::from(cert_der);
        let result = verify_peer_cert(&cert, &*store, TrustPolicy::Strict);
        assert!(result.is_err());
    }

    #[test]
    fn garbage_cert_rejected() {
        let store = Arc::new(MemoryTrustStore::new());
        let cert = CertificateDer::from(vec![0u8; 10]);
        let result = verify_peer_cert(&cert, &*store, TrustPolicy::PairingMode);
        assert!(result.is_err());
    }
}
