//! TLS configuration builders for QUIC server and client endpoints.
//!
//! Constructs `rustls::ServerConfig` and `rustls::ClientConfig` with custom
//! TOFU verifiers, TLS 1.3, and Ed25519 client certificates.
//!
//! Both builders enforce:
//! - TLS 1.3 only (required by QUIC)
//! - Ring crypto provider
//! - Ed25519 self-signed certificates
//! - Custom verifiers backed by a shared [`TrustStore`]

use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::{ProtoError, Result};
use crate::identity::{Certificate, Keypair};
use crate::tls::verifier::{PodClientCertVerifier, PodServerCertVerifier};
use crate::trust::{TrustPolicy, TrustStore};

/// Build a `rustls::ServerConfig` for the agent (QUIC server) side.
///
/// The config requires client certificates (mTLS) and verifies them using
/// the provided trust store and policy.
pub fn build_server_tls_config(
    keypair: &Keypair,
    cert: &Certificate,
    trust_store: Arc<dyn TrustStore>,
    policy: TrustPolicy,
) -> Result<rustls::ServerConfig> {
    let verifier: Arc<dyn ClientCertVerifier> =
        Arc::new(PodClientCertVerifier::new(trust_store, policy));

    let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
    let private_key = private_key_from_keypair(keypair)?;

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| ProtoError::TlsConfiguration(format!("TLS version config: {e}")))?
    .with_client_cert_verifier(verifier)
    .with_single_cert(cert_chain, private_key)
    .map_err(|e| ProtoError::TlsConfiguration(format!("server cert config: {e}")))?;

    // QUIC requires ALPN — use our protocol identifier.
    config.alpn_protocols = vec![b"openpod".to_vec()];

    Ok(config)
}

/// Build a `rustls::ClientConfig` for the client (QUIC client) side.
///
/// The config presents a client certificate for mTLS and verifies the server's
/// certificate using the provided trust store and policy.
pub fn build_client_tls_config(
    keypair: &Keypair,
    cert: &Certificate,
    trust_store: Arc<dyn TrustStore>,
    policy: TrustPolicy,
) -> Result<rustls::ClientConfig> {
    let verifier: Arc<dyn ServerCertVerifier> =
        Arc::new(PodServerCertVerifier::new(trust_store, policy));

    let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
    let private_key = private_key_from_keypair(keypair)?;

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| ProtoError::TlsConfiguration(format!("TLS version config: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(cert_chain, private_key)
    .map_err(|e| ProtoError::TlsConfiguration(format!("client cert config: {e}")))?;

    // QUIC requires ALPN — use our protocol identifier.
    config.alpn_protocols = vec![b"openpod".to_vec()];

    Ok(config)
}

/// Convert an OpenPod keypair to a rustls `PrivateKeyDer`.
fn private_key_from_keypair(keypair: &Keypair) -> Result<PrivateKeyDer<'static>> {
    let pkcs8_bytes = keypair.to_pkcs8_der()?;
    let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8_bytes);
    Ok(PrivateKeyDer::Pkcs8(pkcs8))
}

/// ALPN protocol identifier used by OpenPod.
pub const ALPN_OPENPOD: &[u8] = b"openpod";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::MemoryTrustStore;

    const JAN_1_2025: i64 = 1735689600;

    fn make_keypair_and_cert() -> (Keypair, Certificate) {
        let kp = Keypair::generate();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert gen");
        (kp, cert)
    }

    #[test]
    fn server_config_builds_successfully() {
        let (kp, cert) = make_keypair_and_cert();
        let store = Arc::new(MemoryTrustStore::new());
        let config = build_server_tls_config(&kp, &cert, store, TrustPolicy::PairingMode);
        assert!(config.is_ok());
    }

    #[test]
    fn client_config_builds_successfully() {
        let (kp, cert) = make_keypair_and_cert();
        let store = Arc::new(MemoryTrustStore::new());
        let config = build_client_tls_config(&kp, &cert, store, TrustPolicy::PairingMode);
        assert!(config.is_ok());
    }

    #[test]
    fn server_config_has_alpn() {
        let (kp, cert) = make_keypair_and_cert();
        let store = Arc::new(MemoryTrustStore::new());
        let config = build_server_tls_config(&kp, &cert, store, TrustPolicy::PairingMode).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"openpod".to_vec()]);
    }

    #[test]
    fn client_config_has_alpn() {
        let (kp, cert) = make_keypair_and_cert();
        let store = Arc::new(MemoryTrustStore::new());
        let config = build_client_tls_config(&kp, &cert, store, TrustPolicy::PairingMode).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"openpod".to_vec()]);
    }
}
