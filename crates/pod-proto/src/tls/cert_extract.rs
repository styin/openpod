//! Extract Ed25519 public key from X.509 DER certificates.
//!
//! After a QUIC handshake, `quinn::Connection::peer_identity()` provides the
//! peer's certificate chain as `Vec<CertificateDer>`. This module extracts the
//! Ed25519 public key from the leaf certificate so we can derive the peer's
//! PodId.
//!
//! Reference: `x509-parser` crate (rusticata, MIT/Apache-2.0)

use x509_parser::prelude::*;

use crate::error::{ProtoError, Result};

/// Ed25519 OID: 1.3.101.112
///
/// Re-exported from `oid-registry` (transitive dep of `x509-parser`).
const ED25519_OID: &[u64] = &[1, 3, 101, 112];

/// Extract the raw 32-byte Ed25519 public key from a DER-encoded X.509
/// certificate.
///
/// Returns an error if:
/// - The certificate cannot be parsed
/// - The algorithm is not Ed25519
/// - The public key is not exactly 32 bytes
pub fn extract_ed25519_public_key(cert_der: &[u8]) -> Result<[u8; 32]> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| ProtoError::CertificateVerification(format!("X.509 parse error: {e}")))?;

    let spki = cert.public_key();

    // Build the expected OID and compare.
    let expected_oid = oid_registry::Oid::from(ED25519_OID).expect("Ed25519 OID constant is valid");
    if spki.algorithm.algorithm != expected_oid {
        return Err(ProtoError::CertificateVerification(format!(
            "expected Ed25519 algorithm OID (1.3.101.112), got {}",
            spki.algorithm.algorithm
        )));
    }

    // The SubjectPublicKeyInfo's subject_public_key is a BitString.
    // For Ed25519, the raw 32-byte key is the content (no ASN.1 wrapping).
    let raw_key = spki.subject_public_key.as_ref();

    if raw_key.len() != 32 {
        return Err(ProtoError::CertificateVerification(format!(
            "expected 32-byte Ed25519 public key, got {} bytes",
            raw_key.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(raw_key);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Certificate, Keypair, PodId};

    /// Reference epoch: 2025-01-01 00:00:00 UTC.
    const JAN_1_2025: i64 = 1735689600;

    #[test]
    fn extract_key_matches_original() {
        let kp = Keypair::generate();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");

        let extracted =
            extract_ed25519_public_key(cert.der()).expect("key extraction should succeed");

        assert_eq!(extracted, kp.public_key_bytes());
    }

    #[test]
    fn extracted_key_derives_same_pod_id() {
        let kp = Keypair::generate();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");

        let extracted =
            extract_ed25519_public_key(cert.der()).expect("key extraction should succeed");
        let pod_id_from_cert = PodId::from_public_key(&extracted);
        let pod_id_from_key = PodId::from_public_key(&kp.public_key_bytes());

        assert_eq!(pod_id_from_cert, pod_id_from_key);
    }

    #[test]
    fn rejects_garbage_input() {
        let result = extract_ed25519_public_key(b"not a certificate");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_input() {
        let result = extract_ed25519_public_key(b"");
        assert!(result.is_err());
    }
}
