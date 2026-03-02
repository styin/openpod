//! Self-signed X.509 certificate generation for OpenPod mTLS.
//!
//! Each node wraps its Ed25519 identity key in a self-signed X.509 certificate
//! with 30-day validity. The certificate rotates at day 22 (75% of validity).
//! Peers verify the PodId (derived from the key), not the certificate itself.
//!
//! Reference: `rcgen` crate (rustls team, MIT/Apache-2.0)
//! <https://github.com/rustls/rcgen>

use rcgen::{CertificateParams, KeyPair as RcgenKeyPair, PKCS_ED25519};
use rustls_pki_types::PrivatePkcs8KeyDer;
use time::OffsetDateTime;

use crate::error::{ProtoError, Result};
use crate::identity::keypair::Keypair;

/// Certificate validity duration in days (Manifesto §2.7.2).
const VALIDITY_DAYS: i64 = 30;

/// Rotation threshold as a fraction of validity (75% = day 22).
const ROTATION_THRESHOLD: f64 = 0.75;

/// A self-signed X.509 certificate wrapping an Ed25519 identity key.
pub struct Certificate {
    /// DER-encoded certificate bytes.
    cert_der: Vec<u8>,
    /// PEM-encoded certificate string.
    cert_pem: String,
    /// When this certificate becomes valid (seconds since Unix epoch).
    not_before_epoch: i64,
    /// When this certificate expires (seconds since Unix epoch).
    not_after_epoch: i64,
}

impl Certificate {
    /// Generate a new self-signed certificate for the given identity keypair.
    ///
    /// The certificate is valid for 30 days starting from `now_epoch_secs`
    /// (seconds since Unix epoch).
    pub fn generate(keypair: &Keypair, now_epoch_secs: i64) -> Result<Self> {
        // Export the identity key as PKCS#8 DER for rcgen.
        let pkcs8_der = keypair.to_pkcs8_der()?;
        let pkcs8_typed = PrivatePkcs8KeyDer::from(pkcs8_der);
        let rcgen_keypair = RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_typed, &PKCS_ED25519)
            .map_err(|e| ProtoError::CertificateGeneration(e.to_string()))?;

        let not_before_epoch = now_epoch_secs;
        let not_after_epoch = now_epoch_secs + VALIDITY_DAYS * 86400;

        let not_before = OffsetDateTime::from_unix_timestamp(not_before_epoch)
            .map_err(|e| ProtoError::CertificateGeneration(format!("invalid not_before: {e}")))?;
        let not_after = OffsetDateTime::from_unix_timestamp(not_after_epoch)
            .map_err(|e| ProtoError::CertificateGeneration(format!("invalid not_after: {e}")))?;

        // Build certificate parameters.
        let mut params = CertificateParams::new(vec![])
            .map_err(|e| ProtoError::CertificateGeneration(format!("invalid cert params: {e}")))?;
        params.not_before = not_before;
        params.not_after = not_after;

        let cert = params
            .self_signed(&rcgen_keypair)
            .map_err(|e| ProtoError::CertificateGeneration(e.to_string()))?;

        let cert_der = cert.der().to_vec();
        let cert_pem = cert.pem();

        Ok(Self {
            cert_der,
            cert_pem,
            not_before_epoch,
            not_after_epoch,
        })
    }

    /// Returns true if the certificate should be rotated (past 75% of validity).
    pub fn needs_rotation(&self, now_epoch_secs: i64) -> bool {
        let total = (self.not_after_epoch - self.not_before_epoch) as f64;
        let elapsed = (now_epoch_secs - self.not_before_epoch) as f64;
        if total <= 0.0 {
            return true;
        }
        elapsed / total >= ROTATION_THRESHOLD
    }

    /// Returns the DER-encoded certificate bytes.
    pub fn der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Returns the PEM-encoded certificate string.
    pub fn pem(&self) -> &str {
        &self.cert_pem
    }

    /// Returns the expiration time as seconds since Unix epoch.
    pub fn not_after_epoch(&self) -> i64 {
        self.not_after_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    /// Reference epoch: 2025-01-01 00:00:00 UTC.
    const JAN_1_2025: i64 = 1735689600;

    #[test]
    fn generate_produces_nonempty_der() {
        let kp = test_keypair();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");
        assert!(!cert.der().is_empty());
    }

    #[test]
    fn generate_produces_valid_pem() {
        let kp = test_keypair();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");
        assert!(cert.pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn rotation_not_needed_at_start() {
        let kp = test_keypair();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");
        assert!(!cert.needs_rotation(JAN_1_2025));
    }

    #[test]
    fn rotation_not_needed_at_day_10() {
        let kp = test_keypair();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");
        assert!(!cert.needs_rotation(JAN_1_2025 + 10 * 86400));
    }

    #[test]
    fn rotation_not_needed_at_day_21() {
        let kp = test_keypair();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");
        assert!(!cert.needs_rotation(JAN_1_2025 + 21 * 86400));
    }

    #[test]
    fn rotation_needed_at_day_22_point_5() {
        let kp = test_keypair();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");
        // 22.5 days = 75% of 30 days.
        assert!(cert.needs_rotation(JAN_1_2025 + 22 * 86400 + 43200));
    }

    #[test]
    fn rotation_needed_at_day_30() {
        let kp = test_keypair();
        let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert generation should succeed");
        assert!(cert.needs_rotation(JAN_1_2025 + 30 * 86400));
    }

    #[test]
    fn same_keypair_produces_valid_cert_twice() {
        let kp = test_keypair();
        let cert1 =
            Certificate::generate(&kp, JAN_1_2025).expect("first cert generation should succeed");
        let cert2 = Certificate::generate(&kp, JAN_1_2025 + 1)
            .expect("second cert generation should succeed");
        assert!(!cert1.der().is_empty());
        assert!(!cert2.der().is_empty());
    }
}
