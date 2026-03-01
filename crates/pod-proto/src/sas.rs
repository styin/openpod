//! Short Authentication String (SAS) derivation for pairing verification.
//!
//! The SAS is a 6-digit decimal code derived from the TLS session parameters
//! during the pairing ceremony (Manifesto §2.7.3).
//!
//! **Manual path (no QR):**
//! ```text
//! SAS = truncate_20bits(TLS-Exporter("OPENPOD-SAS", "", 32))
//! ```
//!
//! **QR/OOB path:**
//! ```text
//! SAS = truncate_20bits(HMAC-SHA256(TLS-Exporter("OPENPOD-SAS", "", 32), oob_nonce))
//! ```
//!
//! The TLS exporter output already incorporates the full handshake transcript
//! (client_random, server_random, ECDHE exchange) per RFC 8446 §7.5.
//! No additional handshake parameter mixing is needed (validated by RFC 9266).
//!
//! Displayed as a zero-padded 6-digit decimal: `"000000"` to `"999999"`.
//! 20 bits yields 0–1,048,575; we take mod 1,000,000 for clean decimal display.
//!
//! Reference: `hmac` + `sha2` crates (RustCrypto, MIT/Apache-2.0)
//! <https://github.com/RustCrypto/MACs>

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{ProtoError, Result};

type HmacSha256 = Hmac<Sha256>;

/// The TLS exporter label used for SAS derivation.
pub const SAS_EXPORTER_LABEL: &str = "OPENPOD-SAS";

/// Derive a 6-digit SAS code from TLS exporter keying material.
///
/// # Arguments
/// * `tls_exporter_key` — 32 bytes from `TLS-Exporter("OPENPOD-SAS", "", 32)`
///
/// # Returns
/// A 6-digit zero-padded decimal string (e.g., `"847291"`).
pub fn derive_sas(tls_exporter_key: &[u8]) -> Result<String> {
    if tls_exporter_key.is_empty() {
        return Err(ProtoError::SasDerivation(
            "exporter key must not be empty".into(),
        ));
    }
    Ok(truncate_to_6_digits(tls_exporter_key))
}

/// Derive a SAS code with an additional out-of-band nonce (QR path).
///
/// When the client scans a QR code containing an OOB nonce, the nonce is mixed
/// into the derivation via HMAC, enabling automatic verification without manual
/// code comparison (Manifesto §2.7.3).
///
/// # Arguments
/// * `tls_exporter_key` — 32 bytes from TLS-Exporter
/// * `oob_nonce` — 32-byte nonce from the QR code
pub fn derive_sas_with_oob(tls_exporter_key: &[u8], oob_nonce: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(tls_exporter_key)
        .map_err(|e| ProtoError::SasDerivation(e.to_string()))?;

    mac.update(oob_nonce);

    let result = mac.finalize().into_bytes();
    Ok(truncate_to_6_digits(result.as_slice()))
}

/// Extract 20 bits from the first 3 bytes and reduce to a 6-digit decimal.
fn truncate_to_6_digits(bytes: &[u8]) -> String {
    let b = bytes;
    let raw_20bits = ((b[0] as u32) << 12) | ((b[1] as u32) << 4) | ((b[2] as u32) >> 4);
    let code = raw_20bits % 1_000_000;
    format!("{code:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_EXPORTER: &[u8] = b"test-exporter-key-for-sas-derive";

    #[test]
    fn deterministic_output() {
        let sas1 = derive_sas(TEST_EXPORTER).expect("SAS derivation should succeed");
        let sas2 = derive_sas(TEST_EXPORTER).expect("SAS derivation should succeed");
        assert_eq!(sas1, sas2);
    }

    #[test]
    fn output_is_6_digits() {
        let sas = derive_sas(TEST_EXPORTER).expect("SAS derivation should succeed");
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn oob_produces_different_result() {
        let sas_manual = derive_sas(TEST_EXPORTER).expect("SAS derivation should succeed");
        let oob_nonce = b"oob-nonce-from-qr-code-32-bytes";
        let sas_qr = derive_sas_with_oob(TEST_EXPORTER, oob_nonce).expect("OOB SAS should succeed");

        assert_ne!(sas_manual, sas_qr);
        assert_eq!(sas_qr.len(), 6);
    }

    #[test]
    fn different_exporters_produce_different_sas() {
        let sas1 = derive_sas(TEST_EXPORTER).expect("SAS 1 should succeed");
        let sas2 = derive_sas(b"different-exporter-key-32-bytes!").expect("SAS 2 should succeed");
        assert_ne!(sas1, sas2);
    }

    #[test]
    fn empty_exporter_key_fails() {
        let result = derive_sas(b"");
        assert!(result.is_err());
    }
}
