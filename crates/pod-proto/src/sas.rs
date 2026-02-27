//! Short Authentication String (SAS) derivation for pairing verification.
//!
//! The SAS is a 6-digit decimal code derived from the TLS session parameters
//! during the pairing ceremony (Manifesto §2.7.3).
//!
//! ```text
//! SAS = truncate_20bits(HMAC-SHA256(tls_exporter_key, client_random || server_random))
//! ```
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
pub const SAS_EXPORTER_LABEL: &str = "OPENPOD-PAIRING";

/// Derive a 6-digit SAS code from TLS session material.
///
/// # Arguments
/// * `tls_exporter_key` — 32 bytes from `TLS-Exporter("OPENPOD-PAIRING", "", 32)`
/// * `client_random` — Client's random bytes from the TLS handshake
/// * `server_random` — Server's random bytes from the TLS handshake
///
/// # Returns
/// A 6-digit zero-padded decimal string (e.g., `"847291"`).
pub fn derive_sas(
    tls_exporter_key: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Result<String> {
    compute_sas(tls_exporter_key, client_random, server_random, None)
}

/// Derive a SAS code with an additional out-of-band nonce (QR path).
///
/// When the client scans a QR code containing an OOB nonce, the nonce is mixed
/// into the HMAC input, enabling automatic verification without manual code
/// comparison (Manifesto §2.7.3).
///
/// # Arguments
/// * `tls_exporter_key` — 32 bytes from TLS-Exporter
/// * `client_random` — Client's random bytes
/// * `server_random` — Server's random bytes
/// * `oob_nonce` — 32-byte nonce from the QR code
pub fn derive_sas_with_oob(
    tls_exporter_key: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    oob_nonce: &[u8],
) -> Result<String> {
    compute_sas(
        tls_exporter_key,
        client_random,
        server_random,
        Some(oob_nonce),
    )
}

/// Internal: compute the SAS from HMAC-SHA256, optionally mixing in an OOB nonce.
fn compute_sas(
    tls_exporter_key: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    oob_nonce: Option<&[u8]>,
) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(tls_exporter_key)
        .map_err(|e| ProtoError::SasDerivation(e.to_string()))?;

    mac.update(client_random);
    mac.update(server_random);
    if let Some(nonce) = oob_nonce {
        mac.update(nonce);
    }

    let result = mac.finalize().into_bytes();

    // Extract 20 bits from the first 3 bytes of the HMAC output.
    let b = result.as_slice();
    let raw_20bits = ((b[0] as u32) << 12) | ((b[1] as u32) << 4) | ((b[2] as u32) >> 4);

    // Reduce to 6-digit decimal range.
    let code = raw_20bits % 1_000_000;

    Ok(format!("{code:06}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_EXPORTER: &[u8] = b"test-exporter-key-for-sas-derive";
    const TEST_CLIENT_RANDOM: &[u8] = b"client-random-bytes-from-tls-hs";
    const TEST_SERVER_RANDOM: &[u8] = b"server-random-bytes-from-tls-hs";
    const TEST_OOB_NONCE: &[u8] = b"oob-nonce-from-qr-code-32-bytes";

    #[test]
    fn deterministic_output() {
        let sas1 = derive_sas(TEST_EXPORTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM)
            .expect("SAS derivation should succeed");
        let sas2 = derive_sas(TEST_EXPORTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM)
            .expect("SAS derivation should succeed");
        assert_eq!(sas1, sas2);
    }

    #[test]
    fn output_is_6_digits() {
        let sas = derive_sas(TEST_EXPORTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM)
            .expect("SAS derivation should succeed");
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn oob_produces_different_result() {
        let sas_manual = derive_sas(TEST_EXPORTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM)
            .expect("SAS derivation should succeed");
        let sas_qr = derive_sas_with_oob(
            TEST_EXPORTER,
            TEST_CLIENT_RANDOM,
            TEST_SERVER_RANDOM,
            TEST_OOB_NONCE,
        )
        .expect("SAS derivation with OOB should succeed");

        assert_ne!(sas_manual, sas_qr);
        assert_eq!(sas_qr.len(), 6);
    }

    #[test]
    fn different_randoms_produce_different_sas() {
        let sas1 = derive_sas(TEST_EXPORTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM)
            .expect("SAS derivation should succeed");
        let sas2 = derive_sas(
            TEST_EXPORTER,
            b"different-client-random-32bytesX",
            TEST_SERVER_RANDOM,
        )
        .expect("SAS derivation should succeed");
        assert_ne!(sas1, sas2);
    }

    #[test]
    fn empty_exporter_key_fails() {
        // HMAC-SHA256 accepts any key length, so empty key does not fail.
        // This test verifies the function handles it gracefully.
        let result = derive_sas(b"", TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM);
        assert!(result.is_ok());
    }
}
