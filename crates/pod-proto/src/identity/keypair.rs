//! Ed25519 keypair generation and management.
//!
//! Reference implementation: `ed25519-dalek` (MIT/Apache-2.0)
//! <https://github.com/dalek-cryptography/curve25519-dalek>
//!
//! All cryptographic operations are delegated to `ed25519-dalek`. This module
//! is a thin wrapper providing the interface needed by the rest of `pod-proto`.

use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::EncodePrivateKey};
use rand::rngs::OsRng;

use crate::error::{ProtoError, Result};

/// An Ed25519 identity keypair for an OpenPod node.
///
/// The keypair is the node's permanent identity (Manifesto §2.7.1). The signing
/// key (private) must be persisted securely. The verifying key (public) is used
/// to derive the [`PodId`](super::PodId) and is embedded in the self-signed
/// X.509 certificate for mTLS.
///
/// The inner [`SigningKey`] is automatically zeroized on drop.
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random Ed25519 keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Reconstruct a keypair from a 32-byte secret key.
    ///
    /// Used when loading a persisted identity from disk.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Returns the 32-byte secret key for persistence.
    ///
    /// **Security:** The caller is responsible for storing this securely.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the PKCS#8 DER encoding of the keypair.
    ///
    /// This format is required by [`rcgen`] for X.509 certificate generation.
    /// Uses the `pkcs8` feature of `ed25519-dalek` (RFC 8410 encoding).
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let doc = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| ProtoError::KeyGeneration(e.to_string()))?;
        Ok(doc.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_keypair() {
        let kp = Keypair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
        assert_eq!(kp.secret_bytes().len(), 32);
    }

    #[test]
    fn secret_bytes_roundtrip() {
        let kp1 = Keypair::generate();
        let secret = kp1.secret_bytes();
        let kp2 = Keypair::from_secret_bytes(&secret);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn pkcs8_der_is_nonempty() {
        let kp = Keypair::generate();
        let der = kp.to_pkcs8_der().expect("PKCS#8 export should succeed");
        assert!(!der.is_empty());
    }

    #[test]
    fn different_keypairs_differ() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }
}
