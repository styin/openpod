//! PodId: the human-readable node identity derived from an Ed25519 public key.
//!
//! PodId = SHA-256(public key), stored as a full 32-byte hash for exact trust
//! store matching. The display format uses the first 24 base32 characters
//! (120 bits) plus 4 Luhn check digits (one per group of 6 data characters):
//! `XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX`.
//!
//! The display format is a lossy human-readable projection — it is never used
//! for trust decisions. Trust matching always uses the full 32-byte hash.
//!
//! SHA-256 reference: `sha2` crate (RustCrypto, MIT/Apache-2.0)
//! Base32 reference: `data-encoding` crate (MIT/Apache-2.0)
//! Luhn mod-32 algorithm: adapted from Syncthing device ID pattern
//!   <https://docs.syncthing.net/dev/device-ids.html>

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

use crate::error::Result;

/// The base32 alphabet (RFC 4648) used for Luhn mod-N computation.
const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Number of groups in the display format.
const GROUP_COUNT: usize = 4;

/// Number of data characters per group (before the Luhn check digit).
const DATA_CHARS_PER_GROUP: usize = 6;

/// Total data characters across all groups.
const TOTAL_DATA_CHARS: usize = GROUP_COUNT * DATA_CHARS_PER_GROUP; // 24

/// A PodId uniquely identifies an OpenPod node.
///
/// Internally stores the full 32-byte SHA-256 hash for exact matching in trust
/// stores. The human-readable display format is a truncated base32 string with
/// Luhn check digits: `XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PodId {
    hash: [u8; 32],
}

impl PodId {
    /// Derive a PodId from an Ed25519 public key (32 bytes).
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        let hash: [u8; 32] = Sha256::digest(public_key).into();
        Self { hash }
    }

    /// Construct a PodId from a raw 32-byte hash (for trust store lookups).
    pub fn from_hash(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Returns the full 32-byte hash for exact comparison in trust stores.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Returns the display string: `XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX`.
    pub fn to_display(&self) -> String {
        // Encode the full hash as base32, then take the first 24 characters.
        let full_b32 = BASE32_NOPAD.encode(&self.hash);
        let data = &full_b32[..TOTAL_DATA_CHARS];

        let mut groups = Vec::with_capacity(GROUP_COUNT);
        for i in 0..GROUP_COUNT {
            let group_data = &data[i * DATA_CHARS_PER_GROUP..(i + 1) * DATA_CHARS_PER_GROUP];
            let check = luhn32_check_char(group_data)
                .expect("base32 data should always produce valid Luhn input");
            groups.push(format!("{group_data}{check}"));
        }

        groups.join("-")
    }

    /// Returns just the first 7-character group (used in mDNS TXT records).
    pub fn short_id(&self) -> String {
        let display = self.to_display();
        display[..7].to_string()
    }
}

impl std::fmt::Display for PodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_display())
    }
}

impl std::fmt::Debug for PodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PodId({})", self.to_display())
    }
}

/// Compute a Luhn mod-32 check character for the given base32 string.
///
/// Algorithm: Luhn mod N where N=32, over the base32 alphabet A-Z2-7.
/// Reference: <https://en.wikipedia.org/wiki/Luhn_mod_N_algorithm>
/// Syncthing uses this for device IDs: <https://docs.syncthing.net/dev/device-ids.html>
fn luhn32_check_char(s: &str) -> Result<char> {
    let n = BASE32_ALPHABET.len() as u32; // 32
    let mut factor = 1u32;
    let mut sum = 0u32;

    // Process characters from right to left.
    for ch in s.chars().rev() {
        let code_point = base32_char_value(ch)?;
        let mut addend = factor * code_point;
        factor = if factor == 2 { 1 } else { 2 };
        addend = (addend / n) + (addend % n);
        sum += addend;
    }

    let remainder = sum % n;
    let check_value = (n - remainder) % n;

    Ok(BASE32_ALPHABET[check_value as usize] as char)
}

/// Map a base32 character to its numeric value (0–31).
fn base32_char_value(ch: char) -> Result<u32> {
    match ch {
        'A'..='Z' => Ok(ch as u32 - 'A' as u32),
        '2'..='7' => Ok(ch as u32 - '2' as u32 + 26),
        _ => Err(crate::error::ProtoError::InvalidPodId(format!(
            "invalid base32 character: '{ch}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProtoError;

    /// A fixed public key for deterministic tests.
    fn test_public_key() -> [u8; 32] {
        [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x25, 0x44, 0x85, 0x16, 0x89,
            0xc6, 0x07, 0xfd, 0x54,
        ]
    }

    /// Validate that a 7-character group has a correct Luhn check digit.
    /// Kept in test module to verify to_display() generates correct check digits.
    fn validate_luhn_group(group: &str) -> Result<()> {
        if group.len() != 7 {
            return Err(ProtoError::InvalidPodId(format!(
                "group must be 7 characters, got {}",
                group.len()
            )));
        }

        let data = &group[..6];
        let expected_check = group.as_bytes()[6] as char;
        let computed_check = luhn32_check_char(data)?;

        if expected_check != computed_check {
            return Err(ProtoError::PodIdChecksumMismatch);
        }

        Ok(())
    }

    #[test]
    fn deterministic_derivation() {
        let pod_id1 = PodId::from_public_key(&test_public_key());
        let pod_id2 = PodId::from_public_key(&test_public_key());
        assert_eq!(pod_id1, pod_id2);
        assert_eq!(pod_id1.to_display(), pod_id2.to_display());
    }

    #[test]
    fn display_format_is_correct() {
        let pod_id = PodId::from_public_key(&test_public_key());
        let display = pod_id.to_display();

        // Format: XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX
        let groups: Vec<&str> = display.split('-').collect();
        assert_eq!(groups.len(), 4, "expected 4 groups, got: {display}");
        for group in &groups {
            assert_eq!(group.len(), 7, "each group must be 7 chars: {group}");
            assert!(
                group
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
                "invalid base32 character in group: {group}"
            );
        }
    }

    #[test]
    fn luhn_check_digits_validate() {
        let pod_id = PodId::from_public_key(&test_public_key());
        let display = pod_id.to_display();

        for group in display.split('-') {
            assert!(
                validate_luhn_group(group).is_ok(),
                "Luhn validation failed for group: {group}"
            );
        }
    }

    #[test]
    fn short_id_returns_first_group() {
        let pod_id = PodId::from_public_key(&test_public_key());
        let display = pod_id.to_display();
        let first_group = display.split('-').next().unwrap();
        assert_eq!(pod_id.short_id(), first_group);
    }

    #[test]
    fn different_keys_produce_different_pod_ids() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let pod_id1 = PodId::from_public_key(&key1);
        let pod_id2 = PodId::from_public_key(&key2);
        assert_ne!(pod_id1, pod_id2);
        assert_ne!(pod_id1.to_display(), pod_id2.to_display());
    }
}
