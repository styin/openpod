//! PodId: the human-readable node identity derived from an Ed25519 public key.
//!
//! PodId = SHA-256(public key), displayed as base32 with Luhn check digits.
//! Display format: `XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX` (4 groups of 7 chars).
//!
//! Internally stores the full 32-byte SHA-256 hash for exact trust store matching.
//! The display format uses the first 24 base32 characters (120 bits) plus 4
//! Luhn check digits (one per group of 6 data characters).
//!
//! SHA-256 reference: `sha2` crate (RustCrypto, MIT/Apache-2.0)
//! Base32 reference: `data-encoding` crate (MIT/Apache-2.0)
//! Luhn mod-32 algorithm: adapted from Syncthing device ID pattern
//!   <https://docs.syncthing.net/dev/device-ids.html>

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

use crate::error::{ProtoError, Result};

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

    /// Parse a PodId from its display string.
    ///
    /// Accepts format `XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX` (with or without
    /// dashes). Validates Luhn check digits.
    pub fn from_display(s: &str) -> Result<Self> {
        // Strip dashes.
        let stripped: String = s.chars().filter(|c| *c != '-').collect();
        let stripped = stripped.to_ascii_uppercase();

        // Expect 28 characters: 4 groups × 7 chars (6 data + 1 check).
        if stripped.len() != GROUP_COUNT * 7 {
            return Err(ProtoError::InvalidPodId(format!(
                "expected 28 characters (excluding dashes), got {}",
                stripped.len()
            )));
        }

        // Validate each group's Luhn check digit and collect data characters.
        let mut data_chars = String::with_capacity(TOTAL_DATA_CHARS);
        for i in 0..GROUP_COUNT {
            let group = &stripped[i * 7..(i + 1) * 7];
            validate_luhn_group(group)?;
            data_chars.push_str(&group[..DATA_CHARS_PER_GROUP]);
        }

        // Decode the 24 base32 data characters back to bytes.
        // 24 base32 chars = 15 bytes = 120 bits.
        let decoded = BASE32_NOPAD
            .decode(data_chars.as_bytes())
            .map_err(|e| ProtoError::InvalidPodId(format!("base32 decode: {e}")))?;

        // We can only recover 15 bytes from the display format. Pad the
        // remaining 17 bytes with zeros. This means `from_display` produces a
        // PodId that matches the original in display output but NOT in
        // `as_bytes()` (which returns the full hash). For trust store matching,
        // always use the full hash from `from_public_key()`.
        let mut hash = [0u8; 32];
        hash[..decoded.len()].copy_from_slice(&decoded);

        Ok(Self { hash })
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

/// Validate that a 7-character group has a correct Luhn check digit (7th char).
fn validate_luhn_group(group: &str) -> Result<()> {
    if group.len() != 7 {
        return Err(ProtoError::InvalidPodId(format!(
            "group must be 7 characters, got {}",
            group.len()
        )));
    }

    let data = &group[..6];
    let expected_check = group.chars().nth(6).unwrap();
    let computed_check = luhn32_check_char(data)?;

    if expected_check != computed_check {
        return Err(ProtoError::PodIdChecksumMismatch);
    }

    Ok(())
}

/// Map a base32 character to its numeric value (0–31).
fn base32_char_value(ch: char) -> Result<u32> {
    match ch {
        'A'..='Z' => Ok(ch as u32 - 'A' as u32),
        '2'..='7' => Ok(ch as u32 - '2' as u32 + 26),
        _ => Err(ProtoError::InvalidPodId(format!(
            "invalid base32 character: '{ch}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed public key for deterministic tests.
    fn test_public_key() -> [u8; 32] {
        [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x25, 0x44, 0x85, 0x16, 0x89,
            0xc6, 0x07, 0xfd, 0x54,
        ]
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
    fn display_roundtrip() {
        let pod_id = PodId::from_public_key(&test_public_key());
        let display = pod_id.to_display();
        let parsed = PodId::from_display(&display).expect("should parse own display output");
        assert_eq!(parsed.to_display(), display);
    }

    #[test]
    fn display_roundtrip_without_dashes() {
        let pod_id = PodId::from_public_key(&test_public_key());
        let display = pod_id.to_display();
        let no_dashes: String = display.chars().filter(|c| *c != '-').collect();
        let parsed = PodId::from_display(&no_dashes).expect("should parse without dashes");
        assert_eq!(parsed.to_display(), display);
    }

    #[test]
    fn rejects_wrong_check_digit() {
        let pod_id = PodId::from_public_key(&test_public_key());
        let display = pod_id.to_display();
        let mut chars: Vec<char> = display.chars().collect();

        // Corrupt the last character (a Luhn check digit).
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();

        assert!(PodId::from_display(&corrupted).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(PodId::from_display("TOO-SHORT").is_err());
        assert!(PodId::from_display("").is_err());
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

    #[test]
    fn case_insensitive_parsing() {
        let pod_id = PodId::from_public_key(&test_public_key());
        let display = pod_id.to_display();
        let lower = display.to_lowercase();
        let parsed = PodId::from_display(&lower).expect("should accept lowercase");
        assert_eq!(parsed.to_display(), display);
    }
}
