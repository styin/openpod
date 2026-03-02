//! Protocol version constants.
//!
//! Protocol version follows semver (Manifesto §2.9):
//! - Major bumps = breaking wire-format changes
//! - Minor/patch bumps = backwards-compatible additions

/// Current protocol version string sent in the `Handshake` message.
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// Major version component. Peers with different major versions are incompatible.
pub const MAJOR: u32 = 0;

/// Minor version component.
pub const MINOR: u32 = 1;

/// Patch version component.
pub const PATCH: u32 = 0;

/// Returns true if `their_version` is wire-compatible with ours.
///
/// During 0.x development, exact `major.minor` match is required (minor bumps
/// are treated as breaking). After 1.0, only the major version must match.
pub fn is_compatible(their_version: &str) -> bool {
    let parts: Vec<&str> = their_version.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let Ok(their_major) = parts[0].parse::<u32>() else {
        return false;
    };
    let Ok(their_minor) = parts[1].parse::<u32>() else {
        return false;
    };

    if MAJOR == 0 {
        // During 0.x development, exact major.minor match required.
        their_major == MAJOR && their_minor == MINOR
    } else {
        // After 1.0, same major version is compatible.
        their_major == MAJOR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_is_compatible() {
        assert!(is_compatible("0.1.0"));
    }

    #[test]
    fn patch_difference_is_compatible() {
        assert!(is_compatible("0.1.5"));
    }

    #[test]
    fn minor_difference_incompatible_during_0x() {
        assert!(!is_compatible("0.2.0"));
        assert!(!is_compatible("0.0.1"));
    }

    #[test]
    fn major_difference_incompatible() {
        assert!(!is_compatible("1.0.0"));
        assert!(!is_compatible("2.1.0"));
    }

    #[test]
    fn malformed_versions_rejected() {
        assert!(!is_compatible(""));
        assert!(!is_compatible("garbage"));
        assert!(!is_compatible("1.0"));
        assert!(!is_compatible("1.0.0.0"));
        assert!(!is_compatible("a.b.c"));
    }
}
