//! OpenPod wire protocol definitions.
//!
//! Shared protocol layer used by both `pod-client-core` and `pod-agent-core`:
//!
//! - Compiled protobuf message types (Channel A, B, C)
//! - Shared error types and error code constants
//! - Protocol version constants
//! - Ed25519 identity and X.509 certificate primitives
//! - Short Authentication String (SAS) derivation
//! - Trust store abstraction for TOFU pairing
//! - TLS configuration (certificate extraction, custom verifiers, config builders)
//! - Length-delimited protobuf codec

pub mod codec;
pub mod error;
pub mod identity;
pub mod sas;
pub mod tls;
pub mod trust;
pub mod version;
pub mod wire;
