//! OpenPod wire protocol definitions.
//!
//! Shared protocol layer used by both `pod-client-core` and `pod-agent-core`:
//!
//! - Compiled protobuf message types (Channel A, B, C)
//! - Shared error types and error code constants
//! - Protocol version constants
//! - Ed25519 identity and X.509 certificate primitives
//! - Short Authentication String (SAS) derivation

pub mod error;
pub mod identity;
pub mod sas;
pub mod version;
pub mod wire;
