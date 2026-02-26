//! OpenPod wire protocol definitions.
//!
//! Shared protocol layer used by both `pod-client-core` and `pod-agent-core`:
//!
//! - Compiled protobuf message types (Channel A, B, C)
//! - TOON (Token-Oriented Object Notation) codec
//! - mTLS certificate and identity primitives
//! - Tri-channel framing types

// Re-export generated protobuf types once `pod_protocol.proto` is compiled.
// pub mod pod_protocol {
//     include!(concat!(env!("OUT_DIR"), "/pod.rs"));
// }
