//! Generated protobuf types for the OpenPod wire protocol.
//!
//! These types are compiled from `proto/pod_protocol.proto` by `prost-build`
//! at build time. See that file for field-level documentation.

/// All message types in the `pod` protobuf package.
pub mod pod {
    include!(concat!(env!("OUT_DIR"), "/pod.rs"));
}

// Re-export top-level types for convenience.
pub use pod::*;
