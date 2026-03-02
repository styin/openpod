//! OpenPod server-side transport core.
//!
//! Provides the networking engine imported by agent gateway adapters
//! (Python SDK, Node.js SDK, etc.):
//!
//! - QUIC server (accepts incoming Pod connections via quinn)
//! - mDNS service advertiser (opt-in, broadcasts `_openpod._udp.local`)
//! - Server-side mTLS handshake and client verification
//! - Tri-channel session multiplexing (semantic, telemetry, control)
//! - `.pod_cache` session file cache management

pub mod connection;
pub mod endpoint;
pub mod error;
pub mod stream_io;

pub use connection::PodConnection;
pub use endpoint::AgentEndpoint;
pub use error::AgentError;
