//! OpenPod client-side transport core.
//!
//! Provides the headless networking engine consumed by any Pod client
//! application (Flutter app, native iOS, CLI, etc.):
//!
//! - QUIC client (connection initiation via quinn)
//! - mDNS service browser (discovers `_openpod._udp.local` agents)
//! - Client-side mTLS handshake
//! - Tri-channel session multiplexing (semantic, telemetry, control)
//! - Media upload via background QUIC streams

pub mod connection;
pub mod endpoint;
pub mod error;
pub mod stream_io;

pub use connection::PodConnection;
pub use endpoint::ClientEndpoint;
pub use error::ClientError;
