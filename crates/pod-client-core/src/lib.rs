//! OpenPod client-side transport core.
//!
//! Provides the headless networking engine consumed by any Pod client
//! application (Flutter app, native iOS, CLI, etc.):
//!
//! - QUIC client (connection initiation via quinn)
//! - mDNS service browser (discovers `_openpod._udp.local` agents)
//! - Client-side mTLS handshake
//! - Quad-channel session multiplexing (semantic, telemetry, control, audio)
//! - Datagram demux for Channel C (control) and Channel D (audio)
//! - Media upload via background QUIC streams

pub mod connection;
pub mod endpoint;
pub mod error;
pub mod session;
pub mod stream_io;

pub use connection::{PodConnection, ReceivedDatagram};
pub use endpoint::ClientEndpoint;
pub use error::ClientError;
pub use session::{ClientSession, InboundStream, SessionInitOptions, SessionResumeState};
