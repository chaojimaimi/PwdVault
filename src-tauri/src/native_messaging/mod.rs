//! Native Messaging Server
//!
//! Provides an HTTP server for browser extension communication.
//!
//! Module layout (submodules are private; the public surface is re-exported
//! here unchanged):
//! - `protocol` — wire types (`NativeRequest` / `NativeResponse`), the
//!   per-connection auth gates (path / protocol version / Origin / Bearer)
//!   and the pair-endpoint rate limit.
//! - `server` — TCP listener lifecycle: bind retry, worker pool, bounded
//!   accept queue, HTTP parsing and serialization.
//! - `dispatcher` — `execute_command` and every command handler branch.

mod dispatcher;
mod protocol;
mod server;

pub use protocol::{GeneratorOptions, NativeRequest, NativeResponse};
pub use server::start_server;

#[cfg(test)]
mod tests;
