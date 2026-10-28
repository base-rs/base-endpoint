// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::TlsSession;
use base_scheduler::{Cancellation, OperationResult};
use std::future::Future;

/// An explicitly configured TLS client provider over an owned transport `C`. `S` supplies any execution or I/O capabilities the provider needs; neither input is required to be a scheduler socket.
pub trait TlsConnector<S: ?Sized, C>: Send + Sync {
    /// An authenticated TLS connection with provider-specific application I/O.
    type Connection: TlsSession;

    /// Consume the transport and complete a client handshake. Success must authenticate the peer certificate against the configured trust policy and verify it identifies `server_name`. Use the name for SNI where applicable; IP literals require IP identity verification rather than DNS-name matching. Providers validate server-name syntax and must never fall back to a plaintext connection.
    ///
    /// On failure or cancellation, the provider owns retirement and closure of `connection` before returning. Futures are lazy; pre-cancellation prevents handshake I/O. Successful handshake progress may win concurrent cancellation. Preserve cancellation as `OperationError::Cancelled`; TLS failures use `OperationError::Io` with the original error as its source where possible. Dropping a handshake provides ordinary destruction only, unless the provider documents a stronger guarantee.
    fn connect(
        &self,
        scheduler: &S,
        connection: C,
        server_name: &str,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<Self::Connection>> + Send;
}
