// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::TlsSession;
use base_scheduler::{Cancellation, OperationResult};
use std::future::Future;

/// An explicitly configured TLS server provider over an owned accepted transport `C`. Configuration includes the server identity, ALPN selection and any client-authentication policy.
pub trait TlsAcceptor<S: ?Sized, C>: Send + Sync {
    /// A TLS connection that satisfies the configured authentication policy, with provider-specific application I/O.
    type Connection: TlsSession;

    /// Consume an accepted transport and complete its server handshake. On error or cancellation, retire and close the transport before returning. Futures are lazy; pre-cancellation prevents handshake I/O. Successful progress may win concurrent cancellation. Preserve cancellation distinctly from I/O and TLS failures, and never return a plaintext fallback. Dropping a pending handshake provides ordinary destruction only, unless the provider documents a stronger guarantee.
    fn accept(
        &self,
        scheduler: &S,
        connection: C,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<Self::Connection>> + Send;
}
