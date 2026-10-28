// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::TlsSession;
use base_scheduler::{Cancellation, OperationResult};
use std::{future::Future, io};

/// Sequential TLS application I/O, independent of a particular TLS provider. `S` supplies explicit execution/I/O capabilities. A stream owns its transport and TLS state; no background task or split reader/writer is implied.
///
/// Await operations after cooperative cancellation before closing. Write acceptance and delivery are separate: `write` reports the accepted plaintext prefix, while `flush` drives its encrypted output. Cancellation must preserve queued output without replaying already accepted plaintext. Fatal TLS or transport errors require closing or aborting the stream.
pub trait TlsStream<S: ?Sized>: TlsSession {
    /// Read a possibly short plaintext prefix. A nonempty destination returns zero after an authenticated TLS close notification. Unexpected transport EOF reports `UnexpectedEof` after buffered plaintext is consumed. Empty storage returns zero after checking cancellation.
    fn read(
        &mut self,
        scheduler: &S,
        buffer: &mut [u8],
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<usize>> + Send;

    /// Flush previous output, then accept a possibly short plaintext prefix. Return its accepted byte count without any subsequent asynchronous wait; use `flush` to send the final queued output. No bytes are accepted on an error return. Writing after local TLS shutdown fails.
    fn write(
        &mut self,
        scheduler: &S,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<usize>> + Send;

    /// Send queued output. Cancellation leaves the unsent ciphertext available for a subsequent flush.
    fn flush(
        &mut self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<()>> + Send;

    /// Stop accepting plaintext writes and send a TLS close notification. Reads remain available. Retry after cancellation to finish sending the notification; this does not wait for peer closure.
    fn shutdown(
        &mut self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<()>> + Send;

    /// Attempt TLS shutdown and consume/close the transport even if shutdown fails or is cancelled. Return the primary shutdown error if closure also fails.
    fn close(
        self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<()>> + Send
    where
        Self: Sized;

    /// Consume and close the transport without a TLS close notification, for example after a fatal handshake or application-data error.
    fn abort(self, scheduler: &S) -> impl Future<Output = io::Result<()>> + Send
    where
        Self: Sized;
}
