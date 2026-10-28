// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use base_scheduler::{Cancellation, OperationResult};
use std::future::Future;

/// A reusable description of how to establish a connection. Consumers depend on this contract rather than DNS, addresses, or socket construction. `S` supplies explicit execution capabilities; the endpoint retains no scheduler and spawns no tasks.
///
/// Connection representation belongs to the implementation: a plain endpoint can return a scheduler socket, while a wrapper can return another transport. Errors preserve cooperative cancellation separately from I/O failure. Implementations must not retry cancellation as an ordinary connection failure.
pub trait ConnectEndpoint<S: ?Sized>: Send + Sync {
    /// The established transport, owned by the caller on success.
    type Connection: Send;

    /// Establish one connection. Futures are lazy. Await completion after requesting cooperative cancellation so implementation-owned asynchronous cleanup can finish. Dropping a future abandons it and provides ordinary resource destruction, not an asynchronous cleanup guarantee.
    fn connect(
        &self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<Self::Connection>> + Send;
}
