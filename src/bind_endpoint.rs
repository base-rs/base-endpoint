// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use base_scheduler::{Cancellation, OperationResult};
use std::future::Future;

/// Listening configuration passed to a binding operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindOptions {
    /// Requested listen backlog. Operating-system limits and semantics apply.
    pub backlog: i32,
}

impl Default for BindOptions {
    fn default() -> Self {
        Self { backlog: 128 }
    }
}

/// A reusable description of how to create listeners. Consumers need not know how addresses are resolved or sockets are created. Binding may produce multiple listeners, for example one per IP family.
pub trait BindEndpoint<S: ?Sized>: Send + Sync {
    /// One bound listener, owned by the caller on success. Its representation belongs to the endpoint implementation.
    type Listener: Send;

    /// Bind and start listening on every address. Success returns a nonempty collection; failure transfers no listeners to the caller. Futures are lazy. Await completion after cooperative cancellation to finish asynchronous rollback; dropping a pending future provides ordinary destruction only.
    fn bind(
        &self,
        scheduler: &S,
        options: BindOptions,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<Vec<Self::Listener>>> + Send;
}
