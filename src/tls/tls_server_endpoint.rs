// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::TlsListener;
use crate::{BindEndpoint, BindOptions};
use base_scheduler::{Cancellation, OperationResult};

/// Compose binding with a configured TLS server provider. Binding wraps listeners; each accepted connection performs its own handshake. Wrap a composite endpoint here to support multiple listening addresses.
#[derive(Clone, Debug)]
pub struct TlsServerEndpoint<E, T> {
    endpoint: E,
    acceptor: T,
}

impl<E, T> TlsServerEndpoint<E, T> {
    /// Describe TLS listeners without performing I/O. The acceptor is cloned for each listener; providers can share immutable configuration internally.
    pub fn new(endpoint: E, acceptor: T) -> Self {
        Self { endpoint, acceptor }
    }

    /// The underlying endpoint description.
    pub fn endpoint(&self) -> &E {
        &self.endpoint
    }
}

impl<S, E, T> BindEndpoint<S> for TlsServerEndpoint<E, T>
where
    S: Sync + ?Sized,
    E: BindEndpoint<S>,
    T: Clone + Send + Sync,
{
    type Listener = TlsListener<E::Listener, T>;

    async fn bind(
        &self,
        scheduler: &S,
        options: BindOptions,
        cancellation: &Cancellation,
    ) -> OperationResult<Vec<Self::Listener>> {
        cancellation.check()?;
        let listeners = self.endpoint.bind(scheduler, options, cancellation).await?;
        Ok(listeners
            .into_iter()
            .map(|listener| TlsListener::new(listener, self.acceptor.clone()))
            .collect())
    }
}
