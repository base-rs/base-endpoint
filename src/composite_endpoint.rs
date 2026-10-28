// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use crate::{BindEndpoint, BindOptions, ConnectEndpoint, no_addresses, rollback};
use base_scheduler::{Cancellation, OperationError, OperationResult, SocketClose};

/// An ordered collection of endpoints of one type. Connecting tries children in order until one succeeds. Binding creates every child's listeners and rolls them all back if a later child fails. Empty collections fail with `AddrNotAvailable`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeEndpoint<E> {
    endpoints: Vec<E>,
}

impl<E> CompositeEndpoint<E> {
    /// Describe an ordered collection, without performing I/O.
    pub fn new(endpoints: Vec<E>) -> Self {
        Self { endpoints }
    }

    /// The child endpoint descriptions in attempt order.
    pub fn endpoints(&self) -> &[E] {
        &self.endpoints
    }
}

impl<S, E> ConnectEndpoint<S> for CompositeEndpoint<E>
where
    S: Sync + ?Sized,
    E: ConnectEndpoint<S>,
{
    type Connection = E::Connection;

    async fn connect(
        &self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<Self::Connection> {
        cancellation.check()?;
        let mut last_error = None;
        for endpoint in &self.endpoints {
            cancellation.check()?;
            match endpoint.connect(scheduler, cancellation).await {
                Ok(connection) => return Ok(connection),
                Err(error @ OperationError::Cancelled(_)) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(no_addresses))
    }
}

// Binding composition currently supports listeners closed by the scheduler. Connect composition has no socket representation requirement.
impl<S, E> BindEndpoint<S> for CompositeEndpoint<E>
where
    S: SocketClose<Socket = E::Listener> + ?Sized,
    E: BindEndpoint<S>,
{
    type Listener = E::Listener;

    async fn bind(
        &self,
        scheduler: &S,
        options: BindOptions,
        cancellation: &Cancellation,
    ) -> OperationResult<Vec<Self::Listener>> {
        cancellation.check()?;
        if self.endpoints.is_empty() {
            return Err(no_addresses());
        }
        let mut listeners = Vec::new();
        for endpoint in &self.endpoints {
            let result = match cancellation.check() {
                Ok(()) => endpoint.bind(scheduler, options, cancellation).await,
                Err(error) => Err(error.into()),
            };
            match result {
                Ok(mut bound) => listeners.append(&mut bound),
                Err(error) => {
                    rollback(scheduler, listeners).await;
                    return Err(error);
                }
            }
        }
        Ok(listeners)
    }
}
