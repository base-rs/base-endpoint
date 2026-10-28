// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::TlsConnector;
use crate::ConnectEndpoint;
use base_scheduler::{Cancellation, OperationResult};

/// Compose connection establishment with a TLS client handshake. The server identity is explicit and independent of the underlying endpoint's routing address.
#[derive(Clone, Debug)]
pub struct TlsClientEndpoint<E, T> {
    endpoint: E,
    connector: T,
    server_name: String,
}

impl<E, T> TlsClientEndpoint<E, T> {
    /// Describe a TLS connection using a configured provider and the identity to authenticate. No I/O is performed until `connect` is polled.
    pub fn new(endpoint: E, connector: T, server_name: impl Into<String>) -> Self {
        Self {
            endpoint,
            connector,
            server_name: server_name.into(),
        }
    }

    /// The underlying endpoint description.
    pub fn endpoint(&self) -> &E {
        &self.endpoint
    }

    /// The server identity supplied to the connector.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

impl<S, E, T> ConnectEndpoint<S> for TlsClientEndpoint<E, T>
where
    S: Sync + ?Sized,
    E: ConnectEndpoint<S>,
    T: TlsConnector<S, E::Connection>,
{
    type Connection = T::Connection;

    async fn connect(
        &self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<Self::Connection> {
        cancellation.check()?;
        let connection = self.endpoint.connect(scheduler, cancellation).await?;
        // Ownership transfers to the provider even if cancellation arrived during transport establishment. The provider must retire the connection on every failed handshake path.
        self.connector
            .connect(scheduler, connection, &self.server_name, cancellation)
            .await
    }
}
