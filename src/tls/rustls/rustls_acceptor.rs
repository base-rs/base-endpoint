// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::{RustlsConnection, establish, tls_error};
use crate::tls::TlsAcceptor;
use ::rustls::{ServerConfig, ServerConnection};
use base_scheduler::{
    Cancellation, OperationResult, SocketClose, SocketStreamReading, SocketStreamWriting,
};
use std::sync::Arc;

/// A rustls server provider using application-supplied certificates, client-authentication policy and ALPN configuration.
#[derive(Clone, Debug)]
pub struct RustlsAcceptor {
    config: Arc<ServerConfig>,
}

impl RustlsAcceptor {
    /// Share an explicitly configured rustls server configuration.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

impl<S> TlsAcceptor<S, S::Socket> for RustlsAcceptor
where
    S: SocketStreamReading + SocketStreamWriting + SocketClose + ?Sized,
    S::Socket: 'static,
{
    type Connection = RustlsConnection<S::Socket>;

    async fn accept(
        &self,
        scheduler: &S,
        connection: S::Socket,
        cancellation: &Cancellation,
    ) -> OperationResult<Self::Connection> {
        let state = (|| {
            cancellation.check()?;
            Ok(ServerConnection::new(self.config.clone())
                .map_err(tls_error)?
                .into())
        })();
        establish(scheduler, connection, state, cancellation).await
    }
}
