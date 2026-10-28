// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::{RustlsConnection, establish, tls_error};
use crate::tls::TlsConnector;
use ::rustls::{ClientConfig, ClientConnection, pki_types::ServerName};
use base_scheduler::{
    Cancellation, OperationResult, SocketClose, SocketStreamReading, SocketStreamWriting,
};
use std::{io, sync::Arc};

/// A rustls client provider using application-supplied trust, identity and ALPN configuration. DNS names and IP literals are verified by the configuration's certificate verifier. No system trust roots are loaded implicitly.
#[derive(Clone, Debug)]
pub struct RustlsConnector {
    config: Arc<ClientConfig>,
}

impl RustlsConnector {
    /// Share an explicitly configured rustls client configuration. The optional feature enables rustls's ring crypto provider; applications can also supply a configuration built with another explicitly selected rustls crypto provider.
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl<S> TlsConnector<S, S::Socket> for RustlsConnector
where
    S: SocketStreamReading + SocketStreamWriting + SocketClose + ?Sized,
    S::Socket: 'static,
{
    type Connection = RustlsConnection<S::Socket>;

    async fn connect(
        &self,
        scheduler: &S,
        connection: S::Socket,
        server_name: &str,
        cancellation: &Cancellation,
    ) -> OperationResult<Self::Connection> {
        let state = (|| {
            cancellation.check()?;
            let name = ServerName::try_from(server_name.to_owned())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            Ok(ClientConnection::new(self.config.clone(), name)
                .map_err(tls_error)?
                .into())
        })();
        establish(scheduler, connection, state, cancellation).await
    }
}
