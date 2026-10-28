// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

//! Rustls client/server providers over Base scheduler stream sockets. Enable the `rustls` feature, supply an `Arc<ClientConfig>` or `Arc<ServerConfig>`, and compose the provider with the generic TLS endpoint adapters.
//!
//! Connections use explicit scheduler capabilities for sequential application I/O. `write` buffers accepted plaintext; `flush`, `read`, or `shutdown` drives pending TLS output. No runtime or background task is created. `RustlsConnection::with_duplex` provides independent plaintext directions and supervises both network lanes without spawning a task.

mod rustls_acceptor;
mod rustls_connection;
mod rustls_connector;

pub use rustls_acceptor::RustlsAcceptor;
pub use rustls_connection::{
    EncryptedSocketStreamReader, EncryptedSocketStreamWriter, RustlsConnection,
};
pub use rustls_connector::RustlsConnector;

use base_scheduler::{
    Cancellation, OperationResult, SocketClose, SocketStreamReading, SocketStreamWriting,
};
use std::io;

fn tls_error(error: ::rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

async fn establish<S>(
    scheduler: &S,
    socket: S::Socket,
    state: OperationResult<::rustls::Connection>,
    cancellation: &Cancellation,
) -> OperationResult<RustlsConnection<S::Socket>>
where
    S: SocketStreamReading + SocketStreamWriting + SocketClose + ?Sized,
    S::Socket: 'static,
{
    let state = match state {
        Ok(state) => state,
        Err(error) => {
            let _ = scheduler.socket_close(socket).await;
            return Err(error);
        }
    };
    let mut connection = RustlsConnection::new(socket, state);
    match connection.handshake(scheduler, cancellation).await {
        Ok(()) => Ok(connection),
        Err(error) => {
            let _ = connection.abort(scheduler).await;
            Err(error)
        }
    }
}
