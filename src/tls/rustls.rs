// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

//! Rustls client/server providers over Base scheduler stream sockets. Enable the `rustls` feature, supply an `Arc<ClientConfig>` or `Arc<ServerConfig>`, and compose the provider with the generic TLS endpoint adapters.
//!
//! Rustls connections take the scheduler explicitly for each operation. `write` reports plaintext accepted into buffering; call `flush` to send the final buffered output. Reads also drive pending TLS control output. `shutdown` sends `close_notify` while leaving reads available; `close` attempts shutdown and always closes the transport, even after cancellation. `abort` closes without a TLS notification. Await cancelled operations before closure. Partial ciphertext output is retained for a later flush, so accepted plaintext must not be replayed. Missing peer `close_notify` is reported as `UnexpectedEof` after buffered plaintext is consumed. `TlsStream` retains the sequential interface. No runtime or background task is created.
//!
//! `RustlsConnection::with_duplex` runs an application with independent plaintext reader and writer handles over one TLS connection while explicitly driving network input/output over persistent scheduler capabilities. The writer directly polls one retained transmitter future; successful writes need no supervisor handoff. A stable socket waker reaches both foreground and supervised pollers when output blocks. The writer handle carries the scheduler lifetime, while the codec and body types remain unchanged. Application reads drive the retained receiver until authenticated plaintext is available; input does not read ahead while plaintext awaits consumption. Control output and directional cleanup remain supervised. Incoming TLS control records are processed when the application reads. No lock spans an asynchronous wait, and no task is spawned. Await its completion to join lane retirement and socket closure.

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
