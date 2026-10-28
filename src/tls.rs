// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

//! Provider-neutral TLS handshakes, stream I/O and endpoint composition. The optional `rustls` feature supplies a concrete provider in `tls::rustls`. Applications select trust stores and credentials through provider configuration.
//!
//! Client connectors authenticate the peer's certificate and requested server identity. Server acceptors apply their configured certificate and client-authentication policy. Providers own TLS configuration, trust roots, credentials, protocol versions and ALPN offers; application code can retain concrete configuration types without erasing them into a shared options map.

mod tls_acceptor;
mod tls_client_endpoint;
mod tls_connector;
mod tls_listener;
mod tls_server_endpoint;
mod tls_session;
mod tls_stream;

pub use tls_acceptor::TlsAcceptor;
pub use tls_client_endpoint::TlsClientEndpoint;
pub use tls_connector::TlsConnector;
pub use tls_listener::TlsListener;
pub use tls_server_endpoint::TlsServerEndpoint;
pub use tls_session::TlsSession;
pub use tls_stream::TlsStream;

#[cfg(feature = "rustls")]
pub mod rustls;
