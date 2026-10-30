// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

//! Provider-neutral TLS handshakes, stream I/O and endpoint composition. The optional `rustls` feature supplies a concrete provider in `tls::rustls`. Applications select trust stores and credentials through provider configuration.
//!
//! Client connectors authenticate the peer's certificate and requested server identity. Server acceptors apply their configured certificate and client-authentication policy. Providers own TLS configuration, trust roots, credentials, protocol versions, ALPN offers and selection, TLS I/O, shutdown and failed-handshake cleanup; application code can retain concrete configuration types without erasing them into a shared options map.
//!
//! [`TlsClientEndpoint::new(endpoint, connector, server_name)`](TlsClientEndpoint::new) implements the same connection contract as other endpoints and returns the provider's TLS connection. [`TlsServerEndpoint::new(endpoint, acceptor)`](TlsServerEndpoint::new) implements binding and returns [`TlsListener`] values; their `accept` method accepts and handshakes one native scheduler connection. A failed handshake leaves the listener available for another accept. Custom listener types can access the underlying listener and provider directly. Wrap composite binding inside the TLS server endpoint.
//!
//! The server name used for authentication is independent of the address used for routing. Client providers must verify certificate trust and server identity. [`TlsSession::negotiated_protocol`] exposes the selected ALPN bytes. [`TlsStream<S>`](TlsStream) supplies sequential reads, buffered writes, flushing, TLS shutdown and transport closure without naming a provider. There is no plaintext fallback. HTTP protocol names and engine selection remain owned by HTTP, outside endpoint/TLS.
//!
//! For example, application code can configure a provider elsewhere and compose it without naming a TLS backend:
//!
//! ```rust
//! use base_endpoint::{ConnectEndpoint, tls::{TlsClientEndpoint, TlsConnector}};
//! use base_scheduler::{Cancellation, OperationResult};
//!
//! async fn secure_connection<S, E, T>(
//!     scheduler: &S,
//!     endpoint: E,
//!     connector: T,
//!     server_name: &str,
//!     cancellation: &Cancellation,
//! ) -> OperationResult<T::Connection>
//! where
//!     S: Sync,
//!     E: ConnectEndpoint<S>,
//!     T: TlsConnector<S, E::Connection>,
//! {
//!     TlsClientEndpoint::new(endpoint, connector, server_name)
//!         .connect(scheduler, cancellation).await
//! }
//! ```
//!
//! # Rustls
//!
//! Enable the optional `rustls` Cargo feature to use `tls::rustls::{RustlsConnector, RustlsAcceptor, RustlsConnection}`. The providers accept shared rustls configurations, so applications select certificate trust roots, credentials, client authentication, protocol versions and ALPN. The feature enables rustls's ring crypto provider and TLS 1.2/1.3 support; configurations may also use another explicitly selected rustls crypto provider. No trust roots are loaded implicitly.
//!
//! ```rust
//! # #[cfg(feature = "rustls")]
//! # fn example(client_config: rustls::ClientConfig, server_config: rustls::ServerConfig) {
//! use base_endpoint::{AddressEndpoint, HostEndpoint, tls::{TlsClientEndpoint, TlsServerEndpoint,
//!     rustls::{RustlsAcceptor, RustlsConnector}}};
//! use std::sync::Arc;
//!
//! let client = TlsClientEndpoint::new(
//!     HostEndpoint::new("example.com", 443),
//!     RustlsConnector::new(Arc::new(client_config)),
//!     "example.com",
//! );
//! let server = TlsServerEndpoint::new(
//!     AddressEndpoint::new("127.0.0.1:8443".parse().unwrap()),
//!     RustlsAcceptor::new(Arc::new(server_config)),
//! );
//! // Use the same connect/bind traits as plain endpoints.
//! # }
//! ```

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
