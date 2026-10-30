# Releases

## v0.1.0

Initial release of the runtime-independent endpoints. Requires Rust 1.87 or later. The API is experimental.

- Provide separate `ConnectEndpoint` and `BindEndpoint` contracts, with associated connection and listener types, so consumers can abstract over establishment without a particular transport or runtime.
- Connect and bind TCP over IPv4 and IPv6 with `AddressEndpoint` and `HostEndpoint`. `CompositeEndpoint` composes any connect endpoints, and bind endpoints whose listeners the scheduler closes. Connection attempts fall back in order with fresh sockets and report the last error unless cancelled; binding is all-or-nothing and closes every socket it created on failure.
- Describe plaintext byte I/O with `stream::{ReadableStream, WritableStream}`, which scheduler stream handles implement directly.
- Wrap endpoints with TLS through `tls::{TlsClientEndpoint, TlsServerEndpoint, TlsListener}` over the `TlsConnector`, `TlsAcceptor` and `TlsStream` contracts. `TlsSession` reports the negotiated ALPN protocol, and a failed handshake leaves a `TlsListener` usable.
- With the `rustls` feature, provide `RustlsConnector`, `RustlsAcceptor` and `RustlsConnection`, with sequential reads and writes, `shutdown`, `close` and `abort`. `RustlsConnection::with_duplex` runs an application with independent encrypted reader and writer handles, spawns no task, and joins lane retirement and socket closure before returning. A transport failure while it sends `close_notify` is reported as that failure rather than as cancellation.
- Depend on the published `base-scheduler 0.3` interface; no concrete runtime is a production dependency.
