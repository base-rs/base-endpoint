# Releases

## Unreleased

Initial release of the runtime-independent endpoints. Requires Rust 1.87 or later. The API is experimental.

- Provide separate `ConnectEndpoint` and `BindEndpoint` contracts, with associated connection and listener types, so consumers can abstract over establishment without a particular transport or runtime.
- Connect and bind TCP over IPv4 and IPv6 with `AddressEndpoint`, `HostEndpoint` and `CompositeEndpoint`. Connection attempts fall back in order with fresh sockets and report the last error; binding is all-or-nothing and closes every socket it created on failure.
- Describe plaintext byte I/O with `stream::{ReadableStream, WritableStream}`, which scheduler stream handles implement directly.
- Wrap endpoints with TLS through `tls::{TlsClientEndpoint, TlsServerEndpoint, TlsListener}` over the `TlsConnector`, `TlsAcceptor` and `TlsStream` contracts.
- With the `rustls` feature, provide `RustlsConnector`, `RustlsAcceptor` and `RustlsConnection`, with sequential reads and writes, `shutdown`, `close` and `abort`. `RustlsConnection::with_duplex` runs an application with independent encrypted reader and writer handles, spawns no task, and joins lane retirement and socket closure before returning. A transport failure while sending `close_notify` is reported as that failure.
- Depend on the published `base-scheduler 0.3` interface; no concrete runtime is a production dependency.
