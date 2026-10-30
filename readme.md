# Base Endpoint

Reusable descriptions of how to **connect** and **bind**, inspired by Ruby's [IO::Endpoint](https://github.com/socketry/io-endpoint). Application code depends on endpoint contracts; endpoint implementations handle resolution, socket creation and establishment through explicit `base-scheduler` capabilities. The API is experimental.

`ConnectEndpoint<S>` returns an associated `Connection`; `BindEndpoint<S>` returns a collection of associated `Listener` values. Implementations choose these representations, so consumers can abstract over establishment without hard-coding TCP or a particular runtime. The traits are separate so a connecting consumer does not need binding capabilities. The built-in TCP implementations return the scheduler's native socket type for use with its existing accept and I/O APIs.

```rust
use base_endpoint::{BindEndpoint, BindOptions, ConnectEndpoint, HostEndpoint};
use base_scheduler::{Cancellation, SocketAccept, SocketClose, SocketLocalAddress};
use base_scheduler_direct::{DirectOptions, DirectScheduler};

futures_lite::future::block_on(async {
    let scheduler = DirectScheduler::new(DirectOptions::default())?;
    let cancellation = Cancellation::never();

    let listeners = HostEndpoint::new("127.0.0.1", 0)
        .bind(&scheduler, BindOptions::default(), &cancellation).await?;
    let port = scheduler.socket_local_address(&listeners[0])?.port();
    let client = HostEndpoint::new("127.0.0.1", port)
        .connect(&scheduler, &cancellation).await?;
    let (accepted, _peer) = scheduler.socket_accept(&listeners[0], &cancellation).await?;

    // Use scheduler-bound stream readers/writers here. Retire and drop them
    // before closing their sockets.
    scheduler.socket_close(client).await?;
    scheduler.socket_close(accepted).await?;
    for listener in listeners {
        scheduler.socket_close(listener).await?;
    }
    scheduler.shutdown().await;
    Ok::<(), base_scheduler::OperationError>(())
})?;
# Ok::<(), base_scheduler::OperationError>(())
```

A consumer can work entirely through the connection contract:

```rust
use base_endpoint::ConnectEndpoint;
use base_scheduler::{Cancellation, OperationResult};

async fn establish<S: Sync, E: ConnectEndpoint<S>>(
    scheduler: &S,
    endpoint: &E,
    cancellation: &Cancellation,
) -> OperationResult<E::Connection> {
    endpoint.connect(scheduler, cancellation).await
}
```

`AddressEndpoint::new(socket_address)` describes a numeric TCP address and needs no resolver. `HostEndpoint::new(hostname, port)` resolves afresh for each operation. `HostEndpoint::wildcard(port)` binds local interfaces and resolves loopback addresses when connecting. `with_domain(SocketDomain::Ipv4)` or `Ipv6` restricts resolution. `resolve` exposes numeric endpoints when callers need to inspect candidates.

`CompositeEndpoint::new(vec![...])` connects to the first successful child, preserving order and returning the last failure if all attempts fail. Bind creates all child listeners; a later failure closes earlier listeners before returning. Host endpoints use the same policy for resolved addresses. Cancellation stops fallback, and empty candidate sets fail with `AddrNotAvailable`. Binding composition currently requires listeners that the supplied scheduler can close; connection composition supports arbitrary connection representations.

Binding includes listening with the requested backlog. All candidates must bind successfully; there is no best-effort family fallback. Resolver ordering and duplicates are preserved. Wildcard IPv4/IPv6 overlap follows the operating system's dual-stack policy and may cause binding to fail; select one family when needed. With port zero each listener receives its own OS-selected port, available through `SocketLocalAddress`.

Endpoints retain no scheduler and spawn no tasks. Pass cancellation explicitly and await the operation to finish rollback before scheduler shutdown. Failed connection attempts close their sockets before fallback; failed binds close every socket created by that operation. Cleanup is awaited without the cancelled signal, and the primary establishment error is retained if closing also reports an error. Dropping a pending future provides ordinary destruction only, without an asynchronous join. Successful sockets and their cleanup belong to the caller.

The `tls` submodule exposes provider-neutral `TlsConnector`, `TlsAcceptor`, `TlsSession` and `TlsStream` traits. `TlsClientEndpoint::new(endpoint, connector, server_name)` implements the same connection contract and returns the provider's TLS connection. `TlsServerEndpoint::new(endpoint, acceptor)` implements binding and returns `TlsListener` values; their `accept` method accepts and handshakes one native scheduler connection. A failed handshake leaves the listener available for another accept. Custom listener types can access the underlying listener and provider directly. Wrap composite binding inside the TLS server endpoint.

The server name used for authentication is independent of the address used for routing. Client providers must verify certificate trust and server identity. Providers own credentials, trust configuration, ALPN offers/selection, TLS I/O, shutdown and failed-handshake cleanup. `TlsSession::negotiated_protocol` exposes the selected ALPN bytes. `TlsStream<S>` supplies sequential reads, buffered writes, flushing, TLS shutdown and transport closure without naming a provider. There is no plaintext fallback.

For example, application code can configure a provider elsewhere and compose it without naming a TLS backend:

```rust
use base_endpoint::{ConnectEndpoint, tls::{TlsClientEndpoint, TlsConnector}};
use base_scheduler::{Cancellation, OperationResult};

async fn secure_connection<S, E, T>(
    scheduler: &S,
    endpoint: E,
    connector: T,
    server_name: &str,
    cancellation: &Cancellation,
) -> OperationResult<T::Connection>
where
    S: Sync,
    E: ConnectEndpoint<S>,
    T: TlsConnector<S, E::Connection>,
{
    TlsClientEndpoint::new(endpoint, connector, server_name)
        .connect(scheduler, cancellation).await
}
```

Enable the optional `rustls` Cargo feature to use `tls::rustls::{RustlsConnector, RustlsAcceptor, RustlsConnection}`. The providers accept shared rustls configurations, so applications select certificate trust roots, credentials, client authentication, protocol versions and ALPN. The feature enables rustls's ring crypto provider and TLS 1.2/1.3 support; configurations may also use another explicitly selected rustls crypto provider. No trust roots are loaded implicitly.

```rust
# #[cfg(feature = "rustls")]
# fn example(client_config: rustls::ClientConfig, server_config: rustls::ServerConfig) {
use base_endpoint::{AddressEndpoint, HostEndpoint, tls::{TlsClientEndpoint, TlsServerEndpoint,
    rustls::{RustlsAcceptor, RustlsConnector}}};
use std::sync::Arc;

let client = TlsClientEndpoint::new(
    HostEndpoint::new("example.com", 443),
    RustlsConnector::new(Arc::new(client_config)),
    "example.com",
);
let server = TlsServerEndpoint::new(
    AddressEndpoint::new("127.0.0.1:8443".parse().unwrap()),
    RustlsAcceptor::new(Arc::new(server_config)),
);
// Use the same connect/bind traits shown above.
# }
```

Rustls connections take the scheduler explicitly for each operation. `write` reports plaintext accepted into buffering; call `flush` to send the final buffered output. Reads also drive pending TLS control output. `shutdown` sends `close_notify` while leaving reads available; `close` attempts shutdown and always closes the transport, even after cancellation. `abort` closes without a TLS notification. Await cancelled operations before closure. Partial ciphertext output is retained for a later flush, so accepted plaintext must not be replayed. Missing peer `close_notify` is reported as `UnexpectedEof` after buffered plaintext is consumed. `TlsStream` retains the sequential interface. `RustlsConnection::with_duplex` additionally runs an application with independent encrypted reader/writer handles while explicitly driving network input/output over persistent scheduler capabilities. The writer directly polls one retained transmitter future; successful writes need no supervisor handoff. A stable socket waker reaches both foreground and supervised pollers when output blocks. The writer handle carries the scheduler lifetime, while the codec and body types remain unchanged. Application reads drive the retained receiver until authenticated plaintext is available; input does not read ahead while plaintext awaits consumption. Control output and directional cleanup remain supervised. Incoming TLS control records are processed when the application reads. No lock spans an asynchronous wait, and no task is spawned. Await its completion to join lane retirement and socket closure.

The first concrete transport covers TCP over IPv4/IPv6. UNIX sockets, UDP, URI parsing, named endpoints, socket-option policies, local source binding, Happy Eyeballs and built-in timeouts are follow-up work. TCP uses OS option defaults. The scheduler currently exposes only IP socket creation/address operations, so UNIX sockets need a scheduler extension. No concrete runtime is a production dependency; rustls is optional.

Tests cover generic contracts with simulated providers, Rustls connection faults over a scripted transport, and real TLS 1.2/1.3 data transfer, authentication, ALPN, cancellation and closure with Direct/Tokio schedulers and independent blocking rustls peers. The package uses the published scheduler 0.3 family and Rust 1.87, without local scheduler overrides.

`stream::{ReadableStream, WritableStream}` describes plaintext byte I/O for established transports. Scheduler stream handles forward directly into these small contracts. Packet boundaries and datagram metadata belong to separate packet capabilities; this interface does not imply that all endpoint connections are streams. HTTP protocol names and engine selection remain owned by HTTP, outside endpoint/TLS.

## Development

Install the launcher with `cargo install bake --locked`. The private `bake/` workspace member supplies the shared Base development tasks:

```sh
cargo bake --locked test:coverage --all-targets true --all-features true
```

## Releasing

Prepare a release with `cargo bake cargo:version:patch` (or `minor`, `major`, or `bump --version X.Y.Z`), then run `cargo bake cargo:release` and open a pull request. After review and merge, GitHub Actions publishes the release when the configured `crates-io` environment approves it. Follow the shared [Releasing skill](https://github.com/base-rs/base-project/blob/main/context/releasing.md) for the standard process.

## Releases

Version v0.1.0 is the initial release of the TCP and Rustls endpoints on the `base-scheduler 0.3` interface. See the [release notes](releases.md).

## See Also

- [base-scheduler](https://github.com/base-rs/base-scheduler) supplies the socket, stream and cancellation capabilities that endpoints use.
