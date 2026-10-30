# `base-endpoint`

Reusable descriptions of how to connect and bind, inspired by Ruby's [IO::Endpoint](https://github.com/socketry/io-endpoint). Application code depends on endpoint contracts, while endpoint implementations handle resolution, socket creation, optional TLS and establishment through explicit `base-scheduler` capabilities.

## Usage

Add the crate together with the scheduler interface it uses:

```sh
cargo add base-endpoint base-scheduler
```

The API is experimental. This example binds a loopback listener and connects to it with the Direct scheduler and `futures-lite`; add them with `cargo add base-scheduler-direct futures-lite` to run it:

```rust
use base_endpoint::{BindEndpoint, BindOptions, ConnectEndpoint, HostEndpoint};
use base_scheduler::{Cancellation, OperationError, SocketAccept, SocketClose, SocketLocalAddress};
use base_scheduler_direct::{DirectOptions, DirectScheduler};

fn main() -> Result<(), OperationError> {
    futures_lite::future::block_on(async {
        let scheduler = DirectScheduler::new(DirectOptions::default())?;
        let cancellation = Cancellation::never();

        let listeners = HostEndpoint::new("127.0.0.1", 0)
            .bind(&scheduler, BindOptions::default(), &cancellation).await?;
        let port = scheduler.socket_local_address(&listeners[0])?.port();
        let client = HostEndpoint::new("127.0.0.1", port)
            .connect(&scheduler, &cancellation).await?;
        let (accepted, _peer) = scheduler.socket_accept(&listeners[0], &cancellation).await?;

        scheduler.socket_close(client).await?;
        scheduler.socket_close(accepted).await?;
        for listener in listeners {
            scheduler.socket_close(listener).await?;
        }
        scheduler.shutdown().await;
        Ok(())
    })
}
```

Consumers can depend only on the connection contract, without naming TCP, TLS or a runtime:

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

See the [API documentation](https://docs.rs/base-endpoint) for hostname resolution, composite fallback, binding, cancellation and cleanup, TLS composition, the optional `rustls` provider, and the plaintext stream contracts.

## Releasing

Prepare a release with `cargo bake cargo:version:patch` (or `minor`, `major`, or `bump --version X.Y.Z`), commit it with a `Release: vVERSION` trailer, then run `cargo bake cargo:release` and open a pull request. After review and merge, GitHub Actions publishes the release when the configured `crates-io` environment approves it, then creates or updates the matching GitHub Release from `releases.md`. Follow the shared [Releasing skill](https://github.com/base-rs/base-project/blob/main/context/releasing.md) for the standard process.

## Releases

<!-- bake-readme:releases:start -->
See [releases.md](releases.md) for the full release history.

### v0.1.0

Initial release of the runtime-independent endpoints. Requires Rust 1.87 or later. The API is experimental.

- Provide separate `ConnectEndpoint` and `BindEndpoint` contracts, with associated connection and listener types, so consumers can abstract over establishment without a particular transport or runtime.
- Connect and bind TCP over IPv4 and IPv6 with `AddressEndpoint` and `HostEndpoint`. `CompositeEndpoint` composes any connect endpoints, and bind endpoints whose listeners the scheduler closes. Connection attempts fall back in order with fresh sockets and report the last error unless cancelled; binding is all-or-nothing and closes every socket it created on failure.
- Describe plaintext byte I/O with `stream::{ReadableStream, WritableStream}`, which scheduler stream handles implement directly.
- Wrap endpoints with TLS through `tls::{TlsClientEndpoint, TlsServerEndpoint, TlsListener}` over the `TlsConnector`, `TlsAcceptor` and `TlsStream` contracts. `TlsSession` reports the negotiated ALPN protocol, and a failed handshake leaves a `TlsListener` usable.
- With the `rustls` feature, provide `RustlsConnector`, `RustlsAcceptor` and `RustlsConnection`, with sequential reads and writes, `shutdown`, `close` and `abort`. `RustlsConnection::with_duplex` runs an application with independent encrypted reader and writer handles, spawns no task, and joins lane retirement and socket closure before returning. A transport failure while it sends `close_notify` is reported as that failure rather than as cancellation.
- Depend on the published `base-scheduler 0.3` interface; no concrete runtime is a production dependency.
<!-- bake-readme:releases:end -->

## See Also

- [base-scheduler](https://github.com/base-rs/base-scheduler) supplies the socket, stream and cancellation capabilities that endpoints use.

## Contributing

Please open an issue or pull request on [GitHub](https://github.com/base-rs/base-endpoint).
