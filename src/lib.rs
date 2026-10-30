// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

//! Reusable descriptions of how to **connect** and **bind**, inspired by Ruby's [IO::Endpoint](https://github.com/socketry/io-endpoint). Application code depends on endpoint contracts; endpoint implementations handle resolution, socket creation and establishment through explicit `base-scheduler` capabilities. The API is experimental.
//!
//! [`ConnectEndpoint<S>`](ConnectEndpoint) returns an associated `Connection`; [`BindEndpoint<S>`](BindEndpoint) returns a collection of associated `Listener` values. Implementations choose these representations, so consumers can abstract over establishment without hard-coding TCP or a particular runtime. The traits are separate so a connecting consumer does not need binding capabilities. The built-in TCP implementations return the scheduler's native socket type for use with its existing accept and I/O APIs.
//!
//! ```rust
//! use base_endpoint::{BindEndpoint, BindOptions, ConnectEndpoint, HostEndpoint};
//! use base_scheduler::{Cancellation, SocketAccept, SocketClose, SocketLocalAddress};
//! use base_scheduler_direct::{DirectOptions, DirectScheduler};
//!
//! futures_lite::future::block_on(async {
//!     let scheduler = DirectScheduler::new(DirectOptions::default())?;
//!     let cancellation = Cancellation::never();
//!
//!     let listeners = HostEndpoint::new("127.0.0.1", 0)
//!         .bind(&scheduler, BindOptions::default(), &cancellation).await?;
//!     let port = scheduler.socket_local_address(&listeners[0])?.port();
//!     let client = HostEndpoint::new("127.0.0.1", port)
//!         .connect(&scheduler, &cancellation).await?;
//!     let (accepted, _peer) = scheduler.socket_accept(&listeners[0], &cancellation).await?;
//!
//!     // Use scheduler-bound stream readers/writers here. Retire and drop them
//!     // before closing their sockets.
//!     scheduler.socket_close(client).await?;
//!     scheduler.socket_close(accepted).await?;
//!     for listener in listeners {
//!         scheduler.socket_close(listener).await?;
//!     }
//!     scheduler.shutdown().await;
//!     Ok::<(), base_scheduler::OperationError>(())
//! })?;
//! # Ok::<(), base_scheduler::OperationError>(())
//! ```
//!
//! A consumer can work entirely through the connection contract:
//!
//! ```rust
//! use base_endpoint::ConnectEndpoint;
//! use base_scheduler::{Cancellation, OperationResult};
//!
//! async fn establish<S: Sync, E: ConnectEndpoint<S>>(
//!     scheduler: &S,
//!     endpoint: &E,
//!     cancellation: &Cancellation,
//! ) -> OperationResult<E::Connection> {
//!     endpoint.connect(scheduler, cancellation).await
//! }
//! ```
//!
//! # TCP endpoints
//!
//! [`AddressEndpoint::new(socket_address)`](AddressEndpoint::new) describes a numeric TCP address and needs no resolver. [`HostEndpoint::new(hostname, port)`](HostEndpoint::new) resolves afresh for each operation. [`HostEndpoint::wildcard(port)`](HostEndpoint::wildcard) binds local interfaces and resolves loopback addresses when connecting. [`with_domain(SocketDomain::Ipv4)`](HostEndpoint::with_domain) or `Ipv6` restricts resolution. [`resolve`](HostEndpoint::resolve) exposes numeric endpoints when callers need to inspect candidates.
//!
//! # Composition and fallback
//!
//! [`CompositeEndpoint::new(vec![...])`](CompositeEndpoint::new) connects to the first successful child, preserving order and returning the last failure if all attempts fail. Bind creates all child listeners; a later failure closes earlier listeners before returning. Host endpoints use the same policy for resolved addresses. Cancellation stops fallback, and empty candidate sets fail with `AddrNotAvailable`. Binding composition currently requires listeners that the supplied scheduler can close; connection composition supports arbitrary connection representations.
//!
//! # Binding
//!
//! Binding includes listening with the requested backlog. All candidates must bind successfully; there is no best-effort family fallback. Resolver ordering and duplicates are preserved. Wildcard IPv4/IPv6 overlap follows the operating system's dual-stack policy and may cause binding to fail; select one family when needed. With port zero each listener receives its own OS-selected port, available through `SocketLocalAddress`.
//!
//! # Ownership and cancellation
//!
//! Endpoints retain no scheduler and spawn no tasks. Pass cancellation explicitly and await the operation to finish rollback before scheduler shutdown. Failed connection attempts close their sockets before fallback; failed binds close every socket created by that operation. Cleanup is awaited without the cancelled signal, and the primary establishment error is retained if closing also reports an error. Dropping a pending future provides ordinary destruction only, without an asynchronous join. Successful sockets and their cleanup belong to the caller.
//!
//! # Scope
//!
//! The first concrete transport covers TCP over IPv4/IPv6. TCP uses OS option defaults. UNIX sockets, UDP, URI parsing, named endpoints, socket-option policies, local source binding, Happy Eyeballs and built-in timeouts are not provided. The scheduler currently exposes only IP socket creation/address operations, so UNIX sockets need a scheduler extension. No concrete runtime is a production dependency; rustls is optional.
//!
//! The [`tls`] module composes these endpoints with provider-neutral TLS, including an optional rustls provider. The [`stream`] module describes plaintext byte I/O for established transports.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Compiles and runs the readme examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../readme.md")]
pub struct ReadmeDoctests;

mod address_endpoint;
mod bind_endpoint;
mod composite_endpoint;
mod connect_endpoint;
mod host_endpoint;

pub use address_endpoint::AddressEndpoint;
pub use bind_endpoint::{BindEndpoint, BindOptions};
pub use composite_endpoint::CompositeEndpoint;
pub use connect_endpoint::ConnectEndpoint;
pub use host_endpoint::HostEndpoint;

pub mod stream;
pub mod tls;

use base_scheduler::{OperationError, SocketClose};
use std::io;

fn no_addresses() -> OperationError {
    io::Error::new(io::ErrorKind::AddrNotAvailable, "endpoint has no addresses").into()
}

// Preserve the establishment error, but await cleanup of every owned socket before returning it. SocketClose consumes ownership even when closing reports an error.
async fn rollback<S: SocketClose + ?Sized>(scheduler: &S, sockets: Vec<S::Socket>) {
    for socket in sockets {
        let _ = scheduler.socket_close(socket).await;
    }
}
