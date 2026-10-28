// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

#![doc = include_str!("../readme.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
