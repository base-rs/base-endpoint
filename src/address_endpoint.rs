// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use crate::{BindEndpoint, BindOptions, ConnectEndpoint};
use base_scheduler::{
    Cancellation, OperationResult, SocketAddress, SocketBind, SocketClose, SocketConnect,
    SocketListen, SocketOpen, SocketProtocol, SocketType,
};
use std::fmt;

/// A TCP endpoint at one numeric IPv4 or IPv6 address. Construction performs no I/O, and operations require no resolver capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressEndpoint {
    address: SocketAddress,
}

impl AddressEndpoint {
    /// Describe a TCP endpoint. Port zero requests an OS-selected port when binding.
    pub const fn new(address: SocketAddress) -> Self {
        Self { address }
    }

    /// The configured address. A bound ephemeral port is obtained from the returned listener through the scheduler.
    pub const fn address(&self) -> SocketAddress {
        self.address
    }
}

impl fmt::Display for AddressEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tcp://{}", self.address)
    }
}

impl<S> ConnectEndpoint<S> for AddressEndpoint
where
    S: SocketOpen + SocketConnect + SocketClose + ?Sized,
{
    type Connection = S::Socket;

    async fn connect(
        &self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<S::Socket> {
        cancellation.check()?;
        let socket = scheduler
            .socket_open(
                self.address.into(),
                SocketType::Stream,
                Some(SocketProtocol::Tcp),
                cancellation,
            )
            .await?;
        match scheduler
            .socket_connect(&socket, self.address, cancellation)
            .await
        {
            Ok(()) => Ok(socket),
            Err(error) => {
                let _ = scheduler.socket_close(socket).await;
                Err(error)
            }
        }
    }
}

impl<S> BindEndpoint<S> for AddressEndpoint
where
    S: SocketOpen + SocketBind + SocketListen + SocketClose + ?Sized,
{
    type Listener = S::Socket;

    async fn bind(
        &self,
        scheduler: &S,
        options: BindOptions,
        cancellation: &Cancellation,
    ) -> OperationResult<Vec<S::Socket>> {
        cancellation.check()?;
        let socket = scheduler
            .socket_open(
                self.address.into(),
                SocketType::Stream,
                Some(SocketProtocol::Tcp),
                cancellation,
            )
            .await?;
        let result = async {
            scheduler
                .socket_bind(&socket, self.address, cancellation)
                .await?;
            scheduler
                .socket_listen(&socket, options.backlog, cancellation)
                .await
        }
        .await;
        match result {
            Ok(()) => Ok(vec![socket]),
            Err(error) => {
                let _ = scheduler.socket_close(socket).await;
                Err(error)
            }
        }
    }
}
