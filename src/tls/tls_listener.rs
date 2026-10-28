// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::TlsAcceptor;
use base_scheduler::{Cancellation, OperationResult, SocketAccept, SocketAddress, SocketClose};
use std::io;

/// A listener paired with its configured TLS acceptor. Native scheduler listeners have `accept` and `close` conveniences. Other listener representations can use `listener` and `acceptor` to perform their own accept operation followed by the same TLS handshake contract.
#[derive(Debug)]
pub struct TlsListener<L, T> {
    listener: L,
    acceptor: T,
}

impl<L, T> TlsListener<L, T> {
    /// Pair an existing listener with a TLS acceptor; no handshake takes place yet.
    pub fn new(listener: L, acceptor: T) -> Self {
        Self { listener, acceptor }
    }

    /// Borrow the underlying listener, for example to inspect its local address.
    pub fn listener(&self) -> &L {
        &self.listener
    }

    /// Borrow the provider for handshaking connections from a custom listener representation.
    pub fn acceptor(&self) -> &T {
        &self.acceptor
    }

    /// Recover the owned listener and TLS provider.
    pub fn into_parts(self) -> (L, T) {
        (self.listener, self.acceptor)
    }

    /// Accept one native scheduler connection and complete its TLS handshake. Handshake failure closes that accepted connection through the provider and leaves the listener available for subsequent accepts. The caller drives concurrency explicitly by polling separate accept/connection operations.
    pub async fn accept<S>(
        &self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<(T::Connection, SocketAddress)>
    where
        S: SocketAccept<Socket = L> + ?Sized,
        T: TlsAcceptor<S, L>,
    {
        cancellation.check()?;
        let (connection, peer) = scheduler
            .socket_accept(&self.listener, cancellation)
            .await?;
        let connection = self
            .acceptor
            .accept(scheduler, connection, cancellation)
            .await?;
        Ok((connection, peer))
    }

    /// Consume and close a native scheduler listener. Previously accepted connections remain independently owned by their callers.
    pub async fn close<S>(self, scheduler: &S) -> io::Result<()>
    where
        S: SocketClose<Socket = L> + ?Sized,
    {
        scheduler.socket_close(self.listener).await
    }
}
