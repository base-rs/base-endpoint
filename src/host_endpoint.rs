// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use crate::{AddressEndpoint, BindEndpoint, BindOptions, CompositeEndpoint, ConnectEndpoint};
use base_scheduler::{
    AddressHints, AddressInfoCollection, AddressInfoView, AddressResolution, AddressService,
    Cancellation, OperationResult, SocketBind, SocketClose, SocketConnect, SocketDomain,
    SocketListen, SocketOpen, SocketProtocol, SocketType,
};
use std::fmt;

/// A TCP endpoint resolved afresh for each connect or bind. Connection attempts follow resolver order; binding creates a listener for every resolved address. There is no cache or background resolver task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEndpoint {
    hostname: Option<String>,
    port: u16,
    domain: Option<SocketDomain>,
}

impl HostEndpoint {
    /// Describe a TCP hostname and numeric port. Pass an unbracketed hostname or IP literal without a port.
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            hostname: Some(hostname.into()),
            port,
            domain: None,
        }
    }

    /// Describe all local interfaces for binding. When connecting, an absent hostname selects loopback addresses according to the resolver's contract.
    pub const fn wildcard(port: u16) -> Self {
        Self {
            hostname: None,
            port,
            domain: None,
        }
    }

    /// Restrict resolution to the selected IP family. By default both families are eligible.
    pub fn with_domain(mut self, domain: SocketDomain) -> Self {
        self.domain = Some(domain);
        self
    }

    /// The configured hostname, or `None` for wildcard binding and loopback connecting.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// The configured port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Resolve to numeric TCP endpoints, preserving order and duplicates. `passive` selects wildcard addresses for an absent hostname; otherwise an absent hostname selects loopback. Empty results are preserved here and rejected by connect/bind.
    pub async fn resolve<S: AddressResolution + ?Sized>(
        &self,
        scheduler: &S,
        passive: bool,
        cancellation: &Cancellation,
    ) -> OperationResult<Vec<AddressEndpoint>> {
        cancellation.check()?;
        let addresses = scheduler
            .address_resolve(
                self.hostname(),
                AddressService::Port(self.port),
                AddressHints {
                    domain: self.domain,
                    socket_type: Some(SocketType::Stream),
                    protocol: Some(SocketProtocol::Tcp),
                    passive,
                    ..AddressHints::default()
                },
                cancellation,
            )
            .await?;
        Ok(addresses
            .entries()
            .map(|entry| AddressEndpoint::new(entry.address()))
            .collect())
    }
}

impl fmt::Display for HostEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hostname = self.hostname().unwrap_or("*");
        if hostname.contains(':') {
            write!(formatter, "tcp://[{hostname}]:{}", self.port)
        } else {
            write!(formatter, "tcp://{hostname}:{}", self.port)
        }
    }
}

impl<S> ConnectEndpoint<S> for HostEndpoint
where
    S: AddressResolution + SocketOpen + SocketConnect + SocketClose + ?Sized,
{
    type Connection = S::Socket;

    async fn connect(
        &self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<S::Socket> {
        CompositeEndpoint::new(self.resolve(scheduler, false, cancellation).await?)
            .connect(scheduler, cancellation)
            .await
    }
}

impl<S> BindEndpoint<S> for HostEndpoint
where
    S: AddressResolution + SocketOpen + SocketBind + SocketListen + SocketClose + ?Sized,
{
    type Listener = S::Socket;

    async fn bind(
        &self,
        scheduler: &S,
        options: BindOptions,
        cancellation: &Cancellation,
    ) -> OperationResult<Vec<S::Socket>> {
        CompositeEndpoint::new(self.resolve(scheduler, true, cancellation).await?)
            .bind(scheduler, options, cancellation)
            .await
    }
}
