// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use base_endpoint::{
    BindEndpoint, BindOptions, CompositeEndpoint, ConnectEndpoint,
    tls::{TlsAcceptor, TlsClientEndpoint, TlsConnector, TlsServerEndpoint, TlsSession},
};
use base_scheduler::{Cancellation, OperationResult};
use futures_lite::future::block_on;

// This endpoint and consumer require neither socket nor resolver capabilities.
struct MemoryEndpoint;

impl ConnectEndpoint<()> for MemoryEndpoint {
    type Connection = String;

    async fn connect(&self, _: &(), cancellation: &Cancellation) -> OperationResult<String> {
        cancellation.check()?;
        Ok(String::from("connection"))
    }
}

impl BindEndpoint<()> for MemoryEndpoint {
    type Listener = std::sync::mpsc::Receiver<String>;

    async fn bind(
        &self,
        _: &(),
        _: BindOptions,
        cancellation: &Cancellation,
    ) -> OperationResult<Vec<Self::Listener>> {
        cancellation.check()?;
        let (sender, receiver) = std::sync::mpsc::channel();
        sender.send(String::from("accepted connection")).unwrap();
        Ok(vec![receiver])
    }
}

async fn establish<S: Sync, E: ConnectEndpoint<S>>(
    scheduler: &S,
    endpoint: &E,
) -> OperationResult<E::Connection> {
    endpoint.connect(scheduler, &Cancellation::never()).await
}

async fn listen<S: Sync, E: BindEndpoint<S>>(
    scheduler: &S,
    endpoint: &E,
) -> OperationResult<Vec<E::Listener>> {
    endpoint
        .bind(scheduler, BindOptions::default(), &Cancellation::never())
        .await
}

#[test]
fn generic_consumers_and_connect_composition_support_non_socket_transports() {
    block_on(async {
        assert_eq!(establish(&(), &MemoryEndpoint).await.unwrap(), "connection");
        let listeners = listen(&(), &MemoryEndpoint).await.unwrap();
        assert_eq!(listeners[0].recv().unwrap(), "accepted connection");
        let composite = CompositeEndpoint::new(vec![MemoryEndpoint]);
        assert_eq!(establish(&(), &composite).await.unwrap(), "connection");
    });
}

// A simulation checks generic TLS adapter types; it does not provide TLS encryption.
#[derive(Clone)]
struct SimulatedMemoryTls;

struct MemorySession(String);

impl TlsSession for MemorySession {
    fn negotiated_protocol(&self) -> Option<&[u8]> {
        None
    }
}

impl TlsConnector<(), String> for SimulatedMemoryTls {
    type Connection = MemorySession;

    async fn connect(
        &self,
        _: &(),
        connection: String,
        server_name: &str,
        cancellation: &Cancellation,
    ) -> OperationResult<MemorySession> {
        cancellation.check()?;
        assert_eq!(server_name, "service.test");
        Ok(MemorySession(connection))
    }
}

impl TlsAcceptor<(), String> for SimulatedMemoryTls {
    type Connection = MemorySession;

    async fn accept(
        &self,
        _: &(),
        connection: String,
        cancellation: &Cancellation,
    ) -> OperationResult<MemorySession> {
        cancellation.check()?;
        Ok(MemorySession(connection))
    }
}

#[test]
fn tls_contracts_support_non_socket_transports_and_custom_listener_representations() {
    block_on(async {
        let client = TlsClientEndpoint::new(MemoryEndpoint, SimulatedMemoryTls, "service.test");
        let session = establish(&(), &client).await.unwrap();
        assert_eq!(session.0, "connection");
        assert_eq!(session.negotiated_protocol(), None);
        let server = TlsServerEndpoint::new(MemoryEndpoint, SimulatedMemoryTls);
        let listeners = listen(&(), &server).await.unwrap();
        let raw = listeners[0].listener().recv().unwrap();
        let session = listeners[0]
            .acceptor()
            .accept(&(), raw, &Cancellation::never())
            .await
            .unwrap();
        assert_eq!(session.0, "accepted connection");
    });
}
