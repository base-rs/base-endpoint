// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

mod support;

use base_endpoint::{
    AddressEndpoint, BindEndpoint, BindOptions, CompositeEndpoint, ConnectEndpoint,
    tls::{
        TlsAcceptor, TlsClientEndpoint, TlsConnector, TlsListener, TlsServerEndpoint, TlsSession,
    },
};
use base_scheduler::{Cancellation, OperationError, OperationResult, SocketClose};
use futures_lite::future::block_on;
use std::{
    io::{self, ErrorKind},
    sync::{Arc, Mutex},
};
use support::{Event, Model, Outcome::*, Step, address};

// These providers simulate handshakes to verify composition and ownership. They perform no cryptography and are not usable TLS implementations.
#[derive(Clone, Default)]
struct SimulatedTls {
    handshakes: Arc<Mutex<Vec<Handshake>>>,
    fail: bool,
}

#[derive(Debug, PartialEq)]
struct Handshake {
    connection: usize,
    server_name: Option<String>,
}

struct Session(usize);

impl TlsSession for Session {
    fn negotiated_protocol(&self) -> Option<&[u8]> {
        Some(b"h2")
    }
}

impl SimulatedTls {
    async fn handshake(
        &self,
        scheduler: &Model,
        connection: usize,
        name: Option<&str>,
        cancellation: &Cancellation,
    ) -> OperationResult<Session> {
        self.handshakes.lock().unwrap().push(Handshake {
            connection,
            server_name: name.map(str::to_owned),
        });
        let result = cancellation
            .check()
            .map_err(OperationError::from)
            .and_then(|()| {
                if self.fail {
                    Err(io::Error::new(ErrorKind::InvalidData, "simulated TLS failure").into())
                } else {
                    std::result::Result::Ok(())
                }
            });
        match result {
            std::result::Result::Ok(()) => std::result::Result::Ok(Session(connection)),
            Err(error) => {
                let _ = scheduler.socket_close(connection).await;
                Err(error)
            }
        }
    }
}

impl TlsConnector<Model, usize> for SimulatedTls {
    type Connection = Session;

    async fn connect(
        &self,
        scheduler: &Model,
        connection: usize,
        server_name: &str,
        cancellation: &Cancellation,
    ) -> OperationResult<Session> {
        self.handshake(scheduler, connection, Some(server_name), cancellation)
            .await
    }
}

impl TlsAcceptor<Model, usize> for SimulatedTls {
    type Connection = Session;

    async fn accept(
        &self,
        scheduler: &Model,
        connection: usize,
        cancellation: &Cancellation,
    ) -> OperationResult<Session> {
        self.handshake(scheduler, connection, None, cancellation)
            .await
    }
}

#[test]
fn tls_client_composes_with_endpoints_and_preserves_server_identity_and_alpn() {
    block_on(async {
        let scheduler = Model::new([Step::Open(Ok), Step::Connect(Ok), Step::Close(false)]);
        let provider = SimulatedTls::default();
        let route = AddressEndpoint::new(address(443));
        let endpoint = TlsClientEndpoint::new(route, provider.clone(), "service.test");
        assert_eq!(endpoint.endpoint(), &route);
        assert_eq!(endpoint.server_name(), "service.test");
        let connection = endpoint
            .connect(&scheduler, &Cancellation::never())
            .await
            .unwrap();
        assert_eq!(connection.negotiated_protocol(), Some(b"h2".as_slice()));
        assert_eq!(
            *provider.handshakes.lock().unwrap(),
            [Handshake {
                connection: 0,
                server_name: Some("service.test".into())
            }]
        );
        scheduler.socket_close(connection.0).await.unwrap();
        scheduler.finished();
    });
}

#[test]
fn tls_client_failures_and_cancellation_transfer_cleanup_to_the_provider() {
    block_on(async {
        for cancel in [false, true] {
            let scheduler = Model::new([
                Step::Open(Ok),
                Step::Connect(if cancel { CancelAfterSuccess } else { Ok }),
                Step::Close(false),
            ]);
            let provider = SimulatedTls {
                fail: true,
                ..Default::default()
            };
            let endpoint = TlsClientEndpoint::new(
                AddressEndpoint::new(address(443)),
                provider.clone(),
                "service.test",
            );
            let error = endpoint
                .connect(&scheduler, &Cancellation::new())
                .await
                .err()
                .unwrap();
            if cancel {
                assert!(matches!(error, OperationError::Cancelled(_)));
            } else {
                assert_eq!(error.kind(), ErrorKind::InvalidData);
            }
            assert_eq!(provider.handshakes.lock().unwrap().len(), 1);
            scheduler.finished();
        }
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Connect(Io(ErrorKind::ConnectionRefused)),
            Step::Close(false),
        ]);
        let provider = SimulatedTls::default();
        let endpoint = TlsClientEndpoint::new(
            AddressEndpoint::new(address(443)),
            provider.clone(),
            "service.test",
        );
        assert_eq!(
            endpoint
                .connect(&scheduler, &Cancellation::never())
                .await
                .err()
                .unwrap()
                .kind(),
            ErrorKind::ConnectionRefused
        );
        assert!(provider.handshakes.lock().unwrap().is_empty());
        scheduler.finished();
    });
}

#[test]
fn tls_server_binds_first_and_handshakes_each_accepted_connection() {
    block_on(async {
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
            Step::Accept(Ok, 10),
            Step::Close(false),
            Step::Close(false),
            Step::Close(false),
        ]);
        let provider = SimulatedTls::default();
        let endpoint = TlsServerEndpoint::new(
            CompositeEndpoint::new(vec![
                AddressEndpoint::new(address(443)),
                AddressEndpoint::new(address(8443)),
            ]),
            provider.clone(),
        );
        assert_eq!(endpoint.endpoint().endpoints().len(), 2);
        let mut listeners = endpoint
            .bind(&scheduler, BindOptions::default(), &Cancellation::never())
            .await
            .unwrap();
        assert_eq!(listeners.len(), 2);
        assert!(provider.handshakes.lock().unwrap().is_empty());
        let listener = listeners.remove(0);
        assert_eq!(*listener.listener(), 0);
        assert!(Arc::ptr_eq(
            &listener.acceptor().handshakes,
            &provider.handshakes
        ));
        let (connection, peer) = listener
            .accept(&scheduler, &Cancellation::never())
            .await
            .unwrap();
        assert_eq!(peer, address(4567));
        assert_eq!(connection.negotiated_protocol(), Some(b"h2".as_slice()));
        assert_eq!(
            *provider.handshakes.lock().unwrap(),
            [Handshake {
                connection: 10,
                server_name: None
            }]
        );
        scheduler.socket_close(connection.0).await.unwrap();
        listener.close(&scheduler).await.unwrap();
        let (raw_listener, _) = listeners.remove(0).into_parts();
        scheduler.socket_close(raw_listener).await.unwrap();
        scheduler.finished();
    });
}

#[test]
fn server_handshake_failure_closes_only_the_accepted_connection_and_listener_remains_usable() {
    block_on(async {
        let scheduler = Model::new([
            Step::Accept(Ok, 10),
            Step::Close(false),
            Step::Accept(Ok, 11),
            Step::Close(false),
            Step::Close(false),
        ]);
        let listener = TlsListener::new(
            0,
            SimulatedTls {
                fail: true,
                ..Default::default()
            },
        );
        for _ in 0..2 {
            let error = listener
                .accept(&scheduler, &Cancellation::never())
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
        listener.close(&scheduler).await.unwrap();
        assert_eq!(
            scheduler.events(),
            [
                Event::Accept(0),
                Event::Close(10),
                Event::Accept(0),
                Event::Close(11),
                Event::Close(0)
            ]
        );
        scheduler.finished();
    });
}

#[test]
fn tls_precancellation_prevents_dialing_binding_and_accepting() {
    block_on(async {
        let scheduler = Model::default();
        let cancellation = Cancellation::new();
        cancellation.cancel();
        let client = TlsClientEndpoint::new(
            AddressEndpoint::new(address(443)),
            SimulatedTls::default(),
            "service.test",
        );
        assert!(matches!(
            client.connect(&scheduler, &cancellation).await,
            Err(OperationError::Cancelled(_))
        ));
        let server =
            TlsServerEndpoint::new(AddressEndpoint::new(address(443)), SimulatedTls::default());
        assert!(matches!(
            server
                .bind(&scheduler, BindOptions::default(), &cancellation)
                .await,
            Err(OperationError::Cancelled(_))
        ));
        let listener = TlsListener::new(0, SimulatedTls::default());
        assert!(matches!(
            listener.accept(&scheduler, &cancellation).await,
            Err(OperationError::Cancelled(_))
        ));
        assert!(scheduler.events().is_empty());
    });
}

#[test]
fn tls_server_propagates_underlying_bind_and_accept_errors_without_handshaking() {
    block_on(async {
        let scheduler = Model::new([Step::Open(Io(ErrorKind::PermissionDenied))]);
        let provider = SimulatedTls::default();
        let server = TlsServerEndpoint::new(
            CompositeEndpoint::new(vec![AddressEndpoint::new(address(443))]),
            provider.clone(),
        );
        assert_eq!(
            server
                .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                .await
                .err()
                .unwrap()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(provider.handshakes.lock().unwrap().is_empty());
        scheduler.finished();

        let scheduler = Model::new([
            Step::Accept(Io(ErrorKind::ConnectionAborted), 10),
            Step::Close(false),
        ]);
        let listener = TlsListener::new(0, provider.clone());
        assert_eq!(
            listener
                .accept(&scheduler, &Cancellation::never())
                .await
                .err()
                .unwrap()
                .kind(),
            ErrorKind::ConnectionAborted
        );
        assert!(provider.handshakes.lock().unwrap().is_empty());
        listener.close(&scheduler).await.unwrap();
        scheduler.finished();
    });
}

#[test]
fn cancellation_after_transport_accept_transfers_cleanup_to_the_tls_acceptor() {
    block_on(async {
        let scheduler = Model::new([
            Step::Accept(CancelAfterSuccess, 10),
            Step::Close(false),
            Step::Close(false),
        ]);
        let provider = SimulatedTls::default();
        let listener = TlsListener::new(0, provider.clone());
        assert!(matches!(
            listener.accept(&scheduler, &Cancellation::new()).await,
            Err(OperationError::Cancelled(_))
        ));
        assert_eq!(
            *provider.handshakes.lock().unwrap(),
            [Handshake {
                connection: 10,
                server_name: None
            }]
        );
        listener.close(&scheduler).await.unwrap();
        scheduler.finished();
    });
}

#[test]
fn tls_server_wraps_a_single_numeric_listener_without_handshaking_during_bind() {
    block_on(async {
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
            Step::Close(false),
        ]);
        let provider = SimulatedTls::default();
        let server = TlsServerEndpoint::new(AddressEndpoint::new(address(443)), provider.clone());
        let mut listeners = server
            .bind(&scheduler, BindOptions::default(), &Cancellation::never())
            .await
            .unwrap();
        assert_eq!(listeners.len(), 1);
        assert!(provider.handshakes.lock().unwrap().is_empty());
        listeners.remove(0).close(&scheduler).await.unwrap();
        scheduler.finished();

        let scheduler = Model::new([Step::Open(Io(ErrorKind::PermissionDenied))]);
        assert_eq!(
            server
                .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                .await
                .err()
                .unwrap()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(provider.handshakes.lock().unwrap().is_empty());
        scheduler.finished();
    });
}
