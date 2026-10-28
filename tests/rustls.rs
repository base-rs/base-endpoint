// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

#![cfg(feature = "rustls")]

use base_endpoint::{
    AddressEndpoint, BindEndpoint, BindOptions, ConnectEndpoint,
    tls::{
        TlsAcceptor, TlsClientEndpoint, TlsConnector, TlsServerEndpoint, TlsSession, TlsStream,
        rustls::{RustlsAcceptor, RustlsConnector},
    },
};
use base_scheduler::{
    Cancellation, Clock, OperationError, SocketAccept, SocketBind, SocketClose, SocketConnect,
    SocketListen, SocketLocalAddress, SocketOpen, SocketStreamReader, SocketStreamReading,
    SocketStreamWriting,
};
use base_scheduler_direct::{DirectOptions, DirectScheduler};
use base_scheduler_tokio::TokioScheduler;
use futures_lite::future::{block_on, zip};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

fn identity() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let identity =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    (
        identity.cert.der().clone(),
        PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()),
    )
}

fn configs(tls12: bool) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let (cert, key) = identity();
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let versions = if tls12 {
        &[&rustls::version::TLS12][..]
    } else {
        &[&rustls::version::TLS13][..]
    };
    let mut client = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut server = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
    client.alpn_protocols = vec![b"test/1".to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    (Arc::new(client), Arc::new(server))
}

fn direct() -> DirectScheduler {
    DirectScheduler::new(DirectOptions {
        threads: 2,
        capacity: 32,
    })
    .unwrap()
}

async fn write_all<S: Sync, C: TlsStream<S>>(connection: &mut C, scheduler: &S, mut data: &[u8]) {
    while !data.is_empty() {
        let count = connection
            .write(scheduler, data, &Cancellation::never())
            .await
            .unwrap();
        assert!(count > 0);
        data = &data[count..];
    }
    connection
        .flush(scheduler, &Cancellation::never())
        .await
        .unwrap();
}

async fn read_to_end<S: Sync, C: TlsStream<S>>(connection: &mut C, scheduler: &S) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0; 997];
    loop {
        let count = connection
            .read(scheduler, &mut buffer, &Cancellation::never())
            .await
            .unwrap();
        if count == 0 {
            return output;
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

async fn round_trip<S>(scheduler: &S)
where
    S: SocketOpen
        + SocketConnect
        + SocketBind
        + SocketListen
        + SocketAccept
        + SocketClose
        + SocketLocalAddress
        + SocketStreamReading
        + SocketStreamWriting
        + Clock,
    S::Socket: 'static,
{
    scheduler
        .timeout(Duration::from_secs(10), async {
            for tls12 in [false, true] {
                let (client_config, server_config) = configs(tls12);
                let server = TlsServerEndpoint::new(
                    AddressEndpoint::new("127.0.0.1:0".parse().unwrap()),
                    RustlsAcceptor::new(server_config),
                );
                let mut listeners = server
                    .bind(scheduler, BindOptions::default(), &Cancellation::never())
                    .await
                    .unwrap();
                let listener = listeners.remove(0);
                let address = scheduler.socket_local_address(listener.listener()).unwrap();
                let client = TlsClientEndpoint::new(
                    AddressEndpoint::new(address),
                    RustlsConnector::new(client_config),
                    if tls12 { "127.0.0.1" } else { "localhost" },
                );
                let payload = (0..100_003)
                    .map(|index| (index % 251) as u8)
                    .collect::<Vec<_>>();
                let server_work = async {
                    let (mut connection, _) = listener
                        .accept(scheduler, &Cancellation::never())
                        .await
                        .unwrap();
                    assert_eq!(connection.negotiated_protocol(), Some(b"test/1".as_slice()));
                    assert!(connection.peer_certificates().is_none());
                    assert_eq!(read_to_end(&mut connection, scheduler).await, payload);
                    write_all(&mut connection, scheduler, &payload).await;
                    connection
                        .close(scheduler, &Cancellation::never())
                        .await
                        .unwrap();
                    listener.close(scheduler).await.unwrap();
                };
                let client_work = async {
                    let mut connection = client
                        .connect(scheduler, &Cancellation::never())
                        .await
                        .unwrap();
                    assert_eq!(connection.negotiated_protocol(), Some(b"test/1".as_slice()));
                    assert_eq!(connection.peer_certificates().unwrap().len(), 1);
                    assert_eq!(
                        scheduler
                            .socket_local_address(connection.socket())
                            .unwrap()
                            .ip(),
                        address.ip()
                    );
                    assert_eq!(
                        connection
                            .read(scheduler, &mut [], &Cancellation::never())
                            .await
                            .unwrap(),
                        0
                    );
                    write_all(&mut connection, scheduler, &payload).await;
                    connection
                        .shutdown(scheduler, &Cancellation::never())
                        .await
                        .unwrap();
                    connection
                        .shutdown(scheduler, &Cancellation::never())
                        .await
                        .unwrap();
                    assert_eq!(
                        connection
                            .write(scheduler, b"closed", &Cancellation::never())
                            .await
                            .unwrap_err()
                            .kind(),
                        std::io::ErrorKind::BrokenPipe
                    );
                    assert_eq!(read_to_end(&mut connection, scheduler).await, payload);
                    connection
                        .close(scheduler, &Cancellation::never())
                        .await
                        .unwrap();
                };
                zip(server_work, client_work).await;
            }
        })
        .await
        .unwrap();
}

#[test]
fn tls12_and_tls13_round_trips_with_direct_scheduler() {
    let scheduler = direct();
    block_on(async {
        round_trip(&scheduler).await;
        scheduler.shutdown().await;
    });
}

#[test]
fn tls12_and_tls13_round_trips_with_tokio_scheduler() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let scheduler = TokioScheduler::new(runtime.handle().clone());
    runtime.block_on(async {
        round_trip(&scheduler).await;
        scheduler.shutdown().await;
    });
}

#[test]
fn client_interoperates_with_blocking_rustls_and_reports_truncated_tls() {
    let scheduler = direct();
    block_on(async {
        for graceful in [false, true] {
            let (client_config, server_config) = configs(false);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server_config).unwrap(),
                    socket,
                );
                let mut input = [0; 4];
                stream.read_exact(&mut input).unwrap();
                assert_eq!(&input, b"ping");
                stream.write_all(b"pong").unwrap();
                if graceful {
                    stream.conn.send_close_notify();
                }
                stream.flush().unwrap();
            });
            let client = TlsClientEndpoint::new(
                AddressEndpoint::new(address),
                RustlsConnector::new(client_config),
                "localhost",
            );
            let mut connection = client
                .connect(&scheduler, &Cancellation::never())
                .await
                .unwrap();
            write_all(&mut connection, &scheduler, b"ping").await;
            let mut received = Vec::new();
            let mut buffer = [0; 8];
            loop {
                match connection
                    .read(&scheduler, &mut buffer, &Cancellation::never())
                    .await
                {
                    Ok(0) => {
                        assert!(graceful);
                        break;
                    }
                    Ok(count) => received.extend_from_slice(&buffer[..count]),
                    Err(error) => {
                        assert!(!graceful);
                        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
                        break;
                    }
                }
            }
            assert_eq!(&received, b"pong");
            connection.abort(&scheduler).await.unwrap();
            peer.join().unwrap();
        }
        scheduler.shutdown().await;
    });
}

#[test]
fn server_interoperates_with_blocking_rustls_client() {
    let scheduler = direct();
    block_on(async {
        let (client_config, server_config) = configs(false);
        let server = TlsServerEndpoint::new(
            AddressEndpoint::new("127.0.0.1:0".parse().unwrap()),
            RustlsAcceptor::new(server_config),
        );
        let listener = server
            .bind(&scheduler, BindOptions::default(), &Cancellation::never())
            .await
            .unwrap()
            .remove(0);
        let address = scheduler.socket_local_address(listener.listener()).unwrap();
        let peer = std::thread::spawn(move || {
            let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ClientConnection::new(
                    client_config,
                    ServerName::try_from("localhost").unwrap(),
                )
                .unwrap(),
                socket,
            );
            stream.write_all(b"ping").unwrap();
            stream.flush().unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).unwrap();
            assert_eq!(&input, b"pong");
        });
        let (mut connection, _) = listener
            .accept(&scheduler, &Cancellation::never())
            .await
            .unwrap();
        let mut input = [0; 4];
        let mut offset = 0;
        while offset < input.len() {
            offset += connection
                .read(&scheduler, &mut input[offset..], &Cancellation::never())
                .await
                .unwrap();
        }
        assert_eq!(&input, b"ping");
        write_all(&mut connection, &scheduler, b"pong").await;
        connection
            .close(&scheduler, &Cancellation::never())
            .await
            .unwrap();
        listener.close(&scheduler).await.unwrap();
        peer.join().unwrap();
        scheduler.shutdown().await;
    });
}

#[test]
fn invalid_names_untrusted_certificates_and_alpn_mismatch_fail_without_plaintext_fallback() {
    let scheduler = direct();
    block_on(async {
        for failure in ["wrong-name", "untrusted", "alpn", "invalid-name"] {
            let (mut client_config, server_config) = configs(false);
            if failure == "untrusted" {
                client_config = configs(false).0;
            }
            if failure == "alpn" {
                Arc::make_mut(&mut client_config).alpn_protocols = vec![b"other/1".to_vec()];
            }
            let server = TlsServerEndpoint::new(
                AddressEndpoint::new("127.0.0.1:0".parse().unwrap()),
                RustlsAcceptor::new(server_config),
            );
            let listener = server
                .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                .await
                .unwrap()
                .remove(0);
            let address = scheduler.socket_local_address(listener.listener()).unwrap();
            let name = match failure {
                "wrong-name" => "different.test",
                "invalid-name" => "not a DNS name",
                _ => "localhost",
            };
            let client = TlsClientEndpoint::new(
                AddressEndpoint::new(address),
                RustlsConnector::new(client_config),
                name,
            );
            let (client_result, server_result) = zip(
                client.connect(&scheduler, &Cancellation::never()),
                listener.accept(&scheduler, &Cancellation::never()),
            )
            .await;
            let error = client_result.expect_err("authentication should fail");
            if failure == "invalid-name" {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            } else {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                let OperationError::Io(error) = error else {
                    panic!("expected I/O-wrapped TLS error")
                };
                assert!(error.get_ref().unwrap().is::<rustls::Error>());
            }
            assert!(server_result.is_err());
            listener.close(&scheduler).await.unwrap();
        }
        scheduler.shutdown().await;
    });
}

#[test]
fn cancellation_during_client_handshake_closes_the_plain_transport() {
    let scheduler = direct();
    block_on(async {
        let (client_config, _) = configs(false);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = Cancellation::new();
        let cancel = cancellation.clone();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            assert!(socket.read(&mut [0; 4096]).unwrap() > 0);
            cancel.cancel();
            let mut remaining = Vec::new();
            socket.read_to_end(&mut remaining).unwrap();
        });
        let client = TlsClientEndpoint::new(
            AddressEndpoint::new(address),
            RustlsConnector::new(client_config),
            "localhost",
        );
        assert!(matches!(
            client.connect(&scheduler, &cancellation).await,
            Err(OperationError::Cancelled(_))
        ));
        peer.join().unwrap();
        scheduler.shutdown().await;
    });
}

#[test]
fn precancelled_providers_close_consumed_transports() {
    let scheduler = direct();
    block_on(async {
        for client in [false, true] {
            let (client_config, server_config) = configs(false);
            let endpoint = AddressEndpoint::new("127.0.0.1:0".parse().unwrap());
            let listener = endpoint
                .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                .await
                .unwrap()
                .remove(0);
            let address = scheduler.socket_local_address(&listener).unwrap();
            let socket = AddressEndpoint::new(address)
                .connect(&scheduler, &Cancellation::never())
                .await
                .unwrap();
            let (peer, _) = scheduler
                .socket_accept(&listener, &Cancellation::never())
                .await
                .unwrap();
            let cancellation = Cancellation::new();
            cancellation.cancel();
            let result = if client {
                RustlsConnector::new(client_config)
                    .connect(&scheduler, socket, "localhost", &cancellation)
                    .await
            } else {
                RustlsAcceptor::new(server_config)
                    .accept(&scheduler, socket, &cancellation)
                    .await
            };
            assert!(matches!(result, Err(OperationError::Cancelled(_))));
            let mut reader = scheduler.socket_stream_reader(&peer).unwrap();
            assert_eq!(
                reader
                    .read_into(&mut [0], &Cancellation::never())
                    .await
                    .unwrap(),
                0
            );
            reader.close().await.unwrap();
            drop(reader);
            scheduler.socket_close(peer).await.unwrap();
            scheduler.socket_close(listener).await.unwrap();
        }
        scheduler.shutdown().await;
    });
}

#[test]
fn cancelled_stream_operations_and_close_preserve_cancellation_and_close_the_transport() {
    let scheduler = direct();
    block_on(async {
        let (client_config, server_config) = configs(false);
        let server = TlsServerEndpoint::new(
            AddressEndpoint::new("127.0.0.1:0".parse().unwrap()),
            RustlsAcceptor::new(server_config),
        );
        let listener = server
            .bind(&scheduler, BindOptions::default(), &Cancellation::never())
            .await
            .unwrap()
            .remove(0);
        let address = scheduler.socket_local_address(listener.listener()).unwrap();
        let client = TlsClientEndpoint::new(
            AddressEndpoint::new(address),
            RustlsConnector::new(client_config),
            "localhost",
        );
        let server_work = async {
            let (mut connection, _) = listener
                .accept(&scheduler, &Cancellation::never())
                .await
                .unwrap();
            // An abort with unread TLS records may reset TCP rather than
            // delivering a clean transport EOF. Neither is TLS close_notify.
            assert!(matches!(
                connection
                    .read(&scheduler, &mut [0], &Cancellation::never())
                    .await
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ));
            TlsStream::abort(connection, &scheduler).await.unwrap();
            listener.close(&scheduler).await.unwrap();
        };
        let client_work = async {
            let mut connection = client
                .connect(&scheduler, &Cancellation::never())
                .await
                .unwrap();
            let cancellation = Cancellation::new();
            cancellation.cancel();
            assert!(matches!(
                connection.read(&scheduler, &mut [0], &cancellation).await,
                Err(OperationError::Cancelled(_))
            ));
            assert!(matches!(
                connection.write(&scheduler, b"data", &cancellation).await,
                Err(OperationError::Cancelled(_))
            ));
            assert!(matches!(
                connection.flush(&scheduler, &cancellation).await,
                Err(OperationError::Cancelled(_))
            ));
            assert!(matches!(
                TlsStream::shutdown(&mut connection, &scheduler, &cancellation).await,
                Err(OperationError::Cancelled(_))
            ));
            assert!(matches!(
                TlsStream::close(connection, &scheduler, &cancellation).await,
                Err(OperationError::Cancelled(_))
            ));
        };
        zip(server_work, client_work).await;
        scheduler.shutdown().await;
    });
}

#[test]
fn server_handshake_reports_eof_and_handles_cancellation_while_waiting_for_client_finished() {
    let scheduler = direct();
    block_on(async {
        for cancel in [false, true] {
            let (client_config, server_config) = configs(false);
            let server = TlsServerEndpoint::new(
                AddressEndpoint::new("127.0.0.1:0".parse().unwrap()),
                RustlsAcceptor::new(server_config),
            );
            let listener = server
                .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                .await
                .unwrap()
                .remove(0);
            let address = scheduler.socket_local_address(listener.listener()).unwrap();
            let cancellation = Cancellation::new();
            let signal = cancellation.clone();
            let peer = std::thread::spawn(move || {
                let mut socket =
                    TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
                if cancel {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut state = rustls::ClientConnection::new(
                        client_config,
                        ServerName::try_from("localhost").unwrap(),
                    )
                    .unwrap();
                    while state.wants_write() {
                        state.write_tls(&mut socket).unwrap();
                    }
                    assert!(socket.read(&mut [0; 4096]).unwrap() > 0);
                    signal.cancel();
                    socket.read_to_end(&mut Vec::new()).unwrap();
                }
            });
            let error = listener
                .accept(&scheduler, &cancellation)
                .await
                .err()
                .unwrap();
            if cancel {
                assert!(matches!(error, OperationError::Cancelled(_)));
            } else {
                assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            listener.close(&scheduler).await.unwrap();
            peer.join().unwrap();
        }
        scheduler.shutdown().await;
    });
}

#[test]
fn supplied_rustls_configuration_supports_mutual_tls_and_no_alpn() {
    let scheduler = direct();
    block_on(async {
        let (server_cert, server_key) = identity();
        let (client_cert, client_key) = identity();
        let mut client_roots = RootCertStore::empty();
        client_roots.add(server_cert.clone()).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(client_roots)
            .with_client_auth_cert(vec![client_cert.clone()], client_key.into())
            .unwrap();
        let mut server_roots = RootCertStore::empty();
        server_roots.add(client_cert).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(server_roots))
            .build()
            .unwrap();
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert], server_key.into())
            .unwrap();
        let server = TlsServerEndpoint::new(
            AddressEndpoint::new("127.0.0.1:0".parse().unwrap()),
            RustlsAcceptor::new(Arc::new(server_config)),
        );
        let listener = server
            .bind(&scheduler, BindOptions::default(), &Cancellation::never())
            .await
            .unwrap()
            .remove(0);
        let address = scheduler.socket_local_address(listener.listener()).unwrap();
        let client = TlsClientEndpoint::new(
            AddressEndpoint::new(address),
            RustlsConnector::new(Arc::new(client_config)),
            "localhost",
        );
        let server_work = async {
            let (mut connection, _) = listener
                .accept(&scheduler, &Cancellation::never())
                .await
                .unwrap();
            assert_eq!(connection.peer_certificates().unwrap().len(), 1);
            assert_eq!(connection.negotiated_protocol(), None);
            write_all(&mut connection, &scheduler, b"mTLS").await;
            TlsStream::close(connection, &scheduler, &Cancellation::never())
                .await
                .unwrap();
            listener.close(&scheduler).await.unwrap();
        };
        let client_work = async {
            let mut connection = client
                .connect(&scheduler, &Cancellation::never())
                .await
                .unwrap();
            assert_eq!(connection.negotiated_protocol(), None);
            assert_eq!(read_to_end(&mut connection, &scheduler).await, b"mTLS");
            TlsStream::abort(connection, &scheduler).await.unwrap();
        };
        zip(server_work, client_work).await;
        scheduler.shutdown().await;
    });
}

#[test]
fn duplex_stream_interoperates_with_blocking_peer_under_backpressure() {
    use base_endpoint::stream::{ReadableStream, WritableStream};
    let scheduler = direct();
    block_on(async {
        for tls12 in [false, true] {
            let (client_config, server_config) = configs(tls12);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server_config).unwrap(),
                    socket,
                );
                let mut remaining = 1024 * 1024;
                let mut buffer = [0; 4096];
                while remaining != 0 {
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0);
                    assert!(buffer[..count].iter().all(|byte| *byte == b'x'));
                    remaining -= count;
                    stream.write_all(&buffer[..count]).unwrap();
                    stream.flush().unwrap();
                }
                let mut extra = [0];
                assert_eq!(stream.read(&mut extra).unwrap(), 0);
                stream.conn.send_close_notify();
                stream.flush().unwrap();
            });
            scheduler
                .timeout(Duration::from_secs(15), async {
                    let endpoint = TlsClientEndpoint::new(
                        AddressEndpoint::new(address),
                        RustlsConnector::new(client_config),
                        "localhost",
                    );
                    let connection = endpoint
                        .connect(&scheduler, &Cancellation::never())
                        .await
                        .unwrap();
                    connection
                        .with_duplex(
                            &scheduler,
                            &Cancellation::never(),
                            |mut reader, mut writer| async move {
                                let send = async {
                                    let data = vec![b'x'; 1024 * 1024];
                                    let mut remaining = data.as_slice();
                                    while !remaining.is_empty() {
                                        let count =
                                            writer.write(remaining, &Cancellation::never()).await?;
                                        assert_ne!(count, 0);
                                        remaining = &remaining[count..];
                                    }
                                    writer.flush(&Cancellation::never()).await
                                };
                                let receive = async {
                                    let mut total = 0;
                                    let mut buffer = [0; 997];
                                    while total != 1024 * 1024 {
                                        let count = reader
                                            .read_into(&mut buffer, &Cancellation::never())
                                            .await?;
                                        assert_ne!(count, 0);
                                        assert!(buffer[..count].iter().all(|byte| *byte == b'x'));
                                        total += count;
                                    }
                                    Ok::<_, OperationError>(())
                                };
                                let (sent, received) = zip(send, receive).await;
                                sent?;
                                received
                            },
                        )
                        .await
                        .unwrap();
                })
                .await
                .unwrap();
            peer.join().unwrap();
        }
        scheduler.shutdown().await;
    });
}

#[test]
fn duplex_io_runs_without_polling_its_supervisor() {
    use base_endpoint::stream::{ReadableStream, WritableStream};
    use futures_lite::future::poll_once;
    use std::sync::Mutex;

    let scheduler = direct();
    block_on(async {
        for tls12 in [false, true] {
            let (client_config, server_config) = configs(tls12);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server_config).unwrap(),
                    socket,
                );
                let mut data = vec![0; 256 * 1024];
                stream.read_exact(&mut data).unwrap();
                assert!(data.iter().all(|byte| *byte == b'x'));
                stream.write_all(&data).unwrap();
                stream.conn.send_close_notify();
                stream.flush().unwrap();
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            });
            scheduler
                .timeout(Duration::from_secs(15), async {
                    let cancel = Cancellation::never();
                    let connection = TlsClientEndpoint::new(
                        AddressEndpoint::new(address),
                        RustlsConnector::new(client_config),
                        "localhost",
                    )
                    .connect(&scheduler, &cancel)
                    .await
                    .unwrap();
                    let handles = Mutex::new(None);
                    let done = Cancellation::new();
                    let slot = &handles;
                    let finished = &done;
                    let mut supervised = Box::pin(connection.with_duplex(
                        &scheduler,
                        &cancel,
                        move |reader, writer| async move {
                            *slot.lock().unwrap() = Some((reader, writer));
                            finished.cancelled().await;
                            Ok::<_, OperationError>(())
                        },
                    ));
                    assert!(poll_once(&mut supervised).await.is_none());
                    let (mut reader, mut writer) = handles.lock().unwrap().take().unwrap();
                    // Freeze supervision after setup. Both directions must
                    // drive retained transport state in this calling context.
                    let data = vec![b'x'; 256 * 1024];
                    let mut remaining = data.as_slice();
                    while !remaining.is_empty() {
                        let count = writer.write(remaining, &cancel).await.unwrap();
                        assert_ne!(count, 0);
                        remaining = &remaining[count..];
                    }
                    writer.flush(&cancel).await.unwrap();
                    let mut echoed = 0;
                    let mut buffer = [0; 997];
                    loop {
                        let count = reader.read_into(&mut buffer, &cancel).await.unwrap();
                        if count == 0 {
                            break;
                        }
                        assert!(buffer[..count].iter().all(|byte| *byte == b'x'));
                        echoed += count;
                    }
                    assert_eq!(echoed, data.len());
                    drop(writer);
                    drop(reader);
                    done.cancel();
                    supervised.await.unwrap();
                })
                .await
                .unwrap();
            peer.join().unwrap();
        }
        scheduler.shutdown().await;
    });
}

#[test]
fn duplex_lifetime_cancellation_wakes_a_read_with_an_independent_signal() {
    use base_endpoint::stream::ReadableStream;
    let scheduler = direct();
    let (client_config, server_config) = configs(false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(server_config).unwrap(),
            socket,
        );
        let mut byte = [0];
        assert!(matches!(stream.read(&mut byte), Ok(0) | Err(_)));
    });
    block_on(async {
        scheduler
            .timeout(Duration::from_secs(15), async {
                let endpoint = TlsClientEndpoint::new(
                    AddressEndpoint::new(address),
                    RustlsConnector::new(client_config),
                    "localhost",
                );
                let connection = endpoint
                    .connect(&scheduler, &Cancellation::never())
                    .await
                    .unwrap();
                let lifetime = Cancellation::new();
                let operation = connection.with_duplex(
                    &scheduler,
                    &lifetime,
                    |mut reader, _writer| async move {
                        reader.read_into(&mut [0], &Cancellation::never()).await
                    },
                );
                let cancel = async {
                    futures_lite::future::yield_now().await;
                    lifetime.cancel();
                };
                let (result, ()) = zip(operation, cancel).await;
                assert!(matches!(result, Err(OperationError::Cancelled(_))));
            })
            .await
            .unwrap();
        scheduler.shutdown().await;
    });
    peer.join().unwrap();
}

#[test]
fn duplex_input_reports_tls_truncation_after_consuming_authenticated_plaintext() {
    use base_endpoint::stream::ReadableStream;
    let scheduler = direct();
    let (client_config, server_config) = configs(false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(server_config).unwrap(),
            socket,
        );
        stream.write_all(b"abc").unwrap();
        stream.flush().unwrap();
        // Drop TCP without the authenticated TLS closure.
    });
    block_on(async {
        scheduler.timeout(Duration::from_secs(15), async {
            let endpoint = TlsClientEndpoint::new(AddressEndpoint::new(address), RustlsConnector::new(client_config), "localhost");
            let connection = endpoint.connect(&scheduler, &Cancellation::never()).await.unwrap();
            connection.with_duplex(&scheduler, &Cancellation::never(), |mut reader, _writer| async move {
                let mut data = [0; 3];
                let mut offset = 0;
                while offset != data.len() { offset += reader.read_into(&mut data[offset..], &Cancellation::never()).await?; }
                assert_eq!(&data, b"abc");
                let error = reader.read_into(&mut [0], &Cancellation::never()).await.unwrap_err();
                assert!(matches!(error, OperationError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof));
                Err::<(), OperationError>(std::io::Error::other("expected truncation").into())
            }).await.unwrap_err();
        }).await.unwrap();
        scheduler.shutdown().await;
    });
    peer.join().unwrap();
}
