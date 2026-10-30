// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use base_endpoint::{
    AddressEndpoint, BindEndpoint, BindOptions, ConnectEndpoint, HostEndpoint,
    stream::{ReadableStream, WritableStream},
};
use base_scheduler::{
    AddressResolution, Cancellation, Clock, SocketAccept, SocketBind, SocketClose, SocketConnect,
    SocketDomain, SocketListen, SocketLocalAddress, SocketOpen, SocketStreamReading,
    SocketStreamWriting,
};
use base_scheduler_direct::{DirectOptions, DirectScheduler};
use base_scheduler_tokio::TokioScheduler;
use futures_lite::future::block_on;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

async fn exercise<S>(scheduler: &S)
where
    S: AddressResolution
        + SocketOpen
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
            let never = Cancellation::never();
            // Verify binding against a standard-library peer, independent of our connect implementation.
            let listeners = HostEndpoint::wildcard(0)
                .with_domain(SocketDomain::Ipv4)
                .bind(scheduler, BindOptions::default(), &never)
                .await
                .unwrap();
            assert_eq!(listeners.len(), 1);
            let local = scheduler.socket_local_address(&listeners[0]).unwrap();
            let peer_address = std::net::SocketAddr::from(([127, 0, 0, 1], local.port()));
            let peer = std::thread::spawn(move || {
                let mut socket =
                    TcpStream::connect_timeout(&peer_address, Duration::from_secs(5)).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket.write_all(b"ping").unwrap();
                let mut reply = [0; 4];
                socket.read_exact(&mut reply).unwrap();
                assert_eq!(&reply, b"pong");
            });
            let (accepted, _) = scheduler
                .socket_accept(&listeners[0], &never)
                .await
                .unwrap();
            exchange(scheduler, &accepted, b"ping", b"pong").await;
            scheduler.socket_close(accepted).await.unwrap();
            for listener in listeners {
                scheduler.socket_close(listener).await.unwrap();
            }
            peer.join().unwrap();

            // Verify both connecting implementations against an independent standard-library listener.
            for hostname in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let local = listener.local_addr().unwrap();
                let peer = std::thread::spawn(move || {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socket.write_all(b"hello").unwrap();
                    let mut reply = [0; 5];
                    socket.read_exact(&mut reply).unwrap();
                    assert_eq!(&reply, b"world");
                });
                let connected = if hostname {
                    HostEndpoint::new("localhost", local.port())
                        .with_domain(SocketDomain::Ipv4)
                        .connect(scheduler, &never)
                        .await
                        .unwrap()
                } else {
                    AddressEndpoint::new(local)
                        .connect(scheduler, &never)
                        .await
                        .unwrap()
                };
                exchange(scheduler, &connected, b"hello", b"world").await;
                scheduler.socket_close(connected).await.unwrap();
                peer.join().unwrap();
            }
        })
        .await
        .unwrap();
}

async fn exchange<S>(scheduler: &S, socket: &S::Socket, expected: &[u8], reply: &[u8])
where
    S: SocketStreamReading + SocketStreamWriting,
    S::Socket: 'static,
{
    // Socket lanes provide the plaintext stream contracts directly.
    let mut reader = scheduler.socket_stream_reader(socket).unwrap();
    let mut writer = scheduler.socket_stream_writer(socket).unwrap();
    transfer(&mut reader, &mut writer, expected, reply).await;
}

async fn transfer(
    reader: &mut impl ReadableStream,
    writer: &mut impl WritableStream,
    expected: &[u8],
    reply: &[u8],
) {
    let never = Cancellation::never();
    let mut received = vec![0; expected.len()];
    let mut offset = 0;
    while offset < received.len() {
        let count = reader
            .read_into(&mut received[offset..], &never)
            .await
            .unwrap();
        assert!(count > 0, "unexpected EOF");
        offset += count;
    }
    assert_eq!(received, expected);
    let mut offset = 0;
    while offset < reply.len() {
        let count = writer.write(&reply[offset..], &never).await.unwrap();
        assert!(count > 0, "write made no progress");
        offset += count;
    }
    writer.flush(&never).await.unwrap();
    ReadableStream::close(reader).await.unwrap();
    WritableStream::close(writer).await.unwrap();
}

#[test]
fn direct_scheduler_tcp_establishment_and_io() {
    let scheduler = DirectScheduler::new(DirectOptions {
        threads: 2,
        capacity: 16,
    })
    .unwrap();
    block_on(async {
        exercise(&scheduler).await;
        scheduler.shutdown().await;
    });
}

#[test]
fn tokio_scheduler_tcp_establishment_and_io() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let scheduler = TokioScheduler::new(runtime.handle().clone());
    runtime.block_on(async {
        exercise(&scheduler).await;
        scheduler.shutdown().await;
    });
}
