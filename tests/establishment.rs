// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

mod support;

use base_endpoint::{
    AddressEndpoint, BindEndpoint, BindOptions, CompositeEndpoint, ConnectEndpoint, HostEndpoint,
};
use base_scheduler::{
    AddressHints, Cancellation, OperationError, SocketDomain, SocketProtocol, SocketType,
};
use futures_lite::future::{block_on, poll_once};
use std::io::ErrorKind;
use support::{Event, Model, Outcome::*, Step, address, open};

#[test]
fn numeric_endpoints_connect_and_listen_without_resolving() {
    block_on(async {
        let endpoint = AddressEndpoint::new(address(1234));
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Connect(Ok),
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
        ]);
        let never = Cancellation::never();
        assert_eq!(endpoint.connect(&scheduler, &never).await.unwrap(), 0);
        assert_eq!(
            endpoint
                .bind(&scheduler, BindOptions { backlog: 17 }, &never)
                .await
                .unwrap(),
            vec![1]
        );
        assert_eq!(
            scheduler.events(),
            [
                open(0),
                Event::Connect(0, address(1234)),
                open(1),
                Event::Bind(1, address(1234)),
                Event::Listen(1, 17)
            ]
        );
        scheduler.finished();
    });
}

#[test]
fn failed_numeric_establishment_closes_only_created_sockets_and_preserves_primary_errors() {
    block_on(async {
        for connect in [false, true] {
            for close_fails in [false, true] {
                for failure in 0..if connect { 2 } else { 3 } {
                    let mut steps = vec![Step::Open(if failure == 0 {
                        Io(ErrorKind::PermissionDenied)
                    } else {
                        Ok
                    })];
                    if failure > 0 {
                        if connect {
                            steps.push(Step::Connect(Io(ErrorKind::PermissionDenied)));
                        } else {
                            steps.push(Step::Bind(if failure == 1 {
                                Io(ErrorKind::PermissionDenied)
                            } else {
                                Ok
                            }));
                            if failure == 2 {
                                steps.push(Step::Listen(Io(ErrorKind::PermissionDenied)));
                            }
                        }
                        steps.push(Step::Close(close_fails));
                    }
                    let scheduler = Model::new(steps);
                    let endpoint = AddressEndpoint::new(address(1234));
                    let error = if connect {
                        endpoint
                            .connect(&scheduler, &Cancellation::never())
                            .await
                            .unwrap_err()
                    } else {
                        endpoint
                            .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                            .await
                            .unwrap_err()
                    };
                    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
                    scheduler.finished();
                }
            }
        }
    });
}

#[test]
fn composite_connect_falls_back_in_order_with_fresh_sockets_and_returns_last_error() {
    block_on(async {
        let endpoint = CompositeEndpoint::new(vec![
            AddressEndpoint::new(address(1)),
            AddressEndpoint::new(address(2)),
        ]);
        assert_eq!(endpoint.endpoints().len(), 2);
        for last in [Ok, Io(ErrorKind::ConnectionRefused)] {
            let scheduler = Model::new(
                [
                    Step::Open(Ok),
                    Step::Connect(Io(ErrorKind::NetworkUnreachable)),
                    Step::Close(false),
                    Step::Open(Ok),
                    Step::Connect(last),
                ]
                .into_iter()
                .chain(matches!(last, Io(_)).then_some(Step::Close(false))),
            );
            let result = endpoint.connect(&scheduler, &Cancellation::never()).await;
            match last {
                Ok => assert_eq!(result.unwrap(), 1),
                _ => assert_eq!(result.unwrap_err().kind(), ErrorKind::ConnectionRefused),
            }
            let events = scheduler.events();
            assert_eq!(
                &events[..5],
                [
                    open(0),
                    Event::Connect(0, address(1)),
                    Event::Close(0),
                    open(1),
                    Event::Connect(1, address(2))
                ]
            );
            scheduler.finished();
        }
    });
}

#[test]
fn cancellation_stops_connection_fallback_even_if_the_backend_returns_an_io_error() {
    block_on(async {
        for outcome in [Cancelled, CancelThenIo(ErrorKind::ConnectionRefused)] {
            let cancellation = Cancellation::new();
            let scheduler =
                Model::new([Step::Open(Ok), Step::Connect(outcome), Step::Close(false)]);
            let endpoint = CompositeEndpoint::new(vec![
                AddressEndpoint::new(address(1)),
                AddressEndpoint::new(address(2)),
            ]);
            let error = endpoint
                .connect(&scheduler, &cancellation)
                .await
                .unwrap_err();
            assert!(matches!(error, OperationError::Cancelled(_)));
            scheduler.finished();
        }
    });
}

#[test]
fn bind_is_all_or_nothing_and_attempts_every_rollback_even_after_a_close_error() {
    block_on(async {
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
            Step::Open(Ok),
            Step::Bind(Io(ErrorKind::AddrInUse)),
            Step::Close(true),
            Step::Close(true),
            Step::Close(false),
        ]);
        let endpoint = CompositeEndpoint::new(
            (1..=3)
                .map(|port| AddressEndpoint::new(address(port)))
                .collect(),
        );
        let error = endpoint
            .bind(&scheduler, BindOptions::default(), &Cancellation::never())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AddrInUse);
        let events = scheduler.events();
        assert_eq!(
            &events[8..],
            [Event::Close(2), Event::Close(0), Event::Close(1)]
        );
        scheduler.finished();
    });
}

#[test]
fn cancellation_between_binds_rolls_back_previous_success() {
    block_on(async {
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(CancelAfterSuccess),
            Step::Close(false),
        ]);
        let endpoint = CompositeEndpoint::new(vec![
            AddressEndpoint::new(address(1)),
            AddressEndpoint::new(address(2)),
        ]);
        let error = endpoint
            .bind(&scheduler, BindOptions::default(), &Cancellation::new())
            .await
            .unwrap_err();
        assert!(matches!(error, OperationError::Cancelled(_)));
        scheduler.finished();
    });
}

#[test]
fn bind_cancellation_closes_current_and_previous_listeners() {
    block_on(async {
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Cancelled),
            Step::Close(false),
            Step::Close(false),
        ]);
        let endpoint = CompositeEndpoint::new(vec![
            AddressEndpoint::new(address(1)),
            AddressEndpoint::new(address(2)),
        ]);
        let error = endpoint
            .bind(&scheduler, BindOptions::default(), &Cancellation::new())
            .await
            .unwrap_err();
        assert!(matches!(error, OperationError::Cancelled(_)));
        let events = scheduler.events();
        assert_eq!(&events[6..], [Event::Close(1), Event::Close(0)]);
        scheduler.finished();
    });
}

#[test]
fn empty_composites_fail_and_precancellation_prevents_all_work() {
    block_on(async {
        let scheduler = Model::default();
        let cancellation = Cancellation::new();
        let endpoint = CompositeEndpoint::<AddressEndpoint>::new(vec![]);
        assert_eq!(
            endpoint
                .connect(&scheduler, &cancellation)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::AddrNotAvailable
        );
        assert_eq!(
            endpoint
                .bind(&scheduler, BindOptions::default(), &cancellation)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::AddrNotAvailable
        );
        cancellation.cancel();
        assert!(matches!(
            endpoint.connect(&scheduler, &cancellation).await,
            Err(OperationError::Cancelled(_))
        ));
        assert!(matches!(
            endpoint
                .bind(&scheduler, BindOptions::default(), &cancellation)
                .await,
            Err(OperationError::Cancelled(_))
        ));
        let endpoint = AddressEndpoint::new(address(1));
        assert!(matches!(
            endpoint.connect(&scheduler, &cancellation).await,
            Err(OperationError::Cancelled(_))
        ));
        assert!(matches!(
            endpoint
                .bind(&scheduler, BindOptions::default(), &cancellation)
                .await,
            Err(OperationError::Cancelled(_))
        ));
        let endpoint = HostEndpoint::new("localhost", 1);
        assert!(matches!(
            endpoint.connect(&scheduler, &cancellation).await,
            Err(OperationError::Cancelled(_))
        ));
        assert!(matches!(
            endpoint
                .bind(&scheduler, BindOptions::default(), &cancellation)
                .await,
            Err(OperationError::Cancelled(_))
        ));
        assert!(scheduler.events().is_empty());
    });
}

#[test]
fn hostname_connect_resolves_each_time_and_preserves_candidate_order_and_duplicates() {
    block_on(async {
        let addresses = vec![address(1), address(1), address(2)];
        let scheduler = Model::new([
            Step::Resolve(Ok, addresses.clone()),
            Step::Open(Ok),
            Step::Connect(Io(ErrorKind::ConnectionRefused)),
            Step::Close(false),
            Step::Open(Ok),
            Step::Connect(Io(ErrorKind::ConnectionRefused)),
            Step::Close(false),
            Step::Open(Ok),
            Step::Connect(Ok),
            Step::Resolve(Ok, addresses.clone()),
        ]);
        let endpoint = HostEndpoint::new("service.test", 80).with_domain(SocketDomain::Ipv4);
        let never = Cancellation::never();
        assert_eq!(endpoint.connect(&scheduler, &never).await.unwrap(), 2);
        assert_eq!(
            endpoint
                .resolve(&scheduler, false, &never)
                .await
                .unwrap()
                .iter()
                .map(AddressEndpoint::address)
                .collect::<Vec<_>>(),
            addresses
        );
        let events = scheduler.events();
        let resolution = Event::Resolve(
            Some("service.test".into()),
            80,
            AddressHints {
                domain: Some(SocketDomain::Ipv4),
                socket_type: Some(SocketType::Stream),
                protocol: Some(SocketProtocol::Tcp),
                ..Default::default()
            },
        );
        assert_eq!(events[0], resolution);
        assert_eq!(events[9], resolution);
        assert_eq!(events[5], Event::Connect(1, address(1)));
        assert_eq!(events[8], Event::Connect(2, address(2)));
        scheduler.finished();
    });
}

#[test]
fn hostname_bind_uses_passive_resolution_and_returns_all_listeners() {
    block_on(async {
        let scheduler = Model::new([
            Step::Resolve(Ok, vec![address(1), address(2)]),
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
        ]);
        let endpoint = HostEndpoint::wildcard(8080);
        assert_eq!(
            endpoint
                .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                .await
                .unwrap(),
            [0, 1]
        );
        let events = scheduler.events();
        assert_eq!(
            events[0],
            Event::Resolve(
                None,
                8080,
                AddressHints {
                    socket_type: Some(SocketType::Stream),
                    protocol: Some(SocketProtocol::Tcp),
                    passive: true,
                    ..Default::default()
                }
            )
        );
        assert_eq!(events[3], Event::Listen(0, 128));
        assert_eq!(events[6], Event::Listen(1, 128));
        scheduler.finished();
    });
}

#[test]
fn empty_or_failed_resolution_never_opens_a_socket() {
    block_on(async {
        for outcome in [Ok, Io(ErrorKind::NotFound), Cancelled] {
            for bind in [false, true] {
                let scheduler = Model::new([Step::Resolve(outcome, vec![])]);
                let endpoint = HostEndpoint::new("service.test", 80);
                let error = if bind {
                    endpoint
                        .bind(&scheduler, BindOptions::default(), &Cancellation::never())
                        .await
                        .unwrap_err()
                } else {
                    endpoint
                        .connect(&scheduler, &Cancellation::never())
                        .await
                        .unwrap_err()
                };
                match outcome {
                    Ok => assert_eq!(error.kind(), ErrorKind::AddrNotAvailable),
                    Io(kind) => assert_eq!(error.kind(), kind),
                    _ => assert!(matches!(error, OperationError::Cancelled(_))),
                }
                scheduler.finished();
            }
        }
    });
}

#[test]
fn endpoint_descriptions_are_inspectable_without_io() {
    let endpoint = AddressEndpoint::new(address(80));
    assert_eq!(endpoint.address(), address(80));
    assert_eq!(endpoint.to_string(), "tcp://127.0.0.1:80");
    let endpoint = AddressEndpoint::new("[::1]:80".parse().unwrap());
    assert_eq!(endpoint.to_string(), "tcp://[::1]:80");
    let endpoint = HostEndpoint::new("localhost", 80);
    assert_eq!(endpoint.hostname(), Some("localhost"));
    assert_eq!(endpoint.port(), 80);
    assert_eq!(endpoint.to_string(), "tcp://localhost:80");
    assert_eq!(HostEndpoint::new("::1", 80).to_string(), "tcp://[::1]:80");
    let endpoint = HostEndpoint::wildcard(80);
    assert_eq!(endpoint.hostname(), None);
    assert_eq!(endpoint.to_string(), "tcp://*:80");
}

#[test]
fn establishment_is_lazy_and_failed_attempts_await_cleanup_before_fallback() {
    block_on(async {
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Connect(Io(ErrorKind::ConnectionRefused)),
            Step::Close(false),
            Step::Open(Ok),
            Step::Connect(Ok),
        ]);
        scheduler.pause_cleanup();
        let endpoint = CompositeEndpoint::new(vec![
            AddressEndpoint::new(address(1)),
            AddressEndpoint::new(address(2)),
        ]);
        let never = Cancellation::never();
        let mut future = std::pin::pin!(endpoint.connect(&scheduler, &never));
        assert!(scheduler.events().is_empty());
        assert!(poll_once(future.as_mut()).await.is_none());
        assert_eq!(
            scheduler.events(),
            [open(0), Event::Connect(0, address(1)), Event::Close(0)]
        );
        scheduler.resume_cleanup();
        // The gate is the only reason the first poll can return Pending: later scheduler calls would violate the script before cleanup completes.
        assert_eq!(future.await.unwrap(), 1);
        assert_eq!(
            scheduler.events(),
            [
                open(0),
                Event::Connect(0, address(1)),
                Event::Close(0),
                open(1),
                Event::Connect(1, address(2))
            ]
        );
        scheduler.finished();
    });
}

#[test]
fn ipv6_addresses_preserve_flow_information_and_scope_when_connecting_and_binding() {
    block_on(async {
        let address = std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 443, 42, 7).into();
        let endpoint = AddressEndpoint::new(address);
        let scheduler = Model::new([
            Step::Open(Ok),
            Step::Connect(Ok),
            Step::Open(Ok),
            Step::Bind(Ok),
            Step::Listen(Ok),
        ]);
        let never = Cancellation::never();
        endpoint.connect(&scheduler, &never).await.unwrap();
        endpoint
            .bind(&scheduler, BindOptions::default(), &never)
            .await
            .unwrap();
        assert_eq!(
            scheduler.events(),
            [
                Event::Open(
                    0,
                    SocketDomain::Ipv6,
                    SocketType::Stream,
                    Some(SocketProtocol::Tcp)
                ),
                Event::Connect(0, address),
                Event::Open(
                    1,
                    SocketDomain::Ipv6,
                    SocketType::Stream,
                    Some(SocketProtocol::Tcp)
                ),
                Event::Bind(1, address),
                Event::Listen(1, 128),
            ]
        );
        scheduler.finished();
    });
}
