// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

#![allow(
    dead_code,
    reason = "support module is shared by independent integration tests"
)]

use base_scheduler::{
    AddressHints, AddressInfo, AddressResolution, AddressService, Cancellation, Cancelled,
    OperationResult, SocketAccept, SocketAddress, SocketBind, SocketClose, SocketConnect,
    SocketDomain, SocketListen, SocketOpen, SocketOperation, SocketProtocol, SocketType,
};
use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    sync::Mutex,
    task::{Poll, Waker},
};

#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Ok,
    Io(io::ErrorKind),
    Cancelled,
    CancelThenIo(io::ErrorKind),
    CancelAfterSuccess,
}

impl Outcome {
    fn finish(self, cancellation: &Cancellation) -> OperationResult<()> {
        match self {
            Self::Ok => Ok(()),
            Self::Io(kind) => Err(io::Error::from(kind).into()),
            Self::Cancelled => Err(Cancelled.into()),
            Self::CancelThenIo(kind) => {
                cancellation.cancel();
                Err(io::Error::from(kind).into())
            }
            Self::CancelAfterSuccess => {
                cancellation.cancel();
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum Step {
    Resolve(Outcome, Vec<SocketAddress>),
    Open(Outcome),
    Connect(Outcome),
    Accept(Outcome, usize),
    Bind(Outcome),
    Listen(Outcome),
    Close(bool),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Resolve(Option<String>, u16, AddressHints),
    Open(usize, SocketDomain, SocketType, Option<SocketProtocol>),
    Connect(usize, SocketAddress),
    Accept(usize),
    Bind(usize, SocketAddress),
    Listen(usize, i32),
    Close(usize),
}

#[derive(Default)]
pub struct Model {
    steps: Mutex<VecDeque<Step>>,
    events: Mutex<Vec<Event>>,
    cleanup_gate: Mutex<(bool, Option<Waker>)>,
}

impl Model {
    pub fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            ..Self::default()
        }
    }

    fn next(&self, event: Event) -> Step {
        self.events.lock().unwrap().push(event);
        self.steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected scheduler call")
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn finished(&self) {
        assert!(
            self.steps.lock().unwrap().is_empty(),
            "unconsumed scheduler calls"
        );
    }

    pub fn pause_cleanup(&self) {
        self.cleanup_gate.lock().unwrap().0 = true;
    }

    pub fn resume_cleanup(&self) {
        let mut gate = self.cleanup_gate.lock().unwrap();
        gate.0 = false;
        let waker = gate.1.take();
        drop(gate);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl SocketOperation for Model {
    type Socket = usize;
}

impl SocketOpen for Model {
    async fn socket_open(
        &self,
        domain: SocketDomain,
        kind: SocketType,
        protocol: Option<SocketProtocol>,
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        let id = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, Event::Open(..)))
            .count();
        let Step::Open(outcome) = self.next(Event::Open(id, domain, kind, protocol)) else {
            panic!("expected Open")
        };
        outcome.finish(cancellation)?;
        Ok(id)
    }
}

impl SocketConnect for Model {
    async fn socket_connect(
        &self,
        socket: &usize,
        address: SocketAddress,
        cancellation: &Cancellation,
    ) -> OperationResult<()> {
        let Step::Connect(outcome) = self.next(Event::Connect(*socket, address)) else {
            panic!("expected Connect")
        };
        outcome.finish(cancellation)
    }
}

impl SocketAccept for Model {
    async fn socket_accept(
        &self,
        socket: &usize,
        cancellation: &Cancellation,
    ) -> OperationResult<(usize, SocketAddress)> {
        let Step::Accept(outcome, accepted) = self.next(Event::Accept(*socket)) else {
            panic!("expected Accept")
        };
        outcome.finish(cancellation)?;
        Ok((accepted, address(4567)))
    }
}

impl SocketBind for Model {
    async fn socket_bind(
        &self,
        socket: &usize,
        address: SocketAddress,
        cancellation: &Cancellation,
    ) -> OperationResult<()> {
        let Step::Bind(outcome) = self.next(Event::Bind(*socket, address)) else {
            panic!("expected Bind")
        };
        outcome.finish(cancellation)
    }
}

impl SocketListen for Model {
    async fn socket_listen(
        &self,
        socket: &usize,
        backlog: i32,
        cancellation: &Cancellation,
    ) -> OperationResult<()> {
        let Step::Listen(outcome) = self.next(Event::Listen(*socket, backlog)) else {
            panic!("expected Listen")
        };
        outcome.finish(cancellation)
    }
}

impl SocketClose for Model {
    async fn socket_close(&self, socket: usize) -> io::Result<()> {
        let Step::Close(fails) = self.next(Event::Close(socket)) else {
            panic!("expected Close")
        };
        poll_fn(|cx| {
            let mut gate = self.cleanup_gate.lock().unwrap();
            if gate.0 {
                gate.1 = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        if fails {
            Err(io::Error::other("close failed"))
        } else {
            Ok(())
        }
    }

    async fn socket_close_submit(&self, socket: usize) -> io::Result<()> {
        self.socket_close(socket).await
    }
}

impl AddressResolution for Model {
    type Addresses = Vec<AddressInfo>;

    async fn address_resolve(
        &self,
        name: Option<&str>,
        service: AddressService<'_>,
        hints: AddressHints,
        cancellation: &Cancellation,
    ) -> OperationResult<Self::Addresses> {
        let AddressService::Port(port) = service else {
            panic!("expected numeric port")
        };
        let Step::Resolve(outcome, addresses) =
            self.next(Event::Resolve(name.map(str::to_owned), port, hints))
        else {
            panic!("expected Resolve")
        };
        outcome.finish(cancellation)?;
        Ok(addresses
            .into_iter()
            .map(|address| AddressInfo {
                address,
                socket_type: SocketType::Stream,
                protocol: Some(SocketProtocol::Tcp),
            })
            .collect())
    }
}

pub fn address(port: u16) -> SocketAddress {
    ([127, 0, 0, 1], port).into()
}

pub fn open(id: usize) -> Event {
    Event::Open(
        id,
        SocketDomain::Ipv4,
        SocketType::Stream,
        Some(SocketProtocol::Tcp),
    )
}
