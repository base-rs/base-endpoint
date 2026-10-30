// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

#![cfg(feature = "rustls")]

// A scripted in-memory scheduler connects the client under test to an
// in-process rustls server. Transport faults are injected deterministically,
// and every future is polled a bounded number of times so a broken invariant
// fails instead of hanging.

use base_endpoint::{
    stream::{ReadableStream, WritableStream},
    tls::{
        TlsAcceptor, TlsConnector,
        rustls::{
            EncryptedSocketStreamReader, EncryptedSocketStreamWriter, RustlsAcceptor,
            RustlsConnection, RustlsConnector,
        },
    },
};
use base_scheduler::{
    BufferLease, BufferPoolOptions, BufferPooling, Cancellation, Cancelled, HeapBufferPool, IoBuf,
    IoBufSequence, IoBufSequenceMut, OperationError, OperationResult, SocketClose, SocketOperation,
    SocketRecvFlags, SocketRecvResult, SocketSendFlags, SocketStreamReader, SocketStreamReading,
    SocketStreamWriter, SocketStreamWriting,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    server::ProducesTickets,
};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io::{self, ErrorKind, IoSlice, IoSliceMut, Read, Write},
    marker::PhantomData,
    pin::{Pin, pin},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

const POLL_LIMIT: usize = 10_000;

#[derive(Default)]
struct Faults {
    reader_unavailable: bool,
    writer_unavailable: bool,
    read_error: bool,
    write_error: bool,
    write_zero: bool,
    write_blocked: bool,
    flush_error: bool,
    reader_close_error: bool,
    reader_close_pending: bool,
    writer_close_error: bool,
    socket_close_error: bool,
    cancel_on_write: Option<Cancellation>,
    cancel_on_flush: Option<Cancellation>,
}

#[derive(Default)]
struct Wire {
    bytes: VecDeque<u8>,
    closed: bool,
}

// One scripted socket. Inbound carries server records to the client.
#[derive(Default)]
struct Memory {
    inbound: Mutex<Wire>,
    outbound: Mutex<Wire>,
    faults: Mutex<Faults>,
    closes: AtomicUsize,
}

impl Memory {
    fn faults(&self) -> std::sync::MutexGuard<'_, Faults> {
        self.faults.lock().unwrap()
    }

    fn closes(&self) -> usize {
        self.closes.load(Ordering::SeqCst)
    }
}

fn failure(kind: ErrorKind) -> OperationError {
    io::Error::new(kind, "injected transport fault").into()
}

struct Reader<'a>(&'a Memory);

impl SocketStreamReader for Reader<'_> {
    type Buffer = BufferLease;

    async fn read(&mut self, _: &Cancellation) -> OperationResult<Option<BufferLease>> {
        unreachable!("TLS uses borrowed reads")
    }

    async fn read_into(
        &mut self,
        buffer: &mut [u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        poll_fn(|_| {
            if self.0.faults().read_error {
                return Poll::Ready(Err(failure(ErrorKind::ConnectionReset)));
            }
            let mut wire = self.0.inbound.lock().unwrap();
            if !wire.bytes.is_empty() {
                let count = buffer.len().min(wire.bytes.len());
                for (target, byte) in buffer.iter_mut().zip(wire.bytes.drain(..count)) {
                    *target = byte;
                }
                return Poll::Ready(Ok(count));
            }
            if wire.closed {
                return Poll::Ready(Ok(0));
            }
            if cancellation.is_cancelled() {
                return Poll::Ready(Err(Cancelled.into()));
            }
            Poll::Pending
        })
        .await
    }

    async fn read_vectored(
        &mut self,
        _: &mut [IoSliceMut<'_>],
        _: &Cancellation,
    ) -> OperationResult<usize> {
        unreachable!("TLS uses borrowed reads")
    }

    async fn read_vectored_with_flags(
        &mut self,
        _: &mut [IoSliceMut<'_>],
        _: SocketRecvFlags,
        _: &Cancellation,
    ) -> OperationResult<SocketRecvResult> {
        unreachable!("TLS uses borrowed reads")
    }

    async fn read_owned_vectored<B: IoBufSequenceMut>(
        &mut self,
        _: B,
        _: SocketRecvFlags,
        _: &Cancellation,
    ) -> (OperationResult<SocketRecvResult>, B) {
        unreachable!("TLS uses borrowed reads")
    }

    async fn close(&mut self) -> io::Result<()> {
        poll_fn(|_| {
            let mut faults = self.0.faults();
            if std::mem::take(&mut faults.reader_close_pending) {
                return Poll::Pending;
            }
            Poll::Ready(if faults.reader_close_error {
                Err(io::Error::other("reader retirement failed"))
            } else {
                Ok(())
            })
        })
        .await
    }
}

struct Writer<'a, B> {
    memory: &'a Memory,
    buffer: PhantomData<fn() -> B>,
}

impl<B: IoBuf> SocketStreamWriter for Writer<'_, B> {
    type Buffer = B;

    async fn write(
        &mut self,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        poll_fn(|_| {
            let mut faults = self.memory.faults();
            if faults.write_error {
                return Poll::Ready(Err(failure(ErrorKind::BrokenPipe)));
            }
            if faults.write_zero {
                return Poll::Ready(Ok(0));
            }
            if faults.write_blocked {
                if cancellation.is_cancelled() {
                    return Poll::Ready(Err(Cancelled.into()));
                }
                return Poll::Pending;
            }
            let cancel = faults.cancel_on_write.take();
            drop(faults);
            self.memory
                .outbound
                .lock()
                .unwrap()
                .bytes
                .extend(buffer.iter().copied());
            // Successful progress wins a cancellation requested meanwhile.
            if let Some(cancel) = cancel {
                cancel.cancel();
            }
            Poll::Ready(Ok(buffer.len()))
        })
        .await
    }

    async fn write_vectored(
        &mut self,
        _: &[IoSlice<'_>],
        _: &Cancellation,
    ) -> OperationResult<usize> {
        unreachable!("TLS uses borrowed writes")
    }

    async fn submit(&mut self, _: B, _: &Cancellation) -> Result<(), (OperationError, B)> {
        unreachable!("TLS uses borrowed writes")
    }

    async fn flush(&mut self, _: &Cancellation) -> OperationResult<()> {
        let mut faults = self.memory.faults();
        if faults.flush_error {
            return Err(failure(ErrorKind::TimedOut));
        }
        if let Some(cancel) = faults.cancel_on_flush.take() {
            cancel.cancel();
        }
        Ok(())
    }

    async fn write_vectored_with_flags(
        &mut self,
        _: &[IoSlice<'_>],
        _: SocketSendFlags,
        _: &Cancellation,
    ) -> OperationResult<usize> {
        unreachable!("TLS uses borrowed writes")
    }

    async fn write_owned_vectored<S: IoBufSequence>(
        &mut self,
        _: S,
        _: SocketSendFlags,
        _: &Cancellation,
    ) -> (OperationResult<usize>, S) {
        unreachable!("TLS uses borrowed writes")
    }

    async fn close(&mut self) -> io::Result<()> {
        if self.memory.faults().writer_close_error {
            Err(io::Error::other("writer retirement failed"))
        } else {
            Ok(())
        }
    }
}

impl SocketOperation for Memory {
    type Socket = ();
}

impl BufferPooling for Memory {
    type Pool = HeapBufferPool;

    fn buffer_pool(&self, options: BufferPoolOptions) -> io::Result<HeapBufferPool> {
        HeapBufferPool::with_options(options)
    }
}

impl SocketStreamReading for Memory {
    fn socket_stream_reader<'scheduler>(
        &'scheduler self,
        _: &(),
    ) -> io::Result<impl SocketStreamReader<Buffer = BufferLease> + 'scheduler + use<'scheduler>>
    {
        if self.faults().reader_unavailable {
            return Err(io::Error::other("reader unavailable"));
        }
        Ok(Reader(self))
    }

    fn socket_stream_reader_with_pool<'scheduler>(
        &'scheduler self,
        socket: &(),
        _: HeapBufferPool,
    ) -> io::Result<impl SocketStreamReader<Buffer = BufferLease> + 'scheduler + use<'scheduler>>
    {
        self.socket_stream_reader(socket)
    }
}

impl SocketStreamWriting for Memory {
    fn socket_stream_writer<'scheduler>(
        &'scheduler self,
        socket: &(),
    ) -> io::Result<impl SocketStreamWriter<Buffer = BufferLease> + 'scheduler + use<'scheduler>>
    {
        self.socket_stream_writer_with_buffer(socket)
    }

    fn socket_stream_writer_with_buffer<'scheduler, B: IoBuf>(
        &'scheduler self,
        _: &(),
    ) -> io::Result<impl SocketStreamWriter<Buffer = B> + 'scheduler + use<'scheduler, B>> {
        if self.faults().writer_unavailable {
            return Err(io::Error::other("writer unavailable"));
        }
        Ok(Writer {
            memory: self,
            buffer: PhantomData,
        })
    }
}

impl SocketClose for Memory {
    async fn socket_close(&self, _: ()) -> io::Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        if self.faults().socket_close_error {
            Err(io::Error::other("socket close failed"))
        } else {
            Ok(())
        }
    }

    async fn socket_close_submit(&self, socket: ()) -> io::Result<()> {
        self.socket_close(socket).await
    }
}

// Tickets which fill the handshake reassembly limit, so the client's
// deframer reaches capacity before the message completes.
#[derive(Debug)]
struct OversizedTickets;

impl ProducesTickets for OversizedTickets {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        60
    }
    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        Some(vec![0; 65_486])
    }
    fn decrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

static IDENTITY: LazyLock<Identity> = LazyLock::new(|| {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    Identity {
        certificate: identity.cert.der().clone(),
        key: PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()),
    }
});

fn client_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(IDENTITY.certificate.clone()).unwrap();
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn server_config() -> ServerConfig {
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![IDENTITY.certificate.clone()],
            IDENTITY.key.clone_key().into(),
        )
        .unwrap()
}

// The in-process TLS server, pumped between polls of the client under test.
struct Peer {
    tls: ServerConnection,
    received: Vec<u8>,
}

impl Peer {
    fn new() -> Self {
        Self::with_config(server_config())
    }

    fn with_config(config: ServerConfig) -> Self {
        Self {
            tls: ServerConnection::new(Arc::new(config)).unwrap(),
            received: Vec::new(),
        }
    }

    fn pump(&mut self, memory: &Memory) {
        let input = std::mem::take(&mut memory.outbound.lock().unwrap().bytes);
        let input = Vec::from(input);
        let mut input = input.as_slice();
        while !input.is_empty() {
            if self.tls.read_tls(&mut input).is_err() || self.tls.process_new_packets().is_err() {
                break;
            }
            let mut buffer = [0; 4096];
            while let Ok(count @ 1..) = self.tls.reader().read(&mut buffer) {
                self.received.extend_from_slice(&buffer[..count]);
            }
        }
        let mut output = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut output).unwrap();
        }
        memory.inbound.lock().unwrap().bytes.extend(output);
    }

    fn send(&mut self, memory: &Memory, data: &[u8]) {
        self.tls.writer().write_all(data).unwrap();
        self.pump(memory);
    }
}

fn step<F: Future + ?Sized>(
    memory: &Memory,
    peer: &mut Peer,
    future: Pin<&mut F>,
) -> Poll<F::Output> {
    peer.pump(memory);
    let poll = future.poll(&mut Context::from_waker(Waker::noop()));
    peer.pump(memory);
    poll
}

fn run<F: Future>(memory: &Memory, peer: &mut Peer, future: F) -> F::Output {
    let mut future = pin!(future);
    for _ in 0..POLL_LIMIT {
        if let Poll::Ready(output) = step(memory, peer, future.as_mut()) {
            return output;
        }
    }
    panic!("future did not complete within {POLL_LIMIT} polls");
}

// Poll repeatedly while the transport is stalled, requiring no completion.
fn stall<F: Future + ?Sized>(memory: &Memory, peer: &mut Peer, mut future: Pin<&mut F>) {
    for _ in 0..16 {
        assert!(step(memory, peer, future.as_mut()).is_pending());
    }
}

fn connect(memory: &Memory, peer: &mut Peer) -> RustlsConnection<()> {
    let connector = RustlsConnector::new(Arc::new(client_config()));
    let connection = run(
        memory,
        peer,
        connector.connect(memory, (), "localhost", &Cancellation::never()),
    )
    .unwrap();
    // Deliver the server's session tickets before the test continues.
    peer.pump(memory);
    connection
}

type Configure = fn(&mut Faults);

fn io_kind(error: &OperationError) -> ErrorKind {
    match error {
        OperationError::Io(error) => error.kind(),
        OperationError::Cancelled(_) => panic!("expected an I/O error, got cancellation"),
    }
}

fn is_cancelled<T>(result: &OperationResult<T>) -> bool {
    matches!(result, Err(OperationError::Cancelled(_)))
}

type Handles<'a> = Mutex<
    Option<(
        EncryptedSocketStreamReader<'a>,
        EncryptedSocketStreamWriter<'a>,
    )>,
>;

#[test]
fn invalid_provider_configurations_fail_before_handshake_and_close_the_socket() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let mut client = client_config();
    client.max_fragment_size = Some(1);
    let result = run(
        &memory,
        &mut peer,
        RustlsConnector::new(Arc::new(client)).connect(
            &memory,
            (),
            "localhost",
            &Cancellation::never(),
        ),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::InvalidData);
    let mut server = server_config();
    server.max_fragment_size = Some(1);
    let result = run(
        &memory,
        &mut peer,
        RustlsAcceptor::new(Arc::new(server)).accept(&memory, (), &Cancellation::never()),
    );
    let OperationError::Io(error) = result.unwrap_err() else {
        panic!("expected an I/O-wrapped TLS error")
    };
    assert_eq!(
        error.get_ref().unwrap().downcast_ref::<rustls::Error>(),
        Some(&rustls::Error::BadMaxFragmentSize)
    );
    assert_eq!(memory.closes(), 2);
    assert!(memory.outbound.lock().unwrap().bytes.is_empty());
}

#[test]
fn handshake_lane_and_transport_failures_abort_the_socket() {
    let configure: [fn(&mut Faults); 5] = [
        |faults| faults.reader_unavailable = true,
        |faults| faults.writer_unavailable = true,
        |faults| faults.write_error = true,
        |faults| faults.reader_close_error = true,
        |faults| faults.writer_close_error = true,
    ];
    for configure in configure {
        let memory = Memory::default();
        let mut peer = Peer::new();
        configure(&mut memory.faults());
        let connector = RustlsConnector::new(Arc::new(client_config()));
        let result = run(
            &memory,
            &mut peer,
            connector.connect(&memory, (), "localhost", &Cancellation::never()),
        );
        assert!(matches!(result, Err(OperationError::Io(_))));
        assert_eq!(memory.closes(), 1);
    }
}

#[test]
fn reads_report_lane_and_transport_failures_after_retiring_both_lanes() {
    let configure: [fn(&mut Faults); 3] = [
        |faults| faults.reader_unavailable = true,
        |faults| faults.writer_unavailable = true,
        |faults| faults.read_error = true,
    ];
    for configure in configure {
        let memory = Memory::default();
        let mut peer = Peer::new();
        let mut connection = connect(&memory, &mut peer);
        configure(&mut memory.faults());
        let result = run(
            &memory,
            &mut peer,
            connection.read(&memory, &mut [0; 4], &Cancellation::never()),
        );
        assert!(matches!(result, Err(OperationError::Io(_))));
    }

    // Reads drive pending output before waiting for input.
    let memory = Memory::default();
    let mut peer = Peer::new();
    let mut connection = connect(&memory, &mut peer);
    let never = Cancellation::never();
    assert_eq!(
        run(
            &memory,
            &mut peer,
            connection.write(&memory, b"data", &never)
        )
        .unwrap(),
        4
    );
    memory.faults().write_error = true;
    let result = run(
        &memory,
        &mut peer,
        connection.read(&memory, &mut [0; 4], &never),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::BrokenPipe);

    // Retirement errors are reported without consuming the received plaintext.
    for reader in [true, false] {
        let memory = Memory::default();
        let mut peer = Peer::new();
        let mut connection = connect(&memory, &mut peer);
        peer.send(&memory, b"data");
        if reader {
            memory.faults().reader_close_error = true;
        } else {
            memory.faults().writer_close_error = true;
        }
        let mut buffer = [0; 4];
        let result = run(
            &memory,
            &mut peer,
            connection.read(&memory, &mut buffer, &Cancellation::never()),
        );
        assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
        *memory.faults() = Faults::default();
        let count = run(
            &memory,
            &mut peer,
            connection.read(&memory, &mut buffer, &Cancellation::never()),
        )
        .unwrap();
        assert_eq!(&buffer[..count], b"data");
    }
}

#[test]
fn writes_and_flushes_report_transport_failures_and_cancellation_after_delivery() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let mut connection = connect(&memory, &mut peer);

    memory.faults().writer_unavailable = true;
    let result = run(
        &memory,
        &mut peer,
        connection.write(&memory, b"data", &Cancellation::never()),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
    memory.faults().writer_unavailable = false;

    // The prior output is delivered, but no plaintext is accepted afterwards.
    let cancellation = Cancellation::new();
    memory.faults().cancel_on_flush = Some(cancellation.clone());
    let result = run(
        &memory,
        &mut peer,
        connection.write(&memory, b"data", &cancellation),
    );
    assert!(is_cancelled(&result));

    let count = run(
        &memory,
        &mut peer,
        connection.write(&memory, b"data", &Cancellation::never()),
    )
    .unwrap();
    assert_eq!(count, 4);
    memory.faults().write_error = true;
    let result = run(
        &memory,
        &mut peer,
        connection.flush(&memory, &Cancellation::never()),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::BrokenPipe);
    memory.faults().write_error = false;
    memory.faults().writer_close_error = true;
    let result = run(
        &memory,
        &mut peer,
        connection.flush(&memory, &Cancellation::never()),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
    assert_eq!(peer.received, b"data");

    memory.faults().writer_close_error = false;
    memory.faults().socket_close_error = true;
    let result = run(
        &memory,
        &mut peer,
        connection.close(&memory, &Cancellation::never()),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
    assert_eq!(memory.closes(), 1);
}

#[test]
fn oversized_handshake_messages_fail_reads_when_the_deframer_is_full() {
    let memory = Memory::default();
    let mut server = server_config();
    server.ticketer = Arc::new(OversizedTickets);
    let mut peer = Peer::with_config(server);
    let mut connection = connect(&memory, &mut peer);
    let result = run(
        &memory,
        &mut peer,
        connection.read(&memory, &mut [0; 4], &Cancellation::never()),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::InvalidData);
}

#[test]
fn duplex_reports_unavailable_lanes_without_running_the_application() {
    for reader in [true, false] {
        let memory = Memory::default();
        let mut peer = Peer::new();
        let connection = connect(&memory, &mut peer);
        if reader {
            memory.faults().reader_unavailable = true;
        } else {
            memory.faults().writer_unavailable = true;
        }
        let ran = AtomicBool::new(false);
        let result = run(
            &memory,
            &mut peer,
            connection.with_duplex(&memory, &Cancellation::never(), |_, _| {
                ran.store(true, Ordering::SeqCst);
                std::future::ready(Ok::<_, OperationError>(()))
            }),
        );
        assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
        assert!(!ran.load(Ordering::SeqCst));
        assert_eq!(memory.closes(), 1);
    }
}

#[test]
fn duplex_continues_plaintext_buffered_by_sequential_reads() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let mut connection = connect(&memory, &mut peer);
    peer.send(&memory, b"hello");
    let mut first = [0];
    run(
        &memory,
        &mut peer,
        connection.read(&memory, &mut first, &Cancellation::never()),
    )
    .unwrap();
    assert_eq!(&first, b"h");
    let received = run(
        &memory,
        &mut peer,
        connection.with_duplex(
            &memory,
            &Cancellation::never(),
            |mut reader, _writer| async move {
                let mut buffer = [0; 4];
                let count = reader
                    .read_into(&mut buffer, &Cancellation::never())
                    .await?;
                Ok::<_, OperationError>(buffer[..count].to_vec())
            },
        ),
    )
    .unwrap();
    assert_eq!(received, b"ello");
}

#[test]
fn duplex_input_wakes_output_while_ciphertext_awaits_the_transport() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    memory.faults().write_blocked = true;
    let handles: Handles<'_> = Mutex::new(None);
    let slot = &handles;
    let done = Cancellation::new();
    let finished = &done;
    let lifetime = Cancellation::never();
    let mut supervised =
        pin!(
            connection.with_duplex(&memory, &lifetime, move |reader, writer| async move {
                *slot.lock().unwrap() = Some((reader, writer));
                finished.cancelled().await;
                Ok::<_, OperationError>(())
            },)
        );
    assert!(step(&memory, &mut peer, supervised.as_mut()).is_pending());
    let (mut reader, mut writer) = handles.lock().unwrap().take().unwrap();

    // Leave ciphertext in rustls beyond what the stalled transmitter holds.
    let data = vec![b'x'; 64 * 1024];
    let mut accepted = 0;
    let never = Cancellation::never();
    loop {
        let mut write = pin!(writer.write(&data, &never));
        match step(&memory, &mut peer, write.as_mut()) {
            Poll::Ready(count) => accepted += count.unwrap(),
            Poll::Pending => break,
        }
        assert!(accepted < 1024 * 1024, "rustls output must be bounded");
    }

    // Input processed while output is pending still yields its plaintext.
    peer.send(&memory, b"ping");
    let mut buffer = [0; 4];
    let count = run(&memory, &mut peer, reader.read_into(&mut buffer, &never)).unwrap();
    assert_eq!(&buffer[..count], b"ping");

    memory.faults().write_blocked = false;
    run(&memory, &mut peer, writer.flush(&never)).unwrap();
    assert_eq!(peer.received.len(), accepted);
    assert!(peer.received.iter().all(|&byte| byte == b'x'));
    done.cancel();
    run(&memory, &mut peer, supervised).unwrap();
}

#[test]
fn duplex_directions_handle_empty_cancelled_closed_and_finished_operations() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    let handles: Handles<'_> = Mutex::new(None);
    let slot = &handles;
    let result = run(
        &memory,
        &mut peer,
        connection.with_duplex(
            &memory,
            &Cancellation::never(),
            |mut reader, mut writer| async move {
                let never = Cancellation::never();
                assert_eq!(reader.read_into(&mut [], &never).await?, 0);
                assert_eq!(writer.write(&[], &never).await?, 0);
                let cancelled = Cancellation::new();
                cancelled.cancel();
                assert!(is_cancelled(&reader.read_into(&mut [0], &cancelled).await));
                assert!(is_cancelled(&writer.write(b"data", &cancelled).await));
                assert!(is_cancelled(&writer.flush(&cancelled).await));
                *slot.lock().unwrap() = Some((reader, writer));
                Ok::<_, OperationError>(())
            },
        ),
    );
    result.unwrap();
    let (mut reader, mut writer) = handles.lock().unwrap().take().unwrap();
    let never = Cancellation::never();
    // The supervisor has joined both lanes; escaped directions report closure.
    let error = run(&memory, &mut peer, reader.read_into(&mut [0], &never)).unwrap_err();
    assert_eq!(io_kind(&error), ErrorKind::BrokenPipe);
    let error = run(&memory, &mut peer, writer.write(b"data", &never)).unwrap_err();
    assert_eq!(io_kind(&error), ErrorKind::BrokenPipe);
    run(&memory, &mut peer, ReadableStream::close(&mut reader)).unwrap();
    run(&memory, &mut peer, WritableStream::close(&mut writer)).unwrap();
    assert_eq!(
        run(&memory, &mut peer, reader.read_into(&mut [0], &never)).unwrap(),
        0
    );
    let error = run(&memory, &mut peer, writer.write(b"data", &never)).unwrap_err();
    assert_eq!(io_kind(&error), ErrorKind::BrokenPipe);
    let error = run(&memory, &mut peer, writer.flush(&never)).unwrap_err();
    assert_eq!(io_kind(&error), ErrorKind::BrokenPipe);
}

#[test]
fn duplex_unflushed_output_reports_closure_after_supervision_finishes() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    memory.faults().write_blocked = true;
    let handles: Handles<'_> = Mutex::new(None);
    let slot = &handles;
    let result = run(
        &memory,
        &mut peer,
        connection.with_duplex(
            &memory,
            &Cancellation::never(),
            |reader, mut writer| async move {
                assert_eq!(writer.write(b"data", &Cancellation::never()).await?, 4);
                *slot.lock().unwrap() = Some((reader, writer));
                Err::<(), _>(OperationError::from(io::Error::other("application failed")))
            },
        ),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
    let (_reader, mut writer) = handles.lock().unwrap().take().unwrap();
    let error = run(&memory, &mut peer, writer.flush(&Cancellation::never())).unwrap_err();
    assert_eq!(io_kind(&error), ErrorKind::BrokenPipe);
}

#[test]
fn duplex_peer_protocol_errors_fail_both_directions() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    // An application-data record which cannot authenticate.
    memory
        .inbound
        .lock()
        .unwrap()
        .bytes
        .extend([0x17, 0x03, 0x03, 0x00, 0x20].into_iter().chain([0; 0x20]));
    let result = run(
        &memory,
        &mut peer,
        connection.with_duplex(
            &memory,
            &Cancellation::never(),
            |mut reader, mut writer| async move {
                let never = Cancellation::never();
                let error = reader.read_into(&mut [0], &never).await.unwrap_err();
                assert_eq!(io_kind(&error), ErrorKind::InvalidData);
                let error = reader.read_into(&mut [0], &never).await.unwrap_err();
                assert_eq!(io_kind(&error), ErrorKind::InvalidData);
                let error = writer.write(b"data", &never).await.unwrap_err();
                assert_eq!(io_kind(&error), ErrorKind::InvalidData);
                let error = writer.flush(&never).await.unwrap_err();
                assert_eq!(io_kind(&error), ErrorKind::InvalidData);
                Err::<(), _>(error)
            },
        ),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::InvalidData);
}

#[test]
fn duplex_writes_report_a_connection_already_failed_by_sequential_reads() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let mut connection = connect(&memory, &mut peer);
    memory
        .inbound
        .lock()
        .unwrap()
        .bytes
        .extend([0x17, 0x03, 0x03, 0x00, 0x20].into_iter().chain([0; 0x20]));
    let error = run(
        &memory,
        &mut peer,
        connection.read(&memory, &mut [0], &Cancellation::never()),
    )
    .unwrap_err();
    assert_eq!(io_kind(&error), ErrorKind::InvalidData);
    let result = run(
        &memory,
        &mut peer,
        connection.with_duplex(
            &memory,
            &Cancellation::never(),
            |_reader, mut writer| async move {
                writer.write(b"data", &Cancellation::never()).await
            },
        ),
    );
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::InvalidData);
}

#[test]
fn duplex_transmit_failures_are_reported_to_later_output() {
    let configure: [fn(&mut Faults); 3] = [
        |faults| faults.write_error = true,
        |faults| faults.write_zero = true,
        |faults| faults.flush_error = true,
    ];
    for (configure, kind) in configure.into_iter().zip([
        ErrorKind::BrokenPipe,
        ErrorKind::WriteZero,
        ErrorKind::TimedOut,
    ]) {
        let memory = Memory::default();
        let mut peer = Peer::new();
        let connection = connect(&memory, &mut peer);
        configure(&mut memory.faults());
        let result = run(
            &memory,
            &mut peer,
            connection.with_duplex(
                &memory,
                &Cancellation::never(),
                |_reader, mut writer| async move {
                    let never = Cancellation::never();
                    // Accepted plaintext is reported even if transmission fails.
                    assert_eq!(writer.write(b"data", &never).await?, 4);
                    let error = writer.flush(&never).await.unwrap_err();
                    assert_eq!(io_kind(&error), kind);
                    let error = writer.write(b"data", &never).await.unwrap_err();
                    assert_eq!(io_kind(&error), kind);
                    Err::<(), _>(error)
                },
            ),
        );
        assert_eq!(io_kind(&result.unwrap_err()), kind);
    }
}

#[test]
fn duplex_waiting_output_observes_cancellation_and_lane_retirement_errors() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    memory.faults().write_blocked = true;
    let handles: Handles<'_> = Mutex::new(None);
    let slot = &handles;
    let done = Cancellation::new();
    let finished = &done;
    let lifetime = Cancellation::never();
    let mut supervised =
        pin!(
            connection.with_duplex(&memory, &lifetime, move |reader, writer| async move {
                *slot.lock().unwrap() = Some((reader, writer));
                finished.cancelled().await;
                Ok::<_, OperationError>(())
            },)
        );
    assert!(step(&memory, &mut peer, supervised.as_mut()).is_pending());
    let (_reader, mut writer) = handles.lock().unwrap().take().unwrap();

    // Fill rustls output while the transport is stalled.
    let data = vec![b'x'; 64 * 1024];
    let mut accepted = 0;
    let never = Cancellation::never();
    loop {
        let mut write = pin!(writer.write(&data, &never));
        match step(&memory, &mut peer, write.as_mut()) {
            Poll::Ready(count) => accepted += count.unwrap(),
            Poll::Pending => break,
        }
        assert!(accepted < 1024 * 1024, "rustls output must be bounded");
    }

    let cancellation = Cancellation::new();
    {
        let mut flush = pin!(writer.flush(&cancellation));
        stall(&memory, &mut peer, flush.as_mut());
        cancellation.cancel();
        let Poll::Ready(result) = step(&memory, &mut peer, flush.as_mut()) else {
            panic!("cancellation must complete the waiting flush")
        };
        assert!(is_cancelled(&result));
    }

    // A blocked write observes the transmit lane's retirement error.
    {
        let mut write = pin!(writer.write(&data, &never));
        stall(&memory, &mut peer, write.as_mut());
        {
            let mut faults = memory.faults();
            faults.write_blocked = false;
            faults.write_error = true;
            faults.writer_close_error = true;
        }
        let Poll::Ready(result) = step(&memory, &mut peer, write.as_mut()) else {
            panic!("transport failure must complete the waiting write")
        };
        assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
    }
    done.cancel();
    // The application succeeded; the transmit lane's retirement error remains.
    let result = run(&memory, &mut peer, supervised);
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
}

#[test]
fn duplex_waiting_flush_observes_the_transmit_lane_retirement_error() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    memory.faults().write_blocked = true;
    let handles: Handles<'_> = Mutex::new(None);
    let slot = &handles;
    let done = Cancellation::new();
    let finished = &done;
    let lifetime = Cancellation::never();
    let mut supervised =
        pin!(
            connection.with_duplex(&memory, &lifetime, move |reader, writer| async move {
                *slot.lock().unwrap() = Some((reader, writer));
                finished.cancelled().await;
                Ok::<_, OperationError>(())
            },)
        );
    assert!(step(&memory, &mut peer, supervised.as_mut()).is_pending());
    let (_reader, mut writer) = handles.lock().unwrap().take().unwrap();
    let never = Cancellation::never();
    assert_eq!(
        run(&memory, &mut peer, writer.write(b"data", &never)).unwrap(),
        4
    );
    {
        let mut flush = pin!(writer.flush(&never));
        stall(&memory, &mut peer, flush.as_mut());
        {
            let mut faults = memory.faults();
            faults.write_blocked = false;
            faults.write_error = true;
            faults.writer_close_error = true;
        }
        let Poll::Ready(result) = step(&memory, &mut peer, flush.as_mut()) else {
            panic!("transport failure must complete the waiting flush")
        };
        assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
    }
    done.cancel();
    // The application succeeded; the transmit lane's retirement error remains.
    let result = run(&memory, &mut peer, supervised);
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
}

#[test]
fn duplex_waiting_input_observes_the_receive_lane_retirement_error() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    {
        let mut faults = memory.faults();
        faults.reader_close_pending = true;
        faults.reader_close_error = true;
    }
    let handles: Handles<'_> = Mutex::new(None);
    let slot = &handles;
    let lifetime = Cancellation::never();
    let mut supervised =
        pin!(
            connection.with_duplex(&memory, &lifetime, move |reader, writer| async move {
                *slot.lock().unwrap() = Some((reader, writer));
                Err::<(), _>(OperationError::from(io::Error::other("application failed")))
            },)
        );
    // Teardown cancels the receive lane, whose retirement is still pending.
    assert!(step(&memory, &mut peer, supervised.as_mut()).is_pending());
    let (mut reader, _writer) = handles.lock().unwrap().take().unwrap();
    let error = run(
        &memory,
        &mut peer,
        reader.read_into(&mut [0], &Cancellation::never()),
    )
    .unwrap_err();
    assert_eq!(io_kind(&error), ErrorKind::Other);
    let result = run(&memory, &mut peer, supervised);
    assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::Other);
}

#[test]
fn duplex_completion_reports_close_notify_lane_retirement_and_socket_close_failures() {
    let configure: [(Configure, ErrorKind); 4] = [
        (|faults| faults.write_error = true, ErrorKind::BrokenPipe),
        (|faults| faults.reader_close_error = true, ErrorKind::Other),
        (|faults| faults.writer_close_error = true, ErrorKind::Other),
        (|faults| faults.socket_close_error = true, ErrorKind::Other),
    ];
    for (configure, kind) in configure {
        let memory = Memory::default();
        let mut peer = Peer::new();
        let connection = connect(&memory, &mut peer);
        configure(&mut memory.faults());
        let result = run(
            &memory,
            &mut peer,
            connection.with_duplex(&memory, &Cancellation::never(), |_, _| async {
                Ok::<_, OperationError>(())
            }),
        );
        assert_eq!(io_kind(&result.unwrap_err()), kind);
        assert_eq!(memory.closes(), 1);
    }
}

#[test]
fn duplex_lifetime_cancellation_after_transmit_progress_fails_the_connection() {
    let memory = Memory::default();
    let mut peer = Peer::new();
    let connection = connect(&memory, &mut peer);
    let lifetime = Cancellation::new();
    memory.faults().cancel_on_write = Some(lifetime.clone());
    let result = run(
        &memory,
        &mut peer,
        connection.with_duplex(&memory, &lifetime, |_reader, mut writer| async move {
            let never = Cancellation::never();
            assert_eq!(writer.write(b"data", &never).await?, 4);
            writer.flush(&never).await
        }),
    );
    assert!(is_cancelled(&result));
    assert_eq!(peer.received, b"data");
}

#[test]
fn duplex_input_fails_when_oversized_handshake_messages_fill_the_deframer() {
    // Deliver every record, or stop exactly when the deframer reaches capacity.
    for eof_at_capacity in [false, true] {
        let memory = Memory::default();
        let mut server = server_config();
        server.ticketer = Arc::new(OversizedTickets);
        let mut peer = Peer::with_config(server);
        let connection = connect(&memory, &mut peer);
        if eof_at_capacity {
            let mut wire = memory.inbound.lock().unwrap();
            wire.bytes.truncate(0xffff);
            wire.closed = true;
        }
        let result = run(
            &memory,
            &mut peer,
            connection.with_duplex(
                &memory,
                &Cancellation::never(),
                |mut reader, _writer| async move {
                    reader.read_into(&mut [0], &Cancellation::never()).await
                },
            ),
        );
        assert_eq!(io_kind(&result.unwrap_err()), ErrorKind::InvalidData);
    }
}
