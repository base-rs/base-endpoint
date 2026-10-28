// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::RustlsConnection;
use crate::stream::{ReadableStream, WritableStream};
use base_scheduler::{
    Cancellation, OperationError, OperationResult, SocketClose, SocketStreamReader,
    SocketStreamReading, SocketStreamWriter, SocketStreamWriting,
};
use event_listener::Event;
use futures_util::{future::join, task::AtomicWaker};
use std::{
    future::{Future, poll_fn},
    io::{self, BufRead, Read, Write},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Wake, Waker},
};

const CAPACITY: usize = 16 * 1024;

#[cfg(test)]
mod tests;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone)]
enum Failure {
    Cancelled,
    Io(Arc<io::Error>),
}
impl Failure {
    fn from_error(error: OperationError) -> Self {
        match error {
            OperationError::Cancelled(_) => Self::Cancelled,
            OperationError::Io(error) => Self::Io(Arc::new(error)),
        }
    }
    fn error(&self) -> OperationError {
        match self {
            Self::Cancelled => base_scheduler::Cancelled.into(),
            Self::Io(error) => io::Error::new(error.kind(), error.clone()).into(),
        }
    }
}

struct State {
    tls: ::rustls::Connection,
    plaintext: usize,
    issued: u64,
    delivered: u64,
    failure: Option<Failure>,
    finished: bool,
    output_closed: bool,
}
struct Shared {
    state: Mutex<State>,
    writable: Event,
    transmit: AtomicWaker,
}

// One retained transport future, with a stable socket waker. Application I/O
// can make immediate progress without handing off to the supervisor. A blocked
// socket wakes both possible pollers; neither can replace the other's waker.
struct ProgressWake {
    foreground: AtomicWaker,
    background: AtomicWaker,
}
impl Wake for ProgressWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.foreground.wake();
        self.background.wake();
    }
}
struct ProgressState<'scope> {
    work: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'scope>>>,
    result: Option<Result<(), Arc<io::Error>>>,
}
struct IoProgress<'scope> {
    progress: Mutex<ProgressState<'scope>>,
    wake: Arc<ProgressWake>,
    waker: Waker,
}
impl<'scope> IoProgress<'scope> {
    fn new(work: impl Future<Output = io::Result<()>> + Send + 'scope) -> Self {
        let wake = Arc::new(ProgressWake {
            foreground: AtomicWaker::new(),
            background: AtomicWaker::new(),
        });
        Self {
            progress: Mutex::new(ProgressState {
                work: Some(Box::pin(work)),
                result: None,
            }),
            waker: Waker::from(wake.clone()),
            wake,
        }
    }
    fn poll(&self, cx: &mut Context<'_>, foreground: bool) -> Poll<io::Result<()>> {
        let mut progress = lock(&self.progress);
        if let Some(work) = &mut progress.work {
            if foreground {
                self.wake.foreground.register(cx.waker());
            } else {
                self.wake.background.register(cx.waker());
            }
            let mut cx = Context::from_waker(&self.waker);
            if let Poll::Ready(result) = work.as_mut().poll(&mut cx) {
                progress.work = None;
                progress.result = Some(result.map_err(Arc::new));
                self.wake.wake_by_ref();
            }
        }
        match &progress.result {
            Some(Ok(())) => Poll::Ready(Ok(())),
            Some(Err(error)) => Poll::Ready(Err(io::Error::new(error.kind(), error.clone()))),
            None => Poll::Pending,
        }
    }
}
impl Shared {
    fn notify_all(&self) {
        self.writable.notify(usize::MAX);
        self.transmit.wake();
    }
    fn fail(&self, error: OperationError) {
        lock(&self.state)
            .failure
            .get_or_insert_with(|| Failure::from_error(error));
        self.notify_all();
    }
    async fn delivered(
        &self,
        transmitter: &IoProgress<'_>,
        ticket: u64,
        cancellation: &Cancellation,
    ) -> OperationResult<()> {
        loop {
            event_listener::listener!(self.writable => listener);
            cancellation.check()?;
            {
                let state = lock(&self.state);
                if let Some(error) = &state.failure {
                    return Err(error.error());
                }
                if state.delivered >= ticket {
                    return Ok(());
                }
                if state.finished {
                    return Err(closed());
                }
            }
            let mut waiting = std::pin::pin!(wait(listener, cancellation));
            poll_fn(|cx| {
                if let Poll::Ready(Err(error)) = transmitter.poll(cx, true) {
                    return Poll::Ready(Err(error.into()));
                }
                waiting.as_mut().poll(cx)
            })
            .await?;
        }
    }
}

fn closed() -> OperationError {
    io::Error::new(io::ErrorKind::BrokenPipe, "TLS direction is closed").into()
}

async fn wait(
    listener: impl Future<Output = ()> + Send,
    cancellation: &Cancellation,
) -> OperationResult<()> {
    let mut listener = std::pin::pin!(listener);
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    std::future::poll_fn(|cx| {
        if cancelled.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err(base_scheduler::Cancelled.into()));
        }
        listener.as_mut().poll(cx).map(Ok)
    })
    .await
}

/// Plaintext input which drives its retained TLS receive future. No lock spans
/// an asynchronous wait; paused input does not prevent application output.
pub struct EncryptedSocketStreamReader<'scope> {
    shared: Arc<Shared>,
    receiver: Arc<IoProgress<'scope>>,
    closed: bool,
}
impl Shared {
    fn read(&self, buffer: &mut [u8]) -> Option<OperationResult<usize>> {
        let mut state = lock(&self.state);
        if state.finished {
            return Some(Err(closed()));
        }
        if buffer.is_empty() {
            return Some(Ok(0));
        }
        match state.tls.reader().read(buffer) {
            Ok(count) => {
                state.plaintext = state.plaintext.saturating_sub(count);
                Some(Ok(count))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                state.failure.as_ref().map(|failure| Err(failure.error()))
            }
            Err(error) => Some(Err(error.into())),
        }
    }
}
impl ReadableStream for EncryptedSocketStreamReader<'_> {
    async fn read_into(
        &mut self,
        buffer: &mut [u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        poll_fn(|cx| {
            cancellation.check()?;
            if self.closed {
                return Poll::Ready(Ok(0));
            }
            if let Some(result) = self.shared.read(buffer) {
                return Poll::Ready(result);
            }
            let progress = self.receiver.poll(cx, true);
            if let Some(result) = self.shared.read(buffer) {
                return Poll::Ready(result);
            }
            if let Poll::Ready(Err(error)) = progress {
                return Poll::Ready(Err(error.into()));
            }
            if cancelled.as_mut().poll(cx).is_ready() {
                Poll::Ready(Err(base_scheduler::Cancelled.into()))
            } else {
                Poll::Pending
            }
        })
        .await
    }
    async fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

/// Ordered plaintext output. Writes accept a bounded prefix into TLS; flush
/// waits for its ciphertext to reach the socket. No transport lock spans await.
pub struct EncryptedSocketStreamWriter<'scope> {
    shared: Arc<Shared>,
    transmitter: Arc<IoProgress<'scope>>,
    closed: bool,
}
impl WritableStream for EncryptedSocketStreamWriter<'_> {
    async fn write(
        &mut self,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        loop {
            event_listener::listener!(self.shared.writable => listener);
            cancellation.check()?;
            if self.closed {
                return Err(closed());
            }
            let result = {
                let mut state = lock(&self.shared.state);
                if let Some(error) = &state.failure {
                    return Err(error.error());
                }
                if state.finished || state.output_closed {
                    return Err(closed());
                }
                match state.tls.writer().write(buffer) {
                    Ok(0) if !buffer.is_empty() => None,
                    Ok(count) => {
                        if count != 0 {
                            state.issued += 1;
                        }
                        Some(Ok(count))
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                    Err(error) => Some(Err(error.into())),
                }
            };
            if let Some(result) = result {
                poll_fn(|cx| {
                    let _ = self.transmitter.poll(cx, true);
                    Poll::Ready(())
                })
                .await;
                return result;
            }
            let mut waiting = std::pin::pin!(wait(listener, cancellation));
            poll_fn(|cx| {
                if let Poll::Ready(Err(error)) = self.transmitter.poll(cx, true) {
                    return Poll::Ready(Err(error.into()));
                }
                waiting.as_mut().poll(cx)
            })
            .await?;
        }
    }
    async fn flush(&mut self, cancellation: &Cancellation) -> OperationResult<()> {
        if self.closed {
            return Err(closed());
        }
        cancellation.check()?;
        let ticket = {
            let state = lock(&self.shared.state);
            if let Some(error) = &state.failure {
                return Err(error.error());
            }
            if state.delivered >= state.issued {
                return Ok(());
            }
            state.issued
        };
        self.shared
            .delivered(&self.transmitter, ticket, cancellation)
            .await
    }
    async fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

impl<C: Send + 'static> RustlsConnection<C> {
    /// Run an application with independent plaintext directions. Reads and
    /// writes drive retained I/O futures directly; this future supervises
    /// control output and joins persistent scheduler lanes. No task is spawned.
    ///
    /// On successful application completion, send close_notify. On failure or
    /// cancellation, abort pending I/O. Every path joins lane retirement and
    /// consumes the socket before returning; dropping this future is not a join.
    pub async fn with_duplex<'scope, S, F, Fut, T, E>(
        self,
        scheduler: &'scope S,
        cancellation: &Cancellation,
        application: F,
    ) -> Result<T, E>
    where
        S: SocketStreamReading<Socket = C> + SocketStreamWriting + SocketClose + ?Sized,
        F: FnOnce(EncryptedSocketStreamReader<'scope>, EncryptedSocketStreamWriter<'scope>) -> Fut
            + Send,
        Fut: Future<Output = Result<T, E>> + Send,
        T: Send,
        E: From<OperationError> + From<io::Error> + Send,
    {
        let Self {
            socket,
            mut state,
            incoming,
            incoming_start,
            incoming_end,
            outgoing,
            outgoing_start,
            ..
        } = self;
        let result = async {
            let mut reader = scheduler.socket_stream_reader(&socket)?;
            let mut writer = match scheduler.socket_stream_writer(&socket) {
                Ok(writer) => writer,
                Err(error) => {
                    let _ = SocketStreamReader::close(&mut reader).await;
                    return Err(E::from(error));
                }
            };
            state.set_buffer_limit(Some(CAPACITY));
            let plaintext = state
                .reader()
                .fill_buf()
                .map(|bytes| bytes.len())
                .unwrap_or(0);
            let shared = Arc::new(Shared {
                state: Mutex::new(State {
                    tls: state,
                    plaintext,
                    issued: 0,
                    delivered: 0,
                    failure: None,
                    finished: false,
                    output_closed: false,
                }),
                writable: Event::new(),
                transmit: AtomicWaker::new(),
            });
            let stop = cancellation.child();
            let transmit_shared = shared.clone();
            let transmit_stop = stop.clone();
            let transmit_lifetime = cancellation.clone();
            let transmitter = Arc::new(IoProgress::new(async move {
                let result = transmit(
                    &transmit_shared,
                    &mut writer,
                    outgoing,
                    outgoing_start,
                    &transmit_stop,
                )
                .await;
                if let Err(error) = result {
                    if !transmit_stop.is_cancelled() || transmit_lifetime.is_cancelled() {
                        transmit_shared.fail(error);
                        transmit_stop.cancel();
                    }
                }
                SocketStreamWriter::close(&mut writer).await
            }));
            let receive_shared = shared.clone();
            let receive_stop = stop.clone();
            let receive_lifetime = cancellation.clone();
            let receiver = Arc::new(IoProgress::new(async move {
                let result = receive(
                    &receive_shared,
                    &mut reader,
                    &incoming[incoming_start..incoming_end],
                    &receive_stop,
                )
                .await;
                if let Err(error) = result {
                    if !receive_stop.is_cancelled() || receive_lifetime.is_cancelled() {
                        receive_shared.fail(error);
                        receive_stop.cancel();
                    }
                }
                SocketStreamReader::close(&mut reader).await
            }));
            let input = EncryptedSocketStreamReader {
                shared: shared.clone(),
                receiver: receiver.clone(),
                closed: false,
            };
            let output = EncryptedSocketStreamWriter {
                shared: shared.clone(),
                transmitter: transmitter.clone(),
                closed: false,
            };
            let operation = async {
                let mut result = application(input, output).await;
                lock(&shared.state).output_closed = true;
                if result.is_ok() && !stop.is_cancelled() {
                    let ticket = {
                        let mut state = lock(&shared.state);
                        state.tls.send_close_notify();
                        state.issued += 1;
                        state.issued
                    };
                    if let Err(error) = shared.delivered(&transmitter, ticket, &stop).await {
                        result = Err(E::from(error));
                    }
                }
                stop.cancel();
                result
            };
            let receive = async {
                // Application reads own ordinary receive progress. Teardown
                // drives cancellation and joins the persistent socket lane.
                stop.cancelled().await;
                poll_fn(|cx| receiver.poll(cx, false)).await
            };
            let transmit = poll_fn(|cx| transmitter.poll(cx, false));
            let (result, (read_closed, write_closed)) =
                join(operation, join(receive, transmit)).await;
            lock(&shared.state).finished = true;
            shared.notify_all();
            result.and_then(|value| {
                read_closed?;
                write_closed?;
                Ok(value)
            })
        }
        .await;
        let closed = scheduler.socket_close(socket).await;
        result.and_then(|value| {
            closed?;
            Ok(value)
        })
    }
}

async fn receive<R: SocketStreamReader>(
    shared: &Shared,
    reader: &mut R,
    initial: &[u8],
    cancellation: &Cancellation,
) -> OperationResult<()> {
    let mut buffer = vec![0; CAPACITY.max(initial.len())];
    buffer[..initial.len()].copy_from_slice(initial);
    let (mut position, mut end) = (0, initial.len());
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    loop {
        // Once plaintext is available, return it to the consumer before
        // reading the socket again. The reader polls us again after consuming
        // that plaintext; teardown polls us after cancellation.
        poll_fn(|cx| {
            cancellation.check()?;
            if lock(&shared.state).plaintext == 0 {
                return Poll::Ready(Ok(()));
            }
            if cancelled.as_mut().poll(cx).is_ready() {
                Poll::Ready(Err(OperationError::from(base_scheduler::Cancelled)))
            } else {
                Poll::Pending
            }
        })
        .await?;
        if position == end {
            let count = reader.read_into(&mut buffer, cancellation).await?;
            if count == 0 {
                let mut state = lock(&shared.state);
                state.tls.read_tls(&mut io::empty())?;
                drop(state);
                return Ok(());
            }
            position = 0;
            end = count;
        }
        let peer_closed = {
            let mut state = lock(&shared.state);
            let count = state.tls.read_tls(&mut &buffer[position..end])?;
            position += count;
            let progress = state
                .tls
                .process_new_packets()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            state.plaintext = progress.plaintext_bytes_to_read();
            if state.tls.wants_write() {
                shared.transmit.wake();
            }
            progress.peer_has_closed()
        };
        if peer_closed {
            return Ok(());
        }
    }
}

async fn transmit<W: SocketStreamWriter>(
    shared: &Shared,
    writer: &mut W,
    mut buffer: Vec<u8>,
    mut position: usize,
    cancellation: &Cancellation,
) -> OperationResult<()> {
    let mut end = buffer.len();
    let mut dirty = position != end;
    // Keep initialized storage between records. The valid ciphertext range is
    // tracked separately so small writes do not zero the full capacity again.
    buffer.resize(buffer.len().max(CAPACITY), 0);
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    loop {
        cancellation.check()?;
        if position != end {
            let count = writer.write(&buffer[position..end], cancellation).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS output made no progress",
                )
                .into());
            }
            position += count;
            dirty = true;
            continue;
        }
        end = 0;
        position = 0;
        let ticket = {
            let mut state = lock(&shared.state);
            if state.tls.wants_write() {
                end = state
                    .tls
                    .write_tls(&mut io::Cursor::new(buffer.as_mut_slice()))?;
            }
            if end == 0 && (dirty || state.delivered < state.issued) {
                Some(state.issued)
            } else {
                None
            }
        };
        if end != 0 {
            shared.writable.notify(usize::MAX);
            continue;
        }
        if let Some(ticket) = ticket {
            writer.flush(cancellation).await?;
            lock(&shared.state).delivered = ticket;
            dirty = false;
            shared.writable.notify(usize::MAX);
        } else {
            // Foreground output can poll this future while it is idle. Recheck
            // demand before waiting, so ordinary writes need no notification.
            poll_fn(|cx| {
                shared.transmit.register(cx.waker());
                cancellation.check()?;
                let state = lock(&shared.state);
                if state.tls.wants_write() || state.delivered < state.issued {
                    return Poll::Ready(Ok(()));
                }
                drop(state);
                if cancelled.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(OperationError::from(base_scheduler::Cancelled)))
                } else {
                    Poll::Pending
                }
            })
            .await?;
        }
    }
}
