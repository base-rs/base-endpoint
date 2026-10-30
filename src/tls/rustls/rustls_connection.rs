// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::tls_error;
use crate::tls::{TlsSession, TlsStream};
use ::rustls::{Connection, pki_types::CertificateDer};
use base_scheduler::{
    Cancellation, OperationError, OperationResult, SocketClose, SocketStreamReader,
    SocketStreamReading, SocketStreamWriter, SocketStreamWriting,
};
use std::io::{self, BufRead, Read, Write};

const BUFFER_SIZE: usize = 16 * 1024;

mod duplex;
pub use duplex::{EncryptedSocketStreamReader, EncryptedSocketStreamWriter};

/// An established rustls connection owning its scheduler socket and TLS buffers. Sequential operations take the compatible scheduler explicitly; `with_duplex` additionally supervises concurrent plaintext directions. Await operations after cooperative cancellation before closing; dropping an operation provides no asynchronous retirement guarantee.
///
/// `write` reports the plaintext bytes accepted into TLS buffering. Follow it with `flush` to send the final buffered data. Cancellation while flushing preserves the exact unsent ciphertext for a later flush; never replay already accepted plaintext. A TLS protocol error is fatal, and a transport error may also make continued use impossible.
#[derive(Debug)]
pub struct RustlsConnection<C> {
    socket: C,
    state: Connection,
    incoming: Vec<u8>,
    incoming_start: usize,
    incoming_end: usize,
    outgoing: Vec<u8>,
    outgoing_start: usize,
    write_closed: bool,
}

impl<C> RustlsConnection<C> {
    pub(super) fn new(socket: C, mut state: Connection) -> Self {
        state.set_buffer_limit(Some(BUFFER_SIZE));
        Self {
            socket,
            state,
            incoming: vec![0; BUFFER_SIZE],
            incoming_start: 0,
            incoming_end: 0,
            outgoing: Vec::with_capacity(BUFFER_SIZE),
            outgoing_start: 0,
            write_closed: false,
        }
    }

    /// Borrow the underlying socket to inspect its addresses. Application data must pass through the TLS connection.
    pub fn socket(&self) -> &C {
        &self.socket
    }

    /// The authenticated peer's certificate chain, if supplied. Server connections only have a peer chain when client authentication completed.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.state.peer_certificates()
    }

    pub(super) async fn handshake<S>(
        &mut self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<()>
    where
        S: SocketStreamReading<Socket = C> + SocketStreamWriting + ?Sized,
        C: 'static,
    {
        let mut reader = scheduler.socket_stream_reader(&self.socket)?;
        let mut writer = match scheduler.socket_stream_writer(&self.socket) {
            Ok(writer) => writer,
            Err(error) => {
                let _ = reader.close().await;
                return Err(error.into());
            }
        };
        let result: OperationResult<()> = async {
            loop {
                self.send(&mut writer, cancellation).await?;
                if !self.state.is_handshaking() {
                    return Ok(());
                }
                if self.receive(&mut reader, cancellation).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed during TLS handshake",
                    )
                    .into());
                }
            }
        }
        .await;
        self.send_alert_on_error(&result, &mut writer, cancellation)
            .await;
        let read_closed = reader.close().await;
        let write_closed = writer.close().await;
        result?;
        read_closed?;
        write_closed?;
        Ok(())
    }

    /// Read decrypted bytes, driving pending TLS control output as needed. A nonempty buffer returns zero only after an authenticated TLS close notification. Transport EOF without that notification reports `UnexpectedEof` once buffered plaintext is consumed. An empty buffer returns zero after checking cancellation.
    pub async fn read<S>(
        &mut self,
        scheduler: &S,
        buffer: &mut [u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize>
    where
        S: SocketStreamReading<Socket = C> + SocketStreamWriting + ?Sized,
        C: 'static,
    {
        cancellation.check()?;
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut reader = scheduler.socket_stream_reader(&self.socket)?;
        let mut writer = match scheduler.socket_stream_writer(&self.socket) {
            Ok(writer) => writer,
            Err(error) => {
                let _ = reader.close().await;
                return Err(error.into());
            }
        };
        let result: OperationResult<()> = async {
            loop {
                self.send(&mut writer, cancellation).await?;
                // Keep plaintext in rustls until both lanes have retired, so a cleanup error cannot hide an already consumed application-data prefix.
                match self.state.reader().fill_buf() {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.receive(&mut reader, cancellation).await?;
                    }
                    Ok(_) => return Ok(()),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        .await;
        self.send_alert_on_error(&result, &mut writer, cancellation)
            .await;
        let read_closed = reader.close().await;
        let write_closed = writer.close().await;
        result?;
        read_closed?;
        write_closed?;
        self.state.reader().read(buffer).map_err(Into::into)
    }

    /// Flush prior output, then accept a possibly short plaintext prefix into TLS buffering. The accepted prefix is reported without any subsequent asynchronous wait. Call `flush` to send it; later writes and reads also drive queued output.
    pub async fn write<S>(
        &mut self,
        scheduler: &S,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize>
    where
        S: SocketStreamWriting<Socket = C> + ?Sized,
        C: 'static,
    {
        cancellation.check()?;
        if self.write_closed {
            return Err(
                io::Error::new(io::ErrorKind::BrokenPipe, "TLS output is shut down").into(),
            );
        }
        self.flush(scheduler, cancellation).await?;
        cancellation.check()?;
        self.state.writer().write(buffer).map_err(Into::into)
    }

    /// Send all queued TLS records, including pending ciphertext from a cancelled flush. Cancellation does not discard or duplicate bytes already accepted by TLS.
    pub async fn flush<S>(
        &mut self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<()>
    where
        S: SocketStreamWriting<Socket = C> + ?Sized,
        C: 'static,
    {
        cancellation.check()?;
        let mut writer = scheduler.socket_stream_writer(&self.socket)?;
        let result = self.send(&mut writer, cancellation).await;
        let closed = writer.close().await;
        result?;
        closed?;
        Ok(())
    }

    /// Send a TLS close notification and stop accepting plaintext writes. Reads remain available. This does not wait for the peer's close notification or close the socket. Retry after cancellation to finish sending the same notification.
    pub async fn shutdown<S>(
        &mut self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<()>
    where
        S: SocketStreamWriting<Socket = C> + ?Sized,
        C: 'static,
    {
        cancellation.check()?;
        if !self.write_closed {
            self.state.send_close_notify();
            self.write_closed = true;
        }
        self.flush(scheduler, cancellation).await
    }

    /// Attempt TLS shutdown, then consume and close the socket even if shutdown failed or was cancelled. Preserve the shutdown error if socket closure also fails.
    pub async fn close<S>(
        mut self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<()>
    where
        S: SocketStreamWriting<Socket = C> + SocketClose + ?Sized,
        C: 'static,
    {
        let result = self.shutdown(scheduler, cancellation).await;
        let closed = scheduler.socket_close(self.socket).await;
        result?;
        closed?;
        Ok(())
    }

    /// Consume and close the socket without sending a TLS close notification. Use after fatal errors or when graceful output is not required.
    pub async fn abort<S>(self, scheduler: &S) -> io::Result<()>
    where
        S: SocketClose<Socket = C> + ?Sized,
    {
        scheduler.socket_close(self.socket).await
    }

    async fn send<W: SocketStreamWriter>(
        &mut self,
        writer: &mut W,
        cancellation: &Cancellation,
    ) -> OperationResult<()> {
        loop {
            if self.outgoing_start == self.outgoing.len() {
                self.outgoing.clear();
                self.outgoing_start = 0;
                if !self.state.wants_write() {
                    break;
                }
                self.outgoing.resize(BUFFER_SIZE, 0);
                // Rustls reports only destination errors; a memory cursor has none.
                let count = self
                    .state
                    .write_tls(&mut io::Cursor::new(self.outgoing.as_mut_slice()))
                    .expect("writing TLS records to memory cannot fail");
                self.outgoing.truncate(count);
            }
            let count = writer
                .write(&self.outgoing[self.outgoing_start..], cancellation)
                .await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS transport made no write progress",
                )
                .into());
            }
            self.outgoing_start += count;
        }
        writer.flush(cancellation).await
    }

    // Rustls queues a fatal alert when packet processing fails. Try to deliver it using the caller's cancellation signal, preserving the original TLS error if alert output fails or is cancelled.
    async fn send_alert_on_error<W: SocketStreamWriter>(
        &mut self,
        result: &OperationResult<()>,
        writer: &mut W,
        cancellation: &Cancellation,
    ) {
        if matches!(result, Err(OperationError::Io(error)) if error.get_ref().is_some_and(|source| source.is::<::rustls::Error>()))
        {
            let _ = self.send(writer, cancellation).await;
        }
    }

    async fn receive<R: SocketStreamReader>(
        &mut self,
        reader: &mut R,
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        if self.incoming_start == self.incoming_end {
            self.incoming_start = 0;
            self.incoming_end = reader.read_into(&mut self.incoming, cancellation).await?;
        }
        let mut input = &self.incoming[self.incoming_start..self.incoming_end];
        let count = self.state.read_tls(&mut input)?;
        self.incoming_start += count;
        self.state.process_new_packets().map_err(tls_error)?;
        Ok(count)
    }
}

impl<C: Send> TlsSession for RustlsConnection<C> {
    fn negotiated_protocol(&self) -> Option<&[u8]> {
        self.state.alpn_protocol()
    }
}

impl<S> TlsStream<S> for RustlsConnection<S::Socket>
where
    S: SocketStreamReading + SocketStreamWriting + SocketClose + ?Sized,
    S::Socket: 'static,
{
    async fn read(
        &mut self,
        scheduler: &S,
        buffer: &mut [u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        Self::read(self, scheduler, buffer, cancellation).await
    }

    async fn write(
        &mut self,
        scheduler: &S,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        Self::write(self, scheduler, buffer, cancellation).await
    }

    async fn flush(&mut self, scheduler: &S, cancellation: &Cancellation) -> OperationResult<()> {
        Self::flush(self, scheduler, cancellation).await
    }

    async fn shutdown(
        &mut self,
        scheduler: &S,
        cancellation: &Cancellation,
    ) -> OperationResult<()> {
        Self::shutdown(self, scheduler, cancellation).await
    }

    async fn close(self, scheduler: &S, cancellation: &Cancellation) -> OperationResult<()> {
        Self::close(self, scheduler, cancellation).await
    }

    async fn abort(self, scheduler: &S) -> io::Result<()> {
        Self::abort(self, scheduler).await
    }
}

#[cfg(test)]
mod tests;
