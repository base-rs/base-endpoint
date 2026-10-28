// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

//! Plaintext byte-stream capabilities for established transports.
//!
//! These contracts describe one direction, independently of whether the
//! transport encrypts its bytes. Packet transports retain their own message
//! boundaries and do not implement this interface by flattening packets.

use base_scheduler::{Cancellation, OperationResult, SocketStreamReader, SocketStreamWriter};
use std::{future::Future, io};

/// A sequential input direction. A nonempty read returns zero at EOF.
/// Independent input and output directions must be able to make progress.
pub trait ReadableStream: Send {
    /// Read a possibly short prefix. Empty storage does not establish EOF.
    fn read_into(
        &mut self,
        buffer: &mut [u8],
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<usize>> + Send;

    /// Retire this direction. Transport ownership and final closure are separate.
    fn close(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

/// An ordered output direction. Accepted bytes must not be replayed after a
/// cancelled flush; flush establishes delivery to the underlying transport.
pub trait WritableStream: Send {
    /// Accept a possibly short prefix, reporting progress before another wait.
    fn write(
        &mut self,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<usize>> + Send;

    /// Deliver all previously accepted bytes, without closing the direction.
    fn flush(
        &mut self,
        cancellation: &Cancellation,
    ) -> impl Future<Output = OperationResult<()>> + Send;

    /// Retire this direction. Flush first when delivery is required.
    fn close(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

impl<R: SocketStreamReader> ReadableStream for R {
    async fn read_into(
        &mut self,
        buffer: &mut [u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        SocketStreamReader::read_into(self, buffer, cancellation).await
    }
    async fn close(&mut self) -> io::Result<()> {
        SocketStreamReader::close(self).await
    }
}

impl<W: SocketStreamWriter> WritableStream for W {
    async fn write(
        &mut self,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        SocketStreamWriter::write(self, buffer, cancellation).await
    }
    async fn flush(&mut self, cancellation: &Cancellation) -> OperationResult<()> {
        SocketStreamWriter::flush(self, cancellation).await
    }
    async fn close(&mut self) -> io::Result<()> {
        SocketStreamWriter::close(self).await
    }
}
