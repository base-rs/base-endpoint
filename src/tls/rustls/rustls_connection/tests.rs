// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::*;
use base_scheduler::{IoBufSequence, OperationError, SocketSendFlags};
use futures_lite::future::block_on;
use std::io::IoSlice;

#[derive(Default)]
struct ShortWriter {
    output: Vec<u8>,
    cancel_at: Option<usize>,
    zero: bool,
}

impl SocketStreamWriter for ShortWriter {
    type Buffer = Vec<u8>;

    async fn write(
        &mut self,
        buffer: &[u8],
        cancellation: &Cancellation,
    ) -> OperationResult<usize> {
        cancellation.check()?;
        if self
            .cancel_at
            .is_some_and(|limit| self.output.len() >= limit)
        {
            cancellation.cancel();
            return Err(base_scheduler::Cancelled.into());
        }
        if self.zero {
            return Ok(0);
        }
        let count = buffer.len().min(7);
        self.output.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    async fn flush(&mut self, cancellation: &Cancellation) -> OperationResult<()> {
        cancellation.check().map_err(Into::into)
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn write_vectored(
        &mut self,
        _: &[IoSlice<'_>],
        _: &Cancellation,
    ) -> OperationResult<usize> {
        unreachable!("test uses borrowed writes")
    }
    async fn write_vectored_with_flags(
        &mut self,
        _: &[IoSlice<'_>],
        _: SocketSendFlags,
        _: &Cancellation,
    ) -> OperationResult<usize> {
        unreachable!("test uses borrowed writes")
    }
    async fn write_owned_vectored<B: IoBufSequence>(
        &mut self,
        _: B,
        _: SocketSendFlags,
        _: &Cancellation,
    ) -> (OperationResult<usize>, B) {
        unreachable!("test uses borrowed writes")
    }
    async fn submit(
        &mut self,
        _: Vec<u8>,
        _: &Cancellation,
    ) -> Result<(), (OperationError, Vec<u8>)> {
        unreachable!("test uses borrowed writes")
    }
}

fn client_state() -> Connection {
    let config = ::rustls::ClientConfig::builder()
        .with_root_certificates(::rustls::RootCertStore::empty())
        .with_no_client_auth();
    ::rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        ::rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap()
    .into()
}

#[test]
fn cancelling_partial_ciphertext_output_resumes_without_losing_or_duplicating_bytes() {
    block_on(async {
        let mut state = client_state();
        let mut expected = Vec::new();
        while state.wants_write() {
            state.write_tls(&mut expected).unwrap();
        }
        let mut connection = RustlsConnection::new((), state);
        connection.outgoing = expected.clone();
        let mut writer = ShortWriter {
            cancel_at: Some(14),
            ..Default::default()
        };
        assert!(matches!(
            connection.send(&mut writer, &Cancellation::new()).await,
            Err(OperationError::Cancelled(_))
        ));
        assert_eq!(connection.outgoing_start, 14);
        assert_eq!(writer.output, expected[..14]);
        writer.cancel_at = None;
        connection
            .send(&mut writer, &Cancellation::never())
            .await
            .unwrap();
        assert_eq!(writer.output, expected);
        connection
            .send(&mut writer, &Cancellation::never())
            .await
            .unwrap();
        assert_eq!(writer.output, expected);
    });
}

#[test]
fn zero_progress_writes_report_write_zero_and_retain_the_pending_record() {
    block_on(async {
        let mut connection = RustlsConnection::new((), client_state());
        let mut writer = ShortWriter {
            zero: true,
            ..Default::default()
        };
        let error = connection
            .send(&mut writer, &Cancellation::never())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(connection.outgoing_start, 0);
        assert!(!connection.outgoing.is_empty());
    });
}
