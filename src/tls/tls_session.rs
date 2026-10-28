// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

/// Metadata available after a successful TLS handshake. Stream providers can also implement [`TlsStream`](super::TlsStream) for provider-neutral application I/O and orderly shutdown. Retire those operations and send any required TLS close notification before closing the underlying transport.
pub trait TlsSession: Send {
    /// The protocol selected by ALPN, or `None` if no protocol was negotiated. Protocol identifiers are opaque bytes; callers must decide whether the selected protocol is acceptable.
    fn negotiated_protocol(&self) -> Option<&[u8]>;
}
