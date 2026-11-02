# Stream Immediate Reads

## Requirement

`ReadableStream::try_read_into` is a required, synchronous method that attempts one read now. It must reach the transport rather than report `WouldBlock` because of cached readiness or a retained pending read, so it observes input, EOF and errors already queued there. `WouldBlock` means no input is available now. Scheduler stream readers forward it to `SocketStreamReader::try_read_into`. Wrapping readers forward it to their inner reader; the method has no default, so a wrapper cannot silently fall back to polling a read.

The rustls duplex reader first returns plaintext it has already decrypted. Otherwise it asks its receive lane for an immediate read: the lane abandons its pending borrowed socket read, which has consumed nothing, and reads the socket immediately into the same ciphertext storage, so rustls receives bytes in transport order. It then returns any plaintext that produced, zero after an authenticated close, the lane's failure, or `WouldBlock`. A closed duplex reader returns zero, as its `read_into` does, and one whose supervision has finished reports closure. A lane failed by lifetime cancellation reports `ConnectionAborted` rather than `Interrupted`, which would invite a retry that cannot succeed.

## Rationale

base-http probes idle pooled connections for a peer's close before reusing them, including over TLS ([base-rs/base-http#42](https://github.com/base-rs/base-http/pull/42)). Polling a read once with a no-op waker misses closes the kernel has queued when the reader waits on cached readiness first, and the TLS receive lane retains such a pending read. The scheduler provides `SocketStreamReader::try_read_into` for this ([base-rs/base-scheduler#89](https://github.com/base-rs/base-scheduler/pull/89)); the stream contract carries it through TLS. A second socket reader for immediate reads would need its ciphertext ordered with the lane's, so the lane performs both reads itself.

## Scope

`ReadableStream`, its blanket implementation for scheduler stream readers, and the rustls duplex reader. The sequential `RustlsConnection` read is unchanged.

## Validation

Over a real rustls connection on Native with its only worker kept busy, so no driver publishes readiness, immediate reads return `WouldBlock` with no input, then queued plaintext, then zero after `close_notify`; on Unix, where established reads wait on cached readiness, the same test fails if the lane does not read immediately. A deterministic fault test whose transport leaves borrowed reads pending while records are queued checks the immediate path and byte order on every platform. Fault tests also cover plaintext decrypted before the immediate read, an inner transport failure, lifetime cancellation, a receive lane retirement error and a finished duplex. The TCP exchange checks the blanket forwarding with both schedulers.
