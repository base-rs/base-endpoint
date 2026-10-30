# Endpoint Establishment

## Requirement

Consumers must be able to request connecting or binding through endpoint contracts without implementing address resolution or socket setup. Endpoint implementations select their connection and listener types. The production library uses explicit scheduler capabilities and does not require a concrete runtime, retain a global scheduler, or spawn tasks.

Expose TLS through a generic submodule. TLS connector and acceptor providers own handshake implementation, configuration, authentication and failed-handshake cleanup. Client/server endpoint adapters compose these providers with the existing connect/bind contracts without selecting a cryptography implementation. A provider-neutral stream interface supplies sequential application I/O and shutdown. The client's authenticated server identity is independent of its routing address, and negotiated ALPN is available after a successful handshake.

Include rustls as the first concrete provider behind an optional feature. Accept explicit rustls client/server configurations for trust, credentials, authentication and ALPN, and perform network I/O only through scheduler capabilities. Preserve TLS errors as error sources, reject truncated TLS as unexpected EOF, and retain unsent ciphertext across cancelled output operations without losing or duplicating accepted bytes. Await directional I/O retirement before closing a failed handshake's socket.

TCP hostname endpoints resolve through `AddressResolution`, attempt connections in returned order using a fresh socket per attempt, and bind all returned addresses. Cancellation terminates fallback. An empty endpoint set fails. On an awaited failed establishment, every socket created by the operation is consumed by scheduler cleanup before the operation returns; binding failure also rolls back earlier listeners. Successful resources transfer to the caller.

## Rationale

The requested Rust equivalent of IO::Endpoint primarily abstracts binding and connecting. Address lookup and TCP socket setup are the first implementations of that abstraction, rather than requirements imposed on every endpoint type.

## Scope

Public endpoint traits and built-in TCP address, hostname and composite implementations, generic TLS contracts and adapters, and the optional rustls provider. Binding composition currently supports scheduler-native listeners; wrap that composition in a TLS server endpoint. Awaited cooperative cancellation provides cleanup; abandoning a future does not promise asynchronous completion. UNIX sockets and packet/QUIC endpoints, including UDP, remain outside the initial implementation; UNIX sockets need a scheduler extension for non-IP socket creation and addresses. URI parsing, named endpoints, socket-option policies, local source binding, Happy Eyeballs and built-in timeouts are follow-up work. The rustls provider now also supports explicitly supervised duplex I/O through `with_duplex`, over persistent scheduler handles; small plaintext stream contracts are exposed without adding a separate stream crate. HTTP owns ALPN offers and engine interpretation.

## Validation

Compile generic consumers and a custom endpoint whose connection and listener are not scheduler sockets. Test fallback order, fresh socket ownership, cancellation, empty candidates, resolver hints and bind rollback using deterministic scheduler capabilities. Exercise real TCP bind/connect/accept and data transfer with Direct and Tokio scheduler adapters. Test generic TLS composition with simulated providers, and real TLS 1.2/1.3 exchanges with rustls on both schedulers and against independent blocking rustls peers. Verify certificate/name rejection, ALPN, cancellation cleanup, TLS truncation detection and graceful shutdown. Test partial output and cancellation deterministically. Check both default and rustls feature configurations, and inspect production dependencies for runtime independence.

Duplex validation includes an independent blocking TLS echo peer with backpressure, lifetime cancellation while application input uses a separate signal, and truncated TLS after authenticated plaintext. The HTTP integration exercises both directions through the same provider; no endpoint connection trait requires all future transports to behave like TCP.
