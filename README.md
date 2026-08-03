# pg-proto

A session-typed implementation of the `PostgreSQL` frontend/backend wire protocol
for proxies. Protocol sequencing is represented by consuming transitions on
`Conn<Transport, Phase, Cleanliness>` rather than a runtime connection-state enum.

The crate currently includes:

- direction-parameterised, reconstructable frontend and backend codecs;
- typed SSL/GSS/cancellation/startup choice before normal framing;
- client and server rustls upgrades which change the transport type;
- cleartext, MD5, GSS, SSPI, Kerberos, SCRAM-SHA-256, and
  SCRAM-SHA-256-PLUS authentication projections;
- a filtered async-message demultiplexer with positionally tagged notices;
- client and server simple, extended, error-draining, and COPY sessions;
- transaction and parameter cleanliness evidence for pool release;
- conservative query/resource tainting with explicit stateless-query escape hatches;
- ordered `ParameterStatus` and notification sinks for proxy forwarding;
- a grammar proc macro which emits typestates, a runtime FSM, and railroad SVG;
- compile-fail tests for illegal protocol transitions; and
- Testcontainers coverage against the official PostgreSQL 18 image.

The frontend and backend roles deliberately do not share an authentication
mechanism. A proxy can terminate client authentication with one policy while it
independently authenticates to the upstream server with another.

## Inspecting and rewriting messages

The wire transport first returns a fully typed message without advancing the
session. Proxy policy can inspect, modify, or replace it and then explicitly
project the chosen message into the typestate machine:

```rust
use pg_proto::{
    Conn,
    auth::Ready,
    codec::{Frontend, FrontendMessage, Parse},
    server_session::{ServerExtendedOffer, ServerReadyOffer},
    transport::Buffered,
};

async fn intercept_parse<S, C>(
    mut client: Conn<Buffered<S, Frontend>, Ready, C>,
) -> std::io::Result<ServerExtendedOffer<Buffered<S, Frontend>, C>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut message = client.receive_frontend_wire().await?;
    if let FrontendMessage::Parse(Parse { query, .. }) = &mut message {
        *query = bytes::Bytes::from_static(b"select encrypted_column from records");
    }
    match client.offer_frontend(message) {
        Ok(ServerReadyOffer::Extended(next)) => Ok(next),
        Ok(_) => panic!("expected extended-query input"),
        Err(_) => Err(std::io::Error::other("message is illegal while ready")),
    }
}
```

`Parse`, `Bind`, `Describe`, and `RowDescription` retain all names, values,
format codes, and OIDs needed to reconstruct rewritten frames.

## Verification

Run the deterministic suite with `cargo test`. Run the live PostgreSQL matrix
when a Docker-compatible runtime is available:

```console
cargo test --test postgres_container -- --ignored
```

Layer 2 has a working foundation: one grammar declaration generates typestate
transitions, a runtime FSM for differential testing, and railroad SVG. The next
construction work is expanding that generated grammar over the complete handwritten
client and server roles. Multiparty proxy verification remains after the generated
two-party roles are solid.
