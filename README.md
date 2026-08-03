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
- connection-branded prepared statements and portals with checked name rewriting;
- exact phase/cleanliness erasure with checked re-entry at storage boundaries;
- ordered `ParameterStatus` and notification sinks for proxy forwarding;
- a grammar proc macro which emits transport-carrying two-index typestates, a
  runtime FSM, and railroad SVG with choice, loop, and cleanliness effects;
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

## Connection-branded statements and portals

For locally constructed extended-query traffic, `with_connection_resources`
shares a generative brand between the connection and its statement/portal
namespace. A token cannot be used by another connection, while rewritten client
and upstream names remain available to proxy policy:

```rust
use bytes::Bytes;
use pg_proto::{
    Conn,
    auth::Ready,
    resources::with_connection_resources,
};

fn build_pipeline<S>(ready: Conn<S, Ready>) -> std::io::Result<Conn<S, pg_proto::session::BoundBuilding, pg_proto::Dirty>> {
    with_connection_resources(ready.begin_extended(), |connection| {
        let (connection, statement, _parse) = connection
            .prepare(
                Bytes::from_static(b"client_statement"),
                Bytes::from_static(b"proxy_17_statement"),
                Bytes::from_static(b"select $1::int4"),
                vec![23],
            )
            .map_err(std::io::Error::other)?;
        let (connection, portal, _bind) = connection
            .bind(
                &statement,
                Bytes::from_static(b"client_portal"),
                Bytes::from_static(b"proxy_17_portal"),
                vec![1],
                vec![Some(Bytes::from_static(b"\0\0\0*"))],
                vec![1],
            )
            .map_err(std::io::Error::other)?;
        let (connection, _execute) = connection
            .execute(&portal, 0)
            .map_err(std::io::Error::other)?;
        Ok(connection.into_connection())
    })
}
```

The returned frames are still fully typed and may be inspected or replaced
before buffering. Calling `into_connection` is the explicit escape from
resource-aware handling back to the ordinary typestate API.

## Verification

Run the deterministic suite with `cargo test`. Run the live PostgreSQL matrix
when a Docker-compatible runtime is available:

```console
cargo test --test postgres_container -- --ignored
```

Layer 2 covers the client and server pre-startup, authentication, query, reset,
error-draining, and COPY grammars. One declaration emits transport-carrying
typestate and dual APIs, an executable runtime FSM for differential testing, and
railroad SVG. Generated transitions preserve or replace the orthogonal
cleanliness index explicitly, and transport mapping represents in-place TLS
upgrades without weakening the phase index.

Multiparty proxy verification remains Layer 3 work after the generated roles are
wired directly to message payloads and proxy policy.
