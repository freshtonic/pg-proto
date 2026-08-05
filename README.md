# pg-proto

[![CI](https://github.com/freshtonic/pg-proto/actions/workflows/ci.yml/badge.svg)](https://github.com/freshtonic/pg-proto/actions/workflows/ci.yml)
[![docs.rs](https://docs.rs/pg-proto/badge.svg)](https://docs.rs/pg-proto)
[![crates.io](https://img.shields.io/crates/v/pg-proto.svg)](https://crates.io/crates/pg-proto)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/freshtonic/pg-proto/blob/main/LICENSE)

`pg-proto` is an asynchronous Rust implementation of the PostgreSQL
frontend/backend wire protocol designed for proxies, poolers, gateways, drivers,
and protocol-aware test infrastructure.

Its distinguishing feature is that PostgreSQL's connection state machine is
represented in Rust's type system. Operations consume a
`Conn<Transport, Phase, Cleanliness>` and return a connection in its next phase.
Code which tries to issue a query during `COPY IN`, execute before binding, send
a startup packet while TLS negotiation is pending, or release a dirty connection
to a pool does not compile.

Most PostgreSQL protocol libraries decode messages but retain the session phase
in a runtime enum. `pg-proto` is useful when protocol correctness is part of the
architecture rather than merely an implementation detail: the legal next
operations are visible in function signatures, illegal compositions are rejected
at compile time, and proxy policy can still inspect, replace, or reject complete
typed messages.

## What it provides

- Direction-parameterised frontend and backend codecs. Ambiguous tags such as
  `S` and `E` cannot be decoded in the wrong direction.
- Typed pre-startup handling for `SSLRequest`, `GSSENCRequest`, `CancelRequest`,
  and `StartupMessage`, including transport-changing rustls upgrades.
- A plain/client-TLS/server-TLS network stream, configurable TCP socket options,
  and outbound connection retry with capped exponential backoff.
- Independent client-facing and upstream authentication sessions, including
  cleartext, MD5, SCRAM-SHA-256, and SCRAM-SHA-256-PLUS with channel binding.
- Simple and extended query sessions, pipelining, error draining, function calls,
  COPY IN/OUT/BOTH, and physical replication framing.
- Lossless, reconstructable `Parse`, `Bind`, `Describe`, `Execute`,
  `RowDescription`, and `DataRow` values for SQL and result rewriting.
- A demultiplexer for asynchronous notices, notifications, and parameter status
  updates without polluting the causal session type.
- Positionally tagged notices and transaction/parameter evidence for pooling
  decisions.
- Connection-branded prepared statements and portals with name rewriting.
- Exact typestate erasure and checked re-entry at storage and pool boundaries.
- A protocol grammar macro which emits typestates, their duals, a runtime FSM for
  differential testing, and railroad diagrams embedded in rustdoc.

The crate owns protocol representation and ordering. Applications retain control
of listeners, credentials, authorisation, SQL transformation, routing, pooling,
cancellation storage, telemetry, and failure policy.

## Why use it?

PostgreSQL infrastructure tends to fail at phase boundaries rather than while
decoding an individual frame. A pooler may return a connection while it is still
in a transaction, a proxy may forward `Query` while a COPY exchange is active,
or an extended-query error path may forget to discard messages until `Sync`.
Typestate makes these transitions explicit and turns many such bugs into type
errors.

The phase index is orthogonal to connection cleanliness. A connection can be
protocol-ready but unsuitable for unconditional pool release because of an open
transaction, changed GUC, prepared statement, portal, `LISTEN`, or advisory lock.
Only `Conn<_, Ready, Pristine>` exposes unconditional release.

## What can be built with it?

The [bounded intermediary pipeline example](examples/intermediary_pipeline.rs)
shows ordered forwarding, local interception, and backpressure without proxy-owned
message queues.

- A TLS-terminating PostgreSQL proxy which authenticates each side independently
  and inspects plaintext SQL and result rows.
- A transaction or session pooler whose release policy consumes explicit
  protocol and cleanliness evidence.
- A SQL firewall, audit gateway, query rewriter, or column-encryption proxy.
- A sharding/router layer which rewrites prepared-statement and portal names.
- A logical or physical replication relay with typed COPY-BOTH half-closes.
- A PostgreSQL-compatible server, mock backend, recorder, replay tool, or protocol
  conformance harness.
- A driver or administrative client which benefits from compile-time sequencing.

## Usage

The generated grammar witnesses make the sequencing model easy to see. Every
method consumes the previous phase; uncommenting an operation which is illegal
in the current phase produces a compiler error.

```rust
use pg_proto::grammar::frontend::Session;

let ready = Session::new();
let building = ready.begin_extended().parse().bind().execute();
let ready = building.sync().ready();

// `building.query()` would not compile: Query is unavailable during an
// extended-query pipeline, which must leave through Sync.
let _terminated = ready.terminate();
```

A proxy can inspect or replace a typed message before reconstructing its checked
wire frame:

```rust
use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    codec::{FrontendMessage, Parse},
    intermediary::Intermediary,
};

let mut proxy = Intermediary::new((), ());
let message = FrontendMessage::Parse(Parse {
    statement: Bytes::from_static(b"report"),
    query: Bytes::from_static(b"select email from customers"),
    parameter_types: vec![],
});

let rewritten = proxy
    .inspect(message, |(), (), message| {
        let FrontendMessage::Parse(mut parse) = message else {
            unreachable!("the caller selected a Parse message")
        };
        parse.query = Bytes::from_static(
            b"select decrypt_email(email) from customers where active",
        );
        Ok::<_, Infallible>(FrontendMessage::Parse(parse))
    })
    .unwrap();

let frame = rewritten.to_frame()?;
# Ok::<(), std::io::Error>(())
```

For a complete networked example, see the TLS-terminating
[`SQL logging proxy`](examples/sql_logging_proxy/README.md). The companion
[`protocol logging proxy`](examples/protocol_logging_proxy/README.md) prints every
decoded message in both directions. More focused examples live in the
[`examples/`](examples/) directory, including message rewriting and the neutral
proxy composition boundary.

## Rustdoc entry points

- [Crate overview and `Conn`](https://docs.rs/pg-proto/latest/pg_proto/)
- [Frontend/backend messages and codecs](https://docs.rs/pg-proto/latest/pg_proto/codec/)
- [Buffered network transport and interception](https://docs.rs/pg-proto/latest/pg_proto/transport/)
- [Pre-startup and TLS negotiation](https://docs.rs/pg-proto/latest/pg_proto/pre_startup/)
- [Upstream/client-role authentication](https://docs.rs/pg-proto/latest/pg_proto/auth/)
- [Downstream/server-role authentication](https://docs.rs/pg-proto/latest/pg_proto/server_auth/)
- [Client-role query sessions](https://docs.rs/pg-proto/latest/pg_proto/session/)
- [Server-role query sessions](https://docs.rs/pg-proto/latest/pg_proto/server_session/)
- [Proxy-side composition hooks](https://docs.rs/pg-proto/latest/pg_proto/intermediary/)
- [Bounded intermediary pipeline](https://docs.rs/pg-proto/latest/pg_proto/pipeline/)
- [Prepared-statement and portal resources](https://docs.rs/pg-proto/latest/pg_proto/resources/)
- [Generated protocol grammars and railroad diagrams](https://docs.rs/pg-proto/latest/pg_proto/grammar/)

Build the same documentation locally with:

```console
cargo doc --workspace --no-deps --open
```

## Supported PostgreSQL versions

PostgreSQL **14, 15, 16, 17, and 18** are supported. Each version runs the same
live suite against its official Alpine image. PostgreSQL 14–17 negotiate a
requested protocol 3.2 startup down to 3.0; PostgreSQL 18 reports protocol 3.2.
Both behaviours are covered explicitly.

Run a selected version locally with a Docker-compatible runtime:

```console
PG_PROTO_POSTGRES_VERSION=18 \
  cargo test --test postgres_container -- --ignored
```

See [`SUPPORTED_VERSIONS.md`](SUPPORTED_VERSIONS.md) for the tested protocol
matrix.

## Known limitations

- The API is pre-1.0 and may change as it is integrated into a production proxy.
- Kerberos V5, GSSAPI, SSPI, and GSS token exchanges are represented by the
  protocol API, but the crate does not ship platform credential-provider engines.
  GSS encryption negotiation is modelled; a production GSSENC transport adapter
  remains application work.
- Pool scheduling, routing, SQL parsing, policy, credential storage, certificate
  provisioning, and cancellation-key persistence are intentionally not included.
- Rust is affine rather than linear: callers can abandon a session by dropping
  it. `Conn` is `#[must_use]` and has a debug-only drop bomb, but release builds
  cannot make deliberate connection abandonment impossible.
- Unknown future PostgreSQL message tags are rejected by the typed codec until
  their direction and semantics are added.
- Formal multiparty verification is not provided. Client and server roles are
  dual generated APIs with differential runtime-FSM testing, not a machine-checked
  proof of a complete three-party proxy.

Security assumptions and downstream responsibilities are documented in
[`SECURITY.md`](SECURITY.md). The audited proxy capability boundary is in
[`PROXY_COMPATIBILITY.md`](PROXY_COMPATIBILITY.md), and migration from a
runtime-enum implementation is covered by [`MIGRATION.md`](MIGRATION.md).
Contribution instructions and community expectations are in
[`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Verification

The ordinary suite includes unit, fixture, property-style differential,
compile-fail, and documentation tests:

```console
cargo test --workspace
```

Live PostgreSQL tests require a Docker-compatible runtime:

```console
cargo test --test postgres_container -- --ignored
```

## Licence

Licensed under the [MIT License](https://github.com/freshtonic/pg-proto/blob/main/LICENSE).
