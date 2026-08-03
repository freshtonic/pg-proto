# Migration guide

This guide is for proxy implementations moving from a runtime connection-state
enum to `pg-proto`'s generated and transport-integrated typestate APIs.

## Replace state mutation with ownership transitions

Instead of storing `state: ConnectionState` and checking it before every send or
receive, store `Conn<Transport, Phase, Cleanliness>` at the boundary where its
phase is known. Each legal operation consumes that value and returns the next
phase. Illegal operations are absent from the type, and a rejected incoming
message returns the unchanged connection.

At heterogeneous storage boundaries, call `erase()` and later `try_reenter()`.
This preserves exact phase and cleanliness identities without spreading a large
generic type through the pool implementation.

## Split transport work from application policy

Decode first, inspect or replace the typed message, and only then offer it to the
session. `Intermediary<Downstream, Upstream>` owns the two independent roles and
provides synchronous and asynchronous callbacks with access to both. It does not
route, forward, authorise, or rewrite implicitly.

Use:

- `Buffered::push_frame` followed by cancellation-safe `flush` for batching;
- `Demux::pop_async_event` for cross-kind ordered asynchronous forwarding;
- `with_connection_resources` for branded statement/portal namespaces;
- `CancelKeyMint` and `CancelKeyRegistry` for application-owned cancellation;
- `CleanlinessPolicy` for application-owned pool release decisions; and
- `GssEncUpgrade` or `TokenAuthEngine` for platform credential adapters.

## Authentication and TLS

Create and authenticate each side independently. Client-facing server-role TLS
and authentication need not match upstream client-role TLS or authentication.
Do not carry a single mechanism or credential enum across both sides. For
SCRAM-SHA-256-PLUS, retain the TLS transport wrapper so authentication can query
its `tls-server-end-point` binding.

## Errors, COPY, and pooling

After `ErrorResponse`, keep the returned `Draining` connection and consume only
the legal path to `ReadyForQuery`. COPY IN, OUT, and BOTH are nested phases; do
not erase them into ordinary query forwarding. Release to a pool only with both
idle readiness evidence and an application cleanliness policy that permits it.

## Worked examples

- [`examples/proxy_skeleton.rs`](examples/proxy_skeleton.rs) shows where proxy
  policy and registries plug in.
- [`examples/rewriting_intermediary.rs`](examples/rewriting_intermediary.rs)
  modifies reconstructable extended-query and result messages.
- [`tests/intermediary_harness.rs`](tests/intermediary_harness.rs) is the neutral
  capability acceptance harness.
