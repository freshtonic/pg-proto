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

## Replace direct phase-association bounds

Code which names middleware's phase-association traits directly should replace
`TypedPhase<Role, Wire>` with `PhaseAssociation<Inbound, Role, Wire>` and
`TypedOutboundPhase<Role, Wire>` with
`PhaseAssociation<Outbound, Role, Wire>`. The generated protocol grammars now
own these implementations; application code cannot implement the sealed trait.

Most callers need no explicit bound. Typed receive and outbound interception
methods infer the association from the connection phase, direction, sender role,
and wire message type.

## Replace proxy message queues with a bounded pipeline ledger

Opt in with `Intermediary::with_pipeline(BoundedPipeline::new(limit)?)`. Feed
each decoded frontend message to `pipeline_mut().accept_frontend(...)`. A
`Forward` action returns the original owned message for upstream encoding; a
`Discard` action identifies a locally handled operation. `FrontendAdmission`
wraps either action as `Immediate` or `Waiting`. Capacity and protocol illegality
return the original message in `FrontendProjectionError`, so the proxy can pause
downstream reads and retry without cloning a payload.

The pre-1.0 overlapping entry points have been removed. Replace
`project_frontend` and `frontend_action` with `accept_frontend`, and replace their
`_typed` counterparts with `accept_frontend_typed`. Handle the former
`FrontendAction::Backpressure` case as `FrontendProjectionError::Capacity`.
Replace `accept_session_item` with `SessionItem::into_backend_message` followed
by `accept_backend`, using the corresponding `_typed` method when middleware is
required. This conversion is deliberately lossy: consume `parameters_changed`,
command position, and attributed notices from the `SessionItem` before converting
it.

The ledger stores only operation metadata. It does not clone or retain SQL,
Bind values, COPY chunks, rows, or forwarded responses. For a local response,
retain its `OperationId`, wait until that operation is at the response head,
then call `try_emit_local`. A premature call returns the same response as
`BackendAction::Deferred`, so it cannot overtake earlier upstream work.

After either an upstream or local extended-query `ErrorResponse`, the ledger
discards accepted operations through the next `Sync`. Only the corresponding
`ReadyForQuery` completes recovery. Authorisation, rewriting, routing, local
response contents, and the decision to forward or intercept remain application
policy; pg-proto owns ordering, bounded capacity, protocol legality, COPY phase
tracking, and error-drain bookkeeping.

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
- [`examples/intermediary_pipeline.rs`](examples/intermediary_pipeline.rs)
  combines forwarding, local rejection, backpressure, and ordered emission.
- [`tests/intermediary_harness.rs`](tests/intermediary_harness.rs) is the neutral
  capability acceptance harness.
