# Implementation handoff: ordered backend batch holding

## Objective

Widen pg-proto's builder-only intermediary interface so CipherStash can retain
multiple PostgreSQL `DataRow` messages, transform them asynchronously as a batch,
then forward the same number of replacement rows in original order. Each source
and replacement must affect protocol state exactly once.

This is a one-to-one delayed replacement capability. Preserve the independent
meaning of `BackendMiddlewareOutput::Expand`: immediate replacement of one
received message with multiple outgoing messages.

## Start here

Read these sources before editing:

- [`backend-batching-prototype-report.md`](backend-batching-prototype-report.md)
  contains the validated decision and rejected alternatives.
- [`backend-batching-crate-hold.md`](backend-batching-crate-hold.md) contains the
  fuller crate-owned design, including limits, barriers, errors, and tests.
- [`backend-batching-comparison.md`](backend-batching-comparison.md) compares the
  ownership seams.
- [`backend-batching-prototype.html`](backend-batching-prototype.html) is a
  throwaway state-machine primary source, not production code.
- `CONTEXT.md` defines project terminology.
- `docs/adr/0002-proxy-interception-boundary.md` requires wire receipt, policy,
  and session advancement to remain separate.

The repository is currently at pg-proto 0.8.0. The design documents are untracked
in the working tree at the time of this handoff; preserve them when creating the
implementation branch.

## Existing 0.8.0 behaviour

The relevant implementation is in `src/intermediary_component.rs`:

- `BackendMiddlewareOutput` supports `Forward`, `Expand`, and `Suppress`.
- `process_backend` receives and source-role-intercepts one message, invokes
  async boundary middleware, then destination-role-intercepts output.
- `Suppress(message)` calls `advance_backend(message)` immediately.
- `Expand(messages)` calls `emit_backend` for every output immediately and
  rejects an empty vector.
- `emit_backend` calls `Pipeline::accept_backend` before writing downstream.
- `forward_next` selects between frontend and backend transports.
- `teardown` currently assumes no retained backend payloads.

The ordering ledger is in `src/pipeline.rs`. It intentionally retains operation
metadata rather than message payloads. Keep it payload-free.

The defect is observable when middleware stores rows elsewhere and returns
`Suppress`: every source is projected immediately, then each later re-emitted row
is projected again. `Expand` cannot represent delayed forwarding because it has
one current source and immediate output semantics.

## Chosen ownership model

The intermediary connection owns authoritative uncommitted backend messages.
Caller-defined connection state may own derived application data such as crypto
workspaces, decrypted values, tenant facts, and spill handles. It is not the
authoritative owner of received protocol messages.

Use these ownership states:

```text
transport
  → pending source
  → crate-owned hold
  → borrowed by async batch policy
  → atomically prepared replacements
  → projected and written in order
```

At every await point, each source must remain reachable through exactly one
connection-owned location. Cancellation restores control without replaying
source-role or boundary middleware.

## Target interface shape

Treat names as provisional, but preserve the semantics:

```rust
pub enum BackendMiddlewareOutput {
    Forward(BackendMessage),
    Expand(Vec<BackendMessage>),
    Suppress(BackendMessage),

    /// Retain the unchanged current source without projection or output.
    Hold,
}

pub enum BackendBatchOutput {
    /// Keep the authoritative input span uncommitted.
    KeepHolding,

    /// Atomically replace every held input with one output in the same position.
    ReplaceOneToOne(Vec<BackendMessage>),
}

pub enum BackendFlushReason {
    Capacity,
    ProtocolBarrier,
    Explicit,
    Teardown,
}
```

Add an async/fallible batch hook to `IntermediaryMiddleware`. The held span is
borrowed so cancellation cannot drop it:

```rust
fn flush_backend<'a>(
    &'a mut self,
    server: &'a ServerContext,
    client: &'a ClientContext,
    state: &'a mut State,
    held: &'a HeldBackendMessages,
    reason: BackendFlushReason,
) -> Pin<Box<
    dyn Future<Output = Result<BackendBatchOutput, Self::Error>> + 'a,
>>;
```

`HeldBackendMessages` is an opaque ordered view. Expose iteration and safe message
inspection, not mutation, transport access, pipeline access, or projection
methods. The default hook returns one-to-one clones of the held messages so
identity middleware remains usable. `BackendMessage` already has cheap cloning
for byte payloads; measure before pursuing a more elaborate lending result.

`Hold` is deliberately a unit variant. Before awaiting boundary middleware, the
connection retains the post-client-role-interception source in a private pending
slot and passes a clone to the existing owned-message hook. If the hook returns
`Hold`, move the authoritative pending source into the hold. If the future is
cancelled, the source remains in the connection. Do not require middleware to
return the authoritative message it is asking pg-proto to retain.

Add explicit builder configuration for non-zero message and byte limits. No
implicit unbounded hold is acceptable. Existing configurations that never return
`Hold` should preserve their current behaviour without allocating a hold queue.

## Required semantics

### One-to-one release

The first production slice supports equal input and output cardinality only. A
held span of length `n` accepts exactly `n` replacements. Preserve order by index.
This is the CipherStash requirement and keeps general fan-out out of the delayed
batch state machine.

The current barrier is not part of the held row span unless middleware explicitly
returns `Hold` for it. On a known barrier with pending rows:

1. invoke `flush_backend` with `ProtocolBarrier`;
2. atomically project and emit the replacements;
3. process the barrier through its normal one-message decision; and
4. emit the barrier after the released rows.

Conservatively classify `CommandComplete`, `PortalSuspended`,
`EmptyQueryResponse`, `ErrorResponse`, `ReadyForQuery`, COPY phase transitions,
and asynchronous messages as barriers in the first implementation. Co-locate the
catalogue with backend projection rules and prove each entry with a tracer test.

### Atomic projection

Add private prepare/commit support to `Pipeline` for a complete backend sequence.
Dry-run replacements against a clone or prepared transition log of the lightweight
ledger. Commit the live ledger only if every replacement is reconstructable,
legal, attributable to the same held response span, and ordered.

Do not project original held messages and then project replacements. The original
sequence is used only to validate the response span and cardinality. The committed
downstream projection consists of the replacements exactly once.

No socket write occurs until the entire sequence validates. Once writes begin, an
I/O failure is terminal because a frame prefix may be visible; do not roll back or
replay projection.

### Pressure and driving

Track both held message count and estimated retained bytes. When either limit is
reached:

1. stop polling the upstream backend transport;
2. invoke the batch hook with `Capacity`;
3. accept only a successful release; and
4. return a structured capacity error carrying the intact connection/hold if
   middleware elects to keep holding.

Update `forward_next` so frontend polling cannot create more outstanding work
while a full backend hold blocks progress. Preserve existing pipeline admission
and local-response ordering.

Provide an explicit `flush_backend_hold()` operation for latency timers and
application-controlled batch boundaries. It reads no new upstream frame.

### Errors and teardown

Preserve ownership in every pre-write error:

- middleware failure leaves the hold intact;
- cancellation leaves the hold intact;
- cardinality/projection failure returns proposed outputs and leaves the live
  ledger and hold unchanged;
- capacity refusal leaves the hold intact; and
- encoding failure before any write returns the unsent values.

A normal teardown cannot silently discard a hold. Make the hold-aware teardown
fallible or add a distinct fallible teardown operation before changing the
existing method. It should attempt a `Teardown` flush and return all connection
parts plus held inputs on refusal/failure. Provide a visibly destructive abort
only if callers genuinely need to discard retained messages.

## Implementation sequence

Follow tracer bullets; keep each slice green before widening the next seam.

### 1. Red ownership tests

Add facade-level in-memory tests demonstrating the current failure and desired
state transitions. Completion criterion: tests fail because 0.8.0 lacks `Hold`,
not because fixtures bypass the builder interface.

Cover:

- three held rows released one-to-one before `CommandComplete`;
- no downstream bytes and no live-ledger advancement while held;
- each replacement projected once;
- stable row order; and
- `Expand` retains its immediate one-to-many behaviour in a separate regression.

### 2. Private hold module

Implement a private payload owner with pending, held, flushing, and poisoned
states. Add message/byte accounting and cancellation-safe restoration. Completion
criterion: unit tests account for every source across each state transition and
the public interface is unchanged.

### 3. Atomic pipeline preparation

Add private backend-sequence dry-run and commit operations. Completion criterion:
an illegal element at every batch index leaves the authoritative ledger unchanged,
while a legal sequence commits the same final state as sequential one-message
projection.

### 4. Middleware and builder seam

Add `Hold`, the borrowed batch hook, opaque held view, limits, forwarding outcomes,
and explicit flush. Completion criterion: identity, ordinary forward, suppress,
and immediate expand regressions remain green; a batching adapter can be written
using only root-facade types.

### 5. Driver, barriers, and pressure

Integrate automatic barrier/capacity flush into `forward_backend` and
`forward_next`. Completion criterion: the transport-poll tracer proves no extra
backend read at capacity, and asynchronous/COPY/extended-error cases preserve
wire order.

### 6. Recovery and teardown

Make all pre-write failures ownership-preserving and define fallible teardown.
Completion criterion: cancellation at every await point and injected failures at
every preparation/write boundary account for every input and unsent output.

### 7. CipherStash-shaped acceptance test

Build a facade-only adapter whose connection state contains derived batch data
but no authoritative raw-message queue. Buffer encrypted rows, perform one async
batch transformation, release equal-cardinality decrypted rows, and forward the
terminator. Completion criterion: the peer observes exact order and cardinality,
projection counters are one, and teardown has an empty hold.

### 8. Documentation and compatibility

Update README/rustdoc/MIGRATION and the public-surface manifest. Document
`Forward`, immediate `Expand`, committed `Suppress`, and deferred `Hold` as four
distinct concepts. Completion criterion: every public snippet compiles and audits,
doctests, examples, compile-fail tests, MSRV, Clippy, rustdoc, and the workspace
suite pass.

## Test matrix

At minimum, cover:

- simple-query `DataRow` batches of zero, one, limit, and limit-plus-one rows;
- extended query with `PortalSuspended` and `CommandComplete`;
- `ErrorResponse` followed by extended error drain and `ReadyForQuery`;
- asynchronous `NoticeResponse`, `NotificationResponse`, and `ParameterStatus`;
- COPY IN, OUT, and BOTH transitions;
- pipelined operations, proving a later response cannot overtake a held span;
- middleware error, cancellation, invalid cardinality, illegal replacement,
  encoding failure, write failure, and teardown refusal;
- count and byte limits independently, including one oversized row policy;
- role middleware order: client role once per source, boundary batch policy once,
  server role once per replacement; and
- property tests for ownership conservation, stable order, and failed atomic
  preparation leaving the live ledger unchanged.

Use deterministic in-memory transports for primary coverage. PostgreSQL container
compatibility is supplementary.

## Guardrails and traps

- Keep `Expand` immediate and one-source-to-many-output. It is orthogonal to this
  feature.
- Keep `Suppress` committed. A suppressed source cannot later be replayed.
- Keep authoritative raw messages out of caller-defined connection state.
- Keep `Pipeline` payload-free; the private hold owns payloads.
- Keep held inputs borrowed across async batch policy so cancellation cannot drop
  them.
- Keep destination-role middleware on replacements at release time, exactly once.
- Preserve source-role middleware timing before a source enters the hold.
- Make capacity affect transport polling, not merely vector insertion.
- Validate the entire replacement span before changing the live ledger or writing.
- Treat partial writes as terminal; recovery means accounting, not replay.
- Avoid a public projection token or operation-ledger escape hatch.
- Avoid empty `Expand` as an implicit retention signal.
- Avoid expanding the first slice into a general streaming response scheduler.

## Verification commands

Use the repository's current CI-equivalent commands rather than relying only on
focused tests. At handoff time the expected checks include:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo test --workspace
cargo test --workspace --doc
cargo check --workspace --examples
cargo bench --workspace --no-run
git diff --check
```

Also run the deterministic public-surface and documentation audits already present
in the repository, plus Rust 1.88 all-target checking. If sandbox restrictions
block loopback tests, rerun those tests outside the sandbox and report that fact.

## Definition of done

The feature is complete when a facade-only CipherStash-shaped adapter can retain
and asynchronously transform ordered DataRows in batches without `Suppress` or
`Expand`, every source and replacement is accounted for exactly once, capacity
stops upstream reads, cancellation and pre-write failures preserve ownership,
teardown cannot silently discard held inputs, all existing forwarding modes retain
their semantics, and the full repository verification matrix passes.
