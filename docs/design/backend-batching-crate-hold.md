# Crate-owned backend holds

## Status and intent

This is a design proposal, not an implementation commitment. It adds a crate-owned
holding module at the intermediary backend-forwarding seam. The module enables an
async, fallible middleware adapter to retain a bounded group of PostgreSQL backend
messages and later replace that group with zero, one, or many messages. It is aimed
at policies such as decrypting or filtering rows in batches.

The design deliberately keeps `Pipeline` payload-free. `Pipeline` remains the
protocol-obligation ledger; the new module owns deferred payloads. This preserves
the separation in ADR 0002 between wire receipt, policy, and session advancement.

## v0.8.0 baseline

This proposal targets tag `pg-proto-v0.8.0`. At that tag the forwarding-boundary
`IntermediaryMiddleware` is already async and fallible. Its backend result supports
`Forward`, non-empty ordered `Expand`, and `Suppress`. `process_backend` applies
client-role interception before this hook and server-role interception afterward.
It projects each forwarded/expanded output, projects a suppressed source without
writing it, then flushes queued local responses. `Pipeline` remains payload-free
and can return an owned `BackendAction::Deferred`. The missing capability is to
retain several source messages across calls before choosing the existing forward,
fan-out, or suppression outcome.

## Seam and interface

The seam belongs in the existing `IntermediaryMiddleware::backend` position: after
the PostgreSQL-facing role has decoded and intercepted a backend wire message and
before server-role middleware, projection, and encoding. A single per-connection
`BackendHold` module sits there. The existing middleware interface gains one result
variant and one optional hook; the connection gains one explicit flush entry point:

```rust
pub enum BackendMiddlewareOutput {
    Forward(BackendMessage),
    Expand(Vec<BackendMessage>),
    Suppress(BackendMessage),
    /// Defer this source in the connection-owned, bounded hold.
    Hold(BackendMessage),
}

pub trait IntermediaryMiddleware<State, ServerContext, ClientContext> {
    // Existing frontend(...) and backend(...) remain.
    async fn flush_backend(
        &mut self,
        server: &ServerContext,
        client: &ClientContext,
        state: &mut State,
        held: HeldBackendMessages,
        reason: BackendFlushReason,
    ) -> Result<BackendFlushOutput, Self::Error>;
}

impl<...> IntermediaryConnection<...> {
    pub async fn flush_backend_hold(
        &mut self,
    ) -> Result<BackendForwarding, ForwardError<...>>;
}
```

`forward_backend` keeps its v0.8.0 entry point and result type. On `Hold`, it moves
the returned source into the connection-owned queue and reports a new
`BackendForwarding::Held` outcome. `Forward`, `Expand`, and `Suppress` retain their
v0.8.0 one-source meanings. Before processing a barrier or admitting a message
that would exceed capacity, the driver first releases the held prefix through
`flush_backend`; it never silently combines a later one-source decision with that
prefix. `flush_backend_hold` performs the same operation explicitly without
reading upstream. The identity implementation returns the messages unchanged.
Thus the middleware interface has two backend hooks and the driver has two relevant
calls (`forward_backend`, `flush_backend_hold`).

`HeldBackendMessages` is an opaque, ordered, non-empty owned collection. Middleware
can iterate it and consume it with `into_messages`; only the crate constructs it.
`BackendFlushOutput` is `Release(Vec<BackendMessage>)` or `Hold(HeldBackendMessages)`.
An empty release suppresses the held span; unlike v0.8.0 `Expand`, it is legal here
because its source span is explicit.

The context exposes immutable role contexts plus a reason:

```rust
pub enum BackendFlushReason {
    Capacity,
    ProtocolBarrier,
    ExplicitFlush,
    Teardown,
}
```

The flush context also exposes `held_messages`, `held_bytes`, and configured limits.
It does not expose `Pipeline`, operation IDs, transports, or projection methods.
Middleware can therefore await storage or a batch cryptography engine and fail,
but cannot partially advance protocol state.

An empty flush release is suppression. A one-element release is the ordinary
interception case. Multiple elements are ordered fan-out. `Hold` is a
crate type and the held messages remain fields of `IntermediaryConnection`; the
adapter never has to put payloads in user-defined connection state.

The default `flush_backend` returns `Release(held.into_messages())`, so existing
middleware remains source-compatible unless it exhaustively matches
`BackendMiddlewareOutput`. A builder method enables non-zero hold limits:

```rust
intermediary
    .backend_batching(RowDecryptor::new(keys), BackendHoldLimits {
        max_messages: 256,
        max_bytes: 4 * 1024 * 1024,
    })
```

The exact spelling may change, but the interface facts and ownership must not.

## Protocol projection invariants

1. **Every received input is accounted for exactly once.** It is in exactly one
   of: the unread transport, the crate-owned hold, an in-flight middleware call,
   a committed release, or the terminal error payload. It is never both projected
   and held.
2. **A release is atomic with respect to projection.** The implementation first
   simulates the whole replacement sequence against a cloned/snapshot projection
   ledger. It commits the snapshot only if every output is reconstructable, legal,
   and attributable in order. No prefix is projected on failure.
3. **Input obligations are consumed exactly once.** The simulation carries both
   the original held input sequence and its replacement sequence. It verifies that
   the replacement is a legal projection of the same operation span. Suppression
   consumes the input span without writing; fan-out may contain extra non-advancing
   messages, but may not consume an operation outside that span.
4. **Every released output is projected exactly once before encoding.** There is
   no encode path which bypasses the committed projection. A write failure does
   not roll projection back; it is terminal because bytes may already have escaped.
5. **Order is stable.** Inputs retain wire order. Outputs retain adapter order.
   A later operation cannot be released before an earlier held operation. PostgreSQL
   asynchronous messages may be emitted early only when doing so does not cross a
   held relative-order requirement; the conservative initial implementation holds
   them with the batch.
6. **Each newly received message crosses `backend` once.** On `Hold`, its returned
   value is moved into the queue without cloning. Held values cross only
   `flush_backend`, when the crate transfers the whole queue. A cancelled flush
   restores that same owned queue with an internal guard.
7. **No frontend read may increase outstanding work while the backend hold is at
   capacity.** `forward_next` disables the downstream-read branch and forces a
   capacity release attempt.

The span check in invariant 3 is essential. Merely applying each replacement to
the current `Pipeline` would permit a middleware bug to suppress `ReadyForQuery`,
invent a second completion, or accidentally consume the next operation.

## Capacity and backpressure

Both a message count and estimated decoded payload-byte count are mandatory,
non-zero configuration. Before reading upstream, the driver reserves one maximum
frame slot using the connection's configured maximum frame length. Once a newly
decoded message reaches either limit, middleware is called with `Capacity` and
must return `Release`; `Hold` becomes `BackendHoldError::Capacity` carrying the
intact hold. The driver stops reading both upstream and frontend traffic after
that error. There is no unbounded retry loop.

Known protocol barriers also force a release rather than allowing a batch to cross
an observable command boundary. The initial conservative barrier catalogue is
`ErrorResponse`, `ReadyForQuery`, COPY mode changes/completions, and connection
termination. `CommandComplete` can be batched with preceding row data but ends the
batch. Catalogue decisions live next to backend grammar projection, not in each
adapter. Explicit `flush_backend_hold` handles latency timers owned by an
application driver.

Transport output buffering remains separate: a successful release projects the
entire output, pushes its frames in order, then flushes according to the existing
transport policy. The hold limit therefore controls decoded policy payloads, not
encoded transport bytes.

## Errors and teardown

```rust
pub enum BackendHoldError<E> {
    Io(io::Error),
    Middleware { error: E, held: HeldBackendMessages },
    Capacity { held: HeldBackendMessages },
    Projection { error: BackendProjectionError, held: HeldBackendMessages,
                 output: Vec<BackendMessage> },
}
```

All errors before projection return ownership of the intact input and, where
useful, proposed output. The connection becomes poisoned after middleware,
capacity, or projection failure: callers may inspect or tear it down, but may not
resume forwarding accidentally. This avoids specifying whether fallible middleware
is safe to replay.

Deliberate teardown performs one `Teardown` release attempt. A successful release
is written and flushed before transports are recovered. A failed or refused
release returns `IntermediaryTeardownError` containing the connection parts and
held messages; it must never silently drop a non-empty hold. An explicit
`abort_backend_hold(self)` escape hatch may recover parts while reporting the
dropped messages, but should be visibly destructive and separate from `teardown`.
`Drop` cannot await and therefore only closes transports; debug builds should
assert/log when a live hold is dropped.

After projection commit, any encoding or write failure is terminal and teardown
does not retry the release. This module owns that policy because only it knows
whether projection committed and whether a frame prefix may have been written.

## Hidden implementation

The implementation should be local to a new private `backend_hold` module plus a
small field and delegation in `IntermediaryConnection`:

```rust
struct BackendHold {
    input: VecDeque<HeldBackend>,
    bytes: usize,
    generation: u64,
    status: HoldStatus,
}

struct HeldBackend {
    message: BackendMessage,
    // Private attribution captured without advancing the live ledger.
    span: ResponseSpan,
}
```

`Pipeline` gains private prepare/simulate/commit support, not a public payload
queue. A projection transaction clones only its lightweight operation ledger,
projects the original sequence to determine its operation span, projects proposed
outputs within that span, and swaps the ledger on success. If cloning the ledger
is undesirable, an undo-free prepared transition log provides the same atomicity.

Barrier classification, byte accounting, poisoning, release transactions, and
teardown bookkeeping stay hidden. This gives the module depth: two middleware hooks
and two driver calls hide ownership, ordering, capacity, exact-once projection,
transport sequencing, and recovery. The seam gives callers leverage and keeps
protocol failure fixes local.

## Dependencies and adapters

- `backend_hold` depends on decoded `BackendMessage`, private pipeline projection,
  the configured maximum frame length, and the intermediary's existing transport.
- `Pipeline` does not depend on middleware or transport and remains payload-free.
- The identity adapter preserves today's behavior.
- The existing role middleware ordering is preserved: client-role interception
  occurs before holding; server-role interception occurs on each released output.
- A test adapter releases scripted batches and failures. It crosses the same seam
  as production adapters; no test-only projection bypass is added.

The batching seam is real only when identity, legacy single-message, and batching
adapters exist. Internal seams (span simulation and barrier catalogue) remain
private because applications do not vary them safely.

## Example

```rust
async fn backend(
    &mut self,
    _server: &ServerCx,
    _client: &ClientCx,
    _state: &mut State,
    message: BackendMessage,
) -> Result<BackendMiddlewareOutput, Error> {
    Ok(match message {
        message @ BackendMessage::DataRow(_) => BackendMiddlewareOutput::Hold(message),
        barrier => BackendMiddlewareOutput::Forward(barrier),
    })
}

async fn flush_backend(
    &mut self,
    _server: &ServerCx,
    _client: &ClientCx,
    state: &mut State,
    input: HeldBackendMessages,
    _reason: BackendFlushReason,
) -> Result<BackendFlushOutput, Error> {
    let mut output = Vec::new();
    for message in input.into_messages() {
        match message {
            BackendMessage::DataRow(row) if !state.row_visible(&row).await? => {}
            BackendMessage::DataRow(row) => {
                output.extend(state.decrypt_and_split(row).await?);
            }
            other => output.push(other),
        }
    }
    Ok(BackendFlushOutput::Release(output))
}
```

This shows suppression and ordered fan-out without storing messages in `State`.
The actual legality of suppressing or splitting a particular message is determined
by the atomic span validator, not trusted to the adapter.

## Tests

Tests should exercise the interface rather than reach through it:

- identity parity with current one-message forwarding;
- hold across several `DataRow` messages, then release at `CommandComplete`;
- ordered fan-out and suppression within one operation span;
- rejection of output that consumes too few or too many operation transitions;
- no live-ledger mutation when element 2 of a proposed output fails projection;
- exactly one projection per input span and per emitted output, using a recording
  projection adapter or observable ledger state;
- asynchronous messages conservatively preserve wire order while a hold exists;
- count, byte, and maximum-frame capacity behavior, including frontend read gating;
- async middleware suspension while neither payload ownership nor state is exposed
  to another forwarding call (the connection's `&mut self` enforces this);
- middleware error returns the intact ordered hold and poisons forwarding;
- cancellation of `forward_backend` before and during middleware does not
  lose the decoded input; use an internal guard to restore in-flight input on drop;
- write failure after projection is terminal and never replays output;
- teardown flush success, teardown refusal/error recovery, and explicit abort;
- COPY, extended-error drain, pipelined operations, and protocol barrier catalogue;
- property tests comparing atomic simulation with sequential projection for all
  legal sequences and proving failed proposals leave the live ledger unchanged.

## Migration

1. Introduce the private hold module and projection transaction tests without
   changing the identity forwarding path.
2. Add `Held` to `BackendForwarding`/`ForwardedMessage` and route existing
   `forward_backend` through the hold module while proving identity parity.
3. Preserve and test the v0.8.0 client-role/boundary/server-role ordering.
4. Add builder configuration and limits, then integrate hold-aware `forward_next`.
5. Replace `ForwardError::Deferred(BackendMessage)` with internal crate-owned
   queuing. During a deprecation window, map impossible legacy deferred cases to a
   terminal compatibility error rather than returning payload ownership.
6. Make teardown fallible only for configurations that can hold, or introduce a
   new fallible teardown first and deprecate the infallible method once downstream
   callers can migrate.

## Advantages

- Strong locality: payload lifetime, projection atomicity, capacity, and teardown
  ownership are implemented once rather than reconstructed by every caller.
- A deep module: a two-hook middleware interface provides batching, suppression,
  fan-out, async work, ordering, and backpressure.
- User state remains domain state rather than a protocol recovery queue.
- The crate can enforce exact-once projection and reject invalid replacement spans.
- `Pipeline` retains its useful payload-free design and bounded operation ledger.
- Cancellation and errors can return or recover one authoritative owned batch.

## Costs and risks

- The crate takes on substantial implementation complexity: atomic span validation,
  cancellation guards, memory accounting, poisoning, and fallible teardown.
- `BackendMessage` payload size is only an estimate unless every variant exposes
  exact retained allocation size; limits must document that characteristic.
- The two-hook interface requires batching adapters to split per-message admission
  from whole-batch transformation.
- Conservative asynchronous-message ordering and barriers can add latency.
- Fan-out/suppression legality is subtle and couples private hold code to generated
  backend grammar semantics.
- Existing `forward_backend -> BackendForwarding` needs a `Held` outcome, while
  infallible teardown cannot represent a refused flush, so migration adds surface.
- Applications with specialized scheduling may find crate-owned policy less
  flexible than retaining messages in their own connection state.

The deletion test favors this module: deleting it would redistribute payload
ownership, exact-once projection, ordering, capacity, cancellation, and teardown
logic into every batching caller. That is enough leverage to justify the seam,
provided the external interface remains limited to two hooks and two driver calls.
