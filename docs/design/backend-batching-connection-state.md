# Backend batching in caller-defined connection state

## Summary

Use the existing caller-defined connection `State` as the payload store. Extend the semantics of the v0.8.0 `BackendMiddlewareOutput::Expand` interface so an empty expansion means “middleware retained this input; emit and project nothing yet.” A batching middleware moves `DataRow` values into `State`, returns `Expand(Vec::new())`, and later returns one non-empty `Expand` containing the buffered rows followed by the message that triggered the flush.

This deliberately avoids a crate-owned `Hold` variant and keeps `Pipeline` payload-free. The crate continues to own protocol legality, projection, and downstream order; the caller owns storage shape, capacity policy, and buffered values.

## Target and constraints

This proposal is based on `pg-proto-v0.8.0`, where:

- `IntermediaryMiddleware::backend` is already async and fallible;
- `BackendMiddlewareOutput` already supports `Forward`, `Expand`, and `Suppress`;
- `process_backend` applies destination-role middleware, projects, and sends every expansion element in order;
- `Suppress(message)` projects the supplied message without sending it;
- `Pipeline` retains only lightweight operation obligations;
- `teardown()` returns the sole caller-defined connection state.

The new design must preserve async/fallible policy, zero-or-many output, ordered fan-out, intentional suppression, bounded memory/backpressure, exact-once projection, and recoverability on error or teardown.

## Interface

Keep the existing public enum and change only the documented meaning of an empty expansion:

```rust
pub enum BackendMiddlewareOutput {
    /// Emit and project this message once.
    Forward(BackendMessage),

    /// Emit and project these messages once, in order.
    ///
    /// An empty vector means the input was retained in caller-defined
    /// connection state. Nothing is emitted or projected by this call.
    Expand(Vec<BackendMessage>),

    /// Project this message once without emitting it.
    Suppress(BackendMessage),
}
```

The distinction is important:

- `Suppress` consumes a protocol event now. It is appropriate for a genuine filter or policy replacement whose source must not later be replayed.
- empty `Expand` postpones both emission and projection. It is appropriate only after middleware has moved the input into recoverable caller state.
- non-empty `Expand` is an ordered fan-out. A batch flush returns all retained messages, then the triggering message, so each is projected exactly once.

No public operation ID, projection token, or ledger handle crosses the seam. That keeps the pipeline a deep module: callers learn one output interface while the implementation hides phase selection, legality, ordering, and projection.

### Batch capacity interface

Capacity must be explicit rather than inferred from an arbitrary `State` type:

```rust
#[derive(Clone, Copy, Debug)]
pub struct BatchLimits {
    pub messages: NonZeroUsize,
    pub bytes: NonZeroUsize,
}

pub enum OversizeRow {
    PassThrough,
    Reject,
}

pub struct StateRowBatcher<Access, Policy> {
    access: Access,
    policy: Policy,
    limits: BatchLimits,
    oversize: OversizeRow,
}
```

`StateRowBatcher` is an optional middleware adapter. Accessor closures select fields in the caller's state; the state type need not implement a crate trait.

```rust
#[derive(Default)]
struct ConnectionState {
    rows: VecDeque<BackendMessage>,
    row_bytes: usize,
    tenant: TenantId,
}

let batcher = StateRowBatcher::new(
    |state: &mut ConnectionState| (&mut state.rows, &mut state.row_bytes),
    BatchLimits {
        messages: NonZeroUsize::new(256).unwrap(),
        bytes: NonZeroUsize::new(1 << 20).unwrap(),
    },
    FlushOn::RowsOrResponseEnd,
    OversizeRow::PassThrough,
);
```

Applications needing encrypted blocks, an arena, or spill-to-disk storage can implement `IntermediaryMiddleware` directly. The stock adapter should not force a general store trait until there are two real adapters.

## Behaviour

For a `DataRow`, the adapter computes reconstructable encoded length before moving it.

- If it fits, move it into the state buffer and return empty `Expand`.
- If it would exceed a non-empty buffer, first drain the existing rows and return them followed by this row as a non-empty `Expand`.
- If it exceeds an empty buffer, either emit it alone (`PassThrough`) or return `BatchError::Oversize` containing the unchanged row (`Reject`).
- When row count or byte threshold is reached exactly, drain immediately.
- On `CommandComplete`, `PortalSuspended`, `EmptyQueryResponse`, `ErrorResponse`, `ReadyForQuery`, a COPY transition, or an asynchronous message, drain rows and append the triggering message.
- On explicit connection teardown, rows remain in `State` and are returned to the caller.

Appending the trigger is mandatory. It prevents a response terminator or asynchronous message from overtaking earlier rows.

## Invariants

1. **Single payload owner.** A decoded message is owned by the receive call, middleware, caller state, the current output vector, transport buffering, or an error value. Batching does not clone a message to simulate retention.
2. **Exact-once projection.** Empty `Expand` performs no projection. Each element of a later non-empty expansion is projected once, immediately before send. `Suppress` projects once and its message may not later be emitted.
3. **Source order.** Outputs caused by input `n` are completely emitted before input `n + 1` is received. A drained batch preserves insertion order and places its trigger last.
4. **Atomic expansion validation.** The complete non-empty expansion is dry-run against a clone of the lightweight ledger before the authoritative ledger changes or any message is sent. If any element is illegal, no element is committed.
5. **Recoverable retention.** Middleware may return empty `Expand` only after the source is reachable through caller state. The stock adapter enforces this structurally by returning empty only after successful insertion.
6. **Bounded retention.** The stock adapter has non-zero message and byte limits. It never inserts beyond either limit.
7. **Backpressure.** While state holds a full batch or a prepared output remains unsent, the driver does not poll another upstream backend frame.
8. **No terminal retention.** The stock adapter never returns empty expansion for a state-advancing or response-terminal message.
9. **Non-lossy failure.** On insertion failure the input is returned in the error; on validation failure the entire expansion is returned; on send failure the unsent values and caller state remain recoverable.

The public empty-expansion contract cannot prove that arbitrary custom middleware retained its input. This is the design's central tradeoff. Documentation should mark loss on a dishonest implementation as a middleware contract violation, just as returning a semantically invalid replacement already is.

## Hidden implementation

Replace the v0.8.0 `EmptyExpansion` error branch in `process_backend` with a retained outcome:

```rust
match decision {
    BackendMiddlewareOutput::Expand(messages) if messages.is_empty() => {
        BackendForwarding::Retained
    }
    BackendMiddlewareOutput::Expand(messages) => {
        let prepared = self.pipeline.prepare_backend_sequence(&messages)?;
        self.send_prepared_backend(prepared, messages).await?
    }
    // Forward and Suppress retain their v0.8.0 meanings.
}
```

`BackendForwarding` and `ForwardedMessage` gain payload-free observability cases:

```rust
pub enum BackendForwarding {
    Forwarded(BackendMessage),
    Expanded { source: BackendMessage, messages: Vec<BackendMessage> },
    Suppressed(BackendMessage),
    Retained,
}
```

The implementation must also remove the unconditional `source = message.clone()` performed before middleware in v0.8.0. For `Expand`, the observable source cannot be returned without cloning or obtaining it from middleware. Prefer changing the expanded outcome to contain only emitted messages; callers that require source audit data can retain it in their state. This makes the single-owner invariant real.

`Pipeline::prepare_backend_sequence` operates on a temporary copy of operation metadata. It validates reconstructability, phase legality, operation attribution, and terminal transitions for every output. Only a fully valid sequence is committed. This is an internal seam; it should not become public merely for tests.

The send implementation moves messages one at a time into the downstream buffered transport. It retains the not-yet-pushed suffix in the connection until synchronous encoding succeeds. Async flush follows the transport's cancellation-safe push/flush contract.

## Backpressure and driver integration

Merely bounding the state buffer is insufficient if the driver continues receiving. The batch adapter reports pressure through a small optional interface implemented by the middleware handler:

```rust
pub trait BackendPressure<State> {
    fn backend_pressure(&self, state: &State) -> Pressure;
    fn drain_backend(&mut self, state: &mut State)
        -> Result<Vec<BackendMessage>, Self::Error>;
}
```

This seam is justified by two adapters: identity/no-pressure and `StateRowBatcher`. The duplex driver checks pressure after every backend decision. At the hard limit it drains before polling upstream again. It may continue frontend progress only where the existing operation ledger permits it.

`drain_backend` enables an explicit `flush_backend_batch()` connection method and shutdown draining without manufacturing a backend input. It is synchronous because it only moves caller-owned values; policies needing async spill retrieval implement async middleware and arrange readiness before reporting pressure.

Count and encoded-byte limits are independent of `BoundedPipeline`: the former bound retained payload, while the latter bounds incomplete protocol obligations.

## Error and teardown recovery

- `BatchError::Insert { message, source }` returns the uninserted message; previously buffered rows remain in `State`.
- `BatchError::Oversize(message)` returns the unchanged row.
- Expansion validation returns the complete ordered vector and leaves the authoritative ledger unchanged.
- Encoding failure before a message is pushed returns that message plus the remaining suffix.
- After a partial socket write, replay is not protocol-safe. Close the connection, but return the unsent suffix and state for audit or cleanup.
- Cancellation before middleware completes leaves ownership in its future or in state. Cancellation after preparation leaves the prepared suffix owned by the connection.
- `teardown()` already returns `State`; therefore retained rows naturally survive deliberate teardown. A `teardown_with_pending()` convenience should additionally return any prepared, unpushed expansion suffix.

Recoverability does not imply resumability after arbitrary I/O failure: PostgreSQL framing may already be partially visible to the client.

## Dependencies and adapters

- `Pipeline` depends on generated grammar and lightweight operation records, not batching storage.
- `IntermediaryConnection` coordinates middleware, pipeline, and transports but does not choose storage.
- `StateRowBatcher` adapts fields of caller state to the existing `IntermediaryMiddleware` seam.
- Existing identity and one-to-one middleware retain their current `Forward` behaviour.
- Existing suppression middleware retains its current project-without-send behaviour.
- An identity `BackendPressure` adapter reports empty pressure and drains nothing.

The deletion test supports this seam placement: deleting `Pipeline` would spread ordering, phase legality, and exact-once projection across every caller; deleting `StateRowBatcher` would remove only an optional storage policy. The former is a deep module earning locality and leverage, while the latter is correctly an adapter.

## Tests

Tests should cross the public connection/middleware interface rather than inspect private prepared state.

1. Retain three rows, flush on `CommandComplete`, and observe exactly `row1, row2, row3, command`.
2. Assert empty expansion neither emits nor projects; the later batch projects every retained row exactly once.
3. Verify ordinary `Suppress` advances once and cannot be replayed by the stock adapter.
4. Pipeline two operations and prove later responses cannot overtake the earlier retained batch.
5. Interleave notices and notifications; verify the adapter flushes earlier rows before them.
6. Cover `PortalSuspended`, errors, `ReadyForQuery`, COPY IN/OUT/BOTH, and extended-query error drain.
7. Make the final expansion element illegal; verify atomic rejection, unchanged ledger, and recovery of all messages.
8. Fail state insertion and verify the input is in the error while earlier rows remain in state.
9. Hit count and byte limits independently; verify the upstream reader is not polled while full.
10. Cover oversize pass-through and reject modes.
11. Inject failures before encoding, after encoding, during partial write, and during flush; account for every payload owner.
12. Cancel at each await point, then teardown and account for retained and pending messages.
13. Property-test legal backend streams: stable order, capacity never exceeded, every emitted/suppressed event projected exactly once, and payload ownership conserved.
14. Verify compatibility: identity middleware still produces `Forwarded`, non-empty expansion still produces ordered fan-out, and suppression behaviour is unchanged.

## Migration

1. Document empty `Expand` as retained-without-projection and add `BackendForwarding::Retained`.
2. Remove `ForwardError::EmptyExpansion` and the unconditional source clone.
3. Add atomic sequence preparation inside `Pipeline`; treat one-message forwarding as a degenerate sequence.
4. Add pending-suffix recovery around downstream encoding and flush.
5. Add optional pressure/drain support and the stock `StateRowBatcher` adapter.
6. Applications add buffer fields to their connection state and configure explicit count/byte limits.
7. Existing middleware requires no behavioural migration unless it returned empty expansion expecting an error.

## Advantages

- No crate-owned `Hold` payload or backend queue.
- Caller chooses storage layout, accounting, encryption, and spill strategy.
- Buffered rows are naturally recovered through existing state-returning teardown.
- Reuses the v0.8.0 async/fallible, zero-or-many middleware interface.
- Exact-once projection and ordering remain concentrated in a deep crate module.
- No payload clone is required when the expanded outcome stops echoing its source.
- Existing forward, expansion, and suppression adapters remain compatible.

## Disadvantages and risks

- Empty `Expand` is less explicit than a named `Hold` decision and is easier to misuse.
- The crate cannot prove arbitrary custom middleware actually retained an input; only the stock adapter provides that structural guarantee.
- Caller state becomes coupled to batching policy and must be memory-budgeted.
- Atomic sequence validation adds a pass over the batch and a clone of lightweight ledger metadata.
- Pressure is enforceable only for middleware participating in the optional pressure interface; arbitrary state allocation remains invisible.
- Changing expanded observability to omit `source` is a breaking interface change, though it removes the v0.8.0 payload clone.
- Spill stores that require async draining do not fit the simple stock adapter and need a custom handler.
- Recovery after partial I/O is for cleanup, not safe replay.

## Recommendation

Adopt this approach when state ownership flexibility and teardown recovery outweigh the clarity of an explicit `Hold` variant. Keep buffering as an optional adapter at the middleware seam, keep protocol projection and ordered sending inside the deep pipeline/connection module, and ship the bounded in-state adapter so the safest implementation is also the easiest one.
