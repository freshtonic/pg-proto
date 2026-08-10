# Backend batching prototype report

## Question

Which design best supports CipherStash's ordered, one-to-one transformation of a
batch of `DataRow` messages without projecting a source twice or losing ownership
while asynchronous transformation is pending?

The throwaway [backend batching state-machine lab](backend-batching-prototype.html)
models the three options from the comparison report. It exposes every received
message's current owner, pending and in-flight batches, emitted order, input and
output projection counts, connection closure, and an event log.

## Scenarios exercised

Each option was driven through the same state transitions:

1. receive three `DataRow` messages without projection;
2. receive `CommandComplete`, atomically transform and flush the ordered batch;
3. reach a three-row capacity limit and refuse another transport read;
4. cancel while a flush owns the batch and restore every uncommitted message;
5. tear down with a non-empty batch; and
6. attempt to claim retention without actually storing the received row.

The model deliberately uses a one-to-one transformation:

```text
DataRow(1), DataRow(2), DataRow(3), CommandComplete
    ↓ async batch transformation
DataRow'(1), DataRow'(2), DataRow'(3), CommandComplete
```

`Expand` is not needed for this operation. The relevant capability is delayed,
atomic replacement of an ordered input span.

## Prototype results

### Crate-owned hold

The happy path is direct: every row moves from transport ownership into the
connection hold without projection. At the barrier, the whole span moves into an
in-flight transaction, is validated, and is committed once. Cancellation restores
the same values to the hold. Capacity is visible to the connection before it
polls the transport again.

The prototype could not express “reported retained but lost the value”: the
decision transfers the owned message into a crate-controlled collection. This is
the strongest result of the experiment. The public `Hold` spelling is less
important than the ownership transfer it represents.

The cost predicted by the paper design remains. Teardown becomes fallible or must
return the hold explicitly, and pg-proto must implement limits, atomic projection,
cancellation guards, and barrier handling.

### Caller-defined connection-state buffering

The correct implementation follows the same successful state graph. Middleware
moves each row into the caller-defined connection state, returns a non-projecting
decision, then drains that state at the barrier. It naturally supports
application-specific row representations and teardown already recovers the state.

The contract-violation scenario exposed its weakness. Middleware can report that
an input was retained without inserting it into state. From pg-proto's side the
decision is indistinguishable from a correct retention, yet the ownership
invariant fails immediately. The reverse error—storing a row while returning
`Suppress`—would recreate the double-projection problem when the stored row is
later emitted.

The prototype also confirmed that bounding a `VecDeque` is not enough. The driver
needs a mandatory pressure/drain interface before it can know not to poll another
backend frame. At that point the supposedly small design has gained a second
coordination protocol whose invariants remain split across crate and caller.

### Ordered response collector

The collector also makes the invalid ownership transition unrepresentable and
provides the cleanest driver: received messages enter a private transaction and
the driver drains legal output in order. Cancellation, backpressure, and retry are
local to one module.

For CipherStash's case, however, its extra scheduling machinery produced no
additional useful state transition. There is one upstream response stream, one
downstream response stream, and an order-preserving one-to-one transformation.
Local response producers, fairness between producers, and operation scheduling
would increase implementation and teardown complexity without solving a further
requirement demonstrated by the tracer.

## Comparative findings

| Finding | Crate-owned hold | Connection state | Response collector |
| --- | --- | --- | --- |
| Ordered 1:1 batch | Natural | Natural when correctly implemented | Natural |
| Lost-retention state representable | No | Yes | No |
| Double projection preventable locally | Yes | Depends on caller contract | Yes |
| Driver can enforce pressure | Yes | Only through another mandatory interface | Yes |
| Specialised application storage | Requires an adapter or derived state | Native | Requires an adapter/producer |
| Added machinery for this use case | Moderate | Low initially, moderate when made safe | High |
| Interface depth | High | Low: correctness spans the seam | High, but broader than required |

## Final recommendation

Implement the **crate-owned hold**, narrowed to ordered one-to-one batch
replacement rather than general fan-out.

The prototype changes the emphasis of the earlier paper recommendation. The
important primitive is not `Hold` plus `Expand`; it is an owned, uncommitted input
span with one atomic release:

```rust
enum BackendMiddlewareOutput {
    Forward(BackendMessage),
    Suppress(BackendMessage),
    Hold(BackendMessage),
}

enum BackendBatchOutput {
    ReplaceOneToOne(Vec<BackendMessage>),
    KeepHolding,
}
```

The exact names need refinement, and `ReplaceOneToOne` should ideally carry a
crate-issued opaque batch token or consume `HeldBackendMessages` so the output
cardinality can be checked against the authoritative input span. A release must:

1. consume the held span as a single owned value;
2. require the same number of ordered replacement messages for CipherStash's
   initial use case;
3. dry-run the complete span against separate lightweight input and output
   projections;
4. commit only when every replacement is legal;
5. restore the original span if the async policy future is cancelled before
   commit; and
6. stop upstream reads at explicit message and byte limits.

Keep application-derived batch data—cryptographic workspaces, decrypted values,
tenant facts, and spill handles—in caller-defined connection state. Keep the
authoritative uncommitted `BackendMessage` values in pg-proto. This hybrid assigns
each owner the facts it can enforce.

Do not use empty `Expand` as retention, and do not require `Expand` for the
CipherStash migration. General one-to-many replacement can remain an independent
capability with immediate semantics. The ordered response collector should be
revisited only if local streaming responses or multiple competing response
producers become concrete requirements.

## Implementation tracer bullets

Before widening the production interface, implement these four tests against a
minimal private hold module:

- three `DataRow` inputs become three replacements followed by the unchanged
  terminator, with each input and output projection counted once;
- cancellation at every await point returns all held messages in original order;
- reaching either hold limit prevents another backend transport poll; and
- cardinality mismatch or an illegal replacement leaves the live projection and
  authoritative hold unchanged.

These tests answer the ownership and state questions without committing to the
final public naming.
