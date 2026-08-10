# Backend batching design comparison

## Decision being made

`pg-proto` 0.8.0 can immediately replace one PostgreSQL backend message with
many messages, but it cannot defer a `DataRow` across middleware calls without
advancing protocol state. This report compares two ways to add deferred batching:

1. [crate-owned backend holds](backend-batching-crate-hold.md), where the
   intermediary retains source messages; and
2. [caller-defined connection-state buffering](backend-batching-connection-state.md),
   where middleware moves source messages into the application's connection state.

Both designs preserve ADR 0002's separation of wire receipt, policy, and session
advancement. Both also require an atomic batch-projection operation inside the
crate. Applying today's one-message `Pipeline::accept_backend` repeatedly is not
sufficient: a failure part-way through a batch would otherwise leave the live
ledger partially advanced.

## Comparison

| Concern | Crate-owned hold | Caller-defined connection state |
| --- | --- | --- |
| Public meaning | Explicit `Hold` and later release | Empty `Expand` means retained; later non-empty `Expand` flushes |
| Payload owner while deferred | `IntermediaryConnection` | Caller-defined connection state |
| Exact-once ownership | Enforceable by the crate | A contract custom middleware can violate |
| Projection legality | Atomic held-span validation | Atomic expansion validation |
| Memory bounds | Uniform count/byte limits | Application-defined; enforceable only through a participating adapter |
| Backpressure | Connection can stop reads whenever its hold is full | Connection needs a pressure/drain interface into middleware state |
| Error recovery | Requires hold-aware errors and fallible teardown | Existing state recovery helps, but prepared output still needs recovery |
| Application storage policy | Limited to policies exposed by the crate | Fully flexible, including arenas or spill-to-disk |
| Interface clarity | A deferred input is named directly | Empty `Expand` carries a surprising second meaning |
| Crate implementation | Larger: queue, limits, cancellation guards, teardown | Smaller payload layer, but pressure and atomic projection remain substantial |
| Caller implementation | Small and consistent | Each custom adapter owns correct storage, accounting, and draining |
| Locality | Ownership bugs are fixed once in pg-proto | Storage bugs can be distributed across callers |

## Crate-owned hold

### Strengths

The crate-owned design has the strongest invariant: once middleware returns
`Hold(message)`, exactly one authoritative owner is known. The intermediary can
stop transport reads at capacity, restore an in-flight batch when a future is
cancelled, and ensure teardown cannot silently discard deferred messages. These
behaviours form a deep module: a small middleware interface hides protocol-span
validation, payload ownership, ordering, memory pressure, and recovery.

The named decision is also difficult to misunderstand. `Suppress` means consume
without output, `Hold` means do not consume yet, and `Expand` means replace the
current source immediately. Those meanings remain distinct in logs, errors, and
tests.

### Weaknesses

This design makes pg-proto a payload buffer. It must define byte accounting,
capacity behaviour, protocol barriers, cancellation safety, and what teardown
does with an unflushed batch. It also needs a second middleware hook for batch
release, which makes the interface broader than the current one-message decision.

Applications with specialised encrypted storage, secure-memory requirements, or
disk spooling may have to copy messages out of the crate-owned hold or wait for
more storage adapters to be added.

## Caller-defined connection-state buffering

### Strengths

This design uses an ownership facility the intermediary already provides: one
caller-defined connection state is passed to middleware and recovered on
teardown. CipherStash can store encrypted blocks, decrypted rows, accounting
metadata, or spill handles in the representation that matches its policy. The
pipeline stays payload-free and pg-proto does not become a general-purpose queue.

The initial interface change is small. Empty `Expand` can represent “no output or
projection yet”, while a later expansion drains the state buffer and appends the
current barrier. A supplied bounded `StateRowBatcher` adapter could make the safe
case convenient without requiring every state type to implement a crate trait.

### Weaknesses

The interface cannot prove its most important ownership claim. Arbitrary
middleware can return empty `Expand` without first retaining the message, losing
it silently. Conversely, it can retain a message and accidentally return
`Suppress`, producing the original double-advancement bug on a later flush.

Empty `Expand` is also semantically overloaded: in 0.8.0 it is an error, while in
this design it becomes deferred ownership. A named `Retained` outcome would be
clearer, but it would effectively reintroduce `Hold` without giving the crate
ownership of the held value.

Backpressure is less local. Because pg-proto cannot inspect arbitrary connection
state, middleware must expose pressure and draining through an additional
interface. Custom middleware that bypasses that adapter can allocate without the
connection knowing when to stop reading.

## A third option: an ordered response collector

A more ambitious design would make `IntermediaryConnection` an ordered response
collector. Middleware would declare whether a frontend operation is forwarded or
served by a local response stream, while the connection privately schedules local
and PostgreSQL responses in operation order.

This offers the simplest common calling pattern and the greatest locality: the
crate owns buffering, fairness, ordering, retry, projection, and backpressure. It
also naturally supports lazy local results. However, it is substantially broader
than the reported DataRow requirement, complicates COPY and teardown, and moves
pg-proto from a protocol substrate toward an opinionated runtime. It is better
treated as a possible high-level module built over the lower-level receipt and
projection seam, not as the immediate fix.

## Recommendation

Prefer the **crate-owned hold** design for the public forwarding interface.

The decisive reason is not storage convenience; it is enforceability. Protocol
advancement and payload ownership are one correctness problem here. If pg-proto
owns advancement while arbitrary caller state owns the only evidence that an
input remains pending, neither side can enforce exact-once handling independently.
That produces a shallow seam whose correctness depends on undocumented
coordination.

The caller-state design remains useful as an implementation technique for
application-specific decrypted data, but it should sit behind middleware's batch
release policy rather than carry the authoritative received `BackendMessage`
ownership. Middleware may derive and retain application data in connection state;
pg-proto should retain the uncommitted protocol inputs until the release succeeds.

Before implementation, prototype the crate-owned design against four tracer
cases:

1. hold several `DataRow` messages and release them at `CommandComplete`;
2. suppress one held row and expand another while projecting the whole span once;
3. cancel an async batch release and prove every input remains owned; and
4. hit count and byte limits and prove the upstream transport is not polled again.

If the required atomic span validator proves disproportionately complex, the
fallback should be the caller-state adapter with an explicit named `Retained`
decision—not an undocumented empty-vector convention—and with pressure/drain
participation mandatory for middleware that can retain messages.
