# Burn-in and protocol-conformance verification

## Objective

Build a runnable verification system that drives an independent Rust SQL adapter
through pg-proto's complete public intermediary topology into populated, real
PostgreSQL databases:

```text
tokio-postgres workload driver
  -> Intermediary Server role
  -> intermediary policy
  -> Intermediary Client role
  -> Testcontainers PostgreSQL
```

It must detect protocol and data-corruption defects, exercise every catalogued
message association and transition, expose retained resources, and measure
steady-state performance without conflating these different claims.

## Verification modes

One dedicated `pg-proto-burn-in` workspace binary provides these public commands:

- `conformance`: finite scenarios with deterministic coverage and correctness
  assertions;
- `soak`: canonical cycles followed by recorded, seeded weighted schedules for a
  duration or iteration budget;
- `replay`: the exact recorded scenario prefix and parameters from a prior run;
- `catalogue`: audit collected evidence against the authoritative transition
  catalogue;
- `performance`: capture or evaluate controlled performance evidence;
- `faults`: run isolated PostgreSQL fault-injection and recovery scenarios;
- `make-report`: link the artifacts from conventional run directories into one
  `REPORT.md`.

A thin ignored integration test invokes the short profile. Initial duration tiers
are:

| Profile | Scope |
| --- | --- |
| `smoke` | At most five minutes against PostgreSQL 18 |
| `conformance` | Finite PostgreSQL 14–18 matrix, targeting at most 30 minutes |
| `scheduled-soak` | 60 minutes on a stable runner |
| `overnight` | Eight hours |
| `diagnostic` | Caller-selected scenarios, duration, iterations, and profiling |

Correctness and conformance gate immediately. Leak and performance metrics remain
report-only for several successful stable-runner runs, then individual thresholds
are promoted explicitly.

## Process model

A lightweight supervisor owns Testcontainers, child lifecycles, resource
sampling, scheduling, and artifacts. The workload driver and intermediary run as
separate child processes so their crashes and resource use remain attributable.
They exchange versioned newline-delimited JSON control records over local pipes or
Unix sockets; PostgreSQL traffic uses ordinary TCP connections only.

The primary leak phase keeps one intermediary alive. Separate phases exercise
graceful restart, abrupt termination, connection churn, and teardown. Quiescent
checkpoints stop admission, drain work, close designated connections, and sample
resources between scenario groups.

The harness crosses only public `Client`, `Server`, and `Intermediary` interfaces.
It may use grammar generation to construct the coverage catalogue, but it must not
inspect private typestate or ledger data. When a transition cannot be observed,
prefer a generally useful public typed middleware event or outcome; otherwise
record the observation as indirect.

## PostgreSQL lifecycle

Testcontainers launches pinned PostgreSQL images. The supervisor owns ordinary
containers across compatible phases and creates isolated disposable containers
for destructive or incompatible profiles:

- ordinary plaintext;
- TLS with SCRAM;
- authentication matrix;
- physical replication;
- low resource limits;
- fault injection.

Readiness requires an authenticated query, the expected major version and server
configuration, completed idempotent migrations, a matching fixture checksum, and
all required roles, databases, and extensions. Destructive phases recreate and
reseed their container. Ordinary phases use isolated transaction/schema
namespaces, explicit cleanup, and periodic fixture checksum verification.

Finite conformance runs on PostgreSQL 14 through 18. PostgreSQL 18 is the primary
soak version. Version-dependent expectations and coverage entries are explicit.

## Coverage authority

Generate a catalogue from all protocol grammar transitions and contextual
message associations. Supplement it with checked-in catalogues for:

- asynchronous messages and demultiplexing;
- pre-startup and encryption negotiation;
- authentication semantics;
- cancellation;
- physical replication;
- codec-only variants and malformed inputs.

Each entry has a stable explicit ID. Renaming, splitting, merging, or retiring an
ID requires an intentional migration record. An exemption records the exact ID,
reason, PostgreSQL/version scope, scripted coverage if any, review owner, and
expiry. Unknown missing entries always fail.

Each observation records independent stages:

1. driver emitted or accepted the operation;
2. server-role side decoded it;
3. intermediary middleware observed or rewrote it;
4. client-role side encoded it;
5. PostgreSQL accepted or emitted it;
6. the return path traversed the intermediary;
7. the driver validated the result.

Only all seven stages count as real PostgreSQL end-to-end coverage. Reports keep
three measures separate:

- real PostgreSQL end-to-end coverage;
- scripted-peer conformance coverage;
- total catalogue disposition, including reviewed exemptions.

For every reconstructable message association, require pass-through and identity
rewrite coverage. Add non-identity rewrites for structurally rich messages such as
`Parse`, `Bind`, row descriptions, data rows, diagnostic responses, and COPY
payloads.

## Scenario model

Scenarios are typed Rust implementations registered with declarative metadata:

- stable scenario ID and description;
- prerequisites and PostgreSQL versions;
- expected coverage IDs;
- expected result, SQLSTATE, and recovery state;
- resource/load class;
- deterministic replay parameters;
- supported parameter reduction.

Every soak begins with a canonical deterministic cycle, then uses seeded weighted
shuffles. It records the selected scenario sequence and all parameters. After
preserving an original failure bundle, replay may perform bounded prefix and
parameter reduction without overwriting the original evidence.

## Database fixtures and SQL corpus

Use checked-in, version-controlled schema and fixture SQL. Generate bulk rows
deterministically from a fixed seed. Maintain both:

- a compact protocol/type laboratory covering scalar, binary, array, JSON,
  nullable, wide-text, and encoding cases;
- a coherent commerce-style schema with realistic joins, indexes, skewed
  distributions, constraints, and transaction patterns.

Classify results by rows and bytes: zero, one, small, medium, and large counts;
narrow, mixed, wide, binary, and nullable widths; buffered and streaming
consumption. Stream large results into stable typed digests plus row, byte, and
null counts. Compare small results exactly.

Run applicable statements through both simple and extended query paths. Extended
scenarios cover named and unnamed statements and portals, `Parse`, `Bind`,
`Describe`, `Execute`, `Close`, `Flush`, `Sync`, binary formats, portal
suspension, pipelining, and error recovery.

Session scenarios cover clean cycles, intentionally dirty cycles, reset cycles,
transactions and failed transactions, GUC changes, prepared statements,
temporary objects, advisory locks, listeners, and teardown without reuse. Assert
protocol readiness separately from connection cleanliness. Include prepared-state
invalidation after dependent schema changes from another session.

## Expected failures

Assert SQLSTATE and recovery state rather than unstable diagnostic text. Cover:

- invalid SQL syntax;
- missing tables, columns, and functions;
- type mismatches and division by zero;
- constraint and permission failures;
- serialization failures and deadlocks;
- statement cancellation and timeout;
- failed-transaction recovery;
- COPY failure;
- prepared-statement invalidation;
- configured resource-limit errors.

Malformed lengths, truncated frames, unknown tags, malformed encodings, and
illegal sequencing belong to finite scripted conformance and fuzz/replay, not the
normal database soak. Assert bounded resource use, rejection, and teardown.

## Special protocol paths

Use deterministic triggers for asynchronous traffic: a second session performs
`NOTIFY`; PL/pgSQL emits notices at several severities; supported `SET` operations
produce parameter status; startup captures backend key data. These messages must
not advance causal operation state.

Cancellation runs concurrent long operations, cancels selected sessions through
the SQL adapter, expects SQLSTATE `57014` only for the intended operations, proves
other sessions survive, and verifies cancellation mappings disappear at teardown.

Use the SQL adapter for normal COPY IN/OUT and abort behaviour. Script exact
`CopyFail` values and exhaustive COPY-BOTH half-close orderings. A narrow harness
replication adapter drives physical replication COPY-BOTH: WAL receipt,
standby-status updates, both half-closes, cancellation, and teardown. Logical
replication is a later, separately labelled PostgreSQL integration scenario.

Script peer behaviour for legacy `FunctionCall`, GSS encryption negotiation,
KerberosV5, GSS/GSSContinue, SSPI, legacy encryption errors, malformed frames,
and driver-inaccessible branches. A real Kerberos/GSS environment is optional.

Slow-reader and slow-writer scenarios apply bounded asymmetric rates and assert
pipeline limits, backend-hold limits, socket backpressure, cancellation safety,
and recovery. Backend termination, deadlock induction, limit exhaustion,
interrupted COPY, and PostgreSQL restart run only in isolated fault-injection
profiles and do not contribute performance samples.

## Load model

Measure three attributable phases:

1. one long-lived sequential session for per-message retention;
2. repeated connection churn for teardown retention;
3. bounded concurrent mixed sessions for ordering and lifecycle defects.

Support closed-loop saturation stress and open-loop fixed-rate operation below
measured saturation. Calibrate capacity before measurement and separate warm-up.
Use monotonic time and HDR-style histograms per scenario class. Open-loop metrics
correct for coordinated omission and distinguish queue, execution, and end-to-end
latency while recording achieved rate.

## Resource and performance evidence

Linux is authoritative for resource and performance gates. Portable runs retain
correctness and conformance authority; macOS metrics are best-effort and not
baseline-compatible.

Sample intermediary and driver RSS/PSS, virtual memory, threads, file
descriptors, CPU time, context switches, and I/O. Diagnostic allocator builds add
live and total allocation metrics. Collect PostgreSQL container/process memory,
connections, database statistics, locks, temporary bytes, WAL volume, and
relevant `pg_stat_*` values. Record sampling gaps.

Provide two non-comparable builds:

- an optimized production-allocator performance build;
- a leak-diagnostic build using a measurable allocator or heap profiler.

The reproducible `burn-in` Cargo profile retains debug symbols and fixed codegen
settings. Every bundle records compiler version, target, features, lockfile hash,
allocator, binary hash, PostgreSQL image/configuration, and runner identity.

Initial gates are deliberately conservative:

- no unexpected correctness or protocol failure;
- no live connection, task, or file-descriptor growth after drain;
- fail allocator live-byte growth only when its slope is distinguishable from
  zero and exceeds an absolute retained-byte budget;
- no more than 10% steady-state throughput degradation;
- no more than 20% p95 or p99 latency degradation;
- report PostgreSQL backend growth until retained session effects are understood.

Compare windows within one run for drift and compare historical baselines keyed
by runner, PostgreSQL version, profile, and build configuration. Use robust
medians across repeated windows. Baseline promotion is always reviewed and keeps
prior versions; successful runs never replace it automatically.

## Tracing and artifacts

Normal soak operation counts every coverage ID and retains a bounded in-memory
ring of recent redacted message metadata. Full payload capture is opt-in for
replay or a diagnostic window because it perturbs allocation and may expose data.

The authoritative result is versioned JSON with a generated Markdown summary. A
failure bundle includes the seed, scenario prefix, configuration and commit,
coverage ledger, resource series, histograms, redacted recent trace, child and
PostgreSQL logs, and replay command. It must redact credentials, TLS secrets,
cancellation keys, and configured sensitive fields before persistence.

Retain ordinary summaries and time series for about 90 days, failure bundles for
an initial 30 days, and promoted baselines indefinitely.

Invariant violations, possible corruption, memory-safety signals, and protocol
desynchronisation stop new admission immediately, drain when safe, and preserve
artifacts. Isolated expected-error assertion failures may continue within a small
configured failure budget.

## CI and delivery

Keep the smoke profile in ordinary CI. Run finite multi-version conformance in
the PostgreSQL compatibility workflow or a reusable called workflow. Add a
dedicated scheduled and manually dispatched burn-in workflow. Performance gates
run only on labelled stable self-hosted runners.

Deliver vertical slices, each runnable with an honest partial coverage report:

1. harness binary, Testcontainers profile, supervision, and artifacts;
2. existing extended `SELECT` through the full topology;
3. generated stable coverage catalogue and middleware observations;
4. deterministic schema plus SQL/error/type/volume corpus;
5. simple/extended, transaction, asynchronous, COPY, and cancellation scenarios;
6. scripted-peer exceptional paths;
7. replication and isolated fault injection;
8. metrics, scheduled soaks, baselines, and promoted performance gates.

## Completion criteria

The project is complete when:

- every catalogue entry has real PostgreSQL coverage, scripted-peer coverage, or
  an unexpired reviewed exemption;
- finite PostgreSQL 14–18 conformance is green;
- smoke and scheduled soak profiles operate unattended;
- replay has reproduced a captured failure;
- leak diagnostics and stable-runner performance reporting work;
- every expected-error scenario proves recovery;
- reports distinguish real, scripted, indirect, and exempted evidence;
- no test-only bypass of the builder facade exists.
