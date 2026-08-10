# PostgreSQL session-typed protocol implementation plan

Current integration: issue #38 makes the root builder facade the crate's only
public API, migrates all external consumers, and retains low-level protocol
coverage as crate-internal tests.

Issue #39 puts that facade front and centre in the README and crate Rustdoc,
adds complete compile-checked workflows for all three roles, and names the
documentation, example, and public-surface release gates in CI.

This plan tracks the route from the current protocol library to a production
implementation suitable for `cipherstash/proxy`. A checked item is implemented
and covered by proportionate tests; it does not imply that all later integration
work using that feature is complete.

## 1. Wire codec and transport foundations

- [x] Direction-parameterised frontend and backend tagged codecs.
- [x] Reconstructable typed messages, including `Parse`, `Bind`, `Describe`,
  `Execute`, `RowDescription`, format codes, values, and OIDs.
- [x] Configurable tagged-frame and pre-startup packet limits checked before
  allocation.
- [x] Cancellation-safe buffered output using synchronous push and asynchronous
  flush.
- [x] Raw pre-startup framing for SSL, GSSENC, cancellation, and startup packets.
- [x] Client and server TLS negotiation with transport-type replacement.
- [x] `sslmode` policy and `tls-server-end-point` channel binding.
- [x] Erased plain/client-TLS/server-TLS network streams plus configurable TCP
  socket options and connection retry for production proxy integration.
- [x] Buffered GSSENC request/reply sequencing, including historical `E` replies.
- [x] Expose a production GSSAPI encrypted-transport integration boundary.
  The audited Proxy and pgcat revisions do not implement GSSENC, so selecting a
  platform credential stack is intentionally deferred to a downstream adapter.

## 2. Authentication and startup

- [x] Independent client and server authentication projections.
- [x] Cleartext and MD5 authentication, client and server roles.
- [x] SCRAM-SHA-256 and SCRAM-SHA-256-PLUS, including recursive continuation.
- [x] Protocol projections for KerberosV5, GSS, GSSContinue, SSPI, SASL,
  SASLContinue, and SASLFinal.
- [x] `NegotiateProtocolVersion` handling for protocol 3.1/3.2 options.
- [x] Startup `ParameterStatus`, `BackendKeyData`, and `ReadyForQuery` handling.
- [x] Verify Kerberos/GSSAPI and SSPI engine parity requirements and expose a
  recursive token-engine boundary. Neither audited implementation supplies
  these engines; platform credential acquisition remains an adapter concern.

## 3. Typed query and nested protocol sessions

- [x] Client and server simple-query sessions.
- [x] Full extended-query construction, pipelining, Sync, and error draining.
- [x] Function-call protocol projection pending the proxy usage audit.
- [x] COPY IN, COPY OUT, and COPY BOTH nested sessions for both roles.
- [x] Physical replication message projection within COPY BOTH.
- [x] Transaction status and parameter-change cleanliness evidence.
- [x] Pool reset through `ROLLBACK; DISCARD ALL` with verified idle readiness.
- [x] Positionally tagged notices and ordered asynchronous-message sinks.
- [x] Connection-branded prepared statements and portals with name rewriting.
- [x] Exact typestate erasure and checked re-entry at storage boundaries.
- [x] Extend the connection-branded resource wrapper over the complete extended
  cycle, including repeated Parse/Bind, Close, Sync, response consumption, and
  resource invalidation at protocol boundaries.

## 4. Generated protocol grammar

- [x] Grammar macro emits typestate witnesses and dual witnesses.
- [x] Grammar macro emits transport-carrying phase/cleanliness typestates.
- [x] Explicit cleanliness effects and transport replacement.
- [x] Runtime FSM with per-transition internal/external direction.
- [x] Railroad SVG with sequence, choice, recursion, and cleanliness effects.
- [x] Embed each generated role's railroad SVG on its rustdoc module page.
- [x] Keep embedded rustdoc diagrams styled and legible by preventing Markdown
  from corrupting their CSS and preserving their intrinsic dimensions.
- [x] Polish embedded diagrams with unclipped geometry, enum-variant payload
  syntax, linked rustdoc types, and unambiguous directional glyphs.
  - [x] Conservatively size transition terminals for rustdoc fonts and restrict
    each hyperlink to the payload type inside the variant parentheses.
- [x] Client/server pre-startup, authentication, query, reset, error, COPY, and
  replication grammar coverage.
- [x] Attach typed message payloads and fallible transition results to generated
  methods so generated APIs can replace the handwritten phase implementations.
- [x] Generate or share projection logic between the typed API and runtime FSM,
  eliminating manually duplicated message-to-event matching.
  - [x] Emit one canonical runtime transition table used for both target-state
    and direction lookup, and expose it for differential sequence generation.
  - [x] Add state-aware wire-message projection hooks so nested and mixed
    sessions cannot be projected through a context-free event map.
  - [x] Extend the grammar DSL with direction-specific message types and
    state-scoped transition patterns, emitting checked message-to-event
    projectors.
  - [x] Apply generated projectors to the PostgreSQL grammars and handwritten
    compatibility sessions.
    - [x] Generate state-aware client-message projection for backend Ready,
      extended-query/error-drain, COPY IN, and COPY BOTH states.
    - [x] Generate backend-message projection for query responses, typed
      descriptions, errors, readiness, function calls, and nested COPY states.
    - [x] Replace server-role handwritten request classification with generated
      projection while retaining compatibility payload enums.
      - [x] Route server-role Ready and extended-query request dispatch through
        generated state-aware projection.
      - [x] Route extended error-drain and simple/extended COPY IN dispatch
        through generated projection.
      - [x] Route COPY BOTH open and backend-half-closed dispatch through
        generated projection.
    - [x] Generate upstream/client-role wire projection for simple and extended
      queries, draining, reset, function call, and all COPY directions.
    - [x] Route handwritten upstream simple-query, function-call, draining,
      reset, and COPY response classification through generated projection.
    - [x] Generate dual raw pre-startup packet/single-byte reply projection for
      upstream and server roles.
    - [x] Generate asymmetric authentication and startup-completion projection,
      including recursive SASL/token exchanges and shared password tags.
    - [x] Correct `NegotiateProtocolVersion` to an authentication-phase self-loop
      for both roles.
    - [x] Route client-side authentication mechanism, recursive token/SASL, and
      completion classification through generated projection.
    - [x] Route server-side password, SASL-initial/continuation, and token
      response classification through generated projection.
- [x] Add exhaustive/property-generated valid and invalid sequence testing and
  differential checks between generated and handwritten implementations.
  - [x] Exhaustively enumerate generated runtime valid/invalid sequences through
    depth six from the canonical transition artefact.
  - [x] Exercise codec-message projection across pre-startup, authentication,
    extended query, error recovery, and COPY, with handwritten compatibility
    sessions consuming the same generated classifiers.
  - [x] Exhaust every event at every reachable state through bounded recursive
    paths for all six generated PostgreSQL role grammars, including unchanged
    state on rejection.
- [x] Remove superseded handwritten state-decision logic after parity is proven.
  Transport/resource compatibility adapters remain intentionally, but their
  message projection and transition decisions delegate to the generated grammar.

## 5. Proxy-enabling API and compatibility

`pg-proto` is a protocol library for implementing the next Proxy; it does not
absorb Proxy's application logic. CipherStash-specific EQL rewriting, credential
management, routing, pool orchestration, and deployment remain downstream. The
work here is to expose sufficiently general primitives and prove them with
neutral composition harnesses and examples.

- [x] Audit current `cipherstash/proxy` and pgcat protocol use solely to identify
  required wire coverage, interception points, and library invariants; record
  every discovered obligation without importing application policy.
- [x] Define a neutral client ↔ intermediary ↔ upstream composition API that
  retains independent typed sessions on both sides.
- [x] Prove independent downstream and upstream TLS/authentication mechanisms and
  credentials can be composed without coupling their state or policy.
- [x] Expose typed interception/replacement hooks sufficient for arbitrary
  downstream SQL and result rewriting, demonstrated by a non-CipherStash example.
- [x] Expose prepared-statement and portal namespace primitives that a downstream
  router or rewriter can own, without implementing routing policy.
- [x] Expose cancellation-key minting, observation, and mapping hooks without
  embedding a production registry or cancellation policy.
- [x] Expose ordered forwarding hooks for notices, notifications, parameter
  statuses, and command attribution without prescribing their destination.
- [x] Expose cleanliness evidence and policy hooks for transactions, GUC changes,
  LISTEN/NOTIFY, advisory locks, portals, and prepared statements; pool policy
  remains downstream.
- [x] Add a neutral end-to-end intermediary harness covering asymmetric auth/TLS,
  message rewriting, cancellation, COPY, replication, and connection reuse.
- [x] Document the application boundary and provide a proxy-construction example
  showing where downstream policy plugs in.

## 6. Verification and release gates

- [x] Unit tests over constructed and recorded-style byte streams.
- [x] Compile-fail tests for key illegal transitions and resource misuse.
- [x] Testcontainers tests against the official PostgreSQL 18 image.
- [x] Add recorded traffic fixtures for every supported authentication and query
  family, with sensitive fields removed.
- [x] Run compatibility tests across every PostgreSQL major version supported by
  the next CipherStash Proxy. The complete ten-test live suite passed locally on
  official 14, 15, 16, 17, and 18 Alpine images on 4 August 2026; CI preserves
  that required matrix.
- [x] Add fuzzing for both directional codecs, pre-startup decoding, SCRAM, and
  runtime FSM projection.
- [x] Establish performance and monomorphisation budgets against pgcat/proxy
  workloads.
- [x] Complete security review of TLS verification, channel binding, credential
  handling, frame limits, cancellation, and malformed-message behaviour.
- [x] Prepare publishable API documentation, migration guidance, and a proxy integration
  example.

## Current work

- [x] Establish reusable plaintext trust-authenticated client-role sessions
  through an explicit-security builder, with structured startup overrides,
  conservative limits, caller-owned connection state, and complete teardown.
- [x] Extend the client-role builder with libpq-compatible TLS negotiation,
  reloadable per-connection TLS material, and asynchronous application-defined
  authentication which returns typed identity evidence.
- [x] Add a reusable server-role builder which requires explicit plaintext and
  trust policies, owns startup orchestration, and returns operational or
  cancellation branches while preserving caller-owned connection parts.
- [x] Extend the server-role builder with disabled, optional, and required TLS,
  per-connection reloadable identities, protocol-orchestrated application
  authentication, and typed authenticated connection context.
- [x] Make builder middleware operational across client and server connection
  establishment, authentication, cancellation, generated responses, and live
  protocol traffic with fresh handlers, progressive context, and caller state.
- [x] Compose the complete server and client roles into a routed intermediary
  with pre-authentication startup resolution, optional authenticated routing,
  one shared state value, ordered boundary middleware, legal forwarding,
  explicit cancellation posture, and bounded backpressure.
- [x] Record and explicitly detach application-owned cancellation mappings,
  resolve later cancellation without startup routing, forward one-shot raw
  packets, and provide conservative non-disclosing establishment failures.
- [x] Reject counted message collections whose minimum encoding cannot fit in
  the remaining frame body, preventing fuzz-discovered allocation amplification.

- [x] Add GitHub Actions CI covering formatting, Clippy, Rustdoc, all tests
  (including container-backed tests), benchmarks, and every fuzz target.
- [x] Configure release-plz with crates.io trusted publishing through GitHub OIDC,
  grouped workspace versions, release PRs, changelog updates, and GitHub releases.
- [x] Add CI, docs.rs, and crates.io status badges to the README.
- [x] Cut over to a builder-only root facade, make implementation modules and
  connection typestates crate-private, and freeze the reviewed public surface.
- [x] Lead README/crate documentation with complete client, server, and
  intermediary builder workflows, explicit security guardrails, migration
  guidance, and deterministic documentation/release audits.

- [x] Allow railroad-diagram Rustdoc pages to exceed Rustdoc's standard
  `width-limiter` cap without changing the width of ordinary documentation pages.

- [x] Add comprehensive Rustdoc for every public module, type, trait, function,
  method, constant, field, variant, implementation API, and generated macro item.
  - [x] Document every public item emitted by the protocol grammar macro.
  - [x] Document codec, pre-startup, startup, transport, cancellation, SCRAM,
    authentication, server authentication, and integration foundation APIs.
  - [x] Document cleanliness, demux, resources, replication, and both client- and
    server-role session APIs.
  - [x] Document every handwritten public API and enforce `missing_docs`.

- [x] Provide a technical README covering the crate's purpose, typestate value,
  use cases, usage, rustdoc entry points, examples, supported PostgreSQL versions,
  and known limitations.

- [x] Provide runnable logging proxy examples and a populated customer-orders
  container demonstration.
  - [x] Forward typed frontend/backend messages while logging inbound SQL and
    result row counts.
  - [x] Provide a second binary which logs all decoded protocol messages.
  - [x] Exercise the SQL logger against a populated PostgreSQL test container
    containing a customer-orders schema and representative data.
  - [x] Document automated container and interactive workflows for both examples.
  - [x] Start and retain the populated test container automatically when no
    explicit upstream is supplied, and preflight explicit upstreams.
  - [x] Terminate client TLS in the proxy through pg-proto's typed pre-startup
    transport upgrade so policies observe decrypted messages.

- [x] Extend connection-branded outbound construction across repeated Parse/Bind,
  both Describe and Close targets, Execute, Flush, and Sync.
- [x] Retain connection-branded namespaces through extended-query response and
  error-drain consumption, invalidating unnamed portals at idle transaction
  boundaries.
- [x] Cover the complete asynchronous branded cycle against live PostgreSQL 18.
- [x] Add explicit unnamed-resource boundary regression tests to the branded
  connection API.
  - [x] Idle transaction completion invalidates the unnamed portal only.
  - [x] A simple-query boundary invalidates the unnamed statement only.
- [x] Attach typed message payloads and fallible results to generated grammar
  transitions, beginning with frontend extended-query construction.
  - [x] Add typed payload syntax and state-preserving fallible handlers to the
    proc macro and railroad output.
  - [x] Apply payloads to frontend Parse, Bind, Describe, Execute, and Close
    transitions, including state-preserving reconstruction failure.
  - [x] Apply payloads to frontend simple query, COPY data/failure, and
    function-call transitions.
  - [x] Apply asymmetric payloads to client- and server-facing password, token,
    and recursive SASL authentication transitions.
  - [x] Apply structured request, response, error, transaction-status, and COPY
    payloads across the backend-role query grammar.
  - [x] Apply payloads to pre-startup cancellation/startup and server startup
    metadata, protocol negotiation, cancellation keys, and readiness status.
  - [x] Type remaining data-bearing continuations; retain asynchronous notices,
    parameter statuses, and notifications below the session grammar as the
    deliberately filtered byte-stream projection.
- [x] Apply generated codec-message-to-event projection throughout the protocol.
- [x] Extend differential testing from canonical runtime events to codec-message
  projections and handwritten sessions.

## Stateful message middleware

- [x] Expose asynchronous, fallible intermediary-boundary middleware through
  the builder facade.
  - [x] Support owned forward, suppress, and locally respond decisions.
  - [x] Support backend fan-out without allowing expanded responses to bypass
    pipeline legality or wire ordering.
  - [x] Preserve application errors in the public forwarding error layer.
  - [x] Admit local operations and emit generated responses through the
    connection-owned pipeline without allowing response reordering.
  - [x] Report forwarding outcomes through the duplex and directional drivers.

- [x] Move the examples' protocol observation and rewriting mechanism into a
  policy-neutral core `middleware` module.
  - [x] Define direction-specific middleware for owned `FrontendMessage` and
    `BackendMessage` values. Returning the input value is the no-op; middleware
    may mutate it or replace it with another message of the same direction.
  - [x] Pass caller-owned mutable state through every invocation, with accessors
    to borrow or recover that state for statistics and other accumulated policy.
  - [x] Provide closure adapters and an identity middleware so simple observers
    do not require bespoke wrapper types.
  - [x] Compose middleware in deterministic order, feeding each stage's output
    into the next stage and stopping at the first error.
- [x] Integrate middleware at state-aware protocol boundaries after decoding and
  before projection, demultiplexing, or typestate advancement.
  - [x] Validate every replacement with the generated state-aware message
    projection for the current authentication, query, COPY, replication, or
    error-recovery state.
  - [x] Return rejected replacements without advancing either protocol session;
    preserve the original APIs as no-middleware compatibility paths.
  - [x] Apply backend middleware before `Demux` so asynchronous messages are
    interceptable and rewritten parameter, cancellation, and transaction state
    is recorded consistently.
  - [x] Cover untagged pre-startup packets with a separate typed hook; keep raw
    TLS/GSS decision bytes outside message middleware unless they gain a typed
    protocol representation.
- [x] Refactor the proxy examples onto the core abstraction.
  - [x] Express protocol logging, SQL extraction, and row statistics as separate
    composable middleware while retaining connection-local user state.
  - [x] Update the rewriting example and crate documentation to demonstrate
    no-op, mutation, replacement, state accumulation, and chaining.
  - [x] Retain `Intermediary::inspect` only as a low-level escape hatch, clearly
    distinguishing it from checked state-aware middleware.
- [x] Verify the abstraction at unit, state-machine, and network boundaries.
  - [x] Test no-op identity, mutation, replacement, state access, ordering,
    composition, and error short-circuiting.
  - [x] Reject messages illegal in authentication, extended-query recovery,
    COPY, replication, and pre-startup states.
  - [x] Confirm rewritten messages reach the peer and backend rewrites update
    demultiplexer bookkeeping without changing wire order.

The intended lifecycle is `decode -> middleware chain -> state validation ->
projection/demux -> encode/forward`. Generic `Buffered::receive_wire` remains a
codec boundary because it knows direction but not the current protocol state;
checked middleware belongs on the state-aware session APIs above it.

## Optional future work

### Compile-time-checked message middleware

- [x] Generate a state-specific owned message enum for every role and protocol
  phase, containing only the frontend, backend, pre-startup, authentication,
  COPY, replication, error-recovery, and asynchronous messages legal there.
- [x] Add a `TypedMiddleware<Role, Phase, UserState>` abstraction whose input and
  output are the generated `Phase::Message` type. An illegal replacement should
  be unrepresentable rather than rejected using a `RuntimeState` value.
  - [x] Infer `Role` and `Phase` from the existing `Conn` typestate so callers
    cannot supply a mismatched runtime state.
  - [x] Retain caller-owned mutable state across async interception, async closure
    adapters, identity middleware, deterministic awaited chaining, and typed
    short-circuit errors.
  - [x] Represent asynchronous backend traffic in each applicable phase without
    advancing the connection state or disturbing wire order.
- [x] Generate projection result enums whose variants carry the correctly typed
  next `Conn`, because replacing one legal message variant with another may
  select a different transition and therefore a different next phase.
- [x] Keep wire-shape validation at runtime for constraints such as embedded NUL
  bytes and frame-size overflow, unless message fields later adopt prevalidated
  refinement types. Document this separately from compile-time protocol legality.
- [x] Provide default pass-through adapters so policies can specialize only the
  phases or message families they inspect without manually implementing every
  generated state.
- [x] Add compile-fail coverage proving illegal replacements and role/state
  mismatches do not compile, plus runtime tests for reconstruction failures,
  composition, state threading, asynchronous traffic, and next-state selection.
- [x] Introduce the typed API alongside `intercept_checked`, migrate examples and
  transport/session entry points, then consider deprecating the runtime-state API
  only after the typed API covers every generated grammar phase.
  The phase-aware rewriting example uses the typed API. The transparent network
  loggers deliberately retain direction-wide middleware because they erase the
  current phase while concurrently forwarding both directions; `WireAdapter`
  is the migration path when such a policy is attached to a typed `Conn`.
  `intercept_checked` remains supported for these runtime-selected sessions.

- [x] Add optional operation-bounded intermediary pipeline orchestration with
  payload-free ordering records, local responses, COPY, and Sync error recovery.
- [x] Add async typed middleware dispatch to the runtime bounded pipeline so
  frontend phases and pending backend operation responses constrain replacements
  at compile time without duplicating the runtime ledger.
  - [x] Track the generated backend response subphase independently for every
    queued operation, including COPY and multi-message response sequences.
  - [x] Compose typed pipeline policies in deterministic order with shared state.
  - [x] Index locally generated middleware by the sending `Conn` typestate and
    include non-advancing asynchronous server messages.
  - [x] Split server SASL and token authentication into distinct policy and
    client-response typestates so replies cannot precede required input.
  - [x] Consolidate frontend and backend phase catalogues so hook declaration,
    chaining, wire adaptation, and runtime dispatch share one local source.
  - [x] Split frontend and backend pipeline middleware with independent errors,
    and prepare admission/response decisions before policy so the ledger commits
    each validated decision once.
  - [x] Make each generated grammar the authoritative source for inbound and
    outbound connection-typestate associations, exposed through one sealed
    direction-indexed trait without a manual middleware catalogue.
  - [x] Deepen the pipeline ledger interface by removing overlapping projection,
    action-remapping, and session-item entry points, leaving one frontend
    admission seam and one backend response seam.
  - [x] Consolidate inbound receipt, middleware interception, phase legality,
    and reconstruction validation across backend, frontend, pre-startup, and
    encryption-reply traffic without combining receipt with projection.
- [x] Use the repository README as the crate-level Rustdoc landing page.
- [x] License both published crates and the repository under the MIT License.
- [x] Add descriptive crates.io keywords and categories to both package manifests.
- [x] Add package author metadata to both published crates.
- [x] Declare and test the Rust 1.88 MSRV, pin the development toolchain, add
  package badges, tidy the README, and document the FSM crate separately.
- [x] Add contribution guidance, Proxy's Contributor Covenant, ownership and
  issue/PR templates, plus a private-reporting security policy and review archive.
- [x] Add Dependabot, cargo-deny, MSRV and package CI, pinned stable tooling,
  structured release notes, repository topics, private reporting, and main protection;
  verify nightly fuzzing and current advisory parsing in GitHub Actions.
- [x] Enforce Clippy's all, pedantic, nursery, and Cargo lint groups, retaining
  narrow exceptions only for unstable or dependency-graph noise.

These are deliberately not completion criteria for `pg-proto`'s current plan.
They depend on downstream requirements or pursue additional assurance beyond the
library boundary established above.

- [ ] Provide platform-specific GSSAPI/GSSENC, Kerberos, or SSPI adapters if a
  downstream Proxy deployment requires them. The library integration traits and
  typed protocol loops are complete.
- [ ] Implement CipherStash-specific routing, EQL transformation, credential
  management, and pool policy in the next Proxy, using `pg-proto` as a library.
- [ ] Pursue formal multiparty/proxy verification if its additional assurance
  justifies the research and maintenance cost.
