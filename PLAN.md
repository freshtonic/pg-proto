# PostgreSQL session-typed protocol implementation plan

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
- [x] Buffered GSSENC request/reply sequencing, including historical `E` replies.
- [ ] Integrate a production GSSAPI encrypted transport implementation.

## 2. Authentication and startup

- [x] Independent client and server authentication projections.
- [x] Cleartext and MD5 authentication, client and server roles.
- [x] SCRAM-SHA-256 and SCRAM-SHA-256-PLUS, including recursive continuation.
- [x] Protocol projections for KerberosV5, GSS, GSSContinue, SSPI, SASL,
  SASLContinue, and SASLFinal.
- [x] `NegotiateProtocolVersion` handling for protocol 3.1/3.2 options.
- [x] Startup `ParameterStatus`, `BackendKeyData`, and `ReadyForQuery` handling.
- [ ] Integrate production Kerberos/GSSAPI and SSPI authentication engines after
  verifying pgcat/CipherStash parity requirements.

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
- [x] Client/server pre-startup, authentication, query, reset, error, COPY, and
  replication grammar coverage.
- [x] Attach typed message payloads and fallible transition results to generated
  methods so generated APIs can replace the handwritten phase implementations.
- [ ] Generate or share projection logic between the typed API and runtime FSM,
  eliminating manually duplicated message-to-event matching.
  - [x] Emit one canonical runtime transition table used for both target-state
    and direction lookup, and expose it for differential sequence generation.
  - [x] Add state-aware wire-message projection hooks so nested and mixed
    sessions cannot be projected through a context-free event map.
  - [x] Extend the grammar DSL with direction-specific message types and
    state-scoped transition patterns, emitting checked message-to-event
    projectors.
  - [ ] Apply generated projectors to the PostgreSQL grammars and handwritten
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
    - [ ] Route server-side authentication response classification through
      generated projection.
- [ ] Add exhaustive/property-generated valid and invalid sequence testing and
  differential checks between generated and handwritten implementations.
  - [x] Exhaustively enumerate generated runtime valid/invalid sequences through
    depth six from the canonical transition artefact.
  - [ ] Generate codec-message sequences and compare generated and handwritten
    projections across the complete protocol grammar.
- [ ] Remove superseded handwritten state-machine code after parity is proven.

## 5. Proxy composition and production parity

- [ ] Audit current `cipherstash/proxy` and pgcat protocol use, including function
  calls, authentication mechanisms, extension messages, and pooling behaviour.
- [ ] Define the three-party client ↔ proxy ↔ upstream composition API.
- [ ] Support independent downstream and upstream authentication mechanisms and
  credentials in one proxy session.
- [ ] Connect typed interception/replacement to EQL statement and result rewriting.
- [ ] Integrate prepared-statement and portal name maps with proxy routing.
- [ ] Integrate client-issued and proxy-minted `BackendKeyData` with the
  client-to-upstream cancellation-key map.
- [ ] Forward asynchronous notices, notifications, and parameter statuses with
  correct ordering and command attribution.
- [ ] Enforce pool release and reset rules across transactions, GUC changes,
  LISTEN/NOTIFY, advisory locks, portals, and prepared statements.
- [ ] Add end-to-end proxy tests covering asymmetric authentication, TLS on either
  side, message rewriting, cancellation, COPY, replication, and pooled reuse.

## 6. Verification and release gates

- [x] Unit tests over constructed and recorded-style byte streams.
- [x] Compile-fail tests for key illegal transitions and resource misuse.
- [x] Testcontainers tests against the official PostgreSQL 18 image.
- [ ] Add recorded traffic fixtures for every supported authentication and query
  family, with sensitive fields removed.
- [ ] Run compatibility tests across every PostgreSQL major version supported by
  CipherStash.
- [ ] Add fuzzing for both directional codecs, pre-startup decoding, SCRAM, and
  runtime FSM projection.
- [ ] Establish performance and monomorphisation budgets against pgcat/proxy
  workloads.
- [ ] Complete security review of TLS verification, channel binding, credential
  handling, frame limits, cancellation, and malformed-message behaviour.
- [ ] Publish API documentation, migration guidance, and a proxy integration
  example.

## Current work

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
- [ ] Apply generated codec-message-to-event projection throughout the protocol.
- [ ] Extend differential testing from canonical runtime events to codec-message
  projections and handwritten sessions.
