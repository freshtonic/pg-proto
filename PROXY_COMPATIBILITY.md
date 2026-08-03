# Proxy compatibility requirements

This document records the protocol capabilities that `pg-proto` must expose so
that a future CipherStash Proxy can be built with it. It is not a plan to move
CipherStash-specific application behaviour into this crate.

## Audited sources

- `cipherstash/proxy` commit `15b7f996c8158bfad7054a626578d8fc9661bf2b`
- `postgresml/pgcat` commit `5b038813eb14f181434ab7b5509e74d9b1fe123b`
- Audit performed 4 August 2026.

The audit covered startup, TLS, authentication, cancellation, both query
protocols, COPY, result rewriting, prepared statements, asynchronous backend
messages, transaction state, and connection cleanup.

## Required library capabilities

| Capability | Why a downstream proxy needs it | Current status |
|---|---|---|
| Dual pre-startup roles | Terminate and originate SSL, startup, and cancellation on independent connections | Implemented, including GSSENC and typed transport replacement |
| Independent TLS and authentication | Current Proxy uses different client-facing and upstream authentication flows | Implemented for cleartext, MD5, SCRAM-SHA-256, and SCRAM-SHA-256-PLUS; protocol projections also cover GSS, SSPI, and Kerberos |
| Complete structured extended-query messages | Proxy rewrites SQL, parameter OIDs and values, format codes, result metadata, and names | Implemented for Parse, Bind, Describe, Execute, Close, ParameterDescription, RowDescription, and DataRow |
| Mutable, reconstructable interception | Rewriters must inspect, replace, reject, or forward a message without losing unknown values | Implemented through typed codec values and fallible generated transition handlers |
| Extended pipelining and error drain | Both audited implementations buffer arbitrary extended messages and discard through Sync after errors | Implemented in generated and compatibility typestates |
| Prepared-statement and portal namespaces | pgcat rewrites names and restores prepared statements on another pooled server | Implemented as connection-branded resources with client-to-upstream lookup |
| Simple query and function call | Simple SQL is inspected; deprecated function calls must remain forwardable if encountered | Implemented as typed sessions and reconstructable messages |
| COPY IN, OUT, and BOTH | pgcat forwards COPY data and prevents pool release while COPY is active | Implemented as nested sessions, including half-close tracking and replication projection |
| Transaction status evidence | pgcat releases transaction-pooled connections only after idle ReadyForQuery | Implemented and fed into cleanliness evidence |
| ParameterStatus and startup baseline | Session settings affect SQL interpretation and pool safety | Implemented in the demultiplexer with ordered forwarding data and baseline comparison |
| Notices and notifications | They can arrive independently and must remain ordered for forwarding | Implemented below typestate with positional notice tagging and ordered queues |
| Backend cancellation keys | A proxy must expose its own client key while retaining the current upstream key | Implemented through policy-neutral mint/registry traits and an optional in-memory map |
| Pool cleanliness evidence | pgcat tracks transactions, SET, PREPARE, COPY, and prepared cache state | Implemented as extensible evidence consumed by application-owned pool policy |
| Opaque forwarding escape hatch | Unknown or uninspected traffic must be forwardable without monomorphising every state | Exact state erasure, checked re-entry, and neutral two-sided composition are implemented |
| Output batching and backpressure | Current Proxy buffers rows and pgcat buffers extended/COPY messages | Cancellation-safe push/flush exists; the composition façade must permit downstream buffering without hiding command boundaries |

## Behaviour that remains downstream

The library must not implement EQL parsing or encryption, CipherStash
credentials, query routing, shard selection, pool scheduling, prepared-statement
cache eviction policy, row-decryption batching policy, or deployment/configuration.
It provides the typed messages, state evidence, resource tokens, and interception
points those policies consume.

## Audit observations

- Current Proxy terminates client authentication with MD5 while independently
  originating cleartext, MD5, or SCRAM upstream. The library must never couple
  the two authentication mechanisms.
- Current Proxy handles only SSLRequest in pre-startup; retaining GSSENC and
  protocol negotiation in `pg-proto` is necessary for broader PostgreSQL parity.
- Neither audited implementation supplies GSSENC encryption or a production
  Kerberos/GSSAPI/SSPI credential engine. `pg-proto` therefore owns the typed
  negotiation/token loops and exposes adapter traits, but does not select an OS
  credential provider on behalf of downstream applications.
- Current Proxy rewrites both Parse and Bind and rewrites ParameterDescription,
  RowDescription, and DataRow responses. Byte-only forwarding is therefore not a
  sufficient proxy API for these messages.
- pgcat buffers Parse, Bind, Describe, Execute, and Close until Sync, rewrites
  prepared names, synthesises completion messages, and may restore a prepared
  statement on a different server. Resource identity and response synthesis must
  remain possible without being built into routing policy.
- pgcat uses ReadyForQuery transaction status and COPY state before releasing a
  server. It marks SET and PREPARE command tags for cleanup, but this is explicitly
  best effort. `pg-proto` should expose extensible taint evidence rather than copy
  that fixed policy.
- Asynchronous ParameterStatus, NoticeResponse, and NotificationResponse appear
  in the audited message alphabets. Their filtered projection must retain an
  ordered forwarding path even though they do not advance typestate.

## Library work derived from the audit

All six requirements identified by the audit are implemented and exercised by
the neutral intermediary harness and runnable examples.
