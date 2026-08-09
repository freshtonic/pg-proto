# Migration guide

This guide is for proxy implementations moving to `pg-proto`'s builder-only
root facade. Implementation modules and the low-level `Conn` typestates are no
longer public; applications configure and operate `Client`, `Server`, or
`Intermediary` values instead.

The three supported construction entry points are `Client::builder()`,
`Server::builder()`, and `Intermediary::builder()`. There is no low-level public
escape hatch: if an application requirement is not expressible through these
builders and their root-level message vocabulary, it should be raised as a
facade capability rather than implemented by importing an internal module.

Security posture is never inferred. Production migrations should pair
`SslMode::VerifyFull` with an application `ClientTlsProvider`, require server TLS
with an application `ServerIdentityProvider`, and provide application-owned
authentication policies on each side. Selecting disabled TLS, trust
authentication, a non-verifying client SSL mode, or an unbounded protocol frame
limit is an explicit downgrade and should receive application security review.

## Adopt reusable server construction

Use `Server::builder()` to configure the client-facing role once and call
`accept()` for each application-established transport. TLS and authentication
must both be selected explicitly; intentional plaintext trust deployments use
the named `ServerTlsPolicy::Disabled` and `TrustServerAuthentication` choices.
The returned branch distinguishes an operational session from an out-of-band
cancellation request, and `teardown()` recovers the transport, caller-owned
connection state, handler, and connection context.

## Adopt reusable client construction

Use `Client::builder()` to configure the upstream-facing role once. Select
`ClientTlsPolicy::Disabled` only for deliberate plaintext deployments, or use
`ClientTlsPolicy::libpq` with an `SslMode` and application-owned
`ClientTlsProvider`; the provider is resolved for every connection attempt so
certificate and key rotation do not require rebuilding the component.

Implement `ClientAuthentication` as a factory for mutable per-connection
`ClientAuthenticationSession` values. Sessions answer server challenges
asynchronously and produce typed identity evidence only after the server sends
`AuthenticationOk`. Routing metadata is available to the factory without
replacing or rebuilding the configured client component.

## Attach role middleware through builders

Call `.middleware(factory)` repeatedly on either role builder. Each factory is
synchronous and infallible and creates one isolated handler from the initial
connection context. Stages run in declaration order. The same handler receives
owned pre-startup, startup, authentication, cancellation, generated response,
and operational messages with immutable progressively enriched context and
mutable caller-owned state. Narrow handlers may override only the message
families they use; the default handler remains identity middleware. Teardown
returns the handler and state for explicit recovery.

## Replace direct protocol access

Replace imports from `codec`, `transport`, `grammar`, `session`, `auth`, and
other implementation modules with the root facade vocabulary. Message values
used by middleware and forwarding are available at the crate root. Establish
connections only through `Client::connect`, `Server::accept`, or
`Intermediary::accept`. Recover client parts with `ClientConnection::into_parts`
and server/intermediary parts with their `teardown` methods.

## Replace proxy message queues with a bounded pipeline ledger

Supply `BoundedPipeline::new(limit)?` through `Intermediary::builder()`. The
operational intermediary applies admission, ordering, and backpressure while
`forward_next`, `forward_frontend`, and `forward_backend` drive traffic.

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

Server-role construction now goes through `Server::builder()`. Select one of
`ServerTlsPolicy::Disabled`, `Optional(provider)`, or `Required(provider)` and
provide a `ServerAuthenticationProvider`; omission is a build error. TLS
identity providers are resolved for every accepted TLS connection, so an
application-owned reloadable provider can rotate certificates without rebuilding
the server component.

Replace manual server authentication typestate driving with a fresh
`ServerAuthentication` conversation per connection. Its asynchronous `start`
and `respond` methods return `ServerAuthenticationAction` values. pg-proto
orchestrates Trust, cleartext, MD5, recursive SASL/SCRAM, Kerberos, GSSAPI,
recursive GSS continuation, and SSPI wire transitions; application policy owns
credential lookup, verification, continuation state, rejection, and the typed
identity evidence returned by `Accept` or `SaslFinal`. Responses are delivered
as owned `ServerAuthenticationResponse` values, while immutable startup, TLS,
and peer facts remain available through `ServerAuthenticationRequest`.

`Server::accept` returns either an operational `ServerAccept::Session` or the
distinct cancellation branch. TLS-provider and authentication-policy failures
retain their concrete error types in `AcceptError`, and successful connection
context exposes immutable negotiated-TLS and typed-identity facts.

## Intermediary composition

Use the root `Intermediary::builder()` facade, supplying complete `Server` and
`Client` components, a `StartupRouteResolver`, an explicit cancellation policy,
and optional authenticated routing and boundary-middleware factories. The
operational connection owns one caller state and provides `forward_next()` for
duplex asynchronous, extended, COPY, and replication traffic.

Configure forwarding with `IntermediaryBuilder::cancellation_registry`. The
application-owned handle allocates client keys and stores `CancellationRoute`
values containing the original `ConnectTarget` metadata and upstream key.
Cancellation resolves this mapping directly, without startup routing. Call
`IntermediaryConnection::detach_cancellation` when releasing a live session.
Establishment failures close silently by default; `SafeDiagnostic` emits one
fixed, non-disclosing error through outbound server middleware before closing.

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
