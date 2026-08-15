# PostgreSQL Proxy Protocol

This context describes PostgreSQL traffic as it passes through a proxy while
preserving protocol legality, message ownership, and request/response ordering.

## Language

**Client role**:
The protocol participant that sends PostgreSQL frontend messages and receives
backend messages.
_Avoid_: Frontend-only, upstream side

**Server role**:
The protocol participant that receives PostgreSQL frontend messages and sends
backend messages.
_Avoid_: Backend-only, downstream side

**Intermediary**:
A protocol participant containing independent server-role and client-role sides.
_Avoid_: Proxy role, bidirectional role

**Connection state**:
A caller-defined value scoped to one protocol connection and made available to
middleware while that connection is active.
_Avoid_: Middleware state, global state

**Connection context**:
Immutable facts about one protocol connection, including endpoint metadata and
negotiated transport properties.
_Avoid_: Connection state, session metadata

**Connection cleanliness**:
Evidence of whether a protocol-ready connection may retain session-local changes
that prevent unconditional reuse.
_Avoid_: Protocol readiness, connection state

**Startup resolver**:
Intermediary policy that selects an initial client-role destination using an
accepted startup packet and the initial server-role connection context.
_Avoid_: Upstream resolver, router, backend selector

**Authenticated route policy**:
Intermediary policy that validates or refines the selected client-role
destination after server-role authentication.
_Avoid_: Post-authentication resolver, rerouter
