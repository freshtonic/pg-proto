# ADR 0001: Implement the frontend role first

Status: accepted

## Decision

Implement the frontend (client-driver) role before the backend role. Both roles
remain required for the proxy and will share a single grammar once generation is
introduced.

## Reasons

- A frontend can be checked directly against several real PostgreSQL versions.
- It exercises the difficult transport-changing pre-startup transition and makes
  TLS channel-binding data available to SCRAM authentication early.
- Recorded server byte streams can test error recovery and unusual authentication
  offers without first building a server harness.
- Once the grammar generator exists, the backend API should be emitted as the dual
  rather than developed as a second, potentially divergent state machine.

The backend role starts before Layer 3; this decision is sequencing, not scope.

