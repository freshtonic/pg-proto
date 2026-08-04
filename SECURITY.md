# Security policy

## Supported versions

`pg-proto` is pre-1.0. Security fixes are provided for the latest published
minor release only. Users should upgrade to the newest release before reporting
or evaluating a possible vulnerability.

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| 0.1.x | No |

This table is updated when a new minor release supersedes the current line.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/freshtonic/pg-proto/security/advisories/new)
to send the affected versions, impact, reproduction steps, and any suggested
mitigation privately to the maintainer.

You should receive an acknowledgement within 3 working days. The maintainer
will investigate, coordinate a fix and disclosure where appropriate, and credit
reporters who wish to be named. Please allow a reasonable remediation period
before publishing details.

## Scope and assumptions

Security-sensitive surfaces include wire decoding, allocation bounds,
authentication, TLS and channel binding, cancellation keys, protocol-state
projection, and accidental disclosure through diagnostics. Proxy deployments
remain responsible for credential storage, certificate provisioning, routing
policy, connection timeouts, pool policy, and sanitising application logs.

The latest completed review is recorded in
[`docs/security-review-2026-08-04.md`](docs/security-review-2026-08-04.md).
