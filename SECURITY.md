# Security review

Review completed 4 August 2026 against the proxy-facing API and the audited
CipherStash/pgcat protocol obligations.

`cargo audit` scanned all 312 locked dependencies against 1,186 RustSec
advisories on that date and reported no vulnerabilities.

## Reviewed controls

- **TLS policy:** `disable`, `allow`, `prefer`, `require`, `verify-ca`, and
  `verify-full` have explicit negotiation branches. `verify-ca` validates the
  chain; `verify-full` additionally validates the host. Modes below `verify-ca`
  intentionally provide encryption without peer authentication, matching
  libpq semantics, and must not be presented as identity verification.
- **Channel binding:** `tls-server-end-point` hashes the complete DER leaf
  certificate with the RFC 5929 digest selection rule, including SHA-1/MD5
  promotion to SHA-256. SCRAM-PLUS is unavailable without transport evidence and
  downgrade attempts are rejected.
- **Credentials:** cleartext and MD5 verification use constant-time comparison;
  SCRAM proof and channel-binding checks do likewise. MD5 and cleartext remain
  compatibility mechanisms, not recommendations. Authentication payloads,
  platform tokens, and cancellation secrets are redacted from `Debug` output.
- **Framing and allocation:** declared lengths are validated before reservation.
  Tagged frames default to 16 MiB and raw pre-startup packets to 10 kB; callers
  may deliberately configure another valid bound. Count and integer conversions
  are checked during reconstruction.
- **Cancellation:** keys are length-validated, collisions are not overwritten,
  and registry/minting policy is application-owned. Deployments must mint
  unpredictable keys and remove mappings when either session detaches.
- **Malformed messages:** both directional codecs reject unknown tags, truncated
  known bodies, invalid counts/Booleans, bad protocol branches, and oversized
  frames without advancing typed state. Compile-fail, fixture, differential, and
  fuzz targets cover these boundaries.

## Residual application responsibilities

The library cannot erase every copied `Bytes` allocation on drop and does not
control downstream logs of explicitly accessed SQL, parameters, rows, or
credentials. Applications must minimise credential lifetime, avoid diagnostic
logging of message bodies, configure trust roots and hostnames correctly, apply
timeouts around handshakes and reads, and choose limits appropriate to their
workload. GSSAPI/SSPI adapters must provide their platform's credential and
context-lifetime guarantees.
