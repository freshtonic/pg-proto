# Separate protocol conformance from burn-in verification

Status: accepted

pg-proto will verify its complete public intermediary topology with a dedicated,
multi-process harness rather than one monolithic integration test. A finite
conformance mode will measure stable generated protocol-transition coverage,
while duration-based soak modes reuse the proven scenarios to detect retention
and performance drift; keeping these modes separate gives each an honest stopping
condition and failure signal.

The primary topology is an independent Rust SQL driver through a public
`Intermediary`—containing configured `Server` and `Client` roles—to a real,
version-pinned PostgreSQL instance launched with Testcontainers. Coverage through
real PostgreSQL, coverage through narrowly scripted peers, and reviewed
exemptions remain distinct because PostgreSQL and ordinary drivers cannot produce
every legal or malformed protocol exchange. The harness crosses only the
builder-only public facade required by ADR 0005; missing observations must improve
that interface generally or remain explicitly indirect rather than creating a
test-only seam.

## Consequences

- Protocol coverage is generated from grammar transitions and contextual message
  associations, supplemented by explicit catalogues for asynchronous,
  pre-startup, authentication, cancellation, replication, and codec-only cases.
- A wire enum variant does not count as covered in every state where it appears.
- Correctness and finite conformance gate immediately. Resource and performance
  results remain advisory until stable-runner history supports promoted gates.
- Scripted peers cover otherwise unreachable paths, but cannot inflate the real
  PostgreSQL end-to-end coverage result.

