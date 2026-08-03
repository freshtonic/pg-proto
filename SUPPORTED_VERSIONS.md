# Supported PostgreSQL versions

`pg-proto` supports PostgreSQL 14, 15, 16, 17, and 18.

Every version runs the same live Testcontainers suite against its official
Alpine image. The suite covers startup/protocol negotiation, cleartext, MD5,
SCRAM-SHA-256, SCRAM-SHA-256-PLUS over TLS, asynchronous backend messages,
extended query, error draining, and COPY IN/OUT.

PostgreSQL 14–17 negotiate a requested protocol 3.2 startup down to protocol
3.0. PostgreSQL 18 reports protocol 3.2. Both behaviours are asserted explicitly.

Run one version locally with:

```console
PG_PROTO_POSTGRES_VERSION=18 cargo test --test postgres_container -- --ignored
```
