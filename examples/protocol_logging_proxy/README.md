# Protocol logging proxy example

This example is assembled only through `Server::builder`, `Client::builder`,
and `Intermediary::builder`; listener acceptance and task placement remain
application-owned. The client-facing role requires TLS, while the upstream role
explicitly selects plaintext. Both roles use trust authentication solely for
the local demonstration. Production deployments should provide managed TLS on
each required leg and independent application authentication policies.

This companion example forwards the same traffic while printing every decoded
pre-startup, frontend, and backend message with its direction and connection
number. `PasswordResponse` uses pg-proto's redacted `Debug` implementation.
Logging is implemented as a core message-middleware stage and composed with the
SQL and row-statistics stages used by the companion example.

Run without arguments to start and retain a PostgreSQL 18 test container loaded
with the customer/orders fixture:

```bash
cargo run --example protocol_logging_proxy
```

Connect with TLS required. The proxy terminates TLS and logs the resulting
plaintext protocol messages before forwarding them upstream:

```bash
psql "host=127.0.0.1 port=6432 user=postgres dbname=postgres sslmode=require" \
  -c 'SELECT name FROM customers ORDER BY name'
```

The output includes the startup packet and messages such as `Parse`, `Bind`,
`RowDescription`, `DataRow`, `CommandComplete`, and `ReadyForQuery` in observed
wire order. The generated self-signed certificate is intended only for this
demonstration; production deployments should provide an identity rooted in
their normal certificate-management system.

To use an existing server instead, pass the listener and upstream explicitly:

```bash
cargo run --example protocol_logging_proxy -- 127.0.0.1:6432 127.0.0.1:5432
```

The explicit upstream must already be reachable. The example checks it before
opening its listener and reports a clear error if it cannot connect.
