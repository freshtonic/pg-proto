# Protocol logging proxy example

This companion example forwards the same traffic while printing every decoded
pre-startup, frontend, and backend message with its direction and connection
number. `PasswordResponse` uses pg-proto's redacted `Debug` implementation.

Run without arguments to start and retain a PostgreSQL 18 test container loaded
with the customer/orders fixture:

```sh
cargo run --example protocol_logging_proxy
```

Connect with encryption disabled so that the demonstration can inspect frames:

```sh
psql "host=127.0.0.1 port=6432 user=postgres dbname=postgres sslmode=disable" \
  -c 'SELECT name FROM customers ORDER BY name'
```

The output includes the startup packet and messages such as `Parse`, `Bind`,
`RowDescription`, `DataRow`, `CommandComplete`, and `ReadyForQuery` in observed
wire order. As with the SQL logger, this local example declines SSL and GSS
requests; production proxies should terminate encryption rather than log
plaintext traffic.

To use an existing server instead, pass the listener and upstream explicitly:

```sh
cargo run --example protocol_logging_proxy -- 127.0.0.1:6432 127.0.0.1:5432
```

The explicit upstream must already be reachable. The example checks it before
opening its listener and reports a clear error if it cannot connect.
