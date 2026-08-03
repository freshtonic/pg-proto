# Protocol logging proxy example

This companion example forwards the same traffic while printing every decoded
pre-startup, frontend, and backend message with its direction and connection
number. `PasswordResponse` uses pg-proto's redacted `Debug` implementation.

Start the sample PostgreSQL container as described in the
[`sql_logging_proxy` README](../sql_logging_proxy/README.md), then run:

```sh
cargo run --example protocol_logging_proxy -- 127.0.0.1:6432 127.0.0.1:5432
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
