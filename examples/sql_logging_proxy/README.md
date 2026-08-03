# SQL logging proxy example

This example is a small, transparent PostgreSQL proxy built with pg-proto's
direction-parameterised codecs. It prints every inbound simple-query `Query`
and extended-query `Parse` statement, then prints the number of `DataRow`
messages in each result when `CommandComplete` arrives.

The example forwards authentication and all tagged protocol messages without
changing them. To keep messages inspectable, it declines SSL and GSS encryption
requests. Use `sslmode=disable` (or a mode which permits fallback) when connecting.
A production proxy should instead terminate TLS using pg-proto's typed
pre-startup transport transition.

## Run the automated demonstration

The ignored integration test uses the Rust `testcontainers-modules` crate to
start the official PostgreSQL image, applies [`customer_orders.sql`](customer_orders.sql),
runs a query through the proxy, and checks both its rows and logging observations:

```sh
cargo test --test logging_proxy_example -- --ignored --nocapture
```

PostgreSQL 18 is used by default. Select any supported major version with, for
example:

```sh
PG_PROTO_POSTGRES_VERSION=14 \
  cargo test --test logging_proxy_example -- --ignored --nocapture
```

A Docker-compatible container runtime must be running.

## Run it interactively

Start PostgreSQL with the sample schema mounted as an initialisation script:

```sh
docker run --rm --name pg-proto-orders \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 5432:5432 \
  -v "$PWD/examples/sql_logging_proxy/customer_orders.sql:/docker-entrypoint-initdb.d/customer_orders.sql:ro" \
  postgres:18-alpine
```

In a second terminal, run the proxy. The first address is its listener and the
second is PostgreSQL:

```sh
cargo run --example sql_logging_proxy -- 127.0.0.1:6432 127.0.0.1:5432
```

Then query through it from a third terminal:

```sh
psql "host=127.0.0.1 port=6432 user=postgres dbname=postgres sslmode=disable" \
  -c 'SELECT c.name, count(o.id) FROM customers c LEFT JOIN orders o ON o.customer_id = c.id GROUP BY c.id, c.name ORDER BY c.name'
```

The proxy prints output resembling:

```text
[1] SQL: SELECT c.name, count(o.id) ...
[1] ROWS: 3 (SELECT 3)
```
