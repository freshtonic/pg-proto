# SQL logging proxy example

This example is a small, transparent PostgreSQL proxy built with pg-proto's
direction-parameterised codecs. It prints every inbound simple-query `Query`
and extended-query `Parse` statement, then prints the number of `DataRow`
messages in each result when `CommandComplete` arrives.

Protocol logging, SQL extraction, and row counting are independent core
middleware stages chained in deterministic order. Their shared per-connection
state carries the connection number and accumulated row count.

The example forwards authentication and all tagged protocol messages without
changing them. It terminates client TLS using pg-proto's typed pre-startup
transport transition, then inspects and forwards the decrypted messages. The
demonstration generates a fresh self-signed certificate each time it starts;
`sslmode=require` encrypts the connection without requiring a persistent CA.

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

## Run it interactively with an automatic container

Run the proxy without an upstream argument. It starts PostgreSQL 18 through the
Rust `testcontainers-modules` crate, retains the container for the life of the
proxy, and loads the sample schema automatically:

```sh
cargo run --example sql_logging_proxy
```

Then query it from another terminal:

```sh
psql "host=127.0.0.1 port=6432 user=postgres dbname=postgres sslmode=require" \
  -c 'SELECT c.name, count(o.id) FROM customers c LEFT JOIN orders o ON o.customer_id = c.id GROUP BY c.id, c.name ORDER BY c.name'
```

The proxy prints output resembling:

```text
[1] SQL: SELECT c.name, count(o.id) ...
[1] ROWS: 3 (SELECT 3)
```

Set `PG_PROTO_POSTGRES_VERSION` to select PostgreSQL 14, 15, 16, 17, or 18.

## Use an existing PostgreSQL server

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
psql "host=127.0.0.1 port=6432 user=postgres dbname=postgres sslmode=require" \
  -c 'SELECT c.name, count(o.id) FROM customers c LEFT JOIN orders o ON o.customer_id = c.id GROUP BY c.id, c.name ORDER BY c.name'
```

An explicit upstream is checked before the proxy begins listening. If it is not
reachable, the example exits immediately with guidance instead of accepting and
then abruptly closing a client connection.
