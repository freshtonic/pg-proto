CREATE TABLE customers (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL,
    email text NOT NULL UNIQUE
);

CREATE TABLE orders (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id),
    ordered_at timestamptz NOT NULL,
    total_cents integer NOT NULL CHECK (total_cents >= 0)
);

INSERT INTO customers (name, email) VALUES
    ('Ada Lovelace', 'ada@example.test'),
    ('Grace Hopper', 'grace@example.test'),
    ('Edsger Dijkstra', 'edsger@example.test');

INSERT INTO orders (customer_id, ordered_at, total_cents) VALUES
    (1, '2026-07-01T09:00:00Z', 1299),
    (1, '2026-07-03T14:30:00Z', 4599),
    (2, '2026-07-02T11:15:00Z', 2500),
    (2, '2026-07-04T16:45:00Z', 799),
    (2, '2026-07-05T08:20:00Z', 1099);
