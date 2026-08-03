# pg-proto

A session-typed implementation of the PostgreSQL frontend/backend wire protocol.
Protocol sequencing is represented by consuming transitions on
`Conn<Transport, Phase, Cleanliness>` rather than a runtime connection-state enum.

The first implementation role is the PostgreSQL frontend (client driver). This is
only an implementation order: the backend role required by a proxy remains in
scope and will be derived from the same protocol grammar.

The project is at its first milestone. The raw pre-startup request/reply exchange
and its transport-changing TLS transition are modelled; the framed codec and async
I/O are the next layer.

