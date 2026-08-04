# pg-proto-fsm

`pg-proto-fsm` is the procedural-macro implementation behind
[`pg-proto`](https://crates.io/crates/pg-proto). It turns one PostgreSQL protocol
grammar into:

- transport-carrying typestate APIs for both protocol roles;
- a runtime FSM used for differential and fuzz testing;
- state-aware wire-message projectors; and
- railroad diagrams embedded in Rustdoc.

Most users should depend on `pg-proto`, which re-exports the generated protocol
modules. Depend directly on this crate only when defining or testing another
grammar with the same generator.

## Documentation

- [`pg-proto-fsm` Rustdoc](https://docs.rs/pg-proto-fsm)
- [`pg-proto` Rustdoc](https://docs.rs/pg-proto)
- [Repository](https://github.com/freshtonic/pg-proto)

## Licence

Licensed under the [MIT License](https://github.com/freshtonic/pg-proto/blob/main/pg-proto-fsm/LICENSE).
