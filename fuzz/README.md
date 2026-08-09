# Fuzzing

Install `cargo-fuzz`, then run any target, for example:

```bash
cargo fuzz run frontend_codec
cargo fuzz run backend_codec
cargo fuzz run pre_startup
cargo fuzz run scram
cargo fuzz run runtime_fsm
```

The targets are crash/property oracles: malformed input may return an error but
must not panic, allocate beyond configured framing limits, or corrupt FSM state.
