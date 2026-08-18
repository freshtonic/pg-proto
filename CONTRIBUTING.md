# Contributing to pg-proto

Thank you for helping improve `pg-proto`. By participating, you agree to follow
the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening a change

Use an issue for substantial protocol or public-API design changes. Security
reports must follow [SECURITY.md](SECURITY.md) and must not be filed publicly.

Protocol changes should preserve the generated grammar as the single source of
truth. Prose and comments use British English.

## Development environment

The repository's `rust-toolchain.toml` selects the development compiler. A
Docker-compatible container runtime is needed for live PostgreSQL tests. The
normal verification commands are:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo package --workspace
```

Run the PostgreSQL compatibility suite with:

```bash
cargo test --lib internal_tests::postgres_container -- --ignored --test-threads=1
```

Run a focused fuzz target with nightly Rust:

```bash
cargo +nightly fuzz run --fuzz-dir fuzz backend_codec
```

## Pull requests

- Keep changes focused and include tests for observable behaviour.
- Update public Rustdoc and migration guidance when an API changes.
- Update `PLAN.md` when completing or adding planned work.
- Prefer Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `test:`,
  `refactor:`, `perf:`, `chore:`) so release notes are grouped meaningfully.
- Do not commit credentials, private certificates, production captures, or
  unsanitised protocol payloads.

All required checks must pass and review comments must be resolved before merge.
