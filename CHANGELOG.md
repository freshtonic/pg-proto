# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.10.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.9.0...pg-proto-v0.10.0) - 2026-08-11

### Fixed

- preserve projected state across pipelined responses

## [0.9.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.8.0...pg-proto-v0.9.0) - 2026-08-10

### Added

- add ordered backend batch holding

## [0.8.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.7.0...pg-proto-v0.8.0) - 2026-08-10

### Added

- support backend middleware fan-out

### Fixed

- preserve fuzz checks when reusing CI

## [0.7.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.6.2...pg-proto-v0.7.0) - 2026-08-09

### Added

- expose async intermediary middleware decisions

### Documentation

- illustrate modes of operation

## [0.6.2](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.6.1...pg-proto-v0.6.2) - 2026-08-09

### Documentation

- inventory supported protocol messages

## [0.6.1](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.6.0...pg-proto-v0.6.1) - 2026-08-09

### Changed

- preserve explicit Rust toolchain policy

### Documentation

- link official PostgreSQL protocol references

## [0.6.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.5.0...pg-proto-v0.6.0) - 2026-08-09

### Added

- add operational client builder
- add plaintext trust server builder ([#32](https://github.com/freshtonic/pg-proto/pull/32))
- add client TLS and pluggable authentication ([#31](https://github.com/freshtonic/pg-proto/pull/31))
- add server TLS and pluggable authentication ([#33](https://github.com/freshtonic/pg-proto/pull/33))
- run role middleware across connection lifecycle
- add intermediary role connection seams
- add operational intermediary forwarding
- forward intermediary cancellation safely
- migrate examples to builder facade

### Changed

- Merge branch 'main' into dependabot/cargo/base64-0.23.0
- Merge branch 'main' into dependabot/cargo/tokio-postgres-rustls-0.14.0
- refactor connections around state-free cores
- make builders the only public API
- make logging proxies builder-native

### Documentation

- centre builder facade and release gates
- preserve builder domain decisions
- verify and label code snippets

### Fixed

- connect generated railroad diagrams
- align CI with builder-only test layout
- close and pipeline logging proxy sessions

### Testing

- initialize rustls provider independently

## [0.5.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.4.0...pg-proto-v0.5.0) - 2026-08-07

### Added

- generate phase associations from grammar ([#23](https://github.com/freshtonic/pg-proto/pull/23))

### Changed

- deepen pipeline ledger interface ([#24](https://github.com/freshtonic/pg-proto/pull/24))
- consolidate inbound interception

### Maintenance

- configure Matt Pocock agent skills

## [0.4.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.3.0...pg-proto-v0.4.0) - 2026-08-06

### Added

- add typed bounded pipeline middleware
- compose typed pipeline middleware
- track exact pipeline response phases
- type outbound middleware by connection phase

### Changed

- deepen typed pipeline middleware

### Fixed

- separate server authentication decision phases

### Testing

- refresh outbound role diagnostic
- support platform-specific compiler diagnostics
- match Linux macro diagnostic indentation

## [0.3.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.2.3...pg-proto-v0.3.0) - 2026-08-06

### Added

- make message middleware async

## [0.2.3](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.2.2...pg-proto-v0.2.3) - 2026-08-06

### Added

- generate typed message projections
- add stateful message middleware core
- integrate checked message middleware
- generate phase-typed middleware messages
- infer typed middleware from connections
- project typed transport messages
- migrate rewriting example to typed middleware
- add typed wire pass-through adapter

### Changed

- reuse successful PR checks on main
- tolerate post-merge API lag

### Documentation

- plan stateful message middleware
- clarify runtime middleware validation
- plan compile-time middleware API
- document compile-time middleware
- complete typed middleware plan
- explain dropped pipeline messages

### Fixed

- preserve negotiation observations in proxy example
- align typed projections with completion plan

### Testing

- refresh compile-fail diagnostics
- stabilize compile-fail diagnostics

## [0.2.2](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.2.1...pg-proto-v0.2.2) - 2026-08-05

### Added

- add configurable network transports
- expose buffered transport borrowing
- split negotiated network streams
- expose negotiated channel binding

### Fixed

- satisfy Linux socket lint

## [0.2.1](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.2.0...pg-proto-v0.2.1) - 2026-08-04

### Added

- add crate discovery metadata

### Changed

- change project licence to MIT

### Documentation

- show README on crate documentation landing page
- add community and security policies

### Fixed

- select nightly fuzzing and current cargo-deny

### Maintenance

- define toolchain and publishing metadata
- harden dependency and release automation
- tighten Clippy lint policy

## [0.2.0](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.1.1...pg-proto-v0.2.0) - 2026-08-04

### Other

- add bounded intermediary pipelines

## [0.1.1](https://github.com/freshtonic/pg-proto/compare/pg-proto-v0.1.0...pg-proto-v0.1.1) - 2026-08-04

### Other

- bound decoded collection allocations
