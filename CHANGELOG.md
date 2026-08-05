# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
