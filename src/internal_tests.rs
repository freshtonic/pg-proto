//! Legacy protocol coverage retained behind the builder-only public boundary.

#[path = "internal_tests/intermediary_harness.rs"]
/// Shared neutral intermediary construction for internal integration tests.
mod intermediary_harness;
#[path = "internal_tests/intermediary_pipeline.rs"]
/// Integration tests for queued-request backpressure and ordering.
mod intermediary_pipeline;
#[path = "internal_tests/postgres_container.rs"]
/// Compatibility tests against Testcontainers-managed PostgreSQL instances.
mod postgres_container;
#[path = "internal_tests/recorded_fixtures.rs"]
/// Tests for sanitized recorded wire fixtures.
mod recorded_fixtures;
#[path = "internal_tests/runtime_middleware.rs"]
/// Integration tests for runtime middleware lifecycle and isolation.
mod runtime_middleware;
#[path = "internal_tests/security.rs"]
/// Security regression tests for secret handling.
mod security;
#[path = "internal_tests/server_role.rs"]
/// Integration tests for typed and facade server roles.
mod server_role;
