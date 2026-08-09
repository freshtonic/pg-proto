//! Legacy protocol coverage retained behind the builder-only public boundary.

#[path = "internal_tests/intermediary_harness.rs"]
mod intermediary_harness;
#[path = "internal_tests/intermediary_pipeline.rs"]
mod intermediary_pipeline;
#[path = "internal_tests/postgres_container.rs"]
mod postgres_container;
#[path = "internal_tests/recorded_fixtures.rs"]
mod recorded_fixtures;
#[path = "internal_tests/runtime_middleware.rs"]
mod runtime_middleware;
#[path = "internal_tests/security.rs"]
mod security;
#[path = "internal_tests/server_role.rs"]
mod server_role;
