//! Captures Cargo build-profile metadata for performance artifacts.

fn main() {
    println!("cargo:rerun-if-env-changed=PG_PROTO_REQUESTED_PROFILE");
    let base_profile = std::env::var("PROFILE").expect("Cargo supplies PROFILE to build scripts");
    println!(
        "cargo:rustc-env=PG_PROTO_CARGO_PROFILE={}",
        std::env::var("PG_PROTO_REQUESTED_PROFILE").unwrap_or_else(|_| base_profile.clone())
    );
    println!("cargo:rustc-env=PG_PROTO_BASE_PROFILE={base_profile}");
    println!(
        "cargo:rustc-env=PG_PROTO_OPT_LEVEL={}",
        std::env::var("OPT_LEVEL").expect("Cargo supplies OPT_LEVEL to build scripts")
    );
}
