//! Deterministic source-level guardrails for the builder-only facade.

use std::fs;

#[test]
fn root_facade_matches_the_reviewed_manifest() {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")).unwrap();
    let start = source.find("pub use client_component").unwrap();
    let end = source[start..].find("\n#[cfg(test)]").unwrap() + start;
    let actual = source[start..end].trim_end();
    let expected = include_str!("../docs/public-api.txt").trim_end();
    assert_eq!(
        actual, expected,
        "review docs/public-api.txt with every facade change"
    );

    for (offset, _) in source.match_indices("pub use ") {
        assert!(
            (start..end).contains(&offset),
            "every root re-export must be inside the reviewed facade manifest"
        );
    }
}

#[test]
fn implementation_modules_and_legacy_connection_are_not_public() {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")).unwrap();
    assert!(!source.lines().any(|line| line.starts_with("pub mod ")));
    assert!(source.lines().all(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("pub ") || trimmed.starts_with("pub use ")
    }));
    assert!(!source.contains("pub struct Conn<"));
    assert!(source.contains("#![deny(private_bounds, private_interfaces, unreachable_pub)]"));
}
