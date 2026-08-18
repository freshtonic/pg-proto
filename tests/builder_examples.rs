//! Guardrails for the builder-only examples shipped with the crate.

use std::{fs, path::Path};

#[test]
fn shipped_examples_do_not_import_legacy_protocol_internals() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let forbidden = [
        "pg_proto::Conn",
        "pg_proto::grammar",
        "pg_proto::intermediary",
        "pg_proto::middleware",
        "pg_proto::pipeline",
        "pg_proto::pre_startup",
        "pg_proto::transport",
        "Conn,",
        "grammar::{",
        "SessionPair",
        "Middleware::new",
    ];
    for path in rust_sources(&root) {
        let source = fs::read_to_string(&path).unwrap();
        for legacy in forbidden {
            assert!(
                !source.contains(legacy),
                "{} uses legacy API `{legacy}` instead of the builder facade",
                path.display()
            );
        }
    }
}

#[test]
fn named_intermediary_examples_drive_the_operational_facade() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    for name in [
        "proxy_skeleton.rs",
        "rewriting_intermediary.rs",
        "queued_request_backpressure.rs",
    ] {
        let source = fs::read_to_string(root.join(name)).unwrap();
        assert!(
            source.contains(".accept("),
            "{name} must establish both roles"
        );
        assert!(
            source.contains("forward_"),
            "{name} must forward live traffic"
        );
    }
    let rewriting = fs::read_to_string(root.join("rewriting_intermediary.rs")).unwrap();
    assert!(rewriting.contains("visible = true"));
    assert!(rewriting.contains("visible_amount"));
    let backpressure = fs::read_to_string(root.join("queued_request_backpressure.rs")).unwrap();
    assert!(backpressure.contains("BoundedPipeline::new(1)"));
    assert!(backpressure.contains("session.forward_frontend().await?"));
}

#[test]
fn logging_proxies_build_roles_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    for name in [
        "protocol_logging_proxy/main.rs",
        "sql_logging_proxy/main.rs",
    ] {
        let source = fs::read_to_string(root.join(name)).unwrap();
        for builder in [
            "Server::builder()",
            "Client::builder()",
            "Intermediary::builder()",
        ] {
            assert!(
                source.contains(builder),
                "{name} must call `{builder}` directly"
            );
        }
        assert!(
            !source.contains("proxy_support"),
            "{name} must remain a self-contained builder example"
        );
    }
    assert!(!root.join("proxy_support").exists());
}

fn rust_sources(root: &Path) -> Vec<std::path::PathBuf> {
    let mut sources = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    sources
}
