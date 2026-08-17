//! Deterministic audit keeping public documentation on the builder-only facade.

use std::{fs, path::Path};

#[test]
fn mode_diagrams_use_rustdoc_safe_urls_and_ship_with_the_crate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    let base = "https://raw.githubusercontent.com/freshtonic/pg-proto/main/docs/images";

    for image in [
        "client-mode.svg",
        "server-mode.svg",
        "intermediary-mode.svg",
    ] {
        assert!(root.join("docs/images").join(image).is_file());
        assert!(
            readme.contains(&format!("{base}/{image}")),
            "README must use a rustdoc-safe URL for {image}"
        );
    }
}

#[test]
fn public_docs_reference_only_builder_entry_points() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    collect_markdown(root, &mut paths);
    collect_files(&root.join("examples"), &mut paths);
    for facade_source in [
        "src/client_component.rs",
        "src/server_component.rs",
        "src/intermediary_component.rs",
        "src/runtime_middleware.rs",
        "src/pipeline.rs",
        "src/codec.rs",
        "src/demux.rs",
        "src/pre_startup.rs",
        "src/startup.rs",
    ] {
        paths.push(root.join(facade_source));
    }
    paths.sort();
    paths.dedup();

    let forbidden = ["pg_proto::Conn", "SessionPair", "Middleware::new"];
    let private_modules = [
        "auth",
        "codec",
        "intermediary",
        "middleware",
        "pipeline",
        "pre_startup",
        "session",
        "transport",
    ];
    for path in paths {
        let source = fs::read_to_string(&path).expect("public documentation must be readable");
        let documentation = if path.starts_with(root.join("src")) {
            rustdoc_without_compile_fail_examples(&source)
        } else {
            source
        };
        let compact = documentation.split_whitespace().collect::<String>();
        for legacy in forbidden {
            assert!(
                !documentation.contains(legacy),
                "{} contains legacy public API reference `{legacy}`",
                path.display()
            );
        }
        for module in private_modules {
            for legacy in [
                format!("pg_proto::{module}::"),
                format!("pg_proto::{module}as"),
                format!("pg_proto::{module};"),
            ] {
                assert!(
                    !compact.contains(&legacy),
                    "{} contains legacy public module reference `{legacy}`",
                    path.display()
                );
            }
            assert!(
                !contains_grouped_module(&compact, module),
                "{} contains grouped legacy public module reference `{module}`",
                path.display()
            );
        }
    }
}

fn contains_grouped_module(source: &str, module: &str) -> bool {
    let mut remaining = source;
    while let Some(start) = remaining.find("pg_proto::{") {
        remaining = &remaining[start + "pg_proto::{".len()..];
        let Some(end) = remaining.find('}') else {
            return false;
        };
        if remaining[..end].split(',').any(|item| {
            item == module
                || item.starts_with(&format!("{module}::"))
                || item.starts_with(&format!("{module}as"))
        }) {
            return true;
        }
        remaining = &remaining[end + 1..];
    }
    false
}

fn rustdoc_without_compile_fail_examples(source: &str) -> String {
    let mut in_compile_fail = false;
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if !(trimmed.starts_with("///") || trimmed.starts_with("//!")) {
                return None;
            }
            let content = trimmed
                .strip_prefix("///")
                .or_else(|| trimmed.strip_prefix("//!"))
                .unwrap()
                .trim_start();
            if content.starts_with("```rust,compile_fail") {
                in_compile_fail = true;
                return None;
            }
            if in_compile_fail && content.starts_with("```") {
                in_compile_fail = false;
                return None;
            }
            (!in_compile_fail).then_some(content)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn readme_leads_with_all_complete_builder_workflows_and_guardrails() {
    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    let security = readme.find("## Security choices come first").unwrap();
    let client = readme.find("## Client: connect to PostgreSQL").unwrap();
    let server = readme.find("## Server: accept PostgreSQL clients").unwrap();
    let intermediary = readme.find("## Intermediary: compose both roles").unwrap();
    assert!(security < client && client < server && server < intermediary);
    assert_eq!(readme.matches("```rust,no_run").count(), 3);
    for entry in [
        "Client::builder()",
        "Server::builder()",
        "Intermediary::builder()",
    ] {
        assert!(readme.contains(entry), "README is missing `{entry}`");
    }
    for guardrail in [
        "plaintext",
        "unverified trust",
        "VerifyFull",
        "without_frame_limit",
    ] {
        assert!(
            readme.contains(guardrail),
            "README is missing `{guardrail}` guardrail"
        );
    }
}

#[test]
fn readme_documents_the_burn_in_topology_profiles_and_artifact_policy() {
    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    for required in [
        "## Protocol conformance and burn-in",
        "Server` + `Intermediary` + `Client",
        "conformance --profile smoke",
        "conformance --profile authentication",
        "conformance --profile replication",
        "conformance --profile scripted",
        "conformance --profile rewrites",
        "`faults`",
        "`soak`",
        "`replay`",
        "`performance`",
        "PostgreSQL 14 through 18",
        "real-PostgreSQL, scripted, indirect, or reviewed exemption",
        "diagnostic payload capture is opt-in",
        "docs/design/burn-in-verification.md",
        "docs/adr/0006-separate-protocol-conformance-from-burn-in.md",
    ] {
        assert!(readme.contains(required), "README is missing `{required}`");
    }
}

#[test]
fn readme_message_support_matches_public_message_facade() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    let codec = fs::read_to_string(root.join("src/codec.rs")).unwrap();
    let pre_startup = fs::read_to_string(root.join("src/pre_startup.rs")).unwrap();

    let documented_facade = [
        ("SSLRequest", "SslRequest"),
        ("GSSENCRequest", "GssEncRequest"),
        ("StartupMessage", "Startup(StartupMessage)"),
        ("CancelRequest", "CancelRequest"),
    ];
    for (wire_name, facade_name) in documented_facade {
        assert!(readme.contains(&format!("`{wire_name}`")));
        assert!(pre_startup.contains(facade_name));
    }

    for variant in [
        "Parse",
        "Bind",
        "Describe",
        "Close",
        "Execute",
        "FunctionCall",
        "Query",
        "Flush",
        "Sync",
        "Terminate",
        "CopyData",
        "CopyDone",
        "CopyFail",
        "PasswordResponse",
    ] {
        assert!(readme.contains(variant));
        assert!(codec.contains(&format!("    {variant}")));
    }
    for variant in [
        "Ok",
        "KerberosV5",
        "CleartextPassword",
        "Md5Password",
        "Gss",
        "GssContinue",
        "Sspi",
        "Sasl",
        "SaslContinue",
        "SaslFinal",
    ] {
        assert!(readme.contains(&format!("Authentication::{variant}`")));
        assert!(codec.contains(&format!("    {variant}")));
    }
    for variant in [
        "RowDescription",
        "Authentication",
        "ParseComplete",
        "BindComplete",
        "CloseComplete",
        "CommandComplete",
        "CopyData",
        "CopyDone",
        "CopyInResponse",
        "CopyOutResponse",
        "CopyBothResponse",
        "DataRow",
        "EmptyQueryResponse",
        "ErrorResponse",
        "NoData",
        "ParameterStatus",
        "NoticeResponse",
        "NotificationResponse",
        "BackendKeyData",
        "ReadyForQuery",
        "ParameterDescription",
        "PortalSuspended",
        "FunctionCallResponse",
        "NegotiateProtocolVersion",
    ] {
        assert!(readme.contains(variant));
        assert!(codec.contains(&format!("    {variant}")));
    }
}

#[test]
fn documentation_code_fences_specify_a_language() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    collect_markdown(root, &mut paths);
    collect_files(&root.join("src"), &mut paths);
    paths.sort();
    paths.dedup();
    for path in paths {
        let source = fs::read_to_string(&path).expect("documentation must be readable");
        let mut in_fence = false;
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            let trimmed = if path.extension().is_some_and(|extension| extension == "rs") {
                let Some(documentation) = trimmed
                    .strip_prefix("///")
                    .or_else(|| trimmed.strip_prefix("//!"))
                else {
                    continue;
                };
                documentation.trim_start()
            } else {
                trimmed
            };
            if !trimmed.starts_with("```") {
                continue;
            }
            if in_fence {
                assert_eq!(
                    trimmed,
                    "```",
                    "{}:{} has an invalid closing fence",
                    path.display(),
                    index + 1
                );
            } else {
                assert!(
                    trimmed.len() > 3,
                    "{}:{} has a code fence without a language",
                    path.display(),
                    index + 1
                );
            }
            in_fence = !in_fence;
        }
        assert!(!in_fence, "{} has an unclosed code fence", path.display());
    }
}

fn collect_files(root: &Path, paths: &mut Vec<std::path::PathBuf>) {
    let mut entries = fs::read_dir(root)
        .expect("documentation directory must exist")
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_files(&path, paths);
        } else if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("md" | "rs")
        ) {
            paths.push(path);
        }
    }
}

fn collect_markdown(root: &Path, paths: &mut Vec<std::path::PathBuf>) {
    let mut entries = fs::read_dir(root)
        .expect("repository directory must exist")
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            let name = path.file_name().and_then(|value| value.to_str());
            if !matches!(name, Some(".git" | "target" | "tests")) {
                collect_markdown(&path, paths);
            }
        } else if path.extension().is_some_and(|extension| extension == "md") {
            paths.push(path);
        }
    }
}
