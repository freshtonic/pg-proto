//! Compile-fail coverage for illegal protocol and resource transitions.

#[test]
fn illegal_protocol_transitions_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
    if cfg!(target_os = "macos") {
        tests.compile_fail("tests/ui/platform/typed_outbound_conn_role_mismatch_macos.rs");
    } else {
        tests.compile_fail("tests/ui/platform/typed_outbound_conn_role_mismatch_linux.rs");
    }
}
