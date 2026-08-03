#[test]
fn illegal_protocol_transitions_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
