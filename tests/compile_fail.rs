//! Compile-fail coverage for the builder facade boundary and typestate.

#[test]
fn illegal_facade_usage_does_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/facade/*.rs");
}
