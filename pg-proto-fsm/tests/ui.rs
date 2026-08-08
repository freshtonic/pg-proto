//! Compile-fail coverage for the public protocol grammar interface.

#[test]
fn malformed_association_declarations_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
