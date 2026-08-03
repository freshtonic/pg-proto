use pg_proto_fsm::protocol;

protocol! {
    pub mod query {
        initial Ready;
        Ready {
            Query(query) => Simple,
            Parse(parse) => Building,
        }
        Simple {
            Complete(complete) => Ready,
        }
        Building {
            Parse(parse) => Building,
            Sync(sync) => Ready,
        }
    }
}

#[test]
fn typestate_and_runtime_fsm_follow_the_same_grammar() {
    let _ready: query::Session<query::Ready> = query::Session::new().query().complete();

    let mut runtime = query::RuntimeFsm::new();
    runtime.step(query::Event::Query).unwrap();
    assert_eq!(runtime.state(), query::RuntimeState::Simple);
    runtime.step(query::Event::Complete).unwrap();
    assert_eq!(runtime.state(), query::RuntimeState::Ready);
    assert!(runtime.step(query::Event::Sync).is_err());
}

#[test]
fn railroad_svg_is_emitted_at_compile_time() {
    assert!(query::QUERY_RAILROAD_SVG.starts_with("<svg"));
    assert!(query::QUERY_RAILROAD_SVG.contains("Building"));
    assert!(query::QUERY_RAILROAD_SVG.contains("Sync"));
}
