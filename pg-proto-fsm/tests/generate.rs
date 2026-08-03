use pg_proto_fsm::protocol;

protocol! {
    pub mod query {
        initial Ready;
        Ready internal {
            Query(query) => Simple,
            Parse(parse) => Building,
        }
        Simple external {
            Complete(complete) => Ready,
        }
        Building internal {
            Parse(parse) => Building,
            Sync(sync) => Ready,
        }
    }
}

protocol! {
    mod duplex {
        initial Open;
        Open mixed {
            internal Send(send) => Open,
            external Receive(receive) => Open,
            internal Close(close) => Closed,
        }
        Closed external {}
    }
}

#[test]
fn typestate_and_runtime_fsm_follow_the_same_grammar() {
    let _ready: query::Session<query::Ready> = query::Session::new().query().complete();
    let _dual_ready: query::DualSession<query::Ready> =
        query::DualSession::new().query().complete();

    let mut runtime = query::RuntimeFsm::new();
    runtime.step(query::Event::Query).unwrap();
    assert_eq!(runtime.state(), query::RuntimeState::Simple);
    assert_eq!(runtime.choice(), query::ChoiceKind::External);
    assert_eq!(runtime.dual_choice(), query::ChoiceKind::Internal);
    runtime.step(query::Event::Complete).unwrap();
    assert_eq!(runtime.state(), query::RuntimeState::Ready);
    assert!(runtime.step(query::Event::Sync).is_err());
}

#[test]
fn generated_typed_sessions_carry_transport_and_cleanliness() {
    #[derive(Debug)]
    struct Pristine;

    let session: query::TypedSession<Vec<u8>, query::Ready, Pristine> =
        query::TypedSession::with_transport(vec![1, 2, 3])
            .query()
            .complete();
    assert_eq!(session.into_transport(), [1, 2, 3]);

    let dual: query::DualTypedSession<Vec<u8>, query::Ready, Pristine> =
        query::DualTypedSession::with_transport(vec![4, 5])
            .query()
            .complete();
    assert_eq!(dual.into_transport(), [4, 5]);
}

#[test]
fn railroad_svg_is_emitted_at_compile_time() {
    assert!(query::QUERY_RAILROAD_SVG.starts_with("<svg"));
    assert!(query::QUERY_RAILROAD_SVG.contains("Building"));
    assert!(query::QUERY_RAILROAD_SVG.contains("Sync"));
    assert!(query::QUERY_RAILROAD_SVG.contains("class=\"repeat\""));
    assert!(query::QUERY_RAILROAD_SVG.contains("⊕ Parse"));
}

#[test]
fn mixed_states_retain_each_transition_direction() {
    let mut runtime = duplex::RuntimeFsm::new();
    assert_eq!(runtime.choice(), duplex::ChoiceKind::Mixed);
    assert_eq!(
        runtime.event_choice(duplex::Event::Send),
        Some(duplex::ChoiceKind::Internal)
    );
    assert_eq!(
        runtime.event_choice(duplex::Event::Receive),
        Some(duplex::ChoiceKind::External)
    );
    assert_eq!(
        runtime.dual_event_choice(duplex::Event::Send),
        Some(duplex::ChoiceKind::External)
    );
    assert_eq!(
        runtime.dual_event_choice(duplex::Event::Receive),
        Some(duplex::ChoiceKind::Internal)
    );
    runtime.step(duplex::Event::Send).unwrap();
    runtime.step(duplex::Event::Receive).unwrap();
    runtime.step(duplex::Event::Close).unwrap();
    assert_eq!(runtime.state(), duplex::RuntimeState::Closed);
    assert!(duplex::DUPLEX_RAILROAD_SVG.contains('⊕'));
    assert!(duplex::DUPLEX_RAILROAD_SVG.contains('&'));
}
