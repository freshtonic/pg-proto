use pg_proto_fsm::protocol;

protocol! {
    pub mod query {
        initial Ready;
        Ready internal {
            Query(query: u8) => Simple [Dirty],
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
        query::TypedSession::with_transport(vec![1, 2, 3]);
    let (session, previous_len): (
        query::TypedSession<Vec<u8>, query::Simple, query::Dirty>,
        usize,
    ) = session
        .query(4, |transport, payload| {
            let previous_len = transport.len();
            transport.push(payload);
            Ok::<_, ()>(previous_len)
        })
        .unwrap();
    assert_eq!(previous_len, 3);
    let session: query::TypedSession<Vec<u8>, query::Ready, query::Dirty> = session.complete();
    assert_eq!(session.into_transport(), [1, 2, 3, 4]);

    let dual: query::DualTypedSession<Vec<u8>, query::Ready, Pristine> =
        query::DualTypedSession::with_transport(vec![4, 5]);
    let (dual, ()): (
        query::DualTypedSession<Vec<u8>, query::Simple, query::Dirty>,
        (),
    ) = dual
        .query(6, |transport, payload| {
            transport.push(payload);
            Ok::<_, ()>(())
        })
        .unwrap();
    let dual: query::DualTypedSession<Vec<u8>, query::Ready, query::Dirty> = dual.complete();
    assert_eq!(dual.into_transport(), [4, 5, 6]);
}

#[test]
fn generated_typed_sessions_change_transport_without_changing_state() {
    struct Clean;

    let open: duplex::TypedSession<u8, duplex::Open, Clean> =
        duplex::TypedSession::with_transport(42);
    let open: duplex::TypedSession<String, duplex::Open, Clean> =
        open.map_transport(|transport| transport.to_string());
    assert_eq!(open.close().into_transport(), "42");
}

#[test]
fn railroad_svg_is_emitted_at_compile_time() {
    assert!(query::QUERY_RAILROAD_SVG.starts_with("<svg"));
    assert!(query::QUERY_RAILROAD_SVG.contains("Building"));
    assert!(query::QUERY_RAILROAD_SVG.contains("Sync"));
    assert!(query::QUERY_RAILROAD_SVG.contains("class=\"repeat\""));
    assert!(query::QUERY_RAILROAD_SVG.contains("⊕ Parse"));
    assert!(query::QUERY_RAILROAD_SVG.contains("⊕ Query: u8 [Dirty]"));
}

#[test]
fn fallible_payload_handler_preserves_state_on_error() {
    struct Clean;

    let ready: query::TypedSession<Vec<u8>, query::Ready, Clean> =
        query::TypedSession::with_transport(vec![1]);
    let (ready, error) = ready
        .query(2, |_transport, _payload| Err::<(), _>("rejected"))
        .unwrap_err();
    assert_eq!(error, "rejected");
    assert_eq!(ready.into_transport(), [1]);
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

#[test]
fn runtime_target_and_direction_share_the_generated_transition_table() {
    assert_eq!(query::ALL_EVENTS.len(), 4);
    assert_eq!(query::TRANSITIONS.len(), 5);

    for (index, transition) in query::TRANSITIONS.iter().enumerate() {
        assert!(!query::TRANSITIONS[..index].iter().any(|previous| {
            previous.source == transition.source && previous.event == transition.event
        }));
        assert_eq!(
            query::transition(transition.source, transition.event),
            Some(*transition)
        );
    }

    let mut runtime = query::RuntimeFsm::new();
    let query_transition = query::transition(runtime.state(), query::Event::Query).unwrap();
    assert_eq!(
        runtime.event_choice(query::Event::Query),
        Some(query_transition.choice)
    );
    runtime.step(query::Event::Query).unwrap();
    assert_eq!(runtime.state(), query_transition.target);
}

#[test]
fn runtime_exhaustively_accepts_exactly_the_generated_sequences() {
    fn check(prefix: &mut Vec<query::Event>, depth: usize) {
        let mut expected = query::RuntimeState::Ready;
        let mut expected_error = None;
        for &event in prefix.iter() {
            if let Some(transition) = query::transition(expected, event) {
                expected = transition.target;
            } else {
                expected_error = Some(query::TransitionError {
                    state: expected,
                    event,
                });
                break;
            }
        }

        let mut runtime = query::RuntimeFsm::new();
        let mut actual_error = None;
        for &event in prefix.iter() {
            if let Err(error) = runtime.step(event) {
                actual_error = Some(error);
                break;
            }
        }
        assert_eq!(actual_error, expected_error, "sequence: {prefix:?}");
        assert_eq!(runtime.state(), expected, "sequence: {prefix:?}");

        if depth == 0 {
            return;
        }
        for &event in query::ALL_EVENTS {
            prefix.push(event);
            check(prefix, depth - 1);
            prefix.pop();
        }
    }

    check(&mut Vec::new(), 6);
}

#[test]
fn message_projection_receives_the_current_protocol_state() {
    #[derive(Clone, Copy)]
    enum WireMessage {
        Parse,
        Complete,
    }

    let project = |state, message: &WireMessage| match (state, message) {
        (query::RuntimeState::Ready | query::RuntimeState::Building, WireMessage::Parse) => {
            Some(query::Event::Parse)
        }
        (query::RuntimeState::Simple, WireMessage::Complete) => Some(query::Event::Complete),
        _ => None,
    };

    let mut runtime = query::RuntimeFsm::new();
    assert_eq!(
        runtime
            .step_projected(&WireMessage::Parse, project)
            .unwrap(),
        query::Event::Parse
    );
    assert_eq!(runtime.state(), query::RuntimeState::Building);
    assert_eq!(
        runtime.step_projected(&WireMessage::Complete, project),
        Err(query::ProjectionError {
            state: query::RuntimeState::Building,
        })
    );
    assert_eq!(runtime.state(), query::RuntimeState::Building);
}
