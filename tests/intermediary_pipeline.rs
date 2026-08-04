//! Deterministic coverage for bounded intermediary pipeline orchestration.

use bytes::Bytes;
use pg_proto::{
    codec::{
        BackendMessage, Bind, Close, CopyResponse, DataRow, Describe, DescribeTarget,
        DiagnosticResponse, Execute, FrontendMessage, Parse, TransactionStatus,
    },
    demux::Demux,
    intermediary::Intermediary,
    pipeline::{
        BackendAction, BoundedPipeline, FrontendAction, FrontendAdmission, FrontendHandling,
        FrontendProjectionError, NoPipeline, Pipeline, PipelineState,
    },
};

fn parse(name: &'static [u8]) -> FrontendMessage {
    FrontendMessage::Parse(Parse {
        statement: Bytes::from_static(name),
        query: Bytes::from_static(b"select 1"),
        parameter_types: vec![],
    })
}

fn bind() -> FrontendMessage {
    FrontendMessage::Bind(Bind {
        portal: Bytes::new(),
        statement: Bytes::new(),
        parameter_formats: vec![],
        parameters: vec![],
        result_formats: vec![],
    })
}

fn describe() -> FrontendMessage {
    FrontendMessage::Describe(Describe {
        target: DescribeTarget::Portal,
        name: Bytes::new(),
    })
}

fn execute() -> FrontendMessage {
    FrontendMessage::Execute(Execute {
        portal: Bytes::new(),
        max_rows: 0,
    })
}

fn close() -> FrontendMessage {
    FrontendMessage::Close(Close {
        target: DescribeTarget::Portal,
        name: Bytes::new(),
    })
}

fn error() -> BackendMessage {
    BackendMessage::ErrorResponse(DiagnosticResponse { fields: vec![] })
}

fn forwarded_id(admission: FrontendAdmission) -> pg_proto::pipeline::OperationId {
    match admission.into_action() {
        FrontendAction::Forward { id, .. } => id,
        other => panic!("expected forwarding action, got {other:?}"),
    }
}

fn local_id(admission: FrontendAdmission) -> pg_proto::pipeline::OperationId {
    match admission.into_action() {
        FrontendAction::Discard { id } => id,
        other => panic!("expected discard action, got {other:?}"),
    }
}

fn bounded(limit: usize) -> Pipeline<BoundedPipeline> {
    Pipeline::new(BoundedPipeline::new(limit).unwrap())
}

#[test]
fn bounded_capacity_returns_owned_message_and_recovers() {
    let mut pipeline = bounded(1);
    pipeline
        .accept_frontend(
            FrontendMessage::Query(Bytes::from_static(b"select 1")),
            FrontendHandling::Forward,
        )
        .unwrap();
    let retry = FrontendMessage::Query(Bytes::from_static(b"select 2"));
    let FrontendProjectionError::Capacity(retry) = pipeline
        .accept_frontend(retry, FrontendHandling::Forward)
        .unwrap_err()
    else {
        panic!("capacity must be distinguished from illegality")
    };
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .unwrap();
    assert!(
        pipeline
            .accept_frontend(*retry, FrontendHandling::Forward)
            .is_ok()
    );
}

#[test]
fn large_payload_is_returned_not_retained() {
    let body = Bytes::from(vec![7_u8; 2 * 1024 * 1024]);
    let pointer = body.as_ptr();
    let mut pipeline = bounded(2);
    let admission = pipeline
        .accept_frontend(FrontendMessage::Query(body), FrontendHandling::Forward)
        .unwrap();
    let FrontendAction::Forward {
        message: FrontendMessage::Query(body),
        ..
    } = admission.into_action()
    else {
        panic!("query must be returned to the application")
    };
    assert_eq!(body.as_ptr(), pointer);
    assert_eq!(pipeline.len(), 1);
}

#[test]
fn simple_query_stream_stays_at_head_until_ready() {
    let mut pipeline = bounded(2);
    pipeline
        .accept_frontend(
            FrontendMessage::Query(Bytes::from_static(b"select 1")),
            FrontendHandling::Forward,
        )
        .unwrap();
    for response in [
        BackendMessage::DataRow(DataRow {
            columns: vec![Some(Bytes::from_static(b"1"))],
        }),
        BackendMessage::CommandComplete(Bytes::from_static(b"SELECT 1")),
    ] {
        assert!(matches!(
            pipeline.accept_backend(response).unwrap(),
            BackendAction::Emit(_)
        ));
        assert_eq!(pipeline.len(), 1);
    }
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .unwrap();
    assert!(pipeline.is_empty());
}

#[test]
fn complete_extended_pipeline_is_ordered() {
    let mut pipeline = bounded(8);
    for message in [
        parse(b"s"),
        bind(),
        describe(),
        execute(),
        close(),
        FrontendMessage::Flush,
        FrontendMessage::Sync,
    ] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .unwrap();
    }
    assert_eq!(pipeline.len(), 7);
    for response in [
        BackendMessage::ParseComplete,
        BackendMessage::BindComplete,
        BackendMessage::NoData,
        BackendMessage::CommandComplete(Bytes::from_static(b"SELECT 1")),
        BackendMessage::CloseComplete,
        BackendMessage::ReadyForQuery(TransactionStatus::Idle),
    ] {
        pipeline.accept_backend(response).unwrap();
    }
    assert!(pipeline.is_empty());
}

#[test]
fn multiple_operations_are_accepted_before_responses_and_flush_is_inert() {
    let mut pipeline = bounded(5);
    assert!(matches!(
        pipeline
            .accept_frontend(parse(b"a"), FrontendHandling::Forward)
            .unwrap(),
        FrontendAdmission::Immediate(_)
    ));
    for message in [bind(), FrontendMessage::Flush, FrontendMessage::Sync] {
        assert!(matches!(
            pipeline
                .accept_frontend(message, FrontendHandling::Forward)
                .unwrap(),
            FrontendAdmission::Waiting(_)
        ));
    }
    pipeline
        .accept_backend(BackendMessage::ParseComplete)
        .unwrap();
    pipeline
        .accept_backend(BackendMessage::BindComplete)
        .unwrap();
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .unwrap();
    assert!(pipeline.is_empty());
}

#[test]
fn local_rejection_waits_behind_forwarded_parse() {
    let mut pipeline = bounded(4);
    pipeline
        .accept_frontend(parse(b"a"), FrontendHandling::Forward)
        .unwrap();
    let rejected = local_id(
        pipeline
            .accept_frontend(parse(b"b"), FrontendHandling::Local)
            .unwrap(),
    );
    pipeline
        .accept_frontend(FrontendMessage::Sync, FrontendHandling::Forward)
        .unwrap();
    assert!(matches!(
        pipeline.try_emit_local(rejected, error()).unwrap(),
        BackendAction::Deferred(_)
    ));
    pipeline
        .accept_backend(BackendMessage::ParseComplete)
        .unwrap();
    assert!(matches!(
        pipeline.try_emit_local(rejected, error()).unwrap(),
        BackendAction::Emit(BackendMessage::ErrorResponse(_))
    ));
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .unwrap();
    assert!(pipeline.is_empty());
}

#[test]
fn first_local_rejection_discards_through_sync() {
    let mut pipeline = bounded(4);
    let rejected = local_id(
        pipeline
            .accept_frontend(parse(b"bad"), FrontendHandling::Local)
            .unwrap(),
    );
    pipeline
        .accept_frontend(bind(), FrontendHandling::Forward)
        .unwrap();
    pipeline
        .accept_frontend(FrontendMessage::Sync, FrontendHandling::Forward)
        .unwrap();
    pipeline.try_emit_local(rejected, error()).unwrap();
    assert_eq!(pipeline.state(), PipelineState::ExtendedError);
    assert_eq!(
        pipeline.len(),
        1,
        "discarded Bind must not await a response"
    );
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .unwrap();
    assert!(pipeline.is_empty());
}

#[test]
fn upstream_error_discards_following_operations_until_sync() {
    let mut pipeline = bounded(4);
    for message in [parse(b"bad"), bind(), FrontendMessage::Sync] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .unwrap();
    }
    pipeline.accept_backend(error()).unwrap();
    assert_eq!(pipeline.len(), 1);
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .unwrap();
    assert!(pipeline.is_empty());
}

#[test]
fn illegal_frontend_and_backend_messages_are_not_deferred() {
    let mut pipeline = bounded(3);
    let illegal = FrontendMessage::CopyData(Bytes::from_static(b"outside COPY"));
    assert!(matches!(
        pipeline
            .accept_frontend(illegal, FrontendHandling::Forward)
            .unwrap_err(),
        FrontendProjectionError::Illegal { .. }
    ));
    pipeline
        .accept_frontend(parse(b"s"), FrontendHandling::Forward)
        .unwrap();
    assert!(
        pipeline
            .accept_backend(BackendMessage::BindComplete)
            .is_err()
    );
}

#[test]
fn copy_in_out_and_both_preserve_nested_legality() {
    let copy = CopyResponse {
        overall_format: 0,
        column_formats: vec![],
    };

    let mut input = bounded(6);
    for message in [parse(b"s"), bind(), execute()] {
        input
            .accept_frontend(message, FrontendHandling::Forward)
            .unwrap();
    }
    input.accept_backend(BackendMessage::ParseComplete).unwrap();
    input.accept_backend(BackendMessage::BindComplete).unwrap();
    input
        .accept_backend(BackendMessage::CopyInResponse(copy.clone()))
        .unwrap();
    assert_eq!(input.state(), PipelineState::CopyIn);
    input
        .accept_frontend(
            FrontendMessage::CopyData(Bytes::from_static(b"row\n")),
            FrontendHandling::Forward,
        )
        .unwrap();
    input
        .accept_frontend(FrontendMessage::CopyDone, FrontendHandling::Forward)
        .unwrap();

    for (response, expected) in [
        (
            BackendMessage::CopyOutResponse(copy.clone()),
            PipelineState::CopyOut,
        ),
        (
            BackendMessage::CopyBothResponse(copy),
            PipelineState::CopyBoth,
        ),
    ] {
        let mut pipeline = bounded(4);
        for message in [parse(b"s"), bind(), execute()] {
            pipeline
                .accept_frontend(message, FrontendHandling::Forward)
                .unwrap();
        }
        pipeline
            .accept_backend(BackendMessage::ParseComplete)
            .unwrap();
        pipeline
            .accept_backend(BackendMessage::BindComplete)
            .unwrap();
        pipeline.accept_backend(response).unwrap();
        assert_eq!(pipeline.state(), expected);
        pipeline
            .accept_backend(BackendMessage::CopyData(Bytes::from_static(b"row\n")))
            .unwrap();
    }
}

#[test]
fn asynchronous_messages_do_not_advance_the_ledger() {
    let mut pipeline = bounded(2);
    pipeline
        .accept_frontend(parse(b"s"), FrontendHandling::Forward)
        .unwrap();
    for message in [
        BackendMessage::NoticeResponse(DiagnosticResponse { fields: vec![] }),
        BackendMessage::NotificationResponse {
            process_id: 7,
            channel: Bytes::from_static(b"events"),
            payload: Bytes::from_static(b"changed"),
        },
        BackendMessage::ParameterStatus {
            name: Bytes::from_static(b"TimeZone"),
            value: Bytes::from_static(b"UTC"),
        },
        BackendMessage::BackendKeyData {
            process_id: 9,
            secret_key: Bytes::from_static(b"secret-key"),
        },
    ] {
        assert!(matches!(
            pipeline.accept_backend(message).unwrap(),
            BackendAction::Emit(_)
        ));
        assert_eq!(pipeline.len(), 1);
    }
}

#[test]
fn demuxed_session_items_share_the_pipeline_ordering_path() {
    let mut demux = Demux::default();
    let mut pipeline = bounded(2);
    pipeline
        .accept_frontend(parse(b"s"), FrontendHandling::Forward)
        .unwrap();
    assert!(
        demux
            .route(BackendMessage::NoticeResponse(DiagnosticResponse {
                fields: vec![],
            }))
            .is_none()
    );
    assert!(demux.pop_async_event().is_some());
    let item = demux
        .route(BackendMessage::ParseComplete)
        .expect("ParseComplete advances the session");
    assert!(matches!(
        pipeline.accept_session_item(item).unwrap(),
        BackendAction::Emit(BackendMessage::ParseComplete)
    ));
}

#[tokio::test]
async fn cancellation_of_waiting_local_caller_does_not_change_ledger() {
    let mut pipeline = bounded(2);
    pipeline
        .accept_frontend(parse(b"a"), FrontendHandling::Forward)
        .unwrap();
    let local = local_id(
        pipeline
            .accept_frontend(parse(b"b"), FrontendHandling::Local)
            .unwrap(),
    );
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(1),
        pipeline.wait_until_emittable(local),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(pipeline.len(), 2);
    pipeline
        .accept_backend(BackendMessage::ParseComplete)
        .unwrap();
    pipeline.wait_until_emittable(local).await;
}

#[test]
fn no_pipeline_backpressures_until_current_cycle_completes() {
    let mut pipeline = Pipeline::new(NoPipeline);
    pipeline
        .accept_frontend(
            FrontendMessage::Query(Bytes::from_static(b"select 1")),
            FrontendHandling::Forward,
        )
        .unwrap();
    assert!(matches!(
        pipeline
            .accept_frontend(
                FrontendMessage::Query(Bytes::from_static(b"select 2")),
                FrontendHandling::Forward
            )
            .unwrap_err(),
        FrontendProjectionError::Capacity(_)
    ));
}

#[test]
fn intermediary_preserves_old_constructor_and_can_opt_into_bounding() {
    let old = Intermediary::new(1_u8, 2_u8);
    assert_eq!(*old.downstream(), 1);
    let mut bounded = old.with_pipeline(BoundedPipeline::new(4).unwrap());
    bounded
        .pipeline_mut()
        .accept_frontend(parse(b"s"), FrontendHandling::Forward)
        .unwrap();
    assert_eq!(bounded.pipeline().len(), 1);
}

#[test]
fn later_valid_backend_response_is_deferred_not_illegal() {
    let mut pipeline = bounded(3);
    let first = forwarded_id(
        pipeline
            .accept_frontend(parse(b"s"), FrontendHandling::Forward)
            .unwrap(),
    );
    assert_eq!(first, first);
    pipeline
        .accept_frontend(bind(), FrontendHandling::Forward)
        .unwrap();
    assert!(matches!(
        pipeline
            .accept_backend(BackendMessage::BindComplete)
            .unwrap(),
        BackendAction::Deferred(BackendMessage::BindComplete)
    ));
}
