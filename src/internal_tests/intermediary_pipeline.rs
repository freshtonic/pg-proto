//! Deterministic coverage for bounded intermediary pipeline orchestration.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    codec::{
        BackendMessage, Bind, Close, CopyResponse, DataRow, Describe, DescribeTarget,
        DiagnosticResponse, Execute, FrontendMessage, Parse, TransactionStatus,
    },
    demux::Demux,
    grammar::backend,
    intermediary::SessionPair,
    middleware::{AsynchronousBackendMessage, MessageMiddleware, MessageMiddlewareExt, Middleware},
    pipeline::{
        BackendAction, BackendPipelineMiddleware, BoundedPipeline, FrontendAction,
        FrontendAdmission, FrontendHandling, FrontendPipelineMiddleware, FrontendProjectionError,
        NoPipeline, Pipeline, PipelineState, PipelineWireAdapter,
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
        other @ FrontendAction::Discard { .. } => {
            panic!("expected forwarding action, got {other:?}")
        }
    }
}

fn local_id(admission: FrontendAdmission) -> pg_proto::pipeline::OperationId {
    match admission.into_action() {
        FrontendAction::Discard { id } => id,
        other @ FrontendAction::Forward { .. } => {
            panic!("expected discard action, got {other:?}")
        }
    }
}

fn bounded(limit: usize) -> Pipeline<BoundedPipeline> {
    Pipeline::new(BoundedPipeline::new(limit).unwrap())
}

#[derive(Default)]
struct TypedDispatchPolicy;

impl FrontendPipelineMiddleware<Vec<&'static str>> for TypedDispatchPolicy {
    type Error = Infallible;

    async fn frontend_ready(
        &mut self,
        state: &mut Vec<&'static str>,
        _message: backend::ReadyExternalMessage,
    ) -> Result<backend::ReadyExternalMessage, Self::Error> {
        state.push("frontend-ready-before");
        tokio::task::yield_now().await;
        state.push("frontend-ready-after");
        Ok(backend::ReadyExternalMessage::try_from(parse(b"rewritten"))
            .expect("Parse is legal while ready"))
    }

    async fn frontend_building(
        &mut self,
        state: &mut Vec<&'static str>,
        message: backend::BuildingExternalMessage,
    ) -> Result<backend::BuildingExternalMessage, Self::Error> {
        state.push("frontend-building");
        Ok(message)
    }
}

impl BackendPipelineMiddleware<Vec<&'static str>> for TypedDispatchPolicy {
    type Error = &'static str;

    async fn backend_parse_response(
        &mut self,
        state: &mut Vec<&'static str>,
        _message: backend::ParseResponseInternalMessage,
    ) -> Result<backend::ParseResponseInternalMessage, Self::Error> {
        state.push("backend-parse");
        Ok(backend::ParseResponseInternalMessage::try_from(error())
            .expect("ErrorResponse is legal for ParseResponse"))
    }
}

#[tokio::test]
async fn runtime_pipeline_dispatches_to_compile_time_checked_phase_hooks() {
    let mut pipeline = bounded(4);
    let mut middleware = Middleware::new(Vec::new(), TypedDispatchPolicy);

    let action = pipeline
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::Query(Bytes::from_static(b"select secret")),
            FrontendHandling::Forward,
        )
        .await
        .expect("ready middleware replacement is legal")
        .into_action();
    assert!(matches!(
        action,
        FrontendAction::Forward {
            message: FrontendMessage::Parse(_),
            ..
        }
    ));

    pipeline
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::Sync,
            FrontendHandling::Forward,
        )
        .await
        .expect("building middleware accepts Sync");
    assert!(matches!(
        pipeline
            .accept_backend_typed(&mut middleware, BackendMessage::ParseComplete)
            .await
            .expect("Parse response middleware replacement is legal"),
        BackendAction::Emit(BackendMessage::ErrorResponse(_))
    ));
    assert_eq!(pipeline.state(), PipelineState::Ready);
    pipeline
        .accept_backend_typed(
            &mut middleware,
            BackendMessage::ReadyForQuery(TransactionStatus::Idle),
        )
        .await
        .expect("Sync response is legal");

    assert_eq!(
        middleware.state(),
        &[
            "frontend-ready-before",
            "frontend-ready-after",
            "frontend-building",
            "backend-parse",
        ]
    );
    assert!(pipeline.is_empty());
}

#[tokio::test]
async fn deferred_backend_messages_are_intercepted_only_when_retried_at_head() {
    #[derive(Default)]
    struct Counts;

    impl BackendPipelineMiddleware<usize> for Counts {
        type Error = Infallible;

        async fn backend_bind_response(
            &mut self,
            calls: &mut usize,
            message: backend::BindResponseInternalMessage,
        ) -> Result<backend::BindResponseInternalMessage, Self::Error> {
            *calls += 1;
            Ok(message)
        }
    }

    let mut pipeline = bounded(3);
    pipeline
        .accept_frontend(parse(b"s"), FrontendHandling::Forward)
        .unwrap();
    pipeline
        .accept_frontend(bind(), FrontendHandling::Forward)
        .unwrap();
    let mut middleware = Middleware::new(0, Counts);

    let deferred = pipeline
        .accept_backend_typed(&mut middleware, BackendMessage::BindComplete)
        .await
        .expect("later Bind response is deferred");
    assert!(matches!(deferred, BackendAction::Deferred(_)));
    assert_eq!(*middleware.state(), 0);

    pipeline
        .accept_backend_typed(&mut middleware, BackendMessage::ParseComplete)
        .await
        .expect("Parse completes");
    pipeline
        .accept_backend_typed(&mut middleware, BackendMessage::BindComplete)
        .await
        .expect("retried Bind response is emitted");
    assert_eq!(*middleware.state(), 1);
}

#[tokio::test]
async fn direction_wide_middleware_adapts_to_typed_pipeline_dispatch() {
    struct DirectionWide;

    impl MessageMiddleware<FrontendMessage, usize> for DirectionWide {
        type Error = Infallible;

        async fn intercept(
            &mut self,
            calls: &mut usize,
            message: FrontendMessage,
        ) -> Result<FrontendMessage, Self::Error> {
            *calls += 1;
            Ok(message)
        }
    }

    impl MessageMiddleware<BackendMessage, usize> for DirectionWide {
        type Error = Infallible;

        async fn intercept(
            &mut self,
            calls: &mut usize,
            message: BackendMessage,
        ) -> Result<BackendMessage, Self::Error> {
            *calls += 1;
            Ok(message)
        }
    }

    let mut pipeline = bounded(2);
    let mut middleware = Middleware::new(0, PipelineWireAdapter::new(DirectionWide));
    pipeline
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::Query(Bytes::from_static(b"select 1")),
            FrontendHandling::Forward,
        )
        .await
        .expect("direction-wide frontend policy remains phase legal");
    pipeline
        .accept_backend_typed(
            &mut middleware,
            BackendMessage::ReadyForQuery(TransactionStatus::Idle),
        )
        .await
        .expect("direction-wide backend policy remains operation legal");
    assert_eq!(*middleware.state(), 2);
}

#[tokio::test]
async fn typed_pipeline_middleware_composes_in_order_with_shared_state() {
    struct Record(&'static str);

    impl FrontendPipelineMiddleware<Vec<&'static str>> for Record {
        type Error = Infallible;

        async fn frontend_ready(
            &mut self,
            calls: &mut Vec<&'static str>,
            message: backend::ReadyExternalMessage,
        ) -> Result<backend::ReadyExternalMessage, Self::Error> {
            calls.push(self.0);
            Ok(message)
        }
    }

    let mut pipeline = bounded(1);
    let mut middleware = Middleware::new(Vec::new(), Record("first").then(Record("second")));

    pipeline
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::Query(Bytes::from_static(b"select 1")),
            FrontendHandling::Forward,
        )
        .await
        .expect("composed typed pipeline middleware accepts Query");

    assert_eq!(middleware.state(), &["first", "second"]);
}

#[tokio::test]
async fn capacity_skips_typed_middleware_but_async_backend_traffic_does_not() {
    struct Counts;

    impl FrontendPipelineMiddleware<usize> for Counts {
        type Error = Infallible;

        async fn frontend_ready(
            &mut self,
            calls: &mut usize,
            message: backend::ReadyExternalMessage,
        ) -> Result<backend::ReadyExternalMessage, Self::Error> {
            *calls += 1;
            Ok(message)
        }
    }

    impl BackendPipelineMiddleware<usize> for Counts {
        type Error = Infallible;

        async fn backend_asynchronous(
            &mut self,
            calls: &mut usize,
            message: AsynchronousBackendMessage,
        ) -> Result<AsynchronousBackendMessage, Self::Error> {
            *calls += 1;
            Ok(message)
        }
    }

    let mut pipeline = bounded(1);
    pipeline
        .accept_frontend(parse(b"full"), FrontendHandling::Forward)
        .unwrap();
    let mut middleware = Middleware::new(0, Counts);
    let body = Bytes::from(vec![7_u8; 2 * 1024 * 1024]);
    let pointer = body.as_ptr();
    assert!(matches!(
        pipeline
            .accept_frontend_typed(
                &mut middleware,
                FrontendMessage::Query(body),
                FrontendHandling::Forward,
            )
            .await
            .unwrap_err(),
        pg_proto::pipeline::PipelineMiddlewareError::Projection(
            FrontendProjectionError::Capacity(message)
        ) if matches!(&*message, FrontendMessage::Query(body) if body.as_ptr() == pointer)
    ));
    assert_eq!(*middleware.state(), 0);

    pipeline
        .accept_backend_typed(
            &mut middleware,
            BackendMessage::NoticeResponse(DiagnosticResponse { fields: vec![] }),
        )
        .await
        .expect("asynchronous traffic is always emittable");
    assert_eq!(*middleware.state(), 1);
    assert_eq!(pipeline.len(), 1);
}

#[tokio::test]
async fn copy_hooks_preserve_simple_and_extended_origins() {
    struct CopyOrigins;

    impl FrontendPipelineMiddleware<Vec<&'static str>> for CopyOrigins {
        type Error = Infallible;

        async fn frontend_simple_copy_in(
            &mut self,
            origins: &mut Vec<&'static str>,
            message: backend::SimpleCopyInExternalMessage,
        ) -> Result<backend::SimpleCopyInExternalMessage, Self::Error> {
            origins.push("simple");
            Ok(message)
        }

        async fn frontend_extended_copy_in(
            &mut self,
            origins: &mut Vec<&'static str>,
            message: backend::ExtendedCopyInExternalMessage,
        ) -> Result<backend::ExtendedCopyInExternalMessage, Self::Error> {
            origins.push("extended");
            Ok(message)
        }
    }

    let copy = CopyResponse {
        overall_format: 0,
        column_formats: vec![],
    };
    let mut middleware = Middleware::new(Vec::new(), CopyOrigins);

    let mut simple = bounded(3);
    simple
        .accept_frontend(
            FrontendMessage::Query(Bytes::from_static(b"copy records from stdin")),
            FrontendHandling::Forward,
        )
        .unwrap();
    simple
        .accept_backend(BackendMessage::CopyInResponse(copy.clone()))
        .unwrap();
    simple
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::CopyData(Bytes::from_static(b"simple\n")),
            FrontendHandling::Forward,
        )
        .await
        .expect("simple COPY-IN dispatches");

    let mut extended = bounded(5);
    for message in [parse(b"copy"), bind(), execute()] {
        extended
            .accept_frontend(message, FrontendHandling::Forward)
            .unwrap();
    }
    extended
        .accept_backend(BackendMessage::ParseComplete)
        .unwrap();
    extended
        .accept_backend(BackendMessage::BindComplete)
        .unwrap();
    extended
        .accept_backend(BackendMessage::CopyInResponse(copy))
        .unwrap();
    extended
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::CopyData(Bytes::from_static(b"extended\n")),
            FrontendHandling::Forward,
        )
        .await
        .expect("extended COPY-IN dispatches");

    assert_eq!(middleware.state(), &["simple", "extended"]);
}

#[test]
fn extended_copy_in_uses_the_post_copy_sync_as_its_recovery_barrier() {
    let mut pipeline = bounded(8);
    for message in [bind(), execute(), FrontendMessage::Sync] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .expect("extended COPY start is accepted");
    }
    pipeline
        .accept_backend(BackendMessage::BindComplete)
        .expect("Bind completes");
    pipeline
        .accept_backend(BackendMessage::CopyInResponse(CopyResponse {
            overall_format: 0,
            column_formats: vec![0],
        }))
        .expect("COPY IN starts");
    for message in [
        FrontendMessage::CopyData(Bytes::from_static(b"1\n")),
        FrontendMessage::CopyDone,
        FrontendMessage::Sync,
    ] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .expect("COPY data and completion are accepted");
    }
    pipeline
        .accept_backend(BackendMessage::CommandComplete(Bytes::from_static(
            b"COPY 1",
        )))
        .expect("COPY completes");
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .expect("post-COPY Sync restores readiness");

    pipeline
        .accept_frontend(parse(b"after-copy"), FrontendHandling::Forward)
        .expect("a new statement is accepted after COPY");
    assert!(matches!(
        pipeline
            .accept_backend(BackendMessage::ParseComplete)
            .expect("new statement response is legal"),
        BackendAction::Emit(BackendMessage::ParseComplete)
    ));
}

#[test]
fn extended_copy_in_data_error_recovers_after_copy_done() {
    let mut pipeline = bounded(7);
    for message in [bind(), execute(), FrontendMessage::Sync] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .expect("extended COPY start is accepted");
    }
    pipeline
        .accept_backend(BackendMessage::BindComplete)
        .expect("Bind completes");
    pipeline
        .accept_backend(BackendMessage::CopyInResponse(CopyResponse {
            overall_format: 0,
            column_formats: vec![0],
        }))
        .expect("COPY IN starts");
    for message in [FrontendMessage::CopyDone, FrontendMessage::Sync] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .expect("COPY completion is accepted");
    }
    assert!(matches!(
        pipeline
            .accept_backend(error())
            .expect("invalid copied data produces a legal ErrorResponse"),
        BackendAction::Emit(BackendMessage::ErrorResponse(_))
    ));
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .expect("post-COPY Sync recovers from the data error");
    pipeline
        .accept_frontend(parse(b"after-copy-error"), FrontendHandling::Forward)
        .expect("new work is legal after recovery");
    assert!(matches!(
        pipeline
            .accept_backend(BackendMessage::ParseComplete)
            .expect("new statement response is emitted"),
        BackendAction::Emit(BackendMessage::ParseComplete)
    ));
}

#[tokio::test]
async fn backend_copy_responses_dispatch_through_exact_generated_subphases() {
    struct CopyResponses;

    impl BackendPipelineMiddleware<Vec<&'static str>> for CopyResponses {
        type Error = Infallible;

        async fn backend_simple_copy_out(
            &mut self,
            phases: &mut Vec<&'static str>,
            _message: backend::SimpleCopyOutInternalMessage,
        ) -> Result<backend::SimpleCopyOutInternalMessage, Self::Error> {
            phases.push("copy-out");
            Ok(
                backend::SimpleCopyOutInternalMessage::try_from(BackendMessage::CopyDone)
                    .expect("CopyDone is legal in SimpleCopyOut"),
            )
        }

        async fn backend_simple_copy_out_done(
            &mut self,
            phases: &mut Vec<&'static str>,
            message: backend::SimpleCopyOutDoneInternalMessage,
        ) -> Result<backend::SimpleCopyOutDoneInternalMessage, Self::Error> {
            phases.push("copy-out-done");
            Ok(message)
        }

        async fn backend_simple_copy_ready(
            &mut self,
            phases: &mut Vec<&'static str>,
            message: backend::SimpleCopyReadyInternalMessage,
        ) -> Result<backend::SimpleCopyReadyInternalMessage, Self::Error> {
            phases.push("copy-ready");
            Ok(message)
        }
    }

    let mut pipeline = bounded(2);
    pipeline
        .accept_frontend(
            FrontendMessage::Query(Bytes::from_static(b"copy records to stdout")),
            FrontendHandling::Forward,
        )
        .unwrap();
    let mut middleware = Middleware::new(Vec::new(), CopyResponses);
    let copy = CopyResponse {
        overall_format: 0,
        column_formats: vec![],
    };

    pipeline
        .accept_backend_typed(&mut middleware, BackendMessage::CopyOutResponse(copy))
        .await
        .expect("Query enters SimpleCopyOut");
    assert!(matches!(
        pipeline
            .accept_backend_typed(
                &mut middleware,
                BackendMessage::CopyData(Bytes::from_static(b"row\n")),
            )
            .await
            .expect("COPY data is rewritten within its exact phase"),
        BackendAction::Emit(BackendMessage::CopyDone)
    ));
    pipeline
        .accept_backend_typed(
            &mut middleware,
            BackendMessage::CommandComplete(Bytes::from_static(b"COPY 1")),
        )
        .await
        .expect("command completion follows CopyDone");
    pipeline
        .accept_backend_typed(
            &mut middleware,
            BackendMessage::ReadyForQuery(TransactionStatus::Idle),
        )
        .await
        .expect("ready follows copy command completion");

    assert_eq!(
        middleware.state(),
        &["copy-out", "copy-out-done", "copy-ready"]
    );
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

#[tokio::test]
async fn typed_admission_returns_large_payload_without_copying_or_retaining_it() {
    let body = Bytes::from(vec![7_u8; 2 * 1024 * 1024]);
    let pointer = body.as_ptr();
    let mut pipeline = bounded(2);
    let mut middleware = Middleware::new((), pg_proto::middleware::Identity);
    let admission = pipeline
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::Query(body),
            FrontendHandling::Forward,
        )
        .await
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
fn backend_batch_preparation_is_atomic_and_span_preserving() {
    let mut pipeline = bounded(2);
    pipeline
        .accept_frontend(
            FrontendMessage::Query(Bytes::from_static(b"select 1")),
            FrontendHandling::Forward,
        )
        .unwrap();
    let sources = vec![
        BackendMessage::DataRow(DataRow {
            columns: vec![Some(Bytes::from_static(b"encrypted"))],
        }),
        BackendMessage::CommandComplete(Bytes::from_static(b"SELECT 1")),
    ];
    let replacements = vec![
        BackendMessage::DataRow(DataRow {
            columns: vec![Some(Bytes::from_static(b"clear"))],
        }),
        BackendMessage::CommandComplete(Bytes::from_static(b"SELECT 1")),
    ];
    let prepared = pipeline
        .prepare_backend_replacements(&sources, &replacements)
        .unwrap();
    assert_eq!(
        pipeline.len(),
        1,
        "preparation must not mutate the live ledger"
    );
    pipeline = prepared;
    assert_eq!(pipeline.len(), 1, "command completion awaits ReadyForQuery");

    let before = pipeline.len();
    assert!(
        pipeline
            .prepare_backend_replacements(
                &[BackendMessage::ReadyForQuery(TransactionStatus::Idle)],
                &[BackendMessage::DataRow(DataRow { columns: vec![] })],
            )
            .is_err()
    );
    assert_eq!(pipeline.len(), before, "failed preparation is atomic");
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
fn completing_an_earlier_sync_does_not_rewind_the_projected_frontend_state() {
    let mut pipeline = bounded(8);
    for message in [
        parse(b"first"),
        FrontendMessage::Sync,
        parse(b"second"),
        describe(),
    ] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .unwrap();
    }

    pipeline
        .accept_backend(BackendMessage::ParseComplete)
        .unwrap();
    pipeline
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        .unwrap();

    assert_eq!(pipeline.state(), PipelineState::Extended);
    pipeline
        .accept_frontend(FrontendMessage::Sync, FrontendHandling::Forward)
        .unwrap();
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
    assert!(matches!(
        pipeline.try_emit_local(rejected, error()).unwrap(),
        BackendAction::Deferred(_)
    ));
    assert!(matches!(
        pipeline
            .accept_frontend(describe(), FrontendHandling::Forward)
            .unwrap()
            .into_action(),
        FrontendAction::Discard { .. }
    ));
    pipeline
        .accept_frontend(FrontendMessage::Sync, FrontendHandling::Forward)
        .unwrap();
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
    assert!(matches!(
        pipeline.try_emit_local(rejected, error()).unwrap(),
        BackendAction::Emit(BackendMessage::ErrorResponse(_))
    ));
    assert!(matches!(
        pipeline
            .accept_frontend(bind(), FrontendHandling::Forward)
            .unwrap()
            .into_action(),
        FrontendAction::Discard { .. }
    ));
    pipeline
        .accept_frontend(FrontendMessage::Sync, FrontendHandling::Forward)
        .unwrap();
    assert_eq!(pipeline.state(), PipelineState::Ready);
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
fn an_error_before_an_accepted_sync_preserves_later_cycle_projection() {
    let mut pipeline = bounded(8);
    for message in [parse(b"bad"), bind(), FrontendMessage::Sync, parse(b"next")] {
        pipeline
            .accept_frontend(message, FrontendHandling::Forward)
            .unwrap();
    }

    pipeline.accept_backend(error()).unwrap();

    assert_eq!(pipeline.state(), PipelineState::Extended);
    pipeline
        .accept_frontend(FrontendMessage::Sync, FrontendHandling::Forward)
        .unwrap();
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
        pipeline
            .accept_backend(item.into_backend_message())
            .unwrap(),
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
    let old = SessionPair::new(1_u8, 2_u8);
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

#[tokio::test]
async fn typed_and_untyped_paths_commit_the_same_prepared_decisions() {
    let mut untyped = bounded(2);
    let mut typed = bounded(2);
    let mut middleware = Middleware::new((), pg_proto::middleware::Identity);

    let untyped_frontend = untyped
        .accept_frontend(parse(b"parity"), FrontendHandling::Forward)
        .unwrap();
    let typed_frontend = typed
        .accept_frontend_typed(&mut middleware, parse(b"parity"), FrontendHandling::Forward)
        .await
        .unwrap();
    assert_eq!(typed_frontend, untyped_frontend);

    let untyped_waiting = untyped
        .accept_frontend(bind(), FrontendHandling::Forward)
        .unwrap();
    let typed_waiting = typed
        .accept_frontend_typed(&mut middleware, bind(), FrontendHandling::Forward)
        .await
        .unwrap();
    assert_eq!(typed_waiting, untyped_waiting);

    let untyped_deferred = untyped
        .accept_backend(BackendMessage::BindComplete)
        .unwrap();
    let typed_deferred = typed
        .accept_backend_typed(&mut middleware, BackendMessage::BindComplete)
        .await
        .unwrap();
    assert_eq!(typed_deferred, untyped_deferred);

    let untyped_backend = untyped
        .accept_backend(BackendMessage::ParseComplete)
        .unwrap();
    let typed_backend = typed
        .accept_backend_typed(&mut middleware, BackendMessage::ParseComplete)
        .await
        .unwrap();
    assert_eq!(typed_backend, untyped_backend);
    assert_eq!(
        typed
            .accept_backend_typed(&mut middleware, BackendMessage::BindComplete)
            .await
            .unwrap(),
        untyped
            .accept_backend(BackendMessage::BindComplete)
            .unwrap()
    );
    assert_eq!(typed.state(), untyped.state());
    assert_eq!(typed.len(), untyped.len());
}

#[tokio::test]
async fn rejected_middleware_does_not_commit_a_prepared_decision() {
    struct Reject;

    impl FrontendPipelineMiddleware<()> for Reject {
        type Error = &'static str;

        async fn frontend_ready(
            &mut self,
            _state: &mut (),
            _message: backend::ReadyExternalMessage,
        ) -> Result<backend::ReadyExternalMessage, Self::Error> {
            Err("rejected")
        }
    }

    let mut pipeline = bounded(2);
    let mut middleware = Middleware::new((), Reject);
    let state = pipeline.state();
    let error = pipeline
        .accept_frontend_typed(
            &mut middleware,
            parse(b"rejected"),
            FrontendHandling::Forward,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        pg_proto::pipeline::PipelineMiddlewareError::Middleware("rejected")
    ));
    assert_eq!(pipeline.state(), state);
    assert!(pipeline.is_empty());

    let accepted_after_rejection = pipeline
        .accept_frontend(parse(b"accepted"), FrontendHandling::Forward)
        .unwrap();
    let first_fresh_admission = bounded(2)
        .accept_frontend(parse(b"accepted"), FrontendHandling::Forward)
        .unwrap();
    assert_eq!(accepted_after_rejection, first_fresh_admission);
}
