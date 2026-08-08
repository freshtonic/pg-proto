//! Minimal bounded-pipeline policy for a `PostgreSQL` intermediary.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    codec::{BackendMessage, DiagnosticResponse, FrontendMessage, Parse, TransactionStatus},
    grammar::backend,
    intermediary::SessionPair,
    middleware::Middleware,
    pipeline::{
        BackendAction, BackendPipelineMiddleware, BoundedPipeline, FrontendAction,
        FrontendAdmission, FrontendHandling, FrontendPipelineMiddleware, FrontendProjectionError,
        PipelineMiddlewareError,
    },
};

struct Statistics;

impl FrontendPipelineMiddleware<usize> for Statistics {
    type Error = Infallible;

    async fn frontend_ready(
        &mut self,
        messages: &mut usize,
        message: backend::ReadyExternalMessage,
    ) -> Result<backend::ReadyExternalMessage, Self::Error> {
        *messages += 1;
        Ok(message)
    }
}

impl BackendPipelineMiddleware<usize> for Statistics {
    type Error = Infallible;

    async fn backend_parse_response(
        &mut self,
        messages: &mut usize,
        message: backend::ParseResponseInternalMessage,
    ) -> Result<backend::ParseResponseInternalMessage, Self::Error> {
        *messages += 1;
        Ok(message)
    }
}

#[tokio::main]
async fn main() {
    let mut proxy = SessionPair::new((), ())
        .with_pipeline(BoundedPipeline::new(16).expect("non-zero pipeline limit"));
    let mut middleware = Middleware::new(0, Statistics);

    let parse = FrontendMessage::Parse(Parse {
        statement: Bytes::from_static(b"blocked"),
        query: Bytes::from_static(b"select secret"),
        parameter_types: vec![],
    });
    let action = match proxy
        .pipeline_mut()
        .accept_frontend_typed(&mut middleware, parse, FrontendHandling::Local)
        .await
    {
        Ok(FrontendAdmission::Immediate(action) | FrontendAdmission::Waiting(action)) => action,
        Err(PipelineMiddlewareError::Projection(FrontendProjectionError::Capacity(message))) => {
            // Pause downstream reads and retry this same owned value later.
            // This minimal example exits, but a real intermediary must retain and retry it.
            drop(message);
            return;
        }
        Err(error) => panic!("frontend admission failed: {error:?}"),
    };
    let local_id = match action {
        FrontendAction::Discard { id } => id,
        FrontendAction::Forward { message, .. } => {
            // Encode `message` to the upstream transport here.
            // This transport-free example drops it only as a stand-in for sending it.
            drop(message);
            return;
        }
    };

    let local_error = BackendMessage::ErrorResponse(DiagnosticResponse { fields: vec![] });
    match proxy
        .pipeline_mut()
        .try_emit_local_typed(&mut middleware, local_id, local_error)
        .await
        .expect("response matches Parse")
    {
        BackendAction::Emit(message) => {
            // Encode `message` to the downstream transport here.
            // This transport-free example drops it only as a stand-in for sending it.
            drop(message);
        }
        BackendAction::Deferred(message) => {
            // An earlier response must be processed first; retry this owned value.
            // This minimal example ends, but a real intermediary must retain and retry it.
            drop(message);
        }
    }

    let _ = proxy
        .pipeline_mut()
        .accept_frontend_typed(
            &mut middleware,
            FrontendMessage::Sync,
            FrontendHandling::Forward,
        )
        .await;
    let _ = proxy
        .pipeline_mut()
        .accept_backend_typed(
            &mut middleware,
            BackendMessage::ReadyForQuery(TransactionStatus::Idle),
        )
        .await;
}
