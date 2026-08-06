//! Minimal bounded-pipeline policy for a `PostgreSQL` intermediary.

use bytes::Bytes;
use pg_proto::{
    codec::{BackendMessage, DiagnosticResponse, FrontendMessage, Parse, TransactionStatus},
    intermediary::Intermediary,
    pipeline::{BackendAction, BoundedPipeline, FrontendAction, FrontendHandling},
};

fn main() {
    let mut proxy = Intermediary::new((), ())
        .with_pipeline(BoundedPipeline::new(16).expect("non-zero pipeline limit"));

    let parse = FrontendMessage::Parse(Parse {
        statement: Bytes::from_static(b"blocked"),
        query: Bytes::from_static(b"select secret"),
        parameter_types: vec![],
    });
    let local_id = match proxy
        .pipeline_mut()
        .frontend_action(parse, FrontendHandling::Local)
        .expect("legal Parse")
    {
        FrontendAction::Discard { id } => id,
        FrontendAction::Forward { message, .. } => {
            // Encode `message` to the upstream transport here.
            // This transport-free example drops it only as a stand-in for sending it.
            drop(message);
            return;
        }
        FrontendAction::Backpressure(message) => {
            // Pause downstream reads and retry this same owned value later.
            // This minimal example exits, but a real intermediary must retain and retry it.
            drop(message);
            return;
        }
    };

    let local_error = BackendMessage::ErrorResponse(DiagnosticResponse { fields: vec![] });
    match proxy
        .pipeline_mut()
        .try_emit_local(local_id, local_error)
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
        .frontend_action(FrontendMessage::Sync, FrontendHandling::Forward);
    let _ = proxy
        .pipeline_mut()
        .accept_backend(BackendMessage::ReadyForQuery(TransactionStatus::Idle));
}
