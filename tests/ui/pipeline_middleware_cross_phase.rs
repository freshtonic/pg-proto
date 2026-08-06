use pg_proto::pipeline::{PipelineBackendMessage, phase};

fn replace_parse_with_bind(
    _message: PipelineBackendMessage<phase::Parse>,
    replacement: PipelineBackendMessage<phase::Bind>,
) -> PipelineBackendMessage<phase::Parse> {
    replacement
}

fn main() {}
