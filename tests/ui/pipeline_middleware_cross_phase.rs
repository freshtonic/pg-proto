use pg_proto::grammar::backend;

fn replace_parse_with_bind(
    _message: backend::ParseResponseInternalMessage,
    replacement: backend::BindResponseInternalMessage,
) -> backend::ParseResponseInternalMessage {
    replacement
}

fn main() {}
