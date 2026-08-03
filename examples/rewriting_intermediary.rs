//! A policy-neutral example of typed message inspection and replacement.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    codec::{
        BackendMessage, Bind, Describe, DescribeTarget, FieldDescription, FrontendMessage, Parse,
        RowDescription,
    },
    intermediary::Intermediary,
};

fn main() {
    let mut intermediary = Intermediary::new((), ());

    let parse = FrontendMessage::Parse(Parse {
        statement: Bytes::from_static(b"report"),
        query: Bytes::from_static(b"select amount from ledger where account = $1"),
        parameter_types: vec![25],
    });
    let parse = intermediary
        .inspect(parse, |(), (), message| {
            let FrontendMessage::Parse(mut parse) = message else {
                unreachable!("the caller selected a Parse message")
            };
            parse.query = Bytes::from_static(
                b"select amount from ledger where account = $1 and visible = true",
            );
            Ok::<_, Infallible>(FrontendMessage::Parse(parse))
        })
        .unwrap();

    let bind = FrontendMessage::Bind(Bind {
        portal: Bytes::from_static(b"page-1"),
        statement: Bytes::from_static(b"report"),
        parameter_formats: vec![0],
        parameters: vec![Some(Bytes::from_static(b"assets"))],
        result_formats: vec![1],
    });
    let bind = intermediary
        .inspect(bind, |(), (), message| Ok::<_, Infallible>(message))
        .unwrap();

    let describe = FrontendMessage::Describe(Describe {
        target: DescribeTarget::Portal,
        name: Bytes::from_static(b"page-1"),
    });
    let describe = intermediary
        .inspect(describe, |(), (), message| Ok::<_, Infallible>(message))
        .unwrap();

    let rows = BackendMessage::RowDescription(RowDescription {
        fields: vec![FieldDescription {
            name: Bytes::from_static(b"amount"),
            table_oid: 16_384,
            column: 2,
            type_oid: 1_700,
            type_size: -1,
            type_modifier: -1,
            format: 1,
        }],
    });
    let rows = intermediary
        .inspect(rows, |(), (), message| {
            let BackendMessage::RowDescription(mut rows) = message else {
                unreachable!("the caller selected a RowDescription message")
            };
            rows.fields[0].name = Bytes::from_static(b"visible_amount");
            Ok::<_, Infallible>(BackendMessage::RowDescription(rows))
        })
        .unwrap();

    // Every modified value remains reconstructable as a checked wire frame.
    parse.to_frame().unwrap();
    bind.to_frame().unwrap();
    describe.to_frame().unwrap();
    rows.to_frame().unwrap();
}
