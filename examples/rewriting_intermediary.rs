//! Stateful, checked frontend and backend message rewriting.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    codec::{
        BackendMessage, Bind, Describe, DescribeTarget, FieldDescription, FrontendMessage, Parse,
        RowDescription,
    },
    grammar::{backend, frontend},
    middleware::{MessageMiddleware, Middleware},
};

#[derive(Default)]
struct RewriteStatistics {
    frontend: usize,
    backend: usize,
}

struct Rewriter;

impl MessageMiddleware<FrontendMessage, RewriteStatistics> for Rewriter {
    type Error = Infallible;

    fn intercept(
        &mut self,
        statistics: &mut RewriteStatistics,
        message: FrontendMessage,
    ) -> Result<FrontendMessage, Self::Error> {
        statistics.frontend += 1;
        Ok(match message {
            FrontendMessage::Parse(mut parse) => {
                parse.query = Bytes::from_static(
                    b"select amount from ledger where account = $1 and visible = true",
                );
                FrontendMessage::Parse(parse)
            }
            message => message,
        })
    }
}

impl MessageMiddleware<BackendMessage, RewriteStatistics> for Rewriter {
    type Error = Infallible;

    fn intercept(
        &mut self,
        statistics: &mut RewriteStatistics,
        message: BackendMessage,
    ) -> Result<BackendMessage, Self::Error> {
        statistics.backend += 1;
        Ok(match message {
            BackendMessage::RowDescription(mut rows) => {
                rows.fields[0].name = Bytes::from_static(b"visible_amount");
                BackendMessage::RowDescription(rows)
            }
            message => message,
        })
    }
}

fn main() {
    let mut middleware = Middleware::new(RewriteStatistics::default(), Rewriter);

    let parse = FrontendMessage::Parse(Parse {
        statement: Bytes::from_static(b"report"),
        query: Bytes::from_static(b"select amount from ledger where account = $1"),
        parameter_types: vec![25],
    });
    let parse = middleware
        .intercept_checked(&backend::RuntimeState::Ready, parse)
        .unwrap();

    let bind = FrontendMessage::Bind(Bind {
        portal: Bytes::from_static(b"page-1"),
        statement: Bytes::from_static(b"report"),
        parameter_formats: vec![0],
        parameters: vec![Some(Bytes::from_static(b"assets"))],
        result_formats: vec![1],
    });
    let bind = middleware
        .intercept_checked(&backend::RuntimeState::Building, bind)
        .unwrap();

    let describe = FrontendMessage::Describe(Describe {
        target: DescribeTarget::Portal,
        name: Bytes::from_static(b"page-1"),
    });
    let describe = middleware
        .intercept_checked(&backend::RuntimeState::Building, describe)
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
    let rows = middleware
        .intercept_checked(&frontend::RuntimeState::Simple, rows)
        .unwrap();

    // Every modified value remains reconstructable as a checked wire frame.
    parse.to_frame().unwrap();
    bind.to_frame().unwrap();
    describe.to_frame().unwrap();
    rows.to_frame().unwrap();
    assert_eq!(middleware.state().frontend, 3);
    assert_eq!(middleware.state().backend, 1);
}
