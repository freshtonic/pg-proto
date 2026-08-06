//! Stateful, checked frontend and backend message rewriting.

use std::convert::Infallible;

use bytes::Bytes;
use pg_proto::{
    codec::{
        BackendMessage, Bind, Describe, DescribeTarget, FieldDescription, FrontendMessage, Parse,
        RowDescription,
    },
    grammar::{backend, frontend},
    middleware::{ClientRole, Middleware, ServerRole, TypedMiddleware},
};

#[derive(Default)]
struct RewriteStatistics {
    frontend: usize,
    backend: usize,
}

struct Rewriter;

impl TypedMiddleware<ClientRole, backend::Ready, backend::ReadyExternalMessage, RewriteStatistics>
    for Rewriter
{
    type Error = Infallible;

    fn intercept_typed(
        &mut self,
        statistics: &mut RewriteStatistics,
        message: backend::ReadyExternalMessage,
    ) -> Result<backend::ReadyExternalMessage, Self::Error> {
        statistics.frontend += 1;
        Ok(match message {
            backend::ReadyExternalMessage::Parse(message) => {
                let mapped = message.try_map_wire(|message| match message {
                    FrontendMessage::Parse(mut parse) => {
                        parse.query = Bytes::from_static(
                            b"select amount from ledger where account = $1 and visible = true",
                        );
                        FrontendMessage::Parse(parse)
                    }
                    _ => unreachable!("typed Parse transition contains Parse"),
                });
                match mapped {
                    Ok(message) => backend::ReadyExternalMessage::Parse(message),
                    Err(_) => unreachable!("query mutation preserves the Parse transition"),
                }
            }
            message => message,
        })
    }
}

impl
    TypedMiddleware<
        ClientRole,
        backend::Building,
        backend::BuildingExternalMessage,
        RewriteStatistics,
    > for Rewriter
{
    type Error = Infallible;

    fn intercept_typed(
        &mut self,
        statistics: &mut RewriteStatistics,
        message: backend::BuildingExternalMessage,
    ) -> Result<backend::BuildingExternalMessage, Self::Error> {
        statistics.frontend += 1;
        Ok(message)
    }
}

impl
    TypedMiddleware<
        ServerRole,
        frontend::Simple,
        frontend::SimpleExternalMessage,
        RewriteStatistics,
    > for Rewriter
{
    type Error = Infallible;

    fn intercept_typed(
        &mut self,
        statistics: &mut RewriteStatistics,
        message: frontend::SimpleExternalMessage,
    ) -> Result<frontend::SimpleExternalMessage, Self::Error> {
        statistics.backend += 1;
        Ok(match message {
            frontend::SimpleExternalMessage::Continue(message) => {
                let mapped = message.try_map_wire(|message| match message {
                    BackendMessage::RowDescription(mut rows) => {
                        rows.fields[0].name = Bytes::from_static(b"visible_amount");
                        BackendMessage::RowDescription(rows)
                    }
                    message => message,
                });
                frontend::SimpleExternalMessage::Continue(match mapped {
                    Ok(message) => message,
                    Err(_) => unreachable!("row-description mutation preserves Continue"),
                })
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
    let parse = backend::ReadyExternalMessage::try_from(parse).unwrap();
    let parse = middleware
        .intercept_typed::<ClientRole, backend::Ready, _>(parse)
        .unwrap()
        .into_wire();

    let bind = FrontendMessage::Bind(Bind {
        portal: Bytes::from_static(b"page-1"),
        statement: Bytes::from_static(b"report"),
        parameter_formats: vec![0],
        parameters: vec![Some(Bytes::from_static(b"assets"))],
        result_formats: vec![1],
    });
    let bind = backend::BuildingExternalMessage::try_from(bind).unwrap();
    let bind = middleware
        .intercept_typed::<ClientRole, backend::Building, _>(bind)
        .unwrap()
        .into_wire();

    let describe = FrontendMessage::Describe(Describe {
        target: DescribeTarget::Portal,
        name: Bytes::from_static(b"page-1"),
    });
    let describe = backend::BuildingExternalMessage::try_from(describe).unwrap();
    let describe = middleware
        .intercept_typed::<ClientRole, backend::Building, _>(describe)
        .unwrap()
        .into_wire();

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
    let rows = frontend::SimpleExternalMessage::try_from(rows).unwrap();
    let rows = middleware
        .intercept_typed::<ServerRole, frontend::Simple, _>(rows)
        .unwrap()
        .into_wire();

    // Every modified value remains reconstructable as a checked wire frame.
    parse.to_frame().unwrap();
    bind.to_frame().unwrap();
    describe.to_frame().unwrap();
    rows.to_frame().unwrap();
    assert_eq!(middleware.state().frontend, 3);
    assert_eq!(middleware.state().backend, 1);
}
