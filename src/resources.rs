//! Branded prepared-statement and portal resources with proxy name rewriting.

use std::{cell::Cell, collections::HashSet, marker::PhantomData};

use bytes::Bytes;

use crate::codec::{Bind, Close, Describe, DescribeTarget, Execute, Parse};

/// Runs an operation with a fresh resource brand which cannot escape the closure.
pub fn with_resources<R>(operation: impl for<'id> FnOnce(ResourceScope<'id>) -> R) -> R {
    operation(ResourceScope {
        statements: HashSet::new(),
        portals: HashSet::new(),
        _brand: PhantomData,
    })
}

/// Connection-local statement and portal namespaces.
#[derive(Debug)]
pub struct ResourceScope<'id> {
    statements: HashSet<Bytes>,
    portals: HashSet<Bytes>,
    _brand: PhantomData<Cell<&'id ()>>,
}

/// A prepared statement tied to one generative connection brand.
#[derive(Debug)]
pub struct PreparedStatement<'id> {
    client_name: Bytes,
    upstream_name: Bytes,
    _brand: PhantomData<Cell<&'id ()>>,
}

/// A bound portal tied to the same brand as its statement.
#[derive(Debug)]
pub struct Portal<'id> {
    client_name: Bytes,
    upstream_name: Bytes,
    _brand: PhantomData<Cell<&'id ()>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceError {
    StatementNameCollision,
    PortalNameCollision,
    UnknownStatement,
    UnknownPortal,
}

impl<'id> ResourceScope<'id> {
    /// Allocates a statement token and reconstructable upstream `Parse` message.
    ///
    /// # Errors
    ///
    /// Rejects duplicate upstream statement names.
    pub fn prepare(
        &mut self,
        client_name: Bytes,
        upstream_name: Bytes,
        query: Bytes,
        parameter_types: Vec<u32>,
    ) -> Result<(PreparedStatement<'id>, Parse), ResourceError> {
        if !self.statements.insert(upstream_name.clone()) {
            return Err(ResourceError::StatementNameCollision);
        }
        let statement = PreparedStatement {
            client_name,
            upstream_name: upstream_name.clone(),
            _brand: PhantomData,
        };
        let message = Parse {
            statement: upstream_name,
            query,
            parameter_types,
        };
        Ok((statement, message))
    }

    /// Binds a branded statement into a rewritten portal namespace.
    ///
    /// # Errors
    ///
    /// Rejects statements not present in this scope and duplicate portal names.
    pub fn bind(
        &mut self,
        statement: &PreparedStatement<'id>,
        client_name: Bytes,
        upstream_name: Bytes,
        parameter_formats: Vec<i16>,
        parameters: Vec<Option<Bytes>>,
        result_formats: Vec<i16>,
    ) -> Result<(Portal<'id>, Bind), ResourceError> {
        if !self.statements.contains(&statement.upstream_name) {
            return Err(ResourceError::UnknownStatement);
        }
        if !self.portals.insert(upstream_name.clone()) {
            return Err(ResourceError::PortalNameCollision);
        }
        let portal = Portal {
            client_name,
            upstream_name: upstream_name.clone(),
            _brand: PhantomData,
        };
        let message = Bind {
            portal: upstream_name,
            statement: statement.upstream_name.clone(),
            parameter_formats,
            parameters,
            result_formats,
        };
        Ok((portal, message))
    }

    /// Closes a statement and removes its upstream name from this scope.
    ///
    /// # Errors
    ///
    /// Rejects a token which has already been closed.
    pub fn close_statement(
        &mut self,
        statement: PreparedStatement<'id>,
    ) -> Result<Close, ResourceError> {
        if !self.statements.remove(&statement.upstream_name) {
            return Err(ResourceError::UnknownStatement);
        }
        Ok(Close {
            target: DescribeTarget::Statement,
            name: statement.upstream_name,
        })
    }

    /// Closes a portal and removes its upstream name from this scope.
    ///
    /// # Errors
    ///
    /// Rejects a token which has already been closed.
    pub fn close_portal(&mut self, portal: Portal<'id>) -> Result<Close, ResourceError> {
        if !self.portals.remove(&portal.upstream_name) {
            return Err(ResourceError::UnknownPortal);
        }
        Ok(Close {
            target: DescribeTarget::Portal,
            name: portal.upstream_name,
        })
    }
}

impl PreparedStatement<'_> {
    #[must_use]
    pub fn client_name(&self) -> &[u8] {
        &self.client_name
    }

    #[must_use]
    pub fn upstream_name(&self) -> &[u8] {
        &self.upstream_name
    }

    #[must_use]
    pub fn describe(&self) -> Describe {
        Describe {
            target: DescribeTarget::Statement,
            name: self.upstream_name.clone(),
        }
    }
}

impl Portal<'_> {
    #[must_use]
    pub fn client_name(&self) -> &[u8] {
        &self.client_name
    }

    #[must_use]
    pub fn upstream_name(&self) -> &[u8] {
        &self.upstream_name
    }

    #[must_use]
    pub fn describe(&self) -> Describe {
        Describe {
            target: DescribeTarget::Portal,
            name: self.upstream_name.clone(),
        }
    }

    #[must_use]
    pub fn execute(&self, max_rows: i32) -> Execute {
        Execute {
            portal: self.upstream_name.clone(),
            max_rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branded_resources_rewrite_names_without_losing_bind_details() {
        with_resources(|mut resources| {
            let (statement, parse) = resources
                .prepare(
                    Bytes::from_static(b"client_statement"),
                    Bytes::from_static(b"proxy_7_statement"),
                    Bytes::from_static(b"select $1::int4"),
                    vec![23],
                )
                .unwrap();
            assert_eq!(statement.client_name(), b"client_statement");
            assert_eq!(parse.statement, Bytes::from_static(b"proxy_7_statement"));

            let (portal, bind) = resources
                .bind(
                    &statement,
                    Bytes::from_static(b"client_portal"),
                    Bytes::from_static(b"proxy_7_portal"),
                    vec![1],
                    vec![Some(Bytes::from_static(b"\0\0\0*"))],
                    vec![1],
                )
                .unwrap();
            assert_eq!(bind.statement, Bytes::from_static(b"proxy_7_statement"));
            assert_eq!(bind.portal, Bytes::from_static(b"proxy_7_portal"));
            assert_eq!(bind.parameter_formats, [1]);
            assert_eq!(bind.result_formats, [1]);
            assert_eq!(portal.execute(0).portal, bind.portal);

            resources.close_portal(portal).unwrap();
            resources.close_statement(statement).unwrap();
        });
    }
}
