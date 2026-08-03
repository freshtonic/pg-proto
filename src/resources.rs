//! Branded prepared-statement and portal resources with proxy name rewriting.

use std::{cell::Cell, collections::HashMap, io, marker::PhantomData};

use bytes::Bytes;

use crate::{
    Conn, Dirty,
    codec::{Bind, Close, Describe, DescribeTarget, Execute, Frame, Parse},
    session::{BoundBuilding, Building},
};

/// Runs an operation with a fresh resource brand which cannot escape the closure.
pub fn with_resources<R>(operation: impl for<'id> FnOnce(ResourceScope<'id>) -> R) -> R {
    operation(ResourceScope::new())
}

/// Runs an extended-query operation with one brand shared by its connection
/// and resource namespace.
pub fn with_connection_resources<S, P, C, R>(
    conn: Conn<S, P, C>,
    operation: impl for<'id> FnOnce(ResourceConnection<'id, S, P, C>) -> R,
) -> R {
    operation(ResourceConnection {
        conn,
        resources: ResourceScope::new(),
    })
}

/// A connection paired with its generative statement and portal namespace.
#[derive(Debug)]
pub struct ResourceConnection<'id, S, P, C> {
    conn: Conn<S, P, C>,
    resources: ResourceScope<'id>,
}

impl<S, P, C> ResourceConnection<'_, S, P, C> {
    /// Deliberately leaves resource-aware handling while retaining typestate.
    pub fn into_connection(self) -> Conn<S, P, C> {
        self.conn
    }
}

pub type PrepareResult<'id, S> = Result<
    (
        ResourceConnection<'id, S, Building, Dirty>,
        PreparedStatement<'id>,
        Frame,
    ),
    ResourceProtocolError,
>;

pub type BindResult<'id, S> = Result<
    (
        ResourceConnection<'id, S, BoundBuilding, Dirty>,
        Portal<'id>,
        Frame,
    ),
    ResourceProtocolError,
>;

/// Connection-local statement and portal namespaces.
#[derive(Debug)]
pub struct ResourceScope<'id> {
    statements: HashMap<Bytes, u64>,
    portals: HashMap<Bytes, u64>,
    next_generation: u64,
    _brand: PhantomData<Cell<&'id ()>>,
}

/// A prepared statement tied to one generative connection brand.
#[derive(Debug)]
pub struct PreparedStatement<'id> {
    client_name: Bytes,
    upstream_name: Bytes,
    generation: u64,
    _brand: PhantomData<Cell<&'id ()>>,
}

/// A bound portal tied to the same brand as its statement.
#[derive(Debug)]
pub struct Portal<'id> {
    client_name: Bytes,
    upstream_name: Bytes,
    generation: u64,
    _brand: PhantomData<Cell<&'id ()>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceError {
    StatementNameCollision,
    PortalNameCollision,
    UnknownStatement,
    UnknownPortal,
}

#[derive(Debug)]
pub enum ResourceProtocolError {
    Resource(ResourceError),
    Wire(io::Error),
}

impl From<ResourceError> for ResourceProtocolError {
    fn from(error: ResourceError) -> Self {
        Self::Resource(error)
    }
}

impl From<io::Error> for ResourceProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Wire(error)
    }
}

impl<'id> ResourceScope<'id> {
    fn new() -> Self {
        Self {
            statements: HashMap::new(),
            portals: HashMap::new(),
            next_generation: 0,
            _brand: PhantomData,
        }
    }

    /// Records a simple-query boundary, which destroys the unnamed statement.
    pub fn simple_query_boundary(&mut self) {
        self.statements.remove(b"".as_slice());
    }

    /// Records transaction end, which destroys the unnamed portal.
    pub fn transaction_ended(&mut self) {
        self.portals.remove(b"".as_slice());
    }

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
        let generation = self.allocate(&upstream_name, true)?;
        if self
            .statements
            .insert(upstream_name.clone(), generation)
            .is_some()
            && !upstream_name.is_empty()
        {
            return Err(ResourceError::StatementNameCollision);
        }
        let statement = PreparedStatement {
            client_name,
            upstream_name: upstream_name.clone(),
            generation,
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
        if self.statements.get(&statement.upstream_name) != Some(&statement.generation) {
            return Err(ResourceError::UnknownStatement);
        }
        let generation = self.allocate(&upstream_name, false)?;
        if self
            .portals
            .insert(upstream_name.clone(), generation)
            .is_some()
            && !upstream_name.is_empty()
        {
            return Err(ResourceError::PortalNameCollision);
        }
        let portal = Portal {
            client_name,
            upstream_name: upstream_name.clone(),
            generation,
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
        if self.statements.get(&statement.upstream_name) != Some(&statement.generation) {
            return Err(ResourceError::UnknownStatement);
        }
        self.statements.remove(&statement.upstream_name);
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
        if self.portals.get(&portal.upstream_name) != Some(&portal.generation) {
            return Err(ResourceError::UnknownPortal);
        }
        self.portals.remove(&portal.upstream_name);
        Ok(Close {
            target: DescribeTarget::Portal,
            name: portal.upstream_name,
        })
    }

    fn execute(&self, portal: &Portal<'id>, max_rows: i32) -> Result<Execute, ResourceError> {
        if self.portals.get(&portal.upstream_name) != Some(&portal.generation) {
            return Err(ResourceError::UnknownPortal);
        }
        Ok(portal.execute(max_rows))
    }
}

impl<'id, S, C> ResourceConnection<'id, S, Building, C> {
    /// Creates and sends a branded prepared statement on this connection.
    ///
    /// # Errors
    ///
    /// Returns namespace or wire reconstruction errors.
    pub fn prepare(
        self,
        client_name: Bytes,
        upstream_name: Bytes,
        query: Bytes,
        parameter_types: Vec<u32>,
    ) -> PrepareResult<'id, S> {
        let Self {
            conn,
            mut resources,
        } = self;
        let (statement, message) =
            resources.prepare(client_name, upstream_name, query, parameter_types)?;
        let (conn, frame) = conn.push_parse(&message)?;
        Ok((ResourceConnection { conn, resources }, statement, frame))
    }

    /// Creates and sends a branded portal on this connection.
    ///
    /// # Errors
    ///
    /// Returns namespace or wire reconstruction errors.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        self,
        statement: &PreparedStatement<'id>,
        client_name: Bytes,
        upstream_name: Bytes,
        parameter_formats: Vec<i16>,
        parameters: Vec<Option<Bytes>>,
        result_formats: Vec<i16>,
    ) -> BindResult<'id, S> {
        let Self {
            conn,
            mut resources,
        } = self;
        let (portal, message) = resources.bind(
            statement,
            client_name,
            upstream_name,
            parameter_formats,
            parameters,
            result_formats,
        )?;
        let (conn, frame) = conn.push_bind(&message)?;
        Ok((ResourceConnection { conn, resources }, portal, frame))
    }
}

impl<'id, S, C> ResourceConnection<'id, S, BoundBuilding, C> {
    /// Sends an execute which can name only a live portal from this connection.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale portal or invalid wire value.
    pub fn execute(
        self,
        portal: &Portal<'id>,
        max_rows: i32,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let message = self.resources.execute(portal, max_rows)?;
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_execute(&message)?;
        Ok((Self { conn, resources }, frame))
    }
}

impl ResourceScope<'_> {
    fn allocate(&mut self, name: &Bytes, statement: bool) -> Result<u64, ResourceError> {
        let resources = if statement {
            &self.statements
        } else {
            &self.portals
        };
        if !name.is_empty() && resources.contains_key(name) {
            return Err(if statement {
                ResourceError::StatementNameCollision
            } else {
                ResourceError::PortalNameCollision
            });
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        Ok(generation)
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
    fn resource_connection_sends_only_its_own_branded_portals() {
        let ready: Conn<(), crate::auth::Ready> = Conn::new(()).transition();
        with_connection_resources(ready.begin_extended(), |connection| {
            let (connection, statement, parse) = connection
                .prepare(
                    Bytes::from_static(b"client_statement"),
                    Bytes::from_static(b"proxy_statement"),
                    Bytes::from_static(b"select $1::int4"),
                    vec![23],
                )
                .unwrap();
            assert_eq!(parse.tag, b'P');
            let (connection, portal, bind) = connection
                .bind(
                    &statement,
                    Bytes::from_static(b"client_portal"),
                    Bytes::from_static(b"proxy_portal"),
                    vec![1],
                    vec![Some(Bytes::from_static(b"\0\0\0*"))],
                    vec![1],
                )
                .unwrap();
            assert_eq!(bind.tag, b'B');
            let (connection, execute) = connection.execute(&portal, 0).unwrap();
            assert_eq!(execute.tag, b'E');
            connection.into_connection().into_transport();
        });
    }

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

    #[test]
    fn unnamed_resources_replace_the_previous_unnamed_resource() {
        with_resources(|mut resources| {
            let (obsolete, _) = resources
                .prepare(
                    Bytes::new(),
                    Bytes::new(),
                    Bytes::from_static(b"select 1"),
                    vec![],
                )
                .unwrap();
            let (replacement, _) = resources
                .prepare(
                    Bytes::new(),
                    Bytes::new(),
                    Bytes::from_static(b"select 2"),
                    vec![],
                )
                .expect("unnamed Parse replaces the prior unnamed statement");
            assert_eq!(
                resources
                    .bind(
                        &obsolete,
                        Bytes::new(),
                        Bytes::new(),
                        vec![],
                        vec![],
                        vec![],
                    )
                    .unwrap_err(),
                ResourceError::UnknownStatement
            );

            let (_, _) = resources
                .bind(
                    &replacement,
                    Bytes::new(),
                    Bytes::new(),
                    vec![],
                    vec![],
                    vec![],
                )
                .unwrap();
            resources
                .bind(
                    &replacement,
                    Bytes::new(),
                    Bytes::new(),
                    vec![],
                    vec![],
                    vec![],
                )
                .expect("unnamed Bind replaces the prior unnamed portal");
        });
    }

    #[test]
    fn protocol_boundaries_invalidate_unnamed_resource_tokens() {
        with_resources(|mut resources| {
            let (statement, _) = resources
                .prepare(
                    Bytes::new(),
                    Bytes::new(),
                    Bytes::from_static(b"select 1"),
                    vec![],
                )
                .unwrap();
            let (portal, _) = resources
                .bind(
                    &statement,
                    Bytes::new(),
                    Bytes::new(),
                    vec![],
                    vec![],
                    vec![],
                )
                .unwrap();

            resources.simple_query_boundary();
            assert_eq!(
                resources
                    .bind(
                        &statement,
                        Bytes::from_static(b"p"),
                        Bytes::from_static(b"p"),
                        vec![],
                        vec![],
                        vec![],
                    )
                    .unwrap_err(),
                ResourceError::UnknownStatement
            );

            resources.transaction_ended();
            assert_eq!(
                resources.close_portal(portal).unwrap_err(),
                ResourceError::UnknownPortal
            );
        });
    }
}
