//! Branded prepared-statement and portal resources with proxy name rewriting.

use std::{
    cell::Cell, collections::HashMap, error::Error, fmt, future::Future, io, marker::PhantomData,
    pin::Pin,
};

use bytes::Bytes;

use crate::{
    Conn, Dirty,
    auth::Ready,
    codec::{Bind, Close, Describe, DescribeTarget, Execute, Frame, Parse, TransactionStatus},
    demux::SessionItem,
    session::{
        AwaitingReady, AwaitingReadyTransition, BoundBuilding, Building, Draining,
        DrainingTransition, ErrorResponse, ReadyState, SimpleQuery,
    },
};

/// Runs an operation with a fresh resource brand which cannot escape the closure.
pub(crate) fn with_resources<R>(operation: impl for<'id> FnOnce(ResourceScope<'id>) -> R) -> R {
    operation(ResourceScope::new())
}

/// Runs an extended-query operation with one brand shared by its connection
/// and resource namespace.
pub(crate) fn with_connection_resources<S, P, C, R>(
    conn: Conn<S, P, C>,
    operation: impl for<'id> FnOnce(ResourceConnection<'id, S, P, C>) -> R,
) -> R {
    operation(ResourceConnection {
        conn,
        resources: ResourceScope::new(),
    })
}

/// Runs an asynchronous operation with one brand shared by its connection and
/// resource namespace.
///
/// The boxed future may retain branded tokens across await points, while its
/// output cannot contain the generative lifetime.
pub(crate) async fn with_connection_resources_async<S, P, C, R>(
    conn: Conn<S, P, C>,
    operation: impl for<'id> FnOnce(
        ResourceConnection<'id, S, P, C>,
    ) -> Pin<Box<dyn Future<Output = R> + 'id>>,
) -> R {
    operation(ResourceConnection {
        conn,
        resources: ResourceScope::new(),
    })
    .await
}

/// A connection paired with its generative statement and portal namespace.
#[derive(Debug)]
pub(crate) struct ResourceConnection<'id, S, P, C> {
    conn: Conn<S, P, C>,
    resources: ResourceScope<'id>,
}

impl<'id, S, P, C> ResourceConnection<'id, S, P, C> {
    /// Borrows the typed connection for transport-only operations such as
    /// buffering a frame returned by this wrapper.
    pub(crate) const fn connection(&self) -> &Conn<S, P, C> {
        &self.conn
    }

    /// Mutably borrows the typed connection for transport-only operations such
    /// as buffering and flushing returned frames.
    pub(crate) const fn connection_mut(&mut self) -> &mut Conn<S, P, C> {
        &mut self.conn
    }

    /// Reports whether a prepared-statement token is still live in this
    /// connection's namespace.
    #[must_use]
    pub(crate) fn statement_is_live(&self, statement: &PreparedStatement<'id>) -> bool {
        self.resources.statements.get(&statement.upstream_name) == Some(&statement.generation)
    }

    /// Reports whether a portal token is still live in this connection's
    /// namespace.
    #[must_use]
    pub(crate) fn portal_is_live(&self, portal: &Portal<'id>) -> bool {
        self.resources.portals.get(&portal.upstream_name) == Some(&portal.generation)
    }

    /// Deliberately leaves resource-aware handling while retaining typestate.
    pub(crate) fn into_connection(self) -> Conn<S, P, C> {
        self.conn
    }
}

/// Result of preparing a statement while building an extended-query pipeline.
pub(crate) type PrepareResult<'id, S> = Result<
    (
        ResourceConnection<'id, S, Building, Dirty>,
        PreparedStatement<'id>,
        Frame,
    ),
    ResourceProtocolError,
>;

/// Result of binding a portal for the first time in a pipeline.
pub(crate) type BindResult<'id, S> = Result<
    (
        ResourceConnection<'id, S, BoundBuilding, Dirty>,
        Portal<'id>,
        Frame,
    ),
    ResourceProtocolError,
>;

/// Result of preparing another statement after a portal has been bound.
pub(crate) type BoundPrepareResult<'id, S> = Result<
    (
        ResourceConnection<'id, S, BoundBuilding, Dirty>,
        PreparedStatement<'id>,
        Frame,
    ),
    ResourceProtocolError,
>;

/// Result of binding another portal after the pipeline has become executable.
pub(crate) type RebindResult<'id, S> = Result<
    (
        ResourceConnection<'id, S, BoundBuilding, Dirty>,
        Portal<'id>,
        Frame,
    ),
    ResourceProtocolError,
>;

#[derive(Debug)]
/// Readiness projected while retaining the connection's resource brand.
pub(crate) enum ResourceReadyState<'id, S, C> {
    /// The connection retained its existing cleanliness index.
    Clean(ResourceConnection<'id, S, Ready, C>),
    /// Transaction or parameter evidence made the connection dirty.
    Dirty {
        /// Ready, dirty connection and its resource namespace.
        conn: ResourceConnection<'id, S, Ready, Dirty>,
        /// Transaction status reported by `ReadyForQuery`.
        status: TransactionStatus,
        /// Whether reported parameters differ from their startup values.
        parameters_changed: bool,
    },
}

#[derive(Debug)]
/// Projection while awaiting readiness after an extended-query result.
pub(crate) enum ResourceAwaitingTransition<'id, S, C> {
    /// A non-terminal item was consumed; continue waiting.
    Continue(ResourceConnection<'id, S, AwaitingReady, C>, SessionItem),
    /// `ReadyForQuery` completed the cycle.
    Ready(ResourceReadyState<'id, S, C>),
    /// An error entered the drain-until-ready recovery phase.
    Error(ResourceConnection<'id, S, Draining, C>, ErrorResponse),
}

#[derive(Debug)]
/// Projection while draining an errored resource-aware pipeline.
pub(crate) enum ResourceDrainingTransition<'id, S, C> {
    /// A non-terminal item was consumed; continue draining.
    Continue(ResourceConnection<'id, S, Draining, C>, SessionItem),
    /// `ReadyForQuery` completed recovery.
    Ready(ResourceReadyState<'id, S, C>),
}

/// Connection-local statement and portal namespaces.
#[derive(Debug)]
pub(crate) struct ResourceScope<'id> {
    statements: HashMap<Bytes, u64>,
    client_statements: HashMap<Bytes, (Bytes, u64)>,
    portals: HashMap<Bytes, u64>,
    client_portals: HashMap<Bytes, (Bytes, u64)>,
    next_generation: u64,
    _brand: PhantomData<Cell<&'id ()>>,
}

/// A prepared statement tied to one generative connection brand.
#[derive(Debug)]
pub(crate) struct PreparedStatement<'id> {
    client_name: Bytes,
    upstream_name: Bytes,
    generation: u64,
    _brand: PhantomData<Cell<&'id ()>>,
}

/// A bound portal tied to the same brand as its statement.
#[derive(Debug)]
pub(crate) struct Portal<'id> {
    client_name: Bytes,
    upstream_name: Bytes,
    generation: u64,
    _brand: PhantomData<Cell<&'id ()>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Failure to resolve or allocate a branded protocol resource.
pub(crate) enum ResourceError {
    /// A live prepared statement already uses the requested name.
    StatementNameCollision,
    /// A live portal already uses the requested name.
    PortalNameCollision,
    /// The prepared-statement token or client name is unknown or stale.
    UnknownStatement,
    /// The portal token or client name is unknown or stale.
    UnknownPortal,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StatementNameCollision => "prepared statement name collision",
            Self::PortalNameCollision => "portal name collision",
            Self::UnknownStatement => "unknown or stale prepared statement",
            Self::UnknownPortal => "unknown or stale portal",
        })
    }
}

impl Error for ResourceError {}

#[derive(Debug)]
/// A resource-namespace or wire-encoding failure.
pub(crate) enum ResourceProtocolError {
    /// Resource identity or lifetime validation failed.
    Resource(ResourceError),
    /// Reconstruction of the wire message failed.
    Wire(io::Error),
}

impl fmt::Display for ResourceProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(error) => error.fmt(formatter),
            Self::Wire(error) => error.fmt(formatter),
        }
    }
}

impl Error for ResourceProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Resource(error) => Some(error),
            Self::Wire(error) => Some(error),
        }
    }
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
            client_statements: HashMap::new(),
            portals: HashMap::new(),
            client_portals: HashMap::new(),
            next_generation: 0,
            _brand: PhantomData,
        }
    }

    /// Records a simple-query boundary, which destroys the unnamed statement.
    pub(crate) fn simple_query_boundary(&mut self) {
        self.statements.remove(b"".as_slice());
        self.client_statements
            .retain(|_, (upstream, _)| !upstream.is_empty());
    }

    /// Records transaction end, which destroys the unnamed portal.
    pub(crate) fn transaction_ended(&mut self) {
        self.portals.remove(b"".as_slice());
        self.client_portals
            .retain(|_, (upstream, _)| !upstream.is_empty());
    }

    /// Allocates a statement token and reconstructable upstream `Parse` message.
    ///
    /// # Errors
    ///
    /// Rejects duplicate upstream statement names.
    pub(crate) fn prepare(
        &mut self,
        client_name: Bytes,
        upstream_name: Bytes,
        query: Bytes,
        parameter_types: Vec<u32>,
    ) -> Result<(PreparedStatement<'id>, Parse), ResourceError> {
        let generation = self.allocate(&client_name, &upstream_name, true)?;
        if self
            .statements
            .insert(upstream_name.clone(), generation)
            .is_some()
            && !upstream_name.is_empty()
        {
            return Err(ResourceError::StatementNameCollision);
        }
        let statement = PreparedStatement {
            client_name: client_name.clone(),
            upstream_name: upstream_name.clone(),
            generation,
            _brand: PhantomData,
        };
        self.client_statements
            .insert(client_name, (upstream_name.clone(), generation));
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
    pub(crate) fn bind(
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
        let generation = self.allocate(&client_name, &upstream_name, false)?;
        if self
            .portals
            .insert(upstream_name.clone(), generation)
            .is_some()
            && !upstream_name.is_empty()
        {
            return Err(ResourceError::PortalNameCollision);
        }
        let portal = Portal {
            client_name: client_name.clone(),
            upstream_name: upstream_name.clone(),
            generation,
            _brand: PhantomData,
        };
        self.client_portals
            .insert(client_name, (upstream_name.clone(), generation));
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
    pub(crate) fn close_statement(
        &mut self,
        statement: PreparedStatement<'id>,
    ) -> Result<Close, ResourceError> {
        if self.statements.get(&statement.upstream_name) != Some(&statement.generation) {
            return Err(ResourceError::UnknownStatement);
        }
        self.statements.remove(&statement.upstream_name);
        self.client_statements.retain(|_, (upstream, generation)| {
            upstream != &statement.upstream_name || *generation != statement.generation
        });
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
    pub(crate) fn close_portal(&mut self, portal: Portal<'id>) -> Result<Close, ResourceError> {
        if self.portals.get(&portal.upstream_name) != Some(&portal.generation) {
            return Err(ResourceError::UnknownPortal);
        }
        self.portals.remove(&portal.upstream_name);
        self.client_portals.retain(|_, (upstream, generation)| {
            upstream != &portal.upstream_name || *generation != portal.generation
        });
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

    fn describe_portal(&self, portal: &Portal<'id>) -> Result<Describe, ResourceError> {
        if self.portals.get(&portal.upstream_name) != Some(&portal.generation) {
            return Err(ResourceError::UnknownPortal);
        }
        Ok(portal.describe())
    }

    fn describe_statement(
        &self,
        statement: &PreparedStatement<'id>,
    ) -> Result<Describe, ResourceError> {
        if self.statements.get(&statement.upstream_name) != Some(&statement.generation) {
            return Err(ResourceError::UnknownStatement);
        }
        Ok(statement.describe())
    }

    /// Resolves a client-visible statement name to its branded upstream token.
    #[must_use]
    pub(crate) fn statement(&self, client_name: &[u8]) -> Option<PreparedStatement<'id>> {
        let (upstream_name, generation) = self.client_statements.get(client_name)?;
        Some(PreparedStatement {
            client_name: Bytes::copy_from_slice(client_name),
            upstream_name: upstream_name.clone(),
            generation: *generation,
            _brand: PhantomData,
        })
    }

    /// Resolves a client-visible portal name to its branded upstream token.
    #[must_use]
    pub(crate) fn portal(&self, client_name: &[u8]) -> Option<Portal<'id>> {
        let (upstream_name, generation) = self.client_portals.get(client_name)?;
        Some(Portal {
            client_name: Bytes::copy_from_slice(client_name),
            upstream_name: upstream_name.clone(),
            generation: *generation,
            _brand: PhantomData,
        })
    }
}

impl<'id, S, C> ResourceConnection<'id, S, Building, C> {
    /// Creates and sends a branded prepared statement on this connection.
    ///
    /// # Errors
    ///
    /// Returns namespace or wire reconstruction errors.
    pub(crate) fn prepare(
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
    pub(crate) fn bind(
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

    /// Describes only a live statement from this connection.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale statement or invalid wire value.
    pub(crate) fn describe_statement(
        self,
        statement: &PreparedStatement<'id>,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let message = self.resources.describe_statement(statement)?;
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_describe(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Closes a live statement and invalidates its token.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale statement or invalid wire value.
    pub(crate) fn close_statement(
        self,
        statement: PreparedStatement<'id>,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let Self {
            conn,
            mut resources,
        } = self;
        let message = resources.close_statement(statement)?;
        let (conn, frame) = conn.push_close(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Closes a live portal and invalidates its token.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale portal or invalid wire value.
    pub(crate) fn close_portal(
        self,
        portal: Portal<'id>,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let Self {
            conn,
            mut resources,
        } = self;
        let message = resources.close_portal(portal)?;
        let (conn, frame) = conn.push_close(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Emits Flush without changing resource or phase evidence.
    #[must_use]
    pub(crate) fn flush(self) -> (Self, Frame) {
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_flush();
        (Self { conn, resources }, frame)
    }

    /// Emits Sync while retaining the namespace through response consumption.
    #[must_use]
    pub(crate) fn sync(self) -> (ResourceConnection<'id, S, AwaitingReady, C>, Frame) {
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_sync();
        (ResourceConnection { conn, resources }, frame)
    }
}

impl<'id, S, C> ResourceConnection<'id, S, Ready, C> {
    /// Begins another extended-query cycle with the same resource namespace.
    #[must_use]
    pub(crate) fn begin_extended(self) -> ResourceConnection<'id, S, Building, C> {
        let Self { conn, resources } = self;
        ResourceConnection {
            conn: conn.begin_extended(),
            resources,
        }
    }

    /// Begins a simple query and invalidates the unnamed prepared statement.
    ///
    /// # Errors
    ///
    /// Returns an error if the query cannot be reconstructed on the wire.
    pub(crate) fn query(
        self,
        query: &[u8],
    ) -> Result<(ResourceConnection<'id, S, SimpleQuery, Dirty>, Frame), ResourceProtocolError>
    {
        let Self {
            conn,
            mut resources,
        } = self;
        resources.simple_query_boundary();
        let (conn, frame) = conn.push_query(query)?;
        Ok((ResourceConnection { conn, resources }, frame))
    }
}

impl<'id, S, C> ResourceConnection<'id, S, BoundBuilding, C> {
    /// Creates another prepared statement while retaining executable portals.
    ///
    /// # Errors
    ///
    /// Returns namespace or wire reconstruction errors.
    pub(crate) fn prepare(
        self,
        client_name: Bytes,
        upstream_name: Bytes,
        query: Bytes,
        parameter_types: Vec<u32>,
    ) -> BoundPrepareResult<'id, S> {
        let Self {
            conn,
            mut resources,
        } = self;
        let (statement, message) =
            resources.prepare(client_name, upstream_name, query, parameter_types)?;
        let (conn, frame) = conn.push_parse(&message)?;
        Ok((ResourceConnection { conn, resources }, statement, frame))
    }

    /// Creates another portal while retaining prior live portals.
    ///
    /// # Errors
    ///
    /// Returns namespace or wire reconstruction errors.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind(
        self,
        statement: &PreparedStatement<'id>,
        client_name: Bytes,
        upstream_name: Bytes,
        parameter_formats: Vec<i16>,
        parameters: Vec<Option<Bytes>>,
        result_formats: Vec<i16>,
    ) -> RebindResult<'id, S> {
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

    /// Describes only a live statement from this connection.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale statement or invalid wire value.
    pub(crate) fn describe_statement(
        self,
        statement: &PreparedStatement<'id>,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let message = self.resources.describe_statement(statement)?;
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_describe(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Describes only a live portal from this connection.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale portal or invalid wire value.
    pub(crate) fn describe_portal(
        self,
        portal: &Portal<'id>,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let message = self.resources.describe_portal(portal)?;
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_describe(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Sends an execute which can name only a live portal from this connection.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale portal or invalid wire value.
    pub(crate) fn execute(
        self,
        portal: &Portal<'id>,
        max_rows: i32,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let message = self.resources.execute(portal, max_rows)?;
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_execute(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Closes a live statement and invalidates its token.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale statement or invalid wire value.
    pub(crate) fn close_statement(
        self,
        statement: PreparedStatement<'id>,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let Self {
            conn,
            mut resources,
        } = self;
        let message = resources.close_statement(statement)?;
        let (conn, frame) = conn.push_close(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Closes a live portal and invalidates its token.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale portal or invalid wire value.
    pub(crate) fn close_portal(
        self,
        portal: Portal<'id>,
    ) -> Result<(Self, Frame), ResourceProtocolError> {
        let Self {
            conn,
            mut resources,
        } = self;
        let message = resources.close_portal(portal)?;
        let (conn, frame) = conn.push_close(&message)?;
        Ok((Self { conn, resources }, frame))
    }

    /// Emits Flush without changing resource or phase evidence.
    #[must_use]
    pub(crate) fn flush(self) -> (Self, Frame) {
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_flush();
        (Self { conn, resources }, frame)
    }

    /// Emits Sync while retaining the namespace through response consumption.
    #[must_use]
    pub(crate) fn sync(self) -> (ResourceConnection<'id, S, AwaitingReady, C>, Frame) {
        let Self { conn, resources } = self;
        let (conn, frame) = conn.push_sync();
        (ResourceConnection { conn, resources }, frame)
    }
}

impl<'id, S, C> ResourceConnection<'id, S, AwaitingReady, C> {
    /// Consumes one backend response while retaining the branded namespace.
    #[must_use]
    pub(crate) fn offer(self, item: SessionItem) -> ResourceAwaitingTransition<'id, S, C> {
        let Self { conn, resources } = self;
        match conn.offer(item) {
            AwaitingReadyTransition::Continue(conn, item) => {
                ResourceAwaitingTransition::Continue(Self { conn, resources }, item)
            }
            AwaitingReadyTransition::Ready(ready) => {
                ResourceAwaitingTransition::Ready(resource_ready(resources, ready))
            }
            AwaitingReadyTransition::Error(conn, error) => {
                ResourceAwaitingTransition::Error(ResourceConnection { conn, resources }, error)
            }
        }
    }
}

impl<'id, S, C> ResourceConnection<'id, S, Draining, C> {
    /// Drains one backend response after an error while retaining resources.
    #[must_use]
    pub(crate) fn offer(self, item: SessionItem) -> ResourceDrainingTransition<'id, S, C> {
        let Self { conn, resources } = self;
        match conn.offer(item) {
            DrainingTransition::Continue(conn, item) => {
                ResourceDrainingTransition::Continue(Self { conn, resources }, item)
            }
            DrainingTransition::Ready(ready) => {
                ResourceDrainingTransition::Ready(resource_ready(resources, ready))
            }
        }
    }
}

fn resource_ready<S, C>(
    mut resources: ResourceScope<'_>,
    ready: ReadyState<S, C>,
) -> ResourceReadyState<'_, S, C> {
    match ready {
        ReadyState::Clean(conn) => {
            resources.transaction_ended();
            ResourceReadyState::Clean(ResourceConnection { conn, resources })
        }
        ReadyState::Dirty {
            conn,
            status,
            parameters_changed,
        } => {
            if status == TransactionStatus::Idle {
                resources.transaction_ended();
            }
            ResourceReadyState::Dirty {
                conn: ResourceConnection { conn, resources },
                status,
                parameters_changed,
            }
        }
    }
}

impl ResourceScope<'_> {
    fn allocate(
        &mut self,
        client_name: &Bytes,
        upstream_name: &Bytes,
        statement: bool,
    ) -> Result<u64, ResourceError> {
        let (resources, client_resources) = if statement {
            (&self.statements, &self.client_statements)
        } else {
            (&self.portals, &self.client_portals)
        };
        if (!upstream_name.is_empty() && resources.contains_key(upstream_name))
            || (!client_name.is_empty() && client_resources.contains_key(client_name))
        {
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
    /// Returns the statement name presented by the client.
    #[must_use]
    pub(crate) fn client_name(&self) -> &[u8] {
        &self.client_name
    }

    /// Returns the rewritten statement name sent upstream.
    #[must_use]
    pub(crate) fn upstream_name(&self) -> &[u8] {
        &self.upstream_name
    }

    /// Constructs a `Describe` message using the rewritten statement name.
    #[must_use]
    pub(crate) fn describe(&self) -> Describe {
        Describe {
            target: DescribeTarget::Statement,
            name: self.upstream_name.clone(),
        }
    }
}

impl Portal<'_> {
    /// Returns the portal name presented by the client.
    #[must_use]
    pub(crate) fn client_name(&self) -> &[u8] {
        &self.client_name
    }

    /// Returns the rewritten portal name sent upstream.
    #[must_use]
    pub(crate) fn upstream_name(&self) -> &[u8] {
        &self.upstream_name
    }

    /// Constructs a `Describe` message using the rewritten portal name.
    #[must_use]
    pub(crate) fn describe(&self) -> Describe {
        Describe {
            target: DescribeTarget::Portal,
            name: self.upstream_name.clone(),
        }
    }

    /// Constructs an `Execute` message using the rewritten portal name.
    #[must_use]
    pub(crate) fn execute(&self, max_rows: i32) -> Execute {
        Execute {
            portal: self.upstream_name.clone(),
            max_rows,
        }
    }
}

#[cfg(test)]
/// Tests for branded statement and portal resource tracking.
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
            let (connection, describe) = connection.describe_portal(&portal).unwrap();
            assert_eq!(describe.tag, b'D');
            let (connection, execute) = connection.execute(&portal, 0).unwrap();
            assert_eq!(execute.tag, b'E');
            let (connection, second_statement, parse) = connection
                .prepare(
                    Bytes::from_static(b"client_statement_2"),
                    Bytes::from_static(b"proxy_statement_2"),
                    Bytes::from_static(b"select 2"),
                    vec![],
                )
                .unwrap();
            assert_eq!(parse.tag, b'P');
            let (connection, second_portal, bind) = connection
                .bind(
                    &second_statement,
                    Bytes::from_static(b"client_portal_2"),
                    Bytes::from_static(b"proxy_portal_2"),
                    vec![],
                    vec![],
                    vec![],
                )
                .unwrap();
            assert_eq!(bind.tag, b'B');
            let (connection, describe) = connection.describe_statement(&second_statement).unwrap();
            assert_eq!(describe.tag, b'D');
            let (connection, flush) = connection.flush();
            assert_eq!(flush.tag, b'H');
            let (connection, close) = connection.close_portal(second_portal).unwrap();
            assert_eq!(close.tag, b'C');
            let (connection, close) = connection.close_portal(portal).unwrap();
            assert_eq!(close.tag, b'C');
            let (connection, close) = connection.close_statement(second_statement).unwrap();
            assert_eq!(close.tag, b'C');
            let (connection, close) = connection.close_statement(statement).unwrap();
            assert_eq!(close.tag, b'C');
            let (awaiting, sync) = connection.sync();
            assert_eq!(sync.tag, b'S');
            let ResourceAwaitingTransition::Continue(awaiting, _) = awaiting.offer(
                SessionItem::Message(crate::codec::BackendMessage::ParseComplete),
            ) else {
                panic!("ParseComplete should retain the awaiting phase")
            };
            let ResourceAwaitingTransition::Ready(ResourceReadyState::Clean(ready)) = awaiting
                .offer(SessionItem::ReadyForQuery {
                    status: TransactionStatus::Idle,
                    parameters_changed: false,
                })
            else {
                panic!("idle readiness should complete the extended cycle")
            };
            ready.begin_extended().into_connection().into_transport();
        });
    }

    #[test]
    fn namespace_resolves_client_names_to_rewritten_resources() {
        with_resources(|mut resources| {
            let (statement, _) = resources
                .prepare(
                    Bytes::from_static(b"client-statement"),
                    Bytes::from_static(b"upstream-statement-42"),
                    Bytes::from_static(b"select $1"),
                    vec![25],
                )
                .unwrap();
            let (portal, _) = resources
                .bind(
                    &statement,
                    Bytes::from_static(b"client-portal"),
                    Bytes::from_static(b"upstream-portal-42"),
                    vec![0],
                    vec![Some(Bytes::from_static(b"value"))],
                    vec![1],
                )
                .unwrap();

            assert_eq!(
                resources
                    .statement(b"client-statement")
                    .unwrap()
                    .upstream_name(),
                b"upstream-statement-42"
            );
            assert_eq!(
                resources.portal(b"client-portal").unwrap().upstream_name(),
                b"upstream-portal-42"
            );

            resources.close_portal(portal).unwrap();
            resources.close_statement(statement).unwrap();
            assert!(resources.portal(b"client-portal").is_none());
            assert!(resources.statement(b"client-statement").is_none());
        });
    }

    #[test]
    fn idle_readiness_invalidates_only_the_unnamed_portal() {
        let ready: Conn<(), crate::auth::Ready> = Conn::new(()).transition();
        with_connection_resources(ready.begin_extended(), |connection| {
            let (connection, statement, _) = connection
                .prepare(
                    Bytes::new(),
                    Bytes::new(),
                    Bytes::from_static(b"select 1"),
                    vec![],
                )
                .unwrap();
            let (connection, portal, _) = connection
                .bind(
                    &statement,
                    Bytes::new(),
                    Bytes::new(),
                    vec![],
                    vec![],
                    vec![],
                )
                .unwrap();
            assert!(connection.statement_is_live(&statement));
            assert!(connection.portal_is_live(&portal));
            let (awaiting, _) = connection.sync();
            let ResourceAwaitingTransition::Ready(ResourceReadyState::Clean(ready)) = awaiting
                .offer(SessionItem::ReadyForQuery {
                    status: TransactionStatus::Idle,
                    parameters_changed: false,
                })
            else {
                panic!("idle readiness should complete the extended cycle")
            };

            assert!(ready.statement_is_live(&statement));
            assert!(!ready.portal_is_live(&portal));
            ready.into_connection().into_transport();
        });
    }

    #[test]
    fn simple_query_invalidates_only_the_unnamed_statement() {
        let ready: Conn<(), crate::auth::Ready> = Conn::new(()).transition();
        with_connection_resources(ready.begin_extended(), |connection| {
            let (connection, unnamed, _) = connection
                .prepare(
                    Bytes::new(),
                    Bytes::new(),
                    Bytes::from_static(b"select 1"),
                    vec![],
                )
                .unwrap();
            let (connection, named, _) = connection
                .prepare(
                    Bytes::from_static(b"client_named"),
                    Bytes::from_static(b"proxy_named"),
                    Bytes::from_static(b"select 2"),
                    vec![],
                )
                .unwrap();
            let (awaiting, _) = connection.sync();
            let ResourceAwaitingTransition::Ready(ResourceReadyState::Clean(ready)) = awaiting
                .offer(SessionItem::ReadyForQuery {
                    status: TransactionStatus::Idle,
                    parameters_changed: false,
                })
            else {
                panic!("idle readiness should complete the extended cycle")
            };
            assert!(ready.statement_is_live(&unnamed));
            assert!(ready.statement_is_live(&named));

            let (query, frame) = ready.query(b"select 3").unwrap();
            assert_eq!(frame.tag, b'Q');
            assert!(!query.statement_is_live(&unnamed));
            assert!(query.statement_is_live(&named));
            query.into_connection().into_transport();
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
