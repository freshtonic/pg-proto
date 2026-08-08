//! Policy-neutral composition of independent downstream and upstream sessions.

use std::future::Future;

use crate::pipeline::{NoPipeline, Pipeline, PipelinePolicy};

/// Result of changing one side while preserving the complete intermediary on rejection.
pub type IntermediaryTransition<Current, Next, Output, Error> =
    Result<(Next, Output), (Current, Error)>;

/// Owns two independently typed sides and optional pipeline orchestration.
///
/// `Downstream` is normally a server-role session facing a client and `Upstream`
/// is normally a client-role session facing `PostgreSQL`. No phase, transport,
/// authentication mechanism, or cleanliness index is coupled between them.
/// `Policy` defaults to [`NoPipeline`]; call [`Self::with_pipeline`] to opt into
/// bounded pipelining without changing either session type.
#[must_use = "dropping an intermediary abandons both PostgreSQL sessions"]
#[derive(Debug)]
pub struct SessionPair<Downstream, Upstream, Policy = NoPipeline> {
    downstream: Downstream,
    upstream: Upstream,
    pipeline: Pipeline<Policy>,
}

impl<Downstream, Upstream> SessionPair<Downstream, Upstream, NoPipeline> {
    /// Pairs two independently established protocol sessions.
    pub fn new(downstream: Downstream, upstream: Upstream) -> Self {
        Self {
            downstream,
            upstream,
            pipeline: Pipeline::new(NoPipeline),
        }
    }
}

impl<Downstream, Upstream, Policy: PipelinePolicy> SessionPair<Downstream, Upstream, Policy> {
    /// Replaces the pipeline policy while no pipeline operations are outstanding.
    ///
    /// # Panics
    ///
    /// Panics if operations were accepted before replacing the policy.
    pub fn with_pipeline<Next: PipelinePolicy>(
        self,
        policy: Next,
    ) -> SessionPair<Downstream, Upstream, Next> {
        let Self {
            downstream,
            upstream,
            pipeline,
        } = self;
        assert!(
            pipeline.is_empty(),
            "pipeline policy cannot change with outstanding operations"
        );
        SessionPair {
            downstream,
            upstream,
            pipeline: Pipeline::new(policy),
        }
    }

    /// Returns the reusable request/response pipeline component.
    pub const fn pipeline(&self) -> &Pipeline<Policy> {
        &self.pipeline
    }

    /// Returns mutable access to bounded pipeline orchestration.
    pub const fn pipeline_mut(&mut self) -> &mut Pipeline<Policy> {
        &mut self.pipeline
    }

    /// Borrows the client-facing side without weakening its typestate.
    pub const fn downstream(&self) -> &Downstream {
        &self.downstream
    }

    /// Borrows the upstream-facing side without weakening its typestate.
    pub const fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// Mutably borrows both sides for transport-level orchestration.
    pub const fn sides_mut(&mut self) -> (&mut Downstream, &mut Upstream) {
        (&mut self.downstream, &mut self.upstream)
    }

    /// Deliberately separates the independently typed sessions.
    pub fn into_parts(self) -> (Downstream, Upstream) {
        (self.downstream, self.upstream)
    }

    /// Applies one fallible downstream transition while retaining the upstream
    /// session unchanged.
    ///
    /// A rejected transition must return its original downstream value, allowing
    /// this method to reconstruct the original intermediary without runtime state.
    ///
    /// # Errors
    ///
    /// Returns the reconstructed intermediary and transition error when the
    /// downstream side rejects the transition.
    pub fn transition_downstream<Next, Output, Error>(
        self,
        transition: impl FnOnce(Downstream) -> Result<(Next, Output), (Downstream, Error)>,
    ) -> IntermediaryTransition<Self, SessionPair<Next, Upstream, Policy>, Output, Error> {
        let Self {
            downstream,
            upstream,
            pipeline,
        } = self;
        match transition(downstream) {
            Ok((downstream, output)) => Ok((
                SessionPair {
                    downstream,
                    upstream,
                    pipeline,
                },
                output,
            )),
            Err((downstream, error)) => Err((
                Self {
                    downstream,
                    upstream,
                    pipeline,
                },
                error,
            )),
        }
    }

    /// Applies one fallible upstream transition while retaining the downstream
    /// session unchanged.
    ///
    /// # Errors
    ///
    /// Returns the reconstructed intermediary and transition error when the
    /// upstream side rejects the transition.
    pub fn transition_upstream<Next, Output, Error>(
        self,
        transition: impl FnOnce(Upstream) -> Result<(Next, Output), (Upstream, Error)>,
    ) -> IntermediaryTransition<Self, SessionPair<Downstream, Next, Policy>, Output, Error> {
        let Self {
            downstream,
            upstream,
            pipeline,
        } = self;
        match transition(upstream) {
            Ok((upstream, output)) => Ok((
                SessionPair {
                    downstream,
                    upstream,
                    pipeline,
                },
                output,
            )),
            Err((upstream, error)) => Err((
                Self {
                    downstream,
                    upstream,
                    pipeline,
                },
                error,
            )),
        }
    }

    /// Runs custom synchronous policy with mutable access to both sides.
    ///
    /// The message and result types are chosen by downstream code; `pg-proto`
    /// neither prescribes a rewrite policy nor advances either session implicitly.
    /// This is a low-level escape hatch: prefer
    /// [`crate::middleware::Middleware::intercept_checked`] when rewriting wire
    /// messages so replacements are checked against the current protocol state.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the inspection policy.
    pub fn inspect<Message, Output, Error>(
        &mut self,
        message: Message,
        inspect: impl FnOnce(&mut Downstream, &mut Upstream, Message) -> Result<Output, Error>,
    ) -> Result<Output, Error> {
        inspect(&mut self.downstream, &mut self.upstream, message)
    }

    /// Runs custom asynchronous policy with mutable access to both sides.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the asynchronous inspection policy.
    pub async fn inspect_async<Message, Output, Error, Work>(
        &mut self,
        message: Message,
        inspect: impl FnOnce(&mut Downstream, &mut Upstream, Message) -> Work,
    ) -> Result<Output, Error>
    where
        Work: Future<Output = Result<Output, Error>>,
    {
        inspect(&mut self.downstream, &mut self.upstream, message).await
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::SessionPair;
    use crate::{
        Conn, Pristine,
        auth::{Auth, AuthOffer, SaslInitial, TlsServerEndPoint},
        codec::Authentication,
        grammar::{backend, frontend},
        server_auth::{ServerAuth, ServerPassword},
    };

    #[derive(Debug)]
    struct ClientFacingTls;

    #[derive(Debug)]
    struct UpstreamTls;

    impl TlsServerEndPoint for ClientFacingTls {
        fn tls_server_end_point(&self) -> &[u8] {
            b"client-facing-certificate"
        }
    }

    impl TlsServerEndPoint for UpstreamTls {
        fn tls_server_end_point(&self) -> &[u8] {
            b"upstream-certificate"
        }
    }

    #[test]
    fn each_side_transitions_without_coupling_the_other() {
        #[derive(Debug)]
        struct Clean;

        let downstream: backend::TypedSession<(), backend::Ready, Clean> =
            backend::TypedSession::with_transport(());
        let upstream: frontend::TypedSession<(), frontend::Ready, Clean> =
            frontend::TypedSession::with_transport(());
        let intermediary = SessionPair::new(downstream, upstream);

        let (intermediary, downstream_query) = intermediary
            .transition_downstream(|session| {
                session.query(Bytes::from_static(b"select 1"), |(), query| {
                    Ok::<_, &'static str>(query)
                })
            })
            .expect("downstream inspection succeeds");
        assert_eq!(downstream_query, Bytes::from_static(b"select 1"));

        let (intermediary, upstream_query) = intermediary
            .transition_upstream(|session| {
                session.query(Bytes::from_static(b"select 2"), |(), query| {
                    Ok::<_, &'static str>(query)
                })
            })
            .expect("upstream inspection succeeds");
        assert_eq!(upstream_query, Bytes::from_static(b"select 2"));

        let (_downstream, _upstream): (
            backend::TypedSession<(), backend::Simple, backend::Dirty>,
            frontend::TypedSession<(), frontend::Simple, frontend::Dirty>,
        ) = intermediary.into_parts();
    }

    #[test]
    fn tls_and_authentication_mechanisms_remain_asymmetric() {
        let downstream: Conn<ClientFacingTls, ServerAuth, Pristine> =
            Conn::new(ClientFacingTls).transition();
        let upstream: Conn<UpstreamTls, Auth, Pristine> = Conn::new(UpstreamTls).transition();

        let (downstream, cleartext_request) = downstream.request_cleartext().unwrap();
        let AuthOffer::Sasl {
            conn: upstream,
            mechanisms,
        } = upstream
            .offer(Authentication::Sasl {
                mechanisms: vec![Bytes::from_static(b"SCRAM-SHA-256-PLUS")],
            })
            .unwrap()
        else {
            panic!("upstream did not independently select SASL")
        };
        assert_eq!(cleartext_request.tag, b'R');
        assert_eq!(mechanisms, [Bytes::from_static(b"SCRAM-SHA-256-PLUS")]);

        let intermediary: SessionPair<
            Conn<ClientFacingTls, ServerPassword, Pristine>,
            Conn<UpstreamTls, SaslInitial, Pristine>,
        > = SessionPair::new(downstream, upstream);
        assert_eq!(
            intermediary.downstream().tls_server_end_point(),
            b"client-facing-certificate"
        );
        assert_eq!(
            intermediary.upstream().tls_server_end_point(),
            b"upstream-certificate"
        );
        let (downstream, upstream) = intermediary.into_parts();
        let _downstream_transport = downstream.into_transport();
        let _upstream_transport = upstream.into_transport();
    }

    #[test]
    fn rejected_transition_reconstructs_both_original_sides() {
        let intermediary = SessionPair::new(vec![1_u8], vec![2_u8]);
        let (intermediary, error) = intermediary
            .transition_downstream(|downstream| Err::<(Vec<u8>, ()), _>((downstream, "reject")))
            .unwrap_err();
        assert_eq!(error, "reject");
        assert_eq!(intermediary.into_parts(), (vec![1], vec![2]));
    }

    #[tokio::test]
    async fn asynchronous_policy_can_modify_or_replace_a_typed_message() {
        let mut intermediary = SessionPair::new(Vec::<Bytes>::new(), Vec::<Bytes>::new());
        let rewritten = intermediary
            .inspect_async(
                Bytes::from_static(b"select secret"),
                |downstream, upstream, query| {
                    downstream.push(query);
                    upstream.push(Bytes::from_static(b"select public"));
                    std::future::ready(Ok::<_, std::convert::Infallible>(Bytes::from_static(
                        b"select public",
                    )))
                },
            )
            .await
            .unwrap();
        assert_eq!(rewritten, Bytes::from_static(b"select public"));
        assert_eq!(intermediary.downstream().len(), 1);
        assert_eq!(intermediary.upstream().len(), 1);
    }
}
