//! Policy-neutral composition of independent downstream and upstream sessions.

use std::future::Future;

/// Owns the two independently typed sides of an intermediary connection.
///
/// `Downstream` is normally a server-role session facing a client and `Upstream`
/// is normally a client-role session facing `PostgreSQL`. No phase, transport,
/// authentication mechanism, or cleanliness index is coupled between them.
#[must_use = "dropping an intermediary abandons both PostgreSQL sessions"]
#[derive(Debug)]
pub struct Intermediary<Downstream, Upstream> {
    downstream: Downstream,
    upstream: Upstream,
}

impl<Downstream, Upstream> Intermediary<Downstream, Upstream> {
    /// Pairs two independently established protocol sessions.
    pub const fn new(downstream: Downstream, upstream: Upstream) -> Self {
        Self {
            downstream,
            upstream,
        }
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
    ) -> Result<(Intermediary<Next, Upstream>, Output), (Self, Error)> {
        let Self {
            downstream,
            upstream,
        } = self;
        match transition(downstream) {
            Ok((downstream, output)) => Ok((
                Intermediary {
                    downstream,
                    upstream,
                },
                output,
            )),
            Err((downstream, error)) => Err((
                Intermediary {
                    downstream,
                    upstream,
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
    ) -> Result<(Intermediary<Downstream, Next>, Output), (Self, Error)> {
        let Self {
            downstream,
            upstream,
        } = self;
        match transition(upstream) {
            Ok((upstream, output)) => Ok((
                Intermediary {
                    downstream,
                    upstream,
                },
                output,
            )),
            Err((upstream, error)) => Err((
                Intermediary {
                    downstream,
                    upstream,
                },
                error,
            )),
        }
    }

    /// Runs custom synchronous policy with mutable access to both sides.
    ///
    /// The message and result types are chosen by downstream code; `pg-proto`
    /// neither prescribes a rewrite policy nor advances either session implicitly.
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

    use super::Intermediary;
    use crate::grammar::{backend, frontend};

    #[test]
    fn each_side_transitions_without_coupling_the_other() {
        #[derive(Debug)]
        struct Clean;

        let downstream: backend::TypedSession<(), backend::Ready, Clean> =
            backend::TypedSession::with_transport(());
        let upstream: frontend::TypedSession<(), frontend::Ready, Clean> =
            frontend::TypedSession::with_transport(());
        let intermediary = Intermediary::new(downstream, upstream);

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
    fn rejected_transition_reconstructs_both_original_sides() {
        let intermediary = Intermediary::new(vec![1_u8], vec![2_u8]);
        let (intermediary, error) = intermediary
            .transition_downstream(|downstream| Err::<(Vec<u8>, ()), _>((downstream, "reject")))
            .unwrap_err();
        assert_eq!(error, "reject");
        assert_eq!(intermediary.into_parts(), (vec![1], vec![2]));
    }

    #[tokio::test]
    async fn asynchronous_policy_can_modify_or_replace_a_typed_message() {
        let mut intermediary = Intermediary::new(Vec::<Bytes>::new(), Vec::<Bytes>::new());
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
