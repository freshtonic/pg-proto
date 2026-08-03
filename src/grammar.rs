//! Generated frontend query grammar and differential-test runtime FSM.

use pg_proto_fsm::protocol;

protocol! {
    pub mod frontend {
        initial Ready;
        Ready internal {
            Query(query) => Simple [Dirty],
            BeginExtended(begin_extended) => Building,
            FunctionCall(function_call) => FunctionCalling [Dirty],
            Reset(reset) => Resetting [Dirty],
            Terminate(terminate) => Terminated,
        }
        FunctionCalling external {
            FunctionResponse(function_response) => AwaitingReady,
            Error(error) => Draining,
        }
        Simple external {
            Continue(continue_response) => Simple,
            CopyIn(enter_copy_in) => CopyIn,
            CopyOut(enter_copy_out) => CopyOut,
            CopyBoth(enter_copy_both) => CopyBoth,
            Ready(ready) => Ready,
            Error(error) => Draining,
        }
        Building internal {
            Parse(parse: crate::codec::Parse) => Building [Dirty],
            Describe(describe: crate::codec::Describe) => Building,
            Bind(bind: crate::codec::Bind) => BoundBuilding [Dirty],
            Close(close: crate::codec::Close) => Building,
            Flush(flush) => Building,
            Sync(sync) => AwaitingReady,
        }
        BoundBuilding internal {
            Parse(parse: crate::codec::Parse) => BoundBuilding [Dirty],
            Describe(describe: crate::codec::Describe) => BoundBuilding,
            Bind(bind: crate::codec::Bind) => BoundBuilding [Dirty],
            Execute(execute: crate::codec::Execute) => BoundBuilding,
            Close(close: crate::codec::Close) => BoundBuilding,
            Flush(flush) => BoundBuilding,
            Sync(sync) => AwaitingReady,
        }
        AwaitingReady external {
            Continue(continue_response) => AwaitingReady,
            Ready(ready) => Ready,
            Error(error) => Draining,
        }
        CopyIn mixed {
            internal CopyData(copy_data) => CopyIn,
            internal CopyDone(copy_done) => AwaitingReady,
            internal CopyFail(copy_fail) => AwaitingReady,
            external Error(error) => Draining,
        }
        CopyOut external {
            CopyData(copy_data) => CopyOut,
            CopyDone(copy_done) => AwaitingReady,
            Error(error) => Draining,
        }
        CopyBoth mixed {
            internal SendCopyData(send_copy_data) => CopyBoth,
            external ReceiveCopyData(receive_copy_data) => CopyBoth,
            internal SendCopyDone(send_copy_done) => CopyBothClientDone,
            external ReceiveCopyDone(receive_copy_done) => CopyBothServerDone,
            external Error(error) => Draining,
        }
        CopyBothClientDone external {
            ReceiveCopyData(receive_copy_data) => CopyBothClientDone,
            ReceiveCopyDone(receive_copy_done) => AwaitingReady,
            Error(error) => Draining,
        }
        CopyBothServerDone internal {
            SendCopyData(send_copy_data) => CopyBothServerDone,
            SendCopyDone(send_copy_done) => AwaitingReady,
        }
        Draining external {
            Continue(continue_response) => Draining,
            Ready(ready) => Ready,
        }
        Resetting external {
            Continue(continue_reset) => Resetting,
            DiscardComplete(discard_complete) => ResetComplete,
            Error(error) => Draining,
        }
        ResetComplete external {
            Continue(continue_reset) => ResetComplete,
            ReadyClean(ready_clean) => Ready [Pristine],
            ReadyDirty(ready_dirty) => Ready [Dirty],
            Error(error) => Draining,
        }
        Terminated external {}
    }
}

protocol! {
    pub mod pre_startup {
        initial PreStartup;
        PreStartup internal {
            SslRequest(ssl_request) => AwaitingSslReply,
            GssRequest(gss_request) => AwaitingGssReply,
            Cancel(cancel) => Terminated,
            Startup(startup) => Auth,
        }
        AwaitingSslReply external {
            Accept(accept) => TlsHandshake,
            Reject(reject) => PreStartup,
            LegacyError(legacy_error) => Terminated,
        }
        AwaitingGssReply external {
            Accept(accept) => GssHandshake,
            Reject(reject) => PreStartup,
            LegacyError(legacy_error) => Terminated,
        }
        TlsHandshake internal {
            HandshakeComplete(complete) => PreStartup,
        }
        GssHandshake internal {
            HandshakeComplete(complete) => PreStartup,
        }
        Auth external {}
        Terminated external {}
    }
}

protocol! {
    pub mod server_pre_startup {
        initial PreStartup;
        PreStartup external {
            SslRequest(ssl_request) => SslDecision,
            GssRequest(gss_request) => GssDecision,
            Cancel(cancel) => Terminated,
            Startup(startup) => Auth,
        }
        SslDecision internal {
            Accept(accept) => TlsHandshake,
            Reject(reject) => PreStartup,
            LegacyError(legacy_error) => Terminated,
        }
        GssDecision internal {
            Accept(accept) => GssHandshake,
            Reject(reject) => PreStartup,
            LegacyError(legacy_error) => Terminated,
        }
        TlsHandshake internal {
            HandshakeComplete(complete) => PreStartup,
        }
        GssHandshake internal {
            HandshakeComplete(complete) => PreStartup,
        }
        Auth internal {}
        Terminated internal {}
    }
}

protocol! {
    pub mod authentication {
        initial Auth;
        Auth external {
            Ok(ok) => AwaitingStartupReady,
            Cleartext(cleartext) => PasswordResponse,
            Md5(md5) => PasswordResponse,
            Sasl(sasl) => SaslInitial,
            Gss(gss) => TokenResponse,
            Sspi(sspi) => TokenResponse,
            KerberosV5(kerberos_v5) => TokenResponse,
            Error(error) => Terminated,
        }
        PasswordResponse internal {
            Password(password) => AwaitingAuthOk,
        }
        TokenResponse internal {
            Response(response) => TokenChallenge,
        }
        TokenChallenge external {
            Continue(continue_token) => TokenResponse,
            Ok(ok) => AwaitingStartupReady,
            Error(error) => Terminated,
        }
        SaslInitial internal {
            Initial(initial) => Sasl,
        }
        Sasl external {
            Continue(continue_response) => SaslChallenge,
            Final(final_response) => SaslFinal,
            Error(error) => Terminated,
        }
        SaslChallenge internal {
            Response(response) => Sasl,
        }
        SaslFinal internal {
            Verified(verified) => AwaitingAuthOk,
        }
        AwaitingAuthOk external {
            Ok(ok) => AwaitingStartupReady,
            Error(error) => Terminated,
        }
        AwaitingStartupReady external {
            Ready(ready) => Ready,
        }
        Ready external {}
        Terminated external {}
    }
}

protocol! {
    pub mod backend {
        initial Ready;
        Ready external {
            Query(query) => Simple [Dirty],
            Parse(parse) => ParseResponse [Dirty],
            Bind(bind) => BindResponse [Dirty],
            Describe(describe) => DescribeResponse,
            Execute(execute) => ExecuteResponse [Dirty],
            Close(close) => CloseResponse,
            FunctionCall(function_call) => FunctionResponse [Dirty],
            Terminate(terminate) => Terminated,
        }
        Simple internal {
            Continue(continue_response) => Simple,
            CopyIn(copy_in) => SimpleCopyIn,
            CopyOut(copy_out) => SimpleCopyOut,
            CopyBoth(copy_both) => SimpleCopyBoth,
            Ready(ready) => Ready,
            Error(error) => SimpleError,
        }
        SimpleError internal {
            Ready(ready) => Ready,
        }
        Building external {
            Parse(parse) => ParseResponse [Dirty],
            Bind(bind) => BindResponse [Dirty],
            Describe(describe) => DescribeResponse,
            Execute(execute) => ExecuteResponse [Dirty],
            Close(close) => CloseResponse,
            Flush(flush) => Building,
            Sync(sync) => SyncResponse,
        }
        ParseResponse internal {
            Complete(complete) => Building,
            Error(error) => ExtendedError,
        }
        BindResponse internal {
            Complete(complete) => Building,
            Error(error) => ExtendedError,
        }
        DescribeResponse internal {
            RowDescription(row_description) => Building,
            NoData(no_data) => Building,
            Error(error) => ExtendedError,
        }
        ExecuteResponse internal {
            Continue(continue_response) => ExecuteResponse,
            CopyIn(copy_in) => ExtendedCopyIn,
            CopyOut(copy_out) => ExtendedCopyOut,
            CopyBoth(copy_both) => ExtendedCopyBoth,
            CommandComplete(command_complete) => Building,
            PortalSuspended(portal_suspended) => Building,
            Error(error) => ExtendedError,
        }
        CloseResponse internal {
            Complete(complete) => Building,
            Error(error) => ExtendedError,
        }
        ExtendedError external {
            Discard(discard) => ExtendedError,
            Sync(sync) => SyncResponse,
        }
        SyncResponse internal {
            Ready(ready) => Ready,
        }
        FunctionResponse internal {
            Result(result) => FunctionReady,
            Error(error) => FunctionReady,
        }
        FunctionReady internal {
            Ready(ready) => Ready,
        }
        SimpleCopyIn external {
            Data(data) => SimpleCopyIn,
            Done(done) => SimpleCopyInDone,
            Fail(fail) => SimpleCopyInFailed,
        }
        SimpleCopyInDone internal {
            CommandComplete(command_complete) => SimpleCopyReady,
        }
        SimpleCopyInFailed internal {
            Error(error) => SimpleCopyReady,
        }
        SimpleCopyOut internal {
            Data(data) => SimpleCopyOut,
            Done(done) => SimpleCopyOutDone,
            Error(error) => SimpleCopyReady,
        }
        SimpleCopyOutDone internal {
            CommandComplete(command_complete) => SimpleCopyReady,
        }
        SimpleCopyReady internal {
            Ready(ready) => Ready,
        }
        ExtendedCopyIn external {
            Data(data) => ExtendedCopyIn,
            Done(done) => ExtendedCopyInDone,
            Fail(fail) => ExtendedCopyInFailed,
        }
        ExtendedCopyInDone internal {
            CommandComplete(command_complete) => Building,
        }
        ExtendedCopyInFailed internal {
            Error(error) => ExtendedError,
        }
        ExtendedCopyOut internal {
            Data(data) => ExtendedCopyOut,
            Done(done) => ExtendedCopyOutDone,
            Error(error) => ExtendedError,
        }
        ExtendedCopyOutDone internal {
            CommandComplete(command_complete) => Building,
        }
        SimpleCopyBoth mixed {
            internal SendData(send_data) => SimpleCopyBoth,
            external ReceiveData(receive_data) => SimpleCopyBoth,
            internal SendDone(send_done) => SimpleCopyBothServerDone,
            external ReceiveDone(receive_done) => SimpleCopyBothClientDone,
            external Fail(fail) => SimpleCopyBothFailed,
            internal Error(error) => SimpleCopyReady,
        }
        SimpleCopyBothClientDone internal {
            SendData(send_data) => SimpleCopyBothClientDone,
            SendDone(send_done) => SimpleCopyBothDone,
            Error(error) => SimpleCopyReady,
        }
        SimpleCopyBothServerDone external {
            ReceiveData(receive_data) => SimpleCopyBothServerDone,
            ReceiveDone(receive_done) => SimpleCopyBothDone,
            Fail(fail) => SimpleCopyBothFailed,
        }
        SimpleCopyBothDone internal {
            CommandComplete(command_complete) => SimpleCopyReady,
        }
        SimpleCopyBothFailed internal {
            Error(error) => SimpleCopyReady,
        }
        ExtendedCopyBoth mixed {
            internal SendData(send_data) => ExtendedCopyBoth,
            external ReceiveData(receive_data) => ExtendedCopyBoth,
            internal SendDone(send_done) => ExtendedCopyBothServerDone,
            external ReceiveDone(receive_done) => ExtendedCopyBothClientDone,
            external Fail(fail) => ExtendedCopyBothFailed,
            internal Error(error) => ExtendedError,
        }
        ExtendedCopyBothClientDone internal {
            SendData(send_data) => ExtendedCopyBothClientDone,
            SendDone(send_done) => ExtendedCopyBothDone,
            Error(error) => ExtendedError,
        }
        ExtendedCopyBothServerDone external {
            ReceiveData(receive_data) => ExtendedCopyBothServerDone,
            ReceiveDone(receive_done) => ExtendedCopyBothDone,
            Fail(fail) => ExtendedCopyBothFailed,
        }
        ExtendedCopyBothDone internal {
            CommandComplete(command_complete) => Building,
        }
        ExtendedCopyBothFailed internal {
            Error(error) => ExtendedError,
        }
        Terminated external {}
    }
}

protocol! {
    pub mod server_authentication {
        initial Startup;
        Startup internal {
            Begin(begin) => Auth,
            Reject(reject) => Terminated,
        }
        Auth internal {
            Cleartext(cleartext) => PasswordResponse,
            Md5(md5) => PasswordResponse,
            Sasl(sasl) => SaslInitial,
            Gss(gss) => TokenResponse,
            Sspi(sspi) => TokenResponse,
            KerberosV5(kerberos_v5) => TokenResponse,
            Ok(ok) => StartupReady,
            Error(error) => Terminated,
        }
        PasswordResponse external {
            Response(response) => Auth,
        }
        SaslInitial external {
            Initial(initial) => Sasl,
        }
        Sasl internal {
            Continue(continue_response) => SaslResponse,
            Final(final_response) => Auth,
            Error(error) => Terminated,
        }
        SaslResponse external {
            Response(response) => Sasl,
        }
        TokenResponse external {
            Response(response) => TokenPolicy,
        }
        TokenPolicy internal {
            Continue(continue_token) => TokenResponse,
            Verified(verified) => Auth,
            Error(error) => Terminated,
        }
        StartupReady internal {
            ParameterStatus(parameter_status) => StartupReady,
            BackendKeyData(backend_key_data) => StartupReady,
            NegotiateProtocol(negotiate_protocol) => StartupReady,
            Ready(ready) => Ready,
        }
        Ready external {}
        Terminated external {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;

    use super::{
        authentication, backend, frontend, pre_startup, server_authentication, server_pre_startup,
    };
    use crate::{
        Conn,
        auth::AuthOffer,
        codec::{Authentication, Bind, Execute, Parse, TransactionStatus},
        demux::SessionItem,
        session::{AwaitingReadyTransition, ReadyState},
        startup::{ProtocolVersion, StartupMessage},
    };
    use frontend::{Event, RuntimeFsm, RuntimeState, Session};

    #[test]
    fn generated_typestate_and_runtime_accept_the_extended_loop() {
        let _typed = Session::new()
            .begin_extended()
            .parse()
            .bind()
            .execute()
            .sync()
            .ready();

        let mut runtime = RuntimeFsm::new();
        for event in [
            Event::BeginExtended,
            Event::Parse,
            Event::Bind,
            Event::Execute,
            Event::Sync,
            Event::Ready,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), RuntimeState::Ready);
    }

    #[test]
    fn generated_backend_discards_failed_pipeline_until_sync() {
        let _typed = backend::Session::new()
            .parse()
            .error()
            .discard()
            .discard()
            .sync()
            .ready()
            .terminate();

        let mut runtime = backend::RuntimeFsm::new();
        for event in [
            backend::Event::Parse,
            backend::Event::Error,
            backend::Event::Discard,
            backend::Event::Discard,
            backend::Event::Sync,
            backend::Event::Ready,
            backend::Event::Terminate,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), backend::RuntimeState::Terminated);
    }

    #[test]
    fn generated_backend_copy_resumes_its_enclosing_session() {
        let _simple = backend::Session::new()
            .query()
            .copy_in()
            .data()
            .done()
            .command_complete()
            .ready();
        let _extended = backend::Session::new()
            .execute()
            .copy_out()
            .data()
            .done()
            .command_complete()
            .sync()
            .ready();

        let mut runtime = backend::RuntimeFsm::new();
        for event in [
            backend::Event::Execute,
            backend::Event::CopyOut,
            backend::Event::Data,
            backend::Event::Done,
            backend::Event::CommandComplete,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), backend::RuntimeState::Building);
        runtime.step(backend::Event::Sync).unwrap();
        runtime.step(backend::Event::Ready).unwrap();
        assert_eq!(runtime.state(), backend::RuntimeState::Ready);
    }

    #[test]
    fn generated_backend_copy_both_tracks_independent_half_closes() {
        let _server_first = backend::Session::new()
            .query()
            .copy_both()
            .send_data()
            .receive_data()
            .send_done()
            .receive_data()
            .receive_done()
            .command_complete()
            .ready();
        let _client_first = backend::Session::new()
            .execute()
            .copy_both()
            .receive_done()
            .send_data()
            .send_done()
            .command_complete()
            .sync()
            .ready();

        let mut runtime = backend::RuntimeFsm::new();
        runtime.step(backend::Event::Query).unwrap();
        runtime.step(backend::Event::CopyBoth).unwrap();
        assert_eq!(runtime.choice(), backend::ChoiceKind::Mixed);
        assert_eq!(
            runtime.event_choice(backend::Event::SendData),
            Some(backend::ChoiceKind::Internal)
        );
        assert_eq!(
            runtime.event_choice(backend::Event::ReceiveData),
            Some(backend::ChoiceKind::External)
        );
        runtime.step(backend::Event::SendDone).unwrap();
        assert!(runtime.step(backend::Event::SendData).is_err());
        runtime.step(backend::Event::ReceiveDone).unwrap();
        runtime.step(backend::Event::CommandComplete).unwrap();
        runtime.step(backend::Event::Ready).unwrap();
        assert_eq!(runtime.state(), backend::RuntimeState::Ready);
    }

    #[test]
    fn generated_runtime_rejects_query_during_copy() {
        let mut runtime = RuntimeFsm::new();
        runtime.step(Event::Query).unwrap();
        runtime.step(Event::CopyIn).unwrap();
        assert!(runtime.step(Event::Query).is_err());
        assert_eq!(
            runtime.event_choice(Event::Error),
            Some(frontend::ChoiceKind::External)
        );
        runtime.step(Event::Error).unwrap();
        assert_eq!(runtime.state(), RuntimeState::Draining);
    }

    #[test]
    fn generated_copy_both_waits_for_both_half_closes() {
        let mut directions = RuntimeFsm::new();
        directions.step(Event::Query).unwrap();
        directions.step(Event::CopyBoth).unwrap();
        assert_eq!(directions.choice(), frontend::ChoiceKind::Mixed);
        assert_eq!(
            directions.event_choice(Event::SendCopyData),
            Some(frontend::ChoiceKind::Internal)
        );
        assert_eq!(
            directions.event_choice(Event::ReceiveCopyData),
            Some(frontend::ChoiceKind::External)
        );

        let mut client_first = RuntimeFsm::new();
        for event in [
            Event::Query,
            Event::CopyBoth,
            Event::SendCopyDone,
            Event::ReceiveCopyData,
            Event::ReceiveCopyDone,
        ] {
            client_first.step(event).unwrap();
        }
        assert_eq!(client_first.state(), RuntimeState::AwaitingReady);

        let mut server_first = RuntimeFsm::new();
        for event in [
            Event::Query,
            Event::CopyBoth,
            Event::ReceiveCopyDone,
            Event::SendCopyData,
            Event::SendCopyDone,
        ] {
            server_first.step(event).unwrap();
        }
        assert_eq!(server_first.state(), RuntimeState::AwaitingReady);
    }

    #[test]
    fn generated_function_call_and_termination_match_typed_paths() {
        let _function = Session::new()
            .function_call()
            .function_response()
            .ready()
            .terminate();

        let mut runtime = RuntimeFsm::new();
        for event in [
            Event::FunctionCall,
            Event::FunctionResponse,
            Event::Ready,
            Event::Terminate,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), RuntimeState::Terminated);
    }

    #[test]
    fn generated_pool_reset_requires_discard_and_ready_evidence() {
        let _typed = Session::new()
            .reset()
            .continue_reset()
            .discard_complete()
            .continue_reset()
            .ready_clean();

        let mut runtime = RuntimeFsm::new();
        runtime.step(Event::Reset).unwrap();
        assert!(runtime.step(Event::ReadyClean).is_err());
        runtime.step(Event::DiscardComplete).unwrap();
        runtime.step(Event::ReadyClean).unwrap();
        assert_eq!(runtime.state(), RuntimeState::Ready);

        let dirty: Conn<(), crate::auth::Ready, crate::Dirty> =
            Conn::new(()).transition().mark_dirty();
        let (resetting, _) = dirty.begin_reset().unwrap();
        let crate::session::ResettingTransition::Complete(complete) =
            resetting.offer(SessionItem::CommandComplete {
                tag: Bytes::from_static(b"DISCARD ALL"),
                command: crate::demux::CommandIndex(1),
                notices: Vec::new(),
            })
        else {
            panic!("DISCARD ALL did not advance reset recovery")
        };
        let crate::session::ResetCompleteTransition::Ready(ready) =
            complete.offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
        else {
            panic!("idle readiness did not restore pristine evidence")
        };
        ready.release();
    }

    #[test]
    fn generated_transport_session_tracks_cleanliness_effects() {
        struct InitiallyClean;

        let ready: frontend::TypedSession<(), frontend::Ready, InitiallyClean> =
            frontend::TypedSession::with_transport(());
        let dirty: frontend::TypedSession<(), frontend::Simple, frontend::Dirty> = ready.query();
        let dirty: frontend::TypedSession<(), frontend::Ready, frontend::Dirty> = dirty.ready();
        assert_eq!(dirty.into_transport(), ());

        let dirty: frontend::TypedSession<(), frontend::Ready, frontend::Dirty> =
            frontend::TypedSession::with_transport(());
        let clean: frontend::TypedSession<(), frontend::Ready, frontend::Pristine> =
            dirty.reset().discard_complete().ready_clean();
        assert_eq!(clean.into_transport(), ());
    }

    #[test]
    fn generated_frontend_parse_payload_is_inspectable_and_fallible() {
        #[derive(Debug)]
        struct Clean;

        let ready: frontend::TypedSession<Vec<crate::codec::Frame>, frontend::Ready, Clean> =
            frontend::TypedSession::with_transport(Vec::new());
        let parse = Parse {
            statement: Bytes::from_static(b"statement"),
            query: Bytes::from_static(b"select encrypted_column"),
            parameter_types: vec![23],
        };
        let (building, query): (
            frontend::TypedSession<Vec<crate::codec::Frame>, frontend::Building, frontend::Dirty>,
            Bytes,
        ) = ready
            .begin_extended()
            .parse(parse, |frames, message| {
                let query = message.query.clone();
                frames.push(message.to_frame()?);
                Ok::<_, std::io::Error>(query)
            })
            .unwrap();
        assert_eq!(query, Bytes::from_static(b"select encrypted_column"));
        assert_eq!(building.into_transport()[0].tag, b'P');

        let ready: frontend::TypedSession<Vec<crate::codec::Frame>, frontend::Ready, Clean> =
            frontend::TypedSession::with_transport(Vec::new());
        let invalid = Parse {
            statement: Bytes::from_static(b"bad\0statement"),
            query: Bytes::from_static(b"select 1"),
            parameter_types: vec![],
        };
        let (building, error) = ready
            .begin_extended()
            .parse(invalid, |frames, message| {
                frames.push(message.to_frame()?);
                Ok::<_, std::io::Error>(())
            })
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(building.into_transport().is_empty());
    }

    #[test]
    fn generated_pre_startup_requires_handshake_before_startup() {
        struct Clean;
        struct Tcp;
        struct Tls(Tcp);

        let _typed = pre_startup::Session::new()
            .ssl_request()
            .accept()
            .complete()
            .startup();

        let mut runtime = pre_startup::RuntimeFsm::new();
        runtime.step(pre_startup::Event::SslRequest).unwrap();
        assert!(runtime.step(pre_startup::Event::Startup).is_err());
        runtime.step(pre_startup::Event::Accept).unwrap();
        runtime.step(pre_startup::Event::HandshakeComplete).unwrap();
        runtime.step(pre_startup::Event::Startup).unwrap();

        let pre_startup: pre_startup::TypedSession<Tcp, pre_startup::PreStartup, Clean> =
            pre_startup::TypedSession::with_transport(Tcp);
        let auth: pre_startup::TypedSession<Tls, pre_startup::Auth, Clean> = pre_startup
            .ssl_request()
            .accept()
            .map_transport(Tls)
            .complete()
            .startup();
        let Tls(_tcp) = auth.into_transport();
    }

    #[test]
    fn generated_server_pre_startup_is_the_client_facing_dual() {
        let _plaintext = server_pre_startup::Session::new()
            .ssl_request()
            .reject()
            .startup();
        let _encrypted = server_pre_startup::Session::new()
            .ssl_request()
            .accept()
            .complete()
            .startup();

        let mut runtime = server_pre_startup::RuntimeFsm::new();
        assert_eq!(runtime.choice(), server_pre_startup::ChoiceKind::External);
        runtime.step(server_pre_startup::Event::SslRequest).unwrap();
        assert_eq!(runtime.choice(), server_pre_startup::ChoiceKind::Internal);
        assert!(runtime.step(server_pre_startup::Event::Startup).is_err());
        runtime.step(server_pre_startup::Event::Reject).unwrap();
        runtime.step(server_pre_startup::Event::Startup).unwrap();
        assert_eq!(runtime.state(), server_pre_startup::RuntimeState::Auth);

        assert_eq!(
            pre_startup::RuntimeFsm::new().dual_event_choice(pre_startup::Event::SslRequest),
            Some(pre_startup::ChoiceKind::External)
        );
    }

    #[test]
    fn generated_sasl_continuation_is_recursive() {
        let _typed = authentication::Session::new()
            .sasl()
            .initial()
            .continue_response()
            .response()
            .continue_response()
            .response()
            .final_response()
            .verified()
            .ok()
            .ready();

        let mut runtime = authentication::RuntimeFsm::new();
        for event in [
            authentication::Event::Sasl,
            authentication::Event::Initial,
            authentication::Event::Continue,
            authentication::Event::Response,
            authentication::Event::Continue,
            authentication::Event::Response,
            authentication::Event::Final,
            authentication::Event::Verified,
            authentication::Event::Ok,
            authentication::Event::Ready,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), authentication::RuntimeState::Ready);
    }

    #[test]
    fn generated_token_authentication_is_recursive() {
        let _typed = authentication::Session::new()
            .gss()
            .response()
            .continue_token()
            .response()
            .ok()
            .ready();

        let mut runtime = authentication::RuntimeFsm::new();
        for event in [
            authentication::Event::Gss,
            authentication::Event::Response,
            authentication::Event::Continue,
            authentication::Event::Response,
            authentication::Event::Ok,
            authentication::Event::Ready,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), authentication::RuntimeState::Ready);
    }

    #[test]
    fn generated_server_authentication_keeps_mechanisms_independent() {
        let _typed = server_authentication::Session::new()
            .begin()
            .sasl()
            .initial()
            .continue_response()
            .response()
            .final_response()
            .ok()
            .negotiate_protocol()
            .parameter_status()
            .backend_key_data()
            .ready();

        let mut runtime = server_authentication::RuntimeFsm::new();
        for event in [
            server_authentication::Event::Begin,
            server_authentication::Event::Gss,
            server_authentication::Event::Response,
            server_authentication::Event::Continue,
            server_authentication::Event::Response,
            server_authentication::Event::Verified,
            server_authentication::Event::Ok,
            server_authentication::Event::Ready,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), server_authentication::RuntimeState::Ready);
    }

    #[test]
    fn runtime_fsm_tracks_the_handwritten_extended_typestate() {
        let message = StartupMessage {
            version: ProtocolVersion::V3_2,
            parameters: BTreeMap::new(),
        };
        let (startup, _) = Conn::new(()).startup(&message).unwrap();
        let AuthOffer::Ok(awaiting_ready) =
            startup.authentication().offer(Authentication::Ok).unwrap()
        else {
            panic!("authentication projected to the wrong branch")
        };
        let ready = awaiting_ready
            .offer_ready(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
            .unwrap();
        let mut runtime = RuntimeFsm::new();

        let building = ready.begin_extended();
        runtime.step(Event::BeginExtended).unwrap();
        let (building, _) = building
            .push_parse(&Parse {
                statement: Bytes::from_static(b"s"),
                query: Bytes::from_static(b"select $1"),
                parameter_types: vec![23],
            })
            .unwrap();
        runtime.step(Event::Parse).unwrap();
        let (bound, _) = building
            .push_bind(&Bind {
                portal: Bytes::new(),
                statement: Bytes::from_static(b"s"),
                parameter_formats: vec![],
                parameters: vec![Some(Bytes::from_static(b"42"))],
                result_formats: vec![],
            })
            .unwrap();
        runtime.step(Event::Bind).unwrap();
        let (bound, _) = bound
            .push_execute(&Execute {
                portal: Bytes::new(),
                max_rows: 0,
            })
            .unwrap();
        runtime.step(Event::Execute).unwrap();
        let (awaiting_ready, _) = bound.push_sync();
        runtime.step(Event::Sync).unwrap();
        let AwaitingReadyTransition::Ready(ReadyState::Clean(ready)) =
            awaiting_ready.offer(SessionItem::ReadyForQuery {
                status: TransactionStatus::Idle,
                parameters_changed: false,
            })
        else {
            panic!("ready evidence projected to the wrong branch")
        };
        runtime.step(Event::Ready).unwrap();

        assert_eq!(runtime.state(), RuntimeState::Ready);
        ready.into_transport();
    }
}
