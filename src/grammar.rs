//! Generated frontend query grammar and differential-test runtime FSM.

use pg_proto_fsm::protocol;

protocol! {
    pub mod frontend {
        initial Ready;
        Ready internal {
            Query(query) => Simple,
            BeginExtended(begin_extended) => Building,
            FunctionCall(function_call) => FunctionCalling,
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
            Parse(parse) => Building,
            Describe(describe) => Building,
            Bind(bind) => BoundBuilding,
            Close(close) => Building,
            Flush(flush) => Building,
            Sync(sync) => AwaitingReady,
        }
        BoundBuilding internal {
            Parse(parse) => BoundBuilding,
            Describe(describe) => BoundBuilding,
            Bind(bind) => BoundBuilding,
            Execute(execute) => BoundBuilding,
            Close(close) => BoundBuilding,
            Flush(flush) => BoundBuilding,
            Sync(sync) => AwaitingReady,
        }
        AwaitingReady external {
            Continue(continue_response) => AwaitingReady,
            Ready(ready) => Ready,
            Error(error) => Draining,
        }
        CopyIn internal {
            CopyData(copy_data) => CopyIn,
            CopyDone(copy_done) => AwaitingReady,
            CopyFail(copy_fail) => AwaitingReady,
        }
        CopyOut external {
            CopyData(copy_data) => CopyOut,
            CopyDone(copy_done) => AwaitingReady,
            Error(error) => Draining,
        }
        CopyBoth internal {
            SendCopyData(send_copy_data) => CopyBoth,
            ReceiveCopyData(receive_copy_data) => CopyBoth,
            SendCopyDone(send_copy_done) => CopyBothClientDone,
            ReceiveCopyDone(receive_copy_done) => CopyBothServerDone,
            Error(error) => Draining,
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
    pub mod authentication {
        initial Auth;
        Auth external {
            Ok(ok) => AwaitingStartupReady,
            Cleartext(cleartext) => PasswordResponse,
            Md5(md5) => PasswordResponse,
            Sasl(sasl) => SaslInitial,
            Gss(gss) => Auth,
            Sspi(sspi) => Auth,
            KerberosV5(kerberos_v5) => Auth,
            Error(error) => Terminated,
        }
        PasswordResponse internal {
            Password(password) => AwaitingAuthOk,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;

    use super::{authentication, frontend, pre_startup};
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
    fn generated_runtime_rejects_query_during_copy() {
        let mut runtime = RuntimeFsm::new();
        runtime.step(Event::Query).unwrap();
        runtime.step(Event::CopyIn).unwrap();
        assert!(runtime.step(Event::Query).is_err());
    }

    #[test]
    fn generated_copy_both_waits_for_both_half_closes() {
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
    fn generated_pre_startup_requires_handshake_before_startup() {
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
        ready.release();
    }
}
