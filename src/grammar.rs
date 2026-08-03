//! Generated frontend query grammar and differential-test runtime FSM.

use pg_proto_fsm::protocol;

protocol! {
    pub mod frontend {
        initial Ready;
        Ready {
            Query(query) => Simple,
            BeginExtended(begin_extended) => Building,
        }
        Simple {
            Continue(continue_response) => Simple,
            CopyIn(enter_copy_in) => CopyIn,
            CopyOut(enter_copy_out) => CopyOut,
            CopyBoth(enter_copy_both) => CopyBoth,
            Ready(ready) => Ready,
            Error(error) => Draining,
        }
        Building {
            Parse(parse) => Building,
            Describe(describe) => Building,
            Bind(bind) => BoundBuilding,
            Close(close) => Building,
            Flush(flush) => Building,
            Sync(sync) => AwaitingReady,
        }
        BoundBuilding {
            Parse(parse) => BoundBuilding,
            Describe(describe) => BoundBuilding,
            Bind(bind) => BoundBuilding,
            Execute(execute) => BoundBuilding,
            Close(close) => BoundBuilding,
            Flush(flush) => BoundBuilding,
            Sync(sync) => AwaitingReady,
        }
        AwaitingReady {
            Continue(continue_response) => AwaitingReady,
            Ready(ready) => Ready,
            Error(error) => Draining,
        }
        CopyIn {
            CopyData(copy_data) => CopyIn,
            CopyDone(copy_done) => AwaitingReady,
            CopyFail(copy_fail) => AwaitingReady,
        }
        CopyOut {
            CopyData(copy_data) => CopyOut,
            CopyDone(copy_done) => AwaitingReady,
            Error(error) => Draining,
        }
        CopyBoth {
            SendCopyData(send_copy_data) => CopyBoth,
            ReceiveCopyData(receive_copy_data) => CopyBoth,
            CopyDone(copy_done) => AwaitingReady,
            Error(error) => Draining,
        }
        Draining {
            Continue(continue_response) => Draining,
            Ready(ready) => Ready,
        }
    }
}

protocol! {
    pub mod pre_startup {
        initial PreStartup;
        PreStartup {
            SslRequest(ssl_request) => AwaitingSslReply,
            GssRequest(gss_request) => AwaitingGssReply,
            Cancel(cancel) => Terminated,
            Startup(startup) => Auth,
        }
        AwaitingSslReply {
            Accept(accept) => TlsHandshake,
            Reject(reject) => PreStartup,
            LegacyError(legacy_error) => Terminated,
        }
        AwaitingGssReply {
            Accept(accept) => GssHandshake,
            Reject(reject) => PreStartup,
            LegacyError(legacy_error) => Terminated,
        }
        TlsHandshake {
            HandshakeComplete(complete) => PreStartup,
        }
        GssHandshake {
            HandshakeComplete(complete) => PreStartup,
        }
        Auth {}
        Terminated {}
    }
}

protocol! {
    pub mod authentication {
        initial Auth;
        Auth {
            Ok(ok) => AwaitingStartupReady,
            Cleartext(cleartext) => PasswordResponse,
            Md5(md5) => PasswordResponse,
            Sasl(sasl) => SaslInitial,
            Gss(gss) => Auth,
            Sspi(sspi) => Auth,
            KerberosV5(kerberos_v5) => Auth,
        }
        PasswordResponse {
            Password(password) => AwaitingAuthOk,
        }
        SaslInitial {
            Initial(initial) => Sasl,
        }
        Sasl {
            Continue(continue_response) => Sasl,
            Final(final_response) => AwaitingAuthOk,
        }
        AwaitingAuthOk {
            Ok(ok) => AwaitingStartupReady,
        }
        AwaitingStartupReady {
            Ready(ready) => Ready,
        }
        Ready {}
    }
}

#[cfg(test)]
mod tests {
    use super::{authentication, frontend, pre_startup};
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
            .continue_response()
            .final_response()
            .ok()
            .ready();

        let mut runtime = authentication::RuntimeFsm::new();
        for event in [
            authentication::Event::Sasl,
            authentication::Event::Initial,
            authentication::Event::Continue,
            authentication::Event::Continue,
            authentication::Event::Final,
            authentication::Event::Ok,
            authentication::Event::Ready,
        ] {
            runtime.step(event).unwrap();
        }
        assert_eq!(runtime.state(), authentication::RuntimeState::Ready);
    }
}
