//! Generated `PostgreSQL` grammars and differential-test runtime FSMs.
//!
//! Each generated role module embeds its railroad diagram directly in its
//! rustdoc landing page. Open a module such as [`frontend`] or [`backend`] to
//! review the grammar alongside its generated transition API.

use pg_proto_fsm::protocol;

protocol! {
    pub mod frontend {
        initial Ready;
        messages {
            internal: crate::codec::FrontendMessage,
            external: crate::codec::BackendMessage,
        }
        associations {
            interface: crate::middleware::PhaseAssociation;
            seal: crate::middleware::phase_association_seal::Sealed;
            inbound {
                direction: crate::middleware::Inbound;
                role: crate::middleware::ServerRole;
                wire: crate::codec::BackendMessage;
                message: crate::middleware::TypedBackendMessage<external>;
            }
            outbound {
                direction: crate::middleware::Outbound;
                role: crate::middleware::ClientRole;
                wire: crate::codec::FrontendMessage;
                message: internal;
            }
        }
        Ready internal {
            associate { inbound: crate::auth::Ready; outbound: crate::auth::Ready; }
            Query(query: bytes::Bytes) => Simple [Dirty] <= crate::codec::FrontendMessage::Query(_),
            BeginExtended(begin_extended) => Building,
            FunctionCall(function_call: crate::codec::FunctionCall) => FunctionCalling [Dirty] <= crate::codec::FrontendMessage::FunctionCall(_),
            Reset(reset) => Resetting [Dirty],
            Terminate(terminate) => Terminated <= crate::codec::FrontendMessage::Terminate,
        }
        FunctionCalling external {
            associate { inbound: crate::session::FunctionCalling; outbound: none; }
            FunctionResponse(function_response: bytes::Bytes) => AwaitingReady <= crate::codec::BackendMessage::FunctionCallResponse(_),
            Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        Simple external {
            associate { inbound: crate::session::SimpleQuery; outbound: none; }
            Continue(continue_response: crate::codec::BackendMessage) => Simple <= crate::codec::BackendMessage::RowDescription(_)
                | crate::codec::BackendMessage::DataRow(_)
                | crate::codec::BackendMessage::CommandComplete(_)
                | crate::codec::BackendMessage::EmptyQueryResponse,
            CopyIn(enter_copy_in: crate::codec::CopyResponse) => CopyIn <= crate::codec::BackendMessage::CopyInResponse(_),
            CopyOut(enter_copy_out: crate::codec::CopyResponse) => CopyOut <= crate::codec::BackendMessage::CopyOutResponse(_),
            CopyBoth(enter_copy_both: crate::codec::CopyResponse) => CopyBoth <= crate::codec::BackendMessage::CopyBothResponse(_),
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
            Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        Building internal {
            associate { inbound: crate::session::Building; outbound: crate::session::Building; }
            Parse(parse: crate::codec::Parse) => Building [Dirty] <= crate::codec::FrontendMessage::Parse(_),
            Describe(describe: crate::codec::Describe) => Building <= crate::codec::FrontendMessage::Describe(_),
            Bind(bind: crate::codec::Bind) => BoundBuilding [Dirty] <= crate::codec::FrontendMessage::Bind(_),
            Close(close: crate::codec::Close) => Building <= crate::codec::FrontendMessage::Close(_),
            Flush(flush) => Building <= crate::codec::FrontendMessage::Flush,
            Sync(sync) => AwaitingReady <= crate::codec::FrontendMessage::Sync,
        }
        BoundBuilding internal {
            associate { inbound: crate::session::BoundBuilding; outbound: crate::session::BoundBuilding; }
            Parse(parse: crate::codec::Parse) => BoundBuilding [Dirty] <= crate::codec::FrontendMessage::Parse(_),
            Describe(describe: crate::codec::Describe) => BoundBuilding <= crate::codec::FrontendMessage::Describe(_),
            Bind(bind: crate::codec::Bind) => BoundBuilding [Dirty] <= crate::codec::FrontendMessage::Bind(_),
            Execute(execute: crate::codec::Execute) => BoundBuilding <= crate::codec::FrontendMessage::Execute(_),
            Close(close: crate::codec::Close) => BoundBuilding <= crate::codec::FrontendMessage::Close(_),
            Flush(flush) => BoundBuilding <= crate::codec::FrontendMessage::Flush,
            Sync(sync) => AwaitingReady <= crate::codec::FrontendMessage::Sync,
        }
        AwaitingReady external {
            associate { inbound: crate::session::AwaitingReady; outbound: none; }
            Continue(continue_response: crate::codec::BackendMessage) => AwaitingReady <= crate::codec::BackendMessage::ParseComplete
                | crate::codec::BackendMessage::BindComplete
                | crate::codec::BackendMessage::CloseComplete
                | crate::codec::BackendMessage::RowDescription(_)
                | crate::codec::BackendMessage::NoData
                | crate::codec::BackendMessage::ParameterDescription(_)
                | crate::codec::BackendMessage::DataRow(_)
                | crate::codec::BackendMessage::CommandComplete(_)
                | crate::codec::BackendMessage::PortalSuspended
                | crate::codec::BackendMessage::EmptyQueryResponse,
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
            Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        CopyIn mixed {
            associate { inbound: crate::session::CopyIn; outbound: crate::session::CopyIn; }
            internal CopyData(copy_data: bytes::Bytes) => CopyIn <= crate::codec::FrontendMessage::CopyData(_),
            internal CopyDone(copy_done) => AwaitingReady <= crate::codec::FrontendMessage::CopyDone,
            internal CopyFail(copy_fail: bytes::Bytes) => AwaitingReady <= crate::codec::FrontendMessage::CopyFail(_),
            external Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        CopyOut external {
            associate { inbound: crate::session::CopyOut; outbound: none; }
            CopyData(copy_data: bytes::Bytes) => CopyOut <= crate::codec::BackendMessage::CopyData(_),
            CopyDone(copy_done) => AwaitingReady <= crate::codec::BackendMessage::CopyDone,
            Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        CopyBoth mixed {
            associate { inbound: crate::session::CopyBoth; outbound: crate::session::CopyBoth; }
            internal SendCopyData(send_copy_data: bytes::Bytes) => CopyBoth <= crate::codec::FrontendMessage::CopyData(_),
            external ReceiveCopyData(receive_copy_data: bytes::Bytes) => CopyBoth <= crate::codec::BackendMessage::CopyData(_),
            internal SendCopyDone(send_copy_done) => CopyBothClientDone <= crate::codec::FrontendMessage::CopyDone,
            external ReceiveCopyDone(receive_copy_done) => CopyBothServerDone <= crate::codec::BackendMessage::CopyDone,
            external Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        CopyBothClientDone external {
            associate { inbound: crate::session::CopyBothClientDone; outbound: none; }
            ReceiveCopyData(receive_copy_data: bytes::Bytes) => CopyBothClientDone <= crate::codec::BackendMessage::CopyData(_),
            ReceiveCopyDone(receive_copy_done) => AwaitingReady <= crate::codec::BackendMessage::CopyDone,
            Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        CopyBothServerDone internal {
            associate { inbound: crate::session::CopyBothServerDone; outbound: crate::session::CopyBothServerDone; }
            SendCopyData(send_copy_data: bytes::Bytes) => CopyBothServerDone <= crate::codec::FrontendMessage::CopyData(_),
            SendCopyDone(send_copy_done) => AwaitingReady <= crate::codec::FrontendMessage::CopyDone,
        }
        Draining external {
            associate { inbound: crate::session::Draining; outbound: none; }
            Continue(continue_response: crate::codec::BackendMessage) => Draining <= crate::codec::BackendMessage::RowDescription(_)
                | crate::codec::BackendMessage::DataRow(_)
                | crate::codec::BackendMessage::CommandComplete(_)
                | crate::codec::BackendMessage::EmptyQueryResponse
                | crate::codec::BackendMessage::ParseComplete
                | crate::codec::BackendMessage::BindComplete
                | crate::codec::BackendMessage::CloseComplete
                | crate::codec::BackendMessage::NoData
                | crate::codec::BackendMessage::ParameterDescription(_)
                | crate::codec::BackendMessage::PortalSuspended,
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
        }
        Resetting external {
            associate { inbound: crate::session::Resetting; outbound: none; }
            Continue(continue_reset: crate::codec::BackendMessage) => Resetting <= crate::codec::BackendMessage::RowDescription(_)
                | crate::codec::BackendMessage::DataRow(_)
                | crate::codec::BackendMessage::EmptyQueryResponse,
            DiscardComplete(discard_complete: bytes::Bytes) => ResetComplete <= crate::codec::BackendMessage::CommandComplete(_),
            Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ResetComplete external {
            associate { inbound: crate::session::ResetComplete; outbound: none; }
            Continue(continue_reset: crate::codec::BackendMessage) => ResetComplete <= crate::codec::BackendMessage::RowDescription(_)
                | crate::codec::BackendMessage::DataRow(_)
                | crate::codec::BackendMessage::CommandComplete(_)
                | crate::codec::BackendMessage::EmptyQueryResponse,
            ReadyClean(ready_clean: crate::codec::TransactionStatus) => Ready [Pristine] <= crate::codec::BackendMessage::ReadyForQuery(crate::codec::TransactionStatus::Idle),
            ReadyDirty(ready_dirty: crate::codec::TransactionStatus) => Ready [Dirty] <= crate::codec::BackendMessage::ReadyForQuery(crate::codec::TransactionStatus::InTransaction | crate::codec::TransactionStatus::FailedTransaction),
            Error(error: crate::codec::DiagnosticResponse) => Draining <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        Terminated external {
            associate { inbound: none; outbound: none; }
        }
    }
}

protocol! {
    pub mod pre_startup {
        initial PreStartup;
        messages {
            internal: crate::pre_startup::PreStartupMessage,
            external: crate::pre_startup::EncryptionReply,
        }
        associations {
            interface: crate::middleware::PhaseAssociation;
            seal: crate::middleware::phase_association_seal::Sealed;
            inbound {
                direction: crate::middleware::Inbound;
                role: crate::middleware::ServerRole;
                wire: crate::pre_startup::EncryptionReply;
                message: external;
            }
            outbound {
                direction: crate::middleware::Outbound;
                role: crate::middleware::ClientRole;
                wire: crate::pre_startup::PreStartupMessage;
                message: internal;
            }
        }
        PreStartup internal {
            associate { inbound: none; outbound: crate::pre_startup::PreStartup; }
            SslRequest(ssl_request) => AwaitingSslReply <= crate::pre_startup::PreStartupMessage::SslRequest,
            GssRequest(gss_request) => AwaitingGssReply <= crate::pre_startup::PreStartupMessage::GssEncRequest,
            Cancel(cancel: (u32, bytes::Bytes)) => Terminated <= crate::pre_startup::PreStartupMessage::CancelRequest { .. },
            Startup(startup: crate::startup::StartupMessage) => Auth <= crate::pre_startup::PreStartupMessage::Startup(_),
        }
        AwaitingSslReply external {
            associate { inbound: crate::pre_startup::AwaitingSslReply; outbound: none; }
            Accept(accept) => TlsHandshake <= crate::pre_startup::EncryptionReply::Accepted,
            Reject(reject) => PreStartup <= crate::pre_startup::EncryptionReply::Rejected,
            LegacyError(legacy_error) => Terminated <= crate::pre_startup::EncryptionReply::LegacyError,
        }
        AwaitingGssReply external {
            associate { inbound: crate::pre_startup::AwaitingGssReply; outbound: none; }
            Accept(accept) => GssHandshake <= crate::pre_startup::EncryptionReply::Accepted,
            Reject(reject) => PreStartup <= crate::pre_startup::EncryptionReply::Rejected,
            LegacyError(legacy_error) => Terminated <= crate::pre_startup::EncryptionReply::LegacyError,
        }
        TlsHandshake internal {
            associate { inbound: none; outbound: none; }
            HandshakeComplete(complete) => PreStartup,
        }
        GssHandshake internal {
            associate { inbound: none; outbound: none; }
            HandshakeComplete(complete) => PreStartup,
        }
        Auth external {
            associate { inbound: none; outbound: none; }
        }
        Terminated external {
            associate { inbound: none; outbound: none; }
        }
    }
}

protocol! {
    pub mod server_pre_startup {
        initial PreStartup;
        messages {
            internal: crate::pre_startup::EncryptionReply,
            external: crate::pre_startup::PreStartupMessage,
        }
        associations {
            interface: crate::middleware::PhaseAssociation;
            seal: crate::middleware::phase_association_seal::Sealed;
            inbound {
                direction: crate::middleware::Inbound;
                role: crate::middleware::ClientRole;
                wire: crate::pre_startup::PreStartupMessage;
                message: external;
            }
            outbound {
                direction: crate::middleware::Outbound;
                role: crate::middleware::ServerRole;
                wire: crate::pre_startup::EncryptionReply;
                message: internal;
            }
        }
        PreStartup external {
            associate { inbound: crate::pre_startup::PreStartup; outbound: none; }
            SslRequest(ssl_request) => SslDecision <= crate::pre_startup::PreStartupMessage::SslRequest,
            GssRequest(gss_request) => GssDecision <= crate::pre_startup::PreStartupMessage::GssEncRequest,
            Cancel(cancel: (u32, bytes::Bytes)) => Terminated <= crate::pre_startup::PreStartupMessage::CancelRequest { .. },
            Startup(startup: crate::startup::StartupMessage) => Auth <= crate::pre_startup::PreStartupMessage::Startup(_),
        }
        SslDecision internal {
            associate { inbound: none; outbound: crate::pre_startup::ServerSslDecision; }
            Accept(accept) => TlsHandshake <= crate::pre_startup::EncryptionReply::Accepted,
            Reject(reject) => PreStartup <= crate::pre_startup::EncryptionReply::Rejected,
            LegacyError(legacy_error) => Terminated <= crate::pre_startup::EncryptionReply::LegacyError,
        }
        GssDecision internal {
            associate { inbound: none; outbound: crate::pre_startup::ServerGssDecision; }
            Accept(accept) => GssHandshake <= crate::pre_startup::EncryptionReply::Accepted,
            Reject(reject) => PreStartup <= crate::pre_startup::EncryptionReply::Rejected,
            LegacyError(legacy_error) => Terminated <= crate::pre_startup::EncryptionReply::LegacyError,
        }
        TlsHandshake internal {
            associate { inbound: none; outbound: none; }
            HandshakeComplete(complete) => PreStartup,
        }
        GssHandshake internal {
            associate { inbound: none; outbound: none; }
            HandshakeComplete(complete) => PreStartup,
        }
        Auth internal {
            associate { inbound: none; outbound: none; }
        }
        Terminated internal {
            associate { inbound: none; outbound: none; }
        }
    }
}

protocol! {
    pub mod authentication {
        initial Auth;
        messages {
            internal: crate::codec::FrontendMessage,
            external: crate::codec::BackendMessage,
        }
        associations {
            interface: crate::middleware::PhaseAssociation;
            seal: crate::middleware::phase_association_seal::Sealed;
            inbound {
                direction: crate::middleware::Inbound;
                role: crate::middleware::ServerRole;
                wire: crate::codec::BackendMessage;
                message: crate::middleware::TypedBackendMessage<external>;
            }
            outbound {
                direction: crate::middleware::Outbound;
                role: crate::middleware::ClientRole;
                wire: crate::codec::FrontendMessage;
                message: internal;
            }
        }
        Auth external {
            associate { inbound: crate::auth::Auth; outbound: none; }
            Negotiate(negotiate: crate::codec::NegotiateProtocolVersion) => Auth <= crate::codec::BackendMessage::NegotiateProtocolVersion(_),
            Ok(ok) => AwaitingStartupReady <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Ok),
            Cleartext(cleartext) => PasswordResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::CleartextPassword),
            Md5(md5: [u8; 4]) => PasswordResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Md5Password { .. }),
            Sasl(sasl: Vec<bytes::Bytes>) => SaslInitial <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Sasl { .. }),
            Gss(gss) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Gss),
            Sspi(sspi) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Sspi),
            KerberosV5(kerberos_v5) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::KerberosV5),
            Error(error: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        PasswordResponse internal {
            associate { inbound: none; outbound: crate::auth::PasswordResponse; }
            Password(password: bytes::Bytes) => AwaitingAuthOk <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        TokenResponse internal {
            associate { inbound: none; outbound: crate::auth::TokenResponse; }
            Response(response: bytes::Bytes) => TokenChallenge <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        TokenChallenge external {
            associate { inbound: crate::auth::TokenChallenge; outbound: none; }
            Continue(continue_token: bytes::Bytes) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::GssContinue(_)),
            Ok(ok) => AwaitingStartupReady <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Ok),
            Error(error: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SaslInitial internal {
            associate { inbound: none; outbound: crate::auth::SaslInitial; }
            Initial(initial: crate::server_auth::SaslInitialResponse) => Sasl <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        Sasl external {
            associate { inbound: crate::auth::Sasl; outbound: none; }
            Continue(continue_response: bytes::Bytes) => SaslChallenge <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::SaslContinue(_)),
            Final(final_response: bytes::Bytes) => SaslFinal <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::SaslFinal(_)),
            Error(error: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SaslChallenge internal {
            associate { inbound: none; outbound: crate::auth::SaslChallenge; }
            Response(response: bytes::Bytes) => Sasl <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        SaslFinal internal {
            associate { inbound: none; outbound: none; }
            Verified(verified) => AwaitingAuthOk,
        }
        AwaitingAuthOk external {
            associate { inbound: crate::auth::AwaitingAuthOk; outbound: none; }
            Ok(ok) => AwaitingStartupReady <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Ok),
            Error(error: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        AwaitingStartupReady external {
            associate { inbound: crate::auth::AwaitingStartupReady; outbound: none; }
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
        }
        Ready external {
            associate { inbound: none; outbound: none; }
        }
        Terminated external {
            associate { inbound: none; outbound: none; }
        }
    }
}

protocol! {
    pub mod backend {
        initial Ready;
        messages {
            internal: crate::codec::BackendMessage,
            external: crate::codec::FrontendMessage,
        }
        associations {
            interface: crate::middleware::PhaseAssociation;
            seal: crate::middleware::phase_association_seal::Sealed;
            inbound {
                direction: crate::middleware::Inbound;
                role: crate::middleware::ClientRole;
                wire: crate::codec::FrontendMessage;
                message: external;
            }
            outbound {
                direction: crate::middleware::Outbound;
                role: crate::middleware::ServerRole;
                wire: crate::codec::BackendMessage;
                message: crate::middleware::TypedBackendMessage<internal>;
            }
        }
        Ready external {
            associate { inbound: crate::auth::Ready; outbound: none; }
            Query(query: bytes::Bytes) => Simple [Dirty] <= crate::codec::FrontendMessage::Query(_),
            Parse(parse: crate::codec::Parse) => ParseResponse [Dirty] <= crate::codec::FrontendMessage::Parse(_),
            Bind(bind: crate::codec::Bind) => BindResponse [Dirty] <= crate::codec::FrontendMessage::Bind(_),
            Describe(describe: crate::codec::Describe) => DescribeResponse <= crate::codec::FrontendMessage::Describe(_),
            Execute(execute: crate::codec::Execute) => ExecuteResponse [Dirty] <= crate::codec::FrontendMessage::Execute(_),
            Close(close: crate::codec::Close) => CloseResponse <= crate::codec::FrontendMessage::Close(_),
            FunctionCall(function_call: crate::codec::FunctionCall) => FunctionResponse [Dirty] <= crate::codec::FrontendMessage::FunctionCall(_),
            Terminate(terminate) => Terminated <= crate::codec::FrontendMessage::Terminate,
        }
        Simple internal {
            associate { inbound: none; outbound: crate::server_session::ServerSimpleQuery; }
            Continue(continue_response: crate::codec::BackendMessage) => Simple <= crate::codec::BackendMessage::RowDescription(_)
                | crate::codec::BackendMessage::DataRow(_)
                | crate::codec::BackendMessage::CommandComplete(_)
                | crate::codec::BackendMessage::EmptyQueryResponse,
            CopyIn(copy_in: crate::codec::CopyResponse) => SimpleCopyIn <= crate::codec::BackendMessage::CopyInResponse(_),
            CopyOut(copy_out: crate::codec::CopyResponse) => SimpleCopyOut <= crate::codec::BackendMessage::CopyOutResponse(_),
            CopyBoth(copy_both: crate::codec::CopyResponse) => SimpleCopyBoth <= crate::codec::BackendMessage::CopyBothResponse(_),
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
            Error(error: crate::codec::DiagnosticResponse) => SimpleError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SimpleError internal {
            associate { inbound: none; outbound: crate::server_session::ServerSimpleError; }
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
        }
        Building external {
            associate { inbound: crate::server_session::ServerBuilding; outbound: crate::server_session::ServerBuilding; }
            Parse(parse: crate::codec::Parse) => ParseResponse [Dirty] <= crate::codec::FrontendMessage::Parse(_),
            Bind(bind: crate::codec::Bind) => BindResponse [Dirty] <= crate::codec::FrontendMessage::Bind(_),
            Describe(describe: crate::codec::Describe) => DescribeResponse <= crate::codec::FrontendMessage::Describe(_),
            Execute(execute: crate::codec::Execute) => ExecuteResponse [Dirty] <= crate::codec::FrontendMessage::Execute(_),
            Close(close: crate::codec::Close) => CloseResponse <= crate::codec::FrontendMessage::Close(_),
            Flush(flush) => Building <= crate::codec::FrontendMessage::Flush,
            Sync(sync) => SyncResponse <= crate::codec::FrontendMessage::Sync,
        }
        ParseResponse internal {
            associate { inbound: none; outbound: crate::server_session::ServerParse; }
            Complete(complete) => Building <= crate::codec::BackendMessage::ParseComplete,
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        BindResponse internal {
            associate { inbound: none; outbound: crate::server_session::ServerBind; }
            Complete(complete) => Building <= crate::codec::BackendMessage::BindComplete,
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        DescribeResponse internal {
            associate { inbound: none; outbound: crate::server_session::ServerDescribe; }
            ParameterDescription(parameter_description: Vec<u32>) => DescribeResponse <= crate::codec::BackendMessage::ParameterDescription(_),
            RowDescription(row_description: crate::codec::RowDescription) => Building <= crate::codec::BackendMessage::RowDescription(_),
            NoData(no_data) => Building <= crate::codec::BackendMessage::NoData,
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ExecuteResponse internal {
            associate { inbound: none; outbound: crate::server_session::ServerExecute; }
            Continue(continue_response: crate::codec::BackendMessage) => ExecuteResponse <= crate::codec::BackendMessage::RowDescription(_)
                | crate::codec::BackendMessage::DataRow(_)
                | crate::codec::BackendMessage::EmptyQueryResponse,
            CopyIn(copy_in: crate::codec::CopyResponse) => ExtendedCopyIn <= crate::codec::BackendMessage::CopyInResponse(_),
            CopyOut(copy_out: crate::codec::CopyResponse) => ExtendedCopyOut <= crate::codec::BackendMessage::CopyOutResponse(_),
            CopyBoth(copy_both: crate::codec::CopyResponse) => ExtendedCopyBoth <= crate::codec::BackendMessage::CopyBothResponse(_),
            CommandComplete(command_complete: bytes::Bytes) => Building <= crate::codec::BackendMessage::CommandComplete(_),
            PortalSuspended(portal_suspended) => Building <= crate::codec::BackendMessage::PortalSuspended,
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        CloseResponse internal {
            associate { inbound: none; outbound: crate::server_session::ServerClose; }
            Complete(complete) => Building <= crate::codec::BackendMessage::CloseComplete,
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ExtendedError external {
            associate { inbound: crate::server_session::ServerExtendedError; outbound: crate::server_session::ServerExtendedError; }
            Discard(discard) => ExtendedError <= crate::codec::FrontendMessage::Parse(_)
                | crate::codec::FrontendMessage::Bind(_)
                | crate::codec::FrontendMessage::Describe(_)
                | crate::codec::FrontendMessage::Execute(_)
                | crate::codec::FrontendMessage::Close(_)
                | crate::codec::FrontendMessage::Flush
                | crate::codec::FrontendMessage::Query(_)
                | crate::codec::FrontendMessage::FunctionCall(_)
                | crate::codec::FrontendMessage::Terminate
                | crate::codec::FrontendMessage::CopyData(_)
                | crate::codec::FrontendMessage::CopyDone
                | crate::codec::FrontendMessage::CopyFail(_)
                | crate::codec::FrontendMessage::PasswordResponse(_),
            Sync(sync) => SyncResponse <= crate::codec::FrontendMessage::Sync,
        }
        SyncResponse internal {
            associate { inbound: none; outbound: crate::server_session::ServerSync; }
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
        }
        FunctionResponse internal {
            associate { inbound: none; outbound: crate::server_session::ServerFunctionCall; }
            Result(result: bytes::Bytes) => FunctionReady <= crate::codec::BackendMessage::FunctionCallResponse(_),
            Error(error: crate::codec::DiagnosticResponse) => FunctionReady <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        FunctionReady internal {
            associate { inbound: none; outbound: [crate::server_session::ServerFunctionCallDone, crate::server_session::ServerFunctionCallError]; }
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
        }
        SimpleCopyIn external {
            associate {
                inbound: crate::server_session::ServerCopyIn<crate::server_session::CopySimple>;
                outbound: crate::server_session::ServerCopyIn<crate::server_session::CopySimple>;
            }
            Data(data: bytes::Bytes) => SimpleCopyIn <= crate::codec::FrontendMessage::CopyData(_),
            Done(done) => SimpleCopyInDone <= crate::codec::FrontendMessage::CopyDone,
            Fail(fail: bytes::Bytes) => SimpleCopyInFailed <= crate::codec::FrontendMessage::CopyFail(_),
        }
        SimpleCopyInDone internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyInDone<crate::server_session::CopySimple>; }
            CommandComplete(command_complete: bytes::Bytes) => SimpleCopyReady <= crate::codec::BackendMessage::CommandComplete(_),
        }
        SimpleCopyInFailed internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyInFailed<crate::server_session::CopySimple>; }
            Error(error: crate::codec::DiagnosticResponse) => SimpleCopyReady <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SimpleCopyOut internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyOut<crate::server_session::CopySimple>; }
            Data(data: bytes::Bytes) => SimpleCopyOut <= crate::codec::BackendMessage::CopyData(_),
            Done(done) => SimpleCopyOutDone <= crate::codec::BackendMessage::CopyDone,
            Error(error: crate::codec::DiagnosticResponse) => SimpleCopyReady <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SimpleCopyOutDone internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyOutDone<crate::server_session::CopySimple>; }
            CommandComplete(command_complete: bytes::Bytes) => SimpleCopyReady <= crate::codec::BackendMessage::CommandComplete(_),
        }
        SimpleCopyReady internal {
            associate { inbound: none; outbound: none; }
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
        }
        ExtendedCopyIn external {
            associate {
                inbound: crate::server_session::ServerCopyIn<crate::server_session::CopyExtended>;
                outbound: crate::server_session::ServerCopyIn<crate::server_session::CopyExtended>;
            }
            Data(data: bytes::Bytes) => ExtendedCopyIn <= crate::codec::FrontendMessage::CopyData(_),
            Done(done) => ExtendedCopyInDone <= crate::codec::FrontendMessage::CopyDone,
            Fail(fail: bytes::Bytes) => ExtendedCopyInFailed <= crate::codec::FrontendMessage::CopyFail(_),
        }
        ExtendedCopyInDone internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyInDone<crate::server_session::CopyExtended>; }
            CommandComplete(command_complete: bytes::Bytes) => Building <= crate::codec::BackendMessage::CommandComplete(_),
        }
        ExtendedCopyInFailed internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyInFailed<crate::server_session::CopyExtended>; }
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ExtendedCopyOut internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyOut<crate::server_session::CopyExtended>; }
            Data(data: bytes::Bytes) => ExtendedCopyOut <= crate::codec::BackendMessage::CopyData(_),
            Done(done) => ExtendedCopyOutDone <= crate::codec::BackendMessage::CopyDone,
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ExtendedCopyOutDone internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyOutDone<crate::server_session::CopyExtended>; }
            CommandComplete(command_complete: bytes::Bytes) => Building <= crate::codec::BackendMessage::CommandComplete(_),
        }
        SimpleCopyBoth mixed {
            associate {
                inbound: crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothOpen>;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothOpen>;
            }
            internal SendData(send_data: bytes::Bytes) => SimpleCopyBoth <= crate::codec::BackendMessage::CopyData(_),
            external ReceiveData(receive_data: bytes::Bytes) => SimpleCopyBoth <= crate::codec::FrontendMessage::CopyData(_),
            internal SendDone(send_done) => SimpleCopyBothServerDone <= crate::codec::BackendMessage::CopyDone,
            external ReceiveDone(receive_done) => SimpleCopyBothClientDone <= crate::codec::FrontendMessage::CopyDone,
            external Fail(fail: bytes::Bytes) => SimpleCopyBothFailed <= crate::codec::FrontendMessage::CopyFail(_),
            internal Error(error: crate::codec::DiagnosticResponse) => SimpleCopyReady <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SimpleCopyBothClientDone internal {
            associate {
                inbound: none;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothClientDone>;
            }
            SendData(send_data: bytes::Bytes) => SimpleCopyBothClientDone <= crate::codec::BackendMessage::CopyData(_),
            SendDone(send_done) => SimpleCopyBothDone <= crate::codec::BackendMessage::CopyDone,
            Error(error: crate::codec::DiagnosticResponse) => SimpleCopyReady <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SimpleCopyBothServerDone external {
            associate {
                inbound: crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothServerDone>;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothServerDone>;
            }
            ReceiveData(receive_data: bytes::Bytes) => SimpleCopyBothServerDone <= crate::codec::FrontendMessage::CopyData(_),
            ReceiveDone(receive_done) => SimpleCopyBothDone <= crate::codec::FrontendMessage::CopyDone,
            Fail(fail: bytes::Bytes) => SimpleCopyBothFailed <= crate::codec::FrontendMessage::CopyFail(_),
        }
        SimpleCopyBothDone internal {
            associate {
                inbound: none;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopySimple, crate::server_session::BothDone>;
            }
            CommandComplete(command_complete: bytes::Bytes) => SimpleCopyReady <= crate::codec::BackendMessage::CommandComplete(_),
        }
        SimpleCopyBothFailed internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyBothFailed<crate::server_session::CopySimple>; }
            Error(error: crate::codec::DiagnosticResponse) => SimpleCopyReady <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ExtendedCopyBoth mixed {
            associate {
                inbound: crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothOpen>;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothOpen>;
            }
            internal SendData(send_data: bytes::Bytes) => ExtendedCopyBoth <= crate::codec::BackendMessage::CopyData(_),
            external ReceiveData(receive_data: bytes::Bytes) => ExtendedCopyBoth <= crate::codec::FrontendMessage::CopyData(_),
            internal SendDone(send_done) => ExtendedCopyBothServerDone <= crate::codec::BackendMessage::CopyDone,
            external ReceiveDone(receive_done) => ExtendedCopyBothClientDone <= crate::codec::FrontendMessage::CopyDone,
            external Fail(fail: bytes::Bytes) => ExtendedCopyBothFailed <= crate::codec::FrontendMessage::CopyFail(_),
            internal Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ExtendedCopyBothClientDone internal {
            associate {
                inbound: none;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothClientDone>;
            }
            SendData(send_data: bytes::Bytes) => ExtendedCopyBothClientDone <= crate::codec::BackendMessage::CopyData(_),
            SendDone(send_done) => ExtendedCopyBothDone <= crate::codec::BackendMessage::CopyDone,
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        ExtendedCopyBothServerDone external {
            associate {
                inbound: crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothServerDone>;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothServerDone>;
            }
            ReceiveData(receive_data: bytes::Bytes) => ExtendedCopyBothServerDone <= crate::codec::FrontendMessage::CopyData(_),
            ReceiveDone(receive_done) => ExtendedCopyBothDone <= crate::codec::FrontendMessage::CopyDone,
            Fail(fail: bytes::Bytes) => ExtendedCopyBothFailed <= crate::codec::FrontendMessage::CopyFail(_),
        }
        ExtendedCopyBothDone internal {
            associate {
                inbound: none;
                outbound: crate::server_session::ServerCopyBoth<crate::server_session::CopyExtended, crate::server_session::BothDone>;
            }
            CommandComplete(command_complete: bytes::Bytes) => Building <= crate::codec::BackendMessage::CommandComplete(_),
        }
        ExtendedCopyBothFailed internal {
            associate { inbound: none; outbound: crate::server_session::ServerCopyBothFailed<crate::server_session::CopyExtended>; }
            Error(error: crate::codec::DiagnosticResponse) => ExtendedError <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        Terminated external {
            associate { inbound: none; outbound: none; }
        }
    }
}

protocol! {
    pub mod server_authentication {
        initial Startup;
        messages {
            internal: crate::codec::BackendMessage,
            external: crate::codec::FrontendMessage,
        }
        associations {
            interface: crate::middleware::PhaseAssociation;
            seal: crate::middleware::phase_association_seal::Sealed;
            inbound {
                direction: crate::middleware::Inbound;
                role: crate::middleware::ClientRole;
                wire: crate::codec::FrontendMessage;
                message: external;
            }
            outbound {
                direction: crate::middleware::Outbound;
                role: crate::middleware::ServerRole;
                wire: crate::codec::BackendMessage;
                message: crate::middleware::TypedBackendMessage<internal>;
            }
        }
        Startup internal {
            associate { inbound: none; outbound: crate::server_auth::ServerStartupRejected; }
            Begin(begin) => Auth,
            Reject(reject: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        Auth internal {
            associate { inbound: crate::server_auth::ServerAuth; outbound: crate::server_auth::ServerAuth; }
            Negotiate(negotiate: crate::codec::NegotiateProtocolVersion) => Auth <= crate::codec::BackendMessage::NegotiateProtocolVersion(_),
            Cleartext(cleartext) => PasswordResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::CleartextPassword),
            Md5(md5: [u8; 4]) => PasswordResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Md5Password { .. }),
            Sasl(sasl: Vec<bytes::Bytes>) => SaslInitial <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Sasl { .. }),
            Gss(gss) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Gss),
            Sspi(sspi) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Sspi),
            KerberosV5(kerberos_v5) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::KerberosV5),
            Ok(ok) => StartupReady <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::Ok),
            Error(error: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        PasswordResponse external {
            associate { inbound: crate::server_auth::ServerPassword; outbound: crate::server_auth::ServerPassword; }
            Response(response: bytes::Bytes) => Auth <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        SaslInitial external {
            associate { inbound: crate::server_auth::ServerSaslInitial; outbound: crate::server_auth::ServerSaslInitial; }
            Initial(initial: crate::server_auth::SaslInitialResponse) => Sasl <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        Sasl internal {
            associate { inbound: none; outbound: crate::server_auth::ServerSasl; }
            Continue(continue_response: bytes::Bytes) => SaslResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::SaslContinue(_)),
            Final(final_response: bytes::Bytes) => Auth <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::SaslFinal(_)),
            Error(error: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        SaslResponse external {
            associate { inbound: crate::server_auth::ServerSaslResponse; outbound: crate::server_auth::ServerSaslResponse; }
            Response(response: bytes::Bytes) => Sasl <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        TokenResponse external {
            associate { inbound: crate::server_auth::ServerAuthResponse; outbound: crate::server_auth::ServerAuthResponse; }
            Response(response: bytes::Bytes) => TokenPolicy <= crate::codec::FrontendMessage::PasswordResponse(_),
        }
        TokenPolicy internal {
            associate { inbound: none; outbound: crate::server_auth::ServerAuthPolicy; }
            Continue(continue_token: bytes::Bytes) => TokenResponse <= crate::codec::BackendMessage::Authentication(crate::codec::Authentication::GssContinue(_)),
            Verified(verified) => Auth,
            Error(error: crate::codec::DiagnosticResponse) => Terminated <= crate::codec::BackendMessage::ErrorResponse(_),
        }
        StartupReady internal {
            associate { inbound: crate::server_auth::ServerStartupReady; outbound: crate::server_auth::ServerStartupReady; }
            ParameterStatus(parameter_status: (bytes::Bytes, bytes::Bytes)) => StartupReady <= crate::codec::BackendMessage::ParameterStatus { .. },
            BackendKeyData(backend_key_data: (u32, bytes::Bytes)) => StartupReady <= crate::codec::BackendMessage::BackendKeyData { .. },
            Ready(ready: crate::codec::TransactionStatus) => Ready <= crate::codec::BackendMessage::ReadyForQuery(_),
        }
        Ready external {
            associate { inbound: none; outbound: none; }
        }
        Terminated external {
            associate { inbound: none; outbound: none; }
        }
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
        codec::{
            Authentication, BackendMessage, Bind, Execute, FrontendMessage, Parse,
            TransactionStatus,
        },
        demux::SessionItem,
        session::{AwaitingReadyTransition, ReadyState},
        startup::{ProtocolVersion, StartupMessage},
    };
    use frontend::{Event, RuntimeFsm, RuntimeState, Session};

    #[test]
    fn railroad_labels_use_variant_syntax_and_link_payload_types() {
        let svg = frontend::FRONTEND_RAILROAD_SVG;
        assert!(svg.contains("◁ ReceiveCopyData(</tspan>"));
        assert!(svg.contains("bytes::Bytes</tspan>"));
        assert!(svg.contains(")</tspan>"));
        assert!(svg.contains("xlink:href=\"https://docs.rs/bytes/1/bytes/struct.Bytes.html\""));
        assert!(svg.contains("class=\"link\""));
        assert!(svg.contains("▷ Query(</tspan>"));
        assert!(svg.contains(") [Dirty]</tspan>"));
        assert!(!svg.contains("class=\"link\"> <g class=\"terminal\""));
        assert!(!svg.contains("&amp; ReceiveCopyData"));
    }

    macro_rules! exhaust_generated_runtime {
        ($module:ident, $depth:expr) => {{
            fn visit(runtime: $module::RuntimeFsm, depth: usize) {
                for &event in $module::ALL_EVENTS {
                    let state = runtime.state();
                    let mut next = runtime;
                    match next.step(event) {
                        Ok(()) if depth > 0 => visit(next, depth - 1),
                        Ok(()) => {}
                        Err(error) => {
                            assert_eq!(error.state, state);
                            assert_eq!(error.event, event);
                            assert_eq!(next.state(), state);
                        }
                    }
                }
            }
            visit($module::RuntimeFsm::new(), $depth);
        }};
    }

    #[test]
    fn every_generated_protocol_exhausts_reachable_valid_and_invalid_events() {
        exhaust_generated_runtime!(frontend, 5);
        exhaust_generated_runtime!(backend, 5);
        exhaust_generated_runtime!(pre_startup, 5);
        exhaust_generated_runtime!(server_pre_startup, 5);
        exhaust_generated_runtime!(authentication, 6);
        exhaust_generated_runtime!(server_authentication, 6);
    }

    #[test]
    fn generated_backend_projection_is_state_aware() {
        let parse = FrontendMessage::Parse(Parse {
            statement: Bytes::from_static(b"statement"),
            query: Bytes::from_static(b"select 1"),
            parameter_types: Vec::new(),
        });
        assert_eq!(
            backend::project_external(backend::RuntimeState::Ready, &parse),
            Some(backend::Event::Parse)
        );
        assert_eq!(
            backend::project_external(backend::RuntimeState::SimpleCopyIn, &parse),
            None
        );
        assert_eq!(
            backend::project_external(backend::RuntimeState::ExtendedError, &FrontendMessage::Sync,),
            Some(backend::Event::Sync)
        );
        assert_eq!(
            backend::project_external(
                backend::RuntimeState::ExtendedError,
                &FrontendMessage::Flush,
            ),
            Some(backend::Event::Discard)
        );
        assert_eq!(
            backend::project_internal(
                backend::RuntimeState::Simple,
                &BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ),
            Some(backend::Event::Ready)
        );
        assert_eq!(
            backend::project_internal(
                backend::RuntimeState::ExtendedCopyOut,
                &BackendMessage::CopyDone,
            ),
            Some(backend::Event::Done)
        );
    }

    #[test]
    fn generated_frontend_projection_covers_wire_messages_only() {
        assert_eq!(
            frontend::project_internal(frontend::RuntimeState::Building, &FrontendMessage::Sync,),
            Some(frontend::Event::Sync)
        );
        assert_eq!(
            frontend::project_external(
                frontend::RuntimeState::Simple,
                &BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ),
            Some(frontend::Event::Ready)
        );
        assert_eq!(
            frontend::project_external(
                frontend::RuntimeState::ResetComplete,
                &BackendMessage::ReadyForQuery(TransactionStatus::FailedTransaction),
            ),
            Some(frontend::Event::ReadyDirty)
        );
        assert_eq!(
            frontend::project_external(
                frontend::RuntimeState::CopyIn,
                &BackendMessage::CopyData(Bytes::from_static(b"illegal direction")),
            ),
            None
        );
    }

    #[test]
    fn codec_messages_drive_generated_extended_and_copy_sequences() {
        let parse = FrontendMessage::Parse(Parse {
            statement: Bytes::new(),
            query: Bytes::from_static(b"select $1"),
            parameter_types: vec![23],
        });
        let mut extended = backend::RuntimeFsm::new();
        extended
            .step_projected(&parse, backend::project_external)
            .unwrap();
        extended
            .step_projected(&BackendMessage::ParseComplete, backend::project_internal)
            .unwrap();
        extended
            .step_projected(&FrontendMessage::Sync, backend::project_external)
            .unwrap();
        extended
            .step_projected(
                &BackendMessage::ReadyForQuery(TransactionStatus::Idle),
                backend::project_internal,
            )
            .unwrap();
        assert_eq!(extended.state(), backend::RuntimeState::Ready);

        let mut copy = backend::RuntimeFsm::new();
        copy.step_projected(
            &FrontendMessage::Query(Bytes::from_static(b"copy t from stdin")),
            backend::project_external,
        )
        .unwrap();
        copy.step_projected(
            &BackendMessage::CopyInResponse(crate::codec::CopyResponse {
                overall_format: 0,
                column_formats: vec![0],
            }),
            backend::project_internal,
        )
        .unwrap();
        assert_eq!(copy.state(), backend::RuntimeState::SimpleCopyIn);
        assert!(
            copy.step_projected(
                &FrontendMessage::Query(Bytes::from_static(b"select 1")),
                backend::project_external,
            )
            .is_err()
        );
        assert_eq!(copy.state(), backend::RuntimeState::SimpleCopyIn);
    }

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
        #[derive(Debug)]
        struct InitiallyClean;

        let ready: frontend::TypedSession<(), frontend::Ready, InitiallyClean> =
            frontend::TypedSession::with_transport(());
        let (dirty, query): (
            frontend::TypedSession<(), frontend::Simple, frontend::Dirty>,
            Bytes,
        ) = ready
            .query(Bytes::from_static(b"select 1"), |(), query| {
                Ok::<_, std::convert::Infallible>(query)
            })
            .expect("query handler is infallible");
        assert_eq!(query, Bytes::from_static(b"select 1"));
        let (dirty, _status): (
            frontend::TypedSession<(), frontend::Ready, frontend::Dirty>,
            TransactionStatus,
        ) = dirty
            .ready(TransactionStatus::Idle, |(), status| {
                Ok::<_, std::convert::Infallible>(status)
            })
            .expect("readiness handler is infallible");
        assert_eq!(dirty.into_transport(), ());

        let dirty: frontend::TypedSession<(), frontend::Ready, frontend::Dirty> =
            frontend::TypedSession::with_transport(());
        let (reset_complete, _tag) = dirty
            .reset()
            .discard_complete(Bytes::from_static(b"DISCARD ALL"), |(), tag| {
                Ok::<_, std::convert::Infallible>(tag)
            })
            .expect("command handler is infallible");
        let (clean, _status): (
            frontend::TypedSession<(), frontend::Ready, frontend::Pristine>,
            TransactionStatus,
        ) = reset_complete
            .ready_clean(TransactionStatus::Idle, |(), status| {
                Ok::<_, std::convert::Infallible>(status)
            })
            .expect("readiness handler is infallible");
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
        let startup = crate::startup::StartupMessage {
            version: crate::startup::ProtocolVersion::V3_0,
            parameters: BTreeMap::new(),
        };
        let auth = pre_startup
            .ssl_request()
            .accept()
            .map_transport(Tls)
            .complete()
            .startup(startup, |_, startup| {
                Ok::<_, std::convert::Infallible>(startup)
            });
        let (auth, _startup): (
            pre_startup::TypedSession<Tls, pre_startup::Auth, Clean>,
            crate::startup::StartupMessage,
        ) = match auth {
            Ok(success) => success,
            Err((_session, never)) => match never {},
        };
        let Tls(_tcp) = auth.into_transport();

        assert_eq!(
            pre_startup::project_internal(
                pre_startup::RuntimeState::PreStartup,
                &crate::pre_startup::PreStartupMessage::SslRequest,
            ),
            Some(pre_startup::Event::SslRequest)
        );
        assert_eq!(
            pre_startup::project_external(
                pre_startup::RuntimeState::AwaitingSslReply,
                &crate::pre_startup::EncryptionReply::Accepted,
            ),
            Some(pre_startup::Event::Accept)
        );
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
        assert_eq!(
            authentication::project_external(
                authentication::RuntimeState::Sasl,
                &BackendMessage::Authentication(Authentication::SaslContinue(Bytes::from_static(
                    b"challenge"
                ),)),
            ),
            Some(authentication::Event::Continue)
        );
        assert_eq!(
            authentication::project_internal(
                authentication::RuntimeState::SaslChallenge,
                &FrontendMessage::PasswordResponse(Bytes::from_static(b"response")),
            ),
            Some(authentication::Event::Response)
        );
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
            .negotiate()
            .sasl()
            .initial()
            .continue_response()
            .response()
            .final_response()
            .ok()
            .parameter_status()
            .backend_key_data()
            .ready();

        let mut runtime = server_authentication::RuntimeFsm::new();
        for event in [
            server_authentication::Event::Begin,
            server_authentication::Event::Negotiate,
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
