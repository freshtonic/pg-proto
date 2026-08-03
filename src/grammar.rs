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

#[cfg(test)]
mod tests {
    use super::frontend::{Event, RuntimeFsm, RuntimeState, Session};

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
}
