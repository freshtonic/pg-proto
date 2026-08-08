use pg_proto::{
    Conn,
    auth::Ready,
    session::Building,
};

fn transition<S, C>(ready: Conn<S, Ready, C>) -> Conn<S, Building, C> {
    ready.begin_extended()
}

fn illegal<S, C>(ready: Conn<S, Ready, C>) {
    let _building = transition(ready);
    let _again = transition(ready);
}

fn main() {}
