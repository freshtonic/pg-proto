use pg_proto_fsm::protocol;

enum Wire {}
enum Direction {}
enum Role {}
trait Association<D, R, W> { type ProtocolPhase; type Message; }
mod private { pub trait Seal<D, R, W> {} }

protocol! {
    mod invalid {
        initial Open;
        messages { internal: crate::Wire, external: crate::Wire }
        associations {
            interface: crate::Association;
            seal: crate::private::Seal;
            inbound { direction: crate::Direction; role: crate::Role; wire: crate::Wire; message: external; }
            outbound { direction: crate::Direction; role: crate::Role; wire: crate::Wire; message: internal; }
        }
        Open internal {
            associate { inbound: none; inbound: none; outbound: none; }
        }
    }
}

fn main() {}
