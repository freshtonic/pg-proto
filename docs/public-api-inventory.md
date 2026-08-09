# Public API cutover inventory

Issue #38 classifies the former public surface by responsibility:

| Former surface | Classification | Builder facade replacement |
| --- | --- | --- |
| `Conn`, phase and cleanliness witnesses, generated grammar sessions | implementation-only | operational `ClientConnection`, `ServerConnection`, and `IntermediaryConnection` |
| codec directions, codecs, frames, encoding helpers, transport wrappers | implementation-only | role establishment and forwarding methods |
| startup/authentication/session transition modules | implementation-only | role builders plus authentication policy traits |
| SCRAM, credential, TLS, network, demux, cancellation-map helpers | implementation-only | TLS/authentication providers and application-owned cancellation registry |
| resource branding and erased connections | implementation-only | connection-owned operational APIs |
| handwritten intermediary/session-pair APIs | implementation-only | `Intermediary::builder()` |
| runtime/generated middleware adapters | implementation-only | builder middleware factories and role middleware traits |
| `Client`, `Server`, and `Intermediary` configuration, policy, context, errors, and owned connection types | facade-required | exported at the crate root |
| frontend/backend/startup message values used by application middleware | facade-required vocabulary | exported at the crate root; wire framing remains internal |
| bounded-pipeline configuration and forwarding errors | facade-required nested configuration | supplied through `IntermediaryBuilder::pipeline` |

The exact reviewed root export manifest is [`public-api.txt`](public-api.txt).
`tests/public_surface.rs` rejects public modules, root declarations outside that
manifest, and restoration of the legacy connection type. Compiler lints deny
private bounds, private interfaces, and unreachable public items.
