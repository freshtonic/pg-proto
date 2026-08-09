# Compose reusable role components into intermediaries

Expose reusable, generic `Client`, `Server`, and `Intermediary` components built
through separate role-specific builders. A built intermediary contains complete
server-role and client-role components while preserving their independent TLS,
authentication, transport, and middleware policies; only routing, cancellation,
pipeline, and forwarding-boundary policy belong to the intermediary itself.
Connection establishment receives caller-owned connection state at runtime and
returns typed role connections, while listener loops, spawning, supervision,
shutdown, pooling, and dynamic policy erasure remain outside this first API.
The component builders and the public types required to configure or use their
results form the crate's sole public facade. Existing low-level protocol types,
traits, functions, and constants become crate-private; capabilities that cannot
be reached through the facade are not public API. The README, crate-level
documentation, and every example teach this builder-first interface exclusively.
