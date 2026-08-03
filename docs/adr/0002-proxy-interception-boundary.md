# ADR 0002: Separate wire receipt from session advancement

Status: accepted

## Context

The crate is a protocol substrate for a PostgreSQL proxy. A proxy must be able to
inspect, reject, replace, rewrite, delay, or forward any client or server message.
That logic may itself be asynchronous. Automatically decoding and advancing the
session in one operation would make such policy impossible or force it below the
typed API.

## Decision

Receiving bytes, applying proxy policy, and advancing the session are separate
operations:

1. `receive_backend_wire()` decodes one complete typed wire message.
2. Caller-owned code may perform arbitrary async work and modify or replace it.
3. The caller may reconstruct and forward the resulting message.
4. `project_backend()` applies the message to the demux and session projection.

`receive()` remains as a convenience composition for clients that do not require
interception. It is not the primitive on which proxy code is expected to depend.

The frontend/backend dual will expose the same boundary. Every message type must
ultimately be losslessly reconstructable; opaque recognised frames are temporary
implementation sequencing, not the final proxy API.
