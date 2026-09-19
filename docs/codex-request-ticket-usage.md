# Codex request ticket usage observations

Usage queue events may include an optional `codex_turn_state` object:

```json
{"codex_turn_state":{"request_length":292,"request_source":"cache"}}
```

This records the final outbound `X-Codex-Turn-State` header for that attempt,
independently of `response_headers`. No ticket contents are added to this object.

- `cache`: the matching credential/model cache actually supplied the header.
- `passthrough`: the outgoing header was present but not cache-injected.
- `none`: observed headers contained no ticket; `request_length` is explicitly 0.
- Missing object: no usable observation, not proof that no ticket was sent.

Lengths are byte counts after trimming surrounding whitespace, capped at 65536.
Positive lengths are required for `cache` and `passthrough`. Observing a header
does not prove upstream acceptance or that a ticket is still valid.

## HTTP and WebSocket scope

HTTP streaming, non-streaming and compact executions snapshot the final headers
after injection and header overrides. Failures retain the attempt's observation.

WebSocket observations add `"request_scope":"websocket_handshake"`. They describe
the physical connection's handshake, not a new header on every message. Reused
connections retain their original observation even if the ticket cache changes.
A replacement connection gets its own handshake observation. An unobserved
connection or a dial failure without a handshake response remains unknown.

## Consumer compatibility

The queue addition is optional and additive. Older records remain unknown and
must not be backfilled from a credential's current cache or a response header.
Consumers should show request source/length separately from response length.
No database migration or additional encryption layer is required.

The built-in queue sink exports this observation through both HTTP and RESP queue
access. The SDK usage record also exposes it to in-process consumers; the separate
third-party plugin wire API and CLIProxyAPIHome integration are unchanged.

Tests cover actual HTTP and WebSocket outbound headers, cache injection,
passthrough, explicit absence, failure paths, socket reuse and queue serialization.
