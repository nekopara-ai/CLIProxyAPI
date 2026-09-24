# Gateway-scoped Codex minting

## Scope and trust boundary

The default acquisition engine for an enabled adaptive turn-ticket subsystem is now
`gateway-mint`. It checks the **declared model**, an opaque ticket, and a selected
routing gateway. It does not measure model intelligence, identify model weights,
decrypt tickets, create entitlements, or prove that any gateway is better than another.
The gateway name and lifetime defaults are empirical heuristics from the supplied
reference, not a public upstream service guarantee. Cross-request replay remains
experimental; a locally unexpired lease does not establish upstream acceptance.

The master `enabled` switch remains off by default. Existing API-key credentials and
non-Codex providers are out of scope. No user request is replayed as a probe. There is
no new relay endpoint, Cloudflare IP dialer, request translator, forwarding loop, or
replacement WebSocket server. The original CPA executors, proxy selection, identity,
body transformations, streaming, backpressure and connection management remain in use.
Executor changes are limited to ticket/cookie injection, transport tagging, and an
injection-readiness check before upstream I/O when `fail-closed` is enabled.

## State machine

For each eligible OAuth credential, workspace, upstream origin, business egress,
configured acquisition pool, identity/policy and transport, keep a separate scope.
The access token is part of the scope digest, not a retained manager key or a log.
A scope holds one validated routing pair and separate tickets for each configured
upstream model. SSE and WebSocket material never cross scopes.

1. Reuse fresh tickets and a fresh pair without another upstream request.
2. A missing/expiring ticket with a live target pair is minted with **only the pair**.
   No previously minted `X-Codex-Turn-State` is sent in a mint request.
3. A missing/expiring pair is acquired without routing cookies. An off-target,
   partially rotated, deleted, expired or malformed pair is not reused. The fresh
   target pair can be retained independently when a model declaration mismatches.
4. Accept a ticket only on a successful transport response, a complete
   `response.created` JSON event with a nonempty response ID and model, exact model
   equality, an accepted ticket length (when enabled), and a live target pair.
   Model-name equality alone never activates a direct/bypass state.
5. Keep ticket and pair lifetimes independent. Pair-only renewal does not overwrite
   a still-fresh ticket; ticket renewal does not unnecessarily replace a live pair.
6. Inject both artifacts immediately before the existing executor sends a business
   request. Preserve unrelated headers and cookies. A failed readiness check never
   replays the user's request through the mint worker.

Normal header-only business responses cannot publish a ticket or establish a direct
classification. Rejection of an injected bundle invalidates only the currently
matching submitted material; a late response cannot discard a newer ticket/pair.
Opaque state replay is not a substitute for normal upstream authorization.

## Probe protocols

The synthetic body contains one `ping` message, empty instructions, `store:false`,
`reasoning.effort:low`, `tool_choice:auto` and `parallel_tool_calls:false`. These
settings apply only to acquisition, never to the user's business payload.

SSE uses the existing CPA probe client/identity/proxy helpers. It accepts the expected
SSE and octet-stream content types, parses complete blank-line-terminated events,
supports CR/LF/CRLF and multiline data, and stops at a valid created or error event.
The total inspected event budget is 16 KiB. It closes the synthetic response body
without waiting for completion or draining generated text. Redirects are not followed.

WebSocket probes use the existing proxy utilities and Gorilla WebSocket, not custom
frame/relay code. The worker sends `response.create` and obtains state either from
handshake headers or typed `codex.response.metadata`. Metadata and the created event
may arrive in either order; both ticket and declaration are required. Message and
aggregate scan bounds and cancellation close the dedicated probe connection. A
WebSocket-capable credential is probed over WebSocket only when that transport is
configured; ordinary credentials are not sent unsolicited WebSocket probes.

## Bounded work and cache behavior

A default acquisition flight has at most 24 upstream attempts and 75 seconds total,
shared across the models and pair repair for one credential/transport. Models are
visited round-robin so a bad model cannot spend the entire budget first. There is
one in-flight acquisition per scope, up to four credential workers by default, and
a bounded cache of 256 scopes. Waiters can cancel independently. Stopping the
harvester cancels active synthetic I/O; no new business-response timeout is added.

HTTP 401/403/429 ends acquisition for the credential and applies backoff, including
before attempting the other transport. `Retry-After` can lengthen that backoff.
HTTP 400/404/422 and typed invalid-model/request errors stop that model while allowing
other configured models to proceed. Other unsuccessful flights observe the retry
cooldown; they do not silently accept an off-target gateway after exhausting the
budget. Partial successes remain available for their own models.

Pair expiry is bounded by local policy, cookie attributes and an unverified JWT `exp`
when available. Ticket expiry uses its readable issue timestamp when plausible,
otherwise acquisition time, plus the configured local ticket lease. Cache reads do
not extend either lease. Credential, workspace, egress, identity, model-policy and
transport changes isolate old material. Old disk-persisted tickets are **not**
promoted into the new engine, which is memory-only and reacquires after restart.

The configured business egress is tried first; configured acquisition fallbacks are
used by synthetic probes only. A retained pair records its acquisition egress so a
subsequent cookie-only probe uses that egress. Cross-egress use of resulting material
on the existing business path is experimental. No business proxy setting is rewritten.

## Configuration

Merge these keys into the existing `codex.turn-ticket` section; do not replace unrelated
configuration. Preserve the actual upstream model names and credential scope you use.

```yaml
codex:
  turn-ticket:
    enabled: true                 # Operator opt-in; unchanged default is false.
    adaptive-injection: true
    gateway-mint: true             # New default; false selects the rollback engine.
    injection-enabled: true       # Can be false for probe-only observation.
    fail-closed: true
    mint-gateway: unified-88       # "any" or "*" disables only the gateway check.
    # mint-ticket-length: 780      # Omitted: use existing per-plan length settings.
    # mint-ticket-length: 0        # Explicit zero disables only the length check.
    mint-ticket-ttl-seconds: 240
    mint-pair-ttl-seconds: 3900
    mint-max-attempts: 24
    mint-total-timeout-seconds: 75
    mint-retry-cooldown-seconds: 30
    mint-cache-capacity: 256
    mint-workers: 4
    mint-transports: [sse, websocket]
    probe-timeout-seconds: 25
    reject-backoff-seconds: 600
    routing-refresh-before-seconds: 30
    routing-expiry-margin-seconds: 5
    # Keep your existing models, auth-ids and harvest-proxy-urls here.
```

Changing a local TTL does not lengthen an upstream-validity window. Disabling gateway
or length checks does not improve model quality. Successful probes consume actual
upstream requests; early close must not be described as zero-cost probing.

In gateway mode, strict complete `response.created` parsing, exact model equality and
the two-cookie pair are mandatory. Legacy `require-complete-response` (completed-event
semantics), `require-model-match`, `unknown-state-action`, `validation-ticket-policy`,
`harvest-on-business-error`, custom routing-cookie names, legacy TTL/cooldown and
length-only direct-classification rules apply only to the rollback engine. New `mint-*`
settings replace those acquisition timing/validation rules. Existing per-plan ticket
lengths apply unless `mint-ticket-length` explicitly overrides them.

## Diagnostics and rollback

Management snapshots include `mint_states.sse` and (when configured and supported)
`mint_states.websocket`: readiness, selected gateway, ticket and pair expirations,
attempt count, in-flight state, status, controlled failure reason and next attempt.
The legacy `healthy` label means the configured metadata checks passed, not a model
capability measurement. Snapshots/logs omit bearer tokens, raw tickets, cookie values
and proxy credentials. A scope can be ready for one transport and unavailable for
another; the physical outbound injection guard remains authoritative.

`gateway-mint:false` explicitly selects the previous adaptive engine as a rollback
path. The existing non-adaptive legacy mode remains selected by
`adaptive-injection:false`. Regression fixtures for these old modes now opt into them
explicitly; they are not silently used to certify the gateway engine.

The new core has deterministic-clock tests for independent leases, late-response
fencing, scope isolation, bounded budgets, model/gateway rejection, partial success,
backoff, strict event parsing and injection preservation. Integration tests use only
local HTTP/WebSocket servers with fake credentials; no live account is exercised.
