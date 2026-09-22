# Codex adaptive turn-ticket routing

This document describes the adaptive routing-cookie mode of the Codex turn-ticket
subsystem: what it classifies, what it injects, and where its limits are. It is an
operator-facing description of behavior and configuration, not a specification of the
upstream turn-state semantics.

## Behavior

Adaptive mode adds a business-egress classification step to the existing turn-ticket
harvester. A gated request is classified with a synthetic probe sent through the
business egress before routing is decided:

- A natural healthy probe passes through: no injection is required, and a cached ticket
  does not have to exist.
- An explicitly degraded probe enables injection for the affected auth+model bundle. On
  this stack that is a personal `312` turn state or a Team/Business `356` turn state.
- Transport errors such as `401`, `403`, `429`, and timeouts do not toggle the mode. They
  leave the current classification and its backoff in place.

Injection state is isolated per auth+model. It is never shared per router, and cookie
names are restricted to the `__cflb`/`__oailb` allowlist. Cookies discovered through an
acquisition pool are candidates only; each one must be validated by a business-egress
replay before it becomes usable for routing.

The legacy behavior stays available. Setting `adaptive-injection: false` replays only a
cached healthy ticket and performs no business-egress classification.

## Freshness lease

A validated bundle is activated under a short local freshness lease. The lease is capped
at `routing-cookie-ttl-seconds` (core default and hard cap `180`), renewed
`routing-refresh-before-seconds` early (core default `30`), and invalidated on an explicit
degraded `312`/`356` response.
The `180` value bounds local reuse of a validated bundle. It is not the upstream token's
own TTL, and it should not be described or tuned as one.

Unknown routing state is never carried across a restart: the runtime resets unknown
bundles on startup and never blindly replays a previously persisted cookie. A candidate
is validated before activation.

## Fail-closed

`fail-closed` (default `true`) still governs routing in adaptive mode:

- An unknown or unclassified bundle waits for classification rather than being served.
- A natural healthy classification still passes with no cached ticket.
- A degraded classification requires a validated cookie+ticket bundle.

Setting `fail-closed: false` restores the old pass-through behavior and may allow a `312`
degraded turn state onto live traffic.

## Configuration

The fields live under the existing `codex.turn-ticket` section. See
`config.example.yaml` for the commented reference block.

| Field | Default | Cap | Purpose |
| --- | --- | --- | --- |
| `adaptive-injection` | `true` (resolved in core) | n/a | Enable adaptive mode; `false` selects legacy behavior. |
| `routing-cookie-ttl-seconds` | `180` | `180` | Maximum freshness lease for a validated bundle. |
| `routing-refresh-before-seconds` | `30` | n/a | Renew a validated bundle this early. |
| `routing-probe-interval-seconds` | `15` | n/a | Delay between business-egress classification probes. |
| `harvest-attempts` | `3` | `8` | Acquisition candidates tried before giving up on a bucket. |

`enabled` and `injection-enabled` remain the kill switches for the subsystem and for
replay, exactly as before. The normal business cooldown (`probe-cooldown-seconds`) still
applies and is unchanged by adaptive mode.

An empty `harvest-proxy-urls` disables only the fallback acquisition pool. Adaptive mode
still performs business-egress classification and can still pass natural healthy traffic
through without a fallback egress.

## Limitations

- Turn-state length is an empirical header-length rule, not an official quality metric,
  and it is not a model-quality guarantee.
- Classification reflects the moment of the probe. A later upstream change can make a
  previously healthy route degraded before the lease expires.
- Injection state is keyed by auth+model. A credential shared across models keeps a
  separate decision per model.
- Only validated cookies are usable. An acquisition candidate that has not been replayed
  successfully through the business egress is not eligible for routing.

## Migration

Adaptive mode is the default. To keep the previous behavior, set
`adaptive-injection: false` explicitly. Operators who never set the new fields keep the
defaults above because the core resolves them.

## Restart boundary

Configuration is hot-reloadable. The adaptive classification and lease state is not
persisted as authoritative routing state: on restart, unknown bundles are reset and
re-validated before activation, and existing WebSocket handshakes are unchanged until the
connection is replaced.
