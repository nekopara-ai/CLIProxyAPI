# Configurable Codex turn-ticket routing

Turn-state lengths are empirical routing rules, not official upstream quality metrics.
All settings below live under `codex.turn-ticket`; see
[codex-turn-ticket-tuning.example.yaml](codex-turn-ticket-tuning.example.yaml) for a
mergeable configuration. Preserve the installation's existing master switch and proxies.

## Classification and admission

The four independent defaults are:

| Setting | Default |
| --- | --- |
| `personal-healthy-length` | 780 |
| `personal-degraded-length` | 312 |
| `team-healthy-length` | 780 |
| `team-degraded-length` | 312 |

An explicit per-auth `codex_turn_ticket_plan: pro|team` wins; otherwise matching-workspace
JWT claims select the plan. Unrecognized plans use `target-length` (default 780) for
healthy states and `personal-degraded-length` for degradation. Lengths also require the
Fernet-shaped prefix. Both healthy and degraded lengths must differ within each plan.
`target-length` does not override recognized plans. Older installations can explicitly
configure 292/312 and 332/356 to preserve their previous policy.

State is isolated by credential and model; no auth file is permanently disabled:

- A clean background business probe with a healthy result marks `direct`, clears the
  old bundle, and does not harvest or inject.
- An explicit degraded response marks `inject` and starts acquisition/recovery.
- `block-on-degraded: true` pauses subsequent business selection until a valid bundle
  can actually be injected or a clean business probe restores `direct`. This overrides
  `fail-closed: false` for degraded buckets. Background recovery continues.
- `block-on-degraded: false` allows degraded buckets to keep serving while recovery
  runs, even with `fail-closed: true`. Missing/expired bundles are never injected.
- Omitted/null `block-on-degraded` inherits `fail-closed` for compatibility.
- `fail-closed` governs unclassified buckets. `direct` always passes this ticket guard.
- `unknown-state-action: retain` (default) leaves the previous mode and bundle alone.
  `harvest` enters injection/recovery mode; `block` clears the old bundle and pauses
  admission independently of `fail-closed`. Further probes continue in either case.
- `harvest-on-business-error: true` also starts acquisition after network errors or
  non-200 business results, excluding configured rejection/backoff statuses. Default false.
  An unusable HTTP 200 is handled by `unknown-state-action`.

Business probes are additional real requests through the credential/global business
proxy, with no cached ticket or routing cookie. They are not user requests. Live user
responses are observed at headers: explicit degradation wakes recovery, but the current
response is not automatically aborted, rejected or replayed. Unknown live state uses
`unknown-state-action`. A clean healthy live response can establish direct mode unless
already in injection mode; only a clean generation-checked probe exits injection mode.
Ordinary auth disablement, quotas and cooldowns remain independent of these switches.

## Acquisition and validation

Acquisition uses only `harvest-proxy-urls`, for up to `harvest-attempts` (default 3).
A candidate must have the configured healthy length and a valid routing cookie. It is
then replayed through the business proxy before publication. HTTP 200 is mandatory.

| Setting | Default | Meaning |
| --- | --- | --- |
| `require-complete-response` | true | Require a completed successful Responses SSE result in all adaptive probe phases. |
| `require-model-match` | true | Require the actual response model to equal the requested model. |
| `validation-ticket-policy` | same-or-empty | Accept no returned ticket or an exact echo. `healthy-or-empty` additionally accepts a different ticket with the configured healthy shape. |
| `routing-cookie-names` | [__cflb, __oailb] | Names eligible for acquisition, replacement and replay; [] accepts no cookies, so no bundle activates. |
| `reject-status-codes` | [401, 403, 429] | Whole auth+model probe backoff, for `reject-backoff-seconds` (600). Also used in legacy mode. |
| `harvest-reject-status-codes` | [403] | Acquisition-only exit backoff, for `harvest-reject-backoff-seconds` (15); takes priority over the preceding list only during acquisition. |

Even with `healthy-or-empty`, the published bundle is the submitted ticket and cookies
that passed validation, never the reissued response ticket. The example configuration
selects this option for upstreams that reissue 780-character tickets. Default behavior
remains strict unless configured. Configurable checks apply to synthetic probes; live
response observation remains header-based. Cookie domain/path/expiry and HTTP syntax
validation remain mandatory. Status lists accept explicit [] to disable that category.
A status not in either list follows ordinary failure handling and the normal interval.

## Timing and switches

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | false | Master switch for probing, observation, injection and ticket admission. |
| `injection-enabled` | true | Replay switch; probing continues when false. A blocked degraded bucket cannot be admitted on the strength of a bundle that will not be injected. |
| `adaptive-injection` | true | False selects legacy ticket-only replay. |
| `routing-cookie-ttl-seconds` | 240 | Local lease from acquisition headers, bounded by earlier ticket/cookie expiry. |
| `routing-refresh-before-seconds` | 30 | Renewal margin, capped at half the lease (minimum 1). |
| `routing-probe-interval-seconds` | 15 | Worker interval, capped at half the refresh margin (minimum 1). |
| `routing-expiry-margin-seconds` | 5 | Remaining lifetime required for adaptive admission/injection; explicit 0 allowed. |
| `legacy-expiry-margin-seconds` | 30 | Corresponding legacy margin; explicit 0 allowed. |
| `probe-timeout-seconds` | 25 | Timeout of one synthetic request. |
| `probe-cooldown-seconds` | 3300 | Healthy direct-probe cooldown; the tuning example uses 300. |
| `ttl-seconds` | 3600 | Maximum ticket age from its encoded issue timestamp. |
| `refresh-before-seconds` | 600 | Legacy renewal margin. |
| `probe-interval-seconds` | 60 | Legacy worker interval. |

`models` and `auth-ids` restrict scope. An empty acquisition pool still permits business
classification. Timing settings other than the two expiry margins retain the existing
positive-value/default semantics. Probe execution is serialized; an interval does not
guarantee each account is probed that frequently. Failed renewal retains a valid old
bundle but never extends it. Expiry does not stop recovery probes. Normal injected
success never renews the lease. No local lease guarantees upstream acceptance duration.

The four lengths, `target-length`, legacy expiry margin and rejection status list also
apply to legacy mode. Admission/recovery actions, cookies and validation options are
adaptive-only. Legacy mode retains its existing business-first/degraded-only fallback.

## Reload, persistence and diagnostics

Settings hot-reload through the file watcher and management configuration update paths.
Changing resolved lengths, plan identity, cookie allowlist or validation requirements
invalidates old adaptive classification and bundles, including in-flight results. A
block switch change takes effect immediately without deleting degradation evidence.
Changing timing never extends a saved cookie's expiration or bypasses rejection backoff.

Persistent tickets are restored without a hardcoded length allowlist; current per-account
policy is checked before every use. Adaptive modes are not restored from disk, so an old
bundle cannot enable injection after restart without fresh classification and validation.

The management ticket endpoint exposes normalized `policy`; credential and bucket
snapshots include `target_length` and `degraded_length`. No ticket, cookie values or
credential secrets are exposed. Invalid actions, conflicting lengths, negative margins
and invalid status/cookie names reject config loading rather than silently changing policy.
Existing WebSocket handshakes are unchanged until the connection is replaced.
