# Credential policy and fingerprint monitoring

## Upgrade and removal

The custom Codex ticket/mint/harvest engine, caches, replay/injection, readiness
rules, management endpoint and CPAMP ticket UI have been removed. Legacy
`codex.turn-ticket` and `codex_turn_ticket_plan` fields have no effect. Remove
them from your YAML/auth files when convenient. Old ticket cache files are inert;
this upgrade does not delete credential or usage data. Ordinary native client
`X-Codex-Turn-State` passthrough and Home execution leases are unrelated and remain.

Monitoring is **off by default**, so upgrading alone sends no diagnostic traffic.
Build artifacts do not activate monitoring or restart a production deployment.

## Timezone

`credential-policies` maps auth filenames (preferred) or runtime IDs to overrides.
Timezone and optional country/region/city inherit global values when omitted.
A custom timezone clears inherited global geography; explicitly set geography if
required. An empty timezone string disables rewriting. Auth JSON metadata uses
`timezone_override` and `timezone_override_country/region/city`; these have
precedence over config YAML. Null/removing an auth field restores inheritance.
Payload rewriting uses a per-request configuration copy, never shared mutations.
Tool outputs, including source snippets containing environment tags, are untouched.

## Fingerprint policy

See the annotated `config.example.yaml`. `fingerprint.enabled: true` is the global
master switch. The remaining policy merges: built-in defaults → global → named
credential policy → credential JSON `fingerprint`. CPAMP's credential editor
supports timezone mode/value and a JSON editor for **all** fingerprint knobs;
blank JSON restores inheritance. Global settings remain editable in its YAML editor.
Both Full and Panel modes use CPA's management API for these fields and snapshots.

Each cycle runs the original three prompts (300, 310 and 304 numbers) separately
for each configured model. The current implementation diagnoses **Codex**
credentials; other providers are skipped before budget reservation or requests.
Probes use that credential and its own business proxy (or the normal global proxy),
without selecting another account, substituting egresses, injecting cookies, or
using tools. Codex HTTP/SSE is used for diagnostics even if business traffic uses
WebSocket. No request deadline is imposed after connection establishment.

The global worker limit bounds concurrent credential cycles; requests within a
cycle are serial. Each model has its own next-test time, measured from that model's
completed test, not wall-clock cron. Only due models are included in a cycle.
Startup defaults to 30 seconds (0 also selects this default), plus deterministic
jitter. Each credential's UTC daily budget is reserved durably **before** a request,
including retries. Question retries are only for unusable answers or errors, never
to discard a valid mismatch. Credential-scoped quota/auth failures stop all remaining
models; model-scoped rate limits defer only that model. Failed or
inconclusive cycles retry exponentially, bounded by retry/max-retry seconds.
No cancellation of already admitted business requests is attempted. Diagnostic
requests use terminal-aware SSE processing: completion/failure ends the request
without waiting for transport EOF. Policy changes, removal and manual disabling
cancel obsolete diagnostics even when every worker is occupied. No post-connect
network deadline is added; genuine ongoing generation can still occupy a worker.
Snapshots expose model/question/attempt, start times, completed questions and
stream activity without retaining raw text.

### Quota-aware admission and deferral

Diagnostics bypass only their own fingerprint exclusion. They reuse business
auth/model admission before scheduling, before every question/retry and immediately
before dispatch with a fresh credential snapshot. Known quota, forced cooldown,
expired access tokens and manual disablement cannot be bypassed by a stale auth.
Skipping local admission consumes no upstream request or daily request budget.
New HTTP or terminal-SSE quota/auth failures feed the normal scheduler; successful
diagnostics do not clear concurrent business failures. Already dispatched requests
can race with an independent business request exhausting the limit; no atomic
provider-side quota reservation or cancellation of in-flight traffic is claimed.

Deferrals are persisted separately in each model's `wait` (reason, scope, retry_at).
They preserve the last verdict, failure count and fingerprint exclusion. Provider
RetryAfter/reset hints determine the earliest retry; missing/expired hints fall
back to configured retry/max-retry seconds. Longer known cooldowns always win.
Policy edits and restarts cannot shorten a persisted wait. Model-scoped limits do
not pause healthy siblings; credential-scoped limits defer all monitored models.
Non-due models also record known cooldowns, and skipped accounts occupy no worker.
At recovery time admission is rechecked, not assumed successful. This does not
actively poll a provider's quota API or infer model identity from quota headers.

### Internal system caller

To separate diagnostics from business clients in usage accounting, create a
dedicated random client key in `api-keys` and label it `system` in CPAMP. Set the
top-level `internal-request-api-key-sha256` to the SHA-256 hex digest of that key.
Only the digest is added to this setting; never commit the actual key. Background
fingerprint requests retain the selected credential, account source and proxy,
but their caller usage is attributed to this configured key. The client key is
not sent upstream and grants no management privileges or model-block bypass to
external callers. Explicit external client identity always takes precedence.

An empty reference preserves legacy unattributed diagnostics. An invalid digest
or a reference to a removed key stops new diagnostic requests with a configuration
error instead of choosing another key or producing more unknown-key records.
Hot reload applies the reference to subsequent probes; a previously admitted
request retains its original attribution. Past unknown-key usage is not relabelled,
since not every unattributed historical request can be proven to be a probe.
Operational scripts should authenticate with the same system key, loaded from an
operator-controlled secret file, not a business client's key or command-line value.

## Decisions and recovery

- A usable answer contains at least max(80, ceil(expected count × 0.55)) parsed
  numbers. `minimum-answers` defaults to all three questions.
- A high-scoring prediction matching `expected-models[requested]` (or the requested
  name) passes. An unknown reference-bank model is an error, not a mismatch.
- A sufficiently confident mismatch immediately excludes only that
  **credential + resolved upstream model**. Healthy sibling models, models omitted
  from monitoring and other credentials are unaffected. Routing aliases are
  checked after upstream-model resolution.
- Zero valid outputs, errors and low confidence are separate states with no
  invented 0% probability. They do not newly disable a credential, and never
  restore a previously blocked one.
- After a model's cooldown, only its diagnostic traffic resumes. Its own fresh
  successful test restores it immediately, without waiting for other models. A
  new mismatch restarts only its cooldown. Errors and inconclusive results never
  clear its block. Manually disabled credentials are never probed or auto-enabled.
- Automatic exclusion is separate from the auth file's manual `disabled` bit.
  Management exposes `fingerprint_status.model_states`; a fingerprint mismatch
  does not set the whole auth's `unavailable` flag. Summary `blocked` means some
  monitored models are blocked. CPAMP shows per-model cooldowns, results, score,
  valid answers, next test, daily budget, reference bank version and history.
- Disabling monitoring globally or for a credential is an explicit operator bypass
  of the fingerprint gate; persisted blocks remain if monitoring is enabled again.

Each new result records its decision threshold and each history entry records its
policy. Policy changes mark old results stale, not relabelled with today's threshold.
Legacy results without a recorded policy are explicitly unknown until retested.
Legacy blanket blocks migrate only to recorded mismatching/trigger models;
accounting and history are preserved.

State is an atomic, mode-0600 file at `<auth-dir>/.fingerprint-state` by default,
not an auth `.json` file. Set `state-file` to override; changing that path requires
restart. Use only **one CPA writer per state file**. Multiple CPA replicas require
separate state files and independent monitoring budgets. Runtime IDs isolate members
of shared credential files. Corrupt/unreadable/unwritable state fails closed for
monitored models only and requires operator repair/restart; it is not silently
reset. Identity/policy/proxy changes and manual disabling invalidate in-flight
results. Cooldown duration changes are applied at the next scheduler tick.
Raw answers are omitted by default; opt in with `retain-answers`. Secure state
backups and management access as credential operational data.

## Statistical limitations and attribution

Scores are **reference-bank-relative statistical probabilities**, not proof of
upstream model identity and not calibrated certainty that an account is degraded.
False positives and reference drift are possible. Default confidence is 0.95;
review results before enabling automatic gating broadly. Nine baseline requests
per cycle (three models × three questions) consume quota; retries cost extra.

The classifier and embedded `internal/fingerprint/data/unified_bank.json` reproduce
[ModelTrace](https://github.com/xqy2006/ModelTrace)'s nuisance-projected Hellinger,
ordered-block/environment fusion and calibrated softmax procedure. Source is
MIT licensed; its notice is in `data/LICENSE.ModelTrace`. Bank SHA-256 is emitted
with each result. The pinned bank is the same one used in the September 2026
three-question experiments; sanitized golden fixtures compare Go results to the
reference JavaScript probabilities with tolerance 1e-10. `bank-file` permits a
reviewed replacement without recompiling; each cycle loads and validates it.
