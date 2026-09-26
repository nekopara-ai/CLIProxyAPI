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
credentials; other providers return a diagnostic error without upstream traffic.
Probes use that credential and its own business proxy (or the normal global proxy),
without selecting another account, substituting egresses, injecting cookies, or
using tools. Codex HTTP/SSE is used for diagnostics even if business traffic uses
WebSocket. No request deadline is imposed after connection establishment.

The global worker limit bounds concurrent credential cycles; requests within a
cycle are serial. Interval is measured from cycle completion, not wall-clock cron.
Startup defaults to 30 seconds (0 also selects this default), plus deterministic
jitter. Each credential's UTC daily budget is reserved durably **before** a request,
including retries. Question retries are only for unusable answers or errors, never
to discard a valid mismatch. HTTP 401/403/429 stops the current cycle. Failed or
inconclusive cycles retry exponentially, bounded by retry/max-retry seconds.
No cancellation of already admitted business requests is attempted.

## Decisions and recovery

- A usable answer contains at least max(80, ceil(expected count × 0.55)) parsed
  numbers. `minimum-answers` defaults to all three questions.
- A high-scoring prediction matching `expected-models[requested]` (or the requested
  name) passes. An unknown reference-bank model is an error, not a mismatch.
- A sufficiently confident mismatch immediately excludes the **whole credential**
  from new business selection across all models. Other configured models are still
  diagnosed for reporting unless a request error stops the cycle.
- Zero valid outputs, errors and low confidence are separate states with no
  invented 0% probability. They do not newly disable a credential, and never
  restore a previously blocked one.
- After cooldown, only diagnostic traffic may resume. **All configured models**
  must pass in a fresh cycle to restore eligibility. A new mismatch starts a new
  cooldown. Manually disabled credentials are never probed or auto-enabled.
- Automatic exclusion is separate from the auth file's manual `disabled` bit.
  Management exposes `fingerprint_status` and effective `unavailable`; CPAMP shows
  blocked state, triggering model, results, score, valid answers, next test,
  cooldown, daily budget, reference bank version and bounded history.
- Disabling monitoring globally or for a credential is an explicit operator bypass
  of the fingerprint gate; persisted blocks remain if monitoring is enabled again.

State is an atomic, mode-0600 file at `<auth-dir>/.fingerprint-state` by default,
not an auth `.json` file. Set `state-file` to override; changing that path requires
restart. Use only **one CPA writer per state file**. Multiple CPA replicas require
separate state files and independent monitoring budgets. Runtime IDs isolate members
of shared credential files. Corrupt/unreadable/unwritable state fails closed for
monitored credentials and requires operator repair/restart; it is not silently
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
