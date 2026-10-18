# Codex OAuth hosted search history

Replaying a `web_search_call` without a matching tool declaration can cause the
ChatGPT Codex upstream to fail with `response protection is unavailable`, including
during native compaction. CPA now follows the compatibility behavior from
[Sub2API PR #7939](https://github.com/Wei-Shaw/sub2api/pull/7939).

For OAuth `/responses` requests containing search history, CPA adds
`{"type":"web_search","external_web_access":false}` when neither top-level tools
nor an `additional_tools` item already declares a `web_search*` tool. Historical
items, sources, citations, and encrypted content remain intact.

Standard requests receive the declaration in `tools`. Responses Lite requests
receive it in an existing `additional_tools` item or in a new developer item
before the trailing `compaction_trigger`. When the effective request has no
other tools, an absent, null, empty, `auto`, or `none` choice becomes
`tool_choice:"none"`. Existing tools and other choices retain their semantics.
CPA's configured automatic tool injection counts as an existing tool.

The rewrite applies after payload rules on HTTP, HTTP streaming, and WebSocket
response creation, including subsequent creates in a persistent session. API-key
credentials and the dedicated `/responses/compact` endpoint are excluded.

When upgrading from a configuration workaround, remove only the temporary rule
that deletes `web_search_call` items and its companion compaction tool override.
Deleted input cannot be recovered by the compatibility pass. Keep those rules
active until the new binary is ready for production cutover.

This addresses the search-history trigger. The same upstream error message can
have other causes.
