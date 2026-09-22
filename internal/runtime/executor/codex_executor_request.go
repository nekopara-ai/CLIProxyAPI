package executor

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	codexVersion               = constant.CodexClientVersion
	codexOriginator            = constant.CodexOriginator
	codexUserAgent             = constant.CodexUserAgent
	codexDefaultImageToolModel = "gpt-image-2"
	codexResponsesLiteHeader   = "X-OpenAI-Internal-Codex-Responses-Lite"
)

var dataTag = []byte("data:")

func translateCodexRequestPair(from, to sdktranslator.Format, model string, originalPayload, payload []byte, stream bool, preserveEmptyThinkingBlocks ...bool) ([]byte, []byte) {
	isCompat := len(preserveEmptyThinkingBlocks) > 0 && preserveEmptyThinkingBlocks[0]
	translate := func(raw []byte) []byte {
		if isCompat && from == sdktranslator.FormatClaude && to == sdktranslator.FormatCodex {
			return helps.TranslateRequestWithAPIKeyModelCompatibility(context.Background(), nil, nil, from, to, model, raw, stream, true)
		}
		return sdktranslator.TranslateRequest(from, to, model, raw, stream)
	}
	if bytes.Equal(originalPayload, payload) {
		body := translate(payload)
		return body, body
	}
	originalTranslated := translate(originalPayload)
	body := translate(payload)
	return originalTranslated, body
}

// PrepareRequest injects Codex credentials into the outgoing HTTP request.
func (e *CodexExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	apiKey, _ := codexCreds(auth)
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		req.Header.Del("Authorization")
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects Codex credentials into the request and executes it.
func (e *CodexExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("codex executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

type codexIdentityConfuseState struct {
	enabled                bool
	authID                 string
	originalPromptCacheKey string
	promptCacheKey         string
	identities             []codexIdentityReplacement
}

type codexIdentityReplacement struct {
	original string
	confused string
}

// Codex turn metadata carries one entry per client identifier. Native clients
// keep every entry consistent with the request headers and with the body's
// client_metadata block, so leaving any of them untranslated reintroduces the
// real machine identity and the self-contradiction the confusion layer exists
// to remove.
const (
	codexIdentityPrefixPromptCache = "prompt-cache"
	codexIdentityPrefixInstall     = "installation"
	codexIdentityPrefixTurn        = "turn"
	codexIdentityPrefixContextWin  = "context-window"
)

func (e *CodexExecutor) cacheHelper(ctx context.Context, from sdktranslator.Format, url string, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, userPayload []byte, rawJSON []byte, headerSets ...http.Header) (*http.Request, []byte, codexIdentityConfuseState, error) {
	var headers http.Header
	if len(headerSets) > 0 {
		headers = headerSets[0]
	}
	var cache helps.CodexCache
	if sourceFormatEqual(from, sdktranslator.FormatClaude) {
		modelName := strings.TrimSpace(gjson.GetBytes(rawJSON, "model").String())
		if modelName == "" {
			modelName = thinking.ParseSuffix(req.Model).ModelName
		}
		cached, ok, errCache := helps.ClaudeCodePromptCache(ctx, modelName, req.Payload, headers)
		if errCache != nil {
			return nil, nil, codexIdentityConfuseState{}, errCache
		}
		if ok {
			cache = cached
		}
	} else if sourceFormatEqual(from, sdktranslator.FormatOpenAIResponse) {
		promptCacheKey := gjson.GetBytes(req.Payload, "prompt_cache_key")
		if promptCacheKey.Exists() {
			cache.ID = promptCacheKey.String()
		}
	} else if sourceFormatEqual(from, sdktranslator.FormatOpenAI) {
		if promptCacheKey := gjson.GetBytes(req.Payload, "prompt_cache_key"); promptCacheKey.Exists() {
			cache.ID = strings.TrimSpace(promptCacheKey.String())
		}
		if cache.ID == "" {
			cache.ID = helps.ProviderSessionUUID("codex", req.Metadata)
		}
		if cache.ID == "" {
			if apiKey := strings.TrimSpace(helps.APIKeyFromContext(ctx)); apiKey != "" {
				cache.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:"+apiKey)).String()
			}
		}
	}
	if cache.ID == "" {
		cache.ID = helps.ProviderSessionUUID("codex", req.Metadata)
	}

	if cache.ID != "" {
		rawJSON = helps.SetStringIfDifferent(rawJSON, "prompt_cache_key", cache.ID)
	}
	rawJSON = helps.SanitizeCodexInputItemIDs(rawJSON)
	var identityState codexIdentityConfuseState
	rawJSON, identityState = applyCodexIdentityConfuseBody(e.cfg, auth, userPayload, rawJSON)
	if errValidate := helps.ValidateCodexEncryptedInput(rawJSON); errValidate != nil {
		return nil, nil, codexIdentityConfuseState{}, errValidate
	}
	if identityState.promptCacheKey != "" {
		cache.ID = identityState.promptCacheKey
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rawJSON))
	if err != nil {
		return nil, nil, codexIdentityConfuseState{}, err
	}
	if cache.ID != "" {
		httpReq.Header.Set("Session-Id", cache.ID)
	}
	return httpReq, rawJSON, identityState, nil
}

func applyCodexIdentityConfuseBody(cfg *config.Config, auth *cliproxyauth.Auth, userPayload []byte, rawJSON []byte) ([]byte, codexIdentityConfuseState) {
	if !codexIdentityConfuseEnabled(cfg) || auth == nil || strings.TrimSpace(auth.ID) == "" || len(rawJSON) == 0 {
		return rawJSON, codexIdentityConfuseState{}
	}

	state := codexIdentityConfuseState{enabled: true, authID: strings.TrimSpace(auth.ID)}
	if promptCacheKey := strings.TrimSpace(gjson.GetBytes(userPayload, "prompt_cache_key").String()); promptCacheKey != "" {
		state.originalPromptCacheKey = promptCacheKey
		state.promptCacheKey = state.confuseIdentity(codexIdentityPrefixPromptCache, promptCacheKey)
		rawJSON = helps.SetStringIfDifferent(rawJSON, "prompt_cache_key", state.promptCacheKey)
	}
	if installationID := strings.TrimSpace(gjson.GetBytes(userPayload, "client_metadata.x-codex-installation-id").String()); installationID != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-installation-id", state.confuseIdentity(codexIdentityPrefixInstall, installationID))
	}
	if turnMetadata := strings.TrimSpace(gjson.GetBytes(rawJSON, "client_metadata.x-codex-turn-metadata").String()); turnMetadata != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-turn-metadata", applyCodexTurnMetadataIdentityConfuse(turnMetadata, &state))
	}
	rawJSON = applyCodexClientMetadataIdentityConfuse(rawJSON, &state)

	return rawJSON, state
}

// applyCodexClientMetadataIdentityConfuse rewrites the session, thread and turn
// identifiers the native client mirrors into client_metadata. The request
// headers and the turn metadata carry the same values, so confusing only one
// surface makes the upstream request contradict itself.
func applyCodexClientMetadataIdentityConfuse(rawJSON []byte, state *codexIdentityConfuseState) []byte {
	if state == nil || !state.enabled || len(rawJSON) == 0 {
		return rawJSON
	}
	sessionFields := []string{"session_id", "thread_id"}
	turnFields := []string{"turn_id", "root_turn_id"}
	for _, field := range sessionFields {
		path := "client_metadata." + field
		if value := strings.TrimSpace(gjson.GetBytes(rawJSON, path).String()); value != "" {
			rawJSON, _ = sjson.SetBytes(rawJSON, path, state.confuseIdentity(codexIdentityPrefixPromptCache, value))
		}
	}
	for _, field := range turnFields {
		path := "client_metadata." + field
		if value := strings.TrimSpace(gjson.GetBytes(rawJSON, path).String()); value != "" {
			rawJSON, _ = sjson.SetBytes(rawJSON, path, state.confuseIdentity(codexIdentityPrefixTurn, value))
		}
	}
	if windowID := strings.TrimSpace(gjson.GetBytes(rawJSON, "client_metadata.x-codex-window-id").String()); windowID != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-window-id", state.confuseWindowID(windowID))
	}
	return rawJSON
}

func applyCodexIdentityConfuseHeaders(headers http.Header, state *codexIdentityConfuseState) {
	if headers == nil {
		return
	}
	if state == nil || !state.enabled {
		return
	}

	if rawTurnMetadata := strings.TrimSpace(headers.Get("X-Codex-Turn-Metadata")); rawTurnMetadata != "" {
		headers.Set("X-Codex-Turn-Metadata", applyCodexTurnMetadataIdentityConfuse(rawTurnMetadata, state))
	}
	if state.promptCacheKey == "" {
		return
	}

	setCodexSessionHeaderCasePreserved(headers, "Session-Id", state.promptCacheKey)
	if headerValueCaseInsensitive(headers, "Conversation_id") != "" {
		setHeaderCasePreserved(headers, "Conversation_id", state.promptCacheKey)
	}
	headers.Set("X-Client-Request-Id", state.promptCacheKey)
	headers.Set("Thread-Id", state.promptCacheKey)
	windowID := strings.TrimSpace(headerValueCaseInsensitive(headers, "X-Codex-Window-Id"))
	if windowID == "" {
		windowID = state.promptCacheKey + ":0"
	} else {
		windowID = state.confuseWindowID(windowID)
	}
	setHeaderCasePreserved(headers, "X-Codex-Window-Id", windowID)
}

func applyCodexTurnMetadataIdentityConfuse(rawTurnMetadata string, state *codexIdentityConfuseState) string {
	updatedTurnMetadata := rawTurnMetadata
	if state == nil || !state.enabled {
		return updatedTurnMetadata
	}
	if state.promptCacheKey != "" && gjson.Get(rawTurnMetadata, "prompt_cache_key").Exists() {
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, "prompt_cache_key", state.promptCacheKey)
	} else if state.promptCacheKey != "" && state.originalPromptCacheKey != "" {
		updatedTurnMetadata = strings.ReplaceAll(updatedTurnMetadata, state.originalPromptCacheKey, state.promptCacheKey)
	}
	for _, field := range codexTurnMetadataIdentityFields {
		value := strings.TrimSpace(gjson.Get(rawTurnMetadata, field).String())
		if value == "" {
			continue
		}
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, field, state.confuseTurnMetadataField(field, value))
	}
	return updatedTurnMetadata
}

// codexTurnMetadataIdentityFields lists every per-client identifier the Codex
// turn metadata carries. Every entry maps to exactly one confusion kind so the
// mapping stays deterministic regardless of which surface is rewritten first.
var codexTurnMetadataIdentityFields = []string{
	"installation_id",
	"session_id",
	"thread_id",
	"turn_id",
	"root_turn_id",
	"context_window_id",
	"window_id",
}

func (state *codexIdentityConfuseState) confuseTurnMetadataField(field string, value string) string {
	switch field {
	case "installation_id":
		return state.confuseIdentity(codexIdentityPrefixInstall, value)
	case "turn_id", "root_turn_id":
		return state.confuseIdentity(codexIdentityPrefixTurn, value)
	case "context_window_id":
		return state.confuseIdentity(codexIdentityPrefixContextWin, value)
	case "window_id":
		return state.confuseWindowID(value)
	default:
		return state.confuseIdentity(codexIdentityPrefixPromptCache, value)
	}
}

func applyCodexIdentityConfuseResponsePayload(payload []byte, state codexIdentityConfuseState) []byte {
	payload = replaceCodexIdentityResponsePayload(payload, state.originalPromptCacheKey, state.promptCacheKey)
	for _, identity := range state.identities {
		payload = replaceCodexIdentityResponsePayload(payload, identity.original, identity.confused)
	}
	return payload
}

func applyCodexIdentityExposeResponsePayload(payload []byte, state codexIdentityConfuseState) []byte {
	payload = replaceCodexIdentityResponsePayload(payload, state.promptCacheKey, state.originalPromptCacheKey)
	for _, identity := range state.identities {
		payload = replaceCodexIdentityResponsePayload(payload, identity.confused, identity.original)
	}
	return payload
}

func (state *codexIdentityConfuseState) confuseTurnID(turnID string) string {
	return state.confuseIdentity(codexIdentityPrefixTurn, turnID)
}

// confuseIdentity maps one client identifier onto its per-auth replacement. The
// replacement is memoized by value, so the same identifier always resolves to
// the same confused value whichever surface -- headers, client_metadata or turn
// metadata -- mentions it first. Re-running the rewrite on an already confused
// value returns it unchanged, which keeps repeated passes idempotent.
func (state *codexIdentityConfuseState) confuseIdentity(kind string, value string) string {
	value = strings.TrimSpace(value)
	if state == nil || !state.enabled || strings.TrimSpace(state.authID) == "" || value == "" {
		return value
	}
	for _, replacement := range state.identities {
		if replacement.original == value || replacement.confused == value {
			return replacement.confused
		}
	}
	confused := codexIdentityConfuseUUID(state.authID, kind, value)
	state.identities = append(state.identities, codexIdentityReplacement{original: value, confused: confused})
	return confused
}

// confuseWindowID rewrites the session identifier embedded in a Codex window id
// ("<session-id>:<window-number>") while preserving the window number.
func (state *codexIdentityConfuseState) confuseWindowID(windowID string) string {
	windowID = strings.TrimSpace(windowID)
	if state == nil || !state.enabled || windowID == "" {
		return windowID
	}
	prefix, suffix, found := strings.Cut(windowID, ":")
	confused := state.confuseIdentity(codexIdentityPrefixPromptCache, strings.TrimSpace(prefix))
	if !found {
		return confused + ":0"
	}
	return confused + ":" + suffix
}

func replaceCodexIdentityResponsePayload(payload []byte, from string, to string) []byte {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if len(payload) == 0 || from == "" || to == "" || from == to || !bytes.Contains(payload, []byte(from)) {
		return payload
	}
	return bytes.ReplaceAll(payload, []byte(from), []byte(to))
}

func codexIdentityConfuseEnabled(cfg *config.Config) bool {
	if cfg == nil || !cfg.Codex.IdentityConfuse {
		return false
	}
	strategy := strings.ToLower(strings.TrimSpace(cfg.Routing.Strategy))
	return cfg.Routing.SessionAffinity || strategy == "fill-first" || strategy == "fillfirst" || strategy == "ff"
}

func codexIdentityConfuseUUID(authID string, kind string, value string) string {
	name := strings.Join([]string{"cli-proxy-api", "codex", "identity-confuse", kind, strings.TrimSpace(authID), strings.TrimSpace(value)}, ":")
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}

func applyCodexHeaders(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config, clientHeaders ...http.Header) {
	var ginHeaders http.Header
	if len(clientHeaders) > 0 && clientHeaders[0] != nil {
		ginHeaders = clientHeaders[0]
	} else if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header
	}
	applyCodexHeadersFromSources(r, auth, token, stream, cfg, ginHeaders)
}

// applyCodexTurnTicket replaces the turn-state header with a harvested healthy ticket
// for this (auth, model) bucket, when one is available.
//
// The call site passes the outbound model, not the client's requested model, because the
// harvester buckets tickets by the model it probed. Injection runs after every other
// header source has been considered, including the client-supplied value: a stale or
// degraded turn-state from the client would otherwise keep the account in the state this
// feature exists to escape. A no-op when no ticket is available leaves pass-through
// behaviour intact.
func applyCodexTurnTicket(ctx context.Context, headers http.Header, auth *cliproxyauth.Auth, model string) bool {
	return helps.ApplyCodexTurnTicket(auth, model, headers, ctx)
}

// observeCodexTurnTicketResponse feeds the actual upstream status and both sides of
// the wire to the adaptive ticket policy. The response side is deliberately separate
// from the legacy passive harvester so 312/degraded responses can become sticky without
// replaying the request that discovered them.
func observeCodexTurnTicketResponse(ctx context.Context, status int, responseHeaders, requestHeaders http.Header, auth *cliproxyauth.Auth, model string, injected bool) {
	helps.ObserveCodexTurnTicketResponse(auth, model, status, responseHeaders, requestHeaders, injected, ctx)
}

// observeCodexWebsocketTurnTicketResponse observes a successful physical websocket
// handshake. An HTTP response from a failed upgrade is not a WebSocket 101 and must not
// transition adaptive state. Reused sockets have no handshake response and are skipped.
func observeCodexWebsocketTurnTicketResponse(ctx context.Context, response *http.Response, errDial error, requestHeaders http.Header, auth *cliproxyauth.Auth, model string, injected bool) {
	if errDial != nil || response == nil || response.StatusCode != http.StatusSwitchingProtocols {
		return
	}
	observeCodexTurnTicketResponse(ctx, response.StatusCode, response.Header, requestHeaders, auth, model, injected)
}

// harvestCodexTurnTicket records a healthy turn-state the upstream minted for live
// traffic. Passive capture costs no extra quota and keeps the bucket fresh without
// waiting for the next synthetic probe cycle.
func harvestCodexTurnTicket(headers http.Header, auth *cliproxyauth.Auth, model string) {
	helps.HarvestCodexTurnStateOnResponse(auth, model, headers)
}

// applyModelHeaderOverrides forces models.json config.override_header onto upstream headers.
func applyModelHeaderOverrides(headers http.Header, modelName string) {
	if headers == nil {
		return
	}
	overrides := registry.ModelOverrideHeaders(modelName)
	if len(overrides) == 0 {
		return
	}
	for key, value := range overrides {
		headers.Set(key, value)
	}
	if strings.Contains(headers.Get("User-Agent"), "Mac OS") && codexSessionHeaderValue(headers) == "" {
		headers.Set("Session_id", uuid.NewString())
	}
}

// applyCodexDirectImageHeaders sets Codex upstream headers for direct /images/* calls.
// Downstream client User-Agent values are not forwarded to reduce Cloudflare 1010 blocks.
func applyCodexDirectImageHeaders(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config, clientHeaders ...http.Header) {
	var ginHeaders http.Header
	if len(clientHeaders) > 0 && clientHeaders[0] != nil {
		ginHeaders = clientHeaders[0].Clone()
		ginHeaders.Del("User-Agent")
	} else if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header.Clone()
		ginHeaders.Del("User-Agent")
	}
	applyCodexHeadersFromSources(r, auth, token, stream, cfg, ginHeaders)
}

func applyCodexHeadersFromSources(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config, ginHeaders http.Header) {
	r.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(token) != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	} else {
		r.Header.Del("Authorization")
	}

	misc.EnsureHeader(r.Header, ginHeaders, "Version", "")
	if ginHeaders != nil && ginHeaders.Get("X-Codex-Beta-Features") != "" {
		r.Header.Set("X-Codex-Beta-Features", ginHeaders.Get("X-Codex-Beta-Features"))
	}
	misc.EnsureHeader(r.Header, ginHeaders, "X-Codex-Turn-Metadata", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Codex-Turn-State", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Client-Request-Id", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Codex-Window-Id", "")
	misc.EnsureHeader(r.Header, ginHeaders, "Thread-Id", "")
	misc.EnsureHeader(r.Header, ginHeaders, "Session-Id", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Openai-Internal-Codex-Responses-Lite", "")

	cfgUserAgent, _ := codexHeaderDefaults(cfg, auth)
	ensureHeaderWithConfigPrecedence(r.Header, ginHeaders, "User-Agent", cfgUserAgent, codexUserAgent)

	if stream {
		r.Header.Set("Accept", "text/event-stream")
	} else {
		r.Header.Set("Accept", "application/json")
	}

	isAPIKey := codexAuthUsesAPIKey(auth)
	if originator := strings.TrimSpace(ginHeaders.Get("Originator")); originator != "" {
		r.Header.Set("Originator", originator)
	} else if !isAPIKey {
		r.Header.Set("Originator", codexOriginator)
	}
	if !isAPIKey {
		if auth != nil && auth.Metadata != nil {
			if accountID, ok := auth.Metadata["account_id"].(string); ok {
				r.Header.Set("Chatgpt-Account-Id", accountID)
			}
		}
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs, ginHeaders)
	stripConnectionSpecificUpstreamHeaders(r.Header)
	applyCodexCloakingHeaders(r.Header, cfg)
}

// connectionSpecificUpstreamHeaders are forbidden on HTTP/2 (RFC 9113 §8.2.2)
// and no native client sends them. Go's HTTP/2 stack forwards "Connection"
// instead of dropping it, so a request that advertises "Connection: Keep-Alive"
// over an HTTP/2 connection is both a protocol violation and a cheap way for an
// upstream to tell the request apart from a real client.
var connectionSpecificUpstreamHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Transfer-Encoding",
}

func stripConnectionSpecificUpstreamHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	for _, name := range connectionSpecificUpstreamHeaders {
		headers.Del(name)
	}
}

func applyCodexCloakingHeaders(headers http.Header, cfg *config.Config) {
	if headers == nil || cfg == nil || cfg.Codex.DisableCodexCloaking {
		return
	}
	headers.Set("User-Agent", codexUserAgent)
	headers.Set("Originator", codexOriginator)
	headers.Set("Version", codexVersion)
}

func normalizeCodexInstructions(body []byte, nativeRequest ...bool) []byte {
	if len(nativeRequest) > 0 && nativeRequest[0] {
		return body
	}
	instructions := gjson.GetBytes(body, "instructions")
	if !instructions.Exists() || instructions.Type == gjson.Null {
		body, _ = sjson.SetBytes(body, "instructions", "")
	}
	return body
}

var imageGenToolJSON = []byte(`{"type":"image_generation","output_format":"png"}`)
var imageGenToolArrayJSON = []byte(`[{"type":"image_generation","output_format":"png"}]`)

func isCodexFreePlanAuth(auth *cliproxyauth.Auth) bool {
	if auth == nil || auth.Attributes == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["plan_type"]), "free")
}

func isImageGenerationFunctionTool(tool gjson.Result) bool {
	switch tool.Get("type").String() {
	case "function":
		return tool.Get("name").String() == "image_gen.imagegen"
	case "namespace":
		if tool.Get("name").String() != "image_gen" {
			return false
		}
		tools := tool.Get("tools")
		if !tools.IsArray() {
			return false
		}
		for _, nestedTool := range tools.Array() {
			if nestedTool.Get("type").String() == "function" && nestedTool.Get("name").String() == "imagegen" {
				return true
			}
		}
	}
	return false
}

func ensureImageGenerationTool(body []byte, baseModel string, auth *cliproxyauth.Auth, headers http.Header) []byte {
	if util.IsCodexResponsesLiteRequest(body, headers) {
		return body
	}
	if strings.HasSuffix(baseModel, "spark") {
		return body
	}
	if isCodexFreePlanAuth(auth) {
		return body
	}

	tools := gjson.GetBytes(body, "tools")
	if !tools.Exists() || !tools.IsArray() {
		body, _ = sjson.SetRawBytes(body, "tools", imageGenToolArrayJSON)
		return body
	}
	for _, t := range tools.Array() {
		if t.Get("type").String() == "image_generation" || isImageGenerationFunctionTool(t) {
			return body
		}
	}
	body, _ = sjson.SetRawBytes(body, "tools.-1", imageGenToolJSON)
	return body
}

func normalizeCodexParallelToolCalls(body []byte, headers http.Header) []byte {
	if util.IsCodexResponsesLiteRequest(body, headers) {
		body = helps.SetBoolIfDifferent(body, "parallel_tool_calls", false)
		return body
	}
	return normalizeCodexParallelToolCallsForTools(body)
}

func normalizeCodexParallelToolCallsForTools(body []byte) []byte {
	if !gjson.GetBytes(body, "parallel_tool_calls").Exists() {
		return body
	}

	tools := gjson.GetBytes(body, "tools")
	hasTools := tools.Exists() && tools.IsArray() && len(tools.Array()) > 0
	if hasTools {
		return body
	}

	body, _ = sjson.DeleteBytes(body, "parallel_tool_calls")
	return body
}

func publishCodexImageToolUsage(ctx context.Context, reporter *helps.UsageReporter, body []byte, completedData []byte) {
	detail, ok := helps.ParseCodexImageToolUsage(completedData)
	if !ok {
		return
	}
	reporter.EnsurePublished(ctx)
	reporter.PublishAdditionalModel(ctx, codexImageGenerationToolModel(body), detail)
}

func codexImageGenerationToolModel(body []byte) string {
	tools := gjson.GetBytes(body, "tools")
	if tools.IsArray() {
		for _, tool := range tools.Array() {
			if tool.Get("type").String() != "image_generation" {
				continue
			}
			if model := strings.TrimSpace(tool.Get("model").String()); model != "" {
				return model
			}
			break
		}
	}
	return codexDefaultImageToolModel
}
