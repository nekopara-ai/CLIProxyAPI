package constant

const (
	// CodexClientVersion is the version used by the default Codex device identity.
	CodexClientVersion = "0.155.0"
	// CodexOriginator identifies the default Codex CLI client.
	CodexOriginator = "codex_cli_rs"
)

// CodexUserAgent is shared by requests and model catalog identity overrides.
var CodexUserAgent = CodexUserAgentFor(CodexOriginator, CodexClientVersion)

// CodexUserAgentFor builds the canonical Codex CLI User-Agent for the given originator and
// version. Keeping the shape in one place lets a configured identity stay self-consistent
// instead of mixing a configured Version with a hard-coded device string.
func CodexUserAgentFor(originator, version string) string {
	return originator + "/" + version + " (Linux 7.0.0-28; x86_64) rust"
}
