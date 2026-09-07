package constant

const (
	// CodexClientVersion is the version used by the default Codex device identity.
	CodexClientVersion = "0.153.4"
	// CodexOriginator identifies the default Codex CLI client.
	CodexOriginator = "codex_cli_rs"
	// CodexUserAgent is shared by requests and model catalog identity overrides.
	CodexUserAgent = CodexOriginator + "/" + CodexClientVersion + " (Linux 7.0.0-28; x86_64) rust"
)
