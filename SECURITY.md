# Security

Reporting a vulnerability: e-mail **vyntryxofficial@gmail.com** with the subject "vyntryx-mcp security". Please include steps to
reproduce and do not open a public issue for security problems.

## What this connector does with your data
- Reads only the folder you pass to `vyntryx_scan_source_upload`, after you approve the tool call in your IDE.
  Secrets (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `.npmrc`, ...), `.git/`, dependency/build folders, symlinks and files over
  25 MB are never packaged. `vyntryx-mcp preview <folder>` shows exactly what would be sent.
- Talks only to the one server you logged in to (`https`, or `http` for localhost). Redirects are not followed, so a
  token is never replayed to another host.
- Stores a refresh token and a DPoP private key in the OS keyring; without a keyring, in a `0600` file inside a `0700`
  directory (`~/.config/vyntryx-mcp`). Access tokens are kept in memory only. Tokens are never logged or printed.
- Tokens are bound to the DPoP key (RFC 7638 thumbprint): a copied access token alone does not work.
- No telemetry.

## Prompt-injection hygiene
Scan results contain text from the scanned code. Every tool result is wrapped in a labelled
`UNTRUSTED DATA` block and any end marker inside it is neutralised; MCP clients should still treat tool output as data.
`token_env` only accepts variables named `VYNTRYX_GIT_TOKEN*`, so a malicious finding or README cannot make the agent
send some other secret (such as an API key) to a git host.

## Known limits
- Redaction of secrets found *inside* source is the server's job; the client only avoids sending secret-looking files.
- A secret in a file with an ordinary name (for example `config.py`) is uploaded: that is what a secrets scan is for.
- Git history (`include_git`) is not exposed as a tool option yet; `.git/config` is never sent even then.
