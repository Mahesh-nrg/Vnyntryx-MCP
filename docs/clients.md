# Connecting Claude Code, Codex and VS Code

Written 2026-10-27 from the official pages linked in each section; check them if an IDE update changes the syntax. The connector is installed on demand by `uvx` (nothing to pre-install beyond `uv`).

**First, sign in once in a terminal** (the IDE cannot show the device code):

```bash
uvx --from git+https://github.com/Mahesh-nrg/Vnyntryx-MCP vyntryx-mcp login --url https://testa4.vyntryx.com
```

`VYNTRYX_URL` in the snippets below is optional after that: the server you logged in to is remembered. If you set it, it must
be `https` (or `http://localhost`).

## Claude Code
Source: https://code.claude.com/docs/en/mcp (fetched 2026-10-27)

```bash
claude mcp add --transport stdio vyntryx -- uvx --from git+https://github.com/Mahesh-nrg/Vnyntryx-MCP vyntryx-mcp
# with an env var: put --transport between --env and the name, or the name is read as another KEY=value
claude mcp add --env VYNTRYX_URL=https://testa4.vyntryx.com --transport stdio vyntryx -- uvx --from git+https://github.com/Mahesh-nrg/Vnyntryx-MCP vyntryx-mcp
```
Project-shared file `.mcp.json` (scope `project`; Claude Code asks before using it). Entries without `type` are stdio:
```json
{ "mcpServers": { "vyntryx": {
    "command": "uvx",
    "args": ["--from", "git+https://github.com/Mahesh-nrg/Vnyntryx-MCP", "vyntryx-mcp"],
    "env": { "VYNTRYX_URL": "https://testa4.vyntryx.com" } } } }
```
Verified on the page: syntax `claude mcp add [options] <name> -- <command> [args...]`; `--transport`, `--env`/`-e`, `--scope`
(`local` default in `~/.claude.json`, `project` in `.mcp.json`, `user`); `add-json <name> '<json>'` takes the object inside
`mcpServers`; `${VAR}` / `${VAR:-default}` expansion in `command`, `args`, `env`.

## Codex (CLI, IDE extension and app share one config)
Source: https://learn.chatgpt.com/docs/extend/mcp?surface=cli (the old URL developers.openai.com/codex/mcp redirects here)

```bash
codex mcp add vyntryx -- uvx --from git+https://github.com/Mahesh-nrg/Vnyntryx-MCP vyntryx-mcp
```
or in `~/.codex/config.toml` (project-scoped `.codex/config.toml` works for trusted projects):
```toml
[mcp_servers.vyntryx]
command = "uvx"
args = ["--from", "git+https://github.com/Mahesh-nrg/Vnyntryx-MCP", "vyntryx-mcp"]
startup_timeout_sec = 30     # default 10: a first `uvx` run downloads the package
tool_timeout_sec = 300       # default 60: uploading a large project can take longer

[mcp_servers.vyntryx.env]
VYNTRYX_URL = "https://testa4.vyntryx.com"
```
Verified on the page: top-level key is `mcp_servers`; stdio fields `command`, `args`, `env`, `env_vars`, `cwd`,
`startup_timeout_sec` (default 10), `tool_timeout_sec` (default 60); `codex mcp add <name> [--env K=V] -- <cmd>`.
The page also lists `default_tools_approval_mode` (`auto|prompt|writes|approve`), where `writes` prompts for tools that
are not marked read-only. This connector marks only read tools read-only, so `writes` makes Codex ask before uploads.
**Not verified:** the exact table the approval setting belongs in; check the page before adding it.

## VS Code
Source: https://code.visualstudio.com/docs/agents/reference/mcp-configuration (fetched 2026-10-27)

`.vscode/mcp.json` (workspace) or your user profile. The top-level key is **`servers`** (not `mcpServers`):
```json
{
  "servers": {
    "vyntryx": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Mahesh-nrg/Vnyntryx-MCP", "vyntryx-mcp"],
      "env": { "VYNTRYX_URL": "https://testa4.vyntryx.com" }
    }
  }
}
```
Verified on the page: stdio fields `type`, `command`, `args`, `cwd`, `env`, `envFile`; variables `${env:NAME}`,
`${input:id}`, `${workspaceFolder}`; the portable `.mcp.json` at the workspace root uses `mcpServers` and `${NAME}`
instead; workspace MCP servers inherit Workspace Trust. Because the entry is a stdio server that runs code, VS Code
asks you to trust it on first start.

## MCP protocol facts used (modelcontextprotocol.io, revision **2026-07-28**, fetched 2026-10-27)
- Transports: stdio (newline-delimited JSON-RPC over the child's stdin/stdout) and Streamable HTTP. A stdio server must
  keep stdout for protocol messages (this package logs to stderr only).
  https://modelcontextprotocol.io/specification/2026-07-28/basic/transports
- Authorization (OAuth 2.1 based) is for HTTP transports: "Implementations using an STDIO transport SHOULD NOT follow
  this specification, and instead retrieve credentials from the environment." That is why login is a separate CLI step
  (device code, RFC 8628) and the stdio server reads stored credentials, rather than the IDE doing OAuth.
  https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- Tool annotations (`readOnlyHint` default false, `destructiveHint` default true, `idempotentHint` default false,
  `openWorldHint` default true, `title`) are hints; "clients MUST consider tool annotations to be untrusted unless they
  come from trusted servers", and "there SHOULD always be a human in the loop with the ability to deny tool invocations".
  https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- Progress: `notifications/progress {progressToken, progress, total?, message?}`; a client asks for them by putting a
  `progressToken` in the request `_meta`; the server "is not obligated" to send any. Not used yet (plan item M4.3).
  https://modelcontextprotocol.io/specification/2026-07-28/schema
- Python SDK: `mcp` 2.3.0 is the latest release on PyPI (1.30.0 is the latest 1.x); v1 moves to maintenance with
  critical fixes. The v2 server class is `MCPServer` (`mcp.server.mcpserver`), and "serves both revisions at once" over
  the same stdio server (the 2026-07-28 stateless mode and the legacy `initialize` handshake).
  https://pypi.org/project/mcp/ , https://py.sdk.modelcontextprotocol.io/whats-new/ , https://py.sdk.modelcontextprotocol.io/migration/
  This package pins `mcp>=2.3,<3`.

## Not verified
- **Real IDEs.** The server was exercised only with the SDK's own client in both modes (`auto` = 2026-07-28 stateless,
  `legacy` = `initialize` handshake) over a real stdio subprocess (`tests/test_stdio.py`). It was not run inside Claude
  Code, Codex or VS Code, so which protocol revision each currently negotiates is untested.
- The MCP SDK's minimum Python: the PyPI metadata says `>=3.10`, the SDK README says 3.11+. This package requires 3.11.
- The py.sdk.modelcontextprotocol.io migration page was only partly readable (truncated), so progress-notification and
  other 1.x -> 2.x details beyond those quoted above were not reviewed.
- Windows launch details (for example wrapping with `cmd /c`) appeared only in third-party guides, not the official pages.
- Whether Claude Code's docs say anything about stdout noise (the fetched page was truncated before that section;
  third-party guides say to log to stderr). The spec statement above covers it.
