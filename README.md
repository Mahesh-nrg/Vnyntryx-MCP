# Vyntryx MCP connector

Connect **Claude Code, Codex or VS Code** to your **Vyntryx** account. From your coding session you can ask Vyntryx to scan
your source code (static analysis, dependency and secret checks), read the findings, and see the same session as a chat
thread in the Vyntryx web UI.

> IDE scans are **static analysis (SAST) only**. Nothing in this connector can start active / DAST testing.

```
Your IDE  --(stdio)-->  vyntryx-mcp (runs on your machine)  --(HTTPS)-->  https://mcpa.vyntryx.com
```

## What you need
- An **access ID and access secret** for the connector address, issued to you by your Vyntryx administrator (the connector
  address is not open to the public). Treat the secret like a password.
- A **Vyntryx account** whose role is *pentester*, *team lead* or *manager*. Ask your Vyntryx administrator if the login below
  says your role is not allowed. **No password or key is ever stored in, or needed from, this repository.**
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) (it also fetches Python 3.11+ for you).
- One of: Claude Code, Codex, or VS Code (with its MCP support).

## 1. Sign in (once, in a terminal)
```bash
export VYNTRYX_ACCESS_CLIENT_ID="<your access ID>"
export VYNTRYX_ACCESS_CLIENT_SECRET="<your access secret>"
uvx --from git+https://github.com/Mahesh-nrg/Vnyntryx-MCP vyntryx-mcp login --url https://mcpa.vyntryx.com
```
1. The command prints a web address and a short code (for example `ABCD-EFGH`).
2. Open the address in your browser, sign in to Vyntryx the way you normally do, and confirm that the code matches.
3. The terminal says **Logged in**. The server and your access ID/secret are remembered securely on this computer (OS keyring),
   so IDE settings need neither.

The browser step happens on your normal Vyntryx site; the code is only valid for 10 minutes.

Useful commands (same prefix as above): `vyntryx-mcp status` (who am I), `vyntryx-mcp logout` (forget this machine),
`vyntryx-mcp preview <folder>` (list exactly what an upload would contain, sends nothing).

## 2. Add it to your IDE
Copy the line for your tool. Full details and file-based configs: [docs/clients.md](docs/clients.md).

**Claude Code**
```bash
claude mcp add --transport stdio vyntryx -- uvx --from git+https://github.com/Mahesh-nrg/Vnyntryx-MCP vyntryx-mcp
```

**Codex**
```bash
codex mcp add vyntryx -- uvx --from git+https://github.com/Mahesh-nrg/Vnyntryx-MCP vyntryx-mcp
```

**VS Code** - create `.vscode/mcp.json` in your project:
```json
{
  "servers": {
    "vyntryx": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Mahesh-nrg/Vnyntryx-MCP", "vyntryx-mcp"]
    }
  }
}
```
Restart the IDE (or its MCP server list) after adding. The first start downloads the package, which can take a few seconds.

## 3. Scan your code
Ask your assistant in plain words, for example:
- "Scan this project with Vyntryx." (it will ask you to approve the upload; read the prompt, then approve)
- "What is the status of the Vyntryx scan?"
- "List the high and critical findings." / "Show me finding `<uuid>` in full."
- "Which findings are related to this one, and what would fixing it affect?"

Every finding has a stable **UUID**. Open the Vyntryx web app (your usual address) in your browser to see the same scan as a chat-style
session, with the findings, relationships and report tools.

| Tool | What it does |
|---|---|
| `vyntryx_login_status` | who you are signed in as |
| `vyntryx_scan_source_upload(path, name?, exclude?)` | package a folder, upload it, start a scan (**asks for approval**) |
| `vyntryx_scan_source_git(url, ref?, token_env?)` | have Vyntryx clone an https repo and scan it (**asks for approval**) |
| `vyntryx_scan_status(session_id)` | progress |
| `vyntryx_list_findings(session_id, severity?, status?)` | findings with their UUIDs |
| `vyntryx_get_finding(session_id, uuid)` | one finding in full |
| `vyntryx_finding_relationships(uuid)` | linked findings and fix impact |
| `vyntryx_session_messages(session_id, since?)` / `vyntryx_post_message(session_id, text)` | the shared chat thread |
| `vyntryx_cancel_scan(session_id)` | stop a scan |

## What is sent, and what is kept
- Only the folder you point it at, after you approve. Secret-looking files (`.env*`, `*.pem`, `*.key`, `id_rsa*`, ...), `.git`,
  ignored files, dependency and build folders, symlinks and files over 25 MB are **never** packaged. Run
  `vyntryx-mcp preview <folder>` first if you want to see the list.
- Uploaded source is **deleted by Vyntryx after 7 days**.
- Your sign-in is stored in your OS keyring (or a `0600` file under `~/.config/vyntryx-mcp`). No telemetry.
- More: [SECURITY.md](SECURITY.md).

## Troubleshooting
| Symptom | What to do |
|---|---|
| "not logged in" / tools say login required | Run the sign-in command in step 1, then restart the IDE's MCP server. |
| "role is not allowed" | Your Vyntryx role cannot use IDE scans; ask your administrator. |
| Code expired | The code is valid for 10 minutes; run the login command again. |
| "blocked by the access gateway" / 403 | The access ID or secret is missing, wrong or revoked: set `VYNTRYX_ACCESS_CLIENT_ID` / `VYNTRYX_ACCESS_CLIENT_SECRET`, run the login again, or ask your administrator for new ones. |
| Cannot reach the server | Check your network and proxy settings; contact your Vyntryx administrator. |
| First start times out in Codex | Raise `startup_timeout_sec` (see docs/clients.md). |

## Support and security
Questions: contact your Vyntryx administrator. Security issues: see [SECURITY.md](SECURITY.md) (vyntryxofficial@gmail.com).

## Licence
Proprietary, all rights reserved; free to install and use with your Vyntryx account. See [LICENSE](LICENSE).
