"""Spawn the real `python -m vyntryx_mcp` and talk MCP over stdio, in the 2026 and the legacy (initialize) modes."""
import sys

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from test_server import READ_ONLY, TOOLS


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_real_stdio_process_lists_tools_and_reports_login_state(tmp_path, mode):
    params = StdioServerParameters(command=sys.executable, args=["-m", "vyntryx_mcp"], env={
        "VYNTRYX_MCP_HOME": str(tmp_path), "VYNTRYX_MCP_NO_KEYRING": "1", "PATH": "/usr/bin:/bin",
        "VYNTRYX_URL": "https://vyntryx.invalid"})
    async with Client(params, mode=mode) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert set(tools) == TOOLS
        assert all(t.annotations.read_only_hint is (n in READ_ONLY) for n, t in tools.items())
        r = await c.call_tool("vyntryx_login_status", {})
        assert not r.is_error and '"logged_in": false' in r.content[0].text      # no network call: no credentials yet
        r = await c.call_tool("vyntryx_scan_status", {"session_id": "s1"})
        assert r.is_error and "vyntryx-mcp login" in r.content[0].text
