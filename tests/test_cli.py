import pytest

from vyntryx_mcp import cli
from vyntryx_mcp.store import Store


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VYNTRYX_MCP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VYNTRYX_MCP_NO_KEYRING", "1")
    monkeypatch.delenv("VYNTRYX_URL", raising=False)
    monkeypatch.setattr("vyntryx_mcp.client.time.sleep", lambda s: None)


def test_login_status_logout_flow(fake, capsys):
    assert cli.main(["login", "--url", fake.base]) == 0
    out = capsys.readouterr().out
    assert "WDJB-MJHT" in out and fake.base + "/device" in out
    for secret in ("refresh-secret-1", "access-1"):
        assert secret not in out
    assert cli.main(["status"]) == 0
    assert "logged in" in capsys.readouterr().out
    assert cli.main(["logout"]) == 0
    assert cli.main(["status"]) == 1
    assert "not logged in" in capsys.readouterr().out


def test_login_refuses_plain_http_remote(capsys):
    assert cli.main(["login", "--url", "http://example.com"]) == 2
    assert "https" in capsys.readouterr().err


def test_login_failure_exit_code(fake, capsys):
    fake.device_script = [(400, {"error": "access_denied"})]
    assert cli.main(["login", "--url", fake.base]) == 1
    assert "access_denied" in capsys.readouterr().err


def test_preview_lists_counts_without_uploading(tmp_path, capsys, fake):
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "a.py").write_text("x")
    (tmp_path / "p" / ".env").write_text("S=1")
    assert cli.main(["preview", str(tmp_path / "p")]) == 0
    out = capsys.readouterr().out
    assert "1 file" in out and "a.py" in out and ".env" not in out.replace("excluded", "")
    assert fake.requests == []
