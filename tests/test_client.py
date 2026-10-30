import pytest

from vyntryx_mcp import dpop
from vyntryx_mcp.client import Api, LoginError, NotLoggedIn, ApiError, check_base_url, device_login, resolve_base


class Clock:
    """Fake time: sleep() advances monotonic()."""

    def __init__(self):
        self.t, self.sleeps = 0.0, []

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s

    def now(self):
        return self.t


def login(fake, store, clock=None, say=lambda m: None):
    c = clock or Clock()
    device_login(fake.base, store, say, sleep=c.sleep, monotonic=c.now)
    return c


@pytest.mark.parametrize("url", ["http://example.com", "ftp://x", "https://user:pw@x.example", "https://x.example/?a=1",
                                 "https://", "", "javascript:alert(1)"])
def test_base_url_refused(url):
    with pytest.raises(ValueError):
        check_base_url(url)


@pytest.mark.parametrize("url,out", [("https://v.example/", "https://v.example"),
                                     ("http://localhost:8002", "http://localhost:8002"),
                                     ("http://127.0.0.1:9", "http://127.0.0.1:9"),
                                     ("http://[::1]:9/", "http://[::1]:9")])
def test_base_url_accepted(url, out):
    assert check_base_url(url) == out


def test_resolve_base_order(store, monkeypatch):
    monkeypatch.delenv("VYNTRYX_URL", raising=False)
    with pytest.raises(NotLoggedIn):
        resolve_base(None, store)
    store.set_base_url("https://saved.example")
    assert resolve_base(None, store) == "https://saved.example"
    monkeypatch.setenv("VYNTRYX_URL", "https://env.example")
    assert resolve_base(None, store) == "https://env.example"
    assert resolve_base("https://flag.example", store) == "https://flag.example"
    monkeypatch.setenv("VYNTRYX_URL", "http://insecure.example")
    with pytest.raises(ValueError):
        resolve_base(None, store)


def test_device_flow_pending_slow_down_then_ok(fake, store):
    fake.device_script = [(400, {"error": "authorization_pending"}), (400, {"error": "slow_down"}), (200, None)]
    said = []
    clock = login(fake, store, say=said.append)
    assert clock.sleeps == [2, 2, 7]          # slow_down adds 5s to the interval
    assert any("WDJB-MJHT" in m and fake.base + "/device" in m for m in said)
    assert store.get(fake.base, "refresh_token") == "refresh-secret-1"
    key = dpop.key_from_pem(store.get(fake.base, "dpop_key"))
    body = fake.requests[0]["json"]
    assert body["dpop_jwk"] == dpop.public_jwk(key) and fake.bound_jkt == dpop.thumbprint(dpop.public_jwk(key))
    poll = fake.requests[-1]["json"]
    assert poll["device_code"] == "dev-code-1" and poll["grant_type"].endswith("device_code")
    assert poll["dpop_jwk"] == dpop.public_jwk(key)


@pytest.mark.parametrize("err", ["expired_token", "access_denied", "weird_error"])
def test_device_flow_terminal_errors(fake, store, err):
    fake.device_script = [(400, {"error": err})]
    with pytest.raises(LoginError, match=err):
        login(fake, store)
    assert store.get(fake.base, "refresh_token") is None


def test_device_flow_gives_up_at_local_deadline(fake, store):
    fake.device_script = [(400, {"error": "authorization_pending"})]
    fake.expires_in = 10
    with pytest.raises(LoginError, match="expired"):
        login(fake, store)


def test_authed_call_carries_bearer_and_valid_dpop(fake, store):
    login(fake, store)
    fake.routes[("GET", "/api/mcp/scan/s1/status")] = lambda r: (200, {"state": "running"})
    api = Api(fake.base, store)
    assert api.get("/api/mcp/scan/s1/status", since="5") == {"state": "running"}
    req = fake.requests[-1]
    assert req["headers"]["Authorization"].startswith("Bearer access-") and req["query"] == "since=5"
    assert fake.proof_errors == []


def test_json_post_hashes_body_into_proof(fake, store):
    login(fake, store)
    fake.routes[("POST", "/api/mcp/x")] = lambda r: (200, {"got": r["json"]})
    assert Api(fake.base, store).post("/api/mcp/x", {"a": 1}) == {"got": {"a": 1}}
    assert fake.proof_errors == []


def test_stale_access_token_refreshes_once_and_retries(fake, store):
    login(fake, store)
    fake.routes[("GET", "/api/mcp/ping")] = lambda r: (200, {"ok": True})
    api = Api(fake.base, store)
    api.get("/api/mcp/ping")                      # obtains access-2 via refresh (no token held yet)
    fake.fail_next_authed = True                  # server now says token expired
    assert api.get("/api/mcp/ping") == {"ok": True}
    refreshes = [r for r in fake.requests if r["path"] == "/api/auth/refresh"]
    assert len(refreshes) == 2                    # first use, then after the 401
    last = refreshes[-1]["json"]
    assert last["refresh_token"] == "refresh-secret-1" and last["dpop_jwk"]["kty"] == "EC"


def test_refresh_rejected_clears_credentials(fake, store):
    login(fake, store)
    fake.refresh_token = "rotated-elsewhere"
    api = Api(fake.base, store)
    with pytest.raises(NotLoggedIn, match="login"):
        api.get("/api/mcp/ping")
    assert store.get(fake.base, "refresh_token") is None


def test_not_logged_in_without_refresh_token(fake, store):
    with pytest.raises(NotLoggedIn):
        Api(fake.base, store).get("/api/mcp/ping")
    assert fake.requests == []


def test_api_error_carries_status_and_detail(fake, store):
    login(fake, store)
    fake.routes[("GET", "/api/mcp/boom")] = lambda r: (403, {"detail": "Not your company"})
    with pytest.raises(ApiError) as e:
        Api(fake.base, store).get("/api/mcp/boom")
    assert e.value.status == 403 and "Not your company" in str(e.value)


def test_tokens_never_logged_or_printed(fake, store, caplog, capsys):
    import logging
    caplog.set_level(logging.DEBUG)
    login(fake, store)
    fake.routes[("GET", "/api/mcp/ping")] = lambda r: (200, {})
    Api(fake.base, store).get("/api/mcp/ping")
    out = capsys.readouterr()
    for secret in ("refresh-secret-1", "access-1", "access-2"):
        assert secret not in caplog.text and secret not in out.out and secret not in out.err


# ---- Cloudflare Access service token (dedicated MCP hostname) --------------------------------------------------------
def test_access_headers_sent_on_every_call_remembered_and_survive_session_expiry(fake, store, monkeypatch):
    monkeypatch.setenv("VYNTRYX_ACCESS_CLIENT_ID", "id-1")
    monkeypatch.setenv("VYNTRYX_ACCESS_CLIENT_SECRET", "sec-1")
    login(fake, store)
    assert all(r["headers"].get("CF-Access-Client-Id") == "id-1" and r["headers"].get("CF-Access-Client-Secret") == "sec-1"
               for r in fake.requests)
    assert store.get(fake.base, "access_id") == "id-1" and store.get(fake.base, "access_secret") == "sec-1"
    monkeypatch.delenv("VYNTRYX_ACCESS_CLIENT_ID")  # IDE config holds no secrets: the stored copy is used
    monkeypatch.delenv("VYNTRYX_ACCESS_CLIENT_SECRET")
    fake.routes[("GET", "/api/mcp/ping")] = lambda r: (200, {"ok": True})
    Api(fake.base, store).get("/api/mcp/ping")
    assert fake.requests[-1]["headers"]["CF-Access-Client-Id"] == "id-1"
    fake.refresh_token = "rotated-elsewhere"
    with pytest.raises(NotLoggedIn):
        Api(fake.base, store).get("/api/mcp/ping")
    assert store.get(fake.base, "refresh_token") is None and store.get(fake.base, "access_id") == "id-1"


def test_no_access_headers_when_not_configured(fake, store, monkeypatch):
    for v in ("VYNTRYX_ACCESS_CLIENT_ID", "VYNTRYX_ACCESS_CLIENT_SECRET"):
        monkeypatch.delenv(v, raising=False)
    login(fake, store)
    assert not any("CF-Access-Client-Id" in r["headers"] for r in fake.requests)


@pytest.mark.parametrize("body", [{"detail": "Access denied"}])
def test_gateway_block_gives_a_clear_message_at_login(fake, store, body):
    fake.device_script = [(403, body)]
    original = fake.handle

    def handle(req):
        return (403, body) if req["path"] == "/api/auth/device/code" else original(req)
    fake.handle = handle
    with pytest.raises(LoginError, match="VYNTRYX_ACCESS_CLIENT_ID"):
        login(fake, store)
