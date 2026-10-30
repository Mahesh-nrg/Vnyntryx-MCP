import json
import threading
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from dpop_verify import jwk_thumbprint, verify_proof
from vyntryx_mcp.store import Store

NO_AUTH = {"/api/auth/device/code", "/api/auth/device/token", "/api/auth/refresh"}


class FakeVyntryx:
    """Tiny in-test stand-in for the platform API contract (device flow, refresh, DPoP-checked /api/mcp/*)."""

    def __init__(self):
        self.requests = []                 # every request: method, path, headers, body (bytes), json
        self.routes = {}                   # (method, path) -> callable(req) -> (status, obj)
        self.device_script = [(200, None)]  # (status, body); None body = success tokens
        self.interval, self.expires_in = 2, 600
        self.refresh_token = "refresh-secret-1"
        self.valid_access, self.access_n = set(), 0
        self.bound_jkt, self.seen_jti, self.proof_errors = None, set(), []
        self.fail_next_authed = False
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                path = self.path.split("?")[0]
                try:
                    js = json.loads(body) if body and "json" in (self.headers.get("Content-Type") or "") else None
                except ValueError:
                    js = None
                req = {"method": self.command, "path": path, "query": self.path.partition("?")[2],
                       "headers": dict(self.headers), "body": body, "json": js}
                outer.requests.append(req)
                status, obj = outer.handle(req)
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = _do

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def handle(self, req):
        path, js = req["path"], req["json"] or {}
        if path == "/api/auth/device/code":
            self.bound_jkt = jwk_thumbprint(js["dpop_jwk"])
            return 200, {"device_code": "dev-code-1", "user_code": "WDJB-MJHT",
                         "verification_uri": f"{self.base}/device", "expires_in": self.expires_in,
                         "interval": self.interval}
        if path == "/api/auth/device/token":
            status, body = self.device_script.pop(0) if len(self.device_script) > 1 else self.device_script[0]
            if body is None:
                self.access_n, self.valid_access = 1, {"access-1"}
                body = {"access_token": "access-1", "refresh_token": self.refresh_token, "token_type": "bearer"}
            return status, body
        if path == "/api/auth/refresh":
            if js.get("refresh_token") != self.refresh_token or jwk_thumbprint(js["dpop_jwk"]) != self.bound_jkt:
                return 401, {"detail": "Invalid or expired refresh token"}
            self.access_n += 1
            self.valid_access = {f"access-{self.access_n}"}
            return 200, {"access_token": f"access-{self.access_n}", "token_type": "bearer"}
        auth = (req["headers"].get("Authorization") or "").removeprefix("Bearer ")
        if self.fail_next_authed:
            self.fail_next_authed = False
            return 401, {"detail": "token expired"}
        if auth not in self.valid_access:
            return 401, {"detail": "Invalid or expired token"}
        err = verify_proof(req["headers"].get("DPoP", ""), method=req["method"], url=self.base + path,
                           body=req["body"], bound_jkt=self.bound_jkt, seen=self.seen_jti)
        if err:
            self.proof_errors.append(err)
            return 401, {"error": "invalid_proof", "reason": err}
        route = self.routes.get((req["method"], path))
        return route(req) if route else (404, {"detail": "not found"})


@pytest.fixture
def fake():
    f = FakeVyntryx()
    yield f
    f.close()


@pytest.fixture
def store(tmp_path):
    return Store(home=tmp_path / "home", use_keyring=False)


def parse_multipart(req):
    """-> {field: (filename, bytes)} for a recorded multipart request."""
    ct = req["headers"]["Content-Type"].encode()
    msg = BytesParser(policy=default).parsebytes(b"Content-Type: " + ct + b"\r\n\r\n" + req["body"])
    return {p.get_param("name", header="content-disposition"): (p.get_filename(), p.get_payload(decode=True))
            for p in msg.iter_parts()}
