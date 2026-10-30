"""Vyntryx HTTP client: base-URL policy, OAuth device-code login (RFC 8628), DPoP-signed requests, token refresh.

Contract assumed from the platform: /api/auth/device/{code,token}, /api/auth/refresh,
/api/mcp/*. Tokens are sent only to the one configured https (or localhost) origin; redirects are never followed.
"""
from __future__ import annotations

import json
import os
import time
from urllib.parse import urlsplit

import httpx

from . import dpop
from .store import Store

CLIENT_ID = "vyntryx-mcp"
SCOPE = "scan:source findings:read chat"
_LOCAL = {"localhost", "127.0.0.1", "::1"}
_MAX_RESPONSE = 5 * 1024 * 1024
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class NotLoggedIn(Exception):
    pass


class LoginError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"Vyntryx API error {status}: {detail}")
        self.status, self.detail = status, detail


def check_base_url(url: str) -> str:
    """Normalise to scheme://host[:port]; https required except for localhost; no credentials/query/path."""
    p = urlsplit((url or "").strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("server URL must look like https://host")
    if p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ValueError("server URL must be just scheme://host[:port] (no credentials, path or query)")
    if p.scheme == "http" and p.hostname.lower() not in _LOCAL:
        raise ValueError("server URL must use https (plain http is only allowed for localhost)")
    return f"{p.scheme}://{p.netloc.lower()}"


def resolve_base(flag: str | None, store: Store) -> str:
    """--url flag, then VYNTRYX_URL, then the server we last logged in to."""
    url = flag or os.environ.get("VYNTRYX_URL") or store.base_url()
    if not url:
        raise NotLoggedIn("no Vyntryx server configured: run `vyntryx-mcp login --url https://<your-vyntryx-host>`")
    return check_base_url(url)


_ACCESS_ENV = ("VYNTRYX_ACCESS_CLIENT_ID", "VYNTRYX_ACCESS_CLIENT_SECRET")
GATEWAY_HINT = ("blocked by the access gateway: set VYNTRYX_ACCESS_CLIENT_ID and VYNTRYX_ACCESS_CLIENT_SECRET "
                "(your Vyntryx administrator issues them) and run `vyntryx-mcp login` again")


def access_headers(store: Store, base: str) -> dict[str, str]:
    """Cloudflare Access service-token headers for this server, if the deployment uses them. Environment wins over the
    stored copy; they are only ever sent to `base` (redirects are never followed), never logged."""
    cid = os.environ.get(_ACCESS_ENV[0]) or store.get(base, "access_id")
    sec = os.environ.get(_ACCESS_ENV[1]) or store.get(base, "access_secret")
    return {"CF-Access-Client-Id": cid, "CF-Access-Client-Secret": sec} if cid and sec else {}


def _gateway_blocked(r: httpx.Response) -> bool:
    """403/redirect from the Cloudflare gateway or the origin's own access guard (not an application error)."""
    if r.status_code in (301, 302, 303, 307, 308):
        return "cloudflareaccess.com" in (r.headers.get("location") or "")
    if r.status_code != 403:
        return False
    try:
        body = r.json()
    except ValueError:
        return "cloudflare" in (r.headers.get("server") or "").lower()
    return isinstance(body, dict) and body.get("detail") == "Access denied"


def _error_code(r: httpx.Response) -> str:
    try:
        body = r.json()
    except ValueError:
        return f"http_{r.status_code}"
    if isinstance(body, dict):
        detail = body.get("detail")
        for v in (body.get("error"), detail.get("error") if isinstance(detail, dict) else detail):
            if isinstance(v, str) and v:
                return v[:80]
    return f"http_{r.status_code}"


def device_login(base: str, store: Store, say=print, *, sleep=None, monotonic=None) -> None:
    """Run the device flow; on success persist the refresh token + DPoP key. Raises LoginError."""
    base = check_base_url(base)
    sleep, monotonic = sleep or time.sleep, monotonic or time.monotonic
    key = dpop.new_key()
    jwk = dpop.public_jwk(key)
    try:
        with httpx.Client(timeout=30, follow_redirects=False, headers=access_headers(store, base)) as http:
            r = http.post(f"{base}/api/auth/device/code", json={"client_id": CLIENT_ID, "scope": SCOPE, "dpop_jwk": jwk})
            if r.status_code != 200:
                if _gateway_blocked(r):
                    raise LoginError(GATEWAY_HINT)
                raise LoginError(f"server refused the login request ({_error_code(r)})")
            d = r.json()
            say(f"To sign in, open {d['verification_uri']} and enter the code {d['user_code']}")
            if d.get("verification_uri_complete"):
                say(f"(or open {d['verification_uri_complete']} directly)")
            interval, deadline = int(d.get("interval") or 5), monotonic() + int(d.get("expires_in") or 600)
            while True:
                if monotonic() >= deadline:
                    raise LoginError("login expired before it was approved; run `vyntryx-mcp login` again")
                sleep(interval)
                r = http.post(f"{base}/api/auth/device/token", json={
                    "grant_type": DEVICE_GRANT, "device_code": d["device_code"], "client_id": CLIENT_ID, "dpop_jwk": jwk})
                if r.status_code == 200:
                    tok = r.json()
                    break
                if _gateway_blocked(r):
                    raise LoginError(GATEWAY_HINT)
                code = _error_code(r)
                if code == "authorization_pending":
                    continue
                if code == "slow_down":
                    interval += 5
                    continue
                raise LoginError(f"login failed: {code}")
    except httpx.HTTPError as e:
        raise LoginError(f"cannot reach {base}: {type(e).__name__}") from None
    except (KeyError, ValueError):
        raise LoginError("unexpected response from the server during login") from None
    if not tok.get("refresh_token"):
        raise LoginError("server did not issue a refresh token")
    store.set(base, "dpop_key", dpop.key_to_pem(key))
    store.set(base, "refresh_token", tok["refresh_token"])
    for env, field in zip(_ACCESS_ENV, ("access_id", "access_secret")):  # remember them so IDE configs need no secrets
        if os.environ.get(env):
            store.set(base, field, os.environ[env])
    store.set_base_url(base)


class Api:
    """Authenticated, DPoP-signed calls to one Vyntryx server. Access token is memory-only; refreshed on demand."""

    def __init__(self, base: str, store: Store, *, timeout: float = 60):
        self.base, self.store = check_base_url(base), store
        self._access: str | None = None
        self._http = httpx.Client(timeout=timeout, follow_redirects=False)

    # -- public helpers -------------------------------------------------------------------------------------------
    def get(self, path: str, **params):
        return self.request("GET", path, params={k: v for k, v in params.items() if v is not None})

    def post(self, path: str, body: dict | None = None):
        return self.request("POST", path, json_body=body if body is not None else {})

    def upload(self, path: str, file_path: str, name: str):
        return self.request("POST", path, upload=(file_path, name))

    # -- internals --------------------------------------------------------------------------------------------------
    def _key(self):
        pem = self.store.get(self.base, "dpop_key")
        if not pem:
            raise NotLoggedIn("not logged in: run `vyntryx-mcp login`")
        return dpop.key_from_pem(pem)

    def _refresh(self) -> None:
        token = self.store.get(self.base, "refresh_token")
        if not token:
            raise NotLoggedIn("not logged in: run `vyntryx-mcp login`")
        key = self._key()
        url = f"{self.base}/api/auth/refresh"
        body = json.dumps({"refresh_token": token, "dpop_jwk": dpop.public_jwk(key)}).encode()
        r = self._send("POST", url, content=body, headers={"Content-Type": "application/json",
                                                           "DPoP": dpop.make_proof(key, "POST", url, body=body)})
        if r.status_code in (400, 401, 403):
            keep = {f: self.store.get(self.base, f) for f in ("access_id", "access_secret")}
            self.store.delete(self.base)
            for f, v in keep.items():
                if v:
                    self.store.set(self.base, f, v)
            self._access = None
            raise NotLoggedIn("your Vyntryx session expired or was revoked: run `vyntryx-mcp login`")
        data = self._parse(r)
        self._access = data["access_token"]
        if data.get("refresh_token"):
            self.store.set(self.base, "refresh_token", data["refresh_token"])

    def _send(self, method, url, **kw) -> httpx.Response:
        kw["headers"] = {**access_headers(self.store, self.base), **(kw.get("headers") or {})}
        try:
            r = self._http.request(method, url, **kw)
        except httpx.HTTPError as e:
            raise ApiError(0, f"cannot reach {self.base} ({type(e).__name__})") from None
        if _gateway_blocked(r):
            raise ApiError(r.status_code, GATEWAY_HINT)
        return r

    @staticmethod
    def _parse(r: httpx.Response):
        if len(r.content) > _MAX_RESPONSE:
            raise ApiError(r.status_code, "response too large")
        if 300 <= r.status_code < 400:
            raise ApiError(r.status_code, "unexpected redirect (refusing to follow it with credentials)")
        try:
            body = r.json() if r.content else {}
        except ValueError:
            body = None
        if r.is_success:
            if body is None:
                raise ApiError(r.status_code, "server returned a non-JSON response")
            return body
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(body, dict) and body.get("error"):
            detail = f"{body['error']}: {body.get('reason', '')}".strip(": ")
        if isinstance(detail, (dict, list)):
            detail = json.dumps(detail)
        raise ApiError(r.status_code, str(detail or r.reason_phrase)[:300])

    def request(self, method: str, path: str, *, params=None, json_body=None, upload=None):
        url = self.base + path
        for attempt in (0, 1):
            if not self._access:
                self._refresh()
            headers = {"Authorization": f"Bearer {self._access}"}
            kw: dict = {"params": params or None}
            content = None
            fh = None
            if json_body is not None:
                content = json.dumps(json_body, separators=(",", ":")).encode()
                headers["Content-Type"] = "application/json"
                kw["content"] = content
            if upload:  # multipart stream: body hash (`ath`) is optional on the server and skipped here
                fh = open(upload[0], "rb")
                kw["files"], kw["data"] = {"file": (upload[1] + ".tar.gz", fh, "application/gzip")}, {"name": upload[1]}
            try:
                headers["DPoP"] = dpop.make_proof(self._key(), method, url, body=content)
                r = self._send(method, url, headers=headers, **kw)
            finally:
                if fh:
                    fh.close()
            bad_proof = r.status_code == 401 and _error_code(r) == "invalid_proof"
            if r.status_code == 401 and attempt == 0 and not bad_proof:
                self._access = None  # expired/rotated: refresh once and retry
                continue
            return self._parse(r)
