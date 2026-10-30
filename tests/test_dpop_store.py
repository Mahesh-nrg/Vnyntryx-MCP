import base64
import hashlib
import json
import os
import stat

import keyring
import pytest
from keyring.backend import KeyringBackend

from dpop_verify import jwk_thumbprint, verify_proof
from vyntryx_mcp import dpop
from vyntryx_mcp.store import Store


def _proof(key, method="POST", url="https://x.example/api/a?q=1", body=None):
    return dpop.make_proof(key, method, url, body=body)


def test_proof_verifies_with_platform_maths():
    key = dpop.new_key()
    jkt = dpop.thumbprint(dpop.public_jwk(key))
    assert jkt == jwk_thumbprint(dpop.public_jwk(key))
    body = b'{"a": 1}'
    p = _proof(key, body=body)
    assert verify_proof(p, method="POST", url="https://x.example/api/a", body=body, bound_jkt=jkt, seen=set()) is None


def test_proof_binds_method_url_body_key_and_is_single_use():
    key, other = dpop.new_key(), dpop.new_key()
    jkt, seen, body = dpop.thumbprint(dpop.public_jwk(key)), set(), b"{}"
    p = _proof(key, body=body)
    base = dict(method="POST", url="https://x.example/api/a", body=body, bound_jkt=jkt)
    assert verify_proof(p, **{**base, "method": "GET"}, seen=set()) == "DPoP proof method mismatch"
    assert verify_proof(p, **{**base, "url": "https://x.example/api/b"}, seen=set()) == "DPoP proof URL mismatch"
    assert verify_proof(p, **{**base, "body": b"{ }"}, seen=set()) == "DPoP proof body hash mismatch"
    assert "does not match" in verify_proof(_proof(other, body=body), **base, seen=set())
    assert verify_proof(p, **base, seen=seen) is None
    assert verify_proof(p, **base, seen=seen) == "DPoP proof replay detected"


def test_stale_proof_rejected_and_query_stripped_from_htu():
    key = dpop.new_key()
    jkt = dpop.thumbprint(dpop.public_jwk(key))
    old = dpop.make_proof(key, "GET", "https://x.example/p?token=secret#frag", now=1000.0)
    assert verify_proof(old, method="GET", url="https://x.example/p", body=b"", bound_jkt=jkt, seen=set()) \
        == "DPoP proof timestamp outside allowed window"
    payload = json.loads(base64.urlsafe_b64decode(old.split(".")[1] + "=="))
    assert payload["htu"] == "https://x.example/p" and "ath" not in payload


def test_key_pem_roundtrip():
    key = dpop.new_key()
    again = dpop.key_from_pem(dpop.key_to_pem(key))
    assert dpop.public_jwk(again) == dpop.public_jwk(key)


def test_store_file_fallback_is_0600_in_0700_dir(tmp_path):
    s = Store(home=tmp_path / "h", use_keyring=False)
    s.set("https://v.example", "refresh_token", "r-secret")
    assert s.get("https://v.example", "refresh_token") == "r-secret"
    f = tmp_path / "h" / "credentials.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    s.delete("https://v.example")
    assert s.get("https://v.example", "refresh_token") is None


class MemKeyring(KeyringBackend):
    priority = 5

    def __init__(self):
        self.d = {}

    def get_password(self, service, username):
        return self.d.get((service, username))

    def set_password(self, service, username, password):
        self.d[(service, username)] = password

    def delete_password(self, service, username):
        self.d.pop((service, username), None)


def test_store_prefers_os_keyring_and_writes_no_file(tmp_path):
    old, mem = keyring.get_keyring(), MemKeyring()
    keyring.set_keyring(mem)
    try:
        s = Store(home=tmp_path / "h", use_keyring=True)
        s.set("https://v.example", "dpop_key", "PEM")
        assert s.get("https://v.example", "dpop_key") == "PEM" and len(mem.d) == 1
        assert not (tmp_path / "h" / "credentials.json").exists()
        s.delete("https://v.example")
        assert not mem.d
    finally:
        keyring.set_keyring(old)


def test_store_falls_back_to_file_when_keyring_broken(tmp_path):
    class Broken(MemKeyring):
        def set_password(self, *a):
            raise keyring.errors.KeyringError("locked")

        def get_password(self, *a):
            raise keyring.errors.KeyringError("locked")

    old = keyring.get_keyring()
    keyring.set_keyring(Broken())
    try:
        s = Store(home=tmp_path / "h", use_keyring=True)
        s.set("https://v.example", "refresh_token", "r")
        assert s.get("https://v.example", "refresh_token") == "r"
        assert (tmp_path / "h" / "credentials.json").exists()
    finally:
        keyring.set_keyring(old)
