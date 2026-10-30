"""DPoP-style request proofs (ES256), matching what the Vyntryx platform verifies.

Proof = JWT {typ: dpop+jwt, alg: ES256, jwk: <public key>} . {htm, htu, iat, jti[, ath]} . raw r||s signature.
`htu` is the URL without query/fragment; `ath` (optional) is base64url(SHA-256(request body bytes)).
The server binds the access token to the key's RFC 7638 thumbprint (cnf.jkt), so a stolen token alone is useless.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _b64(n.x.to_bytes(32, "big")), "y": _b64(n.y.to_bytes(32, "big"))}


def thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (same canonical form the server uses)."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                           separators=(",", ":"), sort_keys=True)
    return _b64(hashlib.sha256(canonical.encode()).digest())


def key_to_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def key_from_pem(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("stored DPoP key is not an EC key")
    return key


def make_proof(key: ec.EllipticCurvePrivateKey, method: str, url: str, *, body: bytes | None = None,
               now: float | None = None) -> str:
    payload = {"htm": method.upper(), "htu": url.split("#")[0].split("?")[0],
               "iat": int(time.time() if now is None else now), "jti": uuid.uuid4().hex}
    if body:
        payload["ath"] = _b64(hashlib.sha256(body).digest())
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(key)}
    signing_input = (_b64(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + _b64(json.dumps(payload, separators=(",", ":")).encode()))
    r, s = decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
