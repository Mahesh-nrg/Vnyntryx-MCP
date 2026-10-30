"""Server-side DPoP verification, copied from atom/web/dpop.py (thumbprint, ES256 raw-signature check, htm/htu/iat/ath/jti).

Copied (not imported) so this package stays independent of the platform code. If atom/web/dpop.py changes, update here.
"""
import base64
import hashlib
import json
import time

SKEW = 60


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_thumbprint(jwk):
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                           separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


def _verify_es256(jwk, signing_input, signature):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(signature) != 64:
        return False
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"),
                                        int.from_bytes(_b64d(jwk["y"]), "big"), ec.SECP256R1()).public_key()
    try:
        pub.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                   signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def verify_proof(proof, *, method, url, body, bound_jkt, seen):
    """Return None if valid, else the rejection reason (same checks and order as the platform)."""
    try:
        h_b64, p_b64, s_b64 = proof.split(".")
        header, payload, sig = json.loads(_b64d(h_b64)), json.loads(_b64d(p_b64)), _b64d(s_b64)
    except Exception:
        return "malformed DPoP proof"
    jwk = header.get("jwk") or {}
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or not jwk:
        return "malformed DPoP proof header"
    if jwk_thumbprint(jwk) != bound_jkt:
        return "DPoP proof key does not match the key bound to this token"
    if not _verify_es256(jwk, f"{h_b64}.{p_b64}".encode("ascii"), sig):
        return "DPoP proof signature invalid"
    if payload.get("htm") != method:
        return "DPoP proof method mismatch"
    if payload.get("htu") != url.split("?")[0]:
        return "DPoP proof URL mismatch"
    iat = payload.get("iat")
    if not isinstance(iat, (int, float)) or abs(time.time() - iat) > SKEW:
        return "DPoP proof timestamp outside allowed window"
    ath = payload.get("ath")
    if ath and ath != base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode():
        return "DPoP proof body hash mismatch"
    jti = payload.get("jti")
    if not jti or jti in seen:
        return "DPoP proof replay detected" if jti else "DPoP proof missing jti"
    seen.add(jti)
    return None
