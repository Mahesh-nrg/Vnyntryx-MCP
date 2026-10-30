"""Credential storage: OS keyring first, a 0600 file (in a 0700 directory) when no usable keyring exists.

Per server (base URL) we keep two secrets: `refresh_token` and `dpop_key` (PEM). Access tokens live in memory only.
Never log values from here.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

SERVICE = "vyntryx-mcp"


class Store:
    def __init__(self, home: Path | str | None = None, use_keyring: bool | None = None):
        self.home = Path(home or os.environ.get("VYNTRYX_MCP_HOME") or Path.home() / ".config" / "vyntryx-mcp")
        self.use_keyring = (not os.environ.get("VYNTRYX_MCP_NO_KEYRING")) if use_keyring is None else use_keyring

    # -- plain config (not secret): which server we last logged in to ---------------------------------------------
    def base_url(self) -> str | None:
        return self._read_json("config.json").get("base_url")

    def set_base_url(self, url: str) -> None:
        self._write_json("config.json", {"base_url": url})

    # -- secrets ----------------------------------------------------------------------------------------------------
    def get(self, base: str, field: str) -> str | None:
        return self._load(base).get(field)

    def set(self, base: str, field: str, value: str) -> None:
        blob = self._load(base)
        blob[field] = value
        self._save(base, blob)

    def delete(self, base: str) -> None:
        if self.use_keyring:
            try:
                import keyring
                keyring.delete_password(SERVICE, base)
            except Exception:  # missing entry or no keyring: nothing to remove
                pass
        files = self._read_json("credentials.json")
        if files.pop(base, None) is not None:
            self._write_json("credentials.json", files)

    # -- internals --------------------------------------------------------------------------------------------------
    def _load(self, base: str) -> dict:
        if self.use_keyring:
            try:
                import keyring
                raw = keyring.get_password(SERVICE, base)
                if raw:
                    return json.loads(raw)
            except Exception:
                pass  # locked/absent keyring: fall through to the file
        return self._read_json("credentials.json").get(base, {})

    def _save(self, base: str, blob: dict) -> None:
        if self.use_keyring:
            try:
                import keyring
                keyring.set_password(SERVICE, base, json.dumps(blob))
                return
            except Exception:
                pass
        files = self._read_json("credentials.json")
        files[base] = blob
        self._write_json("credentials.json", files)

    def _read_json(self, name: str) -> dict:
        try:
            return json.loads((self.home / name).read_text())
        except (OSError, ValueError):
            return {}

    def _write_json(self, name: str, data: dict) -> None:
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.home, 0o700)
        fd, tmp = tempfile.mkstemp(dir=self.home, prefix=name + ".")  # mkstemp creates 0600
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.home / name)
        except BaseException:
            os.unlink(tmp)
            raise
