"""vyntryx-mcp command line: serve (default), login, logout, status, preview."""
from __future__ import annotations

import argparse
import sys

from .client import LoginError, NotLoggedIn, check_base_url, device_login, resolve_base
from .pack import PackError, plan_tree
from .store import Store


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vyntryx-mcp", description="Vyntryx MCP connector (stdio). No subcommand = serve.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the MCP server on stdio (what your IDE launches)")
    lg = sub.add_parser("login", help="sign in via the browser (device code)")
    lg.add_argument("--url", help="Vyntryx server, e.g. https://vyntryx.example.com (or set VYNTRYX_URL)")
    sub.add_parser("logout", help="forget the stored credentials")
    sub.add_parser("status", help="show whether credentials are stored")
    pv = sub.add_parser("preview", help="show what a source upload would include, without uploading")
    pv.add_argument("path")
    pv.add_argument("--include-git", action="store_true", help="include git history (.git, minus .git/config)")
    args = ap.parse_args(argv)
    store = Store()
    try:
        if args.cmd in (None, "serve"):
            from .server import run
            run()
        elif args.cmd == "login":
            device_login(check_base_url(args.url) if args.url else resolve_base(None, store), store, print)
            print("Logged in. Restart your IDE's MCP server if it was already running.")
        elif args.cmd == "logout":
            store.delete(resolve_base(None, store))
            print("Logged out.")
        elif args.cmd == "status":
            base = resolve_base(None, store)
            if not store.get(base, "refresh_token"):
                print(f"not logged in to {base}")
                return 1
            print(f"logged in to {base} (credentials stored; the session is checked on first use)")
        elif args.cmd == "preview":
            files, prev = plan_tree(args.path, include_git=args.include_git)
            for rel, size, _ in files[:50]:
                print(f"  {rel}  ({size} bytes)")
            if len(files) > 50:
                print(f"  ... and {len(files) - 50} more")
            print(prev.summary())
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except NotLoggedIn as e:
        print(f"not logged in: {e}", file=sys.stderr if args.cmd != "status" else sys.stdout)
        return 1
    except (LoginError, PackError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0
