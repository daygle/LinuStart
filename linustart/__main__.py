"""Command line entry point: `linustart` or `python -m linustart`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from .app import create_app
from .settings import load_settings
from .updater import running_version


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linustart",
        description="Self-hosted web panel for Debian and Ubuntu server administration.",
    )
    parser.add_argument("--host", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, help="bind port (default: 8765)")
    parser.add_argument("--config", type=Path, help="path to config.json")
    parser.add_argument("--token", help="authentication token (overrides the config file)")
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="disable token authentication (only use on localhost or behind a proxy)",
    )
    # Reports what is really running - '1.0.0-3-g0cdaeb8' on a main checkout,
    # not just the version declared in the source.
    parser.add_argument("--version", action="version", version=f"linustart {running_version()}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    settings = load_settings(
        config_path=args.config,
        host=args.host,
        port=args.port,
        token=args.token,
        no_auth=args.no_auth,
    )
    loopback = settings.host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not settings.auth_enabled:
        # --no-auth is the documented override (e.g. behind an authenticating
        # proxy); without it a tokenless public bind is refused.
        if not args.no_auth:
            print(
                "refusing to bind to a non-loopback address without authentication;\n"
                "set auth_token in the config file, pass --token, or use --no-auth to override.",
                file=sys.stderr,
            )
            return 2
        print(
            f"warning: authentication is disabled and the panel listens on {settings.host}; "
            "anyone who can reach it gets root.",
            file=sys.stderr,
        )

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "warning: not running as root - privileged actions (hostname, timezone, "
            "networking, apt) will fail until it runs as root.",
            file=sys.stderr,
        )

    import uvicorn

    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
