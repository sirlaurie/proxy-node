#!/usr/bin/env python3
"""Loopback-only profile delivery with per-account subscription response headers."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path("/var/lib/proxy-publish")
PATH = re.compile(
    r"/profiles/([A-Za-z0-9_-]+)/(stash\.yaml|stash-bootstrap\.yaml|mihomo\.yaml|nodes\.yaml|happ\.txt)"
)
# User-approved Stash 3.6 compatibility placeholders; never enforced account limits.
STASH_DISPLAY_TOTAL = 100 * 1024**4
STASH_DISPLAY_EXPIRY = 4070908800  # 2099-01-01 00:00:00 UTC


def subscription_header(info, stash=False):
    keys = ("upload", "download", "total", "expire")
    if any(type(info[k]) is not int or info[k] < 0 for k in keys):
        raise ValueError("Invalid accounting")
    display = dict(info)
    if stash:
        if display["total"] == 0:
            display["total"] = STASH_DISPLAY_TOTAL
        if display["expire"] == 0:
            display["expire"] = STASH_DISPLAY_EXPIRY
    return "; ".join(k + "=" + str(display[k]) for k in keys)


class Handler(BaseHTTPRequestHandler):
    server_version = "Song"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass  # Subscription tokens must not enter access logs.

    def do_HEAD(self):
        self.deliver(False)

    def do_GET(self):
        self.deliver(True)

    def deliver(self, body):
        match = PATH.fullmatch(urlsplit(self.path).path)
        if not match:
            self.send_error(404)
            return
        sub, name = match.groups()
        try:
            data = (ROOT / "profiles" / sub / name).read_bytes()
            info = json.loads((ROOT / ".metadata" / (sub + ".json")).read_text())
            stash = name in ("stash.yaml", "stash-bootstrap.yaml") or (
                name == "nodes.yaml" and "stash" in self.headers.get("User-Agent", "").lower()
            )
            header = subscription_header(info, stash)
        except FileNotFoundError:
            self.send_error(404)
            return
        except (OSError, ValueError, KeyError):
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header(
            "Content-Type",
            ("text/plain" if name == "happ.txt" else "application/yaml") + "; charset=utf-8",
        )
        if name == "happ.txt":
            routing = data.decode().splitlines()[0]
            if routing.startswith("happ://routing/onadd/"):
                self.send_header("routing", routing)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if name == "nodes.yaml":
            self.send_header("Vary", "User-Agent")
        self.send_header("Subscription-Userinfo", header)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if body:
            self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18796), Handler).serve_forever()
