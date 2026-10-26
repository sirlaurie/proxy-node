"""Small authenticated client for the local 3x-ui API."""

from __future__ import annotations

import http.cookiejar
import json
import pathlib
import sqlite3
import urllib.parse
import urllib.request
from contextlib import closing


class Panel:
    def __init__(
        self,
        stack_root: pathlib.Path = pathlib.Path("/root/proxy-stack"),
        state_root: pathlib.Path = pathlib.Path("/var/lib/proxy-stack"),
    ) -> None:
        self.settings = json.loads((stack_root / "admin.json").read_text())
        node = json.loads((stack_root / "public-node.json").read_text())
        with closing(
            sqlite3.connect(f"file:{state_root / 'x-ui.db'}?mode=ro", uri=True)
        ) as database:
            port = database.execute("SELECT value FROM settings WHERE key='webPort'").fetchone()[0]
        self.base = f"http://127.0.0.1:{port}{self.settings['path']}"
        self.host = node["domain"]
        self.http = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self.csrf = self.call("csrf-token").get("obj", "")
        self.call(
            "login",
            {"username": self.settings["username"], "password": self.settings["password"]},
            form=True,
        )
        self.csrf = self.call("csrf-token").get("obj", "")

    def call(
        self,
        path: str,
        data: dict | None = None,
        *,
        form: bool = False,
        timeout: float = 20,
    ) -> dict:
        headers = {"Host": self.host, "X-CSRF-Token": self.csrf}
        body = None
        if data is not None:
            headers["Content-Type"] = (
                "application/x-www-form-urlencoded" if form else "application/json"
            )
            body = (
                urllib.parse.urlencode(data).encode()
                if form
                else json.dumps(data, separators=(",", ":")).encode()
            )
        request = urllib.request.Request(self.base + path, data=body, headers=headers)
        with self.http.open(request, timeout=timeout) as response:
            result = json.load(response)
        if result.get("success") is False:
            raise RuntimeError(f"3x-ui API {path} failed: {result.get('msg', 'API error')}")
        return result
