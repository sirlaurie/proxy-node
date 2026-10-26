"""Optional AnyTLS profiles. Native Xray/dae/Happ remain on verified protocols."""

import json
import pathlib

STATE = pathlib.Path("/var/lib/proxy-anytls/published.json")


def extra_node(sub):
    if not STATE.exists():
        return None
    d = json.loads(STATE.read_text())
    password = d.get("users", {}).get(sub)
    if not password:
        return None
    return {
        "name": d["name"],
        "type": "anytls",
        "server": d["domain"],
        "port": d["port"],
        "password": password,
        "sni": d["domain"],
        "client-fingerprint": "chrome",
        "skip-cert-verify": False,
        "udp": True,
    }
