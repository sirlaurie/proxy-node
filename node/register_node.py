#!/usr/bin/env python3
"""Register a freshly migrated node in the central panel and publish its routes."""

from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import subprocess
import sys
import time
import urllib.parse
from contextlib import closing

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from panel_api import Panel

CENTRAL_STATE = pathlib.Path("/var/lib/proxy-stack")
PUBLISHED = pathlib.Path("/var/lib/proxy-publish/profiles")


def validate_connection(info: dict) -> None:
    expected = {"scheme", "address", "port", "basePath", "apiToken", "scope", "tlsVerifyMode"}
    if set(info) != expected:
        raise ValueError("Connection file has missing or unexpected fields")
    if info["scheme"] != "https" or info["port"] != 443:
        raise ValueError("Node sync must use HTTPS on TCP 443")
    if info["scope"] != "node-sync" or info["tlsVerifyMode"] != "verify":
        raise ValueError("Node sync token scope and TLS verification must be restricted")
    if not info["basePath"].startswith("/manage-") or not info["basePath"].endswith("/"):
        raise ValueError("Connection file has an invalid management path")
    if not info["apiToken"] or not info["address"]:
        raise ValueError("Connection file has an empty address or token")


def find_node(api: Panel, info: dict, name: str) -> int:
    nodes = api.call("panel/api/nodes/list").get("obj") or []
    matches = [node for node in nodes if node.get("address") == info["address"]]
    if len(matches) > 1:
        raise ValueError("Multiple node records use this address; resolve duplicates first")
    if matches:
        return int(matches[0]["id"])
    request = {
        key: info[key]
        for key in ("scheme", "address", "port", "basePath", "apiToken", "tlsVerifyMode")
    }
    request.update(name=name, enable=True, inboundSyncMode="all", inboundTags=[])
    return int(api.call("panel/api/nodes/add", request)["obj"]["id"])


def wait_for_inbounds(api: Panel, node_id: int) -> list[dict]:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        rows = api.call("panel/api/inbounds/list").get("obj") or []
        selected = [item for item in rows if item.get("nodeId") == node_id]
        if len(selected) >= 2:
            return selected
        time.sleep(2)
    raise RuntimeError(
        "Central panel did not import both node inbounds; inspect Nodes status and rerun"
    )


def validate_inbounds(inbounds: list[dict], address: str) -> list[int]:
    ids: list[int] = []
    for inbound in inbounds:
        settings = inbound.get("streamSettings", {})
        if isinstance(settings, str):
            settings = json.loads(settings)
        reality = settings.get("realitySettings", {})
        target = reality.get("dest") or reality.get("target") or ""
        if target.split(":", 1)[0] == address:
            raise ValueError("Imported REALITY target points back to this node; do not attach it")
        ids.append(int(inbound["id"]))
    if len(ids) != 2:
        raise ValueError("Expected at least two VLESS/REALITY and Hysteria2 inbounds")
    return ids


def set_hosts(api: Panel, inbounds: list[int], address: str, name: str) -> None:
    selected = set(inbounds)
    groups = api.call("panel/api/hosts/list").get("obj") or []
    covered: set[int] = set()
    for group in groups:
        group_ids = set(group.get("inboundIds") or [])
        overlap = group_ids & selected
        if not overlap:
            continue
        if group_ids - selected:
            raise ValueError(
                "A Hosts group spans multiple servers; split it before registering this node"
            )
        if group.get("hosts") != [f"{address}:443"]:
            group["hosts"] = [f"{address}:443"]
            api.call("panel/api/hosts/update/" + str(group["groupId"]), group)
        covered.update(overlap)
    for inbound_id in sorted(selected - covered):
        api.call(
            "panel/api/hosts/add",
            {"inboundIds": [inbound_id], "hosts": [f"{address}:443"], "remark": name},
        )


def validate_published_profiles(emails: list[str], address: str) -> None:
    with closing(
        sqlite3.connect(f"file:{CENTRAL_STATE / 'x-ui.db'}?mode=ro", uri=True)
    ) as database:
        rows = database.execute(
            "SELECT email, sub_id FROM clients WHERE email IN ("
            + ",".join("?" for _ in emails)
            + ")",
            emails,
        ).fetchall()
    sub_ids = {email: sub_id for email, sub_id in rows}
    for email in emails:
        sub_id = sub_ids.get(email)
        if not sub_id:
            raise ValueError(f"Client is missing a subscription identifier: {email}")
        path = PUBLISHED / sub_id / "nodes.yaml"
        if not path.is_file():
            raise RuntimeError(
                f"Profile was not generated for client {email}; inspect song-profiles.service"
            )
        document = yaml.safe_load(path.read_text()) or {}
        proxies = document.get("proxies") or []
        node_entries = [item for item in proxies if item.get("server") == address]
        if len(node_entries) < 2:
            raise RuntimeError(
                f"Published provider for {email} does not contain both new node entries"
            )


def register(api: Panel, info: dict, name: str, emails: list[str]) -> list[int]:
    for email in emails:
        api.call("panel/api/clients/get/" + urllib.parse.quote(email, safe=""))
    node_id = find_node(api, info, name)
    imported = wait_for_inbounds(api, node_id)
    inbound_ids = validate_inbounds(imported, info["address"])
    set_hosts(api, inbound_ids, info["address"], name)
    for email in emails:
        api.call(
            "panel/api/clients/" + urllib.parse.quote(email, safe="") + "/attach",
            {"inboundIds": inbound_ids},
        )
    subprocess.run(["systemctl", "start", "song-profiles.service"], check=True)
    validate_published_profiles(emails, info["address"])
    return inbound_ids


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "connection", type=pathlib.Path, help="node-connection.json copied over SSH"
    )
    parser.add_argument("--name", required=True)
    parser.add_argument(
        "--clients", nargs="+", required=True, help="existing central panel client names"
    )
    args = parser.parse_args()
    try:
        info = json.loads(args.connection.read_text())
        validate_connection(info)
        inbound_ids = register(Panel(), info, args.name, args.clients)
        print(
            f"Registered node {args.name}; inbounds {inbound_ids}; selected clients: {len(args.clients)}"
        )
        print("Profiles were regenerated and checked. Refresh the client subscription/provider.")
    except Exception as error:
        print(f"Node registration failed: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
