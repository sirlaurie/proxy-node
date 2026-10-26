"""Validation and operating-system helpers for a source-directory node migration."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import socket
import sqlite3
import subprocess
import urllib.request
from contextlib import closing

SEED_FORMAT = 1


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def load_state(path: pathlib.Path, identity: dict[str, str], resume: bool) -> dict:
    if path.exists():
        state = json.loads(path.read_text())
        if state.get("identity") != identity:
            raise ValueError(
                "Existing migration uses a different seed, domain, IP, or firewall mode"
            )
        if not resume:
            raise ValueError("An earlier migration exists; use --resume with the same arguments")
        return state
    if resume:
        raise ValueError(
            "No migration state exists; --resume cannot adopt an existing installation"
        )
    return {}


def save_state(path: pathlib.Path, state: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    write_json(path, state)


def make_manifest(root: pathlib.Path) -> dict[str, object]:
    files: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        if path.name == "manifest.json":
            continue
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError(
                f"Seed contains unsupported filesystem entry: {path.relative_to(root)}"
            )
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            files[relative] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    return {"formatVersion": SEED_FORMAT, "files": files}


def verify_seed(root: pathlib.Path) -> str:
    root = root.resolve(strict=True)
    manifest_path = root / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("formatVersion") != SEED_FORMAT or not isinstance(manifest.get("files"), dict):
        raise ValueError("Unsupported seed manifest; export a new directory seed")

    expected = manifest["files"]
    actual_paths: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"Seed symlinks are not allowed: {relative}")
        if path.is_file() and relative != "manifest.json":
            actual_paths.add(relative)
    if actual_paths != set(expected):
        raise ValueError("Seed file list differs from its manifest")

    for relative, record in expected.items():
        safe_relative = pathlib.PurePosixPath(relative)
        if (
            not isinstance(relative, str)
            or safe_relative.is_absolute()
            or ".." in safe_relative.parts
            or safe_relative.as_posix() != relative
            or not isinstance(record, dict)
        ):
            raise ValueError(f"Unsafe seed path: {relative}")
        path = root / safe_relative
        if not path.is_file() or path.stat().st_size != record.get("size"):
            raise ValueError(f"Seed file missing or size mismatch: {relative}")
        if sha256_file(path) != record.get("sha256"):
            raise ValueError(f"Seed checksum mismatch: {relative}")

    required = {
        "metadata.json",
        "snapshot/x-ui.db",
        "app/x-ui",
        "app/bin/xray-linux-amd64",
        "nginx-http.conf",
        "renew-hook",
    }
    if missing := required - actual_paths:
        raise ValueError("Seed missing required files: " + ", ".join(sorted(missing)))
    metadata = json.loads((root / "metadata.json").read_text())
    if metadata.get("formatVersion") != SEED_FORMAT or metadata.get("architecture") != "x86_64":
        raise ValueError("Seed must be format 1 for x86_64")
    with closing(
        sqlite3.connect(f"file:{root / 'snapshot/x-ui.db'}?mode=ro", uri=True)
    ) as database:
        if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Seed panel database failed integrity check")
    return hashlib.sha256(manifest_bytes).hexdigest()


def validate_domain(domain: str) -> None:
    import re

    labels = domain.rstrip(".").split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
    ):
        raise ValueError("Domain must be a lowercase fully-qualified DNS name")


def check_dns(domain: str, expected_ip: str) -> None:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(domain, 80, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    }
    if addresses != {expected_ip}:
        current = ", ".join(sorted(addresses)) or "no records"
        raise ValueError(
            f"DNS for {domain} must resolve only to {expected_ip}; got {current}. "
            "Correct the A record and remove stale AAAA records or proxy/CDN records."
        )


def check_ports() -> None:
    for kind, ports in (
        (socket.SOCK_STREAM, (80, 443, 8444, 18443, 18796)),
        (socket.SOCK_DGRAM, (443,)),
    ):
        for port in ports:
            with socket.socket(socket.AF_INET, kind) as sock:
                try:
                    sock.bind(("0.0.0.0", port))
                except OSError as error:
                    raise ValueError(
                        f"Required port {port}/{kind_name(kind)} is already occupied"
                    ) from error


def kind_name(kind: int) -> str:
    return "tcp" if kind == socket.SOCK_STREAM else "udp"


def normalize_app(root: pathlib.Path) -> None:
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"Unexpected application symlink: {path}")
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    (root / "x-ui").chmod(0o755)
    (root / "bin/xray-linux-amd64").chmod(0o755)


def prune_remote(database: sqlite3.Connection) -> None:
    tables = {
        row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    database.execute("DELETE FROM inbounds WHERE COALESCE(node_id, 0) != 0")
    for table in ("client_inbounds", "hosts", "inbound_fallbacks"):
        if table not in tables:
            continue
        columns = {row[1] for row in database.execute(f"PRAGMA table_info({table})")}
        if "inbound_id" in columns:
            database.execute(
                f"DELETE FROM {table} WHERE inbound_id NOT IN (SELECT id FROM inbounds)"
            )
    for table in (
        "nodes",
        "client_external_links",
        "client_hwids",
        "inbound_client_ips",
        "client_traffics",
        "node_client_traffics",
        "node_client_ips",
        "client_global_traffics",
        "outbound_traffics",
        "api_tokens",
    ):
        if table in tables:
            database.execute(f"DELETE FROM {table}")
    protocols = sorted(row[0] for row in database.execute("SELECT protocol FROM inbounds"))
    if protocols != ["hysteria", "vless"]:
        raise ValueError(
            "Seed must contain exactly one local VLESS REALITY and one local Hysteria2 inbound"
        )


def adapt_stream(stream: dict, old_domain: str, new_domain: str, sni: str) -> dict:
    updated = json.loads(json.dumps(stream).replace(old_domain, new_domain))
    reality = updated.get("realitySettings")
    if reality:
        reality["dest"] = f"{sni}:443"
        if "target" in reality:
            reality["target"] = f"{sni}:443"
        reality["serverNames"] = [sni]
        reality.setdefault("settings", {})["serverName"] = sni
        updated["externalProxy"] = [{"dest": new_domain, "port": 443}]
        updated.setdefault("sockopt", {})["acceptProxyProtocol"] = True
    return updated


def check_acme(root: pathlib.Path, domain: str) -> None:
    challenge = root / ".well-known/acme-challenge/migration-check"
    challenge.parent.mkdir(parents=True, exist_ok=True)
    challenge.write_text("proxy-migration-ok")
    challenge.chmod(0o644)
    challenge.parent.parent.chmod(0o755)
    challenge.parent.chmod(0o755)
    request = urllib.request.Request(
        "http://127.0.0.1/.well-known/acme-challenge/migration-check", headers={"Host": domain}
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        if response.read() != b"proxy-migration-ok":
            raise ValueError("Local ACME webroot check failed")
    print("Local ACME webroot check passed; public access on TCP 80 is still required.")


def write_access(root: pathlib.Path, domain: str, admin: dict) -> None:
    path = root / "ACCESS.md"
    path.write_text(
        f"# 新节点访问入口\n\n面板：https://{domain}{admin['path']}\n\n"
        "登录账号和密码：`/root/proxy-stack/admin.json`。\n"
        "新节点身份：`/root/proxy-stack/public-node.json`。\n"
        "中心面板 Nodes 所需令牌：`/root/proxy-stack/node-connection.json`。\n"
        "这些文件是目标机新生成的身份，不要使用上传种子中的任何旧身份。\n\n"
        "中心面板添加 Node 后，将节点入站关联到所需客户端并重新生成订阅。\n"
    )
    path.chmod(0o600)


def open_firewall(run) -> None:
    """Open only required proxy ports; preserve all unrelated rules and SSH access."""
    if shutil.which("ufw"):
        status = subprocess.run(
            ["ufw", "status"], capture_output=True, text=True, check=False
        ).stdout
        if "Status: active" in status:
            for port in ("80/tcp", "443/tcp", "443/udp"):
                run("ufw", "allow", port)
            return
    if (
        shutil.which("firewall-cmd")
        and subprocess.run(["firewall-cmd", "--state"], capture_output=True, check=False).returncode
        == 0
    ):
        for port in ("80/tcp", "443/tcp", "443/udp"):
            run("firewall-cmd", "--add-port=" + port)
            run("firewall-cmd", "--permanent", "--add-port=" + port)
        return
    iptables = shutil.which("iptables")
    if not iptables:
        raise ValueError("Install iptables, or open ports manually and pass --firewall manual")
    helper = pathlib.Path("/usr/local/libexec/proxy-firewall")
    helper.parent.mkdir(parents=True, exist_ok=True)
    commands = ["#!/bin/sh", "set -eu"]
    for protocol, port in (("tcp", 80), ("tcp", 443), ("udp", 443)):
        rule = f"INPUT -p {protocol} --dport {port} -m comment --comment proxy-migration -j ACCEPT"
        commands.append(f"{iptables} -w -C {rule} 2>/dev/null || {iptables} -w -I {rule}")
    helper.write_text("\n".join(commands) + "\n")
    helper.chmod(0o755)
    unit = pathlib.Path("/etc/systemd/system/proxy-firewall.service")
    unit.write_text(
        "[Unit]\nDescription=Proxy inbound firewall rules\nAfter=network-pre.target\n"
        "Before=song-ingress.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        "ExecStart=/usr/local/libexec/proxy-firewall\n[Install]\nWantedBy=multi-user.target\n"
    )
    unit.chmod(0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "proxy-firewall.service")
    run("systemctl", "restart", "proxy-firewall.service")


def verify_public(root: pathlib.Path, domain: str) -> None:
    import urllib.parse

    admin = json.loads((root / "admin.json").read_text())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"https://{domain}{admin['path']}", timeout=20) as response:
        if response.status != 200:
            raise ValueError("Panel HTTPS health check failed")
    devices = json.loads((root / "devices.json").read_text())
    for name, device in devices.items():
        url = f"https://{domain}/profiles/{device['subId']}/happ.txt"
        with opener.open(url, timeout=20) as response:
            links = response.read().decode().splitlines()
        nodes = [item for item in links if item.startswith(("vless://", "hysteria2://", "hy2://"))]
        if len(nodes) != 2 or any(urllib.parse.urlsplit(item).hostname != domain for item in nodes):
            raise ValueError(f"Published subscription has missing or stale nodes for {name}")
