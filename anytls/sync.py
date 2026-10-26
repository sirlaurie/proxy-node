#!/usr/bin/env python3
"""Synchronize unlimited local panel accounts; restart only when identity/TLS changes."""

import fcntl
import hashlib
import hmac
import json
import os
import pathlib
import pwd
import secrets
import socket
import sqlite3
import ssl
import subprocess
import time

import yaml

B = pathlib.Path("/root/proxy-stack")
S = pathlib.Path("/var/lib/proxy-anytls")


def eligible(c):
    # No quota accounting bridge: do not offer unmetered bypass for limited/activation accounts.
    return list(
        c.execute("""SELECT DISTINCT c.email,c.sub_id,c.uuid FROM clients c
 JOIN client_inbounds ci ON ci.client_id=c.id JOIN inbounds i ON i.id=ci.inbound_id
 WHERE c.enable=1 AND c.total_gb=0 AND c.expiry_time=0 AND i.enable=1
 AND COALESCE(i.node_id,0)=0 AND c.sub_id IS NOT NULL""")
    )


def build(domain, rows, key):
    users = {
        sub: hmac.new(key, (sub + "\0" + uuid).encode(), hashlib.sha256).hexdigest()
        for email, sub, uuid in rows
    }
    cfg = {
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "external-controller": "",
        "listeners": [
            {
                "name": "anytls",
                "type": "anytls",
                "listen": "0.0.0.0",
                "port": 24443,
                "users": (
                    {email: users[sub] for email, sub, uuid in rows}
                    or {"disabled": hmac.new(key, b"no-active-users", hashlib.sha256).hexdigest()}
                ),
                "certificate": str(S / "fullchain.pem"),
                "private-key": str(S / "privkey.pem"),
            }
        ],
        "rules": [
            "IP-CIDR," + cidr + ",REJECT"
            for cidr in [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "224.0.0.0/3",
            ]
        ]
        + ["IP-CIDR6,::/0,REJECT", "MATCH,DIRECT"],
    }
    return cfg, {
        "domain": domain,
        "port": 24443,
        "name": domain.split(".")[0].capitalize() + "-AnyTLS",
        "users": users,
    }


def main():
    os.umask(0o077)
    with (S / "sync.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        domain = json.loads((B / "public-node.json").read_text())["domain"]
        keypath = S / "secret"
        if not keypath.exists():
            keypath.write_bytes(secrets.token_bytes(32))
            keypath.chmod(0o600)
        c = sqlite3.connect("file:/var/lib/proxy-stack/x-ui.db?mode=ro", uri=True)
        cfg, published = build(domain, eligible(c), keypath.read_bytes())
        c.close()
        gid = pwd.getpwnam("proxy-anytls").pw_gid
        changed = False

        def put(name, data, mode=0o640):
            nonlocal changed
            p = S / name
            if p.exists() and p.read_bytes() == data:
                return
            tmp = S / (name + ".tmp")
            tmp.write_bytes(data)
            os.chown(tmp, 0, gid)
            tmp.chmod(mode)
            tmp.replace(p)
            changed = True

        for name in ["fullchain.pem", "privkey.pem"]:
            put(name, (pathlib.Path("/etc/letsencrypt/live") / domain / name).read_bytes())
        text = yaml.safe_dump(cfg, sort_keys=False).encode()
        candidate = S / "candidate.yaml"
        candidate.write_bytes(text)
        os.chown(candidate, 0, gid)
        candidate.chmod(0o640)
        subprocess.run(
            ["/opt/proxy-anytls/mihomo", "-t", "-d", str(S), "-f", str(candidate)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        put("config.yaml", text)
        active = (
            subprocess.run(
                ["systemctl", "is-active", "--quiet", "proxy-anytls"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
        if changed or not active:
            subprocess.run(["systemctl", "restart", "proxy-anytls"], check=True)
        subprocess.run(["systemctl", "is-active", "--quiet", "proxy-anytls"], check=True)
        for attempt in range(20):
            try:
                with (
                    socket.create_connection(("127.0.0.1", 24443), timeout=2) as sock,
                    ssl.create_default_context().wrap_socket(sock, server_hostname=domain),
                ):
                    pass
                break
            except OSError:
                if attempt == 19:
                    raise
                time.sleep(0.2)
        put("published.json", json.dumps(published).encode(), 0o600)
        candidate.unlink(missing_ok=True)
        print(
            "AnyTLS synchronized:",
            len(published["users"]),
            "unlimited local accounts; config changed:",
            changed,
        )


if __name__ == "__main__":
    main()
