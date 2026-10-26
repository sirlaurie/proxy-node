#!/usr/bin/env python3
import argparse
import json
import pathlib
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument("--stage", action="store_true")
p.add_argument("--client-bin", default="/opt/proxy-stack/bin/xray-linux-amd64")
args = p.parse_args()
b = pathlib.Path("/root/proxy-stack")
n = json.loads((b / "public-node.json").read_text())
devices = json.loads((b / "devices.json").read_text())
if not devices:
    raise RuntimeError("No enabled panel clients are available for the local proxy check")
d = next(iter(devices.values()))
outs = [
    {
        "protocol": "vless",
        "tag": "reality",
        "settings": {
            "vnext": [
                {
                    "address": "127.0.0.1",
                    "port": 19443 if args.stage else 443,
                    "users": [{"id": d["id"], "flow": "xtls-rprx-vision", "encryption": "none"}],
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": n["sni"],
                "fingerprint": "chrome",
                "publicKey": n["publicKey"],
                "shortId": n["shortId"],
                "spiderX": "/",
            },
        },
    },
    {
        "protocol": "hysteria",
        "tag": "hy2",
        "settings": {"version": 2, "address": "127.0.0.1", "port": 443},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {"serverName": n["domain"], "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "auth": d["auth"]},
        },
    },
]
cfg = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "protocol": "socks",
            "tag": tag,
            "listen": "127.0.0.1",
            "port": port,
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
        }
        for tag, port in [("test-r", 11080), ("test-h", 11081)]
    ],
    "outbounds": outs,
    "routing": {
        "rules": [
            {"type": "field", "inboundTag": ["test-r"], "outboundTag": "reality"},
            {"type": "field", "inboundTag": ["test-h"], "outboundTag": "hy2"},
        ]
    },
}


def exact(s, n):
    out = b""
    while len(out) < n:
        block = s.recv(n - len(out))
        if not block:
            raise RuntimeError("closed SOCKS control channel")
        out += block
    return out


def udp_dns(port):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(b"\x05\x01\x00")
        assert exact(s, 2) == b"\x05\x00"
        s.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        head = exact(s, 4)
        assert head[1] == 0
        addr = socket.inet_ntop(
            socket.AF_INET if head[3] == 1 else socket.AF_INET6, exact(s, 4 if head[3] == 1 else 16)
        )
        relay = struct.unpack("!H", exact(s, 2))[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.settimeout(15)
            q = (
                struct.pack("!HHHHHH", 0x4142, 0x0100, 1, 0, 0, 0)
                + b"\x07example\x03com\x00"
                + struct.pack("!HH", 1, 1)
            )
            u.sendto(
                b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53) + q,
                (addr, relay),
            )
            response = u.recv(4096)
            assert response[10:12] == b"AB" and response[13] & 15 == 0, "DNS reply mismatch"


with tempfile.TemporaryDirectory(prefix="song-test-") as td:
    f = pathlib.Path(td) / "config.json"
    f.write_text(json.dumps(cfg))
    f.chmod(0o600)
    with open(pathlib.Path(td) / "log", "w+") as log:
        proc = subprocess.Popen([args.client_bin, "run", "-c", str(f)], stdout=log, stderr=log)
        try:
            time.sleep(1)
            assert proc.poll() is None, "client failed to start"
            for tag, port in [("REALITY", 11080), ("Hysteria2", 11081)]:
                for url in ["https://www.gstatic.com/generate_204", "https://api.ipify.org"]:
                    r = subprocess.run(
                        [
                            "curl",
                            "--silent",
                            "--show-error",
                            "--fail",
                            "--max-time",
                            "20",
                            "--socks5-hostname",
                            "127.0.0.1:" + str(port),
                            url,
                        ],
                        capture_output=True,
                        text=True,
                    )
                    if r.returncode:
                        log.flush()
                        log.seek(0)
                        print(log.read())
                        raise RuntimeError(tag + ": " + r.stderr)
                    print(tag, url, "OK", r.stdout[:60])
                udp_dns(port)
                print(tag, "UDP DNS OK")
                blocked = subprocess.run(
                    [
                        "curl",
                        "--silent",
                        "--max-time",
                        "5",
                        "--socks5-hostname",
                        "127.0.0.1:" + str(port),
                        "http://127.0.0.1:"
                        + str(
                            sqlite3.connect("file:/var/lib/proxy-stack/x-ui.db?mode=ro", uri=True)
                            .execute("SELECT value FROM settings WHERE key='webPort'")
                            .fetchone()[0]
                        )
                        + "/",
                    ],
                    capture_output=True,
                )
                assert blocked.returncode != 0, "Server private-address restriction failed"
                print(tag, "server private-address access blocked")
        finally:
            proc.terminate()
            proc.wait(timeout=10)
