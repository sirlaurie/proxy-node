#!/usr/bin/env python3
"""Install pinned Mihomo AnyTLS sidecar; safe to rerun, rotates no existing passwords."""

import gzip
import hashlib
import json
import os
import pathlib
import pwd
import subprocess
import urllib.request

B = pathlib.Path("/root/proxy-stack")
S = pathlib.Path("/var/lib/proxy-anytls")


def run(*args):
    subprocess.run(args, check=True)


def main():
    artifact = json.loads((B / "anytls/artifact.json").read_text())
    binary = pathlib.Path("/opt/proxy-anytls/mihomo")
    if not binary.exists():
        data = urllib.request.urlopen(artifact["url"], timeout=120).read()
        if hashlib.sha256(data).hexdigest() != artifact["archive_sha256"]:
            raise ValueError("Archive checksum mismatch")
        binary.parent.mkdir(mode=0o755, exist_ok=True)
        binary.write_bytes(gzip.decompress(data))
        binary.chmod(0o755)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != artifact["binary_sha256"]:
        raise ValueError("Binary checksum mismatch")
    try:
        user = pwd.getpwnam("proxy-anytls")
    except KeyError:
        run(
            "useradd",
            "--system",
            "--home-dir",
            str(S),
            "--shell",
            "/usr/sbin/nologin",
            "proxy-anytls",
        )
        user = pwd.getpwnam("proxy-anytls")
    S.mkdir(mode=0o750, exist_ok=True)
    os.chown(S, 0, user.pw_gid)
    S.chmod(0o750)
    # Runtime cache lives separately; credentials remain root-owned.
    cache = S / "cache"
    cache.mkdir(exist_ok=True)
    os.chown(cache, user.pw_uid, user.pw_gid)
    units = {
        "proxy-anytls.service": """[Unit]
Description=AnyTLS independent proxy (Mihomo)
After=network-online.target
Wants=network-online.target
[Service]
User=proxy-anytls
Group=proxy-anytls
Environment=SAFE_PATHS=/var/lib/proxy-anytls
ExecStart=/opt/proxy-anytls/mihomo -d /var/lib/proxy-anytls/cache -f /var/lib/proxy-anytls/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/proxy-anytls/cache
[Install]
WantedBy=multi-user.target
""",
        "proxy-anytls-sync.service": """[Unit]
Description=Synchronize AnyTLS accounts and certificate from local panel
After=proxy-ui.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B /root/proxy-stack/anytls/sync.py
""",
        "proxy-anytls-sync.timer": """[Unit]
Description=Refresh AnyTLS accounts and TLS certificate
[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
[Install]
WantedBy=timers.target
""",
    }
    for name, value in units.items():
        p = pathlib.Path("/etc/systemd/system") / name
        p.write_text(value)
        p.chmod(0o644)
    run("systemctl", "daemon-reload")
    run("python3", "-B", str(B / "anytls/sync.py"))
    run("systemctl", "enable", "proxy-anytls", "proxy-anytls-sync.timer")
    run("systemctl", "start", "proxy-anytls-sync.timer")
    import argparse
    import shutil

    parser = argparse.ArgumentParser()
    parser.add_argument("--firewall", choices=["auto", "manual"], default="auto")
    a = parser.parse_args()
    if a.firewall == "auto":
        if (
            shutil.which("ufw")
            and "Status: active"
            in subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout
        ):
            run("ufw", "allow", "24443/tcp", "comment", "AnyTLS")
        elif (
            shutil.which("firewall-cmd")
            and subprocess.run(["firewall-cmd", "--state"], capture_output=True).returncode == 0
        ):
            run("firewall-cmd", "--add-port=24443/tcp")
            run("firewall-cmd", "--permanent", "--add-port=24443/tcp")
        else:
            iptables = shutil.which("iptables")
            if not iptables:
                raise RuntimeError("Open TCP 24443 manually and rerun with --firewall manual")
            helper = pathlib.Path("/usr/local/libexec/anytls-firewall")
            helper.parent.mkdir(exist_ok=True, parents=True)
            rule = "INPUT -p tcp --dport 24443 -m comment --comment anytls -j ACCEPT"
            helper.write_text(
                "#!/bin/sh\nset -eu\n"
                + iptables
                + " -w -C "
                + rule
                + " 2>/dev/null || "
                + iptables
                + " -w -I "
                + rule
                + "\n"
            )
            helper.chmod(0o755)
            u = pathlib.Path("/etc/systemd/system/anytls-firewall.service")
            u.write_text(
                "[Unit]\nDescription=AnyTLS firewall rule\nAfter=network-pre.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/libexec/anytls-firewall\n[Install]\nWantedBy=multi-user.target\n"
            )
            u.chmod(0o644)
            run("systemctl", "daemon-reload")
            run("systemctl", "enable", "--now", "anytls-firewall")
    print("AnyTLS installed on TCP 24443. Provider firewall must also allow this port.")


if __name__ == "__main__":
    main()
