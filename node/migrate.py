#!/usr/bin/env python3
"""Install a fresh x86_64 node from a verified directory seed; supports safe resume."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import pwd
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from contextlib import closing

from migration_lib import (
    adapt_stream,
    check_acme,
    check_dns,
    check_ports,
    load_state,
    normalize_app,
    open_firewall,
    prune_remote,
    save_state,
    validate_domain,
    verify_public,
    verify_seed,
    write_access,
    write_json,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
APP = pathlib.Path("/opt/proxy-stack")
STATE = pathlib.Path("/var/lib/proxy-stack")
MIGRATION_STATE = pathlib.Path("/var/lib/proxy-migration/state.json")
NGINX_ROOT = pathlib.Path("/etc/proxy-stack")


def run(*command: str, env: dict[str, str] | None = None, capture: bool = False):
    options: dict[str, object] = {"check": True, "text": True}
    if env is not None:
        options["env"] = env
    if capture:
        options["capture_output"] = True
    return subprocess.run(command, **options)


def version_tuple(text: str) -> tuple[int, int, int]:
    match = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        raise ValueError("Could not read Nginx version")
    return tuple(map(int, match.groups()))


def check_prerequisites() -> None:
    if sys.version_info < (3, 12):
        raise RuntimeError("Python 3.12 or newer is required")
    if os.geteuid() != 0:
        raise PermissionError("Run as root")
    if os.uname().machine != "x86_64":
        raise RuntimeError("This seed contains x86_64 binaries; ARM nodes are not supported")
    if pathlib.Path("/root/proxy-stack") != REPO:
        raise RuntimeError("Clone this repository to /root/proxy-stack on the target server")
    for command in ("nginx", "certbot", "systemctl", "useradd", "install", "curl", "runuser"):
        if not shutil.which(command):
            raise RuntimeError(f"Install required command: {command}")
    result = subprocess.run(["nginx", "-v"], capture_output=True, text=True, check=True)
    if version_tuple(result.stderr) < (1, 25, 1):
        raise RuntimeError("Nginx 1.25.1 or newer is required")
    module_dirs = ("/usr/lib/nginx/modules", "/usr/lib64/nginx/modules", "/usr/share/nginx/modules")
    if not any(pathlib.Path(folder, "ngx_stream_module.so").is_file() for folder in module_dirs):
        raise RuntimeError("Install the Nginx stream module (Debian package: libnginx-mod-stream)")
    try:
        import qrcode  # noqa: F401
        import yaml  # noqa: F401
    except ImportError as error:
        raise RuntimeError(
            "Install Python dependencies: python3-yaml and python3-qrcode"
        ) from error


def generate_identity(seed: pathlib.Path, domain: str, ip: str, state: dict) -> dict:
    existing = state.get("generated")
    if existing:
        return existing

    metadata = json.loads((seed / "metadata.json").read_text())
    with closing(
        sqlite3.connect(f"file:{seed / 'snapshot/x-ui.db'}?mode=ro", uri=True)
    ) as database:
        clients = database.execute("SELECT id, email FROM clients ORDER BY id").fetchall()
    core = STATE / "bin/xray-linux-amd64"
    if not core.is_file():
        core = APP / "bin/xray-linux-amd64"
    key_output = run(str(core), "x25519", capture=True).stdout
    key_values = {
        line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip()
        for line in key_output.splitlines()
        if ":" in line
    }
    public_key = (
        key_values.get("Password (PublicKey)")
        or key_values.get("Password")
        or key_values.get("PublicKey")
    )
    private_key = key_values.get("PrivateKey")
    if not public_key or not private_key:
        raise RuntimeError("Xray did not return a complete X25519 keypair")

    admin = {
        "username": "admin_" + secrets.token_hex(4),
        "password": secrets.token_urlsafe(27),
        "path": "/manage-" + secrets.token_hex(12) + "/",
    }
    connection_token = secrets.token_urlsafe(36)
    generated = {
        "admin": admin,
        "node": {
            "domain": domain,
            "ip": ip,
            "publicKey": public_key,
            "privateKey": private_key,
            "shortId": secrets.token_hex(8),
            "sni": "",
        },
        "apiToken": connection_token,
        "clients": {
            str(client_id): {
                "uuid": str(uuid.uuid4()),
                "auth": secrets.token_urlsafe(32),
                "subId": secrets.token_urlsafe(24),
                "email": email,
            }
            for client_id, email in clients
        },
        "metadata": {"domain": metadata["domain"], "panelPath": metadata["panelPath"]},
    }
    state["generated"] = generated
    save_state(MIGRATION_STATE, state)
    return generated


def prepare_database(generated: dict, domain: str, ip: str) -> tuple[dict, int]:
    node = generated["node"]
    with closing(sqlite3.connect(STATE / "x-ui.db")) as database, database:
        prune_remote(database)
        row = database.execute(
            "SELECT stream_settings FROM inbounds WHERE protocol='vless' AND enable=1"
        ).fetchone()
        if row is None:
            raise ValueError("The seed does not contain an enabled VLESS inbound")
        reality = json.loads(row[0]).get("realitySettings", {})
        sni = (reality.get("serverNames") or [""])[0]
        if not sni or sni in (generated["metadata"]["domain"], domain, ip):
            raise ValueError("REALITY SNI must be a third-party TLS hostname")
        node["sni"] = sni

        for setting_id, value in database.execute("SELECT id, value FROM settings").fetchall():
            if isinstance(value, str) and generated["metadata"]["domain"] in value:
                database.execute(
                    "UPDATE settings SET value=? WHERE id=?",
                    (value.replace(generated["metadata"]["domain"], domain), setting_id),
                )

        for inbound_id, stream_text, protocol in database.execute(
            "SELECT id, stream_settings, protocol FROM inbounds"
        ).fetchall():
            stream = adapt_stream(
                json.loads(stream_text), generated["metadata"]["domain"], domain, sni
            )
            reality_settings = stream.get("realitySettings")
            if reality_settings:
                reality_settings["privateKey"] = node["privateKey"]
                reality_settings["shortIds"] = [node["shortId"]]
                reality_settings.setdefault("settings", {})["publicKey"] = node["publicKey"]
            remark = domain.split(".")[0] + ("-REALITY" if protocol == "vless" else "-HY2")
            database.execute(
                "UPDATE inbounds SET stream_settings=?, share_addr=?, up=0, down=0, "
                "remark=?, share_addr_strategy='custom', node_id=NULL, origin_node_guid='' WHERE id=?",
                (json.dumps(stream), domain, remark, inbound_id),
            )
            host_count = database.execute(
                "SELECT COUNT(*) FROM hosts WHERE inbound_id=?", (inbound_id,)
            ).fetchone()[0]
            if host_count == 0:
                raise ValueError(f"No Hosts entry is associated with inbound {inbound_id}")
            database.execute(
                "UPDATE hosts SET address=?, group_id=? WHERE inbound_id=?",
                (domain, secrets.token_hex(8), inbound_id),
            )

        tables = {
            row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        for table in (
            "nodes",
            "api_tokens",
            "client_traffics",
            "outbound_traffics",
            "node_client_traffics",
            "node_client_ips",
            "client_global_traffics",
        ):
            if table in tables:
                database.execute(f"DELETE FROM {table}")
        database.execute(
            "DELETE FROM settings WHERE key IN "
            "('secret','panelGuid','apiToken','nodeMtlsCaCertPem','nodeMtlsCaKeyPem',"
            "'nodeMtlsClientCertPem','nodeMtlsClientKeyPem','nodeMtlsClientCertSha256',"
            "'nodeMtlsClientCAPem','twoFactorEnable','twoFactorToken')"
        )
        for client_id, credentials in generated["clients"].items():
            database.execute(
                "UPDATE clients SET uuid=?, auth=?, sub_id=?, comment=? WHERE id=?",
                (
                    credentials["uuid"],
                    credentials["auth"],
                    credentials["subId"],
                    f"Happ subscription: https://{domain}/profiles/{credentials['subId']}/happ.txt",
                    int(client_id),
                ),
            )
        api_hash = hashlib.sha256(generated["apiToken"].encode()).hexdigest()
        database.execute(
            "INSERT INTO api_tokens(name, token, enabled, created_at, scope, expires_at) "
            "VALUES (?, ?, 1, ?, 'node-sync', 0)",
            ("central-panel", api_hash, int(time.time())),
        )
        inbounds = {
            remark: inbound_id
            for inbound_id, remark in database.execute("SELECT id, remark FROM inbounds")
        }
        node["inbounds"] = inbounds
        panel_port = int(
            database.execute("SELECT value FROM settings WHERE key='webPort'").fetchone()[0]
        )
        if len(inbounds) != 2:
            raise ValueError("Expected exactly two local node inbounds after database preparation")
        if database.execute("SELECT COUNT(*) FROM inbounds WHERE node_id IS NOT NULL").fetchone()[
            0
        ]:
            raise ValueError("Remote inbounds remain in the clone database")
        database.commit()

    return node, panel_port


def create_ingress(domain: str) -> tuple[pathlib.Path, str]:
    NGINX_ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    NGINX_ROOT.chmod(0o755)
    modules = [
        pathlib.Path(folder) / "ngx_stream_module.so"
        for folder in (
            "/usr/lib/nginx/modules",
            "/usr/lib64/nginx/modules",
            "/usr/share/nginx/modules",
        )
    ]
    module = next((path for path in modules if path.is_file()), None)
    if module is None:
        raise RuntimeError("Nginx stream module file is missing")
    header = (
        f"load_module {module};\nworker_processes auto;\nworker_rlimit_nofile 65536;\n"
        "pid /run/song-nginx.pid;\nerror_log /var/log/nginx/song-error.log warn;\n"
        "events { worker_connections 4096; }\n"
    )
    webroot = pathlib.Path("/var/www/proxy-acme")
    webroot.mkdir(parents=True, exist_ok=True)
    webroot.parent.chmod(0o755)
    webroot.chmod(0o755)
    http = (
        f"server {{ listen 80; listen [::]:80; server_name {domain}; "
        "location ^~ /.well-known/acme-challenge/ { root /var/www/proxy-acme; } "
        "location / { return 404; } }"
    )
    conf = NGINX_ROOT / "nginx.conf"
    conf.write_text(header + "http { " + http + " }\n")
    conf.chmod(0o644)
    unit = pathlib.Path("/etc/systemd/system/song-ingress.service")
    unit.write_text(
        "[Unit]\nDescription=Song standalone nginx ingress\nAfter=network-online.target\n"
        "[Service]\nType=forking\nLimitNOFILE=65536\nPIDFile=/run/song-nginx.pid\n"
        "ExecStartPre=/usr/sbin/nginx -t -c /etc/proxy-stack/nginx.conf\n"
        "ExecStart=/usr/sbin/nginx -c /etc/proxy-stack/nginx.conf\n"
        "ExecReload=/usr/sbin/nginx -s reload -c /etc/proxy-stack/nginx.conf\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    unit.chmod(0o644)
    return conf, header


def install_units(seed: pathlib.Path) -> None:
    for source in (seed / "units").iterdir():
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"Invalid systemd unit in seed: {source.name}")
        destination = pathlib.Path("/etc/systemd/system") / source.name
        shutil.copyfile(source, destination)
        destination.chmod(0o644)


def configure_services(
    seed: pathlib.Path, metadata: dict, generated: dict, node: dict, firewall: str
) -> None:
    domain = node["domain"]
    old_domain = metadata["domain"]
    admin = generated["admin"]
    snippet = (seed / "nginx-http.conf").read_text()
    snippet = snippet.replace(old_domain, domain).replace(metadata["panelPath"], admin["path"])
    snippet_path = REPO / "templates/nginx-http.conf"
    snippet_path.parent.mkdir(exist_ok=True)
    snippet_path.write_text(snippet)
    stream = (
        "stream { server { listen 443; listen [::]:443; ssl_preread on; "
        "proxy_protocol on; proxy_pass $song_upstream; } "
        f"map $ssl_preread_server_name $song_upstream {{ {node['sni']} 127.0.0.1:18443; "
        "default 127.0.0.1:8444; } }\n"
    )
    conf = NGINX_ROOT / "nginx.conf"
    header = conf.read_text().split("http {", 1)[0]
    conf.write_text(
        header
        + stream
        + "http { include /etc/nginx/mime.types; map $http_upgrade $connection_upgrade "
        + '{ default upgrade; "" close; }\n'
        + snippet
        + "\n}\n"
    )
    run("nginx", "-t", "-c", str(conf))
    run("systemctl", "reload", "song-ingress")

    hook = pathlib.Path("/etc/letsencrypt/renewal-hooks/deploy/song-proxy")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook_text = (seed / "renew-hook").read_text().replace(old_domain, domain)
    hook_text = hook_text.replace("systemctl reload nginx", "systemctl reload song-ingress")
    hook_text = re.sub(
        r"nginx -t(?: -c /etc/proxy-stack/nginx\.conf)*",
        "nginx -t -c /etc/proxy-stack/nginx.conf",
        hook_text,
    )
    hook.write_text(hook_text)
    hook.chmod(0o755)

    publish = pathlib.Path("/var/lib/proxy-publish")
    publish.mkdir(mode=0o755, exist_ok=True)
    publish.chmod(0o755)
    rules = seed / "rules"
    if rules.is_dir():
        shutil.copytree(rules, publish / "rules", dirs_exist_ok=True)
        (publish / "rules").chmod(0o755)
        for item in (publish / "rules").iterdir():
            item.chmod(0o644)

    if (REPO / "panel-update/install.py").is_file():
        run("/usr/bin/python3", str(REPO / "panel-update/install.py"))
    if (REPO / "xray-update/install.py").is_file():
        run("/usr/bin/python3", str(REPO / "xray-update/install.py"))
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", "song-profile-http", "proxy-ui", "song-profiles.timer")
    run("systemctl", "reset-failed", "proxy-ui")
    run("systemctl", "restart", "proxy-ui")
    wait_for_listeners(metadata)
    run("systemctl", "start", "song-profiles.service")
    if (REPO / "anytls/install.py").is_file() and (REPO / "anytls/artifact.json").is_file():
        run("/usr/bin/python3", str(REPO / "anytls/install.py"), "--firewall", firewall)
    run(
        "/usr/bin/python3",
        str(REPO / "node/verify-proxy.py"),
        "--client-bin",
        str(STATE / "bin/xray-linux-amd64"),
    )
    verify_public(REPO, node["domain"])
    write_access(REPO, node["domain"], generated["admin"])


def wait_for_listeners(metadata: dict) -> None:
    ports = (int(metadata["webPort"]), int(metadata["subPort"]))
    deadline = time.monotonic() + 60
    pending = set(ports)
    while time.monotonic() < deadline:
        if (
            subprocess.run(
                ["systemctl", "is-active", "--quiet", "proxy-ui"], check=False
            ).returncode
            != 0
        ):
            time.sleep(1)
            continue
        for port in tuple(pending):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    pending.remove(port)
            except OSError:
                pass
        if not pending:
            return
        time.sleep(0.5)
    logs = subprocess.run(
        ["journalctl", "-u", "proxy-ui", "-n", "80", "--no-pager"],
        check=False,
        capture_output=True,
        text=True,
    ).stdout
    raise RuntimeError(
        f"Panel listeners did not become ready on {sorted(pending)}. Recent logs:\n{logs}"
    )


def install(seed: pathlib.Path, domain: str, server_ip: str, firewall: str, resume: bool) -> None:
    validate_domain(domain)
    ip = ipaddress.ip_address(server_ip)
    if ip.version != 4 or not ip.is_global:
        raise ValueError("A public IPv4 server address is required")
    seed = seed.resolve(strict=True)
    seed_digest = verify_seed(seed)
    metadata = json.loads((seed / "metadata.json").read_text())
    identity = {"seed": seed_digest, "domain": domain, "ip": str(ip), "firewall": firewall}
    if pathlib.Path("/root/proxy-stack") != REPO:
        raise RuntimeError("Repository must be checked out at /root/proxy-stack on the new server")

    lock_path = pathlib.Path("/run/proxy-migration.lock")
    with lock_path.open("w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = load_state(MIGRATION_STATE, identity, resume)
        if state.get("complete"):
            print("Migration already completed. See /root/proxy-stack/ACCESS.md")
            return

        protected_paths = (APP, STATE, NGINX_ROOT / "nginx.conf")
        if not state and any(path.exists() for path in protected_paths):
            occupied = next(path for path in protected_paths if path.exists())
            raise FileExistsError(f"Refusing to overwrite existing managed path: {occupied}")
        if not state:
            check_prerequisites()
            check_ports()
            check_dns(domain, str(ip))
            state = {"identity": identity}
            save_state(MIGRATION_STATE, state)
        os.umask(0o077)

        if firewall == "auto":
            open_firewall(run)
        check_dns(domain, str(ip))

        if not state.get("prepared"):
            # Only an existing matching migration can reach this branch with
            # leftovers: preflight refused these paths before the state file
            # was created. Reset the incomplete install while keeping its
            # generated identity in the protected migration state.
            if APP.exists():
                shutil.rmtree(APP)
            if STATE.exists():
                for child in STATE.iterdir():
                    if child.is_symlink() or not child.is_dir():
                        child.unlink()
                    else:
                        shutil.rmtree(child)
            shutil.copytree(seed / "app", APP)
            normalize_app(APP)
            STATE.mkdir(mode=0o750, parents=True)
            shutil.copyfile(seed / "snapshot/x-ui.db", STATE / "x-ui.db")
            for folder in ("bin", "tls", "log"):
                (STATE / folder).mkdir(mode=0o750, exist_ok=True)
            for item in (APP / "bin").iterdir():
                if item.name == "config.json" or item.name.startswith(".config-"):
                    continue
                if item.is_file():
                    shutil.copy2(item, STATE / "bin" / item.name)
            (STATE / "bin/xray-linux-amd64").chmod(0o755)

            try:
                panel_user = pwd.getpwnam("proxy-ui")
            except KeyError:
                run(
                    "useradd",
                    "--system",
                    "--home-dir",
                    str(STATE),
                    "--shell",
                    "/usr/sbin/nologin",
                    "proxy-ui",
                )
                panel_user = pwd.getpwnam("proxy-ui")
            os.chown(STATE, panel_user.pw_uid, panel_user.pw_gid)
            for path in (STATE, STATE / "bin", STATE / "tls", STATE / "log"):
                path.chmod(0o750)
                os.chown(path, panel_user.pw_uid, panel_user.pw_gid)
            for path in STATE.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    os.chown(path, panel_user.pw_uid, panel_user.pw_gid)

            generated = generate_identity(seed, domain, str(ip), state)
            node, panel_port = prepare_database(generated, domain, str(ip))
            write_json(
                REPO / "admin.json",
                dict(generated["admin"], url=f"https://{domain}{generated['admin']['path']}"),
            )
            write_json(
                REPO / "public-node.json",
                {key: value for key, value in node.items() if key != "privateKey"},
            )
            write_json(
                REPO / "node-connection.json",
                {
                    "scheme": "https",
                    "address": domain,
                    "port": 443,
                    "basePath": generated["admin"]["path"],
                    "apiToken": generated["apiToken"],
                    "scope": "node-sync",
                    "tlsVerifyMode": "verify",
                },
            )
            env = dict(
                os.environ,
                XUI_DB_FOLDER=str(STATE),
                XUI_BIN_FOLDER=str(STATE / "bin"),
                XUI_LOG_FOLDER=str(STATE / "log"),
            )
            run(
                str(APP / "x-ui"),
                "setting",
                "-listenIP",
                "127.0.0.1",
                "-port",
                str(panel_port),
                "-username",
                generated["admin"]["username"],
                "-password",
                generated["admin"]["password"],
                "-webBasePath",
                generated["admin"]["path"],
                env=env,
                capture=True,
            )
            state["prepared"] = True
            save_state(MIGRATION_STATE, state)

        generated = state["generated"]
        node = generated["node"]
        _conf, _header = create_ingress(domain)
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "song-ingress")
        run("systemctl", "restart", "song-ingress")
        check_acme(pathlib.Path("/var/www/proxy-acme"), domain)
        run(
            "certbot",
            "certonly",
            "--webroot",
            "-w",
            "/var/www/proxy-acme",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
            "--key-type",
            "ecdsa",
        )
        for name in ("fullchain.pem", "privkey.pem"):
            run(
                "install",
                "-o",
                "proxy-ui",
                "-g",
                "proxy-ui",
                "-m",
                "0640",
                f"/etc/letsencrypt/live/{domain}/{name}",
                str(STATE / "tls" / name),
            )
        run("chown", "-R", "proxy-ui:proxy-ui", str(STATE))
        run(
            "runuser",
            "-u",
            "proxy-ui",
            "--",
            str(STATE / "bin/xray-linux-amd64"),
            "version",
            capture=True,
        )
        install_units(seed)
        with closing(sqlite3.connect(f"file:{STATE / 'x-ui.db'}?mode=ro", uri=True)) as database:
            devices = {
                row[0]: {"email": row[0], "id": row[1], "auth": row[2], "subId": row[3]}
                for row in database.execute(
                    "SELECT email, uuid, auth, sub_id FROM clients WHERE enable=1"
                )
            }
        write_json(REPO / "devices.json", devices)
        configure_services(seed, metadata, generated, node, firewall)

        if state.get("complete"):
            return
        state["complete"] = True
        save_state(MIGRATION_STATE, state)
        print(f"Installed node: {domain}")
        print(f"Panel URL: https://{domain}{generated['admin']['path']}")
        print(
            "New identity files: /root/proxy-stack/{admin.json,public-node.json,node-connection.json,ACCESS.md}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "seed", type=pathlib.Path, help="private directory exported by node/export_seed.py"
    )
    parser.add_argument("--domain", required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--firewall", choices=("auto", "manual"), default="auto")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        digest = verify_seed(args.seed)
        validate_domain(args.domain)
        ip = ipaddress.ip_address(args.server_ip)
        if ip.version != 4 or not ip.is_global:
            raise ValueError("A public IPv4 address is required")
        if args.check_only:
            print(f"Seed verified: {digest}; target {args.domain} ({ip})")
            return
        install(args.seed, args.domain, str(ip), args.firewall, args.resume)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        print(f"Command failed ({error.returncode}): {error.cmd[0]}", file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)
        print(
            "Fix the reported cause and repeat with the same arguments plus --resume.",
            file=sys.stderr,
        )
        print(
            "For HTTP-01: check DNS A/AAAA, cloud firewall TCP 80, host INPUT TCP 80, "
            "and /var/log/letsencrypt/letsencrypt.log. Keep SSH rules intact.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as error:
        print(f"Migration stopped: {error}", file=sys.stderr)
        print(
            "Fix the reported cause and repeat with the same arguments plus --resume.",
            file=sys.stderr,
        )
        print(
            "For HTTP-01: check DNS A/AAAA, cloud firewall TCP 80, host INPUT TCP 80, "
            "and /var/log/letsencrypt/letsencrypt.log. Keep SSH rules intact.",
            file=sys.stderr,
        )
        print(
            "Diagnostics: journalctl -u proxy-ui -u song-ingress -n 80 --no-pager", file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
