#!/usr/bin/env python3
"""Publish per-device profiles from the panel's live subscriptions; no credential duplication."""

import fcntl
import hashlib
import io
import json
import pathlib
import re
import shutil
import sqlite3
import urllib.parse
import urllib.request

import qrcode
import qrcode.image.svg
import yaml
from anytls_profiles import extra_node
from client_formats import extra_profiles

ROOT = pathlib.Path("/var/lib/proxy-publish")
ROOT.mkdir(mode=0o755, exist_ok=True)
lock = pathlib.Path("/var/lib/proxy-publish/.export.lock").open("w")  # noqa: SIM115
fcntl.flock(lock, fcntl.LOCK_EX)
DOMAIN = json.loads(pathlib.Path("/root/proxy-stack/public-node.json").read_text())["domain"]
BASE = "https://" + DOMAIN
DB = sqlite3.connect("file:/var/lib/proxy-stack/x-ui.db?mode=ro", uri=True)
settings = dict(DB.execute("SELECT key,value FROM settings"))


def write(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.parent.chmod(0o755)
    f = p.with_suffix(p.suffix + ".tmp")
    f.write_text(data)
    f.chmod(0o644)
    f.replace(p)


def doc(x):
    return yaml.safe_dump(x, allow_unicode=True, sort_keys=False)


STASH_NOTE = "# Stash display compatibility: unlimited quota/no expiry use 100 TiB / 2099-01-01 placeholders; account limits are unchanged and upload/download are real.\n"
active = set()
for name, sub in DB.execute(
    "SELECT email,sub_id FROM clients WHERE enable=1 AND sub_id IS NOT NULL"
):
    if not sub or not all(c.isalnum() or c in "_-" for c in sub):
        continue
    active.add(sub)
    # These paths are backed by the panel: revocation is reflected on next publish.
    req = urllib.request.Request(
        "http://127.0.0.1:" + settings["subPort"] + settings["subClashPath"] + sub,
        headers={"Host": DOMAIN},
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        userinfo = response.headers.get("Subscription-Userinfo", "")
        d = yaml.safe_load(response.read())
    # Preserve panel accounting, including unlimited quota/no-expiry values of zero.
    values = {}
    for item in userinfo.split(";"):
        key, sep, value = item.strip().partition("=")
        if sep and key in ("upload", "download", "total", "expire") and value.isdigit():
            values[key] = int(value)
    if not all(k in values for k in ("upload", "download", "total", "expire")):
        raise ValueError("Panel subscription accounting header missing or invalid")
    nodes = d.get("proxies", [])
    if not nodes:
        continue
    for node in nodes:
        if node["type"] == "hysteria2" and "password" in node:
            node["auth"] = node["password"]
    dest = ROOT / "profiles" / sub
    write(ROOT / ".metadata" / (sub + ".json"), json.dumps(values))
    anytls_node = extra_node(sub)
    write(dest / "nodes.yaml", doc({"proxies": nodes + ([anytls_node] if anytls_node else [])}))
    extra_profiles(name, sub, nodes, dest, write, BASE)
    cfg = {
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "allow-lan": False,
        "dns": {
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
            "follow-rule": True,
            "nameserver-policy": {
                "geosite:cn": ["223.5.5.5", "119.29.29.29"],
                DOMAIN: ["223.5.5.5", "119.29.29.29"],
                "+.lan": "system",
                "+.local": "system",
            },
        },
        "proxy-providers": {
            "song": {"url": BASE + "/profiles/" + sub + "/nodes.yaml", "interval": 1800}
        },
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"], "use": ["song"]},
            {
                "name": "AUTO",
                "type": "fallback",
                "use": ["song"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 60,
            },
        ],
        "rules": [
            "DOMAIN," + DOMAIN + ",DIRECT",
            "DOMAIN-SUFFIX,lan,DIRECT",
            "DOMAIN-SUFFIX,local,DIRECT",
            *[
                "IP-CIDR," + x + ",DIRECT,no-resolve"
                for x in [
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.0.0/16",
                    "224.0.0.0/3",
                ]
            ],
            *[
                "IP-CIDR6," + x + ",DIRECT,no-resolve"
                for x in ["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]
            ],
            "IP-CIDR,1.1.1.1/32,PROXY,no-resolve",
            "IP-CIDR,8.8.8.8/32,PROXY,no-resolve",
            "GEOSITE,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }
    # Optional local experiment: inline Stash node, excluded from provider/AUTO and Mihomo.
    stash_cfg = json.loads(json.dumps(cfg))
    experiment = pathlib.Path("/root/proxy-stack/stash-test-node.json")
    if name == "iphone" and experiment.exists():
        test_node = json.loads(experiment.read_text())
        stash_cfg["proxies"] = [test_node]
        stash_cfg["proxy-groups"][0]["proxies"].append(test_node["name"])
    write(
        dest / "stash.yaml",
        "#SUBSCRIBED " + BASE + "/profiles/" + sub + "/stash.yaml\n" + STASH_NOTE + doc(stash_cfg),
    )
    # Stash imports a complete YAML configuration through its documented URL scheme.
    stash_uri = "stash://install-config?url=" + urllib.parse.quote(
        BASE + "/profiles/" + sub + "/stash.yaml", safe=""
    )
    qr = qrcode.make(stash_uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=4)
    buf = io.BytesIO()
    qr.save(buf)
    write(dest / "stash-import.svg", buf.getvalue().decode())
    bootstrap = json.loads(json.dumps(stash_cfg))
    bootstrap["dns"]["nameserver-policy"].pop("geosite:cn")
    bootstrap["dns"]["nameserver-policy"]["+.cn"] = ["223.5.5.5", "119.29.29.29"]
    bootstrap["rules"] = [x for x in bootstrap["rules"] if not x.startswith("GEOSITE,")]
    write(
        dest / "stash-bootstrap.yaml",
        "#SUBSCRIBED "
        + BASE
        + "/profiles/"
        + sub
        + "/stash-bootstrap.yaml\n"
        + STASH_NOTE
        + doc(bootstrap),
    )
    # mihomo variants support the same protocols but use conventional DNS/rule-provider configuration.
    mi = json.loads(json.dumps(cfg))
    mi["mixed-port"] = 7890
    mi["dns"].pop("follow-rule")
    mi["dns"]["respect-rules"] = True
    mi["dns"]["enable"] = True
    mi["dns"]["enhanced-mode"] = "fake-ip"
    mi["dns"]["fake-ip-range"] = "198.18.0.1/16"
    mi["dns"]["fake-ip-filter"] = ["*.lan", "*.local", DOMAIN]
    mi["proxy-providers"]["song"].update(
        {
            "type": "http",
            "path": "./providers/song.yaml",
            "health-check": {
                "enable": True,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 60,
            },
        }
    )
    mi["geodata-mode"] = True
    mi["geox-url"] = {"geoip": BASE + "/rules/geoip.dat", "geosite": BASE + "/rules/geosite.dat"}
    mi["tun"] = {
        "enable": True,
        "stack": "mixed",
        "auto-route": True,
        "auto-detect-interface": True,
        "dns-hijack": ["any:53"],
    }
    write(dest / "mihomo.yaml", doc(mi))
    lan = "    lan_interface: enp1s0\n" if name == "arch-gateway" else ""
    dns_bind = (
        "    bind: 'tcp+udp://0.0.0.0:53'\n"
        if name == "arch-gateway"
        else "    bind: 'tcp+udp://127.0.0.1:5353'\n"
    )
    dae = (
        """global {
    log_level: info
    tproxy_port: 12345
    tproxy_port_protect: true
    pprof_port: 0
    wan_interface: auto
LAN    auto_config_kernel_parameter: true
    dial_mode: domain
    allow_insecure: false
    tls_implementation: utls
    utls_imitate: chrome_auto
    tcp_check_url: 'https://www.gstatic.com/generate_204'
    udp_check_dns: 'dns.google:53,8.8.8.8'
    check_interval: 30s
    check_tolerance: 100ms
}
subscription {
    song: 'SUBURL'
}
dns {
    ipversion_prefer: 4
BIND    upstream {
        landns: 'udp://192.168.1.1:53'
        localdns: 'udp://223.5.5.5:53'
        remote: 'tcp://8.8.8.8:53'
    }
    routing {
        request {
            qname(suffix: lan, suffix: local) -> landns
            qname(full: DOMAIN) -> localdns
            qname(geosite:cn) -> localdns
            fallback: remote
        }
    }
}
group {
    proxy {
        filter: name(keyword: 'REALITY') [add_latency: -200ms]
        filter: !name(keyword: 'REALITY')
        policy: min_moving_avg
    }
}
routing {
    pname(NetworkManager, systemd-networkd) -> direct
    dip(224.0.0.0/3, 'ff00::/8') -> direct
    dip(geoip:private) -> direct
    domain(suffix: lan, suffix: local) -> direct
    domain(full: DOMAIN) -> direct
    dip(8.8.8.8/32, 1.1.1.1/32) -> proxy
    domain(geosite:cn) -> direct
    dip(geoip:cn) -> direct
    fallback: proxy
}
""".replace("LAN", lan)
        .replace("BIND", dns_bind)
        .replace("SUBURL", BASE + settings["subPath"] + sub)
        .replace("DOMAIN", DOMAIN)
    )
    write(dest / "config.dae", dae)
    # Private local delivery copies. No inbound UUIDs/passwords are written into logs.
    safe_name = (
        name
        if re.fullmatch(r"[A-Za-z0-9_.@-]+", name) and name not in (".", "..")
        else "client-" + hashlib.sha256(name.encode()).hexdigest()[:16]
    )
    local = pathlib.Path("/root/proxy-stack/clients") / safe_name
    local.mkdir(parents=True, exist_ok=True)
    local.chmod(0o700)
    for f in [
        "stash.yaml",
        "mihomo.yaml",
        "config.dae",
        "happ.txt",
        "xray-macos.json",
        "xray-macos-tun.json",
    ]:
        shutil.copyfile(dest / f, local / f)
        (local / f).chmod(0o600)
for d in (ROOT / "profiles").iterdir():
    if d.is_dir() and d.name not in active:
        shutil.rmtree(d)
print("Published", len(active), "device profiles")
