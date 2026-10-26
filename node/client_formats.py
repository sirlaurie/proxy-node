"""Additional per-account Happ and native Xray formats."""

import base64
import hashlib
import ipaddress
import json
import pathlib
import socket
import urllib.parse
from functools import lru_cache

B = pathlib.Path("/root/proxy-stack")


@lru_cache(maxsize=128)
def bootstrap_ipv4(host):
    try:
        return str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]


def node_outputs(nodes):
    """Convert every supported panel proxy, preserving each endpoint and credential."""
    links = []
    outbounds = []
    hosts = {}
    counts = {}
    for node in nodes:
        host = node["server"]
        port = int(node["port"])
        address = bootstrap_ipv4(host)
        hosts[host] = address
        authority = ("[" + host + "]" if ":" in host else host) + ":" + str(port)
        fragment = urllib.parse.quote(node["name"], safe="")
        if (
            node["type"] == "vless"
            and node.get("reality-opts")
            and node.get("network", "tcp") in ("tcp", "raw")
        ):
            kind = "reality"
            rr = node["reality-opts"]
            sni = node.get("servername", host)
            fp = node.get("client-fingerprint", "chrome")
            flow = node.get("flow", "")
            enc = node.get("encryption", "none")
            query = {
                "encryption": enc,
                "security": "reality",
                "pbk": rr["public-key"],
                "sid": rr.get("short-id", ""),
                "fp": fp,
                "type": "tcp",
                "sni": sni,
                "spx": "/",
            }
            user = {"id": node["uuid"], "encryption": enc}
            if flow:
                query["flow"] = flow
                user["flow"] = flow
            links.append(
                "vless://"
                + urllib.parse.quote(node["uuid"], safe="")
                + "@"
                + authority
                + "?"
                + urllib.parse.urlencode(query)
                + "#"
                + fragment
            )
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": sni,
                        "fingerprint": fp,
                        "publicKey": rr["public-key"],
                        "shortId": rr.get("short-id", ""),
                        "spiderX": "/",
                    },
                },
            }
        elif node["type"] == "hysteria2":
            kind = "hy2"
            auth = node.get("auth", node.get("password"))
            sni = node.get("sni", host)
            alpn = node.get("alpn", ["h3"])
            query = {"sni": sni, "alpn": ",".join(alpn)}
            tls = {"serverName": sni, "alpn": alpn}
            if node.get("skip-cert-verify"):
                query["insecure"] = "1"
                tls["allowInsecure"] = True
            # Unsupported transport extras must not be silently discarded.
            if node.get("obfs"):
                raise ValueError("Hysteria2 obfs conversion is not configured")
            links.append(
                "hysteria2://"
                + urllib.parse.quote(auth, safe="")
                + "@"
                + authority
                + "?"
                + urllib.parse.urlencode(query)
                + "#"
                + fragment
            )
            outbound = {
                "protocol": "hysteria",
                "settings": {"version": 2, "address": address, "port": port},
                "streamSettings": {
                    "network": "hysteria",
                    "security": "tls",
                    "tlsSettings": tls,
                    "hysteriaSettings": {"version": 2, "auth": auth},
                },
            }
        else:
            raise ValueError(
                "Unsupported native export protocol/transport: "
                + str(node.get("type"))
                + "/"
                + str(node.get("network"))
            )
        counts[kind] = counts.get(kind, 0) + 1
        outbound["tag"] = kind if counts[kind] == 1 else kind + "-" + str(counts[kind])
        outbounds.append(outbound)
    return links, outbounds, hosts


def extra_profiles(name, sub, nodes, dest, write, base):
    n = json.loads((B / "public-node.json").read_text())
    domain = n["domain"]
    ip = n["ip"]
    links, proxy_outbounds, endpoint_hosts = node_outputs(nodes)
    if not proxy_outbounds:
        raise ValueError("No proxy outbounds to publish")
    proxy_tags = [x["tag"] for x in proxy_outbounds]
    probe_interval = "30s" if name == "mac-mini" else "60s"
    routing = {
        "Name": "Song-China",
        "GlobalProxy": "true",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "RemoteDNSIP": "1.1.1.1",
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "",
        "DomesticDNSIP": "223.5.5.5",
        "Geoipurl": base + "/rules/geoip.dat",
        "Geositeurl": base + "/rules/geosite.dat",
        "DnsHosts": {"cloudflare-dns.com": "1.1.1.1", domain: ip},
        "DirectSites": ["geosite:cn", "domain:lan", "domain:local", "full:" + domain],
        "DirectIp": ["geoip:private", "geoip:cn", ip + "/32"],
        "ProxySites": [],
        "ProxyIp": ["1.1.1.1/32", "8.8.8.8/32"],
        "BlockSites": [],
        "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false",
    }
    routing["DnsHosts"].update(endpoint_hosts)
    routing["DirectSites"] += ["full:" + h for h in endpoint_hosts if h != domain]
    routing["DirectIp"] += list(
        dict.fromkeys(v + "/32" for v in endpoint_hosts.values() if v != ip)
    )
    # Re-encode after adding remote-node bootstrap/route exceptions.
    link = (
        "happ://routing/onadd/"
        + base64.b64encode(json.dumps(routing, separators=(",", ":")).encode()).decode()
    )
    write(dest / "happ.txt", link + "\n" + "\n".join(links) + "\n")
    cfg = {
        "log": {"loglevel": "warning", "access": "none"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "hosts": {domain: ip},
            "servers": [
                {"address": "223.5.5.5", "domains": ["geosite:cn"], "skipFallback": True},
                {"address": "https://1.1.1.1/dns-query"},
            ],
        },
        "inbounds": [
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 1080,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True},
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": 1081,
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": [
            *proxy_outbounds,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
                "streamSettings": {"sockopt": {"domainStrategy": "AsIs"}},
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
        "observatory": {
            "subjectSelector": proxy_tags,
            "probeURL": "https://www.gstatic.com/generate_204",
            "probeInterval": probe_interval,
            "enableConcurrency": True,
        },
        "routing": {
            "domainStrategy": "IPOnDemand",
            "balancers": [
                {
                    "tag": "proxy",
                    "selector": proxy_tags,
                    "fallbackTag": proxy_tags[0],
                    "strategy": {"type": "leastPing"},
                }
            ],
            "rules": [
                {"type": "field", "ip": ["1.1.1.1/32", "8.8.8.8/32"], "balancerTag": "proxy"},
                {
                    "type": "field",
                    "domain": ["geosite:cn", "domain:lan", "domain:local", "full:" + domain],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "ip": ["geoip:private", "geoip:cn", ip + "/32"],
                    "outboundTag": "direct",
                },
                {"type": "field", "network": "tcp,udp", "balancerTag": "proxy"},
            ],
        },
    }
    cfg["dns"]["hosts"].update(endpoint_hosts)
    cfg["routing"]["rules"][1]["domain"] += ["full:" + h for h in endpoint_hosts if h != domain]
    cfg["routing"]["rules"][2]["ip"] += list(
        dict.fromkeys(v + "/32" for v in endpoint_hosts.values() if v != ip)
    )
    # Match local/China domain exceptions before on-demand DNS lookup for IP rules.
    cfg["routing"]["rules"].insert(0, cfg["routing"]["rules"].pop(1))
    write(dest / "xray-macos.json", json.dumps(cfg, indent=2) + "\n")
    # Native macOS TUN: intercept DNS, retain real IPs, capture both families but block public IPv6.
    tun = json.loads(json.dumps(cfg))
    tun["inbounds"] = [
        {
            "tag": "tun",
            "protocol": "tun",
            "settings": {
                "name": "utun98",
                "mtu": 1500,
                "gateway": ["169.254.10.1/30"],
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto",
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        },
        {
            "tag": "dns-in",
            "listen": "127.0.0.1",
            "port": 53,
            "protocol": "tunnel",
            "settings": {"address": "1.1.1.1", "port": 53, "network": "tcp,udp"},
        },
    ]
    tun["dns"] = {
        "tag": "dns-upstream",
        "queryStrategy": "UseIPv4",
        "disableCache": False,
        "hosts": {domain: ip, "tun-check.invalid": "127.0.0.1"},
        "servers": [
            {
                "address": "192.168.1.1",
                "domains": ["domain:lan", "domain:local", "domain:home.arpa"],
                "skipFallback": True,
            },
            {"address": "223.5.5.5", "domains": ["geosite:cn"], "skipFallback": True},
            {"address": "119.29.29.29", "domains": ["geosite:cn"], "skipFallback": True},
            {"address": "https://1.1.1.1/dns-query"},
            {"address": "https://8.8.8.8/dns-query"},
        ],
    }
    tun["dns"]["hosts"].update(endpoint_hosts)
    tun["outbounds"] += [
        {
            "tag": "dns-handler",
            "protocol": "dns",
            "settings": {
                "rewriteAddress": "1.1.1.1",
                "rewritePort": 53,
                "rewriteNetwork": "tcp",
                "rules": [
                    {"qType": 28, "action": "return", "rCode": 0},
                    {"qType": 1, "action": "hijack"},
                    {"action": "direct"},
                ],
            },
            "streamSettings": {"sockopt": {"dialerProxy": "dns-via-proxy"}},
        },
        {"tag": "dns-via-proxy", "protocol": "loopback", "settings": {"inboundTag": "dns-forward"}},
    ]
    tun["routing"]["rules"] = [
        {
            "type": "field",
            "inboundTag": ["dns-upstream"],
            "ip": ["223.5.5.5/32", "119.29.29.29/32", "192.168.1.1/32"],
            "outboundTag": "direct",
        },
        {"type": "field", "inboundTag": ["dns-upstream", "dns-forward"], "balancerTag": "proxy"},
        {"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-handler"},
        {
            "type": "field",
            "inboundTag": ["tun"],
            "network": "tcp,udp",
            "port": "53",
            "outboundTag": "dns-handler",
        },
        {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
    ] + tun["routing"]["rules"]
    write(dest / "xray-macos-tun.json", json.dumps(tun, indent=2) + "\n")
    runner = (B / "macos-tun-runner.sh").read_text()
    write(dest / "song-xray-tun.sh", runner)
    # Same installation instructions work for every enabled client, with separate credentials.
    manifest = json.loads((B / "macos-artifacts.json").read_text())
    tmpl = (B / "macos-install.template.sh").read_text()
    replacements = {"@PROFILE@": base + "/profiles/" + sub, "@BASE@": base}
    for arch, item in manifest.items():
        replacements["@FILE_" + arch + "@"] = item["file"]
        replacements["@SHA_" + arch + "@"] = item["sha256"]
    for geo in ["geoip", "geosite"]:
        replacements["@SHA_" + geo + "@"] = hashlib.sha256(
            (pathlib.Path("/var/lib/proxy-publish/rules") / (geo + ".dat")).read_bytes()
        ).hexdigest()
    for k, v in replacements.items():
        tmpl = tmpl.replace(k, v)
    write(dest / "install-macos.sh", tmpl)
    tun_install = (B / "macos-tun-install.template.sh").read_text()
    replacements["@SHA_RUNNER@"] = hashlib.sha256(runner.encode()).hexdigest()
    for k, v in replacements.items():
        tun_install = tun_install.replace(k, v)
    write(dest / "install-macos-tun.sh", tun_install)
