#!/usr/bin/env python3
"""Export a private directory seed from the central server; never creates an archive."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
from contextlib import closing

from migration_lib import make_manifest, sha256_file

STACK = pathlib.Path("/root/proxy-stack")
APP = pathlib.Path("/opt/proxy-stack")
STATE = pathlib.Path("/var/lib/proxy-stack")
SEED_FORMAT = 1
UNITS = (
    "proxy-ui.service",
    "song-profile-http.service",
    "song-profiles.service",
    "song-profiles.timer",
)


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Run this export command as root")


def copy_app(seed: pathlib.Path, core: pathlib.Path) -> None:
    destination = seed / "app"
    destination.mkdir(mode=0o755)
    shutil.copy2(APP / "x-ui", destination / "x-ui")
    shutil.copy2(
        pathlib.Path(__file__).with_name("profile-http.py"), destination / "profile-http.py"
    )
    source_bin = APP / "bin"
    target_bin = destination / "bin"
    target_bin.mkdir(mode=0o755)
    shutil.copy2(core, destination / "bin/xray-linux-amd64")
    (destination / "bin/xray-linux-amd64").chmod(0o755)
    if source_bin.is_dir():
        for path in source_bin.iterdir():
            if path.is_file() and path.suffix == ".dat":
                shutil.copy2(path, target_bin / path.name)


def export(destination: pathlib.Path) -> None:
    require_root()
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite seed directory: {destination}")
    if not (APP / "x-ui").is_file():
        raise FileNotFoundError(f"Panel executable is missing: {APP / 'x-ui'}")
    core_candidates = (STATE / "bin/xray-linux-amd64", APP / "bin/xray-linux-amd64")
    core = next((item for item in core_candidates if item.is_file()), None)
    if core is None:
        raise FileNotFoundError(
            "Xray core missing from both runtime state and application directory"
        )

    metadata_file = STACK / "public-node.json"
    admin_file = STACK / "admin.json"
    if not metadata_file.is_file() or not admin_file.is_file():
        raise FileNotFoundError(
            "Central node identity files are not available under /root/proxy-stack"
        )
    public = json.loads(metadata_file.read_text())
    admin = json.loads(admin_file.read_text())

    destination.mkdir(mode=0o700, parents=True)
    try:
        snapshot = destination / "snapshot"
        snapshot.mkdir(mode=0o700)
        with (
            closing(sqlite3.connect(f"file:{STATE / 'x-ui.db'}?mode=ro", uri=True)) as source,
            closing(sqlite3.connect(snapshot / "x-ui.db")) as target,
        ):
            source.backup(target)
            target.commit()
        with closing(sqlite3.connect(f"file:{snapshot / 'x-ui.db'}?mode=ro", uri=True)) as database:
            if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Database snapshot failed integrity check")
        (snapshot / "x-ui.db").chmod(0o600)

        copy_app(destination, core)
        (destination / "units").mkdir(mode=0o700)
        for name in UNITS:
            template = pathlib.Path(__file__).resolve().parents[1] / "templates/systemd" / name
            if not template.is_file():
                raise FileNotFoundError(f"Required unit template is missing: {template}")
            shutil.copy2(template, destination / "units" / name)

        nginx_source = pathlib.Path("/etc/nginx/conf.d/song-proxy.conf")
        if not nginx_source.is_file():
            raise FileNotFoundError(f"Current proxy Nginx site is missing: {nginx_source}")
        shutil.copy2(nginx_source, destination / "nginx-http.conf")
        renew_hook = pathlib.Path("/etc/letsencrypt/renewal-hooks/deploy/song-proxy")
        if not renew_hook.is_file():
            raise FileNotFoundError(f"Certbot deploy hook is missing: {renew_hook}")
        shutil.copy2(renew_hook, destination / "renew-hook")

        rules = pathlib.Path("/var/lib/proxy-publish/rules")
        if rules.is_dir():
            shutil.copytree(rules, destination / "rules", symlinks=False)

        with closing(sqlite3.connect(f"file:{snapshot / 'x-ui.db'}?mode=ro", uri=True)) as database:
            settings = dict(database.execute("SELECT key, value FROM settings"))
        panel_version = subprocess.run(
            [str(APP / "x-ui"), "-v"], check=True, capture_output=True, text=True
        ).stdout.strip()
        core_version = (
            subprocess.run([str(core), "version"], check=True, capture_output=True, text=True)
            .stdout.splitlines()[0]
            .split()[1]
        )
        data = {
            "formatVersion": SEED_FORMAT,
            "domain": public["domain"],
            "panelPath": admin["path"],
            "webPort": int(settings["webPort"]),
            "subPort": int(settings["subPort"]),
            "panelVersion": panel_version,
            "coreVersion": core_version,
            "architecture": "x86_64",
        }
        (destination / "metadata.json").write_text(json.dumps(data, indent=2) + "\n")
        (destination / "metadata.json").chmod(0o600)
        manifest = make_manifest(destination)
        manifest_path = destination / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        manifest_path.chmod(0o600)
        print(f"Directory seed ready: {destination}")
        print(f"Manifest SHA256: {sha256_file(manifest_path)}")
        print(
            "Contains a private panel database. Copy only over authenticated SSH; do not commit it."
        )
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    export(args.destination)


if __name__ == "__main__":
    main()
