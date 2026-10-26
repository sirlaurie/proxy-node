#!/usr/bin/env python3
"""Restore a selected panel state snapshot without replacing /var/lib mountpoints."""

from __future__ import annotations

import argparse
import datetime
import os
import pathlib
import pwd
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing

STATE = pathlib.Path("/var/lib/proxy-stack")
BACKUP_ROOT = pathlib.Path("/root/proxy-stack/upgrade-backups")


def run(*command: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, text=True)


def validate_snapshot(snapshot: pathlib.Path) -> None:
    resolved = snapshot.resolve(strict=True)
    if BACKUP_ROOT not in resolved.parents or resolved.name != "state":
        raise ValueError(
            "Snapshot must be a state/ directory under /root/proxy-stack/upgrade-backups"
        )
    database_path = resolved / "x-ui.db"
    core_path = resolved / "bin/xray-linux-amd64"
    if not database_path.is_file() or not core_path.is_file():
        raise ValueError("Snapshot must contain x-ui.db and bin/xray-linux-amd64")
    with closing(sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)) as database:
        if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Snapshot database failed integrity check")
    if subprocess.run([str(core_path), "version"], capture_output=True, check=False).returncode:
        raise ValueError("Snapshot Xray binary cannot execute")


def restore_contents(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for entry in destination.iterdir():
        if entry.is_symlink() or not entry.is_dir():
            entry.unlink()
        else:
            shutil.rmtree(entry)
    for entry in source.iterdir():
        target = destination / entry.name
        if entry.is_symlink():
            target.symlink_to(os.readlink(entry))
        elif entry.is_dir():
            shutil.copytree(entry, target, symlinks=True)
        else:
            shutil.copy2(entry, target, follow_symlinks=False)
    shutil.copystat(source, destination, follow_symlinks=False)


def recover(snapshot: pathlib.Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Run as root")
    validate_snapshot(snapshot)
    timer_active = (
        run("systemctl", "is-active", "--quiet", "song-profiles.timer", check=False).returncode == 0
    )
    run("systemctl", "stop", "song-profiles.timer", "song-profiles.service", check=False)
    run("systemctl", "stop", "proxy-ui", check=False)

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    failed_copy = STATE.with_name(f"proxy-stack.failed-{stamp}")
    if STATE.exists():
        shutil.copytree(STATE, failed_copy, symlinks=True)
    restore_contents(snapshot.resolve(), STATE)

    user = pwd.getpwnam("proxy-ui")
    for root, directories, files in os.walk(STATE):
        os.chown(root, user.pw_uid, user.pw_gid)
        for name in directories + files:
            path = pathlib.Path(root) / name
            if not path.is_symlink():
                os.chown(path, user.pw_uid, user.pw_gid)

    run("systemctl", "reset-failed", "proxy-ui", check=False)
    run("systemctl", "start", "proxy-ui")
    run("systemctl", "is-active", "--quiet", "proxy-ui")
    if timer_active:
        run("systemctl", "start", "song-profiles.timer")
    print(f"Restored panel state from {snapshot}")
    print(f"Previous partial state preserved at {failed_copy}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "snapshot", type=pathlib.Path, help="exact upgrade-backups/panel-*/state path"
    )
    args = parser.parse_args()
    try:
        recover(args.snapshot)
    except Exception as error:
        print(f"Recovery failed: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
