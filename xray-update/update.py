#!/usr/bin/env python3
"""Transactional Xray core update through 3x-ui's official version API."""

from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path("/root/proxy-stack")
APP = pathlib.Path("/opt/proxy-stack")
STATE = pathlib.Path("/var/lib/proxy-stack")
CORE = STATE / "bin/xray-linux-amd64"
BACKUPS = ROOT / "upgrade-backups"

sys.path.insert(0, str(ROOT / "node"))
from panel_api import Panel  # noqa: E402


def run(*command: str, check: bool = True, timeout: int = 60):
    return subprocess.run(command, check=check, capture_output=True, text=True, timeout=timeout)


def ensure_runtime_core() -> None:
    source = APP / "bin/xray-linux-amd64"
    if not source.is_file():
        raise FileNotFoundError("Packaged Xray core is missing from /opt/proxy-stack/bin")
    folder = CORE.parent
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o750)
    try:
        user = pwd.getpwnam("proxy-ui")
    except KeyError as error:
        raise RuntimeError("proxy-ui account is missing") from error
    os.chown(folder, user.pw_uid, user.pw_gid)
    if not CORE.is_file():
        temporary = folder / ".xray-repair"
        shutil.copy2(source, temporary)
        temporary.chmod(0o755)
        os.chown(temporary, user.pw_uid, user.pw_gid)
        os.replace(temporary, CORE)


def core_version(path: pathlib.Path = CORE) -> str:
    result = run(str(path), "version")
    match = re.search(r"Xray\s+(\d+\.\d+\.\d+)", result.stdout + result.stderr)
    if not match:
        raise ValueError("Could not read installed Xray version")
    return match.group(1)


def check_panel() -> None:
    api = Panel()
    result = api.call("panel/api/inbounds/list")
    if len(result.get("obj") or []) < 2:
        raise RuntimeError("Panel health check did not find both managed inbounds")


def wait_panel() -> None:
    deadline = time.monotonic() + 90
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            check_panel()
            return
        except Exception as error:  # Retain the final concrete API failure for diagnostics.
            last_error = error
            time.sleep(2)
    raise RuntimeError(f"Panel API did not recover after core update: {last_error}")


def replace_core(source: pathlib.Path) -> None:
    folder = CORE.parent
    try:
        user = pwd.getpwnam("proxy-ui")
        owner = (user.pw_uid, user.pw_gid)
    except KeyError as error:
        raise RuntimeError("proxy-ui account is missing") from error
    fd, temporary_name = tempfile.mkstemp(prefix=".xray-restore-", dir=folder)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as destination, source.open("rb") as original:
            shutil.copyfileobj(original, destination)
            destination.flush()
            os.fsync(destination.fileno())
        temporary.chmod(0o755)
        os.chown(temporary, *owner)
        os.replace(temporary, CORE)
    finally:
        temporary.unlink(missing_ok=True)


def verify_service() -> None:
    check_panel()
    subprocess.run(
        [
            "/usr/bin/python3",
            str(ROOT / "node/verify-proxy.py"),
            "--client-bin",
            str(CORE),
        ],
        check=True,
        timeout=240,
    )


def write_status(status: dict) -> None:
    temporary = STATE / ".xray-update-status.tmp"
    temporary.write_text(json.dumps(status, indent=2) + "\n")
    temporary.chmod(0o644)
    os.replace(temporary, STATE / "xray-update-status.json")


def update(version: str) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Run Xray core updates as root")
    if version != "latest" and not re.fullmatch(r"v?\d+\.\d+\.\d+", version):
        raise ValueError("Version must be 'latest' or a numeric Xray release tag")

    lock_path = ROOT / "upgrade.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another panel or Xray update is running") from error

        ensure_runtime_core()
        current_version = core_version()
        stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = BACKUPS / f"core-{stamp}"
        backup.mkdir(mode=0o700, parents=True)
        backup_core = backup / "xray-linux-amd64"
        shutil.copy2(CORE, backup_core)
        backup_core.chmod(0o700)
        original_hash = hashlib.sha256(backup_core.read_bytes()).hexdigest()
        status = {
            "state": "pending",
            "requestedVersion": version,
            "previousVersion": current_version,
            "backup": str(backup),
            "startedAt": int(time.time()),
        }
        write_status(status)
        request_started = False
        try:
            api = Panel()
            request_started = True
            response = api.call(
                "panel/api/server/installXray/" + version,
                {},
                timeout=900,
            )
            status["panelResponse"] = response.get("msg", "accepted")
            wait_panel()
            new_version = core_version()
            if (
                new_version == current_version
                and version != "latest"
                and version.lstrip("v") != current_version
            ):
                raise RuntimeError("Panel update returned without changing the Xray version")
            verify_service()
            status.update(
                state="success",
                currentVersion=new_version,
                coreSHA256=hashlib.sha256(CORE.read_bytes()).hexdigest(),
                finishedAt=int(time.time()),
            )
            write_status(status)
            print(f"Xray core update passed local checks: {current_version} -> {new_version}")
        except BaseException as update_error:
            rollback_error: Exception | None = None
            if request_started:
                try:
                    replace_core(backup_core)
                    run("systemctl", "restart", "proxy-ui", timeout=120)
                    wait_panel()
                    if core_version() != current_version:
                        raise RuntimeError(
                            "Restored binary version does not match the saved version"
                        )
                except Exception as error:
                    rollback_error = error
            status.update(
                state="failed",
                error=str(update_error),
                rollbackError=str(rollback_error) if rollback_error else None,
                rollbackCoreSHA256=original_hash,
                finishedAt=int(time.time()),
            )
            write_status(status)
            if rollback_error:
                raise RuntimeError(
                    f"Xray update failed: {update_error}; rollback failed: {rollback_error}"
                ) from rollback_error
            raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="latest or an explicit Xray tag")
    args = parser.parse_args()
    try:
        update(args.version)
    except Exception as error:
        print(f"Xray core update failed: {error}", file=sys.stderr)
        print("Status: /var/lib/proxy-stack/xray-update-status.json", file=sys.stderr)
        print(
            "Logs: journalctl -u proxy-ui -u xray-core-update.service --since '-15 minutes'",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
