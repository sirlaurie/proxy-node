#!/usr/bin/python3
"""Root-owned, socket-activated stable panel updater. Never accepts commands or URLs."""

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
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from contextlib import suppress

B = pathlib.Path("/root/proxy-stack")
APP = pathlib.Path("/opt/proxy-stack")
STATE = pathlib.Path("/var/lib/proxy-stack")
CORE = STATE / "bin/xray-linux-amd64"
API = "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest"


def run(*args, **kw):
    return subprocess.run(args, check=True, timeout=kw.pop("timeout", 180), **kw)


def version(text):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", text.strip())
    if not match:
        raise ValueError("Unsupported panel version")
    return tuple(map(int, match.groups()))


def request(data):
    if not isinstance(data, dict) or set(data) != {"runId", "channel"}:
        raise ValueError("Invalid request fields")
    if (
        data["channel"] != "stable"
        or not isinstance(data["runId"], str)
        or not re.fullmatch(r"[0-9]{1,20}", data["runId"])
    ):
        raise ValueError("Only stable updates with a numeric run ID are supported")
    return data["runId"]


def status(run_id, state, code=0):
    obj = {
        "runId": run_id,
        "state": state,
        "exitCode": code,
        "finishedAt": 0 if state == "pending" else int(time.time()),
    }
    fd, path = tempfile.mkstemp(prefix=".update-status-", dir=STATE)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    os.chmod(path, 0o644)
    os.replace(path, STATE / "update-status.json")


def fetch(url, path, limit):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "managed-3x-ui-updater",
            "Accept": "application/vnd.github+json" if url == API else "application/octet-stream",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as response, path.open("wb") as f:
        count = 0
        while block := response.read(1024 * 1024):
            count += len(block)
            if count > limit:
                raise ValueError("Download exceeds size limit")
            f.write(block)


def release_asset(release):
    tag = release["tag_name"]
    version(tag)
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("Not a stable release")
    asset = next(a for a in release["assets"] if a["name"] == "x-ui-linux-amd64.tar.gz")
    digest = asset.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Official SHA256 digest is required")
    url = f"https://github.com/MHSanaei/3x-ui/releases/download/{tag}/x-ui-linux-amd64.tar.gz"
    if asset["browser_download_url"] != url:
        raise ValueError("Unexpected release asset URL")
    return tag, url, digest[7:]


def panel_health():
    sys.path.insert(0, str(B / "node"))
    from panel_api import Panel

    for attempt in range(30):
        try:
            api = Panel()
            inbounds = api.call("panel/api/inbounds/list")["obj"]
            if len(inbounds) < 2:
                raise RuntimeError("Missing managed inbounds")
            return
        except Exception:
            if attempt == 29:
                raise
            time.sleep(2)


def restore_tree_contents(source, destination):
    """Restore a state snapshot without removing its ReadWritePaths mountpoint."""
    destination.mkdir(parents=True, exist_ok=True)
    for entry in list(destination.iterdir()):
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


def ensure_runtime_core():
    """Repair a missing mutable bin directory before the panel writes config there."""
    binary = APP / "bin/xray-linux-amd64"
    if not binary.is_file():
        raise FileNotFoundError("Packaged Xray core is missing from /opt/proxy-stack/bin")
    folder = STATE / "bin"
    folder.mkdir(mode=0o750, parents=True, exist_ok=True)
    folder.chmod(0o750)
    try:
        user = pwd.getpwnam("proxy-ui")
    except KeyError as error:
        raise RuntimeError("proxy-ui account is missing") from error
    os.chown(folder, user.pw_uid, user.pw_gid)
    if not CORE.is_file():
        temporary = folder / ".xray-repair"
        shutil.copy2(binary, temporary)
        temporary.chmod(0o755)
        os.chown(temporary, user.pw_uid, user.pw_gid)
        os.replace(temporary, CORE)
    for item in (APP / "bin").iterdir():
        if item.name in ("config.json", "xray-linux-amd64") or not item.is_file():
            continue
        target = folder / item.name
        if not target.exists():
            shutil.copy2(item, target)
            target.chmod(0o644)
            os.chown(target, user.pw_uid, user.pw_gid)


def activate(candidate, backup):
    """Snapshot stopped DB, swap panel files, validate, and restore on any failure."""
    previous = APP.with_name("proxy-stack.previous-" + backup.name)
    timer_active = (
        subprocess.run(["systemctl", "is-active", "--quiet", "song-profiles.timer"]).returncode == 0
    )
    swapped = False
    stopped = False
    try:
        run("systemctl", "stop", "song-profiles.timer", "song-profiles.service")
        run("systemctl", "stop", "proxy-ui")
        stopped = True
        shutil.copytree(STATE, backup / "state", symlinks=True)
        db = sqlite3.connect(backup / "state/x-ui.db")
        try:
            if db.execute("pragma integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup DB failed integrity check")
        finally:
            db.close()
        os.rename(APP, previous)
        swapped = True
        os.rename(candidate, APP)
        run("systemctl", "start", "proxy-ui")
        panel_health()
        run("/usr/bin/python3", str(B / "node/export-profiles.py"))
        run(
            "/usr/bin/python3",
            str(B / "node/verify-proxy.py"),
            "--client-bin",
            str(CORE),
            timeout=180,
        )
        return str(previous)
    except BaseException as update_error:
        rollback_error = None
        try:
            if swapped:
                run("systemctl", "stop", "proxy-ui")
                if APP.exists():
                    os.rename(APP, APP.with_name("proxy-stack.failed-" + backup.name))
                os.rename(previous, APP)
                restore_tree_contents(backup / "state", STATE)
                user = pwd.getpwnam("proxy-ui")
                for root, _dirs, files in os.walk(STATE):
                    os.chown(root, user.pw_uid, user.pw_gid)
                    for name in files:
                        p = pathlib.Path(root) / name
                        if not p.is_symlink():
                            os.chown(p, user.pw_uid, user.pw_gid)
            if stopped:
                run("systemctl", "start", "proxy-ui")
                if swapped:
                    panel_health()
                    run("/usr/bin/python3", str(B / "node/export-profiles.py"))
        except BaseException as error:
            rollback_error = error
        if rollback_error:
            raise RuntimeError(
                f"Update failed: {update_error}; rollback failed: {rollback_error}"
            ) from rollback_error
        raise
    finally:
        if timer_active:
            run("systemctl", "start", "song-profiles.timer")


def perform_update(run_id, force=False):
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + run_id
    backup = B / "upgrade-backups" / ("panel-" + stamp)
    backup.mkdir(parents=True, mode=0o700)
    result = {"runId": run_id, "state": "pending", "corePolicy": "preserve"}
    try:
        ensure_runtime_core()
        with tempfile.TemporaryDirectory(prefix="panel-update-", dir="/opt") as td:
            stage = pathlib.Path(td)
            fetch(API, stage / "release.json", 2 * 1024 * 1024)
            release = json.loads((stage / "release.json").read_text())
            tag, url, digest = release_asset(release)
            current = run(str(APP / "x-ui"), "-v", capture_output=True, text=True).stdout.strip()
            result.update(currentVersion=current, targetVersion=tag)
            if version(tag) <= version(current) and not (
                force and version(tag) == version(current)
            ):
                result["action"] = "already-current"
                print("Panel is already current:", current, flush=True)
            else:
                fetch(url, stage / "release.tar.gz", 512 * 1024 * 1024)
                if hashlib.sha256((stage / "release.tar.gz").read_bytes()).hexdigest() != digest:
                    raise ValueError("Release SHA256 mismatch")
                # Extract only the embedded-web panel binary; retain all validated core/assets/helpers.
                with tarfile.open(stage / "release.tar.gz", "r:gz") as archive:
                    entries = [
                        m for m in archive.getmembers() if m.name in ("x-ui/x-ui", "./x-ui/x-ui")
                    ]
                    if (
                        len(entries) != 1
                        or not entries[0].isfile()
                        or entries[0].size > 256 * 1024 * 1024
                    ):
                        raise ValueError("Invalid panel binary in archive")
                    with (
                        archive.extractfile(entries[0]) as source,
                        (stage / "x-ui").open("wb") as dest,
                    ):
                        shutil.copyfileobj(source, dest)
                (stage / "x-ui").chmod(0o755)
                installed = run(
                    str(stage / "x-ui"), "-v", capture_output=True, text=True
                ).stdout.strip()
                if version(installed) != version(tag):
                    raise ValueError("Candidate version mismatch")
                candidate = stage / "candidate"
                shutil.copytree(APP, candidate, symlinks=True)
                shutil.copy2(stage / "x-ui", candidate / "x-ui")
                result["coreSHA256"] = hashlib.sha256(CORE.read_bytes()).hexdigest()
                shutil.copy2(stage / "release.json", backup / "release.json")
                result["previousApp"] = activate(candidate, backup)
                if hashlib.sha256(CORE.read_bytes()).hexdigest() != result["coreSHA256"]:
                    raise RuntimeError("Core unexpectedly changed")
                result["action"] = "updated"
                result["sha256"] = digest
            result["state"] = "success"
            status(run_id, "success")
    except BaseException as error:
        result.update(state="failed", error=str(error))
        status(run_id, "failed", 1)
        raise
    finally:
        (backup / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result), flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--reinstall", action="store_true")
    args = p.parse_args()
    os.umask(0o077)

    def interrupted(signum, frame):
        raise RuntimeError("Update interrupted by signal " + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    conn = None
    accepted = False
    run_id = None
    lock = (B / "upgrade.lock").open("a")
    try:
        if args.reinstall:
            if os.geteuid() != 0:
                raise PermissionError("Root required")
            run_id = str(time.time_ns())
        else:
            conn = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(5)
            _pid, uid, _gid = struct.unpack(
                "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != pwd.getpwnam("proxy-ui").pw_uid:
                raise PermissionError("Panel account required")
            data = b""
            while b"\n" not in data:
                part = conn.recv(1024)
                if not part or len(data) + len(part) > 1024:
                    raise ValueError("Invalid request size")
                data += part
            run_id = request(json.loads(data))
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status(run_id, "pending")
        if conn:
            conn.sendall(b'{"accepted":true}\n')
            conn.close()
            conn = None
        accepted = True
        perform_update(run_id, force=args.reinstall)
    except Exception as error:
        if conn:
            with suppress(OSError):
                conn.sendall(json.dumps({"accepted": False, "error": str(error)}).encode() + b"\n")
        if accepted and run_id:
            status(run_id, "failed", 1)
        print("Panel update:", str(error), file=sys.stderr)
        sys.exit(1)
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    main()
