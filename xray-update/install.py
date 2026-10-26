#!/usr/bin/env python3
"""Install the opt-in Xray core update timer and transactional updater."""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess

SOURCE = pathlib.Path(__file__).resolve().parent
TARGET = pathlib.Path("/usr/local/libexec/xray-core-update")
UNITS = pathlib.Path("/etc/systemd/system")


def install(enable_timer: bool) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Run as root")
    TARGET.mkdir(mode=0o755, parents=True, exist_ok=True)
    TARGET.chmod(0o755)
    shutil.copy2(SOURCE / "update.py", TARGET / "update.py")
    (TARGET / "update.py").chmod(0o755)
    for name in ("xray-core-update.service", "xray-core-update.timer"):
        shutil.copy2(SOURCE / name, UNITS / name)
        (UNITS / name).chmod(0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    if enable_timer:
        subprocess.run(["systemctl", "enable", "--now", "xray-core-update.timer"], check=True)
    print("Xray transactional updater installed; scheduled updates are disabled by default.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-timer", action="store_true")
    args = parser.parse_args()
    install(args.enable_timer)


if __name__ == "__main__":
    main()
