#!/usr/bin/python3
import os
import pathlib
import shutil
import subprocess

assert os.geteuid() == 0
source = pathlib.Path(__file__).resolve().parent
target = pathlib.Path("/usr/local/libexec/xray-panel-update")
target.mkdir(parents=True, exist_ok=True)
target.chmod(0o755)
for name in ["systemd-run", "worker.py"]:
    shutil.copyfile(source / name, target / name)
    (target / name).chmod(0o755)
for name in ["xray-panel-update.socket", "xray-panel-update@.service"]:
    shutil.copyfile(source / name, pathlib.Path("/etc/systemd/system") / name)
    pathlib.Path("/etc/systemd/system", name).chmod(0o644)
drop = pathlib.Path("/etc/systemd/system/proxy-ui.service.d")
drop.mkdir(exist_ok=True)
(drop / "panel-update.conf").write_text(
    "[Service]\n"
    "Environment=PATH=/usr/local/libexec/xray-panel-update:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "BindReadOnlyPaths=/usr/local/libexec/xray-panel-update/systemd-run:/usr/bin/systemd-run\n"
)
(drop / "panel-update.conf").chmod(0o644)
subprocess.run(["systemctl", "daemon-reload"], check=True)
subprocess.run(["systemctl", "enable", "--now", "xray-panel-update.socket"], check=True)
print("Panel update bridge installed; restart proxy-ui to activate its scoped systemd-run wrapper.")
