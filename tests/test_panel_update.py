"""Offline tests for the restricted update bridge and rollback transaction."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import pathlib
import sqlite3
import subprocess
import tempfile
import types
import unittest
from contextlib import closing
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parents[1] / "panel-update"
shim_loader = importlib.machinery.SourceFileLoader("update_shim", str(HERE / "systemd-run"))
shim = types.ModuleType("update_shim")
shim_loader.exec_module(shim)
worker_spec = importlib.util.spec_from_file_location("update_worker", HERE / "worker.py")
worker = importlib.util.module_from_spec(worker_spec)
worker_spec.loader.exec_module(worker)


def valid_args() -> list[str]:
    args = ["--unit", "x-ui-web-update-123"]
    values = {
        "XUI_MAIN_FOLDER": "/opt/proxy-stack",
        "XUI_SERVICE": "/etc/systemd/system",
        "XUI_UPDATE_TAG": "",
        "XUI_UPDATE_RUN_ID": "123",
        "XUI_UPDATE_STATUS_FILE": "/var/lib/proxy-stack/update-status.json",
    }
    for key, value in values.items():
        args.extend(("--setenv", f"{key}={value}"))
    args.extend(
        (
            "/usr/bin/bash",
            "-lc",
            "set -e; trap 'rm -f '/tmp/3x-ui-update-123.sh'' EXIT; "
            "'/usr/bin/bash' '/tmp/3x-ui-update-123.sh'",
        )
    )
    return args


class BridgeTests(unittest.TestCase):
    def test_adapter_accepts_only_managed_stable_update(self) -> None:
        request, cleanup = shim.parse(valid_args())
        self.assertEqual(request, {"runId": "123", "channel": "stable"})
        self.assertEqual(cleanup, {"/tmp/3x-ui-update-123.sh"})

    def test_adapter_rejects_custom_commands_paths_and_channels(self) -> None:
        valid = valid_args()
        invalid = [
            [*valid, "extra"],
            [item.replace("XUI_UPDATE_TAG=", "XUI_UPDATE_TAG=dev") for item in valid],
            [item.replace("/opt/proxy-stack", "/tmp/other") for item in valid],
            [item.replace("/tmp/3x-ui-update-123.sh", "$(id)") for item in valid],
        ]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises((ValueError, IndexError)):
                shim.parse(args)

    def test_update_request_rejects_shell_text_and_extra_fields(self) -> None:
        for request in (
            {"runId": "$(id)", "channel": "stable"},
            {"runId": "123", "channel": "dev"},
            {"runId": "123", "channel": "stable", "command": "id"},
        ):
            with self.subTest(request=request), self.assertRaises(ValueError):
                worker.request(request)

    def test_release_asset_url_and_digest_are_pinned(self) -> None:
        release = {
            "tag_name": "v3.8.0",
            "assets": [
                {
                    "name": "x-ui-linux-amd64.tar.gz",
                    "digest": "sha256:" + "a" * 64,
                    "browser_download_url": "https://evil.example/file",
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "Unexpected release asset URL"):
            worker.release_asset(release)

    def test_state_restore_keeps_authorized_mountpoint_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "snapshot"
            destination = root / "state"
            source.mkdir()
            destination.mkdir()
            (source / "bin").mkdir()
            (source / "bin/xray-linux-amd64").write_text("saved core")
            (destination / "obsolete").write_text("partial state")
            original_inode = destination.stat().st_ino
            worker.restore_tree_contents(source, destination)
            self.assertEqual(destination.stat().st_ino, original_inode)
            self.assertFalse((destination / "obsolete").exists())
            self.assertEqual((destination / "bin/xray-linux-amd64").read_text(), "saved core")

    def test_panel_update_rolls_back_files_and_database_after_failed_validation(self) -> None:
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                worker.B = root
                worker.APP = root / "app"
                worker.STATE = root / "state"
                worker.APP.mkdir()
                worker.STATE.mkdir()
                (worker.APP / "x-ui").write_text("old panel")
                with closing(sqlite3.connect(worker.STATE / "x-ui.db")) as database, database:
                    database.execute("CREATE TABLE marker(value TEXT)")
                    database.execute("INSERT INTO marker VALUES ('original')")
                candidate = root / "candidate"
                candidate.mkdir()
                (candidate / "x-ui").write_text("new panel")
                backup = root / "backup"
                backup.mkdir()
                commands: list[tuple] = []

                def fake_run(*command, fail=fail, commands=commands, **kwargs):
                    commands.append(command)
                    if fail and any("verify-proxy.py" in str(argument) for argument in command):
                        raise RuntimeError("injected validation failure")
                    return subprocess.CompletedProcess(command, 0)

                fake_user = types.SimpleNamespace(pw_uid=0, pw_gid=0)
                with (
                    mock.patch.object(worker, "run", side_effect=fake_run),
                    mock.patch.object(worker, "panel_health"),
                    mock.patch.object(
                        worker.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
                    ),
                    mock.patch.object(worker.pwd, "getpwnam", return_value=fake_user),
                ):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "injected validation failure"):
                            worker.activate(candidate, backup)
                    else:
                        worker.activate(candidate, backup)

                expected_panel = "old panel" if fail else "new panel"
                self.assertEqual((worker.APP / "x-ui").read_text(), expected_panel)
                with closing(sqlite3.connect(worker.STATE / "x-ui.db")) as database:
                    self.assertEqual(
                        database.execute("SELECT value FROM marker").fetchone()[0], "original"
                    )
                self.assertEqual(commands[-1], ("systemctl", "start", "song-profiles.timer"))


if __name__ == "__main__":
    unittest.main()
