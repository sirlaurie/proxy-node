"""Offline regression checks for seed validation and migration safeguards."""

from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))

import migration_lib as lib  # noqa: E402
import register_node  # noqa: E402


def seed_directory(root: pathlib.Path) -> pathlib.Path:
    (root / "snapshot").mkdir(parents=True)
    (root / "app/bin").mkdir(parents=True)
    (root / "units").mkdir()
    with closing(sqlite3.connect(root / "snapshot/x-ui.db")) as database, database:
        database.execute(
            "CREATE TABLE inbounds (id INTEGER PRIMARY KEY, protocol TEXT, node_id INTEGER)"
        )
        database.executemany(
            "INSERT INTO inbounds(protocol, node_id) VALUES (?, ?)",
            [("vless", None), ("hysteria", None)],
        )
    (root / "app/x-ui").write_text("panel binary placeholder")
    (root / "app/bin/xray-linux-amd64").write_text("xray binary placeholder")
    (root / "metadata.json").write_text(
        json.dumps(
            {
                "formatVersion": 1,
                "architecture": "x86_64",
                "domain": "source.example",
                "panelPath": "/manage-x/",
            }
        )
    )
    (root / "nginx-http.conf").write_text("server_name source.example;")
    (root / "renew-hook").write_text("#!/bin/sh\n")
    (root / "units/proxy-ui.service").write_text("[Service]\n")
    (root / "manifest.json").write_text(json.dumps(lib.make_manifest(root), sort_keys=True))
    return root


class SeedTests(unittest.TestCase):
    def test_manifest_accepts_files_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            seed = seed_directory(pathlib.Path(directory) / "seed")
            self.assertEqual(len(lib.verify_seed(seed)), 64)
            (seed / "app/x-ui").write_text("x" * len("panel binary placeholder"))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                lib.verify_seed(seed)

    def test_manifest_rejects_unlisted_files_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            seed = seed_directory(pathlib.Path(directory) / "seed")
            (seed / "unlisted").write_text("unexpected")
            with self.assertRaisesRegex(ValueError, "file list"):
                lib.verify_seed(seed)
            (seed / "unlisted").unlink()
            (seed / "symlink").symlink_to(seed / "metadata.json")
            with self.assertRaisesRegex(ValueError, "symlinks"):
                lib.verify_seed(seed)

    def test_resume_requires_same_identity_and_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "state.json"
            identity = {"seed": "abc", "domain": "node.example", "ip": "203.0.113.1"}
            lib.save_state(path, {"identity": identity, "generated": {"secret": "same"}})
            with self.assertRaisesRegex(ValueError, "different seed"):
                lib.load_state(path, {**identity, "domain": "other.example"}, True)
            with self.assertRaisesRegex(ValueError, "use --resume"):
                lib.load_state(path, identity, False)
            self.assertEqual(lib.load_state(path, identity, True)["generated"]["secret"], "same")

    def test_database_pruning_keeps_only_local_protocols(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = sqlite3.connect(pathlib.Path(directory) / "panel.db")
            database.execute("CREATE TABLE inbounds (id INTEGER, protocol TEXT, node_id INTEGER)")
            database.executemany(
                "INSERT INTO inbounds VALUES (?, ?, ?)",
                [(1, "vless", 0), (2, "hysteria", None), (3, "vless", 9)],
            )
            database.execute("CREATE TABLE hosts (inbound_id INTEGER)")
            database.executemany("INSERT INTO hosts VALUES (?)", [(1,), (2,), (3,)])
            database.execute("CREATE TABLE nodes (id INTEGER)")
            database.execute("INSERT INTO nodes VALUES (9)")
            lib.prune_remote(database)
            rows = database.execute("SELECT protocol, node_id FROM inbounds ORDER BY id").fetchall()
            self.assertEqual(rows, [("vless", 0), ("hysteria", None)])
            self.assertEqual(
                database.execute("SELECT inbound_id FROM hosts ORDER BY inbound_id").fetchall(),
                [(1,), (2,)],
            )
            self.assertEqual(database.execute("SELECT COUNT(*) FROM nodes").fetchone()[0], 0)
            database.close()

    def test_stream_rewrite_does_not_use_the_new_node_as_reality_target(self) -> None:
        stream = {
            "realitySettings": {"dest": "source.example:443", "serverNames": ["source.example"]},
            "externalProxy": [{"dest": "source.example", "port": 443}],
        }
        updated = lib.adapt_stream(stream, "source.example", "node.example", "www.apple.com")
        self.assertEqual(updated["realitySettings"]["dest"], "www.apple.com:443")
        self.assertEqual(updated["externalProxy"][0]["dest"], "node.example")

    def test_stale_aaaa_is_rejected(self) -> None:
        answers = [
            (0, 0, 0, "", ("203.0.113.5", 80)),
            (0, 0, 0, "", ("2001:db8::1", 80, 0, 0)),
        ]
        with (
            patch.object(lib.socket, "getaddrinfo", return_value=answers),
            self.assertRaisesRegex(ValueError, "remove stale AAAA"),
        ):
            lib.check_dns("node.example", "203.0.113.5")

    def test_app_permissions_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = pathlib.Path(directory)
            (app / "bin").mkdir()
            for path in (app / "x-ui", app / "bin/xray-linux-amd64", app / "bin/geosite.dat"):
                path.write_text("placeholder")
                path.chmod(0o600)
            lib.normalize_app(app)
            self.assertEqual((app / "x-ui").stat().st_mode & 0o777, 0o755)
            self.assertEqual((app / "bin/geosite.dat").stat().st_mode & 0o777, 0o644)


class RegistrationTests(unittest.TestCase):
    def test_self_loop_is_rejected(self) -> None:
        bad = [{"id": 1, "streamSettings": {"realitySettings": {"dest": "node.example:443"}}}]
        with self.assertRaisesRegex(ValueError, "points back"):
            register_node.validate_inbounds(bad, "node.example")

    def test_hosts_group_shared_with_old_node_is_rejected(self) -> None:
        api = type("FakePanel", (), {})()
        api.call = lambda path: {
            "obj": [{"groupId": "shared", "inboundIds": [10, 20], "hosts": ["old.example:443"]}]
        }
        with self.assertRaisesRegex(ValueError, "spans multiple servers"):
            register_node.set_hosts(api, [20], "node.example", "node")


if __name__ == "__main__":
    unittest.main()
