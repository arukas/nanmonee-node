#!/usr/bin/env python3
"""Verify the manifest checker against a manifest built from this checkout.

After the repository split the node tree is its own repository, so the tests no
longer read a panel-side build-*.json: they synthesise a record from the current
fingerprint and fill in the dependency digests of the files actually present,
then assert that a matching record passes while a tampered one is rejected.

The artifact digests are exercised against whatever binaries a local build left
in node/.build; when none exist the tests fall back to tracked files so the
tamper cases still run. A real release verifies the real artifacts by running
write_manifest.py --check against the generated manifest.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("write_manifest", Path(__file__).with_name("write_manifest.py"))
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)

DEPENDENCIES = {
    "core": {
        "source": "https://github.com/SagerNet/sing-box",
        "version": "v1.14.4",
        "commit": "c005f35300ce76427dc285481ec5695f5b179cd2",
        "license": "GPL-3.0-or-later",
        "patches": ["patches/sing-box-v1.14.4/0001-vless-hot-update.patch"],
        "patched_files": "patches/sing-box-v1.14.4/patched-files.sha256",
        "license_file": "patches/sing-box-v1.14.4/LICENSE",
    },
    "quic": {
        "source": "https://github.com/sagernet/sing-quic",
        "commit": "7e0a5869a5f49ed0a685143345dfda0448bbc708",
        "license": "GPL-3.0-or-later",
        "patches": ["patches/sing-quic-7e0a5869a5f4/0001-hysteria2-hot-update.patch"],
        "patched_files": "patches/sing-quic-7e0a5869a5f4/patched-files.sha256",
        "license_file": "patches/sing-quic-7e0a5869a5f4/LICENSE",
    },
    "anytls": {
        "source": "https://github.com/anytls/sing-anytls",
        "version": "v0.0.11",
        "commit": "130d2e61b8895727bfed4942c535e91b246a9603",
        "license": "MIT",
        "patches": ["patches/sing-anytls-130d2e61b889/0001-anytls-hot-update.patch"],
        "patched_files": "patches/sing-anytls-130d2e61b889/patched-files.sha256",
        "license_file": "patches/sing-anytls-130d2e61b889/LICENSE",
    },
}
BUILT_ARTIFACTS = ("node/.build/nanmonee-node", "node/.build/nanmonee-nodectl")
FALLBACK_ARTIFACTS = ("node/api/node/v1/node_control.proto", "node/scripts/build.sh")


def artifacts() -> tuple[str, ...]:
    if all((ROOT / path).is_file() for path in BUILT_ARTIFACTS):
        return BUILT_ARTIFACTS
    return FALLBACK_ARTIFACTS


def synthesise() -> dict:
    record = {
        "sources": {
            "node": {"commit": manifest.git_head() or "0" * 40},
            "panel": {"commit": "1" * 40, "role": manifest.PANEL_ROLE},
        }
    }
    record.update(manifest.fingerprint())
    for name, dependency in DEPENDENCIES.items():
        record[name] = copy.deepcopy(dependency)
        record[name]["patches"] = [
            {"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}
            for path in dependency["patches"]
        ]
        record[name]["patched_files_sha256"] = hashlib.sha256(
            (ROOT / dependency["patched_files"]).read_bytes()
        ).hexdigest()
        record[name]["license_sha256"] = hashlib.sha256(
            (ROOT / dependency["license_file"]).read_bytes()
        ).hexdigest()
    record["artifacts"] = [
        {"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}
        for path in artifacts()
    ]
    return record


class ManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="nanmonee-manifest-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "manifest.json"
        self.record = synthesise()

    def check(self, record):
        self.path.write_text(json.dumps(record))
        with contextlib.redirect_stdout(io.StringIO()):
            return manifest.check(self.path)

    def test_build_inputs_are_fingerprinted(self):
        sources = self.record["source_files_sha256"]
        for path in ("node/go.mod", "node/go.sum", "node/api/node/v1/node_control.proto"):
            with self.subTest(path=path):
                self.assertIn(path, sources)

    def test_the_record_covers_only_this_repository(self):
        self.assertNotIn("panel_files_sha256", self.record)
        for path in self.record["source_files_sha256"]:
            self.assertFalse(path.startswith(("app/", "resources/", "tests/")), path)
        for path in self.record["source_files_sha256"]:
            self.assertNotIn("__pycache__", path)

    def test_matching_manifest_is_accepted(self):
        self.assertEqual(self.check(self.record), 0)

    def test_a_record_without_the_panel_commit_is_rejected(self):
        changed = copy.deepcopy(self.record)
        del changed["sources"]["panel"]
        self.assertEqual(self.check(changed), 1)

    def test_a_short_panel_commit_is_rejected(self):
        changed = copy.deepcopy(self.record)
        changed["sources"]["panel"]["commit"] = "61d82c7"
        self.assertEqual(self.check(changed), 1)

    def test_the_panel_commit_must_stay_a_migration_origin(self):
        for role in (None, "build-input"):
            with self.subTest(role=role):
                changed = copy.deepcopy(self.record)
                if role is None:
                    changed["sources"]["panel"].pop("role", None)
                else:
                    changed["sources"]["panel"]["role"] = role
                self.assertEqual(self.check(changed), 1)

    def test_a_node_commit_that_is_not_this_checkout_is_rejected(self):
        changed = copy.deepcopy(self.record)
        changed["sources"]["node"]["commit"] = "d" * 40
        self.assertEqual(self.check(changed), 1)

    def test_a_wrong_licence_digest_is_rejected(self):
        for section in DEPENDENCIES:
            with self.subTest(section=section):
                changed = copy.deepcopy(self.record)
                changed[section]["license_sha256"] = "0" * 64
                self.assertEqual(self.check(changed), 1)

    def test_a_missing_artifact_is_rejected(self):
        changed = copy.deepcopy(self.record)
        changed["artifacts"][0]["path"] = "node/.build/not-built"
        self.assertEqual(self.check(changed), 1)

    def test_changed_recorded_inputs_patches_and_artifacts_are_rejected(self):
        for section, field in (("inputs", "go_mod_sha256"), ("core", "patched_files_sha256")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.record)
                changed[section][field] = "0" * 64
                self.assertEqual(self.check(changed), 1)
        for section in DEPENDENCIES:
            with self.subTest(section=section):
                changed = copy.deepcopy(self.record)
                changed[section]["patches"][0]["sha256"] = "0" * 64
                self.assertEqual(self.check(changed), 1)
        changed = copy.deepcopy(self.record)
        changed["artifacts"][0]["sha256"] = "0" * 64
        self.assertEqual(self.check(changed), 1)

    def test_an_unrecorded_source_file_is_rejected(self):
        changed = copy.deepcopy(self.record)
        changed["source_files_sha256"]["node/scripts/unrecorded.py"] = "0" * 64
        self.assertEqual(self.check(changed), 1)

    def test_a_removed_recorded_source_file_is_rejected(self):
        changed = copy.deepcopy(self.record)
        changed["source_files_sha256"].pop("node/go.mod")
        self.assertEqual(self.check(changed), 1)


if __name__ == "__main__":
    unittest.main()
