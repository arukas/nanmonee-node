#!/usr/bin/env python3
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SING_BOX_SOURCE = ROOT / ".cache/sing-box-v1.14.4"
SING_BOX_PATCHES = ROOT.parent / "patches/sing-box-v1.14.4"
SING_QUIC_SOURCE = ROOT / ".cache/sing-quic-7e0a5869a5f4"
SING_QUIC_PATCHES = ROOT.parent / "patches/sing-quic-7e0a5869a5f4"
SING_ANYTLS_SOURCE = ROOT / ".cache/sing-anytls-130d2e61b889"
SING_ANYTLS_PATCHES = ROOT.parent / "patches/sing-anytls-130d2e61b889"


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nanmonee-prepare-test-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.sing_box = root / "node/.cache/sing-box-v1.14.4"
        self.sing_quic = root / "node/.cache/sing-quic-7e0a5869a5f4"
        self.sing_anytls = root / "node/.cache/sing-anytls-130d2e61b889"
        scripts = root / "node/scripts"
        sing_box_patches = root / "patches/sing-box-v1.14.4"
        sing_quic_patches = root / "patches/sing-quic-7e0a5869a5f4"
        sing_anytls_patches = root / "patches/sing-anytls-130d2e61b889"
        for directory in (scripts, sing_box_patches, sing_quic_patches, sing_anytls_patches, self.sing_box.parent):
            directory.mkdir(parents=True)
        self.script = scripts / "prepare.sh"
        shutil.copy2(ROOT / "scripts/prepare.sh", self.script)
        for name in [
            "0001-vless-hot-update.patch",
            "0002-hysteria2-hot-update.patch",
            "0003-anytls-hot-update.patch",
            "0004-tuic-hot-update.patch",
            "patched-files.sha256",
        ]:
            shutil.copy2(SING_BOX_PATCHES / name, sing_box_patches / name)
        for name in ["0001-hysteria2-hot-update.patch", "0002-tuic-hot-update.patch", "patched-files.sha256"]:
            shutil.copy2(SING_QUIC_PATCHES / name, sing_quic_patches / name)
        for name in ["0001-anytls-hot-update.patch", "0002-client-hook-race.patch", "0003-session-identity-and-close-hooks.patch", "patched-files.sha256"]:
            shutil.copy2(SING_ANYTLS_PATCHES / name, sing_anytls_patches / name)
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(SING_BOX_SOURCE), str(self.sing_box)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(SING_QUIC_SOURCE), str(self.sing_quic)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(SING_ANYTLS_SOURCE), str(self.sing_anytls)],
            check=True, capture_output=True, text=True,
        )

    def prepare(self):
        return subprocess.run(["sh", str(self.script)], capture_output=True, text=True)

    def assert_prepared(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_clean_source_and_repeated_preparation(self):
        self.assert_prepared()
        self.assert_prepared()

    def test_a_partially_patched_cache_is_reapplied(self):
        # An interrupted run leaves one file reverted while the patch-added test
        # files are still untracked; that state used to be unrecoverable because
        # a plain checkout cannot remove the added files.
        self.assert_prepared()
        subprocess.run(
            ["git", "-C", str(self.sing_box), "checkout", "--", "protocol/tuic/inbound.go"],
            check=True, capture_output=True, text=True,
        )
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("partially patched", result.stderr)
        self.assert_prepared()

    def test_a_tampered_patched_file_is_rejected(self):
        self.assert_prepared()
        path = self.sing_box / "protocol/vless/inbound.go"
        before = path.read_bytes()
        try:
            path.write_bytes(before + b"\nfunc unexpectedUnrecordedChange() bool { return true }\n")
            result = self.prepare()
            self.assertNotEqual(result.returncode, 0, "tampered patch contents were accepted")
        finally:
            path.write_bytes(before)

    def test_extra_changes_in_each_patched_file_are_rejected(self):
        self.assert_prepared()
        for tree, names in (
            (self.sing_box, [
                "protocol/vless/inbound.go",
                "protocol/vless/nanmonee_hot_update_test.go",
                "protocol/hysteria2/inbound.go",
                "protocol/hysteria2/nanmonee_hot_update_test.go",
                "protocol/anytls/inbound.go",
                "protocol/anytls/nanmonee_hot_update_test.go",
                "protocol/tuic/inbound.go",
                "protocol/tuic/nanmonee_hot_update_test.go",
            ]),
            (self.sing_quic, [
                "hysteria2/service.go",
                "hysteria2/service_packet.go",
                "tuic/service.go",
                "tuic/service_test.go",
            ]),
            (self.sing_anytls, [
                "service.go",
                "session/client.go",
                "session/session.go",
                "session/stream.go",
                "service_test.go",
                "session/hook_test.go",
            ]),
        ):
            for name in names:
                with self.subTest(name=name):
                    path = tree / name
                    before = path.read_bytes()
                    try:
                        path.write_bytes(before + b"\nfunc unexpectedUnrecordedChange() bool { return true }\n")
                        result = self.prepare()
                        self.assertNotEqual(result.returncode, 0, "modified patch contents were accepted")
                    finally:
                        path.write_bytes(before)

    def test_untracked_source_before_patch_is_rejected(self):
        path = self.sing_box / "protocol/vless/unrecorded.go"
        path.write_text("package vless\n")
        before = (self.sing_box / "protocol/vless/inbound.go").read_bytes()
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0, "untracked source was accepted before patching")
        self.assertEqual((self.sing_box / "protocol/vless/inbound.go").read_bytes(), before)

    def test_untracked_source_after_patch_is_rejected(self):
        self.assert_prepared()
        (self.sing_box / "protocol/vless/unrecorded.go").write_text("package vless\n")
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_untracked_quic_source_after_patch_is_rejected(self):
        self.assert_prepared()
        (self.sing_quic / "hysteria2/unrecorded.go").write_text("package hysteria2\n")
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_other_tracked_changes_are_rejected(self):
        self.assert_prepared()
        for tree in (self.sing_box, self.sing_quic, self.sing_anytls):
            with self.subTest(tree=tree.name):
                path = tree / "go.mod"
                before = path.read_text()
                try:
                    path.write_text(before + "\n// unexpected dependency change\n")
                    self.assertNotEqual(self.prepare().returncode, 0)
                finally:
                    path.write_text(before)

    def test_a_missing_hysteria2_patch_is_rejected(self):
        (self.sing_box.parents[2] / "patches/sing-box-v1.14.4/0002-hysteria2-hot-update.patch").unlink()
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_a_missing_anytls_patch_is_rejected(self):
        (self.sing_box.parents[2] / "patches/sing-box-v1.14.4/0003-anytls-hot-update.patch").unlink()
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_a_missing_tuic_inbound_patch_is_rejected(self):
        (self.sing_box.parents[2] / "patches/sing-box-v1.14.4/0004-tuic-hot-update.patch").unlink()
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_a_missing_hook_race_patch_is_rejected(self):
        (self.sing_box.parents[2] / "patches/sing-anytls-130d2e61b889/0002-client-hook-race.patch").unlink()
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_a_missing_tuic_quic_patch_is_rejected(self):
        (self.sing_box.parents[2] / "patches/sing-quic-7e0a5869a5f4/0002-tuic-hot-update.patch").unlink()
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_a_missing_anytls_followup_patch_is_rejected(self):
        (self.sing_box.parents[2] / "patches/sing-anytls-130d2e61b889/0003-session-identity-and-close-hooks.patch").unlink()
        self.assertNotEqual(self.prepare().returncode, 0)

    def test_untracked_anytls_source_after_patch_is_rejected(self):
        self.assert_prepared()
        (self.sing_anytls / "session/unrecorded.go").write_text("package session\n")
        self.assertNotEqual(self.prepare().returncode, 0)


if __name__ == "__main__":
    unittest.main()
