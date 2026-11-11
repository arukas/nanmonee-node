#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("deployment_acceptance", Path(__file__).with_name("deployment_acceptance.py"))
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


class DeploymentAcceptanceTests(unittest.TestCase):
    def test_acceptance_only_probes_and_restarts_the_selected_node(self):
        self.check_restart([])

    def test_successful_reporting_can_drain_pending_batches_during_restart(self):
        self.check_restart([{"batch_id": "pending-before-restart"}])

    def test_queue_identity_must_survive_restart(self):
        with self.assertRaisesRegex(RuntimeError, "queue identity disappeared"):
            self.check_restart([], remove_queue=True)

    def check_restart(self, batches, remove_queue=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary_root = root / "bin"
            binary_root.mkdir()
            (binary_root / "nanmonee-node").write_bytes(b"test binary")
            state = root / "state"
            state.mkdir(mode=0o700)
            queue = state / "nanmonee-traffic-v1" / ("a" * 64)
            queue.mkdir(parents=True, mode=0o700)
            pending = queue / "pending.json"
            pending.write_text(json.dumps({"pending": batches}))
            pending.chmod(0o600)
            config = root / "31.json"
            config.write_text(json.dumps({
                "control": {"secret": "private-control", "listen": "127.0.0.1:39480"},
                "panel": {"token": "private-token", "protocol": "vless", "node_id": 31},
                "agent": {"backend_protocol": "nanmonee-node-v1", "kernel": "singbox"},
                "traffic": {"data_dir": str(state)},
            }))
            config.chmod(0o400)
            test = deployment.DeploymentAcceptance(root / "work", 31)
            test.config_path = config
            restarted = False
            commands = []

            def call(command, timeout=30):
                nonlocal restarted
                commands.append(command)
                if command[:2] == ["systemctl", "show"]:
                    self.assertEqual(command[2], "nanmonee-node@31.service")
                    return {"User": "nanmonee-node", "ActiveState": "active", "StateDirectory": "nanmonee-node/31"}[command[-1]]
                if command[:2] == ["systemctl", "cat"]:
                    return "[Service]\nStateDirectory=nanmonee-node/%i\n"
                if command[:2] == ["systemctl", "is-enabled"]:
                    return "enabled\n"
                if command[:2] == ["systemctl", "restart"]:
                    self.assertEqual(command[2], "nanmonee-node@31.service")
                    restarted = True
                    pending.write_text('{"pending": []}')
                    if remove_queue:
                        shutil.rmtree(queue)
                    return ""
                if command[0] == "journalctl":
                    self.assertEqual(command[2], "nanmonee-node@31.service")
                    return "panel-owned vless mode\n"
                self.fail(f"Unexpected command: {command}")

            def status():
                return {
                    "apiVersion": "nanmonee-node-v1", "agentVersion": "0.10.0-n1",
                    "coreVersion": "1.14.4", "coreCommit": "c005f35300ce76427dc285481ec5695f5b179cd2",
                    "panelOwned": True, "configured": True, "state": "RUNTIME_STATE_RUNNING",
                    "supportedProtocols": ["vless"], "panel": {"host": "panel.test", "lastPullUnix": 100},
                    "runtimeId": "after" if restarted else "before", "stateRevision": 1, "authorizationSha256": "auth",
                }

            def run(command, **kwargs):
                self.assertEqual(command[command.index("-config") + 1], str(config))
                return subprocess.CompletedProcess(command, 1, "", "FailedPrecondition: panel-owned")

            def path(value):
                raw = str(value)
                return binary_root / Path(raw).name if raw.startswith("/opt/nanmonee-node/current/bin/") else Path(value)

            with patch.object(deployment, "call", side_effect=call), patch.object(deployment.subprocess, "run", side_effect=run), \
                 patch.object(deployment, "Path", side_effect=path), patch.object(test, "status", side_effect=status):
                test.run()
            self.assertTrue(restarted)
            self.assertEqual(test.report["status"], "pass")
            self.assertEqual(test.report["service"]["state_directory"], "nanmonee-node/31")
            restart = next(case for case in test.report["cases"] if case["name"] == "restart-keeps-panel-authority-and-queue-identity")
            self.assertTrue(restart["queue_identity_unchanged"])
            self.assertEqual(restart["pending_batches_before"], len(batches))
            self.assertEqual(restart["pending_batches_after"], 0)
            self.assertTrue(all("nanmonee-node.service" not in command for command in commands))


if __name__ == "__main__":
    unittest.main()
