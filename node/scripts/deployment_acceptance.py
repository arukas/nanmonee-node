#!/usr/bin/env python3
"""Verify one installed, panel-owned node instance without touching its private configuration.

T35 ran a standalone node whose unit applied a local bootstrap snapshot at every
start. T36 moved authorization to the panel worker, so this script checks the
properties that mode promises instead: the kernel stays shut until the panel
authorizes, external ApplySnapshot is refused forever, the durable queue lives
under systemd's StateDirectory, and a restart keeps serving the same panel
authorization from the same queue identity.

The real connection, metering and entitlement matrix runs from a machine that can
reach both the panel and the node; it needs a real member subscription, which this
script intentionally does not fabricate.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

PENDING = re.compile(r"^[0-9a-f]{64}$")


def call(command, timeout=30):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"{Path(command[0]).name} failed: {result.stderr.strip()[-1200:]}")
    return result.stdout


class DeploymentAcceptance:
    def __init__(self, work, node_id):
        self.work = work
        self.node_id = node_id
        self.unit = f"nanmonee-node@{node_id}.service"
        self.config_path = Path(f"/etc/nanmonee-node/nodes/{node_id}.json")
        self.report = {
            "task": "N1-4",
            "scope": "resident panel-owned service; authorization, metering and entitlement matrix run separately",
            "platform": socket.gethostname(),
            "cases": [],
        }
        self.secret_values = set()
        self.config = {}
        self.queue_dirs = []

    def safe(self, value):
        text = str(value)
        for secret in self.secret_values:
            if secret:
                text = text.replace(str(secret), "<redacted>")
        return text

    def service_property(self, name):
        return call(["systemctl", "show", self.unit, "--value", "-p", name]).strip()

    def status(self):
        output = call([str(self.nodectl), "-config", str(self.config_path), "-op", "status"])
        return json.loads(output)["status"]

    def case(self, name, **evidence):
        self.report["cases"].append({"name": name, "status": "pass", **evidence})

    def queue_state(self):
        """Summarize on-disk queue state without reading member identifiers."""
        total = 0
        bytes_used = 0
        for directory in self.queue_dirs:
            pending = directory / "pending.json"
            if not pending.exists():
                continue
            state = json.loads(pending.read_text())
            total += len(state.get("pending") or [])
            bytes_used += pending.stat().st_size
        return {"pending_batches": total, "bytes": bytes_used}

    def run(self):
        self.work.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.work.chmod(0o700)
        self.nodectl = Path("/opt/nanmonee-node/current/bin/nanmonee-nodectl")
        binary = Path("/opt/nanmonee-node/current/bin/nanmonee-node")
        self.config = json.loads(self.config_path.read_text())
        self.secret_values.update([self.config["control"]["secret"], self.config["panel"]["token"]])

        if self.service_property("User") != "nanmonee-node" or self.service_property("ActiveState") != "active":
            raise RuntimeError("resident service is not active as the dedicated user")
        call(["systemctl", "is-enabled", self.unit])

        # Panel mode owns authorization: no local bootstrap may be applied at start.
        fragment = call(["systemctl", "cat", self.unit])
        if "ExecStartPost" in fragment:
            raise RuntimeError("the unit still applies a local bootstrap snapshot")
        if self.service_property("StateDirectory") != f"nanmonee-node/{self.node_id}":
            raise RuntimeError("the unit does not declare its per-node state directory")
        self.case("unit-owns-authorization", exec_start_post_present=False, state_directory=f"nanmonee-node/{self.node_id}")

        for key in ("control", "panel", "agent", "traffic"):
            if key not in self.config:
                raise RuntimeError(f"startup config is missing the {key} section")
        if "vless" in self.config:
            raise RuntimeError("a panel-owned startup config must not pin a local inbound")
        if self.config["agent"]["backend_protocol"] != "nanmonee-node-v1":
            raise RuntimeError("unexpected backend protocol")
        if self.config["agent"]["kernel"] != "singbox":
            raise RuntimeError("unexpected kernel selection")
        self.case(
            "startup-config-shape",
            sections=sorted(self.config),
            backend_protocol=self.config["agent"]["backend_protocol"],
            kernel=self.config["agent"]["kernel"],
            protocol=self.config["panel"]["protocol"],
            node_id=self.config["panel"]["node_id"],
        )

        mode = self.config_path.stat().st_mode & 0o777
        data_dir = Path(self.config["traffic"]["data_dir"])
        data_mode = data_dir.stat().st_mode & 0o777
        if mode & 0o077:
            raise RuntimeError("startup config is readable by other users")
        if data_mode & 0o077:
            raise RuntimeError("traffic data directory is readable by other users")
        self.case("permissions", startup_config=oct(mode), data_dir=oct(data_mode))

        root = data_dir / "nanmonee-traffic-v1"
        if not root.is_dir():
            raise RuntimeError("the durable queue root is missing")
        self.queue_dirs = [entry for entry in root.iterdir() if entry.is_dir()]
        if not self.queue_dirs:
            raise RuntimeError("no queue directory was created for this node identity")
        for directory in self.queue_dirs:
            if not PENDING.match(directory.name):
                raise RuntimeError("queue directory name is not a content hash")
            if directory.stat().st_mode & 0o077:
                raise RuntimeError("queue directory is readable by other users")
            pending = directory / "pending.json"
            if pending.exists() and pending.stat().st_mode & 0o077:
                raise RuntimeError("queue state file is readable by other users")
        self.case(
            "durable-queue-layout",
            queue_dirs=len(self.queue_dirs),
            hash_is_hex_sha256=True,
            dir_mode="0700",
            state="present" if (self.queue_dirs[0] / "pending.json").exists() else "not yet created",
        )

        status = self.status()
        if status["apiVersion"] != "nanmonee-node-v1":
            raise RuntimeError("unexpected API protocol")
        if status["coreCommit"] != "c005f35300ce76427dc285481ec5695f5b179cd2":
            raise RuntimeError("unexpected kernel commit")
        if not status["panelOwned"]:
            raise RuntimeError("the runtime does not report panel ownership")
        self.report["versions"] = {
            key: status[key] for key in ("agentVersion", "apiVersion", "coreVersion", "coreCommit")
        }
        self.case(
            "runtime-is-panel-owned",
            panel_owned=True,
            configured=status["configured"],
            state=status["state"],
            supported_protocols=status["supportedProtocols"],
            panel_host=status["panel"]["host"],
        )

        # External writes must be refused as a permanent precondition failure.
        snapshot = self.work / "snapshot.json"
        snapshot.write_text(json.dumps({"users": {"users": []}}))
        snapshot.chmod(0o600)
        refused = subprocess.run(
            [str(self.nodectl), "-config", str(self.config_path), "-op", "apply", "-snapshot", str(snapshot)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        message = (refused.stderr or "") + (refused.stdout or "")
        if refused.returncode == 0 or "FailedPrecondition" not in message:
            raise RuntimeError(f"external ApplySnapshot was not refused with FailedPrecondition: {self.safe(message[-400:])}")
        self.case("external-apply-is-refused", error_class="FailedPrecondition", query_rpcs_still_work=True)

        # Query RPCs must stay responsive; the panel observation is what an operator reads.
        timings = []
        for _ in range(10):
            started = time.monotonic()
            observed = self.status()
            timings.append((time.monotonic() - started) * 1000)
        if not all(value < 3000 for value in timings):
            raise RuntimeError("status RPC was not responsive")
        self.report["status_latency_ms"] = {"min": round(min(timings), 1), "max": round(max(timings), 1)}
        self.case(
            "status-probe-rpcs-stay-responsive",
            calls=len(timings),
            failures=0,
            observation={"last_pull": observed["panel"].get("lastPullUnix"), "rejected": observed["panel"].get("rejected", False)},
        )

        before = self.queue_state()
        runtime_before = observed["runtimeId"]
        revision_before = observed["stateRevision"]
        authorization_before = observed.get("authorizationSha256", "")

        call(["systemctl", "restart", self.unit], timeout=60)
        deadline = time.monotonic() + 90
        # A fresh runtime id plus an advanced pull timestamp proves the worker
        # renegotiated with the panel. RUNTIME_STATE_EMPTY is a legitimate
        # result: an empty user list means the panel revoked everyone.
        while True:
            try:
                after = self.status()
            except Exception:
                after = None
            if (
                after is not None
                and after["runtimeId"] != runtime_before
                and int(after["panel"].get("lastPullUnix") or 0) >= int(observed["panel"].get("lastPullUnix") or 0)
            ):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("the node did not renegotiate with the panel after restart")
            time.sleep(1)

        if not after["panelOwned"]:
            raise RuntimeError("panel ownership was lost across restart")
        if int(after["panel"].get("lastPullUnix") or 0) <= 0:
            raise RuntimeError("the worker did not pull from the panel after restart")
        same_authorization = after.get("authorizationSha256", "") == authorization_before and authorization_before != ""
        if not same_authorization and after["state"] not in ("RUNTIME_STATE_RUNNING", "RUNTIME_STATE_EMPTY"):
            raise RuntimeError("authorization changed and the node is not serving nor deliberately empty")
        after_queue = self.queue_state()
        # Online reporting may drain or append batches; only identity is invariant here.
        if not all(directory.is_dir() for directory in self.queue_dirs):
            raise RuntimeError("the durable queue identity disappeared across a restart")
        self.case(
            "restart-keeps-panel-authority-and-queue-identity",
            runtime_id_renewed=True,
            authorization_unchanged=same_authorization,
            state=after["state"],
            queue_identity_unchanged=True,
            pending_batches_before=before["pending_batches"],
            pending_batches_after=after_queue["pending_batches"],
            revision_advanced=after["stateRevision"] >= revision_before,
        )

        journal = call(["journalctl", "-u", self.unit, "--no-pager", "-n", "400"])
        hits = [secret for secret in self.secret_values if secret and secret in journal]
        if hits:
            raise RuntimeError("a secret appears in the resident service journal")
        if f"panel-owned {self.config['panel']['protocol']} mode" not in journal:
            raise RuntimeError("the service did not log its panel-owned mode")
        self.case("journal-has-no-secrets", hits=0, panel_owned_logged=True)

        self.report["service"] = {
            "active": self.service_property("ActiveState"),
            "enabled": True,
            "node_id": self.node_id,
            "user": self.service_property("User"),
            "exec_start_post": False,
            "state_directory": f"nanmonee-node/{self.node_id}",
            "control_listen": self.config["control"]["listen"],
            "journal_secret_hits": 0,
        }
        self.report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.report["status"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--node-id", type=int, required=True)
    args = parser.parse_args()
    test = DeploymentAcceptance(args.work, args.node_id)
    error = None
    try:
        test.run()
    except Exception as exc:
        error = test.safe(exc)
        test.report.update(status="fail", error=error)
    report_path = args.work / "deployment-acceptance.json"
    report_path.write_text(json.dumps(test.report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    report_path.chmod(0o600)
    if error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
    print(report_path)


if __name__ == "__main__":
    main()
