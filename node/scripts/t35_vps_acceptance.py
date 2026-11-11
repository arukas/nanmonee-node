#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets as random_secrets
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time
import uuid as uuid_module

PROXY_PORT = 31460
CONTROL_PORT = 39460
HTTP_PORT = 19168
UDP_PORT = 19169
CLIENT_PORTS = {"mihomo": {"A": 19160, "B": 19161}, "sing-box": {"A": 19162, "B": 19163}}
MEMBER_IDS = {"A": 101, "B": 102}


def exact_receive(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def socks_reply(sock):
    version, status, _, atyp = exact_receive(sock, 4)
    if version != 5:
        raise RuntimeError("invalid SOCKS reply")
    if atyp == 1:
        address = socket.inet_ntoa(exact_receive(sock, 4))
    elif atyp == 3:
        address = exact_receive(sock, exact_receive(sock, 1)[0]).decode()
    elif atyp == 4:
        address = socket.inet_ntop(socket.AF_INET6, exact_receive(sock, 16))
    else:
        raise RuntimeError("invalid SOCKS address")
    port = struct.unpack("!H", exact_receive(sock, 2))[0]
    return status, address, port


def socks_connect(port, destination, destination_port, timeout=5):
    sock = socket.create_connection(("127.0.0.1", port), timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    if exact_receive(sock, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS authentication failed")
    host = destination.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", destination_port))
    status, _, _ = socks_reply(sock)
    if status != 0:
        sock.close()
        raise RuntimeError(f"SOCKS connect rejected with status {status}")
    return sock


class UDPAssociation:
    def __init__(self, port, timeout=5):
        self.control = socket.create_connection(("127.0.0.1", port), timeout)
        self.control.settimeout(timeout)
        self.control.sendall(b"\x05\x01\x00")
        if exact_receive(self.control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication failed")
        self.control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
        status, host, relay_port = socks_reply(self.control)
        if status != 0:
            raise RuntimeError(f"UDP associate rejected with status {status}")
        self.relay = (host, relay_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(timeout)

    def request(self, payload, destination="127.0.0.1", destination_port=UDP_PORT):
        host = destination.encode()
        packet = b"\x00\x00\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", destination_port) + payload
        self.sock.sendto(packet, self.relay)
        response, _ = self.sock.recvfrom(65535)
        if response[:3] != b"\x00\x00\x00":
            raise RuntimeError("invalid UDP response")
        atyp = response[3]
        if atyp == 1:
            offset = 10
        elif atyp == 3:
            offset = 7 + response[4]
        elif atyp == 4:
            offset = 22
        else:
            raise RuntimeError("invalid UDP response address")
        return response[offset:]

    def close(self):
        self.sock.close()
        self.control.close()


class HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data.extend(chunk)
        headers, body = bytes(data).split(b"\r\n\r\n", 1)
        length = 0
        for line in headers.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        while len(body) < length:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            body += chunk
        received = headers + b"\r\n\r\n" + body
        response_body = b'{"ok":true}\n'
        response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(response_body)).encode() + b"\r\nConnection: close\r\n\r\n" + response_body
        self.server.received.append((received, response))
        self.request.sendall(response)


class HoldHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    return
                self.request.sendall(b"ack")
        except (ConnectionError, OSError):
            return


class ThreadedServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Acceptance:
    def __init__(self, work, node, nodectl, mihomo, singbox):
        self.work = work
        self.node = node
        self.nodectl = nodectl
        self.mihomo = mihomo
        self.singbox = singbox
        self.private = work / "private"
        self.report = {"task": "T35", "platform": "gc-tyo.acris.cc / Debian 13 / Linux amd64-v1", "cases": []}
        self.processes = {}
        self.servers = []
        self.server_threads = []
        self.open_sockets = []
        self.secret_values = set()
        self.uuids = {"A": str(uuid_module.uuid4()), "B": str(uuid_module.uuid4())}
        self.control_secret = random_secrets.token_hex(32)
        self.short_id = random_secrets.token_hex(8)
        self.private_key = ""
        self.public_key = ""
        self.production_before = self.production_snapshot()
        self.cleanup_result = {}

    def safe(self, value):
        text = str(value)
        for secret in self.secret_values:
            if secret:
                text = text.replace(str(secret), "<redacted>")
        return text

    def call(self, command, timeout=30, expected=True):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if expected and result.returncode != 0:
            raise RuntimeError(self.safe(f"command {Path(command[0]).name} failed: {result.stderr[-1500:]}"))
        return result

    def write_private(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o600)

    def start(self, name, command):
        log_path = self.private / f"{name}.log"
        log = log_path.open("w")
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        self.processes[name] = process
        return process

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)

    def production_snapshot(self):
        health = self.call(["curl", "--silent", "--show-error", "--output", "/dev/null", "--max-time", "12", "--write-out", "%{http_code}", "https://nanmonee.shinai.co.uk/up"]).stdout.strip()
        lines = self.call(["ps", "-eo", "pid,args"]).stdout.splitlines()
        matched = sorted(int(line.strip().split(None, 1)[0]) for line in lines if "/usr/local/bin/xboard-node -c /etc/xboard-node/config.yml" in line)
        return {"health": health, "xboard_pids": matched}

    def node_status(self):
        result = self.call([str(self.nodectl), "-config", str(self.private / "node.json"), "-op", "status"])
        return json.loads(result.stdout)["status"]

    def usage(self):
        result = self.call([str(self.nodectl), "-config", str(self.private / "node.json"), "-op", "usage"])
        entries = json.loads(result.stdout)["usage"]
        return {int(item["memberId"]): [int(item.get("upload", "0")), int(item.get("download", "0"))] for item in entries}

    def apply(self, members, port=PROXY_PORT, expected=True, short_id=None):
        snapshot = {
            "config": {"vless": {
                "listen": "127.0.0.1", "port": port, "serverName": "www.apple.com",
                "handshakeServer": "www.apple.com", "handshakePort": 443,
                "realityPrivateKey": self.private_key, "realityShortId": self.short_id if short_id is None else short_id,
            }},
            "users": {"users": [{"memberId": str(MEMBER_IDS[member]), "uuid": self.uuids[member]} for member in members]},
        }
        path = self.private / "snapshot.json"
        self.write_private(path, json.dumps(snapshot))
        return self.call([str(self.nodectl), "-config", str(self.private / "node.json"), "-op", "apply", "-snapshot", str(path)], expected=expected)

    def wait_status(self, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.node_status()
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)

    def wait_usage(self, member_id, expected, timeout=5):
        deadline = time.monotonic() + timeout
        while True:
            actual = self.usage().get(member_id, [0, 0])
            if actual == expected:
                return actual
            if time.monotonic() >= deadline:
                raise RuntimeError(f"usage mismatch for member {member_id}: got {actual}, want {expected}")
            time.sleep(0.05)

    def wait_socks(self, port, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            try:
                sock = socket.create_connection(("127.0.0.1", port), 0.5)
                sock.close()
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)

    def client_config(self, kind, member):
        port = CLIENT_PORTS[kind][member]
        if kind == "mihomo":
            return f"""log-level: error
mode: rule
allow-lan: false
bind-address: 127.0.0.1
ipv6: false
socks-port: {port}
udp: true
proxies:
  - name: t35
    type: vless
    server: 127.0.0.1
    port: {PROXY_PORT}
    uuid: {self.uuids[member]}
    flow: xtls-rprx-vision
    network: tcp
    udp: true
    packet-encoding: xudp
    tls: true
    servername: www.apple.com
    client-fingerprint: chrome
    reality-opts:
      public-key: {self.public_key}
      short-id: {self.short_id}
proxy-groups:
  - name: PROXY
    type: select
    proxies: [t35]
rules:
  - MATCH,PROXY
"""
        return json.dumps({
            "log": {"level": "error"},
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{
                "type": "vless", "tag": "t35", "server": "127.0.0.1", "server_port": PROXY_PORT,
                "uuid": self.uuids[member], "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
                "tls": {"enabled": True, "server_name": "www.apple.com", "utls": {"enabled": True, "fingerprint": "chrome"}, "reality": {"enabled": True, "public_key": self.public_key, "short_id": self.short_id}},
            }],
            "route": {"final": "t35"},
        })

    def start_client(self, kind, member):
        name = f"{kind}-{member}"
        config = self.private / f"{name}.json" if kind == "sing-box" else self.private / f"{name}.yaml"
        self.write_private(config, self.client_config(kind, member))
        if kind == "mihomo":
            self.call([str(self.mihomo), "-t", "-f", str(config)])
            home = self.private / f"{name}-home"
            home.mkdir(exist_ok=True)
            self.start(name, [str(self.mihomo), "-d", str(home), "-f", str(config)])
        else:
            self.call([str(self.singbox), "check", "-c", str(config)])
            self.start(name, [str(self.singbox), "run", "-c", str(config)])
        self.wait_socks(CLIENT_PORTS[kind][member])

    def http_roundtrip(self, kind, member):
        sock = socks_connect(CLIENT_PORTS[kind][member], "127.0.0.1", HTTP_PORT)
        body = b"test"
        request = b"POST /t35 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nConnection: close\r\n\r\n" + body
        sock.sendall(request)
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        sock.close()
        if not response.endswith(b'{"ok":true}\n'):
            raise RuntimeError(f"HTTP response content mismatch: length={len(response)}, prefix={bytes(response[:32]).hex()}")
        received, expected_response = self.servers[0].received[-1]
        if received != request or bytes(response) != expected_response:
            raise RuntimeError("HTTP bytes changed in transit")
        return len(received), len(response)

    def wait_http_success(self, kind, member, timeout=10):
        deadline = time.monotonic() + timeout
        last_error = None
        while True:
            try:
                return self.http_roundtrip(kind, member)
            except Exception as exc:
                last_error = exc
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"{kind}/{member} did not recover: {last_error}; status={self.node_status()}")
                time.sleep(0.1)

    def https_roundtrip(self, kind, member):
        port = CLIENT_PORTS[kind][member]
        result = self.call(["curl", "--silent", "--show-error", "--output", "/dev/null", "--max-time", "20", "--socks5-hostname", f"127.0.0.1:{port}", "--write-out", "%{http_code}", "https://www.apple.com/"], timeout=25)
        if result.stdout.strip() != "200":
            raise RuntimeError(f"external HTTPS returned {result.stdout.strip()}")

    def udp_roundtrip(self, kind, member):
        association = UDPAssociation(CLIENT_PORTS[kind][member])
        try:
            response = association.request(b"hello")
            if response != b"bye":
                raise RuntimeError("UDP response content mismatch")
        finally:
            association.close()

    def calibrate(self, kind, member):
        member_id = MEMBER_IDS[member]
        before = self.usage().get(member_id, [0, 0])
        upload, download = self.http_roundtrip(kind, member)
        expected = [before[0] + upload, before[1] + download]
        self.wait_usage(member_id, expected)
        before_udp = expected
        self.udp_roundtrip(kind, member)
        expected_udp = [before_udp[0] + 5, before_udp[1] + 3]
        self.wait_usage(member_id, expected_udp)
        self.https_roundtrip(kind, member)
        self.report["cases"].append({"name": f"{kind}/{member}/tcp-udp-https", "status": "pass", "tcp_upload": upload, "tcp_download": download, "udp_upload": 5, "udp_download": 3, "usage_after_calibration": expected_udp})

    def expect_http_failure(self, kind, member):
        try:
            self.http_roundtrip(kind, member)
        except Exception:
            return
        raise RuntimeError(f"{kind}/{member} connected successfully while authorization was rejected")

    def revoke_restore_rotate(self, kind):
        self.stop(f"{kind}-A")
        self.start_client(kind, "A")
        self.apply(["A", "B"])
        a_hold = socks_connect(CLIENT_PORTS[kind]["A"], "127.0.0.1", HTTP_PORT + 1)
        b_hold = socks_connect(CLIENT_PORTS[kind]["B"], "127.0.0.1", HTTP_PORT + 1)
        a_udp = UDPAssociation(CLIENT_PORTS[kind]["A"])
        b_udp = UDPAssociation(CLIENT_PORTS[kind]["B"])
        member_id = MEMBER_IDS["A"]
        before = self.usage().get(member_id, [0, 0])
        a_hold.sendall(b"tail")
        if exact_receive(a_hold, 3) != b"ack":
            raise RuntimeError("tail probe failed")
        started = time.monotonic()
        self.apply(["B"])
        closed = False
        a_hold.settimeout(2)
        try:
            closed = a_hold.recv(1) == b""
        except (ConnectionError, socket.timeout, OSError):
            closed = True
        if not closed:
            raise RuntimeError("A persistent TCP remained open after revocation")
        latency = time.monotonic() - started
        b_hold.sendall(b"ping")
        if exact_receive(b_hold, 3) != b"ack":
            raise RuntimeError("B persistent TCP stopped after A revocation")
        try:
            if a_udp.request(b"hello") == b"bye":
                raise RuntimeError("A persistent UDP remained usable")
        except (socket.timeout, ConnectionError, OSError):
            pass
        if b_udp.request(b"hello") != b"bye":
            raise RuntimeError("B persistent UDP stopped after A revocation")
        self.expect_http_failure(kind, "A")
        self.wait_usage(member_id, [before[0] + 4, before[1] + 3])
        self.report["cases"].append({"name": f"{kind}/revoke-existing-and-new", "status": "pass", "a_tcp_udp_closed": True, "b_tcp_udp_preserved": True, "tail_upload": 4, "tail_download": 3, "latency_seconds": round(latency, 6)})
        a_hold.close()
        b_hold.close()
        a_udp.close()
        b_udp.close()
        self.apply(["A", "B"])
        self.http_roundtrip(kind, "A")

        a_hold = socks_connect(CLIENT_PORTS[kind]["A"], "127.0.0.1", HTTP_PORT + 1)
        b_hold = socks_connect(CLIENT_PORTS[kind]["B"], "127.0.0.1", HTTP_PORT + 1)
        a_udp = UDPAssociation(CLIENT_PORTS[kind]["A"])
        b_udp = UDPAssociation(CLIENT_PORTS[kind]["B"])
        old_uuid = self.uuids["A"]
        self.uuids["A"] = str(uuid_module.uuid4())
        self.secret_values.add(self.uuids["A"])
        started = time.monotonic()
        self.apply(["A", "B"])
        a_hold.settimeout(2)
        try:
            closed = a_hold.recv(1) == b""
        except (ConnectionError, socket.timeout, OSError):
            closed = True
        if not closed:
            raise RuntimeError("old UUID persistent TCP remained open")
        b_hold.sendall(b"ping")
        if exact_receive(b_hold, 3) != b"ack":
            raise RuntimeError("B stopped during A UUID rotation")
        try:
            if a_udp.request(b"hello") == b"bye":
                raise RuntimeError("old UUID persistent UDP remained usable")
        except (socket.timeout, ConnectionError, OSError):
            pass
        if b_udp.request(b"hello") != b"bye":
            raise RuntimeError("B persistent UDP stopped during A UUID rotation")
        self.expect_http_failure(kind, "A")
        a_hold.close()
        b_hold.close()
        a_udp.close()
        b_udp.close()
        self.stop(f"{kind}-A")
        self.start_client(kind, "A")
        self.http_roundtrip(kind, "A")
        self.report["cases"].append({"name": f"{kind}/uuid-rotation", "status": "pass", "old_uuid_rejected": old_uuid != self.uuids["A"], "new_uuid_accepted": True, "b_preserved": True, "latency_seconds": round(time.monotonic() - started, 6)})

    def invalid_short_id(self):
        for kind in CLIENT_PORTS:
            self.stop(f"{kind}-A")
            self.start_client(kind, "A")
            held = socks_connect(CLIENT_PORTS[kind]["B"], "127.0.0.1", HTTP_PORT + 1)
            association = UDPAssociation(CLIENT_PORTS[kind]["B"])
            try:
                held.sendall(b"init")
                if exact_receive(held, 3) != b"ack" or association.request(b"hello") != b"bye":
                    raise RuntimeError("could not establish the existing connection probes")
                before = self.node_status()
                for length in (9, 16):
                    invalid = "ab" * length
                    self.secret_values.add(invalid)
                    result = self.apply(["A", "B"], expected=False, short_id=invalid)
                    if result.returncode == 0 or "InvalidArgument" not in result.stderr:
                        raise RuntimeError("oversized short ID did not return InvalidArgument")
                    if self.node_status() != before or self.processes["node"].poll() is not None:
                        raise RuntimeError("oversized short ID changed state or stopped the node")
                    held.sendall(b"ping")
                    if exact_receive(held, 3) != b"ack" or association.request(b"hello") != b"bye":
                        raise RuntimeError("oversized short ID interrupted an existing connection")
                self.http_roundtrip(kind, "A")
                self.http_roundtrip(kind, "B")
                self.report["cases"].append({"name": f"{kind}/invalid-short-id-preserves-runtime", "status": "pass", "rejected_byte_lengths": [9, 16], "existing_tcp_udp_preserved": True, "state_unchanged": True})
            finally:
                held.close()
                association.close()

    def config_failure(self):
        for kind in CLIENT_PORTS:
            self.stop(f"{kind}-A")
            self.start_client(kind, "A")
        blocker = socket.socket()
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", PROXY_PORT + 1))
        blocker.listen()
        self.apply(["B"], port=PROXY_PORT + 1, expected=False)
        status = self.node_status()
        if status["state"] != "RUNTIME_STATE_DEGRADED" or status.get("configSha256"):
            raise RuntimeError(f"occupied port did not produce degraded status: {status}")
        blocker.close()
        self.apply(["B"], port=PROXY_PORT + 1)
        self.apply(["B"])
        self.expect_http_failure("mihomo", "A")
        self.apply(["A", "B"])
        self.wait_http_success("mihomo", "B")
        self.wait_http_success("mihomo", "A")
        self.report["cases"].append({"name": "occupied-port-and-explicit-repair", "status": "pass", "degraded_observed": True, "removed_member_not_revived": True})

    def setup(self):
        shutil.rmtree(self.work / "debug", ignore_errors=True)
        self.private.mkdir(parents=True)
        self.private.chmod(0o700)
        generated = self.call([str(self.singbox), "generate", "reality-keypair"]).stdout.splitlines()
        values = dict(line.split(": ", 1) for line in generated if ": " in line)
        self.private_key = values["PrivateKey"]
        self.public_key = values["PublicKey"]
        self.secret_values.update([self.private_key, self.control_secret, self.short_id, *self.uuids.values()])
        startup = {
            "control": {"listen": f"127.0.0.1:{CONTROL_PORT}", "secret": self.control_secret},
            "vless": {"listen": "127.0.0.1", "port": PROXY_PORT, "server_name": "www.apple.com", "handshake_server": "www.apple.com", "handshake_port": 443, "reality_private_key": self.private_key, "reality_short_id": self.short_id},
        }
        self.write_private(self.private / "node.json", json.dumps(startup))
        self.start("node", [str(self.node), "-config", str(self.private / "node.json")])
        status = self.wait_status()
        self.report["versions"] = {key: status[key] for key in ("agentVersion", "apiVersion", "coreVersion", "coreCommit")}
        if status["agentVersion"] != "0.1.1-t35":
            raise RuntimeError("unexpected agent version for the T35 review-fix acceptance")
        if status["state"] != "RUNTIME_STATE_EMPTY":
            raise RuntimeError("node did not start with an explicit empty snapshot")
        http_server = ThreadedServer(("127.0.0.1", HTTP_PORT), HTTPHandler)
        http_server.received = []
        hold_server = ThreadedServer(("127.0.0.1", HTTP_PORT + 1), HoldHandler)
        self.servers.extend([http_server, hold_server])
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.server_threads.append(thread)
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.bind(("127.0.0.1", UDP_PORT))
        udp_server.settimeout(0.2)
        self.open_sockets.append(udp_server)
        def udp_loop():
            while not udp_server._closed:
                try:
                    data, address = udp_server.recvfrom(65535)
                    udp_server.sendto(b"bye", address)
                except socket.timeout:
                    continue
                except OSError:
                    return
        thread = threading.Thread(target=udp_loop, daemon=True)
        thread.start()
        self.server_threads.append(thread)
        for kind in CLIENT_PORTS:
            for member in ("A", "B"):
                self.start_client(kind, member)
                self.expect_http_failure(kind, member)
        self.report["cases"].append({"name": "empty-start-rejects-all", "status": "pass"})
        self.apply(["A", "B"])

    def cleanup(self):
        for name in list(self.processes):
            self.stop(name)
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for sock in self.open_sockets:
            try:
                sock.close()
            except OSError:
                pass
        hits = 0
        if self.private.exists():
            for path in self.private.rglob("*.log"):
                if path.is_file():
                    try:
                        content = path.read_bytes()
                    except OSError:
                        continue
                    for secret in self.secret_values:
                        if secret and str(secret).encode() in content:
                            hits += 1
                            break
                    if self.report["status"] == "fail":
                        debug = self.work / "debug"
                        debug.mkdir(exist_ok=True)
                        debug.chmod(0o700)
                        (debug / path.name).write_text(self.safe(content.decode(errors="replace")))
        self.cleanup_result = {"processes_stopped": True, "secret_scan_hits": hits}
        shutil.rmtree(self.private, ignore_errors=True)
        after = self.production_snapshot()
        self.cleanup_result["production_preserved"] = after == self.production_before
        self.cleanup_result["private_removed"] = not self.private.exists()

    def run(self):
        error = None
        try:
            self.setup()
            for kind in CLIENT_PORTS:
                for member in ("A", "B"):
                    self.calibrate(kind, member)
            for kind in CLIENT_PORTS:
                self.revoke_restore_rotate(kind)
            self.invalid_short_id()
            self.config_failure()
            self.report["status"] = "pass"
        except Exception as exc:
            error = self.safe(exc)
            self.report["status"] = "fail"
            self.report["error"] = error
        finally:
            self.cleanup()
            self.report["cleanup"] = self.cleanup_result
            if error is None and (self.cleanup_result["secret_scan_hits"] != 0 or not self.cleanup_result["production_preserved"] or not self.cleanup_result["private_removed"]):
                error = "cleanup or production preservation verification failed"
                self.report["status"] = "fail"
                self.report["error"] = error
            self.report["production"] = self.production_before
            self.report["binary_sha256"] = hashlib.sha256(self.node.read_bytes()).hexdigest()
            (self.work / "acceptance.json").write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")
            (self.work / "acceptance.json").chmod(0o600)
        if error:
            raise RuntimeError(error)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--nodectl", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--sing-box", dest="singbox", type=Path, required=True)
    args = parser.parse_args()
    Acceptance(args.work, args.node, args.nodectl, args.mihomo, args.singbox).run()


if __name__ == "__main__":
    main()
