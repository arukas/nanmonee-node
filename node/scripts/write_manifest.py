#!/usr/bin/env python3
"""Fingerprint the sources a build manifest claims to describe.

The earlier manifests listed a hand-maintained set of files, so a file added in
one task (node/scripts/test_kernels.sh) or edited in another silently fell out of
date. This script walks the trees the manifest must cover and prints the maps,
and --check fails when a manifest no longer matches the checkout.

After the node repository split this script describes only this repository: the
Go module, its scripts, the deploy notes and the three fixed patch sets. The
panel it talks to is a separate repository, so a manifest records the panel
commit it was verified against as a plain field instead of a file map; the old
build-*.json files stay in the panel repository and are never rewritten here.

Usage:
  python3 node/scripts/write_manifest.py                  # print the JSON maps
  python3 node/scripts/write_manifest.py --check MANIFEST # verify a manifest
  python3 node/scripts/write_manifest.py --write MANIFEST --node-commit SHA \
      --panel-commit SHA [--tag TAG] [--prerelease]       # generate a manifest

--write refuses to invent a commit: both SHAs must be full 40-character hashes,
so a manifest always names the node revision it was built from and the panel
revision it was verified against.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

SOURCE_TREES = {
    "node/api": {".go", ".proto"},
    "node/cmd": {".go"},
    "node/internal": {".go"},
    "node/scripts": {".sh", ".py"},
    "node/deploy": {".md"},
    "patches/sing-box-v1.14.4": {".patch", ".sha256"},
    "patches/sing-quic-7e0a5869a5f4": {".patch", ".sha256"},
    "patches/sing-anytls-130d2e61b889": {".patch", ".sha256"},
}
INPUT_FILES = {
    "go_mod_sha256": "node/go.mod",
    "go_sum_sha256": "node/go.sum",
    "proto_sha256": "node/api/node/v1/node_control.proto",
    "generated_go_sha256": "node/api/node/v1/node_control.pb.go",
    "generated_grpc_go_sha256": "node/api/node/v1/node_control_grpc.pb.go",
    "prepare_script_sha256": "node/scripts/prepare.sh",
    "build_script_sha256": "node/scripts/build.sh",
    "prepare_test_sha256": "node/scripts/test_prepare.py",
    "kernel_test_sha256": "node/scripts/test_kernels.sh",
    "manifest_script_sha256": "node/scripts/write_manifest.py",
}
DEPENDENCIES = ("core", "quic", "anytls")
PANEL_ROLE = "migration-origin"
ARTIFACTS = (
    ("node/.build/nanmonee-node", "nanmonee-node"),
    ("node/.build/nanmonee-nodectl", "nanmonee-nodectl"),
)
AGENT_VERSION = "0.10.0-n1"
TOOLCHAIN = {
    "go": "1.26.8",
    "docker_image": "golang@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348",
    "go_toolchain": "local",
    "protoc": "33.1",
    "protoc_archive_sha256": "f3340e28a83d1c637d8bafdeed92b9f7db6a384c26bca880a6e5217b40a4328b",
    "protoc_gen_go": "v1.36.11",
    "protoc_gen_go_grpc": "v1.5.1",
    "grpc": "v1.79.1",
    "protobuf": "v1.36.11",
}
BUILD = {
    "script": "node/scripts/build.sh",
    "goos": "linux",
    "goarch": "amd64",
    "goamd64": "v1",
    "cgo_enabled": "0",
    "mod": "readonly",
    "parallel": 2,
    "trimpath": True,
    "buildvcs": False,
    "tags": ["with_quic", "with_utls"],
}
DEFINITIONS = {
    "core": {
        "source": "https://github.com/SagerNet/sing-box",
        "version": "v1.14.4",
        "commit": "c005f35300ce76427dc285481ec5695f5b179cd2",
        "license": "GPL-3.0-or-later",
        "patched_files": "patches/sing-box-v1.14.4/patched-files.sha256",
        "license_file": "patches/sing-box-v1.14.4/LICENSE",
        "patches": [
            "patches/sing-box-v1.14.4/0001-vless-hot-update.patch",
            "patches/sing-box-v1.14.4/0002-hysteria2-hot-update.patch",
            "patches/sing-box-v1.14.4/0003-anytls-hot-update.patch",
            "patches/sing-box-v1.14.4/0004-tuic-hot-update.patch",
        ],
    },
    "quic": {
        "source": "https://github.com/sagernet/sing-quic",
        "commit": "7e0a5869a5f49ed0a685143345dfda0448bbc708",
        "license": "GPL-3.0-or-later",
        "patched_files": "patches/sing-quic-7e0a5869a5f4/patched-files.sha256",
        "license_file": "patches/sing-quic-7e0a5869a5f4/LICENSE",
        "patches": [
            "patches/sing-quic-7e0a5869a5f4/0001-hysteria2-hot-update.patch",
            "patches/sing-quic-7e0a5869a5f4/0002-tuic-hot-update.patch",
        ],
    },
    "anytls": {
        "source": "https://github.com/anytls/sing-anytls",
        "version": "v0.0.11",
        "commit": "130d2e61b8895727bfed4942c535e91b246a9603",
        "license": "MIT",
        "patched_files": "patches/sing-anytls-130d2e61b889/patched-files.sha256",
        "license_file": "patches/sing-anytls-130d2e61b889/LICENSE",
        "patches": [
            "patches/sing-anytls-130d2e61b889/0001-anytls-hot-update.patch",
            "patches/sing-anytls-130d2e61b889/0002-client-hook-race.patch",
            "patches/sing-anytls-130d2e61b889/0003-session-identity-and-close-hooks.patch",
        ],
    },
}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(trees: dict[str, set[str]], files: tuple[str, ...]) -> dict[str, str]:
    found: dict[str, str] = {}
    for relative, suffixes in trees.items():
        base = ROOT / relative
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts:
                found[path.relative_to(ROOT).as_posix()] = digest(path)
    for relative in files:
        path = ROOT / relative
        if path.is_file():
            found[relative] = digest(path)
    return dict(sorted(found.items()))


def fingerprint() -> dict[str, dict[str, str]]:
    return {
        "source_files_sha256": collect(SOURCE_TREES, tuple(INPUT_FILES.values())),
        "inputs": {key: digest(ROOT / path) for key, path in INPUT_FILES.items()},
    }


def dependency_record(name: str) -> dict:
    definition = DEFINITIONS[name]
    record = {key: value for key, value in definition.items() if key not in ("patches", "license_file")}
    record["patches"] = [{"path": path, "sha256": digest(ROOT / path)} for path in definition["patches"]]
    record["patched_files_sha256"] = digest(ROOT / definition["patched_files"])
    record["license_file"] = definition["license_file"]
    record["license_sha256"] = digest(ROOT / definition["license_file"])
    return record


def artifact_record(path: str, name: str) -> dict:
    file = ROOT / path
    return {
        "path": path,
        "name": name,
        "sha256": digest(file),
        "bytes": file.stat().st_size,
        "reported_version": AGENT_VERSION,
    }


def manifest(node_commit: str, panel_commit: str, tag: str | None, prerelease: bool) -> dict:
    record = {
        "agent": {"name": "nanmonee-node", "version": AGENT_VERSION, "api_protocol": "nanmonee-node-v1"},
        "sources": {
            "node": {"repository": "https://github.com/arukas/nanmonee-node", "commit": node_commit},
            "panel": {
                "repository": "https://github.com/arukas/nanmonee",
                "commit": panel_commit,
                "role": PANEL_ROLE,
                "note": "The panel is a separate repository: this commit is only the migration origin of the exported tree, not a build input.",
            },
        },
        "toolchain": TOOLCHAIN,
        "build": BUILD,
        "artifacts": [artifact_record(path, name) for path, name in ARTIFACTS],
    }
    for name in DEPENDENCIES:
        record[name] = dependency_record(name)
    record.update(fingerprint())
    if tag:
        record["tag"] = tag
        record["prerelease"] = prerelease
    return record


def check_sources(manifest: dict) -> int:
    """Validate the recorded commits and the role each of them plays.

    The node commit must be the revision this checkout is, so a manifest cannot
    name a stale or unrelated build source. The panel commit is only the
    migration origin: the panel is a separate repository and never part of this
    build, so it is recorded under an explicit role and checked for shape.
    """
    problems = 0
    sources = manifest.get("sources", {})
    node = sources.get("node")
    if node is None:
        print("sources: node commit is not recorded")
        problems += 1
    else:
        commit = node.get("commit", "")
        if not is_commit(commit):
            print("sources: node commit must be a full 40-character lowercase SHA")
            problems += 1
        elif commit != git_head():
            print(f"sources: node commit {commit} is not this checkout ({git_head()})")
            problems += 1
    panel = sources.get("panel")
    if panel is None:
        print("sources: panel commit is not recorded")
        problems += 1
    else:
        if not is_commit(panel.get("commit", "")):
            print("sources: panel commit must be a full 40-character lowercase SHA")
            problems += 1
        if panel.get("role") != PANEL_ROLE:
            print(f"sources: panel must be recorded as {PANEL_ROLE!r}, not {panel.get('role')!r}")
            problems += 1
    return problems


def git_head() -> str | None:
    """Return the commit this checkout is, or None outside a Git checkout."""
    if not (ROOT / ".git").exists():
        return None
    result = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def check(manifest_path: pathlib.Path) -> int:
    manifest = json.loads(manifest_path.read_text())
    current = fingerprint()
    problems = 0
    for section, actual in current.items():
        recorded = manifest.get(section, {})
        for path in sorted(set(recorded) - set(actual)):
            print(f"{section}: {path} is listed but missing from the checkout")
            problems += 1
        for path in sorted(set(actual) - set(recorded)):
            print(f"{section}: {path} exists but is not listed")
            problems += 1
        for path in sorted(set(actual) & set(recorded)):
            if actual[path] != recorded[path]:
                print(f"{section}: {path} changed since the manifest was written")
                problems += 1
    references = []
    for section in DEPENDENCIES:
        dependency = manifest[section]
        references.extend((patch["path"], patch["sha256"]) for patch in dependency["patches"])
        references.append((dependency["patched_files"], dependency["patched_files_sha256"]))
        references.append((dependency["license_file"], dependency["license_sha256"]))
    references.extend((artifact["path"], artifact["sha256"]) for artifact in manifest["artifacts"])
    problems += check_sources(manifest)
    for relative, expected in references:
        path = ROOT / relative
        if not path.is_file() or digest(path) != expected:
            print(f"{relative}: recorded digest does not match the file")
            problems += 1
    if problems:
        print(f"{manifest_path} is out of date ({problems} problem(s)); regenerate it mechanically")
        return 1
    print(f"{manifest_path} matches the checkout")
    return 0


def is_commit(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "--check":
        return check(pathlib.Path(argv[2]))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", metavar="MANIFEST", help="write a complete manifest to this path")
    parser.add_argument("--node-commit", help="full commit SHA of this repository")
    parser.add_argument("--panel-commit", help="full commit SHA of the panel this build was verified against")
    parser.add_argument("--tag", help="release tag this build is published under")
    parser.add_argument("--prerelease", action="store_true", help="mark the recorded tag as a prerelease")
    options = parser.parse_args(argv[1:])
    if options.write is None:
        print(json.dumps(fingerprint(), indent=2, sort_keys=True))
        return 0
    for flag, value in (("--node-commit", options.node_commit), ("--panel-commit", options.panel_commit)):
        if value is None or not is_commit(value):
            print(f"{flag} must be a full 40-character lowercase commit SHA", file=sys.stderr)
            return 2
    for path, _ in ARTIFACTS:
        if not (ROOT / path).is_file():
            print(f"{path} is missing; build the artifacts first", file=sys.stderr)
            return 2
    record = manifest(options.node_commit, options.panel_commit, options.tag, options.prerelease)
    pathlib.Path(options.write).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(options.write)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
