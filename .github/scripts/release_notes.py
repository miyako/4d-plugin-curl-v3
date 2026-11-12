#!/usr/bin/env python3
"""Render dependency/security context from the two validated final inventories."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


TARGETS = ("macos-arm64", "macos-x86_64", "windows-x86_64")


def render(paths, version):
    if len(paths) != 2 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected one ZIP and one DMG inventory and a release version")
    snapshots = []
    containers = set()
    for path in paths:
        inventory = json.loads(path.read_text(encoding="utf-8"))
        name = inventory["artifact"]["name"]
        if name not in {f"cURL-{version}.zip", f"cURL-{version}.dmg"} or name in containers:
            raise ValueError("Missing, duplicate or unexpected release container")
        containers.add(name)
        artifact = path.parent.parent / name
        if (inventory["version"] != version
                or inventory["artifact"]["sha256"] != hashlib.sha256(artifact.read_bytes()).hexdigest()):
            raise ValueError("Release notes inventory version/container hash mismatch")
        targets = {target["id"]: target for target in inventory["targets"]}
        if len(inventory["targets"]) != 3 or set(targets) != set(TARGETS):
            raise ValueError("Release notes require all three distinct targets")
        snapshot = {}
        for target in TARGETS:
            dependencies = {}
            for package in targets[target]["dependencies"]:
                name = package["name"]
                if name in dependencies:
                    raise ValueError("Duplicate dependency identity")
                dependencies[name] = package.get("version")
            snapshot[target] = {
                "binarySha256": targets[target]["binarySha256"],
                "analyzedSha256": targets[target]["analyzedSha256"],
                "dependencies": dependencies,
            }
        snapshots.append(snapshot)
    if snapshots[0] != snapshots[1]:
        raise ValueError("ZIP and DMG dependency/binary snapshots disagree")

    def cell(value):
        return str(value).replace("|", r"\|").replace("\n", " ").replace("\r", " ")

    snapshot = snapshots[0]
    names = sorted({name for target in snapshot.values() for name in target["dependencies"]})
    lines = [
        "## Dependency and security context",
        "",
        "Both containers ship the same cross-platform bundle. The table is a scoped",
        "snapshot, not a claim that every dependency changed in this release.",
        "See the generated change list below for merged security/dependency updates.",
        "",
        "| Component | macOS arm64 | macOS x86_64 | Windows x64 |",
        "| --- | --- | --- | --- |",
    ]
    for name in names:
        versions = []
        for target in TARGETS:
            packages = snapshot[target]["dependencies"]
            versions.append(cell(packages[name] or "Version not verified") if name in packages else "Not evidenced")
        lines.append("| " + " | ".join([cell(name), *versions]) + " |")
    lines += [
        "",
        "Versions preserve observed suffixes (including `_DEV`) and platform differences.",
        "The attached CycloneDX/SPDX sidecars distinguish binary observations, selected",
        "archive evidence and compiled-source inputs. Archive hashes are not logical",
        "package hashes; unknown suppliers, licenses and acquisition origins remain unknown.",
        "",
        "GitHub build provenance covers each final ZIP/DMG and its sidecars; SBOM",
        "attestations bind each container separately to its CycloneDX and SPDX documents.",
        "Verify with `gh attestation verify FILE --repo miyako/4d-plugin-curl-v3`.",
        "For SBOM predicates, add `--predicate-type https://cyclonedx.org/bom` or",
        "`--predicate-type https://spdx.dev/Document/v2.3`.",
        "",
        "This is not a vulnerability assessment or a vulnerability-free claim.",
        "See [security policy](https://github.com/miyako/4d-plugin-curl-v3/blob/v"
        + version + "/SECURITY.md) and [dependency follow-up](https://github.com/miyako/"
        "4d-plugin-curl-v3/blob/v" + version + "/build/sbom/SECURITY-REVIEW.md).",
        "No Windows Authenticode or additional code-signing coverage is asserted.",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("inventories", nargs=2, type=Path)
    args = parser.parse_args()
    args.output.write_text(render(args.inventories, args.version), encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"Release notes stopped: {error}", file=sys.stderr)
        sys.exit(1)
