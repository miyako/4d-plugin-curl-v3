#!/usr/bin/env python3
"""Freeze observed release inputs, never reconstruct missing historical provenance."""

import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sbom"))
from generate import inventory
from provenance import digest, write_json


COMMIT = "9d82748eeeaa59aaa84a0c1e188cd1cb33bbb618"
TARGETS = {"macos-arm64", "macos-x86_64", "windows-x86_64"}


def freeze(root):
    release = json.loads((root / "release.json").read_text())
    run = json.loads((root / "run.json").read_text())
    if run["headSha"] != COMMIT:
        raise ValueError("Baseline run does not identify the accepted release commit")
    assets = release["assets"]
    expected_names = {
        f"cURL-4.9.10.{container}{suffix}"
        for container in ("zip", "dmg")
        for suffix in ("", ".inventory.json", ".cdx.json", ".spdx.json")
    }
    if len(assets) != 8 or {a["name"] for a in assets} != expected_names:
        raise ValueError("Unexpected baseline asset set")
    for asset in assets:
        if asset["digest"] != "sha256:" + digest(root / asset["name"]):
            raise ValueError("Baseline asset hash mismatch: " + asset["name"])
    inventories = []
    for suffix in ("zip", "dmg"):
        artifact = root / f"cURL-4.9.10.{suffix}"
        saved = json.loads(Path(str(artifact) + ".inventory.json").read_text())
        actual = inventory(artifact, "4.9.10", [])
        if saved["artifact"] != actual["artifact"]:
            raise ValueError("Saved artifact binding mismatch")
        if ({t["id"] for t in actual["targets"]} != TARGETS
                or {t["id"] for t in saved["targets"]} != TARGETS):
            raise ValueError("Unexpected baseline targets")
        for current in actual["targets"]:
            target = next(t for t in saved["targets"] if t["id"] == current["id"])
            for key in ("binaryPath", "binarySha256", "analyzedSha256"):
                if current[key] != target[key]:
                    raise ValueError("Packaged baseline binary binding mismatch: " + key)
        inventories.append(saved)
    if inventories[0]["targets"] != inventories[1]["targets"]:
        raise ValueError("ZIP and DMG target evidence differ")
    targets = []
    for target in inventories[0]["targets"]:
        build = target["buildEvidence"]
        if build["sourceCommit"] != COMMIT:
            raise ValueError("Unexpected baseline source commit")
        selected = []
        rebuilt = {}
        for source in build["rebuiltArchiveEvidence"]:
            if not source.get("sourceCommit") or not source.get("sourceRepository"):
                raise ValueError("Incomplete contemporaneous source-build identity")
            for archive in source["archives"]:
                rebuilt[(archive["path"], archive["sha256"])] = source
        for dependency in target["dependencies"]:
            for archive in dependency.get("selectedArchives", []):
                source = rebuilt.get((archive["candidatePath"], archive["sha256"]))
                if source and source["name"] != dependency["name"]:
                    raise ValueError("Source-build/package identity mismatch")
                selected.append({
                    "path": archive["candidatePath"], "sha256": archive["sha256"],
                    "name": dependency["name"],
                    **({"version": dependency["version"]} if dependency.get("version") else {}),
                    "members": archive["selectedMembers"],
                    "sourceBuilt": source is not None,
                    **({"sourceCommit": source["sourceCommit"],
                        "sourceRepository": source["sourceRepository"]} if source else {}),
                })
        if len({a["path"] for a in selected}) != len(selected):
            raise ValueError("Duplicate baseline selected archive")
        paths = {a["path"] for a in selected}
        trace = build["linkEvidence"][target["id"]]
        trace_selections = {
            (a["candidatePath"], a["sha256"]) for a in trace["archives"]
            if a.get("candidatePath") and a.get("sha256")
        }
        if trace_selections != {(a["path"], a["sha256"]) for a in selected}:
            raise ValueError("Saved packages and actual linker selections differ")
        targets.append({
            "id": target["id"], "binarySha256": target["binarySha256"],
            "analyzedSha256": target["analyzedSha256"],
            "coverage": target["selectedArchiveCoverage"],
            "selectedArchives": sorted(selected, key=lambda a: a["path"]),
            "unselectedCandidates": [
                {"path": a["path"], "sha256": a["sha256"]}
                for a in build["archiveInventory"] if a["path"] not in paths
            ],
            "nonRepositorySelections": [
                {key: a[key] for key in ("reportedPath", "resolvedPath", "scope",
                                        "status", "selectedMembers") if key in a}
                for a in trace["archives"] if not a.get("candidatePath")
            ],
            "configurationInputs": build["configuration"],
        })
    log = (root / "build.log").read_text()
    flags = sorted(set(re.findall(
        r"-target (?:arm64|x86_64)-apple-macos[0-9.]+|/MT\b|"
        r"MACOSX_DEPLOYMENT_TARGET = [0-9.]+", log)))
    return {
        "schemaVersion": 1, "release": "v4.9.10", "sourceCommit": COMMIT,
        "releaseUrl": release["url"], "runUrl": run["url"],
        "assets": [{"name": a["name"], "sha256": a["digest"].removeprefix("sha256:")}
                   for a in sorted(assets, key=lambda a: a["name"])],
        "buildLogSha256": digest(root / "build.log"),
        "observedBuildFlags": flags, "targets": targets,
        "residuals": [
            "No historical source identity is assigned to prebuilt archives.",
            "Curl runtime feature/protocol data and original prebuilt configure flags are not recorded in the published inventory; recovery remains open.",
            "Source/build metadata is contemporaneous evidence, not proof of byte-identical reproducibility.",
            "System frameworks, CRT and external modules are not claimed as exhaustively inventoried."
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_json(args.output, freeze(args.release_directory))
