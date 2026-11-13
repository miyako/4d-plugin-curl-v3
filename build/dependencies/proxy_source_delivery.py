#!/usr/bin/env python3
"""Derive proxy corresponding-source materials without historical probe binaries."""

import argparse
import json
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode = True
import inspect_proxy
from provenance import archive_hashes, digest, write_json


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANIFEST = "proxy-source-delivery.json"
RECORD = "proxy-build-provenance.json"
MATERIALS = [
    RECORD, "upstream-base.tar", "upstream-source.tar", "candidate-recipe.tar",
    "install/include/proxy.h", "install/share/licenses/libproxy/COPYING",
]
TOOLS = [
    "build/dependencies/proxy_source_delivery.py",
    "build/dependencies/relink_candidate.py", "build/dependencies/inspect_proxy.py",
    "build/dependencies/proxy-source.json", "build/sbom/provenance.py",
    "build/sbom/native_archive_objects.py", "LICENSE",
]


def source_lock():
    return json.loads((HERE / "proxy-source.json").read_text())


def inspect(output):
    manifest = json.loads((output / MANIFEST).read_text())
    record = json.loads((output / RECORD).read_text())
    target = record["target"]
    lock = source_lock()
    expected = set(MATERIALS) | {"tools/" + name for name in TOOLS}
    paths = [p.relative_to(output).as_posix() for p in output.rglob("*")
             if p.is_file() and p != output / MANIFEST]
    if (manifest.get("schemaVersion") != 1
            or manifest.get("evidenceType") != "derived-proxy-source-delivery"
            or manifest.get("status") != "not-approved-for-production"
            or manifest.get("target") != target
            or manifest.get("originalBuildRecordSha256") != digest(output / RECORD)
            or set(paths) != expected or any(p.is_symlink() for p in output.rglob("*"))
            or manifest.get("files") != archive_hashes(output, sorted(expected))):
        raise ValueError("Derived proxy source delivery has changed or contains unexpected files")
    key = "windows" if target == "windows-x86_64" else "macos"
    if (target not in ("macos-arm64", "macos-x86_64", "windows-x86_64")
            or record.get("schema_version") != 2
            or record.get("evidence_type") != "isolated-source-build-candidate"
            or any(record.get(field) != lock[field] for field in (
                "status", "components", "patches", "acceptedCandidateChanges", "licenseFile"))
            or record.get("source_repository") != lock["repository"]
            or record.get("source_commit") != lock["commit"]
            or record.get("modules") != lock["modules"][key]):
        raise ValueError("Derived proxy source identity differs from the reviewed candidate")
    inspect_proxy.verify_tar(output / "upstream-base.tar", record["baseSourceFiles"], directories=True)
    inspect_proxy.verify_tar(output / "upstream-source.tar", record["sourceFiles"])
    recipes = [{"path": "build/dependencies/" + a["path"], "sha256": a["sha256"]}
               for a in record["recipeFiles"]] + record["recipeSupportFiles"]
    inspect_proxy.verify_tar(output / "candidate-recipe.tar", recipes)
    inspect_proxy.verify_source_delta(
        record["baseSourceFiles"], record["sourceFiles"], record["patches"])
    support = {a["path"]: a["sha256"] for a in record["recipeSupportFiles"]}
    recipe = {a["path"]: a["sha256"] for a in record["recipeFiles"]}
    sources = {a["path"]: a["sha256"] for a in record["sourceFiles"]}
    if (support.get("LICENSE") != record["recipeLicenseSha256"]
            or not {"build/sbom/provenance.py", "build/sbom/native_archive_objects.py"}.issubset(support)
            or any(recipe.get(p["path"]) != p["sha256"] for p in record["patches"])
            or sources.get(record["licenseFile"]) != record["licenseFileSha256"]
            or digest(output / "install/share/licenses/libproxy/COPYING") != record["licenseFileSha256"]
            or digest(output / "install/include/proxy.h") != sources.get("libproxy/proxy.h")):
        raise ValueError("Delivered proxy patches, helpers, license or public header changed")
    return {
        "target": target, "sourceCommit": record["source_commit"],
        "originalBuildRecordSha256": manifest["originalBuildRecordSha256"],
        "deliveryManifestSha256": digest(output / MANIFEST),
        "scope": "Derived corresponding-source inputs and rebuild tools; not a complete original build-evidence kit, full-plugin delivery or license-compliance certification.",
    }


def export(candidate, output):
    if output.exists() or output.resolve().is_relative_to(candidate.resolve()):
        raise ValueError("Use a fresh source-delivery directory outside the original candidate")
    original = inspect_proxy.inspect(candidate)
    if not original["compilerArchiveBinding"] or original["validationStatus"] != "passed":
        raise ValueError("Source delivery requires a successful original compiler-bound candidate")
    output.mkdir(parents=True)
    for name in MATERIALS:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(candidate / name, destination)
    for name in TOOLS:
        destination = output / "tools" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    write_json(output / MANIFEST, {
        "schemaVersion": 1, "evidenceType": "derived-proxy-source-delivery",
        "status": "not-approved-for-production", "target": original["target"],
        "originalBuildRecordSha256": digest(candidate / RECORD),
        "files": archive_hashes(output, MATERIALS + ["tools/" + name for name in TOOLS]),
        "originalEvidenceScope": "The original record is a reference, not a claim that omitted producer outputs are present. Full originals must be preserved independently.",
        "exclusions": [
            "Historical-baseline and candidate test executables, original compiler objects and static archives.",
            "Product objects, other-library inputs, complete full-plugin redistribution terms and host-install proof remain separate.",
        ],
    })
    return inspect(output)


def inspect_candidate(candidate):
    if (candidate / MANIFEST).exists():
        return inspect(candidate)
    return inspect_proxy.inspect(candidate)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("export")
    sub.add_argument("--candidate", type=Path, required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.candidate.resolve(), args.output.resolve())
                     if args.command == "export" else inspect(args.output.resolve()), indent=2))
