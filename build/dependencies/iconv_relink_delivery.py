#!/usr/bin/env python3
"""Derive GNU source/relink materials without historical probe executables."""

import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
import sys

sys.dont_write_bytecode = True
import build_iconv as iconv
from provenance import archive_hashes, digest, write_json


ROOT = Path(__file__).resolve().parents[2]
RECORD = "native-build-provenance.json"
TOOLS = sorted(set(iconv.ICONV_RECIPES + iconv.WINDOWS_RECIPES + [
    "build/dependencies/iconv_relink_delivery.py",
    "build/dependencies/relink_iconv_macos.py",
]))


def material_paths(record):
    paths = {RECORD, "upstream-source.tar.gz", "baseline.json", "candidate.json", "interface/iconv.h"}
    for field, prefix in (("sourceFiles", "source/"), ("recipeFiles", "recipe/"),
                          ("installFiles", "install/")):
        paths.update(prefix + item["path"] for item in record[field])
    paths.update("tools/" + name for name in TOOLS)
    paths.add("tools/include/iconv.h")
    if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
           or "\\" in name or ":" in name for name in paths):
        raise ValueError("GNU delivery material path escapes its kit")
    return sorted(paths)


def inspect(output):
    manifest = json.loads((output / iconv.DELIVERY_MANIFEST).read_text())
    record = json.loads((output / RECORD).read_text())
    expected = material_paths(record)
    actual = [p.relative_to(output).as_posix() for p in output.rglob("*")
              if p.is_file() and p != output / iconv.DELIVERY_MANIFEST]
    if (manifest.get("schemaVersion") != 1
            or manifest.get("evidenceType") != "derived-iconv-source-relink-delivery"
            or manifest.get("status") != "not-approved-for-production"
            or manifest.get("target") != record["target"]
            or manifest.get("originalBuildRecordSha256") != digest(output / RECORD)
            or set(actual) != set(expected) or any(p.is_symlink() for p in output.rglob("*"))
            or manifest.get("files") != archive_hashes(output, expected)):
        raise ValueError("Derived GNU source/relink delivery changed or contains unexpected files")
    pin = iconv.pin(record["target"])
    if (record.get("schema_version") != 1 or record.get("library") != "libiconv"
            or record.get("evidence_type") != "isolated-source-build-candidate"
            or record.get("status") != "not-approved-for-production"
            or record.get("version") != pin["version"] or record.get("sourceArchive") != pin
            or digest(output / "upstream-source.tar.gz") != pin["sha256"]
            or record["sourceFiles"] != iconv.tree_files(output / "source")
            or record["recipeFiles"] != archive_hashes(
                output / "recipe", [p["path"] for p in record["recipeFiles"]])
            or record["installFiles"] != iconv.tree_files(output / "install")
            or record["archives"] != archive_hashes(
                output / "install", [p["path"] for p in record["archives"]])
            or digest(output / "source" / pin["licenseFile"]) != pin["licenseSha256"]
            or digest(output / "install/share/licenses/libiconv/COPYING.LIB") != pin["licenseSha256"]):
        raise ValueError("GNU source pin, source/recipe tree or known-source reference archive changed")
    iconv.verify_tar(output / "upstream-source.tar.gz", [
        {"path": "libiconv-" + record["version"] + "/" + p["path"], "sha256": p["sha256"]}
        for p in record["sourceFiles"]], directories=True)
    build_files = {p["path"]: p["sha256"] for p in record["buildFiles"]}
    if (any(digest(output / name) != build_files.get(name)
            for name in ("baseline.json", "candidate.json", "interface/iconv.h"))
            or digest(output / "tools/include/iconv.h") != build_files.get("interface/iconv.h")):
        raise ValueError("GNU original comparison/interface input changed")
    iconv.compare(json.loads((output / "candidate.json").read_text()),
                  json.loads((output / "baseline.json").read_text()), record["version"])
    return {
        "target": record["target"], "version": record["version"],
        "originalBuildRecordSha256": manifest["originalBuildRecordSha256"],
        "deliveryManifestSha256": digest(output / iconv.DELIVERY_MANIFEST),
        "scope": "Derived source/relink inputs and one exact known-source reference library; not a complete original producer kit, full-plugin delivery or compliance certification.",
    }


def export(candidate, output):
    if output.exists() or output.resolve().is_relative_to(candidate.resolve()):
        raise ValueError("Use a fresh GNU delivery directory outside the original candidate")
    record = json.loads((candidate / RECORD).read_text())
    if record.get("schema_version") != 1:
        raise ValueError("GNU delivery must derive directly from an original unmodified candidate")
    iconv.inspect(candidate)
    paths = material_paths(record)
    output.mkdir(parents=True)
    for name in paths:
        if name == "tools/include/iconv.h":
            source = candidate / "interface/iconv.h"
        elif name.startswith("tools/"):
            source = ROOT / name.removeprefix("tools/")
        else:
            source = candidate / name
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    write_json(output / iconv.DELIVERY_MANIFEST, {
        "schemaVersion": 1, "evidenceType": "derived-iconv-source-relink-delivery",
        "status": "not-approved-for-production", "target": record["target"],
        "originalBuildRecordSha256": digest(candidate / RECORD),
        "files": archive_hashes(output, paths),
        "originalEvidenceScope": "The original record references omitted producer outputs; full original evidence remains independently preserved.",
        "referenceLibraryScope": "Only the exact original source-built libiconv archive is retained for the user rebuild comparison; no historical prebuilt archive or probe executable is delivered.",
    })
    return inspect(output)


def inspect_candidate(candidate):
    if (candidate / iconv.DELIVERY_MANIFEST).exists():
        return inspect(candidate)
    return iconv.inspect(candidate)


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
