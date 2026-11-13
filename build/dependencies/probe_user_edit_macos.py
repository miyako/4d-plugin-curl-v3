#!/usr/bin/env python3
"""Rebuild an active GNU function and use its archive in a marker-free Mac plugin link."""

import argparse
import json
from pathlib import Path, PurePosixPath
import platform
import sys

sys.dont_write_bytecode = True
from build_native import probe_selections
from plugin_relink_materials import relative_path
from provenance import archive_hashes, digest, write_json
import relink_iconv_macos as library
import user_relink_macos as user


def source_material(kit, target):
    original = json.loads((kit / user.portable.MANIFEST).read_text())
    materials = [m for m in original["libraryMaterials"]
                 if m["library"] == "libiconv" and m["target"] == target]
    if len(materials) != 1:
        raise ValueError("One original GNU source kit is required for the selected architecture")
    return relative_path(kit, materials[0]["directory"])


def inspect(kit, output):
    record = json.loads((output / "user-edit-proof.json").read_text())
    target = record["target"]
    built = library.inspect(source_material(kit, target), output / "library")
    proof = user.inspect(kit, output / "plugin")
    replacements = proof["replacements"]
    if len(replacements) != 1 or replacements[0]["target"] != target:
        raise ValueError("Expected one native user GNU replacement")
    replacement = replacements[0]
    archive = output / "library/build/lib/.libs/libiconv.a"
    original_archive = PurePosixPath(proof["originalOutputPath"]) / replacement["path"]
    folder = output / "plugin" / target
    selected = probe_selections(
        folder, target, {"libiconv": {"path": str(original_archive)}},
        map_name="link.map", log_name="link.log",
        working_directory=proof["originalKitPath"])["libiconv"]
    lines = [line for line in (folder / "link.map").read_text(
        encoding="utf-8", errors="surrogateescape").splitlines()
             if "_libiconv_close" in line.split()]
    binary = folder / "cURL"
    baseline = output / "plugin/baseline" / target / "cURL"
    if (record.get("schemaVersion") != 1
            or record.get("evidenceType") != "marker-free-user-source-edit-experiment"
            or record.get("status") != "not-approved-for-production"
            or built.get("modificationKind") != "active-function-user-edit"
            or record["originalKitManifestSha256"] != digest(kit / user.portable.MANIFEST)
            or record["libraryProofSha256"] != digest(output / "library/iconv-user-relink-proof.json")
            or record["pluginProofSha256"] != digest(output / "plugin" / user.MANIFEST)
            or record["sourceModification"] != built["modification"]
            or record["archiveSha256"] != digest(archive)
            or replacement["sha256"] != digest(archive)
            or record["selectedMembers"] != selected
            or record["activeFunctionMapLine"] not in lines or len(lines) != 1
            or record["conversionChecks"] != library.iconv.CHECKS
            or record["binarySha256"] != proof["binarySha256"]
            or record["files"] != archive_hashes(output, sorted(
                p.relative_to(output).as_posix() for p in output.rglob("*")
                if p.is_file() and p != output / "user-edit-proof.json"))):
        raise ValueError("User source/compiler/archive/plugin experiment binding changed")
    if (digest(binary) == digest(baseline)
            or not any(s["member"] == "iconv.o" for s in selected)
            or any(marker.encode() in p.read_bytes() for marker in (
                "iconv_user_relink_probe", "proxy_user_relink_probe") for p in (archive, binary))
            or any("user_relink_probe" in a for item in proof["architectures"] for a in item["command"])):
        raise ValueError("Full-plugin link did not retain the active marker-free user change")
    return record


def run(kit, output, target):
    if (platform.system() != "Darwin" or target not in user.TARGETS or output.exists()
            or output.is_relative_to(kit) or kit.is_relative_to(output)):
        raise ValueError("Use a supported target and fresh external Mac experiment directory")
    user.selected_inputs(kit)
    material = source_material(kit, target)
    output.mkdir(parents=True)
    built = library.rebuild(material, output / "library", active_function=True)
    archive = output / "library/build/lib/.libs/libiconv.a"
    proof = user.replay(kit, output / "plugin", {target: {"a/libiconv.a": archive}})
    folder = output / "plugin" / target
    retained = output / "plugin" / proof["replacements"][0]["path"]
    selected = probe_selections(
        folder, target, {"libiconv": {"path": str(retained)}},
        map_name="link.map", log_name="link.log", working_directory=kit)["libiconv"]
    lines = [line for line in (folder / "link.map").read_text(
        encoding="utf-8", errors="surrogateescape").splitlines()
             if "_libiconv_close" in line.split()]
    if len(lines) != 1:
        raise ValueError("One live GNU close-function map symbol is required")
    record = {
        "schemaVersion": 1, "evidenceType": "marker-free-user-source-edit-experiment",
        "status": "not-approved-for-production", "target": target,
        "originalKitManifestSha256": digest(kit / user.portable.MANIFEST),
        "libraryProofSha256": digest(output / "library/iconv-user-relink-proof.json"),
        "pluginProofSha256": digest(output / "plugin" / user.MANIFEST),
        "sourceModification": built["modification"], "archiveSha256": digest(archive),
        "selectedMembers": selected, "activeFunctionMapLine": lines[0],
        "conversionChecks": library.iconv.CHECKS, "binarySha256": proof["binarySha256"],
        "scope": "Native GNU source recompile, baseline conversions and raw universal plugin link; "
                 "separate user toolchain, no fixed marker, plugin/4D loading or production approval.",
    }
    record["files"] = archive_hashes(output, sorted(
        p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()))
    write_json(output / "user-edit-proof.json", record)
    return inspect(kit, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=sorted(user.TARGETS))
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    if args.inspect_only == bool(args.target):
        parser.error("Choose --target for a new build, or --inspect-only for existing outputs")
    result = (inspect(args.kit.resolve(), args.output.resolve()) if args.inspect_only else
              run(args.kit.resolve(), args.output.resolve(), args.target))
    print(json.dumps({key: result[key] for key in ("status", "target", "binarySha256")}, indent=2))
