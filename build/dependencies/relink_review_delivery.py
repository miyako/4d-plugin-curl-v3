#!/usr/bin/env python3
"""Assemble selected plugin/source/notice inputs without rewriting producer evidence."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import license_materials
import plugin_relink_delivery as plugins
from plugin_relink_materials import relative_path
from provenance import archive_hashes, digest, write_json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sbom"))
import provider_materials
import generate


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "relink-review-delivery.json"
TARGETS = {"macos-arm64": "macos-universal", "macos-x86_64": "macos-universal",
           "windows-x86_64": "windows-x86_64"}
REQUIRED = ["RELINKING.md", "tools/LICENSE"] + [
    "tools/build/dependencies/" + name for name in (
        "RELINKING.md", "README.md", "user_relink_macos.py", "user_relink_windows.py",
        "relink_review_delivery.py", "relink_iconv_macos.py", "native-sources.json")]


def provider_references(inventory):
    result = {}
    for target in inventory["targets"]:
        for dependency in target["dependencies"]:
            for archive in dependency.get("archiveIdentities", []):
                source = archive["identity"]["sourceEvidence"]
                for reference in source.get("source_builds", []):
                    record = reference.get("record", reference)
                    if not record.get("buildMaterialEvidence"):
                        raise ValueError("Selected provider lacks original compiler/source evidence")
                    sha = record["buildMaterialEvidence"]["originalRecordSha256"]
                    value = {"name": dependency["name"],
                             "target": reference.get("target", record.get("target")), "record": record}
                    if (len(sha) != 64 or set(sha) - set("0123456789abcdef")
                            or value["target"] not in TARGETS
                            or (sha in result and result[sha] != value)):
                        raise ValueError("Provider source references are conflicting or unsupported")
                    result[sha] = value
    if not result:
        raise ValueError("Original provider compiler/source records are required")
    return result


def provider_paths(record):
    paths = ["original-build-record.json"]
    paths.extend("build-materials/" + p["path"] for p in record["buildMaterials"]["files"])
    paths.extend(p["path"] for p in record["archives"])
    if len(set(paths)) != len(paths):
        raise ValueError("Provider material paths overlap")
    return sorted(paths)


def join_selected(inventory, kits):
    if (inventory.get("inventoryVersion") != 1
            or {t["id"] for t in inventory["targets"]} != set(TARGETS)
            or len(inventory["targets"]) != len(TARGETS)
            or set(kits) != set(TARGETS.values())):
        raise ValueError("One inventory and both selected platform kits are required")
    summaries = {key: plugins.inspect(path) for key, path in kits.items()}
    records = {key: json.loads((path / plugins.PORTABLE[key]).read_text())
               for key, path in kits.items()}
    expected = {key: {} for key in kits}
    bindings = []
    for target in inventory["targets"]:
        seen = set()
        platform = TARGETS[target["id"]]
        record = records[platform]
        if target["binarySha256"] != record["originalBinarySha256"]:
            raise ValueError("Inventory/plugin reference binary mismatch")
        if target["id"].startswith("macos-"):
            slices = [a for a in record["architectures"] if a["target"] == target["id"]]
            if len(slices) != 1 or target["analyzedSha256"] != slices[0]["originalSliceSha256"]:
                raise ValueError("Inventory/plugin reference slice mismatch")
        elif target["analyzedSha256"] != target["binarySha256"]:
            raise ValueError("Windows analyzed/plugin binary mismatch")
        for dependency in target["dependencies"]:
            selected = dependency.get("selectedArchives", [])
            if selected and len(dependency.get("archiveIdentities", [])) != len(selected):
                raise ValueError("Selected archive lacks source identity evidence")
            for archive in selected:
                path, sha = "project/" + archive["candidatePath"], archive["sha256"]
                if path in seen:
                    raise ValueError("A target selected archive is assigned more than once")
                seen.add(path)
                if path in expected[platform] and expected[platform][path] != sha:
                    raise ValueError("One selected archive has conflicting target hashes")
                expected[platform][path] = sha
                bindings.append({"target": target["id"], "name": dependency["name"],
                                 "version": dependency.get("version"), "path": path, "sha256": sha})
    if any(expected[key] != summaries[key]["selectedArchives"] for key in kits):
        raise ValueError("Inventory does not match every actual selected kit archive")
    return bindings


def reference_plugin(path, inventory):
    if path.suffix.lower() != ".zip" or digest(path) != inventory["artifact"]["sha256"]:
        raise ValueError("Reference must be the exact original unsigned cross-platform ZIP")
    with generate.container_reader(path) as read:
        for target in inventory["targets"]:
            data = read(target["binaryPath"])
            if generate.sha256(data) != target["binarySha256"]:
                raise ValueError("Reference ZIP binary differs from the original inventory")
            if target["id"].startswith("macos-"):
                data = generate.mac_slices(data)[target["id"]]
            else:
                generate.check_pe(data)
            if generate.sha256(data) != target["analyzedSha256"]:
                raise ValueError("Reference ZIP target slice differs from the original inventory")


def inspect(output):
    manifest = json.loads((output / MANIFEST).read_text())
    inventory_path = output / "inventory.json"
    inventory = json.loads(inventory_path.read_text())
    actual = sorted(p.relative_to(output).as_posix() for p in output.rglob("*")
                    if p.is_file() and p != output / MANIFEST)
    if (manifest.get("schemaVersion") != 1
            or manifest.get("evidenceType") != "combined-candidate-relink-review-delivery"
            or manifest.get("status") != "not-approved-for-production"
            or manifest["inventorySha256"] != digest(inventory_path)
            or manifest["referencedPluginArtifact"] != inventory["artifact"]
            or any(not relative_path(output, path).is_file() for path in REQUIRED)
            or (output / "RELINKING.md").read_bytes() != (
                output / "tools/build/dependencies/RELINKING.md").read_bytes()
            or any(p.is_symlink() for p in output.rglob("*"))
            or manifest["files"] != archive_hashes(output, actual)):
        raise ValueError("Combined delivery bytes, scope or original inventory changed")
    reference_plugin(relative_path(output / "reference", inventory["artifact"]["name"]), inventory)
    kits = {key: output / "platforms" / key for key in set(TARGETS.values())}
    bindings = join_selected(inventory, kits)
    notices = license_materials.inspect_delivery(output / "notices", inventory_path)
    if (manifest["selectedArchiveBindings"] != bindings
            or manifest["notices"] != notices
            or notices["selectedArchiveBindings"] != len(bindings)):
        raise ValueError("Combined source/object/notice coverage changed")
    expected = provider_references(inventory)
    if (len(manifest["providers"]) != len(expected)
            or {p["originalRecordSha256"] for p in manifest["providers"]} != set(expected)):
        raise ValueError("Missing or repeated original provider source-material joins")
    for item in manifest["providers"]:
        sha = item["originalRecordSha256"]
        record_path = output / "providers" / sha / "original-build-record.json"
        original = json.loads(record_path.read_text())
        files = sorted(p.relative_to(record_path.parent).as_posix()
                       for p in record_path.parent.rglob("*") if p.is_file())
        if (item != {"originalRecordSha256": sha, "name": expected[sha]["name"],
                     "target": expected[sha]["target"]}
                or digest(record_path) != sha or files != provider_paths(original)
                or provider_materials.compact_record(record_path) != expected[sha]["record"]):
            raise ValueError("Provider source/compiler/archive record differs from inventory")
    return {"status": manifest["status"], "selectedArchiveBindings": len(bindings),
            "versionedSelectedArchiveBindings": sum(p["version"] is not None for p in bindings),
            "providerRecords": len(expected), "notices": notices,
            "deliveryManifestSha256": digest(output / MANIFEST)}


def deliver(inventory_path, reference, mac_kit, windows_kit, notices, providers, output):
    inputs = [inventory_path.parent, reference.parent, mac_kit, windows_kit, notices,
              *[path.parent for path in providers], ROOT]
    if (output.exists() or any(output.is_relative_to(p) or p.is_relative_to(output) for p in inputs)):
        raise ValueError("Use a fresh external delivery directory")
    inventory = json.loads(inventory_path.read_text())
    reference_plugin(reference, inventory)
    kits = {"macos-universal": mac_kit, "windows-x86_64": windows_kit}
    bindings = join_selected(inventory, kits)
    notice_summary = license_materials.inspect_delivery(notices, inventory_path)
    references = provider_references(inventory)
    paths = {digest(path): path for path in providers}
    if len(paths) != len(providers) or set(paths) != set(references):
        raise ValueError("Supply each exact original referenced provider record once")
    for sha, path in paths.items():
        if provider_materials.compact_record(path) != references[sha]["record"]:
            raise ValueError("Original provider does not match normalized source evidence")
    output.mkdir(parents=True)
    shutil.copyfile(inventory_path, output / "inventory.json")
    (output / "reference").mkdir()
    shutil.copyfile(reference, relative_path(output / "reference", inventory["artifact"]["name"]))
    for target, path in kits.items():
        shutil.copytree(path, output / "platforms" / target)
    shutil.copytree(notices, output / "notices")
    delivered = []
    for sha, path in sorted(paths.items()):
        record = json.loads(path.read_text())
        destination = output / "providers" / sha
        for name in provider_paths(record):
            source = path if name == "original-build-record.json" else relative_path(path.parent, name)
            target = relative_path(destination, name)
            if not source.is_file() or source.is_symlink():
                raise ValueError("Provider delivery needs regular retained material files")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        delivered.append({"originalRecordSha256": sha, "name": references[sha]["name"],
                          "target": references[sha]["target"]})
    tracked = subprocess.check_output([
        "git", "-C", str(ROOT), "ls-files", "-z", "--",
        "build/dependencies", "build/sbom", "LICENSE"]).decode().split("\0")
    for name in filter(None, tracked):
        source = relative_path(ROOT, name)
        if not source.is_file() or source.is_symlink():
            raise ValueError("Current user tools must be regular tracked source files")
        destination = relative_path(output / "tools", name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    shutil.copyfile(ROOT / "build/dependencies/RELINKING.md", output / "RELINKING.md")
    manifest = {
        "schemaVersion": 1, "evidenceType": "combined-candidate-relink-review-delivery",
        "status": "not-approved-for-production", "inventorySha256": digest(inventory_path),
        "referencedPluginArtifact": inventory["artifact"], "selectedArchiveBindings": bindings,
        "notices": notice_summary, "providers": delivered,
        "toolSourceCommit": subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "files": archive_hashes(output, sorted(
            p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file())),
        "scope": "Combined review/user-relink materials, not a product release or compliance "
                 "certification. Original records remain unchanged. Provider audit trees retain "
                 "complete compiler/archive closure, including unselected source-built outputs; "
                 "only platform selected-kit archives are plugin link inputs. No proprietary "
                 "compiler/SDK/CRT/system archives or installed provider executables are copied.",
    }
    write_json(output / MANIFEST, manifest)
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--reference-zip", type=Path)
    parser.add_argument("--mac-kit", type=Path)
    parser.add_argument("--windows-kit", type=Path)
    parser.add_argument("--notices", type=Path)
    parser.add_argument("--provider", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    if not args.inspect_only and any(getattr(args, key) is None for key in (
            "inventory", "reference_zip", "mac_kit", "windows_kit", "notices")):
        parser.error("Provide the original inventory/reference ZIP, both selected kits and notices")
    result = (inspect(args.output.resolve()) if args.inspect_only else deliver(
        args.inventory.resolve(), args.reference_zip.resolve(), args.mac_kit.resolve(), args.windows_kit.resolve(),
        args.notices.resolve(), [p.resolve() for p in args.provider], args.output.resolve()))
    print(json.dumps(result, indent=2))
