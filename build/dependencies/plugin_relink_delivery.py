#!/usr/bin/env python3
"""Derive isolated selected-input plugin relink materials from full audit kits."""

import argparse
import copy
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import sys

sys.dont_write_bytecode = True
import iconv_relink_delivery
import proxy_source_delivery
from plugin_relink_materials import relative_path, verify_files
from provenance import archive_hashes, digest, write_json


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "plugin-relink-delivery.json"
TYPE = "derived-selected-input-plugin-relink-delivery"
PORTABLE = {"macos-universal": "portable-object-kit.json",
            "windows-x86_64": "portable-windows-object-kit.json"}
HISTORICAL_CONTAINERS = {"product-source/cURL.zip", "product-source/cURL.dmg"}


def replacement_options(values):
    result = {}
    for value in values:
        key, separator, path = value.partition("=")
        if (not separator or not path or key in result or "\\" in key
                or PureWindowsPath(key).drive or PurePosixPath(key).is_absolute()
                or ".." in PurePosixPath(key).parts
                or PurePosixPath(key).as_posix() != key):
            raise ValueError("Use unique canonical repository/archive=USER_ARCHIVE replacements")
        result[key] = Path(path).absolute()
    return result


def selected_archives(evidence):
    result = {}
    for link in evidence["linkEvidence"].values():
        for item in link["archives"]:
            if item["scope"] != "repository":
                continue
            path = item["candidatePath"]
            if (PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                    or "\\" in path or ":" in path):
                raise ValueError("Selected repository archive path escapes its project")
            name, sha = "project/" + path, item["sha256"]
            if name in result and result[name] != sha:
                raise ValueError("Selected archive has conflicting target hashes")
            result[name] = sha
    if not result:
        raise ValueError("Actual repository archive selection is required")
    return result


def filtered_arguments(arguments, omitted_names, selected_names, system_names=()):
    omitted, selected, system = (set(n.casefold() for n in names)
                                  for names in (omitted_names, selected_names, system_names))
    if omitted & selected or omitted & system:
        raise ValueError("Omitted library basename collides with a retained or system input")
    result, removed = [], []
    for index, value in enumerate(arguments):
        name = None
        if value.startswith("-l"):
            name = "lib" + value[2:] + ".a"
        elif value.lower().endswith(".lib") and not value.startswith("/"):
            name = PurePosixPath(value.replace("\\", "/")).name
        if name and name.casefold() in omitted:
            removed.append({"index": index, "argument": value})
        else:
            result.append(value)
    return result, removed


def inspect(kit):
    marker = json.loads((kit / MANIFEST).read_text())
    target = marker["target"]
    if target not in PORTABLE:
        raise ValueError("Unsupported derived plugin delivery target")
    name = PORTABLE[target]
    record = json.loads((kit / name).read_text())
    reference = "original-" + name
    original = json.loads((kit / reference).read_text())
    if (marker.get("schemaVersion") != 1 or marker.get("evidenceType") != TYPE
            or marker.get("status") != "not-approved-for-production"
            or marker.get("portableRecordSha256") != digest(kit / name)
            or marker.get("originalKitRecordSha256") != digest(kit / reference)
            or record.get("evidenceType") != TYPE
            or record.get("status") != "not-approved-for-production"
            or record["target"] != target or original["target"] != target
            or record["originalBuildEvidenceSha256"] != original["originalBuildEvidenceSha256"]
            or record["originalBinarySha256"] != original["originalBinarySha256"]):
        raise ValueError("Derived plugin delivery reference or manifest changed")
    changed = {"files", "arguments", "architectures", "limitations", "evidenceType"}
    if ({k: v for k, v in record.items() if k not in changed}
            != {k: v for k, v in original.items() if k not in changed}):
        raise ValueError("Derived delivery changed original binary, toolchain or source metadata")
    verify_files(kit, record)
    actual = {p.relative_to(kit).as_posix() for p in kit.rglob("*") if p.is_file()}
    if (actual != {p["path"] for p in record["files"]} | {name, MANIFEST}
            or any(p.is_symlink() for p in kit.rglob("*"))):
        raise ValueError("Derived plugin delivery contains unexpected files or links")
    evidence_path = kit / "project/native-trace/build-evidence.json"
    if digest(evidence_path) != record["originalBuildEvidenceSha256"]:
        raise ValueError("Original selected-link evidence changed")
    selected = selected_archives(json.loads(evidence_path.read_text()))
    delivered = {p["path"]: p["sha256"] for p in record["files"]
                 if p["path"].startswith("project/") and Path(p["path"]).suffix.lower() in (
                     ".a", ".lib", ".dylib")}
    if selected != delivered or marker.get("selectedArchives") != selected:
        raise ValueError("Derived plugin delivery must contain only exact selected repository libraries")
    if actual & HISTORICAL_CONTAINERS:
        raise ValueError("Historical product containers are not derived source materials")
    omitted = marker["omittedLibraries"]
    source_files = {p["path"]: p["sha256"] for p in original["files"]}
    expected_omissions = [p for p in original["files"] if p["path"].startswith("project/")
                         and Path(p["path"]).suffix.lower() in (".a", ".lib", ".dylib")
                         and p["path"] not in selected]
    if (omitted != expected_omissions
            or marker["omittedHistoricalContainers"] != [
                p for p in original["files"] if p["path"] in HISTORICAL_CONTAINERS]
            or any(p["path"] in actual or source_files.get(p["path"]) != p["sha256"] for p in omitted)
            or any(source_files.get(p) != sha for p, sha in selected.items())):
        raise ValueError("Selected or omitted library evidence differs from the original audit kit")
    selected_names = [Path(p).name for p in selected]
    omitted_names = [Path(p["path"]).name for p in omitted]
    if target == "macos-universal":
        if len(record["architectures"]) != len(original["architectures"]):
            raise ValueError("Derived plugin architecture coverage changed")
        for old, new in zip(original["architectures"], record["architectures"]):
            expected = copy.deepcopy(old)
            expected["arguments"], _ = filtered_arguments(old["arguments"], omitted_names, selected_names)
            if new != expected:
                raise ValueError("Derived Mac link recipe changes more than unused repository flags")
    else:
        expected, _ = filtered_arguments(original["arguments"], omitted_names, selected_names,
                                        [p["name"] for p in original["systemArchives"]])
        if record["arguments"] != expected:
            raise ValueError("Derived Windows link recipe changes more than unused repository flags")
    if len(record["libraryMaterials"]) != len(original["libraryMaterials"]):
        raise ValueError("Derived LGPL source-material coverage changed")
    for old, new in zip(original["libraryMaterials"], record["libraryMaterials"]):
        if new != old:
            raise ValueError("Derived source-material identity changed")
        material = relative_path(kit, new["directory"])
        helper = proxy_source_delivery if new["library"] == "libproxy" else iconv_relink_delivery
        proof = helper.inspect(material)
        if proof["originalBuildRecordSha256"] != new["originalBuildRecordSha256"]:
            raise ValueError("Derived source materials differ from the selected original producer")
    return {"target": target, "status": record["status"], "selectedArchives": selected,
            "deliveryManifestSha256": digest(kit / MANIFEST),
            "scope": "Derived selected inputs and LGPL source/relink materials; not complete notices, licensing, installation or host verification."}


def verify_if_derived(kit, record):
    if record.get("evidenceType") == TYPE or (kit / MANIFEST).exists():
        inspect(kit)


def bind_probe_inputs(kit, target, project, archives):
    selected = inspect(kit)
    if target not in ("macos-arm64", "macos-x86_64", "windows-x86_64"):
        raise ValueError("Unsupported native probe target")
    windows = target.startswith("windows")
    if selected["target"] != ("windows-x86_64" if windows else "macos-universal"):
        raise ValueError("Probe and selected plugin delivery targets differ")
    manifest = PORTABLE[selected["target"]]
    record = json.loads((kit / manifest).read_text())
    paths = PureWindowsPath if windows else PurePosixPath
    inputs = []
    for item in archives:
        relative = "project/" + paths(item["path"]).relative_to(paths(project)).as_posix()
        if selected["selectedArchives"].get(relative) != item["sha256"]:
            raise ValueError("Probe input differs from actual selected plugin archives")
        inputs.append({"path": relative, "sha256": item["sha256"]})
    if not inputs or len({p["path"] for p in inputs}) != len(inputs):
        raise ValueError("Empty or repeated probe archive bindings")
    slice_hash = None
    if not windows:
        architectures = [a for a in record["architectures"] if a["target"] == target]
        if len(architectures) != 1:
            raise ValueError("Missing or repeated original plugin slice")
        slice_hash = architectures[0]["originalSliceSha256"]
    return {"target": target, "kitManifestSha256": digest(kit / manifest),
            "deliveryManifestSha256": selected["deliveryManifestSha256"],
            "binarySha256": record["originalBinarySha256"], "sliceSha256": slice_hash,
            "inputs": inputs}


def export(original, output):
    if output.exists() or output.resolve().is_relative_to(original.resolve()):
        raise ValueError("Use a fresh derived delivery directory outside the original audit kit")
    names = [name for name in PORTABLE.values() if (original / name).is_file()]
    if len(names) != 1 or (original / MANIFEST).exists():
        raise ValueError("Derive directly from one original full portable audit kit")
    name = names[0]
    record = json.loads((original / name).read_text())
    if (record.get("schemaVersion") != 1 or record.get("status") != "not-approved-for-production"
            or PORTABLE.get(record["target"]) != name or record.get("evidenceType") == TYPE):
        raise ValueError("Expected an original isolated full portable audit kit")
    verify_files(original, record)
    evidence = json.loads((original / "project/native-trace/build-evidence.json").read_text())
    if digest(original / "project/native-trace/build-evidence.json") != record["originalBuildEvidenceSha256"]:
        raise ValueError("Original audit evidence changed")
    selected = selected_archives(evidence)
    omitted = [p for p in record["files"] if p["path"].startswith("project/")
               and Path(p["path"]).suffix.lower() in (".a", ".lib", ".dylib")
               and p["path"] not in selected]
    omitted_paths = {p["path"] for p in omitted}
    output.mkdir(parents=True)
    for item in record["files"]:
        path = item["path"]
        if path.startswith("library-materials/") or path in omitted_paths | HISTORICAL_CONTAINERS:
            continue
        source, destination = relative_path(original, path), relative_path(output, path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for material in record["libraryMaterials"]:
        helper = proxy_source_delivery if material["library"] == "libproxy" else iconv_relink_delivery
        helper.export(relative_path(original, material["directory"]),
                      relative_path(output, material["directory"]))
    for folder in ("dependencies", "sbom"):
        for source in (ROOT / "build" / folder).iterdir():
            if source.is_file() and source.suffix in (".py", ".json"):
                destination = output / "tools/build" / folder / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
    shutil.copyfile(original / name, output / ("original-" + name))
    derived = copy.deepcopy(record)
    derived["evidenceType"] = TYPE
    derived["limitations"] = [
        "Derived selected-input/source-relink candidate, not an unchanged original full producer/audit kit.",
        "Original unused repository flags and archive copies omitted; matching native baseline/modified replay is required.",
        "Complete third-party notices/terms, proprietary toolchain prerequisites, installation/trust and operator host gates remain.",
    ]
    selected_names = [Path(p).name for p in selected]
    omitted_names = [Path(p["path"]).name for p in omitted]
    if record["target"] == "macos-universal":
        for recipe in derived["architectures"]:
            recipe["arguments"], _ = filtered_arguments(recipe["arguments"], omitted_names, selected_names)
            for value in recipe["arguments"]:
                if value.startswith(("-L${KIT}/", "-F${KIT}/")):
                    relative_path(output, value[9:]).mkdir(parents=True, exist_ok=True)
    else:
        derived["arguments"], _ = filtered_arguments(record["arguments"], omitted_names, selected_names,
                                                    [p["name"] for p in record["systemArchives"]])
    derived["files"] = archive_hashes(output, [
        p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()])
    write_json(output / name, derived)
    write_json(output / MANIFEST, {
        "schemaVersion": 1, "evidenceType": TYPE, "status": "not-approved-for-production",
        "target": record["target"], "originalKitRecordSha256": digest(original / name),
        "portableRecordSha256": digest(output / name), "selectedArchives": selected,
        "omittedLibraries": omitted,
        "omittedHistoricalContainers": [p for p in record["files"] if p["path"] in HISTORICAL_CONTAINERS],
    })
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("export")
    sub.add_argument("--original", type=Path, required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("kit", type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.original.resolve(), args.output.resolve())
                     if args.command == "export" else inspect(args.kit.resolve()), indent=2))
