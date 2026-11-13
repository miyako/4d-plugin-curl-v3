#!/usr/bin/env python3
"""Relink Mac plugin objects with ordinary per-architecture user archives."""

import argparse
import json
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import inspect_proxy
import plugin_relink_delivery as delivery
import portable_plugin_macos as portable
from plugin_relink_delivery import replacement_options
from plugin_relink_materials import relative_path
from provenance import archive_hashes, digest, write_json


MANIFEST = "user-macos-relink-proof.json"
TARGETS = {"macos-arm64", "macos-x86_64"}


def selected_inputs(kit):
    selected = delivery.inspect(kit)
    if selected["target"] != "macos-universal":
        raise ValueError("A Mac universal selected-input kit is required")
    selected["selectedArchives"] = {
        PurePosixPath(p).relative_to("project").as_posix(): sha
        for p, sha in selected["selectedArchives"].items()}
    return selected


def substitute(arguments, kit, selected, replacements):
    result = list(arguments)
    if not set(replacements).issubset(selected):
        raise ValueError("Replace explicitly selected repository archive paths only")
    for path, replacement in replacements.items():
        name = PurePosixPath(path).name
        if (not name.startswith("lib") or not name.endswith(".a")
                or sum(PurePosixPath(p).name == name for p in selected) != 1):
            raise ValueError("Expected an unambiguous selected static Mac archive")
        spellings = {"-l" + name[3:-2], str(kit / "project" / path)}
        indexes = [i for i, value in enumerate(result) if value in spellings]
        if len(indexes) != 1:
            raise ValueError("Expected one original selected archive argument: " + path)
        result[indexes[0]] = str(replacement)
    return result


def arguments_for(kit, output, recipe, driver, sdk, selected, replacements):
    values = {"${KIT}": str(kit), "${OUTPUT}": str(output),
              "${DRIVER}": str(driver), "${SDK}": str(sdk)}
    arguments = []
    for argument in recipe["arguments"]:
        for token, value in values.items():
            argument = argument.replace(token, value)
        arguments.append(argument)
    arguments[arguments.index("-filelist") + 1] = str(output / recipe["target"] / "objects.list")
    return substitute(arguments, kit, selected, replacements)


def public_symbols(data):
    return {s["name"] for s in portable.local.defined_section_symbols(data) if s["public"]}


def link_slices(kit, output, original, driver, sdk, selected, replacements):
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for recipe in original["architectures"]:
        target = recipe["target"]
        folder = output / target
        folder.mkdir()
        (folder / "objects.list").write_text("".join(
            str(relative_path(kit, name)) + "\n" for name in recipe["objects"]))
        arguments = arguments_for(kit, output, recipe, driver, sdk, selected, replacements[target])
        with (folder / "link.log").open("w") as stream:
            subprocess.run(arguments, cwd=kit, stdout=stream, stderr=subprocess.STDOUT, check=True)
        results.append({"target": target, "sha256": digest(folder / "cURL"), "command": arguments})
    subprocess.run(["xcrun", "lipo", "-create",
                    *[str(output / a["target"] / "cURL") for a in results],
                    "-output", str(output / "cURL")], check=True)
    return results


def inspect(kit, output):
    selected = selected_inputs(kit)
    original = json.loads((kit / portable.MANIFEST).read_text())
    record = json.loads((output / MANIFEST).read_text())
    paths = sorted(p.relative_to(output).as_posix() for p in output.rglob("*")
                   if p.is_file() and p != output / MANIFEST)
    if (any(p.is_symlink() for p in output.rglob("*"))
            or record.get("schemaVersion") != 1
            or record.get("evidenceType") != "user-supplied-archive-plugin-relink"
            or record.get("target") != "macos-universal"
            or record.get("status") != "not-approved-for-production"
            or record["kitManifestSha256"] != digest(kit / portable.MANIFEST)
            or record["deliveryManifestSha256"] != selected["deliveryManifestSha256"]
            or record["originalToolchain"] != original["toolchain"]
            or set(record["toolchain"]) != set(original["toolchain"])
            or any(not isinstance(sha, str) or len(sha) != 64
                   or set(sha) - set("0123456789abcdef")
                   for sha in record["toolchain"].values())
            or record["files"] != archive_hashes(output, paths)):
        raise ValueError("User relink files or original selected-input bindings changed")
    replacements = {target: {} for target in TARGETS}
    for item in record["replacements"]:
        target, path = item["target"], item["originalPath"]
        if (target not in TARGETS or path in replacements[target]
                or selected["selectedArchives"].get(path) != item["originalSha256"]
                or item["path"] != "replacements/" + target + "/" + path
                or digest(relative_path(output, item["path"])) != item["sha256"]):
            raise ValueError("User replacements do not bind selected original archives")
        replacements[target][path] = output / item["path"]
        inspect_proxy.verify_architecture(output / item["path"], target)
    if not any(replacements.values()):
        raise ValueError("At least one per-architecture user archive is required")
    old_kit = PurePosixPath(record["originalKitPath"])
    old_output = PurePosixPath(record["originalOutputPath"])
    if any(not p.is_absolute() or ".." in p.parts for p in (old_kit, old_output)):
        raise ValueError("Recorded native working roots are not absolute canonical paths")
    reference = kit / "project/test/Plugins/cURL.bundle/Contents/MacOS/cURL"
    if digest(reference) != original["originalBinarySha256"]:
        raise ValueError("Original reference plugin changed")
    reference_slices = portable.local.generate.mac_slices(reference.read_bytes())
    base_slices = portable.local.generate.mac_slices((output / "baseline/cURL").read_bytes())
    slices = portable.local.generate.mac_slices((output / "cURL").read_bytes())
    if (record["baselineBinarySha256"] != digest(output / "baseline/cURL")
            or record["binarySha256"] != digest(output / "cURL")
            or {a["target"] for a in record["baselineArchitectures"]} != TARGETS
            or len(record["baselineArchitectures"]) != 2
            or {a["target"] for a in record["architectures"]} != TARGETS
            or len(record["architectures"]) != 2):
        raise ValueError("Original or user-linked universal binary changed")
    for recipe in original["architectures"]:
        target = recipe["target"]
        proof = next(a for a in record["architectures"] if a["target"] == target)
        filelist = output / target / "objects.list"
        expected = "".join(str(old_kit / name) + "\n" for name in recipe["objects"])
        old_replacements = {
            path: old_output / replacement.relative_to(output).as_posix()
            for path, replacement in replacements[target].items()}
        base_proof = next(a for a in record["baselineArchitectures"] if a["target"] == target)
        if (portable.local.generate.sha256(reference_slices[target]) != recipe["originalSliceSha256"]
                or portable.local.generate.sha256(base_slices[target]) != base_proof["sha256"]
                or digest(output / "baseline" / target / "cURL") != base_proof["sha256"]
                or (output / "baseline" / target / "objects.list").read_text() != expected
                or base_proof["command"] != arguments_for(
                    old_kit, old_output / "baseline", recipe, record["driver"], record["sdk"],
                    selected["selectedArchives"], {})
                or portable.local.generate.sha256(slices[target]) != proof["sha256"]
                or digest(output / target / "cURL") != proof["sha256"]
                or filelist.read_text() != expected
                or proof["command"] != arguments_for(
                    old_kit, old_output, recipe, record["driver"], record["sdk"],
                    selected["selectedArchives"], old_replacements)
                or not public_symbols(reference_slices[target]).issubset(public_symbols(base_slices[target]))
                or not public_symbols(base_slices[target]).issubset(public_symbols(slices[target]))):
            raise ValueError("User slice, raw link recipe or original public symbols changed")
    return record


def replay(kit, output, replacements):
    if (platform.system() != "Darwin" or output.exists()
            or output.is_relative_to(kit) or kit.is_relative_to(output)):
        raise ValueError("Use a fresh external user-relink directory on macOS")
    selected = selected_inputs(kit)
    original = json.loads((kit / portable.MANIFEST).read_text())
    if set(replacements) - TARGETS or not any(replacements.values()):
        raise ValueError("At least one supported per-architecture user archive is required")
    driver = Path(subprocess.check_output(["xcrun", "--find", "clang++"], text=True).strip())
    sdk = Path(subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip())
    toolchain = portable.toolchain(driver, sdk)
    retained = {target: {} for target in TARGETS}
    bindings = []
    for target, archives in replacements.items():
        for path, source in archives.items():
            if path not in selected["selectedArchives"] or source.is_symlink():
                raise ValueError("Use regular user archives for explicitly selected paths")
            inspect_proxy.verify_architecture(source, target)
            destination = relative_path(output, "replacements/" + target + "/" + path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if digest(source) != digest(destination):
                raise ValueError("User archive changed during copying")
            retained[target][path] = destination
            bindings.append({"target": target, "originalPath": path,
                             "originalSha256": selected["selectedArchives"][path],
                             "path": destination.relative_to(output).as_posix(),
                             "sha256": digest(destination)})
    baseline = link_slices(kit, output / "baseline", original, driver, sdk,
                           selected["selectedArchives"], {target: {} for target in TARGETS})
    results = link_slices(kit, output, original, driver, sdk, selected["selectedArchives"], retained)
    if portable.toolchain(driver, sdk) != toolchain:
        raise ValueError("Apple toolchain changed during user relinking")
    proof = {
        "schemaVersion": 1, "evidenceType": "user-supplied-archive-plugin-relink",
        "status": "not-approved-for-production", "target": "macos-universal",
        "kitManifestSha256": digest(kit / portable.MANIFEST),
        "deliveryManifestSha256": selected["deliveryManifestSha256"],
        "originalKitPath": str(kit), "originalOutputPath": str(output),
        "driver": str(driver), "sdk": str(sdk), "toolchain": toolchain,
        "originalToolchain": original["toolchain"],
        "baselineArchitectures": baseline,
        "baselineBinarySha256": digest(output / "baseline/cURL"),
        "replacements": bindings, "architectures": results, "binarySha256": digest(output / "cURL"),
        "scope": "User-supplied thin archives linked using a separately recorded user toolchain, "
                 "with original public symbols retained. Not byte-identical reproduction, original "
                 "producer provenance, source/behavior/host proof or legal-compliance certification.",
    }
    proof["files"] = archive_hashes(output, sorted(
        p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()))
    write_json(output / MANIFEST, proof)
    return inspect(kit, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("replay", "inspect"))
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replace-arm64", action="append", default=[])
    parser.add_argument("--replace-x86-64", action="append", default=[])
    args = parser.parse_args()
    if args.command == "inspect" and (args.replace_arm64 or args.replace_x86_64):
        parser.error("inspect reads retained replacements; do not supply replacement options")
    kit, output = args.kit.resolve(), args.output.resolve()
    result = (inspect(kit, output) if args.command == "inspect" else replay(kit, output, {
        "macos-arm64": replacement_options(args.replace_arm64),
        "macos-x86_64": replacement_options(args.replace_x86_64)}))
    print(json.dumps({key: result[key] for key in ("status", "target", "binarySha256")}, indent=2))
