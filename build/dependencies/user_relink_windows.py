#!/usr/bin/env python3
"""Relink a selected-input Windows kit with user-supplied library replacements."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import plugin_relink_delivery as delivery
from plugin_relink_delivery import replacement_options
import portable_plugin_windows as portable
from plugin_relink_materials import relative_path
from provenance import archive_hashes, digest, write_json

MANIFEST = "user-windows-relink-proof.json"
TYPE = "user-supplied-archive-plugin-relink"


def selected_inputs(kit):
    selected = delivery.inspect(kit)
    if selected["target"] != "windows-x86_64":
        raise ValueError("A Windows selected-input kit is required")
    selected["selectedArchives"] = {
        PurePosixPath(p).relative_to("project").as_posix(): sha
        for p, sha in selected["selectedArchives"].items()}
    return selected


def substitute(arguments, selected, replacements):
    result = list(arguments)
    if not replacements or not set(replacements).issubset(selected):
        raise ValueError("Replace explicitly selected repository archive paths only")
    for path, replacement in replacements.items():
        name = PurePosixPath(path).name.casefold()
        if sum(PurePosixPath(p).name.casefold() == name for p in selected) != 1:
            raise ValueError("Ambiguous selected archive basename")
        indexes = [i for i, a in enumerate(result) if a.casefold() == name]
        if len(indexes) != 1:
            raise ValueError("Expected one bare original library argument: " + path)
        result[indexes[0]] = str(replacement)
    return result


def inspect(kit, output):
    selected = selected_inputs(kit)
    record = json.loads((output / MANIFEST).read_text())
    paths = [p.relative_to(output).as_posix() for p in output.rglob("*")
             if p.is_file() and p != output / MANIFEST]
    if (any(p.is_symlink() for p in output.rglob("*"))
            or record.get("schemaVersion") != 1 or record.get("evidenceType") != TYPE
            or record.get("target") != "windows-x86_64"
            or record.get("status") != "not-approved-for-production"
            or record.get("kitManifestSha256") != digest(kit / portable.MANIFEST)
            or record.get("deliveryManifestSha256") != selected["deliveryManifestSha256"]
            or record["files"] != archive_hashes(output, paths)):
        raise ValueError("User relink files or original selected-input bindings changed")
    replacements = record["replacements"]
    if (not replacements or len({p["originalPath"] for p in replacements}) != len(replacements)
            or any(p["originalPath"] not in selected["selectedArchives"]
                   or p["originalSha256"] != selected["selectedArchives"][p["originalPath"]]
                   or p["path"] != "replacements/" + p["originalPath"]
                   or digest(relative_path(output, p["path"])) != p["sha256"]
                   for p in replacements)):
        raise ValueError("User replacements do not bind selected original archives")
    portable.inspect_replay(kit, output / "original-replay")
    baseline = portable.local.pe_layout(
        (output / "original-replay/baseline/cURL.4DX").read_bytes())
    linked = output / "user-linked/cURL.4DX"
    if (record["binarySha256"] != digest(linked)
            or not set(baseline[1]).issubset(portable.local.pe_layout(linked.read_bytes())[1])):
        raise ValueError("User binary changed or original plugin exports were removed")
    return record


def replay(kit, output, replacements):
    if (platform.system() != "Windows" or output.exists()
            or output.is_relative_to(kit) or kit.is_relative_to(output)):
        raise ValueError("Use a fresh external user-relink directory on Windows")
    selected = selected_inputs(kit)
    record = json.loads((kit / portable.MANIFEST).read_text())
    substitute(record["arguments"], selected["selectedArchives"], replacements)
    output.mkdir(parents=True)
    retained = {}
    bindings = []
    for original, source in replacements.items():
        path = relative_path(output, "replacements/" + original)
        path.parent.mkdir(parents=True)
        shutil.copyfile(source, path)
        if source.is_symlink() or digest(source) != digest(path):
            raise ValueError("User archive changed during copying or is a symlink")
        retained[original] = path
        bindings.append({"originalPath": original,
                         "originalSha256": selected["selectedArchives"][original],
                         "path": path.relative_to(output).as_posix(), "sha256": digest(path)})
    portable.replay(kit, output / "original-replay")
    driver = relative_path(Path(os.environ["VCToolsInstallDir"]), record["linkDriverRelativePath"])
    if digest(driver) != record["linkDriverSha256"]:
        raise ValueError("MSVC linker differs from the original build")
    folder = output / "user-linked"
    folder.mkdir()
    arguments = []
    for argument in record["arguments"]:
        for token, value in (("${KIT}", str(kit)), ("${OUTPUT}", str(output)),
                             ("${DRIVER}", str(driver))):
            argument = argument.replace(token, value)
        arguments.append(argument)
    arguments = portable.local.link_arguments(arguments, folder)
    arguments = substitute(arguments, selected["selectedArchives"], retained)
    with (folder / "link.log").open("w") as stream:
        subprocess.run(arguments, cwd=kit / "project", stdout=stream,
                       stderr=subprocess.STDOUT, check=True)
    portable.system_archives(record, kit / "project")
    delivery.inspect(kit)
    proof = {"schemaVersion": 1, "evidenceType": TYPE, "target": "windows-x86_64",
             "status": "not-approved-for-production",
             "kitManifestSha256": digest(kit / portable.MANIFEST),
             "deliveryManifestSha256": selected["deliveryManifestSha256"],
             "driverSha256": digest(Path(__file__)), "command": arguments,
             "replacements": bindings, "binarySha256": digest(folder / "cURL.4DX"),
             "scope": "User-supplied archives, not original producer provenance, source verification, "
                      "CRT/behavior/host validation or legal-compliance certification."}
    proof["files"] = archive_hashes(output, [p.relative_to(output).as_posix()
                                           for p in output.rglob("*") if p.is_file()])
    write_json(output / MANIFEST, proof)
    return inspect(kit, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("replay", "inspect"))
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replace", action="append", default=[])
    args = parser.parse_args()
    kit, output = args.kit.resolve(), args.output.resolve()
    if args.command == "inspect" and args.replace:
        parser.error("inspect reads retained replacements; do not supply --replace")
    proof = (inspect(kit, output) if args.command == "inspect" else
             replay(kit, output, replacement_options(args.replace)))
    print(json.dumps({k: proof[k] for k in ("status", "target", "binarySha256")}, indent=2))
