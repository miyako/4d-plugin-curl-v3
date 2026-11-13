#!/usr/bin/env python3
"""Export and replay relocated Windows plugin inputs without loading the DLL."""

import argparse
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import platform
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import relink_plugin_windows as local
from plugin_relink_delivery import verify_if_derived
from plugin_relink_materials import copy_delivery, relative_path, verify_files
from provenance import archive_hashes, digest, write_json


MANIFEST = "portable-windows-object-kit.json"


def inspect_replay(kit, output, modified=None, modified_iconv=None):
    record = json.loads((kit / MANIFEST).read_text())
    proof = json.loads((output / "portable-windows-replay-proof.json").read_text())
    if (record["schemaVersion"] != 1 or record["target"] != "windows-x86_64"
            or record["status"] != "not-approved-for-production"
            or proof["status"] != record["status"] or proof["target"] != record["target"]
            or proof["kitManifestSha256"] != digest(kit / MANIFEST)):
        raise ValueError("Portable Windows replay does not bind this candidate kit")
    verify_if_derived(kit, record)
    verify_files(kit, record)
    binary = kit / "project/test/Plugins/cURL.bundle/Contents/Windows64/cURL.4DX"
    if (digest(binary) != record["originalBinarySha256"]
            or digest(kit / "project/native-trace/build-evidence.json")
            != record["originalBuildEvidenceSha256"]):
        raise ValueError("Original Windows plugin/build binding changed")
    markers = set()
    for path, key, marker in (
            (modified, "modifiedArchiveSha256", local.MARKER),
            (modified_iconv, "modifiedIconvArchiveSha256", local.ICONV_MARKER)):
        if (digest(path) if path else None) != proof.get(key):
            raise ValueError("Provide the original modified archive matching the replay proof")
        if path:
            markers.add(marker)
    if set(proof["links"]) != ({"baseline", "modified"} if markers else {"baseline"}):
        raise ValueError("Unexpected portable Windows replay output set")
    for mode, link in proof["links"].items():
        if digest(output / mode / "cURL.4DX") != link["sha256"]:
            raise ValueError("Portable Windows replay binary changed")
    original = local.pe_layout(binary.read_bytes())
    if original != local.pe_layout((output / "baseline/cURL.4DX").read_bytes()):
        raise ValueError("Relocated Windows baseline differs beyond clock/checksum fields")
    if markers:
        changed = (output / "modified/cURL.4DX").read_bytes()
        if (set(original[1]) & markers
                or set(local.pe_layout(changed)[1]) != set(original[1]) | markers
                or changed == binary.read_bytes()):
            raise ValueError("Portable Windows modified functions are missing or unexplained")
    return proof


def relocate(arguments, project):
    arguments = local.link_arguments(arguments, PureWindowsPath("${OUTPUT}") / "baseline")
    arguments[0] = "${DRIVER}"
    result, external = [], []
    for argument in arguments:
        if argument.lower().endswith(".obj"):
            relative = PureWindowsPath(argument).relative_to(PureWindowsPath(project))
            argument = str(PureWindowsPath("${KIT}") / "project" / relative)
        elif argument.upper().startswith("/LIBPATH:"):
            path = argument.split(":", 1)[1]
            if ntpath.isabs(path):
                try:
                    relative = PureWindowsPath(path).relative_to(PureWindowsPath(project))
                except ValueError:
                    external.append(path)
                else:
                    argument = "/LIBPATH:" + str(PureWindowsPath("${KIT}") / "project" / relative)
            elif ".." in PureWindowsPath(path).parts:
                raise ValueError("Relative Windows search escapes the project")
        elif ((not argument.startswith("/") and ntpath.isabs(argument))
              or (":" in argument and ntpath.isabs(argument.split(":", 1)[1]))):
            raise ValueError("Unaccounted absolute Windows link input: " + argument)
        result.append(argument)
    return result, sorted(set(external))


def system_archives(record, project):
    directories = [project / "lib/64", *[Path(p) for p in os.environ["LIB"].split(os.pathsep) if p]]
    for item in record["systemArchives"]:
        matches = [directory / item["name"] for directory in directories
                   if (directory / item["name"]).is_file()]
        if not matches or digest(matches[0]) != item["sha256"]:
            raise ValueError("Recorded Windows SDK/CRT archive is missing or changed: " + item["name"])
    for name in record["absentSearchDirectories"]:
        if Path(name).exists():
            raise ValueError("Originally absent developer search path now exists: " + name)


def export(project, output):
    if platform.system() != "Windows" or output.exists() or output.is_relative_to(project):
        raise ValueError("Use a fresh external kit directory on the original Windows build host")
    path = project / "native-trace/build-evidence.json"
    evidence = json.loads(path.read_text())
    stage = json.loads((project.parent / "plugin-candidate-staging.json").read_text())
    binary = project / "test/Plugins/cURL.bundle/Contents/Windows64/cURL.4DX"
    if (stage["target"] != "windows-x86_64" or stage["status"] != "not-approved-for-production"
            or evidence["binarySha256"] != digest(binary)):
        raise ValueError("Expected the unchanged isolated Windows source-candidate build")
    for source in evidence["rebuiltArchiveEvidence"]:
        if source["archives"] != archive_hashes(project, [a["path"] for a in source["archives"]]):
            raise ValueError("Original source-candidate archives changed")
    arguments = local.original_command(project)
    recipe, absent = relocate(arguments, project)
    if any(Path(p).exists() for p in absent):
        raise ValueError("External developer library directory needs explicit delivery review")
    output.mkdir(parents=True)

    def copy(path):
        name = path.resolve().relative_to(project).as_posix()
        destination = output / "project" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)

    for argument in arguments:
        if argument.lower().endswith(".obj"):
            copy(Path(argument))
        elif argument.upper().startswith("/DEF:"):
            copy(project / argument.split(":", 1)[1])
        elif argument.upper().startswith("/LIBPATH:"):
            directory = Path(argument.split(":", 1)[1])
            if not directory.is_absolute():
                directory = project / directory
            if directory.is_relative_to(project):
                (output / "project" / directory.relative_to(project)).mkdir(parents=True, exist_ok=True)
                for file in directory.iterdir():
                    if file.is_file():
                        copy(file)
    bundle = project / "test/Plugins/cURL.bundle"
    for file in bundle.rglob("*"):
        if file.is_symlink():
            raise ValueError("Bundle symlinks require separate delivery review")
        if file.is_file() and not {"MacOS", "_CodeSignature"}.intersection(file.relative_to(bundle).parts):
            copy(file)
    copy(path)
    copy(project / "native-trace/msbuild.log")
    materials = copy_delivery(project, output, evidence, {"windows-x86_64"})
    tools = Path(os.environ["VCToolsInstallDir"]).resolve()
    systems = {}
    for item in evidence["linkEvidence"]["windows-x86_64"]["archives"]:
        if item.get("scope") != "external":
            continue
        name = ntpath.basename(item["resolvedPath"])
        if name in systems and systems[name] != item["sha256"]:
            raise ValueError("Ambiguous selected Windows SDK/CRT archive")
        systems[name] = item["sha256"]
    record = {
        "schemaVersion": 1, "status": "not-approved-for-production", "target": "windows-x86_64",
        "originalBinarySha256": digest(binary), "originalBuildEvidenceSha256": digest(path),
        "productSourceBaseCommit": evidence["sourceCommit"], "libraryMaterials": materials,
        "arguments": recipe, "absentSearchDirectories": absent,
        "linkDriverRelativePath": Path(arguments[0]).relative_to(tools).as_posix(),
        "linkDriverSha256": digest(Path(arguments[0])),
        "systemArchives": [{"name": name, "sha256": sha} for name, sha in sorted(systems.items())],
        "limitations": [
            "Internal candidate source/object kit, not complete licensing delivery or production adoption.",
            "The original unused absolute developer search path must remain absent; it is not silently removed.",
            "Requires matching MSVC and selected SDK/CRT archive bytes; those proprietary tools are not redistributed.",
            "No DLL/4D initialization, local trust/install check or transfer execution.",
        ],
    }
    system_archives(record, project)
    record["files"] = archive_hashes(output, [p.relative_to(output).as_posix()
                                            for p in output.rglob("*") if p.is_file()])
    write_json(output / MANIFEST, record)
    return record


def replay(kit, output, modified=None, modified_iconv=None):
    if platform.system() != "Windows" or output.exists() or output.is_relative_to(kit):
        raise ValueError("Use a fresh external replay directory on Windows")
    record = json.loads((kit / MANIFEST).read_text())
    if (record["schemaVersion"] != 1 or record["target"] != "windows-x86_64"
            or record["status"] != "not-approved-for-production"):
        raise ValueError("Unsupported Windows portable object kit")
    verify_if_derived(kit, record)
    verify_files(kit, record)
    project = kit / "project"
    system_archives(record, project)
    driver = relative_path(Path(os.environ["VCToolsInstallDir"]), record["linkDriverRelativePath"])
    if digest(driver) != record["linkDriverSha256"]:
        raise ValueError("MSVC linker differs from the original build")
    modified_hash = digest(modified) if modified else None
    iconv_hash = digest(modified_iconv) if modified_iconv else None
    output.mkdir(parents=True)
    results = {}
    for mode in ("baseline", "modified") if modified or modified_iconv else ("baseline",):
        folder = output / mode
        folder.mkdir()
        arguments = []
        for argument in record["arguments"]:
            for token, value in (("${KIT}", str(kit)), ("${OUTPUT}", str(output)),
                                 ("${DRIVER}", str(driver))):
                argument = argument.replace(token, value)
            arguments.append(argument)
        arguments = local.link_arguments(arguments, folder, modified if mode == "modified" else None,
                                         modified_iconv if mode == "modified" else None)
        with (folder / "link.log").open("w") as stream:
            subprocess.run(arguments, cwd=project, stdout=stream, stderr=subprocess.STDOUT, check=True)
        results[mode] = {"command": arguments, "sha256": digest(folder / "cURL.4DX")}
    original = (project / "test/Plugins/cURL.bundle/Contents/Windows64/cURL.4DX").read_bytes()
    baseline = (output / "baseline/cURL.4DX").read_bytes()
    if digest(project / "test/Plugins/cURL.bundle/Contents/Windows64/cURL.4DX") != record["originalBinarySha256"]:
        raise ValueError("Original Windows plugin binding changed")
    if local.pe_layout(original) != local.pe_layout(baseline):
        raise ValueError("Relocated Windows baseline differs beyond clock/checksum fields")
    if modified or modified_iconv:
        changed = (output / "modified/cURL.4DX").read_bytes()
        markers = ({local.MARKER} if modified else set()) | (
            {local.ICONV_MARKER} if modified_iconv else set())
        if (set(local.pe_layout(original)[1]) & markers
                or set(local.pe_layout(changed)[1]) != set(local.pe_layout(original)[1]) | markers
                or changed == original
                or (modified and digest(modified) != modified_hash)
                or (modified_iconv and digest(modified_iconv) != iconv_hash)):
            raise ValueError("Relocated modified proxy/iconv code or archive binding changed")
    verify_files(kit, record)
    system_archives(record, project)
    proof = {"status": record["status"], "target": record["target"],
             "kitManifestSha256": digest(kit / MANIFEST), "links": results,
             "modifiedArchiveSha256": modified_hash,
             "modifiedIconvArchiveSha256": iconv_hash,
             "scope": "Relocated actual Windows object links; not host or complete licensing verification"}
    write_json(output / "portable-windows-replay-proof.json", proof)
    return inspect_replay(kit, output, modified, modified_iconv)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("export", "replay", "inspect"):
        command = sub.add_parser(name)
        command.add_argument("--project" if name == "export" else "--kit", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if name != "export":
            command.add_argument("--modified-proxy", type=Path)
            command.add_argument("--modified-iconv", type=Path)
    args = parser.parse_args()
    result = (export(args.project.resolve(), args.output.resolve()) if args.command == "export"
              else (replay if args.command == "replay" else inspect_replay)(
                          args.kit.resolve(), args.output.resolve(),
                          args.modified_proxy.resolve() if args.modified_proxy else None,
                          args.modified_iconv.resolve() if args.modified_iconv else None))
    print(json.dumps({k: result[k] for k in ("status", "target")}, indent=2))
