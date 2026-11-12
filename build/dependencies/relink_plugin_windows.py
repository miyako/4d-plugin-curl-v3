#!/usr/bin/env python3
"""Replay an isolated plugin's actual Windows object link; never load the DLL."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sbom"))
import generate
from native_archive_objects import cstring, region, unpack
from provenance import archive_hashes, digest, write_json
from relink_candidate import inspect_relink


MARKER = "proxy_user_relink_probe"


def pe_layout(data):
    generate.check_pe(data)
    pe, = unpack("<I", data, 0x3C)
    count, = unpack("<H", data, pe + 6)
    size, = unpack("<H", data, pe + 20)
    if size < 120:
        raise ValueError("Missing PE export directory")
    optional = pe + 24
    region(data, optional, size + count * 40)
    sections = []
    for index in range(count):
        offset = optional + size + 40 * index
        _, address, raw_size, raw = unpack("<4I", data, offset + 8)
        flags, = unpack("<I", data, offset + 36)
        region(data, raw, raw_size)
        sections.append((address, raw_size, raw, flags))

    def location(address, size=1, executable=False):
        found = [raw + address - start for start, length, raw, flags in sections
                 if start <= address and address + size <= start + length
                 and (not executable or flags & 0x20000000)]
        if len(found) != 1:
            raise ValueError("Ambiguous, unbacked or non-executable PE address")
        return found[0]

    export, length = unpack("<II", data, optional + 112)
    directory = location(export, 40)
    functions, names, function_rva, name_rva, ordinal_rva = unpack("<5I", data, directory + 20)
    strings = location(name_rva, names * 4)
    ordinals = location(ordinal_rva, names * 2)
    addresses = location(function_rva, functions * 4)
    exports = {}
    for index in range(names):
        name, = unpack("<I", data, strings + 4 * index)
        ordinal, = unpack("<H", data, ordinals + 2 * index)
        if ordinal >= functions:
            raise ValueError("Invalid PE export ordinal")
        address, = unpack("<I", data, addresses + ordinal * 4)
        key = cstring(data, location(name))
        if key in exports:
            raise ValueError("Duplicate PE export name")
        exports[key] = address
    if MARKER in exports:
        if export <= exports[MARKER] < export + length:
            raise ValueError("Modified-plugin marker is a forwarder, not its own function")
        location(exports[MARKER], executable=True)
    normalized = bytearray(data)
    fields = {"coffTimeDateStamp": pe + 8, "optionalHeaderCheckSum": optional + 64,
              "exportTimeDateStamp": directory + 4}
    for offset in fields.values():
        normalized[offset:offset + 4] = b"\0" * 4
    return bytes(normalized), exports, fields


def link_arguments(original, output, modified=None):
    arguments = list(original)
    if len([a for a in arguments if a.lower() == "libproxy.lib"]) != 1:
        raise ValueError("Expected one original proxy library")
    for option, name in (("OUT", "cURL.4DX"), ("PDB", "cURL.pdb"), ("MAP", "link.map"),
                         ("IMPLIB", "cURL.lib"), ("LTCGOUT", "cURL.iobj")):
        indexes = [i for i, a in enumerate(arguments) if a.upper().startswith("/" + option + ":")]
        if len(indexes) != 1:
            raise ValueError("Missing or repeated original linker output: " + option)
        arguments[indexes[0]] = "/" + option + ":" + str(output / name)
    if any(a.upper().startswith(("/PGD:", "/MANIFESTFILE:", "/ILK:", "/DEBUG"))
           for a in arguments):
        raise ValueError("Unsupported additional Windows linker/debug output")
    if modified:
        index = next(i for i, a in enumerate(arguments) if a.lower() == "libproxy.lib")
        arguments[index] = str(modified)
        arguments.append("/EXPORT:" + MARKER)
    return arguments


def original_command(project):
    lines = (project / "native-trace/msbuild.log").read_text(encoding="utf-8-sig").splitlines()
    matches = [(index, re.fullmatch(r"\s*(.+\\link\.exe)\s+(.+)", line, re.I))
               for index, line in enumerate(lines)]
    matches = [(index, match) for index, match in matches if match]
    if len(matches) != 1:
        raise ValueError("Expected one original full-plugin link command")
    index, match = matches[0]
    text = match[2]
    for line in lines[index + 1:]:
        if not line.strip():
            break
        text += " " + line.strip()
    driver = Path(match[1].strip()).resolve()
    tools = Path(os.environ["VCToolsInstallDir"]).resolve()
    if not driver.is_relative_to(tools) or not driver.is_file():
        raise ValueError("Original linker is not in the active MSVC toolchain")
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    count = ctypes.c_int()
    pointer = shell.CommandLineToArgvW("link.exe " + text, ctypes.byref(count))
    if not pointer:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        arguments = [str(driver), *[pointer[i] for i in range(1, count.value)]]
    finally:
        kernel.LocalFree(ctypes.cast(pointer, ctypes.c_void_p))
    if "/DLL" not in arguments or "/MACHINE:X64" not in arguments:
        raise ValueError("Expected original x64 plugin DLL arguments")
    return arguments


def relink(project, output, candidate, modified):
    if platform.system() != "Windows" or output.exists() or output.is_relative_to(project):
        raise ValueError("Use a fresh external output and the original Windows build host")
    stage = json.loads((project.parent / "plugin-candidate-staging.json").read_text())
    original_path = project / "native-trace/build-evidence.json"
    original = json.loads(original_path.read_text())
    binary = project / "test/Plugins/cURL.bundle/Contents/Windows64/cURL.4DX"
    if (stage["status"] != "not-approved-for-production" or stage["target"] != "windows-x86_64"
            or original["binarySha256"] != digest(binary)):
        raise ValueError("Expected the unchanged isolated source-candidate plugin")
    inspection = inspect_relink(candidate, modified)
    proxy = next(p for p in original["rebuiltArchiveEvidence"] if p["name"] == "libproxy")
    if (inspection["target"] != "windows-x86_64"
            or not any(p["sha256"] == digest(candidate / "proxy-build-provenance.json")
                       for p in proxy["originalBuildRecords"])):
        raise ValueError("Modified proxy does not derive from the plugin's original source kit")
    for source in original["rebuiltArchiveEvidence"]:
        if source["archives"] != archive_hashes(project, [p["path"] for p in source["archives"]]):
            raise ValueError("Original source-candidate archive changed")
    arguments = original_command(project)
    objects = [Path(p).resolve().relative_to(project).as_posix()
               for p in arguments if p.lower().endswith(".obj")]
    if not objects:
        raise ValueError("No original plugin objects")
    before = archive_hashes(project, objects)
    output.mkdir(parents=True)
    commands = {}
    for name in ("baseline", "modified"):
        folder = output / name
        folder.mkdir()
        command = link_arguments(arguments, folder,
                                 modified / "build/libproxy.lib" if name == "modified" else None)
        commands[name] = command
        with (folder / "link.log").open("w") as stream:
            subprocess.run(command, cwd=project, stdout=stream, stderr=subprocess.STDOUT, check=True)
    baseline = (output / "baseline/cURL.4DX").read_bytes()
    changed = (output / "modified/cURL.4DX").read_bytes()
    normalized, exports, fields = pe_layout(binary.read_bytes())
    replay, replay_exports, replay_fields = pe_layout(baseline)
    if normalized != replay or exports != replay_exports or fields != replay_fields:
        raise ValueError("Windows baseline differs beyond the documented timestamp/checksum fields")
    _, changed_exports, _ = pe_layout(changed)
    if MARKER in exports or set(changed_exports) != set(exports) | {MARKER}:
        raise ValueError("Modified plugin must add exactly its own probe export")
    if changed == binary.read_bytes() or before != archive_hashes(project, objects):
        raise ValueError("Modified plugin did not change or original objects changed")
    for item in before:
        destination = output / "objects" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(project / item["path"], destination)
    shutil.copyfile(binary, output / "original.4DX")
    shutil.copyfile(original_path, output / "original-build-evidence.json")
    record = {
        "target": "windows-x86_64", "status": "not-approved-for-production",
        "originalBuildEvidenceSha256": digest(original_path),
        "originalBinarySha256": digest(binary), "baselineBinarySha256": generate.sha256(baseline),
        "relinkedBinarySha256": generate.sha256(changed),
        "candidateRecordSha256": digest(candidate / "proxy-build-provenance.json"),
        "userRelinkProofSha256": digest(modified / "user-relink-proof.json"),
        "modifiedArchiveSha256": digest(modified / "build/libproxy.lib"),
        "originalObjectFiles": before, "commands": commands,
        "linkDriverSha256": digest(Path(arguments[0])),
        "baselineComparison": {"ignoredFields": fields,
                               "normalizedSha256": generate.sha256(normalized)},
        "markerExport": MARKER,
        "limitations": [
            "Local original-object replay, not portable LGPL source/relink delivery.",
            "Only COFF/export timestamps and PE checksum are excluded from baseline byte comparison.",
            "No DLL/4D initialization, host trust/install check or transfer execution.",
        ],
    }
    write_json(output / "full-plugin-user-relink-proof.json", record)
    inspect(output, candidate, modified)
    return record


def inspect(output, candidate, modified):
    record = json.loads((output / "full-plugin-user-relink-proof.json").read_text())
    original = json.loads((output / "original-build-evidence.json").read_text())
    inspect_relink(candidate, modified)
    proxy = next(p for p in original["rebuiltArchiveEvidence"] if p["name"] == "libproxy")
    if (record["target"] != "windows-x86_64" or record["status"] != "not-approved-for-production"
            or record["originalBuildEvidenceSha256"] != digest(output / "original-build-evidence.json")
            or record["originalBinarySha256"] != digest(output / "original.4DX")
            or original["binarySha256"] != record["originalBinarySha256"]
            or record["baselineBinarySha256"] != digest(output / "baseline/cURL.4DX")
            or record["relinkedBinarySha256"] != digest(output / "modified/cURL.4DX")
            or record["candidateRecordSha256"] != digest(candidate / "proxy-build-provenance.json")
            or not any(p["sha256"] == record["candidateRecordSha256"]
                       for p in proxy["originalBuildRecords"])
            or record["userRelinkProofSha256"] != digest(modified / "user-relink-proof.json")
            or record["modifiedArchiveSha256"] != digest(modified / "build/libproxy.lib")
            or record["originalObjectFiles"] != archive_hashes(
                output / "objects", [p["path"] for p in record["originalObjectFiles"]])):
        raise ValueError("Persisted Windows object/library/plugin binding changed")
    normal, exports, fields = pe_layout((output / "original.4DX").read_bytes())
    replay, replay_exports, replay_fields = pe_layout((output / "baseline/cURL.4DX").read_bytes())
    _, changed_exports, _ = pe_layout((output / "modified/cURL.4DX").read_bytes())
    if (normal != replay or exports != replay_exports or fields != replay_fields
            or record["baselineComparison"] != {
                "ignoredFields": fields, "normalizedSha256": generate.sha256(normal)}
            or record["markerExport"] != MARKER or MARKER in exports
            or set(changed_exports) != set(exports) | {MARKER}):
        raise ValueError("Persisted Windows baseline/export proof changed")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project", "output", "proxy-candidate", "proxy-relink"):
        parser.add_argument("--" + name, type=Path, required=name != "project")
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    if args.inspect_only:
        result = inspect(args.output.resolve(), args.proxy_candidate.resolve(), args.proxy_relink.resolve())
    else:
        if not args.project:
            parser.error("--project is required for a native object replay")
        result = relink(args.project.resolve(), args.output.resolve(),
                        args.proxy_candidate.resolve(), args.proxy_relink.resolve())
    print(json.dumps({"target": result["target"],
                      "relinkedBinarySha256": result["relinkedBinarySha256"]}, indent=2))
