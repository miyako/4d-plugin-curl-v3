#!/usr/bin/env python3
"""Replay a local candidate's real object links with the reviewed modified proxy."""

import argparse
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sbom"))
import generate
from native_archive_objects import cstring, region, unpack
from provenance import archive_hashes, digest, write_json
from relink_candidate import inspect_relink


MARKER = "_proxy_user_relink_probe"


def defines_marker(data, marker=MARKER):
    count, size = unpack("<II", data, 16)
    region(data, 32, size)
    offset, tables = 32, []
    for _ in range(count):
        command, length = unpack("<II", data, offset)
        if length < 8 or offset + length > 32 + size:
            raise ValueError("Invalid modified-plugin load command")
        if command == 2:
            if length != 24:
                raise ValueError("Invalid modified-plugin symbol-table command")
            tables.append(unpack("<4I", data, offset + 8))
        offset += length
    if offset != 32 + size or len(tables) != 1:
        raise ValueError("Expected one modified-plugin symbol table")
    raw, count, strings, length = tables[0]
    region(data, raw, count * 16)
    names = region(data, strings, length)
    found = 0
    for index in range(count):
        string, kind, section, _, _ = unpack("<IBBHQ", data, raw + 16 * index)
        if not kind & 0xE0 and kind & 0x0E == 0x0E and section > 0:
            found += cstring(names, string) == marker
    return found == 1


def link_arguments(original, output, modified=None):
    arguments = list(original)
    if arguments.count("-o") != 1 or arguments.count("-lproxy") != 1:
        raise ValueError("Expected one original plugin output and proxy selection")
    for option, name in (("-map", "link.map"), ("-dependency_info", "dependencies.dat")):
        if arguments.count(option) != 1:
            raise ValueError("Missing or repeated original linker diagnostic output")
        index = arguments.index(option)
        if arguments[index - 1:index + 2] != ["-Xlinker", option, "-Xlinker"]:
            raise ValueError("Unsupported original linker diagnostic arguments")
        arguments[index + 2] = str(output / name)
    arguments[arguments.index("-o") + 1] = str(output / "cURL")
    if modified:
        arguments[arguments.index("-lproxy")] = str(modified)
        arguments.extend(["-Wl,-u,_proxy_user_relink_probe"])
    return arguments


def original_commands(project, driver):
    commands = {}
    for line in (project / "native-trace/xcodebuild.log").read_text().splitlines():
        if not line.strip().startswith(str(driver) + " "):
            continue
        arguments = shlex.split(line)
        if "-bundle" not in arguments or "-filelist" not in arguments:
            continue
        target = "macos-" + arguments[arguments.index("-target") + 1].split("-")[0]
        if target in commands or target not in ("macos-arm64", "macos-x86_64"):
            raise ValueError("Original full-plugin link commands are ambiguous")
        commands[target] = arguments
    if set(commands) != {"macos-arm64", "macos-x86_64"}:
        raise ValueError("Both original full-plugin object-link commands are required")
    return commands


def object_inputs(project, arguments):
    filelist = Path(arguments[arguments.index("-filelist") + 1])
    objects = []
    for line in filelist.read_text().splitlines():
        paths = shlex.split(line)
        if len(paths) != 1:
            raise ValueError("Unsupported original plugin object file list")
        objects.append(Path(paths[0]).resolve().relative_to(project).as_posix())
    return filelist, archive_hashes(project, objects)


def relink(project, output, candidates, modified_kits):
    if platform.system() != "Darwin":
        raise ValueError("Local full-plugin replay requires the original macOS toolchain")
    if output.exists() or output.is_relative_to(project):
        raise ValueError("Full-plugin relinking requires a fresh directory outside its project")
    stage_path = project.parent / "plugin-candidate-staging.json"
    staging = json.loads(stage_path.read_text())
    if (staging["target"] != "macos-universal"
            or staging["status"] != "not-approved-for-production"
            or project != (stage_path.parent / staging["projectDirectory"]).resolve()):
        raise ValueError("Expected the separate isolated source-candidate project")
    original_path = project / "native-trace/build-evidence.json"
    original = json.loads(original_path.read_text())
    binary = project / "test/Plugins/cURL.bundle/Contents/MacOS/cURL"
    if digest(binary) != original["binarySha256"]:
        raise ValueError("Original source-candidate plugin changed")
    for source in original["rebuiltArchiveEvidence"]:
        if source["archives"] != archive_hashes(project, [a["path"] for a in source["archives"]]):
            raise ValueError("Original source-candidate archives changed")
    expected = {"macos-arm64", "macos-x86_64"}
    if len(candidates) != 2 or len(modified_kits) != 2:
        raise ValueError("Both original architecture-specific proxy/relink pairs are required")
    sources = {}
    proxy = next(p for p in original["rebuiltArchiveEvidence"] if p["name"] == "libproxy")
    for candidate, modified in zip(candidates, modified_kits):
        result = inspect_relink(candidate, modified)
        target = result["target"]
        record_hash = digest(candidate / "proxy-build-provenance.json")
        if target in sources or not any(r["target"] == target and r["sha256"] == record_hash
                                        for r in proxy["originalBuildRecords"]):
            raise ValueError("Modified proxy does not derive from the plugin's original source kit")
        sources[target] = (candidate, modified)
    if set(sources) != expected:
        raise ValueError("Modified proxy architecture coverage is incomplete")
    driver = Path(subprocess.check_output(["xcrun", "--find", "clang++"], text=True).strip())
    commands = original_commands(project, driver)
    output.mkdir(parents=True)
    proof = []
    slices = generate.mac_slices(binary.read_bytes())
    for target in sorted(expected):
        arguments = commands[target]
        filelist, before = object_inputs(project, arguments)
        candidate, modified = sources[target]
        archive = modified / "build/libproxy.a"
        baseline = output / target / "baseline"
        changed = output / target / "modified"
        baseline.mkdir(parents=True)
        changed.mkdir()
        baseline_command = link_arguments(arguments, baseline)
        changed_command = link_arguments(arguments, changed, archive)
        for command, folder in ((baseline_command, baseline), (changed_command, changed)):
            with (folder / "link.log").open("w") as stream:
                subprocess.run(command, cwd=project, stdout=stream, stderr=subprocess.STDOUT,
                               check=True)
        if (baseline / "cURL").read_bytes() != slices[target]:
            raise ValueError("Original objects/libraries did not reproduce the original plugin slice")
        if (changed / "cURL").read_bytes() == slices[target]:
            raise ValueError("Modified-library full-plugin relink did not change the plugin")
        if not defines_marker((changed / "cURL").read_bytes()):
            raise ValueError("Modified proxy marker was not retained in the full plugin")
        if before != object_inputs(project, arguments)[1]:
            raise ValueError("Original plugin objects changed during relinking")
        proof.append({
            "target": target, "originalObjectFiles": before,
            "originalFileListSha256": digest(filelist),
            "candidateRecordSha256": digest(candidate / "proxy-build-provenance.json"),
            "userRelinkProofSha256": digest(modified / "user-relink-proof.json"),
            "modifiedArchiveSha256": digest(archive),
            "baselineCommand": baseline_command, "modifiedCommand": changed_command,
            "originalSliceSha256": generate.sha256(slices[target]),
            "relinkedSliceSha256": digest(changed / "cURL"),
            "marker": MARKER,
        })
    lipo = Path(subprocess.check_output(["xcrun", "--find", "lipo"], text=True).strip())
    subprocess.run([str(lipo), "-create",
                    *[str(output / t / "modified/cURL") for t in sorted(expected)],
                    "-output", str(output / "cURL")], check=True)
    final = generate.mac_slices((output / "cURL").read_bytes())
    for target in sorted(expected):
        if final[target] != (output / target / "modified/cURL").read_bytes():
            raise ValueError("Universal modified-plugin slice differs from its link output")
    record = {
        "status": "not-approved-for-production", "target": "macos-universal",
        "originalBuildEvidenceSha256": digest(original_path),
        "originalBuildLogSha256": digest(project / "native-trace/xcodebuild.log"),
        "originalBinarySha256": digest(binary), "relinkedBinarySha256": digest(output / "cURL"),
        "linkDriver": {"path": str(driver), "sha256": digest(driver)},
        "mergeTool": {"path": str(lipo), "sha256": digest(lipo)},
        "architectures": proof,
        "limitations": [
            "Local replay of the actual plugin's original objects, not a byte-reproducible source-build guarantee.",
            "No 4D/plugin initialization, host trust/install check or protocol execution.",
            "Absolute original object/SDK/archive paths are not portable self-contained LGPL delivery.",
            "Windows full-plugin relinking and complete source/license/build-material delivery remain open.",
        ],
    }
    write_json(output / "full-plugin-user-relink-proof.json", record)
    inspect(output, project, sources)
    return record


def inspect(output, project, sources):
    record = json.loads((output / "full-plugin-user-relink-proof.json").read_text())
    original_path = project / "native-trace/build-evidence.json"
    original = json.loads(original_path.read_text())
    binary = project / "test/Plugins/cURL.bundle/Contents/MacOS/cURL"
    if (record["status"] != "not-approved-for-production"
            or record["target"] != "macos-universal"
            or record["originalBuildEvidenceSha256"] != digest(original_path)
            or record["originalBuildLogSha256"] != digest(project / "native-trace/xcodebuild.log")
            or record["originalBinarySha256"] != digest(binary)
            or original["binarySha256"] != digest(binary)
            or record["relinkedBinarySha256"] != digest(output / "cURL")):
        raise ValueError("Full-plugin relink original/final binary binding changed")
    originals = generate.mac_slices(binary.read_bytes())
    final = generate.mac_slices((output / "cURL").read_bytes())
    commands = original_commands(project, Path(record["linkDriver"]["path"]))
    for source in original["rebuiltArchiveEvidence"]:
        if source["archives"] != archive_hashes(project, [a["path"] for a in source["archives"]]):
            raise ValueError("Original source-candidate archives changed")
    proxy = next(p for p in original["rebuiltArchiveEvidence"] if p["name"] == "libproxy")
    if ({p["target"] for p in record["architectures"]} != set(originals)
            or len(record["architectures"]) != 2 or set(sources) != set(originals)):
        raise ValueError("Full-plugin relink architecture coverage changed")
    for proof in record["architectures"]:
        target = proof["target"]
        candidate, modified = sources[target]
        inspect_relink(candidate, modified)
        filelist, objects = object_inputs(project, commands[target])
        baseline = output / target / "baseline/cURL"
        changed = output / target / "modified/cURL"
        if (objects != proof["originalObjectFiles"]
                or not any(r["target"] == target and r["sha256"] == digest(
                    candidate / "proxy-build-provenance.json") for r in proxy["originalBuildRecords"])
                or proof["originalFileListSha256"] != digest(filelist)
                or proof["baselineCommand"] != link_arguments(
                    commands[target], output / target / "baseline")
                or proof["modifiedCommand"] != link_arguments(
                    commands[target], output / target / "modified", modified / "build/libproxy.a")
                or proof["candidateRecordSha256"] != digest(candidate / "proxy-build-provenance.json")
                or proof["userRelinkProofSha256"] != digest(modified / "user-relink-proof.json")
                or proof["modifiedArchiveSha256"] != digest(modified / "build/libproxy.a")
                or proof["originalSliceSha256"] != generate.sha256(originals[target])
                or baseline.read_bytes() != originals[target]
                or proof["relinkedSliceSha256"] != digest(changed)
                or final[target] != changed.read_bytes() or final[target] == originals[target]
                or proof["marker"] != MARKER or not defines_marker(final[target])):
            raise ValueError("Persisted full-plugin object/library/slice proof changed")
    return {"target": record["target"], "relinkedBinarySha256": record["relinkedBinarySha256"],
            "scope": "Full Mac plugin object relink; not portable delivery or actual 4D host proof"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--proxy-candidate", type=Path, action="append", required=True)
    parser.add_argument("--proxy-relink", type=Path, action="append", required=True)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    candidates = [p.resolve() for p in args.proxy_candidate]
    modified = [p.resolve() for p in args.proxy_relink]
    if args.inspect_only:
        if len(candidates) != 2 or len(modified) != 2:
            parser.error("Both original architecture-specific proxy/relink pairs are required")
        sources = {inspect_relink(c, m)["target"]: (c, m) for c, m in zip(candidates, modified)}
        result = inspect(args.output.resolve(), args.project.resolve(), sources)
    else:
        result = relink(args.project.resolve(), args.output.resolve(), candidates, modified)
    print(json.dumps({"target": result["target"], "relinkedBinarySha256":
                      result["relinkedBinarySha256"]}, indent=2))
