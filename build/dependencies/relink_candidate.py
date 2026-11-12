#!/usr/bin/env python3
"""Rebuild delivered candidate sources with a benign user modification, not a plugin."""

import argparse
import json
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sbom"))
from inspect_proxy import inspect, verify_architecture
from provenance import archive_hashes, digest, write_json


MODIFICATION = '\nextern "C" int proxy_user_relink_probe() { return 417; }\n'


def unpack(path, files, destination):
    with tarfile.open(path) as archive:
        for item in files:
            relative = PurePosixPath(item["path"])
            if (relative.is_absolute() or ".." in relative.parts
                    or "\\" in item["path"] or ":" in item["path"]):
                raise ValueError("Unsafe delivered source/recipe path")
            member = archive.getmember(item["path"])
            if not member.isfile():
                raise ValueError("Delivered build input is not a regular file")
            target = destination / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
    if archive_hashes(destination, [a["path"] for a in files]) != sorted(files, key=lambda a: a["path"]):
        raise ValueError("Extracted user-relink materials differ from the candidate record")


def command(arguments, log):
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        sys.stderr.write(log.read_text())
        raise subprocess.CalledProcessError(result.returncode, arguments)


def verify_tests(path):
    results = ET.parse(path).getroot()
    tests = results.findall("testcase")
    expected = {"proxy_behavior", "proxy_file_url", "proxy_url_test",
                "proxy_url_encode", "proxy_user_relink"}
    if (results.get("failures") != "0" or len(tests) != 5
            or {t.get("name") for t in tests} != expected
            or any(t.get("status") != "run" or any(
                t.find(tag) is not None for tag in ("failure", "error", "skipped")) for t in tests)):
        raise ValueError("User-relink proof did not execute all required comparisons")


def relink(candidate, output):
    inspection = inspect(candidate)
    record = json.loads((candidate / "proxy-build-provenance.json").read_text())
    target = inspection["target"]
    if (target.startswith("windows")) != (platform.system() == "Windows"):
        raise ValueError("Candidate relinking requires its native operating system/toolchain")
    if output.exists():
        raise ValueError("Use a fresh user-relink proof directory")
    output.mkdir(parents=True)
    source = output / "source"
    kit = output / "kit"
    unpack(candidate / "upstream-source.tar", record["sourceFiles"], source)
    recipe = [{"path": "build/dependencies/" + a["path"], "sha256": a["sha256"]}
              for a in record["recipeFiles"]] + record["recipeSupportFiles"]
    unpack(candidate / "candidate-recipe.tar", recipe, kit)
    path = source / "libproxy/url.cpp"
    before = digest(path)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(MODIFICATION)
    after = digest(path)
    windows = target.startswith("windows")
    config = json.loads((kit / "build/dependencies/proxy-source.json").read_text())
    key = "windows" if windows else "macos"
    build = output / "build"
    arguments = [
        "cmake", "-S", str(kit / "build/dependencies/proxy"), "-B", str(build),
        "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
        "-DPROXY_SOURCE=" + source.as_posix(),
        "-DPROXY_MODULES=" + ";".join(config["modules"][key]),
        "-DPROXY_MODULE_DIRECTORY=" + config["moduleDirectory"][key],
        "-DPROXY_RELINK_PROBE=ON",
    ]
    if not windows:
        arguments += ["-DCMAKE_OSX_ARCHITECTURES=" + target.removeprefix("macos-"),
                      "-DCMAKE_OSX_DEPLOYMENT_TARGET=10.13"]
    command(arguments, output / "configure.log")
    command(["cmake", "--build", str(build), "--verbose"], output / "build.log")
    command(["ctest", "--test-dir", str(build), "--verbose", "--output-on-failure",
             "--output-junit", str(output / "test-results.xml")], output / "tests.log")
    verify_tests(output / "test-results.xml")
    name = "libproxy.lib" if windows else "libproxy.a"
    archive = build / name
    verify_architecture(archive, target)
    original = next(a for a in record["archives"] if a["path"].endswith(name))
    if digest(archive) == original["sha256"]:
        raise ValueError("User-modified library did not produce different archive bytes")
    executable = build / ("proxy_user_relink.exe" if windows else "proxy_user_relink")
    proof = {
        "schemaVersion": 1, "target": target,
        "candidateRecordSha256": digest(candidate / "proxy-build-provenance.json"),
        "deliveredSourceSha256": digest(candidate / "upstream-source.tar"),
        "deliveredRecipeSha256": digest(candidate / "candidate-recipe.tar"),
        "modification": {"path": "libproxy/url.cpp", "beforeSha256": before,
                         "afterSha256": after, "appendedSource": MODIFICATION},
        "modifiedArchiveSha256": digest(archive),
        "relinkedTestBinarySha256": digest(executable),
        "configureArguments": arguments,
        "buildFiles": archive_hashes(output, ["configure.log", "build.log", "tests.log",
                                             "test-results.xml", "build/CMakeCache.txt",
                                             "build/compile_commands.json"]),
        "scope": "Source-only libproxy/libmodman relink proof, not a complete plugin relink kit or 4D host-install verification",
    }
    write_json(output / "user-relink-proof.json", proof)
    inspect_relink(candidate, output)
    return proof


def inspect_relink(candidate, output):
    original = json.loads((candidate / "proxy-build-provenance.json").read_text())
    proof = json.loads((output / "user-relink-proof.json").read_text())
    inspection = inspect(candidate)
    if (proof["target"] != inspection["target"]
            or proof["candidateRecordSha256"] != digest(candidate / "proxy-build-provenance.json")
            or proof["deliveredSourceSha256"] != digest(candidate / "upstream-source.tar")
            or proof["deliveredRecipeSha256"] != digest(candidate / "candidate-recipe.tar")):
        raise ValueError("User-relink proof does not bind the delivered candidate")
    expected = [dict(a) for a in original["sourceFiles"]]
    changed = next(a for a in expected if a["path"] == "libproxy/url.cpp")
    with tarfile.open(candidate / "upstream-source.tar") as archive:
        data = archive.extractfile("libproxy/url.cpp").read()
    modified = output / "source/libproxy/url.cpp"
    if (modified.read_bytes() != data + MODIFICATION.encode()
            or proof["modification"]["beforeSha256"] != changed["sha256"]
            or proof["modification"]["afterSha256"] != digest(modified)):
        raise ValueError("User-relink source modification was not the reviewed benign probe")
    changed["sha256"] = digest(modified)
    actual_paths = {p.relative_to(output / "source").as_posix()
                    for p in (output / "source").rglob("*") if not p.is_dir()}
    if (actual_paths != {a["path"] for a in expected}
            or archive_hashes(output / "source", [a["path"] for a in expected]) != expected):
        raise ValueError("User-relink source inputs changed")
    recipe = [{"path": "build/dependencies/" + a["path"], "sha256": a["sha256"]}
              for a in original["recipeFiles"]] + original["recipeSupportFiles"]
    if archive_hashes(output / "kit", [a["path"] for a in recipe]) != sorted(recipe, key=lambda a: a["path"]):
        raise ValueError("Delivered user-relink recipe changed")
    if proof["buildFiles"] != archive_hashes(output, [a["path"] for a in proof["buildFiles"]]):
        raise ValueError("User-relink original build evidence changed")
    windows = proof["target"].startswith("windows")
    archive = output / "build" / ("libproxy.lib" if windows else "libproxy.a")
    executable = output / "build" / ("proxy_user_relink.exe" if windows else "proxy_user_relink")
    if (digest(archive) != proof["modifiedArchiveSha256"]
            or digest(executable) != proof["relinkedTestBinarySha256"]):
        raise ValueError("User-relinked archive/test executable changed")
    old = next(a for a in original["archives"] if a["path"].endswith(archive.name))
    if old["sha256"] == digest(archive):
        raise ValueError("User-relink proof reused the unmodified archive")
    verify_tests(output / "test-results.xml")
    verify_architecture(archive, proof["target"])
    return {"target": proof["target"], "relinkedTestBinarySha256": proof["relinkedTestBinarySha256"],
            "scope": proof["scope"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inspect-only", action="store_true",
                        help="Verify downloaded proof bytes without compiling or executing")
    args = parser.parse_args()
    function = inspect_relink if args.inspect_only else relink
    print(json.dumps(function(args.candidate.resolve(), args.output.resolve()), indent=2))
