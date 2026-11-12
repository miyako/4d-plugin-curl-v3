#!/usr/bin/env python3
"""Independently inspect persisted candidate artifacts without running binaries."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tarfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sbom"))
from native_archive_objects import members
from provenance import archive_hashes, digest


def verify_tar(path, files, extra=None):
    expected = {item["path"]: item["sha256"] for item in files}
    if len(expected) != len(files):
        raise ValueError("Duplicate source/recipe file evidence")
    expected.update(extra or {})
    with tarfile.open(path) as archive:
        entries = archive.getmembers()
        if (len(entries) != len(expected) or {e.name for e in entries} != set(expected)
                or any(not e.isfile() for e in entries)):
            raise ValueError("Source/recipe tar has duplicate, missing, extra or non-file members")
        for entry in entries:
            with archive.extractfile(entry) as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != expected[entry.name]:
                    raise ValueError("Source/recipe tar member hash mismatch: " + entry.name)


def verify_architecture(path, target):
    count = 0
    for name, _, data in members(path.read_bytes()):
        if target == "windows-x86_64":
            valid = data[:2] == b"\x64\x86"
        else:
            cpu = 0x0100000C if target == "macos-arm64" else 0x01000007
            valid = (len(data) >= 16 and data[:4] == b"\xcf\xfa\xed\xfe"
                     and struct.unpack_from("<I", data, 4)[0] == cpu
                     and struct.unpack_from("<I", data, 12)[0] == 1)
        if not valid:
            raise ValueError("Wrong or unsupported archive member target: " + name)
        count += 1
    if not count:
        raise ValueError("Empty proxy archive")
    return count


def verify_tests(path):
    suite = ET.parse(path).getroot()
    tests = suite.findall("testcase")
    expected = {"proxy_behavior", "proxy_url_test", "proxy_url_encode", "proxy_baseline_behavior"}
    if (suite.tag != "testsuite" or suite.get("tests") != "4"
            or suite.get("failures") != "0"
            or len(tests) != 4 or {t.get("name") for t in tests} != expected
            or any(t.get("status") != "run" or any(
                t.find(tag) is not None for tag in ("failure", "error", "skipped")) for t in tests)):
        raise ValueError("Missing successful native candidate/baseline comparisons")


def inspect(output):
    record = json.loads((output / "proxy-build-provenance.json").read_text())
    lock = json.loads((HERE / "proxy-source.json").read_text())
    target = record["target"]
    expected_archives = (["lib/libproxy.lib", "lib/modman.lib"] if target == "windows-x86_64"
                         else ["lib/libmodman.a", "lib/libproxy.a"])
    if (target not in ("macos-arm64", "macos-x86_64", "windows-x86_64")
            or record["schema_version"] != 1
            or record["evidence_type"] != "isolated-source-build-candidate"
            or record["source_commit"] != lock["commit"]
            or record["source_repository"] != lock["repository"]
            or record["components"] != lock["components"]
            or record["patches"] != lock["patches"]
            or record["status"] != lock["status"]
            or record["modules"] != lock["modules"]["windows" if target.startswith("windows") else "macos"]):
        raise ValueError("Persisted candidate identity/target mismatch")
    if record["archives"] != archive_hashes(output / "install", expected_archives):
        raise ValueError("Persisted candidate archive mismatch")
    required = {"configure.log", "build.log", "tests.log", "test-results.xml", "install.log",
                "build/CMakeCache.txt", "build/compile_commands.json", "build/build.ninja",
                "upstream-source.tar", "candidate-recipe.tar",
                "install/include/proxy.h", "install/share/licenses/libproxy/COPYING"}
    paths = [item["path"] for item in record["buildFiles"]]
    if not required.issubset(paths):
        raise ValueError("Missing original build evidence")
    if record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("Persisted original build evidence mismatch")
    verify_tar(output / "upstream-source.tar", record["sourceFiles"])
    verify_tar(output / "candidate-recipe.tar", record["recipeFiles"],
               {"recipe-LICENSE": record["recipeLicenseSha256"]})
    source_files = {a["path"]: a["sha256"] for a in record["sourceFiles"]}
    if (record["licenseFile"] != lock["licenseFile"]
            or source_files.get(record["licenseFile"]) != record["licenseFileSha256"]
            or digest(output / "install/share/licenses/libproxy/COPYING") != record["licenseFileSha256"]
            or digest(output / "install/include/proxy.h") != source_files.get("libproxy/proxy.h")):
        raise ValueError("Source/installed license or public header mismatch")
    frozen = json.loads((HERE / "baseline-v4.9.10.json").read_text())
    baseline = next(t for t in frozen["targets"] if t["id"] == target)
    expected_old = {a["name"]: a["sha256"] for a in baseline["selectedArchives"]
                    if a["name"] in ("libproxy", "libmodman")}
    if (len(record["baselineArchives"]) != 2 or
            {a["name"]: a["sha256"] for a in record["baselineArchives"]} != expected_old):
        raise ValueError("Historical comparison archive mismatch")
    verify_tests(output / "test-results.xml")
    return {"target": target, "sourceCommit": record["source_commit"],
            "archives": [
                {**a, "objectMembers": verify_architecture(output / "install" / a["path"], target)}
                for a in record["archives"]],
            "scope": "isolated candidate; no production adoption or full compatibility assertion"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.output), indent=2))
