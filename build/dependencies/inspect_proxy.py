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


def verify_tar(path, files, extra=None, directories=False):
    expected = {item["path"]: item["sha256"] for item in files}
    if len(expected) != len(files):
        raise ValueError("Duplicate source/recipe file evidence")
    expected.update(extra or {})
    with tarfile.open(path) as archive:
        entries = archive.getmembers()
        if directories:
            entries = [e for e in entries if not e.isdir()]
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


def verify_source_delta(base, compiled, patches):
    expected = {a["path"]: a["sha256"] for a in base}
    actual = {a["path"]: a["sha256"] for a in compiled}
    if len(expected) != len(base) or len(actual) != len(compiled):
        raise ValueError("Duplicate source input")
    for patch in patches:
        for change in patch["files"]:
            if expected.get(change["path"]) != change["beforeSha256"]:
                raise ValueError("Patch base source hash mismatch")
            expected[change["path"]] = change["afterSha256"]
    if expected != actual:
        raise ValueError("Compiled source differs from the exact reviewed patch delta")


def verify_tests(path, allow_failed=False):
    suite = ET.parse(path).getroot()
    tests = suite.findall("testcase")
    expected = {"proxy_behavior", "proxy_file_url", "proxy_url_test", "proxy_url_encode", "proxy_baseline_behavior"}
    if (suite.tag != "testsuite" or suite.get("tests") != "5"
            or len(tests) != 5 or {t.get("name") for t in tests} != expected
            or any(t.get("status") != ("fail" if t.find("failure") is not None else "run") or any(
                t.find(tag) is not None for tag in ("error", "skipped")) for t in tests)):
        raise ValueError("Missing successful native candidate/baseline comparisons")
    failed = sorted(t.get("name") for t in tests if t.find("failure") is not None)
    if suite.get("failures") != str(len(failed)) or (failed and not allow_failed):
        raise ValueError("Native candidate/baseline compatibility tests failed: " + ", ".join(failed))
    return failed


def inspect(output, allow_failed_tests=False):
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
            or record["acceptedCandidateChanges"] != lock["acceptedCandidateChanges"]
            or record["status"] != lock["status"]
            or record["modules"] != lock["modules"]["windows" if target.startswith("windows") else "macos"]):
        raise ValueError("Persisted candidate identity/target mismatch")
    if record["archives"] != archive_hashes(output / "install", expected_archives):
        raise ValueError("Persisted candidate archive mismatch")
    required = {"configure.log", "build.log", "tests.log", "test-results.xml", "install.log",
                "build/CMakeCache.txt", "build/compile_commands.json", "build/build.ninja",
                "upstream-base.tar", "upstream-source.tar", "candidate-recipe.tar",
                "install/include/proxy.h", "install/share/licenses/libproxy/COPYING"}
    paths = [item["path"] for item in record["buildFiles"]]
    if not required.issubset(paths):
        raise ValueError("Missing original build evidence")
    if record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("Persisted original build evidence mismatch")
    verify_tar(output / "upstream-base.tar", record["baseSourceFiles"], directories=True)
    verify_tar(output / "upstream-source.tar", record["sourceFiles"])
    recipe_files = [{"path": "build/dependencies/" + a["path"], "sha256": a["sha256"]}
                    for a in record["recipeFiles"]] + record["recipeSupportFiles"]
    verify_tar(output / "candidate-recipe.tar", recipe_files)
    support = {a["path"]: a["sha256"] for a in record["recipeSupportFiles"]}
    if (support.get("LICENSE") != record["recipeLicenseSha256"]
            or not {"build/sbom/provenance.py", "build/sbom/native_archive_objects.py"}.issubset(support)):
        raise ValueError("Missing source-kit helper/license materials")
    recipe = {a["path"]: a["sha256"] for a in record["recipeFiles"]}
    if any(recipe.get(patch["path"]) != patch["sha256"] for patch in record["patches"]):
        raise ValueError("Patch bytes differ from the source record")
    verify_source_delta(record["baseSourceFiles"], record["sourceFiles"], record["patches"])
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
    failed = verify_tests(output / "test-results.xml", allow_failed_tests)
    if ((record["testExitCode"] == 0) != (not failed)
            or record["validationStatus"] != ("failed" if failed else "passed")):
        raise ValueError("Native test status disagrees with original build record")
    return {"target": target, "sourceCommit": record["source_commit"],
            "validationStatus": record["validationStatus"], "failedTests": failed,
            "acceptedCandidateChanges": [c["id"] for c in record["acceptedCandidateChanges"]],
            "archives": [
                {**a, "objectMembers": verify_architecture(output / "install" / a["path"], target)}
                for a in record["archives"]],
            "scope": "isolated candidate; no production adoption or full compatibility assertion"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--allow-failed-tests", action="store_true",
                        help="Read rejected candidate evidence; never waive adoption gates")
    args = parser.parse_args()
    print(json.dumps(inspect(args.output, args.allow_failed_tests), indent=2))
