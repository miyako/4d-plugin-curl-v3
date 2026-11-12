#!/usr/bin/env python3
"""Isolated pinned HTTP prerequisite builds; never install into production paths."""

import argparse
import json
from pathlib import Path
import platform
import re
import shutil
import xml.etree.ElementTree as ET

from build_native import ROOT, RECIPES, run, stage, tree_files, toolchain, object_evidence
from inspect_proxy import verify_architecture, verify_tar
from provenance import archive_hashes, digest, git, write_json

PINS = {
    "nghttp2": {
        "commit": "85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2", "version": "1.70.0",
        "repository": "https://github.com/nghttp2/nghttp2",
        "licenseSha256": "6b94f3abc1aabd0c72a7c7d92a77f79dda7c8a0cb3df839a97890b4116a2de2a",
        "modules": {"tests/munit": ("114805e1bab0222574b5eb3a92461ad5216647ed", "tests-only")},
    },
    "nghttp3": {
        "commit": "d326f4c1eb3f6a780d77793b30e16756c498f913", "version": "1.15.0",
        "repository": "https://github.com/ngtcp2/nghttp3",
        "licenseSha256": "58cc3fc8c6d6cb2485ab35eb5918e849b5bf1e56522974e106d7a39a88d61dcd",
        "modules": {
            "lib/sfparse": ("ff7f230e7df2844afef7dc49631cda03a30455f3", "compiled-parser"),
            "tests/munit": ("11e8e3466b2d6a8bdfd4b05a3d1ee7805c5d3442", "tests-only"),
        },
        "uncompiledNestedGitlinks": {
            "lib/sfparse": {"munit": "11e8e3466b2d6a8bdfd4b05a3d1ee7805c5d3442"},
        },
    },
}
HTTP_RECIPES = RECIPES + ["build/dependencies/build_http.py"]


def snapshot(source, commit):
    if git(source, "rev-parse", "HEAD") != commit or git(
            source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("HTTP source must be clean at its immutable pin")
    links = {}
    for line in git(source, "ls-tree", "-r", "HEAD").splitlines():
        metadata, path = line.split("\t", 1)
        if metadata.startswith("160000 "):
            links[path] = metadata.split()[2]
    paths = [p for p in git(source, "ls-files").splitlines() if p not in links]
    return archive_hashes(source, paths), links


def verify_tests(path):
    suite = ET.parse(path).getroot()
    tests = suite.findall("testcase")
    if (suite.tag != "testsuite" or suite.get("tests") != "1" or suite.get("failures") != "0"
            or len(tests) != 1 or tests[0].get("name") != "main"
            or tests[0].get("status") != "run" or len(tests[0].findall("skipped"))
            or tests[0].find("failure") is not None or tests[0].find("error") is not None):
        raise ValueError("HTTP upstream main test suite did not pass completely")


def inspect(output):
    record = json.loads((output / "native-build-provenance.json").read_text())
    pin = PINS[record["library"]]
    if any(record.get(k) != v for k, v in {
            "schema_version": 1, "evidence_type": "isolated-source-build-candidate",
            "status": "not-approved-for-production", "source_commit": pin["commit"],
            "version": pin["version"], "source_repository": pin["repository"],
            "license": "MIT", "licenseFile": "COPYING",
            "licenseFileSha256": pin["licenseSha256"],
            "validationScope": "upstream source self-tests; baseline interoperability not yet established",
    }.items()):
        raise ValueError("HTTP prerequisite source identity or validation scope changed")
    if record["sourceFiles"] != tree_files(output / "source"):
        raise ValueError("HTTP configured source changed after compilation")
    expected_components = {"": (pin["commit"], "library-source")}
    expected_components.update(pin["modules"])
    if (len(record["components"]) != len(expected_components)
            or {c["path"]: (c["commit"], c["role"]) for c in record["components"]}
            != expected_components):
        raise ValueError("HTTP source closure differs from the reviewed immutable pins")
    combined = []
    for component in record["components"]:
        verify_tar(output / component["archive"], component["files"], directories=True)
        combined.extend({"path": (component["path"] + "/" + a["path"]).lstrip("/"),
                         "sha256": a["sha256"]} for a in component["files"])
    if sorted(combined, key=lambda a: a["path"]) != record["sourceFiles"]:
        raise ValueError("HTTP configured source does not match delivered source closure")
    if record["recipeFiles"] != archive_hashes(
            output / "recipe", [a["path"] for a in record["recipeFiles"]]):
        raise ValueError("HTTP recipe differs from its original inputs")
    paths = [a["path"] for a in record["buildFiles"]]
    required = {"configure.log", "build.log", "tests.log", "test-results.xml",
                "build/CMakeCache.txt", "build/compile_commands.json", "build/build.ninja",
                "build/config.h", record["builtArchive"],
                "build/tests/main" + (".exe" if record["target"].startswith("windows") else "")}
    if not required.issubset(paths) or record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("Original HTTP build records changed")
    if record["archives"] != archive_hashes(output / "install", [a["path"] for a in record["archives"]]):
        raise ValueError("Installed HTTP archive changed")
    archive = record["archives"][0]["path"]
    if (digest(output / "install" / archive) != digest(output / record["builtArchive"])
            or digest(output / "install/share/licenses" / record["library"] / "COPYING")
            != pin["licenseSha256"]):
        raise ValueError("HTTP installed archive/license differs from original build inputs")
    verify_tests(output / "test-results.xml")
    if not re.search(r"(\d+) of \1 \(100%\) tests successful, 0 \(0%\) test skipped\.",
                     (output / "tests.log").read_text()):
        raise ValueError("Upstream HTTP test cases were missing, failed or skipped")
    compiled = [c for c in json.loads((output / "build/compile_commands.json").read_text())
                if "CMakeFiles/" + record["library"] + "_static.dir/"
                in c["output"].replace("\\", "/")]
    if not compiled or compiled != record["compiledSources"]:
        raise ValueError("HTTP compile inputs disagree with the original build database")
    original_build = record["configure_arguments"][record["configure_arguments"].index("-B") + 1]
    proof = object_evidence(output, record["builtArchive"], compiled, original_build)
    if any(record.get(k) != v for k, v in proof.items()):
        raise ValueError("HTTP source-to-object-to-archive proof changed")
    members = verify_architecture(output / "install" / archive, record["target"])
    return {"library": record["library"], "target": record["target"], "version": pin["version"],
            "sourceCommit": pin["commit"], "archive": record["archives"][0],
            "objectMembers": members, "validationScope": record["validationScope"],
            "status": record["status"]}


def build(source, output, library, target):
    if target.startswith("windows") != (platform.system() == "Windows"):
        raise ValueError("HTTP prerequisite must build on its target operating system")
    if library == "nghttp3" and target.startswith("windows"):
        raise ValueError("nghttp3 is not a selected Windows baseline input")
    pin = PINS[library]
    source, output = source.resolve(), output.resolve()
    if output.exists():
        raise ValueError("Use a fresh HTTP evidence directory")
    files, links = snapshot(source, pin["commit"])
    output.mkdir(parents=True)
    components = []
    roots = [("", source, pin["commit"], files)]
    for path, (commit, role) in pin["modules"].items():
        if links.get(path) != commit:
            raise ValueError("HTTP nested source differs from its parent gitlink")
        module_files, nested = snapshot(source / path, commit)
        if nested != pin.get("uncompiledNestedGitlinks", {}).get(path, {}):
            raise ValueError("Unreviewed nested HTTP source requirements")
        roots.append((path, source / path, commit, module_files))
    for index, (prefix, root, commit, checkout) in enumerate(roots):
        part = output / "acquisitions" / str(index)
        part.mkdir(parents=True)
        staged, canonical = stage(root, part, commit, checkout)
        destination = output / "source" / prefix
        shutil.copytree(staged, destination, dirs_exist_ok=True)
        components.append({"path": prefix, "commit": commit,
                           "role": "library-source" if not prefix else pin["modules"][prefix][1],
                           "archive": (part / "upstream-source.tar").relative_to(output).as_posix(),
                           "files": canonical, "checkoutFiles": checkout})
    staged = output / "source"
    before = tree_files(staged)
    if digest(staged / "COPYING") != pin["licenseSha256"]:
        raise ValueError("HTTP pinned license text changed")
    recipes = archive_hashes(ROOT, HTTP_RECIPES)
    for item in recipes:
        path = output / "recipe" / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], path)
    arguments = ["cmake", "-S", str(staged), "-B", str(output / "build"), "-G", "Ninja",
                 "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                 "-DCMAKE_POSITION_INDEPENDENT_CODE=ON", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
                 "-DENABLE_LIB_ONLY=ON", "-DBUILD_TESTING=ON", "-DENABLE_STATIC_CRT=ON"]
    arguments += (["-DBUILD_STATIC_LIBS=ON", "-DBUILD_SHARED_LIBS=OFF", "-DENABLE_DOC=OFF",
                   "-DENABLE_FAILMALLOC=OFF"] if library == "nghttp2" else
                  ["-DENABLE_STATIC_LIB=ON", "-DENABLE_SHARED_LIB=OFF"])
    if target.startswith("macos"):
        arguments += ["-DCMAKE_OSX_ARCHITECTURES=" + target.removeprefix("macos-"),
                      "-DCMAKE_OSX_DEPLOYMENT_TARGET=10.13"]
    run(arguments, output / "configure.log")
    tools, compiler_file = toolchain(output, target)
    run(["cmake", "--build", str(output / "build"), "--target", "main", "--verbose"],
        output / "build.log")
    run(["ctest", "--test-dir", str(output / "build"), "--verbose", "--no-tests=error",
         "--output-junit", str(output / "test-results.xml")], output / "tests.log")
    if before != tree_files(staged):
        raise ValueError("HTTP source changed during compilation")
    commands = json.loads((output / "build/compile_commands.json").read_text())
    compiled = [c for c in commands if "CMakeFiles/" + library + "_static.dir/"
                in c["output"].replace("\\", "/")]
    if not compiled:
        raise ValueError("Missing actual static HTTP compilation inputs")
    hashes = {a["path"]: a["sha256"] for a in before}
    for command in compiled:
        relative = Path(command["file"]).relative_to(staged).as_posix()
        if relative not in hashes or digest(staged / relative) != hashes[relative]:
            raise ValueError("HTTP compiler input lacks source evidence")
        if target.startswith("macos") and (
                "-arch " + target.removeprefix("macos-") not in command["command"]
                or "-mmacosx-version-min=10.13" not in command["command"]):
            raise ValueError("HTTP architecture/deployment settings changed")
        if target.startswith("windows") and (
                not re.search(r"(?:^|[ /-])MT(?:\s|$)", command["command"])
                or re.search(r"(?:^|[ /-])M[DT]d(?:\s|$)|(?:^|[ /-])MD(?:\s|$)",
                             command["command"])):
            raise ValueError("HTTP prerequisite must use the release static MSVC CRT")
    name = library + ".lib" if target.startswith("windows") else "lib" + library + ".a"
    built = output / "build/lib" / name
    installed = output / "install/lib" / name
    installed.parent.mkdir(parents=True)
    shutil.copyfile(built, installed)
    license_path = output / "install/share/licenses" / library / "COPYING"
    license_path.parent.mkdir(parents=True)
    shutil.copyfile(staged / "COPYING", license_path)
    shutil.copytree(staged / "lib/includes" / library, output / "install/include" / library)
    shutil.copytree(output / "build/lib/includes" / library,
                    output / "install/include" / library, dirs_exist_ok=True)
    for _, root, commit, checkout in roots:
        if snapshot(root, commit)[0] != checkout:
            raise ValueError("Original HTTP checkout changed during the build")
    if recipes != archive_hashes(ROOT, HTTP_RECIPES):
        raise ValueError("HTTP build recipe changed during compilation")
    evidence = ["configure.log", "build.log", "tests.log", "test-results.xml",
                "build/CMakeCache.txt", "build/compile_commands.json", "build/build.ninja",
                "build/config.h", "build/tests/main" + (".exe" if target.startswith("windows") else ""),
                built.relative_to(output).as_posix(), license_path.relative_to(output).as_posix()]
    evidence += [p.relative_to(output).as_posix() for p in (output / "install/include").rglob("*")
                 if p.is_file()]
    if toolchain(output, target) != (tools, compiler_file):
        raise ValueError("HTTP build toolchain changed during compilation")
    evidence.append(compiler_file)
    proof = object_evidence(output, built.relative_to(output).as_posix(), compiled, output / "build")
    evidence += [a["path"] for a in proof["compiledObjects"]]
    record = {
        "schema_version": 1, "evidence_type": "isolated-source-build-candidate",
        "status": "not-approved-for-production", "library": library, "target": target,
        "source_commit": pin["commit"], "source_repository": pin["repository"],
        "version": pin["version"], "license": "MIT", "licenseFile": "COPYING",
        "licenseFileSha256": pin["licenseSha256"], "components": components,
        "uncompiledGitlinks": {p: c for p, c in links.items() if p not in pin["modules"]},
        "sourceFiles": before, "recipeFiles": recipes, "configure_arguments": arguments,
        "compiledSources": compiled, "buildFiles": archive_hashes(output, evidence),
        "toolchain": tools,
        **proof,
        "archives": archive_hashes(output / "install", ["lib/" + name]),
        "builtArchive": built.relative_to(output).as_posix(),
        "validationScope": "upstream source self-tests; baseline interoperability not yet established",
    }
    write_json(output / "native-build-provenance.json", record)
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("build")
    sub.add_argument("--source", type=Path, required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub.add_argument("--library", choices=PINS, required=True)
    sub.add_argument("--target", choices=("macos-arm64", "macos-x86_64", "windows-x86_64"), required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("output", type=Path)
    args = parser.parse_args()
    result = (inspect(args.output) if args.command == "inspect" else
              build(args.source, args.output, args.library, args.target))
    print(json.dumps(result, indent=2))
