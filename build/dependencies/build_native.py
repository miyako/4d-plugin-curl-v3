#!/usr/bin/env python3
"""Build isolated version-matched native prerequisites; never replace vendor inputs."""

import argparse
from collections import Counter
import hashlib
import json
import ntpath
from pathlib import Path
import platform
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "sbom"))
from provenance import archive_hashes, digest, git, write_json
from inspect_proxy import verify_architecture, verify_tar
from linker import parse_apple, parse_msvc
from native_archive_objects import members

TARGETS = ("macos-arm64", "macos-x86_64", "windows-x86_64")
TESTS = {"zlib_candidate_write", "zlib_baseline_write", "zlib_candidate_read",
         "zlib_baseline_read", "zlib_configuration"}
RECIPES = ["build/dependencies/build_native.py", "build/dependencies/native-sources.json",
           "build/dependencies/baseline-v4.9.10.json",
           "build/dependencies/native/CMakeLists.txt", "build/dependencies/native/zlib-probe.c",
           "build/dependencies/inspect_proxy.py", "build/sbom/provenance.py",
           "build/sbom/native_archive_objects.py", "build/sbom/linker.py",
           "build/dependencies/README.md", "LICENSE"]


def settings(library, target):
    lock = json.loads((HERE / "native-sources.json").read_text())
    return lock["libraries"][library], lock["libraries"][library]["targets"][target]


def tree_files(root):
    paths = list(root.rglob("*"))
    if any(p.is_symlink() for p in paths):
        raise ValueError("Unexpected symbolic link in staged source")
    return archive_hashes(root, [p.relative_to(root).as_posix() for p in paths if not p.is_dir()])


def checkout_files(source, commit):
    if git(source, "rev-parse", "HEAD") != commit:
        raise ValueError("Source checkout does not match the immutable pin")
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Source checkout must be clean, including untracked files")
    return archive_hashes(source, git(source, "ls-files").splitlines())


def verify_layout(before, after, renames):
    expected = {a["path"]: a["sha256"] for a in before}
    for old, new in renames.items():
        if new in expected or old not in expected:
            raise ValueError("Invalid configured source rename")
        expected[new] = expected.pop(old)
    if len(expected) != len(after) or expected != {a["path"]: a["sha256"] for a in after}:
        raise ValueError("Source changed beyond the reviewed configure-time renames")


def stage(source, output, commit, checkout):
    path = output / "upstream-source.tar"
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
                    "-C", str(source), "archive", "--format=tar",
                    "--output=" + str(path), commit], check=True)
    staged = output / "source"
    with tarfile.open(path) as archive:
        entries = archive.getmembers()
        if (any(not e.isfile() and not e.isdir() for e in entries)
                or {e.name for e in entries if e.isfile()} != {a["path"] for a in checkout}):
            raise ValueError("Unexpected pinned source archive contents")
        for item in checkout:
            target = staged / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(item["path"]).read())
            target.chmod(0o755 if archive.getmember(item["path"]).mode & 0o111 else 0o644)
    return staged, tree_files(staged)


def run(arguments, path, check=True):
    with path.open("w", encoding="utf-8") as stream:
        result = subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode and check:
        sys.stderr.write(path.read_text(encoding="utf-8"))
        raise subprocess.CalledProcessError(result.returncode, arguments)
    return result.returncode


def compare_zlib(candidate, baseline):
    new = json.loads(candidate.read_text())
    old = json.loads(baseline.read_text())
    if new != old or not isinstance(new.get("compileFlags"), int):
        raise ValueError("zlib version/compile flags differ from the exact selected baseline: "
                         + json.dumps({"candidate": new, "baseline": old}))
    return new


def check_commands(output, source, target, compiled_sources):
    commands = json.loads((output / "build/compile_commands.json").read_text())
    actual = [c for c in commands
              if "CMakeFiles/zlibstatic.dir/" in c["output"].replace("\\", "/")]
    prefix = str(source).replace("\\", "/").rstrip("/") + "/"
    if (any(not c["file"].replace("\\", "/").startswith(prefix) for c in actual)
            or {c["file"].replace("\\", "/")[len(prefix):] for c in actual}
            != set(compiled_sources) or len(actual) != len(compiled_sources)):
        raise ValueError("Static archive compile inputs differ from the source recipe")
    for entry in actual:
        command = entry["command"]
        if target.startswith("windows"):
            if not re.search(r"(?:^|[ /-])MT(?:\s|$)", command) or re.search(
                    r"(?:^|[ /-])M[DT]d(?:\s|$)|(?:^|[ /-])MD(?:\s|$)", command):
                raise ValueError("Native prerequisite must use the release static MSVC CRT")
        elif ("-arch " + target.removeprefix("macos-") not in command
              or "-mmacosx-version-min=10.13" not in command):
            raise ValueError("Native prerequisite changed architecture/deployment settings")


def link_selections(output, target, original_build, baseline, archive):
    result = {}
    windows = target.startswith("windows")
    normal = (lambda path: ntpath.normcase(ntpath.normpath(path))) if windows else posixpath.normpath
    for kind in ("candidate", "baseline"):
        expected = (str(original_build).replace("\\", "/") + "/upstream/" + archive
                    if kind == "candidate" else baseline)
        text = (output / "build" / (kind + ".map")).read_text()
        selected, _ = (parse_msvc((output / (kind + "-build.log")).read_text(), text)
                       if windows else parse_apple(text, target.removeprefix("macos-")))
        matched = []
        for item in selected:
            path = item["archive"].replace("\\", "/")
            if not (ntpath.isabs(path) if windows else posixpath.isabs(path)):
                path = str(original_build).replace("\\", "/") + "/" + path
            if normal(path) == normal(expected):
                matched.append(item)
        if not matched:
            raise ValueError("Linker did not select the exact " + kind + " zlib archive")
        result[kind] = matched
    return result


def verify_tests(path, allow_failed=False):
    suite = ET.parse(path).getroot()
    tests = suite.findall("testcase")
    if (suite.tag != "testsuite" or suite.get("tests") != str(len(TESTS))
            or len(tests) != len(TESTS) or {t.get("name") for t in tests} != TESTS
            or any(t.get("status") != ("fail" if t.find("failure") is not None else "run")
                   or t.find("skipped") is not None or t.find("error") is not None for t in tests)):
        raise ValueError("Missing or skipped prerequisite compatibility tests")
    failed = sorted(t.get("name") for t in tests if t.find("failure") is not None)
    if suite.get("failures") != str(len(failed)) or (failed and not allow_failed):
        raise ValueError("Native prerequisite compatibility tests failed: " + ", ".join(failed))
    return failed


def toolchain(output, target):
    compiler_files = list((output / "build/CMakeFiles").glob("*/CMakeCCompiler.cmake"))
    if len(compiler_files) != 1:
        raise ValueError("Expected one actual C compiler identity")
    compiler = re.search(r'set\(CMAKE_C_COMPILER "([^"]+)"\)', compiler_files[0].read_text())
    cache = (output / "build/CMakeCache.txt").read_text()
    tools = {}
    for name in ("CMAKE_MAKE_PROGRAM", "CMAKE_AR", "CMAKE_LINKER") + (
            () if target.startswith("windows") else ("CMAKE_RANLIB",)):
        value = re.search(r"^" + name + r":FILEPATH=(.+)$", cache, re.MULTILINE)
        if not value:
            raise ValueError("Missing native build tool: " + name)
        tools[name] = Path(value[1])
    cmake = shutil.which("cmake")
    if not compiler or not cmake:
        raise ValueError("Missing actual compiler/CMake executable")
    tools.update({"CMAKE_C_COMPILER": Path(compiler[1]), "cmake": Path(cmake)})
    return ({name: {"path": str(path), "sha256": digest(path)} for name, path in tools.items()},
            compiler_files[0].relative_to(output).as_posix())


def object_evidence(output, archive, commands, original_build):
    prefix = str(original_build).replace("\\", "/").rstrip("/") + "/"
    paths = []
    for command in commands:
        path = command["output"].replace("\\", "/")
        if path.startswith(prefix):
            path = path[len(prefix):]
        paths.append("build/" + path)
    compiled = archive_hashes(output, paths)
    objects = [{"member": name, "sha256": hashlib.sha256(data).hexdigest()}
               for name, _, data in members((output / archive).read_bytes())]
    if Counter(a["sha256"] for a in compiled) != Counter(a["sha256"] for a in objects):
        raise ValueError("Archive members do not equal the actual compiled object outputs")
    return {"compiledObjects": compiled, "archiveObjects": objects}


def inspect(output, allow_failed=False):
    record = json.loads((output / "native-build-provenance.json").read_text())
    library, pin = settings(record["library"], record["target"])
    expected = {"schema_version": 1, "evidence_type": "isolated-source-build-candidate",
                "status": "not-approved-for-production", "version": pin["version"],
                "source_commit": pin["commit"], "source_repository": library["repository"],
                "license": library["license"], "licenseFile": library["licenseFile"],
                "licenseFileSha256": pin["licenseSha256"], "sourceRenames": pin["sourceRenames"]}
    if any(record.get(k) != v for k, v in expected.items()):
        raise ValueError("Native prerequisite identity/configuration mismatch")
    if record["archives"] != archive_hashes(output / "install", [pin["archive"]]):
        raise ValueError("Native prerequisite archive does not match its original record")
    required = {"upstream-source.tar", "source-recipe.tar", "configure.log",
                "candidate-build.log", "baseline-build.log",
                "install.log", "tests.log", "test-results.xml", "build/CMakeCache.txt",
                "build/compile_commands.json", "build/build.ninja", "build/upstream/zconf.h",
                "build/candidate-streams/version-info.json", "build/baseline-streams/version-info.json",
                "install/include/zlib.h", "install/include/zconf.h",
                "install/share/licenses/zlib/LICENSE"}
    built_archive = "build/upstream/" + Path(pin["archive"]).name
    required.add(built_archive)
    executable_suffix = ".exe" if record["target"].startswith("windows") else ""
    required.update("build/zlib_" + kind + "_probe" + executable_suffix for kind in ("candidate", "baseline"))
    required.update("build/" + kind + ".map" for kind in ("candidate", "baseline"))
    paths = [a["path"] for a in record["buildFiles"]]
    if not required.issubset(paths) or record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("Original native build records are missing or changed")
    verify_tar(output / "upstream-source.tar", record["sourceFiles"], directories=True)
    if {a["path"] for a in record["recipeFiles"]} != set(RECIPES):
        raise ValueError("Native source-kit recipe/helper inputs are incomplete")
    verify_tar(output / "source-recipe.tar", record["recipeFiles"])
    verify_layout(record["sourceFiles"], record["configuredSourceFiles"], pin["sourceRenames"])
    if record["configuredSourceFiles"] != tree_files(output / "source"):
        raise ValueError("Configured source differs from the original build inputs")
    if digest(output / built_archive) != digest(output / "install" / pin["archive"]):
        raise ValueError("Installed archive differs from the actual compiler/archive output")
    if (digest(output / "install/share/licenses/zlib/LICENSE") != pin["licenseSha256"]
            or digest(output / "install/include/zconf.h") != digest(output / "build/upstream/zconf.h")
            or digest(output / "install/include/zlib.h") != next(
                a["sha256"] for a in record["sourceFiles"] if a["path"] == "zlib.h")):
        raise ValueError("Installed license/generated header mismatch")
    frozen = json.loads((HERE / "baseline-v4.9.10.json").read_text())
    target = next(t for t in frozen["targets"] if t["id"] == record["target"])
    old = next(a for a in target["selectedArchives"] if a["name"] == record["library"])
    if record["baselineArchive"] != {"path": old["path"], "sha256": old["sha256"]}:
        raise ValueError("Prerequisite comparison was not bound to the exact baseline archive")
    arguments = record["configure_arguments"]
    original_source = next(a.split("=", 1)[1] for a in arguments if a.startswith("-DNATIVE_SOURCE="))
    original_build = arguments[arguments.index("-B") + 1]
    original_baseline = next(a.split("=", 1)[1] for a in arguments if a.startswith("-DBASELINE_ARCHIVE="))
    check_commands(output, original_source, record["target"], library["compiledSources"])
    commands = [c for c in json.loads((output / "build/compile_commands.json").read_text())
                if "CMakeFiles/zlibstatic.dir/" in c["output"].replace("\\", "/")]
    proof = object_evidence(output, built_archive, commands, original_build)
    if any(record.get(k) != v for k, v in proof.items()):
        raise ValueError("Stored source-to-object-to-archive proof changed")
    if record["linkSelections"] != link_selections(
            output, record["target"], original_build, original_baseline, Path(pin["archive"]).name):
        raise ValueError("Stored archive selection disagrees with original linker diagnostics")
    failed = verify_tests(output / "test-results.xml", allow_failed)
    if ((record["testExitCode"] == 0) != (not failed)
            or record["validationStatus"] != ("failed" if failed else "passed")):
        raise ValueError("Native validation status disagrees with original test results")
    if not failed:
        compare_zlib(output / "build/candidate-streams/version-info.json",
                     output / "build/baseline-streams/version-info.json")
    objects = verify_architecture(output / "install" / pin["archive"], record["target"])
    return {"library": record["library"], "target": record["target"], "version": pin["version"],
            "sourceCommit": pin["commit"], "validationStatus": record["validationStatus"],
            "failedTests": failed, "archive": record["archives"][0], "objectMembers": objects,
            "scope": "isolated source prerequisite; original production archives unchanged"}


def build(source, output, library_name, target):
    library, pin = settings(library_name, target)
    source, output = source.resolve(), output.resolve()
    before = checkout_files(source, pin["commit"])
    recipe = archive_hashes(ROOT, RECIPES)
    if output.exists():
        raise ValueError("Use a fresh output directory; do not relabel an old build")
    if target.startswith("windows") != (platform.system() == "Windows"):
        raise ValueError("Native prerequisite requires its target operating system")
    frozen = json.loads((HERE / "baseline-v4.9.10.json").read_text())
    baseline = next(a for t in frozen["targets"] if t["id"] == target
                    for a in t["selectedArchives"] if a["name"] == library_name)
    old = ROOT / baseline["path"]
    if digest(old) != baseline["sha256"]:
        raise ValueError("Selected baseline archive has changed")
    output.mkdir(parents=True)
    staged, files = stage(source, output, pin["commit"], before)
    if digest(staged / library["licenseFile"]) != pin["licenseSha256"]:
        raise ValueError("Pinned prerequisite license text mismatch")
    arguments = ["cmake", "-S", str(HERE / "native"), "-B", str(output / "build"),
                 "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                 "-DNATIVE_LIBRARY=" + library_name, "-DNATIVE_SOURCE=" + staged.as_posix(),
                 "-DEXPECTED_VERSION=" + pin["version"], "-DBASELINE_ARCHIVE=" + old.as_posix(),
                 "-DNATIVE_DRIVER=" + (HERE / "build_native.py").as_posix(),
                 "-DCMAKE_INSTALL_PREFIX=" + (output / "install").as_posix()]
    if not target.startswith("windows"):
        arguments += ["-DCMAKE_OSX_ARCHITECTURES=" + target.removeprefix("macos-"),
                      "-DCMAKE_OSX_DEPLOYMENT_TARGET=10.13"]
    run(arguments, output / "configure.log")
    tools, compiler_file = toolchain(output, target)
    configured = tree_files(staged)
    verify_layout(files, configured, pin["sourceRenames"])
    for kind in ("candidate", "baseline"):
        run(["cmake", "-E", "env", "VERBOSE=1", "cmake",
             "--build", str(output / "build"), "--target",
             "zlib_" + kind + "_probe", "--verbose"], output / (kind + "-build.log"))
    for kind in ("candidate", "baseline"):
        (output / "build" / (kind + "-streams")).mkdir()
    test_exit = run(["ctest", "--test-dir", str(output / "build"), "--verbose",
                    "--output-on-failure", "--output-junit", str(output / "test-results.xml")],
                   output / "tests.log", check=False)
    run(["cmake", "--install", str(output / "build")], output / "install.log")
    check_commands(output, staged, target, library["compiledSources"])
    if (checkout_files(source, pin["commit"]) != before or tree_files(staged) != configured
            or archive_hashes(ROOT, RECIPES) != recipe or digest(old) != baseline["sha256"]):
        raise ValueError("Native source, recipes or baseline changed during compilation")
    with tarfile.open(output / "source-recipe.tar", "w") as archive:
        for item in recipe:
            archive.add(ROOT / item["path"], arcname=item["path"])
    evidence = ["upstream-source.tar", "source-recipe.tar", "configure.log",
                "candidate-build.log", "baseline-build.log",
                "install.log", "tests.log", "test-results.xml", "build/CMakeCache.txt",
                "build/compile_commands.json", "build/build.ninja", "build/upstream/zconf.h",
                "install/include/zlib.h", "install/include/zconf.h", "install/share/licenses/zlib/LICENSE"]
    evidence.append("build/upstream/" + Path(pin["archive"]).name)
    executable_suffix = ".exe" if target.startswith("windows") else ""
    evidence += ["build/zlib_" + kind + "_probe" + executable_suffix for kind in ("candidate", "baseline")]
    evidence += ["build/" + kind + ".map" for kind in ("candidate", "baseline")]
    evidence += [p.relative_to(output).as_posix() for kind in ("candidate", "baseline")
                 for p in sorted((output / "build" / (kind + "-streams")).iterdir())]
    if toolchain(output, target) != (tools, compiler_file):
        raise ValueError("Native build toolchain changed during compilation")
    evidence.append(compiler_file)
    commands = [c for c in json.loads((output / "build/compile_commands.json").read_text())
                if "CMakeFiles/zlibstatic.dir/" in c["output"].replace("\\", "/")]
    proof = object_evidence(output, "build/upstream/" + Path(pin["archive"]).name,
                            commands, output / "build")
    evidence += [a["path"] for a in proof["compiledObjects"]]
    record = {"schema_version": 1, "evidence_type": "isolated-source-build-candidate",
              "status": "not-approved-for-production", "library": library_name,
              "version": pin["version"], "source_repository": library["repository"],
              "source_commit": pin["commit"], "target": target,
              "license": library["license"], "licenseFile": library["licenseFile"],
              "licenseFileSha256": pin["licenseSha256"], "patches": [],
              "sourceRenames": pin["sourceRenames"], "checkoutFiles": before,
              "sourceFiles": files, "configuredSourceFiles": configured, "recipeFiles": recipe,
              "configure_arguments": arguments, "buildFiles": archive_hashes(output, evidence),
              "toolchain": tools,
              **proof,
              "archives": archive_hashes(output / "install", [pin["archive"]]),
              "baselineArchive": {"path": baseline["path"], "sha256": baseline["sha256"]},
              "linkSelections": link_selections(output, target, output / "build",
                                               old.as_posix(), Path(pin["archive"]).name),
              "testExitCode": test_exit, "validationStatus": "failed" if test_exit else "passed"}
    write_json(output / "native-build-provenance.json", record)
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("build")
    sub.add_argument("--source", type=Path, required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub.add_argument("--library", choices=("zlib",), required=True)
    sub.add_argument("--target", choices=TARGETS, required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("output", type=Path)
    sub.add_argument("--allow-failed-tests", action="store_true")
    sub = commands.add_parser("compare-zlib")
    sub.add_argument("candidate", type=Path)
    sub.add_argument("baseline", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        result = build(args.source, args.output, args.library, args.target)
    elif args.command == "inspect":
        result = inspect(args.output, args.allow_failed_tests)
    else:
        result = compare_zlib(args.candidate, args.baseline)
    print(json.dumps(result, indent=2))
