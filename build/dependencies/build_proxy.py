#!/usr/bin/env python3
"""Build an isolated proxy candidate; never overwrite selected vendor archives."""

import argparse
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sbom"))
from provenance import archive_hashes, digest, git, write_json
from inspect_proxy import compiler_archive_evidence, inspect, verify_architecture, verify_source_delta


TARGETS = ("macos-arm64", "macos-x86_64", "windows-x86_64")


def source_snapshot(source, lock):
    if git(source, "rev-parse", "HEAD") != lock["commit"]:
        raise ValueError("Proxy source commit does not match the immutable candidate pin")
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Proxy source checkout must be clean, including untracked files")
    paths = git(source, "ls-files").splitlines()
    return archive_hashes(source, paths)


def recipe_snapshot():
    return archive_hashes(HERE, [".gitattributes", "build_proxy.py", "inspect_proxy.py", "proxy-source.json",
        "baseline-v4.9.10.json", "proxy/CMakeLists.txt", "proxy/behavior.cpp",
        "proxy/file-url.cpp", "proxy/relink-probe.cpp", "proxy/test.pac",
        "patches/proxy-windows-file-url.patch", "relink_candidate.py",
        "proxy_source_delivery.py", "README.md"])


def support_snapshot():
    return archive_hashes(HERE.parents[1], ["LICENSE", "build/sbom/provenance.py",
                                          "build/sbom/native_archive_objects.py"])


def staged_snapshot(source, files):
    paths = [a["path"] for a in files]
    actual = [p for p in source.rglob("*") if not p.is_dir()]
    if (any(p.is_symlink() for p in actual)
            or {p.relative_to(source).as_posix() for p in actual} != set(paths)):
        raise ValueError("Unexpected staged proxy source inputs")
    return archive_hashes(source, paths)


def baseline_inputs(root, target):
    frozen = json.loads((HERE / "baseline-v4.9.10.json").read_text())
    record = next(t for t in frozen["targets"] if t["id"] == target)
    inputs = []
    for name in ("libproxy", "libmodman"):
        archive = next(a for a in record["selectedArchives"] if a["name"] == name)
        path = root / archive["path"]
        if digest(path) != archive["sha256"]:
            raise ValueError("Baseline proxy archive hash mismatch: " + str(path))
        inputs.append({"path": str(path.resolve()), "sha256": archive["sha256"],
                       "name": name, "identity": "historical-version-unknown"})
    return inputs


def run(command, log, check=True):
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode and check:
        sys.stderr.write(log.read_text(encoding="utf-8"))
        raise subprocess.CalledProcessError(result.returncode, command)
    return result.returncode


def expected_archives(target):
    return (["lib/libproxy.lib", "lib/modman.lib"] if target == "windows-x86_64"
            else ["lib/libmodman.a", "lib/libproxy.a"])


def stage_source(source, output, lock, checkout_files):
    base_tar = output / "upstream-base.tar"
    canonical_git = ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf"]
    subprocess.run(canonical_git + ["-C", str(source), "archive", "--format=tar",
                    "--output=" + str(base_tar), lock["commit"]], check=True)
    staged = output / "source"
    with tarfile.open(base_tar) as archive:
        expected = {a["path"] for a in checkout_files}
        entries = archive.getmembers()
        if (any(not e.isfile() and not e.isdir() for e in entries)
                or {e.name for e in entries if e.isfile()} != expected):
            raise ValueError("Pinned source archive has unexpected files")
        for item in checkout_files:
            path = staged / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(item["path"]).read())
    base_files = archive_hashes(staged, [a["path"] for a in checkout_files])
    for patch in lock["patches"]:
        path = (HERE / patch["path"]).resolve()
        if digest(path) != patch["sha256"]:
            raise ValueError("Reviewed proxy patch hash mismatch")
        subprocess.run(canonical_git + ["apply", "--no-index", "--check", str(path)],
                       cwd=staged, check=True)
        subprocess.run(canonical_git + ["apply", "--no-index", str(path)], cwd=staged, check=True)
    files = staged_snapshot(staged, checkout_files)
    verify_source_delta(base_files, files, lock["patches"])
    return staged, base_files, files


def check_commands(output, target, modules, source):
    commands = json.loads((output / "build/compile_commands.json").read_text())
    expected = {
        "libmodman/module_manager.cpp", "libproxy/extension_config.cpp",
        "libproxy/extension_pacrunner.cpp", "libproxy/extension_wpad.cpp",
        "libproxy/proxy.cpp", "libproxy/url.cpp",
        "libproxy/test/url-test.cpp", "libproxy/test/url-encode.cpp",
        *("libproxy/modules/" + module + ".cpp" for module in modules),
    }
    actual = {Path(c["file"]).resolve().relative_to(source.resolve()).as_posix()
              for c in commands if Path(c["file"]).resolve().is_relative_to(source.resolve())}
    if actual != expected:
        raise ValueError("Actual compiled upstream sources differ from the candidate recipe")
    for entry in commands:
        command = entry["command"]
        if target == "windows-x86_64":
            if not re.search(r"(?:^|[ /-])MT(?:\s|$)", command) or re.search(
                    r"(?:^|[ /-])M[DT]d(?:\s|$)|(?:^|[ /-])MD(?:\s|$)", command):
                raise ValueError("Proxy candidate must use the release static MSVC CRT")
        else:
            if ("-arch " + target.removeprefix("macos-") not in command
                    or "-mmacosx-version-min=10.13" not in command):
                raise ValueError("Proxy compile command changed target/deployment compatibility")


def build(source, output, target, baseline):
    lock = json.loads((HERE / "proxy-source.json").read_text())
    source = source.resolve()
    output = output.resolve()
    before = source_snapshot(source, lock)
    recipe = recipe_snapshot()
    support = support_snapshot()
    if output.exists():
        raise ValueError("Use a fresh output directory; an old build cannot receive new provenance")
    old = baseline_inputs(baseline, target)
    windows = target == "windows-x86_64"
    if windows != (platform.system() == "Windows"):
        raise ValueError("Target requires its native operating system")
    output.mkdir(parents=True)
    staged, base_files, compiled_files = stage_source(source, output, lock, before)
    platform_key = "windows" if windows else "macos"
    install = output / "install"
    arguments = [
        "cmake", "-S", str(HERE / "proxy"), "-B", str(output / "build"),
        "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
        "-DPROXY_SOURCE=" + staged.as_posix(),
        "-DPROXY_MODULES=" + ";".join(lock["modules"][platform_key]),
        "-DPROXY_MODULE_DIRECTORY=" + lock["moduleDirectory"][platform_key],
        "-DCMAKE_INSTALL_PREFIX=" + install.as_posix(),
        "-DBASELINE_PROXY=" + Path(old[0]["path"]).as_posix(),
        "-DBASELINE_MODMAN=" + Path(old[1]["path"]).as_posix(),
    ]
    if not windows:
        arguments += ["-DCMAKE_OSX_ARCHITECTURES=" + target.removeprefix("macos-"),
                      "-DCMAKE_OSX_DEPLOYMENT_TARGET=10.13"]
    run(arguments, output / "configure.log")
    run(["cmake", "--build", str(output / "build"), "--verbose"], output / "build.log")
    test_exit_code = run(["ctest", "--test-dir", str(output / "build"), "--verbose",
         "--output-on-failure", "--output-junit", str(output / "test-results.xml")],
        output / "tests.log", check=False)
    run(["cmake", "--install", str(output / "build")], output / "install.log")
    check_commands(output, target, lock["modules"][platform_key], staged)
    if (before != source_snapshot(source, lock) or recipe != recipe_snapshot()
            or support != support_snapshot()):
        raise ValueError("Source or recipe changed during compilation")
    if compiled_files != staged_snapshot(staged, compiled_files):
        raise ValueError("Patched proxy source changed during compilation")
    if old != baseline_inputs(baseline, target):
        raise ValueError("Baseline archives changed during comparison")
    with tarfile.open(output / "upstream-source.tar", "w") as archive:
        for item in compiled_files:
            archive.add(staged / item["path"], arcname=item["path"])
    with tarfile.open(output / "candidate-recipe.tar", "w") as archive:
        for item in recipe:
            archive.add(HERE / item["path"], arcname="build/dependencies/" + item["path"])
        for item in support:
            archive.add(HERE.parents[1] / item["path"], arcname=item["path"])
    evidence_paths = ["configure.log", "build.log", "tests.log", "test-results.xml", "install.log",
        "build/CMakeCache.txt", "build/compile_commands.json", "build/build.ninja",
        "build/cmake_install.cmake",
        "install/include/proxy.h", "install/share/licenses/libproxy/COPYING",
        "upstream-base.tar", "upstream-source.tar", "candidate-recipe.tar"]
    compiler_files = sorted((output / "build/CMakeFiles").glob("*/CMakeCXXCompiler.cmake"))
    if len(compiler_files) != 1:
        raise ValueError("Expected one CMake compiler identity")
    evidence_paths.append(compiler_files[0].relative_to(output).as_posix())
    compiler_text = compiler_files[0].read_text()
    compiler = re.search(r'set\(CMAKE_CXX_COMPILER "([^"]+)"\)', compiler_text)
    if not compiler:
        raise ValueError("Missing actual CMake compiler path")
    cache = (output / "build/CMakeCache.txt").read_text()
    ninja = re.search(r"^CMAKE_MAKE_PROGRAM:FILEPATH=(.+)$", cache, re.MULTILINE)
    cmake = shutil.which("cmake")
    if not ninja or not cmake:
        raise ValueError("Missing actual CMake/Ninja toolchain path")
    tools = [Path(compiler[1]), Path(cmake), Path(ninja[1])]
    for name in ("CMAKE_AR", "CMAKE_LINKER") + (() if target.startswith("windows") else ("CMAKE_RANLIB",)):
        tool = re.search(r"^" + name + r":FILEPATH=(.+)$", cache, re.MULTILINE)
        if not tool:
            raise ValueError("Missing original proxy build tool: " + name)
        tools.append(Path(tool[1]))
    proof = compiler_archive_evidence(output, target, lock["modules"][platform_key],
                                     staged.as_posix(), (output / "build").as_posix())
    evidence_paths += [p["path"] for value in proof.values() for p in value["compiledObjects"]]
    evidence_paths += [value["builtArchive"] for value in proof.values()]
    record = {
        "schema_version": 2, "evidence_type": "isolated-source-build-candidate",
        "originalSource": staged.as_posix(), "originalBuild": (output / "build").as_posix(),
        "compilerArchiveEvidence": proof,
        "status": lock["status"], "source_repository": lock["repository"],
        "source_commit": lock["commit"], "components": lock["components"],
        "target": target, "configure_arguments": arguments,
        "testExitCode": test_exit_code,
        "validationStatus": "passed" if test_exit_code == 0 else "failed",
        "checkoutFiles": before, "baseSourceFiles": base_files, "sourceFiles": compiled_files,
        "recipeFiles": recipe, "recipeSupportFiles": support, "patches": lock["patches"],
        "acceptedCandidateChanges": lock["acceptedCandidateChanges"],
        "sourceCheckoutHandling": "Clean pinned checkout bytes are recorded separately; git archive supplies canonical source bytes before reviewed patches.",
        "recipeLicenseSha256": digest(HERE.parents[1] / "LICENSE"),
        "licenseFile": lock["licenseFile"], "licenseFileSha256": digest(staged / lock["licenseFile"]),
        "modules": lock["modules"][platform_key],
        "baselineArchives": old, "archives": archive_hashes(install, expected_archives(target)),
        "toolchainExecutables": [{"path": str(path.resolve()), "sha256": digest(path)}
                                for path in tools],
        "buildFiles": archive_hashes(output, evidence_paths),
        "limitations": lock["limitations"] + [
            "This is not plugin linker-selection evidence and is not promoted into release SBOMs.",
            "Tests exercise synthetic settings and a local PAC; WPAD discovery and external proxy/TLS traffic are not covered.",
            "Fresh builds only; no cached output is relabeled."
        ],
    }
    write_json(output / "proxy-build-provenance.json", record)
    verify(source, output, target)
    if test_exit_code:
        sys.stderr.write((output / "tests.log").read_text())
    inspect(output)
    return record


def verify(source, output, target):
    lock = json.loads((HERE / "proxy-source.json").read_text())
    record = json.loads((output / "proxy-build-provenance.json").read_text())
    if (record["schema_version"] != 2 or record["target"] != target
            or record["source_commit"] != lock["commit"]
            or record["source_repository"] != lock["repository"]
            or record["status"] != lock["status"]
            or record["components"] != lock["components"]
            or record["patches"] != lock["patches"]
            or record["acceptedCandidateChanges"] != lock["acceptedCandidateChanges"]
            or record["licenseFile"] != lock["licenseFile"]
            or record["licenseFileSha256"] != digest(output / "source" / lock["licenseFile"])
            or record["modules"] != lock["modules"]["windows" if target.startswith("windows") else "macos"]):
        raise ValueError("Proxy candidate identity mismatch")
    if [a["path"] for a in record["archives"]] != sorted(expected_archives(target)):
        raise ValueError("Unexpected proxy output archive set")
    for expected, actual in (
        (record["checkoutFiles"], source_snapshot(source, lock)),
        (record["sourceFiles"], staged_snapshot(output / "source", record["sourceFiles"])),
        (record["recipeFiles"], recipe_snapshot()),
        (record["recipeSupportFiles"], support_snapshot()),
        (record["archives"], archive_hashes(output / "install",
                                          [a["path"] for a in record["archives"]])),
        (record["buildFiles"], archive_hashes(output, [a["path"] for a in record["buildFiles"]])),
    ):
        if expected != actual:
            raise ValueError("Proxy source/recipe/output/original-build evidence mismatch")
    verify_source_delta(record["baseSourceFiles"], record["sourceFiles"], lock["patches"])
    check_commands(output, target, record["modules"], output / "source")
    for tool in record["toolchainExecutables"]:
        if digest(Path(tool["path"])) != tool["sha256"]:
            raise ValueError("Proxy toolchain executable changed")
    for archive in record["archives"]:
        verify_architecture(output / "install" / archive["path"], target)
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "verify"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--baseline-root", type=Path, default=HERE.parents[1])
    args = parser.parse_args()
    if args.command == "build":
        build(args.source, args.output, args.target, args.baseline_root)
    else:
        verify(args.source, args.output, args.target)
        inspect(args.output)
