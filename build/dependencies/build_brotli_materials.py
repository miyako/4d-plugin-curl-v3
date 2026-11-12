#!/usr/bin/env python3
"""Fresh isolated Brotli material capture using the existing source record."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

from build_native import ROOT
from inspect_proxy import verify_architecture
import generate
import provider_materials
import provenance


def build(source, output, target, commit):
    source, output = source.resolve(), output.resolve()
    windows = target == "windows-x86_64"
    if (platform.system() != ("Windows" if windows else "Darwin")
            or output.exists() or output.is_relative_to(source)
            or provenance.git(source, "rev-parse", "HEAD") != commit
            or provenance.git(source, "status", "--porcelain", "--untracked-files=no")
            or provenance.git(source, "ls-files", "--others", "--directory")):
        raise ValueError("Use fresh external output and the clean pinned native Brotli source")
    recipes = [
        "LICENSE",
        "build/dependencies/build_brotli_materials.py", "build/dependencies/trace_compiler.py",
        "build/dependencies/build_native.py", "build/dependencies/inspect_proxy.py",
        "build/sbom/provider_materials.py", "build/sbom/provenance.py",
        "build/sbom/generate.py", "build/sbom/native_archive_objects.py",
        "build/sbom/archives.py", "build/sbom/native_archive_identities.py",
        "build/sbom/linker.py",
    ]
    before_recipes = provenance.archive_hashes(ROOT, recipes)
    output.mkdir(parents=True)
    calls = output / "compiler-calls"
    calls.mkdir()
    env = os.environ.copy()
    install = output / "vendor"
    work = output / "build"
    prefix = output / "install"
    cmake, ninja = shutil.which("cmake"), shutil.which("ninja")
    if not cmake or not ninja:
        raise FileNotFoundError("The chosen native provider build requires cmake and ninja")
    arguments = [cmake, "-S", str(source), "-B", str(work), "-G", "Ninja",
                 "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=OFF",
                 "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
                 "-DCMAKE_C_COMPILER_LAUNCHER=" + ";".join([
                     sys.executable, str(ROOT / "build/dependencies/trace_compiler.py"), str(calls)])]
    arguments += (["-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
                   "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"] if windows else [
                       "-DCMAKE_OSX_ARCHITECTURES=" + target.removeprefix("macos-"),
                       "-DCMAKE_OSX_DEPLOYMENT_TARGET=10.13"])

    def run(command, name):
        with (output / name).open("w") as stream:
            subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)

    run(arguments, "configure.log")
    cache = (work / "CMakeCache.txt").read_text()
    paths = {"cmake": cmake, "ninja": ninja, "python": sys.executable}
    for key in (("C_COMPILER", "AR", "LINKER") if windows else
                ("C_COMPILER", "AR", "RANLIB", "LINKER")):
        matches = re.findall(r"^CMAKE_" + key + r":(?:FILEPATH|STRING)=(.+)$", cache, re.M)
        if len(matches) != 1 or not Path(matches[0]).is_file():
            raise ValueError("CMake native tool needs explicit resolution: " + key)
        paths[key] = matches[0]
    if not windows:
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
        paths["SDKSettings.json"] = str(Path(sdk) / "SDKSettings.json")
    toolchain = {name: {"path": path, "sha256": provenance.digest(Path(path))}
                 for name, path in paths.items()}
    run([cmake, "--build", str(work), "--parallel", "3", "--verbose"], "build.log")
    run([str(Path(cmake).with_name("ctest" + (".exe" if windows else ""))),
         "--test-dir", str(work), "--output-on-failure", "--no-tests=error"], "tests.log")
    run([cmake, "--install", str(work)], "install.log")
    archives = sorted((prefix / "lib").glob("brotli*.lib" if windows else "libbrotli*.a"))
    if len(archives) != 3:
        raise ValueError("Expected the three original static Brotli provider archives")
    destination = install / ("lib/64" if windows else "a")
    destination.mkdir(parents=True)
    for archive in archives:
        verify_architecture(archive, target)
        shutil.copyfile(archive, destination / archive.name)
    generate.brotli_provenance(argparse.Namespace(source=source, vendor=install))
    path = install / "brotli-provenance.json"
    record = json.loads(path.read_text())
    if (record["sourceCommit"] != commit or record["version"] != "1.2.1"
            or provenance.git(source, "status", "--porcelain", "--untracked-files=no")
            or provenance.archive_hashes(ROOT, recipes) != before_recipes
            or any(provenance.digest(Path(p["path"])) != p["sha256"] for p in toolchain.values())):
        raise ValueError("Brotli source, recipe or native tools changed during compilation")
    provider_materials.capture(
        source, install, record, calls,
        [(work / name, name) for name in ("CMakeCache.txt", "compile_commands.json", "build.ninja")],
        [(output / name, name) for name in ("configure.log", "build.log", "tests.log", "install.log")],
        [(ROOT / name, name) for name in recipes], toolchain, target)
    record["buildMaterials"]["configureCommand"] = arguments
    provenance.write_json(path, record)
    provider_materials.inspect(install, record)
    return {"target": target, "sourceCommit": commit,
            "archives": {a["archive"]: len(a["objects"]) for a in record["buildMaterials"]["archives"]},
            "status": "isolated-material-experiment-not-approved-for-production"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=("macos-arm64", "macos-x86_64", "windows-x86_64"), required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.output, args.target, args.commit), indent=2))
