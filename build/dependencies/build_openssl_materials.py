#!/usr/bin/env python3
"""Fresh isolated OpenSSL compiler-material experiment; never adopt archives."""

import argparse
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys

from build_native import ROOT
from inspect_proxy import verify_architecture
import provider_materials
import provenance


def tools(target):
    if target == "windows-x86_64":
        paths = {name: shutil.which(name) for name in ("cl", "link", "lib", "nmake", "perl", "nasm")}
        paths["python"] = sys.executable
        if any(not path for path in paths.values()):
            raise FileNotFoundError("OpenSSL needs the native MSVC, Perl and NASM tools")
        return {name: {"path": path, "sha256": provenance.digest(Path(path))}
                for name, path in paths.items()}
    paths = {name: subprocess.check_output(
        ["xcrun", "--find", name], text=True).strip()
             for name in ("clang", "ld", "ar", "ranlib")}
    paths.update({name: shutil.which(name) for name in ("make", "perl")})
    paths["cc"] = "/usr/bin/cc"
    paths["python"] = sys.executable
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    paths["SDKSettings.json"] = str(Path(sdk) / "SDKSettings.json")
    return {name: {"path": path, "sha256": provenance.digest(Path(path))}
            for name, path in paths.items()}


def build(source, output, target, commit):
    source, output = source.resolve(), output.resolve()
    windows = target == "windows-x86_64"
    if (platform.system() != ("Windows" if windows else "Darwin")
            or output.exists() or output.is_relative_to(source)
            or (source / "configdata.pm").exists()
            or provenance.git(source, "ls-files", "--others", "--directory")):
        raise ValueError("Use fresh external output and a clean, unconfigured native source checkout")
    identity = provenance.source_identity(source)
    if identity["source_commit"] != commit or identity["version"] != "3.5.8":
        raise ValueError("OpenSSL experiment must use the explicitly pinned matching source")
    output.mkdir(parents=True)
    calls = output / "compiler-calls"
    calls.mkdir()
    toolchain = tools(target)
    recipes = [
        "LICENSE",
        "build/dependencies/build_openssl_materials.py",
        "build/dependencies/build_native.py", "build/dependencies/inspect_proxy.py",
        "build/dependencies/trace_compiler.py",
        "build/dependencies/probe_provider_tls.py",
        "build/dependencies/native/provider-tls-probe.c",
        "build/sbom/provider_materials.py", "build/sbom/provenance.py",
        "build/sbom/native_archive_objects.py", "build/sbom/linker.py",
    ]
    recipe_hashes = provenance.archive_hashes(ROOT, recipes)
    trace = ROOT / "build/dependencies/trace_compiler.py"
    env = os.environ.copy()
    quote = subprocess.list2cmdline if windows else shlex.join
    env["CC"] = quote([sys.executable, str(trace), str(calls),
                       toolchain["cl" if windows else "cc"]["path"]])
    if windows:
        env["AS"] = quote([sys.executable, str(trace), str(calls), toolchain["nasm"]["path"]])
    arguments = [provenance.PLATFORMS[target], "no-shared", "no-tests"]
    arguments += (["-MT", "--release"] if windows else ["-mmacosx-version-min=10.13"])
    arguments.append("--prefix=" + str(output / "install"))
    if windows:
        arguments.append("--openssldir=" + str(output / "install/ssl"))

    def run(command, name):
        with (output / name).open("w") as stream:
            subprocess.run(command, cwd=source, env=env, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)

    run([toolchain["perl"]["path"], str(source / "Configure"), *arguments], "configure.log")
    actual_cc = subprocess.check_output(
        ["perl", "-I", str(source), "-Mconfigdata", "-e", "print $configdata::config{CC}"],
        cwd=source, text=True)
    if actual_cc != env["CC"]:
        raise ValueError("OpenSSL Configure did not retain the exact compiler tracer")
    if windows:
        actual_as = subprocess.check_output(
            ["perl", "-I", str(source), "-Mconfigdata", "-e", "print $configdata::config{AS}"],
            cwd=source, text=True)
        if actual_as != env["AS"]:
            raise ValueError("OpenSSL Configure did not retain the exact NASM tracer")
    run([toolchain["nmake"]["path"]] if windows else [toolchain["make"]["path"], "-j3"], "build.log")
    run([toolchain["nmake" if windows else "make"]["path"], "install_sw"], "install.log")
    if (tools(target) != toolchain or provenance.source_identity(source) != identity
            or provenance.archive_hashes(ROOT, recipes) != recipe_hashes):
        raise ValueError("OpenSSL source/toolchain changed during the fresh experiment")
    install = output / "install"
    record = provenance.source_record(source, install, target, arguments)
    for archive in record["archives"]:
        verify_architecture(install / archive["path"], target)
    provider_materials.capture(
        source, install, record, calls,
        [(source / name, name) for name in ("Makefile", "configdata.pm")],
        [(output / name, name) for name in ("configure.log", "build.log", "install.log")],
        [(ROOT / name, name) for name in recipes], toolchain)
    record["buildMaterials"]["compilerEnvironment"] = {
        key: env.get(key) for key in ("CC", "AS", "CFLAGS", "CPPFLAGS", "LDFLAGS", "SDKROOT",
                                     "MACOSX_DEPLOYMENT_TARGET", "DEVELOPER_DIR", "INCLUDE",
                                     "LIB", "WindowsSdkDir", "WindowsSDKVersion", "VCToolsVersion")}
    provenance.write_json(install / provenance.RECORD, record)
    provenance.read_record(install / provenance.RECORD)
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
