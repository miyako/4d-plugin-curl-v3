#!/usr/bin/env python3
"""Build isolated version-matched libssh2 against a verified OpenSSL provider."""

import argparse
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from build_http import snapshot
from build_native import ROOT, RECIPES, run, stage, tree_files, toolchain, object_evidence
from build_native import probe_selections as selections
from inspect_proxy import verify_architecture, verify_tar
from observe_curl import inspect as inspect_baseline
from provenance import archive_hashes, digest, read_record, write_json

COMMIT = "a312b43325e3383c865a87bb1d26cb52e3292641"
LICENSE_SHA = "f7f9633cf9ff2f1333f3d7ce46973a8716a4d2a2815ad56f30d437d5fea7bafe"
SSH_RECIPES = RECIPES + [
    "build/dependencies/build_ssh.py", "build/dependencies/build_http.py",
    "build/dependencies/observe_curl.py", "build/dependencies/native/curl-info.c",
    "build/dependencies/native/probe-json.h"]
NOTICES = ["COPYING", "src/bcrypt_pbkdf.c", "src/blowfish.c",
           "src/cipher-chachapoly.c", "src/cipher-chachapoly.h",
           "src/chacha.c", "src/chacha.h", "src/poly1305.c", "src/poly1305.h", "src/misc.c"]


def compare(candidate, baseline):
    if candidate.get("version") != "1.11.1_DEV":
        raise ValueError("libssh2 candidate version differs from the version-matched source")
    if (not baseline.get("sshAlgorithms")
            or candidate.get("sshAlgorithms") != baseline["sshAlgorithms"]):
        raise ValueError("libssh2 algorithm order/configuration differs from the measured baseline")


def verify_tests(path):
    root = ET.parse(path).getroot()
    cases = root.findall("testcase")
    if (root.tag != "testsuite" or root.get("failures") != "0" or root.get("tests") != "1"
            or {c.get("name") for c in cases} != {"test_simple"}
            or len(cases) != 1 or cases[0].get("status") != "run"
            or any(c.tag in ("failure", "error", "skipped") for c in cases[0])):
        raise ValueError("libssh2 standalone test_simple did not pass completely")


def verify_compile_settings(compiled, target):
    for entry in compiled:
        command = entry["command"]
        if target.startswith("windows"):
            if (not re.search(r"(?:^|[ /-])MT(?:\s|$)", command)
                    or re.search(r"(?:^|[ /-])M[DT]d(?:\s|$)|(?:^|[ /-])MD(?:\s|$)", command)):
                raise ValueError("libssh2 must retain the release static MSVC CRT")
        elif ("-arch " + target.removeprefix("macos-") not in command
              or "-mmacosx-version-min=10.13" not in command):
            raise ValueError("libssh2 architecture/deployment settings changed")


def inspect(output):
    record = json.loads((output / "native-build-provenance.json").read_text())
    if any(record.get(k) != v for k, v in {
            "schema_version": 1, "library": "libssh2",
            "source_commit": COMMIT, "version": "1.11.1_DEV",
            "source_repository": "https://github.com/libssh2/libssh2",
            "evidence_type": "isolated-source-build-candidate",
            "status": "not-approved-for-production", "licenseFileSha256": LICENSE_SHA,
    }.items()):
        raise ValueError("libssh2 source identity or candidate status changed")
    verify_tar(output / "upstream-source.tar", record["sourceFiles"], directories=True)
    recipe_version = record.get("recipeContractVersion", 1)
    expected_recipes = set(SSH_RECIPES)
    if recipe_version == 1:
        expected_recipes.remove("build/dependencies/native/probe-json.h")
    elif recipe_version != 2:
        raise ValueError("Unsupported libssh2 recipe contract")
    if (record["sourceFiles"] != tree_files(output / "source")
            or digest(output / "source/COPYING") != LICENSE_SHA
            or set(p["path"] for p in record["recipeFiles"]) != expected_recipes
            or record["recipeFiles"] != archive_hashes(
                output / "recipe", [p["path"] for p in record["recipeFiles"]])
            or record["noticeFiles"] != archive_hashes(output / "source", NOTICES)):
        raise ValueError("libssh2 source/recipe/notices changed")
    paths = [p["path"] for p in record["buildFiles"]]
    required = {"configure.log", "build.log", "tests.log", "test-results.xml",
                "build/CMakeCache.txt", "build/compile_commands.json", "build/build.ninja",
                "candidate.json", "candidate.stderr", "probe-build.log", "probe.map",
                "build/src/libssh2_config.h", record["builtArchive"],
                "build/tests/test_simple" + (".exe" if record["target"].startswith("windows") else ""),
                "probe.exe" if record["target"].startswith("windows") else "probe"}
    if not required.issubset(paths) or record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("libssh2 original build/validation outputs changed")
    if record["target"].startswith("windows"):
        if ("unit.map" not in paths or record.get("unitLinkSelections") != selections(
                output, record["target"], record["probeInputs"],
                map_name="unit.map", log_name="build.log")):
            raise ValueError("libssh2 upstream unit test did not select the exact delivered providers")
    installed = output / "install"
    if (record["installFiles"] != tree_files(installed)
            or digest(installed / record["archives"][0]["path"]) != digest(output / record["builtArchive"])):
        raise ValueError("libssh2 installed archive/interface changed")
    provider = read_record(output / "provider/openssl-build-provenance.json")
    if record["providerFiles"] != tree_files(output / "provider"):
        raise ValueError("libssh2 OpenSSL provider headers/installed files changed")
    if (provider["target"] != record["target"] or provider["version"] != "3.5.8"
            or provider["source_commit"] != "f4dc4d58b48d346a8270183f89acf826d459b0ca"):
        raise ValueError("libssh2 OpenSSL provider differs from the pinned baseline")
    baseline = inspect_baseline(output / "baseline")["observations"]
    compare(json.loads((output / "candidate.json").read_text()), baseline)
    verify_tests(output / "test-results.xml")
    commands = json.loads((output / "build/compile_commands.json").read_text())
    compiled = [c for c in commands if "CMakeFiles/libssh2_static.dir/"
                in c["output"].replace("\\", "/")]
    if not compiled or compiled != record["compiledSources"]:
        raise ValueError("libssh2 actual compile inputs changed")
    verify_compile_settings(compiled, record["target"])
    original_build = record["configure_arguments"][record["configure_arguments"].index("-B") + 1]
    proof = object_evidence(output, record["builtArchive"], compiled, original_build)
    if any(record.get(k) != v for k, v in proof.items()):
        raise ValueError("libssh2 compiler-object/archive-member binding changed")
    if record["linkSelections"] != selections(output, record["target"], record["probeInputs"]):
        raise ValueError("libssh2 actual probe selections changed")
    if (record["probeInputs"]["libssh2"]["sha256"] != digest(output / record["builtArchive"])
            or record["probeInputs"]["OpenSSL"]["sha256"] != next(
                a["sha256"] for a in provider["archives"] if "crypto" in a["path"])):
        raise ValueError("libssh2 selected probe archives differ from delivered build outputs")
    members = verify_architecture(installed / record["archives"][0]["path"], record["target"])
    return {"library": "libssh2", "target": record["target"], "version": record["version"],
            "objectMembers": members, "status": record["status"],
            "validationScope": record["validationScope"]}


def build(source, output, target, openssl_install, baseline):
    if target.startswith("windows") != (platform.system() == "Windows"):
        raise ValueError("libssh2 requires its native target operating system")
    source, output, openssl_install = source.resolve(), output.resolve(), openssl_install.resolve()
    observed = inspect_baseline(baseline)
    if observed["target"] != target or "sshAlgorithms" not in observed["observations"]:
        raise ValueError("A measured SSH algorithm baseline for this exact target is required")
    if any(values != ["none"] for name, values in observed["observations"]["sshAlgorithms"].items()
           if name.startswith("compression")):
        raise ValueError("Review the measured SSH compression configuration before choosing its recipe")
    provider = read_record(openssl_install / "openssl-build-provenance.json")
    provider_files = tree_files(openssl_install)
    if (provider["target"] != target or provider["version"] != "3.5.8"
            or provider["source_commit"] != "f4dc4d58b48d346a8270183f89acf826d459b0ca"):
        raise ValueError("libssh2 requires the matching source-built OpenSSL provider")
    if output.exists():
        raise ValueError("Use a fresh libssh2 evidence directory")
    checkout, links = snapshot(source, COMMIT)
    if links:
        raise ValueError("Unexpected libssh2 source gitlinks")
    output.mkdir(parents=True)
    staged, files = stage(source, output, COMMIT, checkout)
    if digest(staged / "COPYING") != LICENSE_SHA:
        raise ValueError("libssh2 pinned license text changed")
    recipes = archive_hashes(ROOT, SSH_RECIPES)
    for item in recipes:
        destination = output / "recipe" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], destination)
    shutil.copytree(baseline, output / "baseline")
    shutil.copytree(openssl_install, output / "provider")
    windows = target.startswith("windows")
    crypto = next(a["path"] for a in provider["archives"] if "crypto" in a["path"])
    ssl = next(a["path"] for a in provider["archives"] if "ssl" in Path(a["path"]).name)
    arguments = ["cmake", "-S", str(staged), "-B", str(output / "build"), "-G", "Ninja",
                 "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                 "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                 "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
                 "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON",
                 "-DBUILD_STATIC_LIBS=ON", "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_EXAMPLES=OFF",
                 "-DBUILD_TESTING=ON", "-DRUN_DOCKER_TESTS=OFF", "-DRUN_SSHD_TESTS=OFF",
                 "-DENABLE_ZLIB_COMPRESSION=OFF", "-DCRYPTO_BACKEND=OpenSSL",
                 "-DOPENSSL_USE_STATIC_LIBS=TRUE",
                 "-DOPENSSL_INCLUDE_DIR=" + str(openssl_install / "include"),
                 "-DOPENSSL_CRYPTO_LIBRARY=" + str(openssl_install / crypto),
                 "-DOPENSSL_SSL_LIBRARY=" + str(openssl_install / ssl),
                 "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"]
    if not windows:
        arguments += ["-DCMAKE_OSX_ARCHITECTURES=" + target.removeprefix("macos-"),
                      "-DCMAKE_OSX_DEPLOYMENT_TARGET=10.13"]
    else:
        arguments += ["-DOPENSSL_ROOT_DIR=" + str(openssl_install),
                      "-DOPENSSL_MSVC_STATIC_RT=TRUE",
                      '-DCMAKE_EXE_LINKER_FLAGS=/VERBOSE:LIB /MAP:"' + str(output / "unit.map") + '"']
        for config in ("RELEASE", "DEBUG"):
            arguments += ["-DLIB_EAY_" + config + "=" + str(openssl_install / crypto),
                          "-DSSL_EAY_" + config + "=" + str(openssl_install / ssl)]
    run(arguments, output / "configure.log")
    tools, compiler_file = toolchain(output, target)
    run(["cmake", "-E", "env", "VERBOSE=1", "cmake", "--build",
         str(output / "build"), "--target", "test_simple", "--verbose"],
        output / "build.log")
    run(["ctest", "--test-dir", str(output / "build"), "-R", "^test_simple$", "--verbose",
         "--no-tests=error", "--output-junit", str(output / "test-results.xml")], output / "tests.log")
    commands = json.loads((output / "build/compile_commands.json").read_text())
    compiled = [c for c in commands if "CMakeFiles/libssh2_static.dir/"
                in c["output"].replace("\\", "/")]
    hashes = {p["path"]: p["sha256"] for p in files}
    for command in compiled:
        relative = Path(command["file"]).relative_to(staged).as_posix()
        if relative not in hashes or digest(staged / relative) != hashes[relative]:
            raise ValueError("libssh2 compilation input lacks original source evidence")
    verify_compile_settings(compiled, target)
    name = "libssh2.lib" if windows else "libssh2.a"
    built = output / "build/src" / name
    install = output / "install"
    (install / "lib").mkdir(parents=True)
    (install / "include").mkdir()
    shutil.copyfile(built, install / "lib" / name)
    for header in ("libssh2.h", "libssh2_publickey.h", "libssh2_sftp.h"):
        shutil.copyfile(staged / "include" / header, install / "include" / header)
    probe = output / ("probe.exe" if windows else "probe")
    compiler = shutil.which("cl") if windows else subprocess.check_output(
        ["xcrun", "--find", "clang"], text=True).strip()
    if windows:
        probe_arguments = [compiler, "/nologo", "/O2", "/MT", "/DSSH_ONLY", "/DLIBSSH2_STATIC",
                           "/I" + str(install / "include"), str(ROOT / "build/dependencies/native/curl-info.c"),
                           "/Fo" + str(output / "probe.obj"), "/Fe" + str(probe), str(built),
                           str(openssl_install / crypto), "/link", "/VERBOSE:LIB",
                           "/MAP:" + str(output / "probe.map"),
                           "ws2_32.lib", "crypt32.lib", "bcrypt.lib", "user32.lib", "advapi32.lib"]
    else:
        sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
        probe_arguments = [compiler, "-arch", target.removeprefix("macos-"), "-isysroot", sdk,
                           "-mmacosx-version-min=10.13", "-DSSH_ONLY", "-DLIBSSH2_STATIC",
                           "-I" + str(install / "include"), str(ROOT / "build/dependencies/native/curl-info.c"),
                           str(built), str(openssl_install / crypto),
                           "-Wl,-map," + str(output / "probe.map"), "-o", str(probe)]
    run(probe_arguments, output / "probe-build.log")
    probe_compiler = {"path": compiler, "sha256": digest(Path(compiler))}
    with (output / "candidate.json").open("w") as stdout, (output / "candidate.stderr").open("w") as stderr:
        subprocess.run([str(probe)], stdout=stdout, stderr=stderr, check=True)
    compare(json.loads((output / "candidate.json").read_text()), observed["observations"])
    if (files != tree_files(staged) or snapshot(source, COMMIT)[0] != checkout
            or recipes != archive_hashes(ROOT, SSH_RECIPES)
            or read_record(openssl_install / "openssl-build-provenance.json") != provider
            or tree_files(openssl_install) != provider_files
            or toolchain(output, target) != (tools, compiler_file)):
        raise ValueError("libssh2 source, recipes, provider or toolchain changed during build")
    evidence = ["configure.log", "build.log", "tests.log", "test-results.xml",
                "build/CMakeCache.txt", "build/compile_commands.json", "build/build.ninja",
                "build/src/libssh2_config.h", built.relative_to(output).as_posix(), compiler_file,
                "candidate.json", "candidate.stderr", "probe-build.log", "probe.map", probe.name,
                "build/tests/test_simple" + (".exe" if windows else "")]
    proof = object_evidence(output, built.relative_to(output).as_posix(), compiled, output / "build")
    probe_inputs = {"libssh2": {"path": str(built), "sha256": digest(built)},
                    "OpenSSL": {"path": str(openssl_install / crypto),
                                "sha256": digest(openssl_install / crypto)}}
    evidence += [p["path"] for p in proof["compiledObjects"]]
    unit_selections = {}
    if windows:
        evidence.append("unit.map")
        unit_selections = selections(output, target, probe_inputs, map_name="unit.map", log_name="build.log")
    record = {
        "schema_version": 1, "recipeContractVersion": 2,
        "evidence_type": "isolated-source-build-candidate",
        "status": "not-approved-for-production", "library": "libssh2", "target": target,
        "source_commit": COMMIT, "source_repository": "https://github.com/libssh2/libssh2",
        "version": "1.11.1_DEV", "sourceFiles": files, "checkoutFiles": checkout,
        "recipeFiles": recipes, "configure_arguments": arguments, "probe_arguments": probe_arguments,
        "toolchain": tools, "compiledSources": compiled, **proof,
        "probeCompiler": probe_compiler, "probeInputs": probe_inputs,
        "linkSelections": selections(output, target, probe_inputs), "providerFiles": provider_files,
        "unitLinkSelections": unit_selections,
        "builtArchive": built.relative_to(output).as_posix(),
        "archives": archive_hashes(install, ["lib/" + name]), "installFiles": tree_files(install),
        "buildFiles": archive_hashes(output, evidence), "licenseFileSha256": LICENSE_SHA,
        "noticeFiles": archive_hashes(staged, NOTICES),
        "licenseScope": "COPYING is BSD-3-Clause; additional BSD-2-Clause, ISC-style and public-domain notices retained in source; not a legal-compliance conclusion",
        "validationScope": "standalone test_simple and exact supported-algorithm/order comparison; no live SSH negotiation or full-plugin validation",
    }
    write_json(output / "native-build-provenance.json", record)
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("build")
    sub.add_argument("--source", type=Path, required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub.add_argument("--target", choices=("macos-arm64", "macos-x86_64", "windows-x86_64"), required=True)
    sub.add_argument("--openssl-install", type=Path, required=True)
    sub.add_argument("--baseline", type=Path, required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("output", type=Path)
    args = parser.parse_args()
    result = (inspect(args.output) if args.command == "inspect" else
              build(args.source, args.output, args.target, args.openssl_install, args.baseline))
    print(json.dumps(result, indent=2))
