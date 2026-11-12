#!/usr/bin/env python3
"""Reconstruct version-matched curl from source without replacing production inputs."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

import build_http
import build_native
import build_ssh
from build_iconv import extract
from build_native import ROOT, object_evidence, probe_selections, run, toolchain, tree_files
from inspect_proxy import verify_architecture, verify_tar
import observe_curl
from provenance import archive_hashes, digest, write_json

RECIPES = build_ssh.SSH_RECIPES + [
    "build/dependencies/build_curl.py", "build/dependencies/build_iconv.py"]


def pin():
    return next(p for p in json.loads(
        (ROOT / "build/dependencies/native-sources.json").read_text())["sourceArchives"]
                if p["library"] == "curl")


def compare(candidate, baseline, target):
    if (set(candidate) != set(baseline) or not isinstance(candidate.get("host"), str)
            or not candidate["host"] or "tlsBackends" not in candidate
            or "sshAlgorithms" not in candidate):
        raise ValueError("Curl configuration observations have missing or unexpected fields")
    observe_curl.validate_observations(candidate, observe_curl.baseline(target), target)
    differences = {k: {"candidate": candidate[k], "baseline": baseline[k]}
                   for k in baseline if k != "host" and candidate[k] != baseline[k]}
    if differences:
        raise ValueError("Reconstructed curl configuration differs: " + json.dumps(differences))
    return {"candidate": candidate["host"], "baseline": baseline["host"]}


def provider_checks(output, target):
    providers = output / "providers"
    for name, inspector in (("ssh", build_ssh.inspect), ("zlib", build_native.inspect),
                            ("http", build_http.inspect), ("baseline", observe_curl.inspect)):
        if inspector(providers / name)["target"] != target:
            raise ValueError("Curl prerequisite evidence targets a different architecture")
    baseline = json.loads((providers / "baseline/curl-baseline-observation.json").read_text())
    ssl = json.loads((providers / "ssh/provider/openssl-build-provenance.json").read_text())
    if ssl != baseline["rebuiltProviders"]["OpenSSL"]:
        raise ValueError("Curl baseline and SSH prerequisite use different original OpenSSL providers")
    return baseline["observations"], baseline["rebuiltProviders"]


def inputs(output, target):
    providers = output / "providers"
    ssl = providers / "ssh/provider"
    ssh = providers / "ssh/install"
    zlib = providers / "zlib/install"
    http = providers / "http/install"
    baseline = json.loads((providers / "baseline/curl-baseline-observation.json").read_text())
    records = baseline["rebuiltProviders"]
    result = {}
    for name, root, filename in (
            ("libssh2", ssh, "libssh2.lib" if target.startswith("windows") else "libssh2.a"),
            ("zlib", zlib, "zlib.lib" if target.startswith("windows") else "libz.a"),
            ("nghttp2", http, "nghttp2.lib" if target.startswith("windows") else "libnghttp2.a")):
        result[name] = root / "lib" / filename
    for archive in records["OpenSSL"]["archives"]:
        name = "OpenSSL-crypto" if "crypto" in archive["path"] else "OpenSSL-ssl"
        result[name] = ssl / archive["path"]
    for archive in records["Brotli"]["archives"]:
        for component in ("dec", "common"):
            if component in archive["path"]:
                result["Brotli-" + component] = (
                    providers / "baseline/rebuilt-providers/Brotli" / archive["path"])
    return result, {"ssl": ssl / "include", "ssh": ssh / "include",
                    "zlib": zlib / "include", "http": http / "include",
                    "brotli": output / "brotli/source/c/include"}


def configure(output, target, archives, headers):
    flags = [
        "CMAKE_BUILD_TYPE=Release", "CMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "CMAKE_POSITION_INDEPENDENT_CODE=ON", "CMAKE_POLICY_DEFAULT_CMP0091=NEW",
        "CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
        "BUILD_SHARED_LIBS=OFF", "BUILD_STATIC_LIBS=ON", "BUILD_CURL_EXE=OFF",
        "BUILD_LIBCURL_DOCS=OFF", "BUILD_MISC_DOCS=OFF", "ENABLE_CURL_MANUAL=OFF",
        "CURL_USE_PKGCONFIG=OFF", "CURL_USE_CMAKECONFIG=OFF", "CURL_USE_OPENSSL=ON",
        "OPENSSL_USE_STATIC_LIBS=TRUE", "OPENSSL_INCLUDE_DIR=" + str(headers["ssl"]),
        "OPENSSL_CRYPTO_LIBRARY=" + str(archives["OpenSSL-crypto"]),
        "OPENSSL_SSL_LIBRARY=" + str(archives["OpenSSL-ssl"]),
        "ZLIB_INCLUDE_DIR=" + str(headers["zlib"]), "ZLIB_LIBRARY=" + str(archives["zlib"]),
        "CURL_ZLIB=ON", "CURL_BROTLI=ON", "BROTLI_INCLUDE_DIR=" + str(headers["brotli"]),
        "BROTLIDEC_LIBRARY=" + str(archives["Brotli-dec"]),
        "BROTLICOMMON_LIBRARY=" + str(archives["Brotli-common"]),
        "USE_NGHTTP2=ON", "NGHTTP2_USE_STATIC_LIBS=ON",
        "NGHTTP2_INCLUDE_DIR=" + str(headers["http"]),
        "NGHTTP2_LIBRARY=" + str(archives["nghttp2"]), "CURL_USE_LIBSSH2=ON",
        "LIBSSH2_INCLUDE_DIR=" + str(headers["ssh"]),
        "LIBSSH2_LIBRARY=" + str(archives["libssh2"]),
        "CURL_ZSTD=OFF", "CURL_USE_LIBPSL=OFF", "USE_LIBIDN2=OFF", "USE_APPLE_IDN=OFF",
        "USE_WIN32_IDN=OFF", "USE_NGTCP2=OFF", "USE_QUICHE=OFF", "ENABLE_ARES=OFF",
        "ENABLE_THREADED_RESOLVER=ON", "CURL_DISABLE_LDAP=ON", "CURL_DISABLE_LDAPS=ON",
        "CURL_DISABLE_WEBSOCKETS=ON", "CURL_ENABLE_SMB=OFF", "CURL_ENABLE_NTLM=OFF",
        "CURL_USE_GSSAPI=OFF", "CURL_CA_BUNDLE=none", "CURL_CA_PATH=none"]
    if target.startswith("windows"):
        flags += ["CURL_STATIC_CRT=ON", "CURL_USE_SCHANNEL=ON", "CURL_WINDOWS_SSPI=ON",
                  "ENABLE_UNICODE=ON", "CURL_DEFAULT_SSL_BACKEND=openssl",
                  "OPENSSL_ROOT_DIR=" + str(headers["ssl"].parent), "OPENSSL_MSVC_STATIC_RT=TRUE"]
        for config in ("RELEASE", "DEBUG"):
            flags += ["LIB_EAY_" + config + "=" + str(archives["OpenSSL-crypto"]),
                      "SSL_EAY_" + config + "=" + str(archives["OpenSSL-ssl"])]
    else:
        flags += ["CMAKE_OSX_ARCHITECTURES=" + target.removeprefix("macos-"),
                  "CMAKE_OSX_DEPLOYMENT_TARGET=10.13", "USE_APPLE_SECTRUST=ON"]
    return ["cmake", "-S", str(output / "source"), "-B", str(output / "build"),
            "-G", "Ninja", *("-D" + flag for flag in flags)]


def compiled_sources(output, target, original_source):
    commands = json.loads((output / "build/compile_commands.json").read_text())
    compiled = [c for c in commands if any(
        "CMakeFiles/" + name + ".dir/" in c["output"].replace("\\", "/")
        for name in ("libcurl_static", "libcurl_object"))]
    prefix = original_source.replace("\\", "/") + "/"
    if (not compiled or any(not c["file"].replace("\\", "/").startswith(prefix) for c in compiled)
            or len({c["file"] for c in compiled}) != len(compiled)):
        raise ValueError("Curl compilation inputs are missing, duplicated or outside the pinned source")
    build_ssh.verify_compile_settings(compiled, target)
    if target.startswith("windows") and any(not re.search(
            r"(?:^|\s)[/-]DNGHTTP2_STATICLIB(?:=1)?(?:\s|$)", c["command"]) for c in compiled):
        raise ValueError("Curl must compile against the static nghttp2 interface, not DLL imports")
    return compiled


def inspect(output):
    record = json.loads((output / "native-build-provenance.json").read_text())
    expected = pin()
    if any(record.get(k) != v for k, v in {
            "schema_version": 1, "library": "curl", "version": expected["version"],
            "sourceArchive": expected, "evidence_type": "isolated-source-build-candidate",
            "status": "not-approved-for-production"}.items()):
        raise ValueError("Curl source identity or candidate status changed")
    if (digest(output / "upstream-source.tar.xz") != expected["sha256"]
            or digest(output / "source/COPYING") != expected["licenseSha256"]
            or record["sourceFiles"] != tree_files(output / "source")):
        raise ValueError("Curl source archive, license or source tree changed")
    verify_tar(output / "upstream-source.tar.xz", [
        {**p, "path": "curl-" + expected["version"] + "/" + p["path"]}
        for p in record["sourceFiles"]], directories=True)
    if (set(p["path"] for p in record["recipeFiles"]) != set(RECIPES)
            or record["recipeFiles"] != archive_hashes(
                output / "recipe", [p["path"] for p in record["recipeFiles"]])):
        raise ValueError("Curl original recipe changed")
    target = record["target"]
    before, providers = provider_checks(output, target)
    if (record["providerFiles"] != tree_files(output / "providers")
            or record["brotliHeaderFiles"] != tree_files(output / "brotli/source")):
        raise ValueError("Curl delivered provider inputs changed")
    verify_tar(output / "brotli/upstream-source.tar", record["brotliHeaderFiles"], directories=True)
    if record["brotliSourceCommit"] != providers["Brotli"]["sourceCommit"]:
        raise ValueError("Curl Brotli headers differ from the original provider source pin")
    paths = [p["path"] for p in record["buildFiles"]]
    required = {"configure.log", "build.log", "probe-build.log", "probe.map", "candidate.json",
                "candidate.stderr", "build/CMakeCache.txt", "build/build.ninja",
                "build/compile_commands.json", "build/lib/curl_config.h", record["builtArchive"],
                "probe.exe" if target.startswith("windows") else "probe"}
    if not required.issubset(paths) or record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("Curl original configuration, compiler or runtime outputs changed")
    compiled = compiled_sources(output, target, record["originalSource"])
    proof = object_evidence(output, record["builtArchive"], compiled, record["originalBuild"])
    if compiled != record["compiledSources"] or any(record.get(k) != v for k, v in proof.items()):
        raise ValueError("Curl compiled-object/archive binding changed")
    source_paths = {record["originalSource"] + "/" + p["path"] for p in record["sourceFiles"]}
    if any(c["file"].replace("\\", "/") not in source_paths for c in compiled):
        raise ValueError("Curl compiler input has no acquired source binding")
    expected_inputs, _ = inputs(output, target)
    expected_inputs["libcurl"] = output / record["builtArchive"]
    original_output = record["originalSource"].rsplit("/", 1)[0]
    if (set(record["probeInputs"]) != set(expected_inputs) or any(
            record["probeInputs"][name]["sha256"] != digest(path)
            or record["probeInputs"][name]["path"].replace("\\", "/")
            != original_output + "/" + path.relative_to(output).as_posix()
            for name, path in expected_inputs.items())):
        raise ValueError("Curl selected archives differ from the delivered prerequisite inputs")
    if (record["linkSelections"] != probe_selections(output, target, record["probeInputs"])
            or record["probeInputs"]["libcurl"]["sha256"] != digest(output / record["builtArchive"])):
        raise ValueError("Curl actual linker selection changed")
    installed = output / "install"
    if (record["installFiles"] != tree_files(installed)
            or record["archives"] != archive_hashes(installed, [record["archives"][0]["path"]])
            or digest(installed / record["archives"][0]["path"]) != digest(output / record["builtArchive"])):
        raise ValueError("Curl installed archive/interface changed")
    for header in sorted((output / "source/include/curl").glob("*.h")):
        if digest(header) != digest(installed / "include/curl" / header.name):
            raise ValueError("Curl installed public header differs from the acquired source")
    if digest(installed / "share/licenses/curl/COPYING") != expected["licenseSha256"]:
        raise ValueError("Curl installed license differs from the acquired source")
    difference = compare(json.loads((output / "candidate.json").read_text()), before, target)
    if difference != record["hostDifference"]:
        raise ValueError("Curl recorded host-string difference changed")
    return {"library": "curl", "version": expected["version"], "target": target,
            "objectMembers": verify_architecture(installed / record["archives"][0]["path"], target),
            "hostDifference": difference, "status": record["status"]}


def build(archive, output, target, provider_paths, brotli_source):
    if target.startswith("windows") != (platform.system() == "Windows"):
        raise ValueError("Curl source builds require the native target operating system")
    output = output.resolve()
    expected = pin()
    if output.exists() or digest(archive) != expected["sha256"]:
        raise ValueError("Use a fresh curl output and the exact reviewed release-source archive")
    output.mkdir(parents=True)
    for name, source in provider_paths.items():
        shutil.copytree(source, output / "providers" / name)
    before, provider_records = provider_checks(output, target)
    providers_before = tree_files(output / "providers")
    brotli_commit = provider_records["Brotli"]["sourceCommit"]
    checkout, links = build_http.snapshot(brotli_source, brotli_commit)
    if links:
        raise ValueError("Unexpected Brotli source submodules")
    (output / "brotli").mkdir()
    header_checkout = [p for p in checkout if p["path"] == "LICENSE"
                       or p["path"].startswith("c/include/")]
    _, brotli_files = build_native.stage(
        brotli_source, output / "brotli", brotli_commit, header_checkout, ("c/include", "LICENSE"))
    shutil.copyfile(archive, output / "upstream-source.tar.xz")
    extract(archive, output / "source", expected["version"], "curl")
    sources = tree_files(output / "source")
    if digest(output / "source/COPYING") != expected["licenseSha256"]:
        raise ValueError("Curl acquired license differs from the reviewed release")
    recipes = archive_hashes(ROOT, RECIPES)
    for item in recipes:
        destination = output / "recipe" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], destination)
    archives, headers = inputs(output, target)
    archive_inputs = {name: {"path": str(path), "sha256": digest(path)}
                      for name, path in archives.items()}
    arguments = configure(output, target, archives, headers)
    run(arguments, output / "configure.log")
    tools, compiler_file = toolchain(output, target)
    if not target.startswith("windows"):
        sdk = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
        settings = Path(sdk) / "SDKSettings.json"
        tools["SDKSettings.json"] = {"path": str(settings), "sha256": digest(settings)}
    run(["cmake", "--build", str(output / "build"), "--target", "libcurl_static", "--parallel", "3"],
        output / "build.log")
    compiled = compiled_sources(output, target, (output / "source").as_posix())
    built = "build/lib/libcurl.lib" if target.startswith("windows") else "build/lib/libcurl.a"
    proof = object_evidence(output, built, compiled, output / "build")
    compiler = tools["CMAKE_C_COMPILER"]["path"]
    executable = output / ("probe.exe" if target.startswith("windows") else "probe")
    if target.startswith("windows"):
        probe = [compiler, "/nologo", "/O2", "/MT", "/DCURL_STATICLIB", "/DLIBSSH2_STATIC",
                 "/I" + str(output / "source/include"), "/I" + str(headers["ssh"]),
                 str(ROOT / "build/dependencies/native/curl-info.c"),
                 "/Fo" + str(output / "probe.obj"), "/Fe" + str(executable)]
    else:
        probe = [compiler, "-arch", target.removeprefix("macos-"), "-mmacosx-version-min=10.13",
                 "-isysroot", sdk, "-DCURL_STATICLIB", "-DLIBSSH2_STATIC",
                 "-I" + str(output / "source/include"), "-I" + str(headers["ssh"]),
                 str(ROOT / "build/dependencies/native/curl-info.c")]
    probe += [str(output / built)] + [str(archives[name]) for name in (
        "libssh2", "OpenSSL-ssl", "OpenSSL-crypto", "zlib", "nghttp2", "Brotli-dec", "Brotli-common")]
    if target.startswith("windows"):
        probe += ["/link", "/VERBOSE:LIB", "/MAP:" + str(output / "probe.map"),
                  "ws2_32.lib", "crypt32.lib", "bcrypt.lib", "secur32.lib", "wldap32.lib",
                  "advapi32.lib", "normaliz.lib", "user32.lib", "iphlpapi.lib"]
    else:
        probe += ["-framework", "Security", "-framework", "CoreFoundation",
                  "-framework", "SystemConfiguration", "-Wl,-map," + str(output / "probe.map"),
                  "-o", str(executable)]
    run(probe, output / "probe-build.log")
    with (output / "candidate.json").open("w") as stdout, (
            output / "candidate.stderr").open("w") as stderr:
        subprocess.run([str(executable)], stdout=stdout, stderr=stderr, check=True)
    host_difference = compare(json.loads((output / "candidate.json").read_text()), before, target)
    archive_inputs["libcurl"] = {"path": str(output / built), "sha256": digest(output / built)}
    selection = probe_selections(output, target, archive_inputs)
    if (sources != tree_files(output / "source") or recipes != archive_hashes(ROOT, RECIPES)
            or providers_before != tree_files(output / "providers")
            or brotli_files != tree_files(output / "brotli/source")
            or any(digest(Path(p["path"])) != p["sha256"] for p in archive_inputs.values())
            or any(digest(Path(p["path"])) != p["sha256"] for p in tools.values())):
        raise ValueError("Curl source, recipe, provider or toolchain changed during compilation")
    install = output / "install"
    (install / "lib").mkdir(parents=True)
    name = "libcurl.lib" if target.startswith("windows") else "libcurl.a"
    shutil.copyfile(output / built, install / "lib" / name)
    (install / "include/curl").mkdir(parents=True)
    for header in sorted((output / "source/include/curl").glob("*.h")):
        shutil.copyfile(header, install / "include/curl" / header.name)
    (install / "share/licenses/curl").mkdir(parents=True)
    shutil.copyfile(output / "source/COPYING", install / "share/licenses/curl/COPYING")
    build_paths = [p.relative_to(output).as_posix() for p in (output / "build").rglob("*")
                   if p.is_file() and not p.is_symlink()]
    build_paths += [p.name for p in output.iterdir()
                    if p.is_file() and p.name != "upstream-source.tar.xz"]
    record = {
        "schema_version": 1, "library": "curl", "version": expected["version"], "target": target,
        "sourceArchive": expected, "evidence_type": "isolated-source-build-candidate",
        "status": "not-approved-for-production", "sourceFiles": sources, "recipeFiles": recipes,
        "configure_arguments": arguments, "compiledSources": compiled, **proof,
        "toolchain": tools, "compilerFile": compiler_file, "builtArchive": built,
        "compilerEnvironment": {k: os.environ.get(k) for k in (
            "INCLUDE", "LIB", "WindowsSdkDir", "WindowsSDKVersion", "VCToolsVersion")},
        "originalSource": (output / "source").as_posix(), "originalBuild": (output / "build").as_posix(),
        "providerFiles": providers_before, "brotliHeaderFiles": brotli_files,
        "brotliSourceCommit": brotli_commit, "probeInputs": archive_inputs,
        "probeArguments": probe, "linkSelections": selection, "hostDifference": host_difference,
        "buildFiles": archive_hashes(output, build_paths), "installFiles": tree_files(install),
        "archives": archive_hashes(install, ["lib/" + name]),
        "limitations": [
            "Reconstructed matching configuration, not recovery of historical configure/compiler arguments.",
            "The host string is recorded separately; features, protocols and provider observations must match.",
            "Standalone library APIs only; no transfers, full-plugin loading, relinking or redistribution approval.",
            "Original prerequisite/provider records are preserved; their existing evidence scope is not expanded."],
    }
    write_json(output / "native-build-provenance.json", record)
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("build")
    sub.add_argument("--target", choices=build_native.TARGETS, required=True)
    sub.add_argument("--archive", type=Path, required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub.add_argument("--brotli-source", type=Path, required=True)
    for name in ("ssh", "zlib", "http", "baseline"):
        sub.add_argument("--" + name, type=Path, required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.output) if args.command == "inspect" else build(
        args.archive, args.output, args.target,
        {name: getattr(args, name) for name in ("ssh", "zlib", "http", "baseline")},
        args.brotli_source), indent=2))
