#!/usr/bin/env python3
"""Observe exact baseline curl archives with rebuilt matching TLS/Brotli providers."""

import argparse
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "sbom"))
from provenance import archive_hashes, digest, read_record, write_json

RECIPES = ["build/dependencies/observe_curl.py", "build/dependencies/native/curl-info.c",
           "build/dependencies/baseline-v4.9.10.json", "build/sbom/provenance.py"]


def baseline(target):
    frozen = json.loads((HERE / "baseline-v4.9.10.json").read_text())
    return next(t for t in frozen["targets"] if t["id"] == target)["selectedArchives"]


def validate_observations(info, selected):
    versions = {a["name"]: a["version"] for a in selected if "version" in a}
    if (info["version"] != versions["curl"] or info["libzVersion"] != versions["zlib"]
            or info["brotliVersion"] not in (versions["Brotli"], "brotli/" + versions["Brotli"])
            or info["libsshVersion"] != "libssh2/" + versions["libssh2"]
            or info["nghttp2Version"] != versions["nghttp2"]
            or not re.fullmatch(r"OpenSSL/" + re.escape(versions["OpenSSL"]), info["sslVersion"])
            or not isinstance(info["featuresMask"], int)
            or not info["features"] or not info["protocols"]
            or len(set(info["features"])) != len(info["features"])
            or len(set(info["protocols"])) != len(info["protocols"])):
        raise ValueError("Curl runtime observations do not match the frozen versions/interface: "
                         + json.dumps(info, sort_keys=True))


def baseline_inputs(selected, target):
    names = ("curl", "libssh2", "nghttp2", "zlib")
    if not target.startswith("windows"):
        names += ("nghttp3",)
    return [next(a for a in selected if a["name"] == name) for name in names]


def inspect(output):
    record = json.loads((output / "curl-baseline-observation.json").read_text())
    selected = baseline(record["target"])
    expected = [{"path": a["path"], "sha256": a["sha256"]}
                for a in baseline_inputs(selected, record["target"])]
    if (record["evidenceType"] != "exact-baseline-curl-runtime-with-rebuilt-matching-providers"
            or record["baselineArchiveInputs"] != expected):
        raise ValueError("Curl probe did not bind the exact selected baseline inputs")
    required = {"build.log", "runtime.json", "runtime.stderr", "curl-probe.map",
                "openssl-build-provenance.json", "brotli-provenance.json"}
    required.add("curl-probe.exe" if record["target"].startswith("windows") else "curl-probe")
    paths = [a["path"] for a in record["buildFiles"]]
    if not required.issubset(paths) or record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("Curl observation outputs/original logs changed")
    info = json.loads((output / "runtime.json").read_text())
    validate_observations(info, selected)
    if info != record["observations"]:
        raise ValueError("Stored curl observations differ from the original output")
    if (set(a["path"] for a in record["recipeFiles"]) != set(RECIPES)
            or record["recipeFiles"] != archive_hashes(
                output / "recipe", [a["path"] for a in record["recipeFiles"]])
            or record["interfaceFiles"] != archive_hashes(
                output / "interface", [a["path"] for a in record["interfaceFiles"]])
            or record["probeSourceSha256"] != digest(
                output / "recipe/build/dependencies/native/curl-info.c")):
        raise ValueError("Curl probe source/interface/recipes differ from the original inputs")
    for name in ("OpenSSL", "Brotli"):
        old = next(a for a in selected if a["name"] == name)
        provider = record["rebuiltProviders"][name]
        filename = "openssl-build-provenance.json" if name == "OpenSSL" else "brotli-provenance.json"
        if (provider.get("source_commit", provider.get("sourceCommit")) != old["sourceCommit"]
                or provider["version"] != old["version"]
                or json.loads((output / filename).read_text()) != provider):
            raise ValueError("Rebuilt curl provider differs from the frozen source version")
        installed = output / "rebuilt-providers" / name
        if provider["archives"] != archive_hashes(installed, [a["path"] for a in provider["archives"]]):
            raise ValueError("Delivered rebuilt provider archive differs from its original record")
        if name == "OpenSSL" and read_record(installed / filename) != provider:
            raise ValueError("Original rebuilt OpenSSL record changed")
    return {"target": record["target"], "observations": info, "scope": record["limitations"]}


def observe(target, output, openssl_install, brotli_vendor):
    output = output.resolve()
    if output.exists():
        raise ValueError("Use a fresh curl observation directory")
    if target.startswith("windows") != (platform.system() == "Windows"):
        raise ValueError("Curl observation requires the target operating system")
    selected = baseline(target)
    windows = target.startswith("windows")
    inputs = baseline_inputs(selected, target)
    if any(digest(ROOT / a["path"]) != a["sha256"] for a in inputs):
        raise ValueError("Exact selected curl/dependency baseline input has changed")
    openssl = read_record(openssl_install / "openssl-build-provenance.json")
    brotli_record = brotli_vendor / "brotli-provenance.json"
    brotli = json.loads(brotli_record.read_text())
    if openssl["target"] != target:
        raise ValueError("Rebuilt OpenSSL target differs from the curl probe")
    if brotli["archives"] != archive_hashes(brotli_vendor, [a["path"] for a in brotli["archives"]]):
        raise ValueError("Brotli archive bytes differ from their original build record")
    for name, provider in (("OpenSSL", openssl), ("Brotli", brotli)):
        old = next(a for a in selected if a["name"] == name)
        if (provider.get("source_commit", provider.get("sourceCommit")) != old["sourceCommit"]
                or provider["version"] != old["version"]):
            raise ValueError("Rebuilt provider source/version does not match the frozen baseline")
    output.mkdir(parents=True)
    recipes = archive_hashes(ROOT, RECIPES)
    for item in recipes:
        path = output / "recipe" / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], path)
    for source in (openssl_install / "openssl-build-provenance.json", brotli_record):
        shutil.copyfile(source, output / source.name)
    for name, provider, root, filename in (
            ("OpenSSL", openssl, openssl_install, "openssl-build-provenance.json"),
            ("Brotli", brotli, brotli_vendor, "brotli-provenance.json")):
        installed = output / "rebuilt-providers" / name
        for item in provider["archives"] + [{"path": filename}]:
            path = installed / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / item["path"], path)
    executable = output / ("curl-probe.exe" if windows else "curl-probe")
    source = HERE / "native/curl-info.c"
    headers = sorted((ROOT / "include/curl").glob("*.h"))
    interface = archive_hashes(ROOT, [p.relative_to(ROOT).as_posix() for p in headers])
    for item in interface:
        path = output / "interface" / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], path)
    source_before = digest(source)
    ssl = [openssl_install / a["path"] for a in openssl["archives"]]
    ssl.sort(key=lambda p: 0 if p.name in ("libssl.a", "libssl.lib") else 1)
    bro = [brotli_vendor / a["path"] for a in brotli["archives"]
           if "dec" in a["path"] or "common" in a["path"]]
    bro.sort(key=lambda p: 0 if "dec" in p.name else 1)
    paths = [ROOT / a["path"] for a in inputs[:2]] + ssl
    paths += [ROOT / a["path"] for a in inputs[2:]] + bro
    if windows:
        compiler = shutil.which("cl")
        if not compiler:
            raise ValueError("Run curl probing in the native MSVC developer environment")
        arguments = [compiler, "/nologo", "/O2", "/MT", "/DCURL_STATICLIB",
                     "/I" + str(ROOT / "include"), str(source),
                     "/Fo" + str(output / "curl-info.obj"), "/Fe" + str(executable)]
        arguments += [str(p) for p in paths]
        arguments += ["/link", "/MAP:" + str(output / "curl-probe.map"),
                      "ws2_32.lib", "crypt32.lib", "bcrypt.lib", "secur32.lib",
                      "wldap32.lib", "advapi32.lib", "normaliz.lib"]
    else:
        compiler = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
        sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
        arguments = [compiler, "-arch", target.removeprefix("macos-"),
                     "-isysroot", sdk,
                     "-mmacosx-version-min=10.13", "-DCURL_STATICLIB",
                     "-I" + str(ROOT / "include"), str(source)]
        arguments += [str(p) for p in paths]
        arguments += ["-framework", "Security", "-framework", "CoreFoundation",
                      "-framework", "SystemConfiguration", "-framework", "GSS",
                      "-framework", "LDAP", "-lresolv", "-liconv",
                      "-Wl,-map," + str(output / "curl-probe.map"), "-o", str(executable)]
    with (output / "build.log").open("w") as stream:
        result = subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        sys.stderr.write((output / "build.log").read_text())
        raise subprocess.CalledProcessError(result.returncode, arguments)
    with (output / "runtime.json").open("w") as stdout, (output / "runtime.stderr").open("w") as stderr:
        subprocess.run([str(executable)], stdout=stdout, stderr=stderr, check=True)
    info = json.loads((output / "runtime.json").read_text())
    validate_observations(info, selected)
    if (source_before != digest(source) or interface != archive_hashes(
            ROOT, [a["path"] for a in interface])
            or any(digest(ROOT / a["path"]) != a["sha256"] for a in inputs)
            or read_record(openssl_install / "openssl-build-provenance.json") != openssl
            or brotli["archives"] != archive_hashes(brotli_vendor, [a["path"] for a in brotli["archives"]])
            or recipes != archive_hashes(ROOT, RECIPES)):
        raise ValueError("Curl probe source/interface/provider inputs changed during observation")
    record = {
        "schemaVersion": 1, "target": target,
        "evidenceType": "exact-baseline-curl-runtime-with-rebuilt-matching-providers",
        "baselineArchiveInputs": [{"path": a["path"], "sha256": a["sha256"]} for a in inputs],
        "rebuiltProviders": {"OpenSSL": openssl, "Brotli": brotli},
        "interfaceFiles": interface, "probeSourceSha256": source_before, "recipeFiles": recipes,
        "compiler": {"path": compiler, "sha256": digest(Path(compiler))},
        "compileArguments": arguments, "observations": info,
        "buildFiles": archive_hashes(output, ["build.log", "runtime.json", "runtime.stderr",
            "curl-probe.map", executable.name, "openssl-build-provenance.json", "brotli-provenance.json"]),
        "limitations": [
            "Exact historical curl and selected non-provider archive hashes, not execution of the old plugin.",
            "OpenSSL/Brotli use matching pinned source versions rebuilt now, not original release archive bytes.",
            "This recovers enabled runtime features/protocols, not the historical configure command or every compiler option.",
            "The 4D application is never loaded or initialized by this probe; no network transfers are performed.",
        ],
    }
    write_json(output / "curl-baseline-observation.json", record)
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("observe")
    sub.add_argument("--target", choices=("macos-arm64", "macos-x86_64", "windows-x86_64"), required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub.add_argument("--openssl-install", type=Path, required=True)
    sub.add_argument("--brotli-vendor", type=Path, required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("output", type=Path)
    args = parser.parse_args()
    result = (inspect(args.output) if args.command == "inspect" else
              observe(args.target, args.output, args.openssl_install, args.brotli_vendor))
    print(json.dumps(result, indent=2))
