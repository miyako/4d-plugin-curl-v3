#!/usr/bin/env python3
"""Compare standalone loopback HTTP/2 transfers without initializing the plugin."""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
from build_native import ROOT, probe_selections
from build_curl import pin as curl_pin
import http2_fixture
import probe_curl_transfers as transfers
import plugin_relink_delivery
from provenance import archive_hashes, digest, write_json

PAYLOAD = bytes(range(256)) * 1027
CASES = [
    {"case": "h2c-get", "version": "h2c", "upload": False, "encoding": ""},
    {"case": "h2c-post", "version": "h2c", "upload": True, "encoding": ""},
    {"case": "h2-tls12-get", "version": "1.2", "upload": False, "encoding": ""},
    {"case": "h2-tls13-post", "version": "1.3", "upload": True, "encoding": ""},
    {"case": "h2-tls13-gzip", "version": "1.3", "upload": False, "encoding": "gzip"},
]
RECIPES = sorted(set(transfers.RECIPES + [
    "build/dependencies/probe_curl_http2.py", "build/dependencies/http2_fixture.py",
    "build/dependencies/http2-fixture-requirements.txt",
    "build/dependencies/native-sources.json",
    "build/dependencies/native/curl-http2-transfer.c"]))


def copy_public_interface(archive, output):
    pin = curl_pin()
    if digest(archive) != pin["sha256"]:
        raise ValueError("Curl public interface archive differs from the original source pin")
    root = "curl-" + pin["version"] + "/"
    copied = []
    with tarfile.open(archive, "r:*") as source:
        for item in source.getmembers():
            path = item.name.removeprefix(root)
            if not item.name.startswith(root) or not (
                    path == "COPYING" or (len(PurePosixPath(path).parts) == 3
                                         and path.startswith("include/curl/") and path.endswith(".h"))):
                continue
            if not item.isfile() or item.size > 2 * 1024 * 1024 or path in copied:
                raise ValueError("Invalid or repeated pinned curl public interface member")
            destination = output / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(item) as stream:
                destination.write_bytes(stream.read())
            copied.append(path)
    if ("COPYING" not in copied or len(copied) < 2
            or digest(output / "COPYING") != pin["licenseSha256"]
            or digest(archive) != pin["sha256"]):
        raise ValueError("Pinned curl public interface or applicable license is incomplete")
    return pin


def fixture_runtime():
    lock = (ROOT / "build/dependencies/http2-fixture-requirements.txt").read_text()
    packages = []
    for name, version in re.findall(r"^([a-z0-9-]+)==([0-9.]+)", lock, re.MULTILINE):
        distribution = importlib.metadata.distribution(name)
        if distribution.version != version:
            raise ValueError("HTTP/2 fixture differs from its hash lock: " + name)
        metadata = distribution.read_text("METADATA")
        installed = distribution.read_text("RECORD")
        if metadata is None or installed is None:
            raise ValueError("HTTP/2 fixture package lacks original installed metadata")
        packages.append({"name": name, "version": version,
                         "metadataSha256": hashlib.sha256(metadata.encode()).hexdigest(),
                         "installedRecordSha256": hashlib.sha256(installed.encode()).hexdigest()})
    if len(packages) != 3:
        raise ValueError("Expected the three reviewed HTTP/2 fixture packages")
    return {"pythonVersion": platform.python_version(), "packages": packages,
            "scope": "Development-only fixture wheels; not plugin components or incorporated code."}


def inspect_proof(output):
    record = json.loads((output / "curl-http2-proof.json").read_text())
    target = record["target"]
    expected = {"payload.bin", "localhost.crt", "interfaces/COPYING.curl",
                *("recipes/" + p for p in RECIPES)}
    for variant in ("candidate", "baseline"):
        expected.update("interfaces/" + variant + "/" + p["path"]
                        for p in record["compile"][variant]["interface"])
        expected.update(variant + "/" + p for p in (
            "compile.log", "transfer.map",
            "curl-http2-transfer.exe" if target.startswith("windows") else "curl-http2-transfer"))
        if target.startswith("windows"):
            expected.add(variant + "/curl-http2-transfer.obj")
        for case in CASES:
            expected.update(variant + "/" + case["case"] + suffix
                            for suffix in (".stdout", ".stderr", ".server.json", ".uploaded"))
    paths = [p.relative_to(output).as_posix() for p in output.rglob("*")
             if p.is_file() and p.name != "curl-http2-proof.json"]
    if (record.get("schemaVersion") != 1
            or record.get("status") != "not-approved-for-production"
            or target not in ("macos-arm64", "macos-x86_64", "windows-x86_64")
            or set(record["results"]) != {"candidate", "baseline"}
            or set(record["compile"]) != {"candidate", "baseline"}
            or set(paths) != expected or any(p.is_symlink() for p in output.rglob("*"))
            or record["files"] != archive_hashes(output, paths)
            or record["recipeInputs"] != archive_hashes(output / "recipes", RECIPES)
            or (output / "payload.bin").read_bytes() != PAYLOAD):
        raise ValueError("HTTP/2 proof has missing/changed files, recipes or target bindings")
    source_pin = next(p for p in json.loads(
        (output / "recipes/build/dependencies/native-sources.json").read_text())["sourceArchives"]
                      if p["library"] == "curl")
    if (record["curlPublicInterfaceSource"] != source_pin
            or digest(output / "interfaces/COPYING.curl") != source_pin["licenseSha256"]):
        raise ValueError("Retained pinned curl public interface or applicable license binding changed")
    lock = (output / "recipes/build/dependencies/http2-fixture-requirements.txt").read_text()
    versions = re.findall(r"^([a-z0-9-]+)==([0-9.]+)", lock, re.MULTILINE)
    if [(p["name"], p["version"]) for p in record["fixtureRuntime"]["packages"]] != versions:
        raise ValueError("Observed HTTP/2 fixture runtime differs from its retained hash lock")
    for variant in ("candidate", "baseline"):
        interface = record["compile"][variant]["interface"]
        if (not interface or any(not p["path"].startswith("include/curl/")
                                 or not p["path"].endswith(".h") for p in interface)
                or interface != archive_hashes(output / "interfaces" / variant,
                                               [p["path"] for p in interface])):
            raise ValueError("Original HTTP/2 compiler public interface bytes changed")
        if len(record["results"][variant]) != len(CASES):
            raise ValueError("Missing or repeated HTTP/2 test cases")
        paths = [p for p in record["compile"][variant]["archives"]
                 if PureWindowsPath(p["path"]).name.lower() in ("libnghttp2.a", "nghttp2.lib")]
        if (len(paths) != 1 or record["nghttp2Selections"][variant] != probe_selections(
                output / variant, target, {"nghttp2": paths[0]}, map_name="transfer.map",
                log_name="compile.log")):
            raise ValueError("Actual HTTP/2 probe did not select its recorded nghttp2 archive")
        for expected_case, result in zip(CASES, record["results"][variant]):
            name = expected_case["case"]
            folder = output / variant
            server = json.loads((folder / (name + ".server.json")).read_text())
            actual_metadata = json.loads((folder / (name + ".stderr")).read_text())
            uploaded = (folder / (name + ".uploaded")).read_bytes()
            wanted_upload = PAYLOAD if expected_case["upload"] else b""
            requests = server["requests"]
            if (result["case"] != name or result["exitCode"] != 0
                    or result["metadata"] != {"curlCode": 0, "httpStatus": 200, "httpVersion": 3}
                    or actual_metadata != result["metadata"] or server != result["server"]
                    or (folder / (name + ".stdout")).read_bytes() != PAYLOAD
                    or uploaded != wanted_upload or server["uploadBytes"] != len(uploaded)
                    or server["uploadSha256"] != hashlib.sha256(uploaded).hexdigest()
                    or server["responseBytes"] != len(PAYLOAD)
                    or server["responseSha256"] != hashlib.sha256(PAYLOAD).hexdigest()
                    or len(requests) != 1 or requests[0]["stream"] != 1
                    or dict(requests[0]["headers"]).get(":method")
                    != ("POST" if expected_case["upload"] else "GET")
                    or dict(requests[0]["headers"]).get(":path") != "/fixture"
                    or (expected_case["encoding"] and dict(requests[0]["headers"]).get(
                        "accept-encoding") != expected_case["encoding"])
                    or server["contentEncoding"] != (expected_case["encoding"] or None)
                    or server["alpn"] != (None if expected_case["version"] == "h2c" else "h2")
                    or server["tlsProtocol"] != {
                        "h2c": None, "1.2": "TLSv1.2", "1.3": "TLSv1.3"}[expected_case["version"]]
                    or server["completion"] not in ("peer-eof", "goaway-no-error")
                    or server["dataFramesSent"] < (1 if expected_case["encoding"] else 2)):
                raise ValueError("Actual HTTP/2 transfer/server evidence failed: " + variant + "/" + name)
    return record


def bind_plugin(kit, output):
    proof = inspect_proof(output)
    binding = plugin_relink_delivery.bind_probe_inputs(
        kit, proof["target"], proof["project"], proof["compile"]["candidate"]["archives"])
    return {**binding, "proofSha256": digest(output / "curl-http2-proof.json"),
            "scope": "Probe archive inputs bound to actual selected plugin archive positions; "
                     "not a claim that every input contributes live code to this probe."}


def probe(project, baseline, target, output, openssl, source_archive):
    if (output.exists() or project == baseline
            or any(output.is_relative_to(p) or p.is_relative_to(output) for p in (project, baseline))
            or platform.system() != ("Windows" if target.startswith("windows") else "Darwin")):
        raise ValueError("Use fresh external HTTP/2 evidence output on its native OS")
    runtime = fixture_runtime()
    recipes = archive_hashes(ROOT, RECIPES)
    tool = {"path": str(openssl), "sha256": digest(openssl)}
    source_pin = copy_public_interface(source_archive, output / "interfaces/candidate")
    (output / "interfaces/candidate/COPYING").rename(output / "interfaces/COPYING.curl")
    destination = output / "interfaces/baseline/include/curl"
    destination.mkdir(parents=True)
    for path in (baseline / "include/curl").glob("*.h"):
        shutil.copyfile(path, destination / path.name)
    compiled = {name: transfers.build_probe(
        root, output / name, target, project, ROOT / "build/dependencies/native/curl-http2-transfer.c",
        output / "interfaces" / name)
        for name, root in (("candidate", project), ("baseline", baseline))}
    (output / "payload.bin").write_bytes(PAYLOAD)
    results = {}
    with tempfile.TemporaryDirectory(prefix="curl-h2-tls-") as directory:
        temporary = Path(directory)
        config = temporary / "openssl.cnf"
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
            "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n"
            "basicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment\n")
        command = [str(openssl), "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                   "-sha256", "-days", "1", "-config", str(config),
                   "-keyout", str(temporary / "localhost.key"),
                   "-out", str(temporary / "localhost.crt")]
        subprocess.run(command, capture_output=True, check=True, timeout=30)
        shutil.copyfile(temporary / "localhost.crt", output / "localhost.crt")
        for variant, (binary, _) in compiled.items():
            cases = []
            for case in CASES:
                context = None
                if case["version"] != "h2c":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    version = ssl.TLSVersion.TLSv1_2 if case["version"] == "1.2" else ssl.TLSVersion.TLSv1_3
                    context.minimum_version = context.maximum_version = version
                    context.set_alpn_protocols(["h2"])
                    context.load_cert_chain(temporary / "localhost.crt", temporary / "localhost.key")
                with http2_fixture.serve(PAYLOAD, context=context,
                                         compressed=bool(case["encoding"])) as (port, server):
                    url = ("https://localhost:" if context else "http://127.0.0.1:") + str(port) + "/fixture"
                    command = [str(binary), url, str(output / "localhost.crt") if context else "-",
                               case["version"], str(output / "payload.bin") if case["upload"] else "-",
                               case["encoding"]]
                    if target.startswith("macos"):
                        command = ["arch", "-" + target.removeprefix("macos-"), *command]
                    completed = subprocess.run(command, capture_output=True, timeout=25)
                    folder, name = output / variant, case["case"]
                    (folder / (name + ".stdout")).write_bytes(completed.stdout)
                    (folder / (name + ".stderr")).write_bytes(completed.stderr)
                uploaded = server.pop("uploaded")
                (folder / (name + ".uploaded")).write_bytes(uploaded)
                write_json(folder / (name + ".server.json"), server)
                if completed.returncode != 0:
                    raise ValueError("Native HTTP/2 client failed; retained output: " + variant + "/" + name)
                cases.append({"case": name, "command": command, "exitCode": completed.returncode,
                              "metadata": json.loads(completed.stderr), "server": server})
            results[variant] = cases
    for variant, (_, model) in compiled.items():
        transfers.verify_inputs(project if variant == "candidate" else baseline, model)
    if recipes != archive_hashes(ROOT, RECIPES) or digest(openssl) != tool["sha256"]:
        raise ValueError("HTTP/2 fixture recipes, compiler inputs or certificate tool changed")
    for item in recipes:
        destination = output / "recipes" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], destination)
    proof = {"schemaVersion": 1, "target": target, "status": "not-approved-for-production",
             "project": str(project),
             "compile": {name: model for name, (_, model) in compiled.items()}, "results": results,
             "recipeInputs": recipes, "fixtureRuntime": runtime, "certificateTool": tool,
             "curlPublicInterfaceSource": source_pin,
             "serverTLS": ssl.OPENSSL_VERSION,
             "nghttp2Selections": {name: probe_selections(
                 output / name, target, {"nghttp2": next(
                     p for p in model["archives"] if PureWindowsPath(p["path"]).name.lower()
                     in ("libnghttp2.a", "nghttp2.lib"))},
                 map_name="transfer.map", log_name="compile.log")
                 for name, (_, model) in compiled.items()},
             "files": archive_hashes(output, [p.relative_to(output).as_posix()
                                              for p in output.rglob("*") if p.is_file()]),
             "scope": "Actual loopback HTTP/2 HPACK, h2c prior knowledge, authenticated OpenSSL "
                      "TLS1.2/1.3 ALPN h2, bounded GET/POST flow control and gzip. "
                      "Frozen non-provider libraries share current source-matched TLS/Brotli providers. "
                      "Fixture wheels/certificate tool are not plugin components; no application load, "
                      "PAC integration, host, older-system runtime or release authorization."}
    write_json(output / "curl-http2-proof.json", proof)
    return inspect_proof(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project", "baseline", "output", "source-archive"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--target", choices=("macos-arm64", "macos-x86_64", "windows-x86_64"), required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.project.resolve(), args.baseline.resolve(), args.target,
                   args.output.resolve(), args.openssl.resolve(), args.source_archive.resolve())
    print(json.dumps({"target": result["target"], "cases": len(CASES) * 2}, indent=2))
