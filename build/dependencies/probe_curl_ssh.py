#!/usr/bin/env python3
"""Compare real loopback SSH transfers, never load the plugin or alter host SSH."""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import probe_curl_transfers as transfers
import ssh_fixture
from build_native import ROOT
from provenance import archive_hashes, digest, write_json


CASES = [
    {"case": scheme + "-" + operation, "scheme": scheme, "operation": operation,
     "path": operation + ".bin", "code": 0}
    for scheme in ("sftp", "scp") for operation in ("download", "upload")
] + [
    {"case": "sftp-host-key-rejected", "scheme": "sftp", "operation": "download",
     "path": "download.bin", "code": 60},
    {"case": "sftp-auth-rejected", "scheme": "sftp", "operation": "download",
     "path": "download.bin", "code": 67},
    {"case": "sftp-missing-file", "scheme": "sftp", "operation": "download",
     "path": "missing.bin", "code": 78},
]
RECIPES = sorted(set(transfers.RECIPES + [
    "build/dependencies/probe_curl_ssh.py", "build/dependencies/ssh_fixture.py",
    "build/dependencies/native/curl-ssh-transfer.c",
    "build/dependencies/ssh-fixture-requirements.txt",
]))


def fixture_runtime():
    lock = (ROOT / "build/dependencies/ssh-fixture-requirements.txt").read_text()
    versions = re.findall(r"^([a-z0-9-]+)==([0-9.]+)", lock, re.MULTILINE)
    if not versions or sys.version_info[:2] != (3, 12):
        raise ValueError("The reviewed SSH fixture wheel set requires Python 3.12")
    packages = []
    for name, version in versions:
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as error:
            raise RuntimeError("Install the hash-locked SSH fixture requirements with the "
                               "active interpreter: " + sys.executable + " (prefix "
                               + sys.prefix + ")") from error
        if distribution.version != version:
            raise ValueError("SSH fixture dependency differs from its reviewed wheel lock: " + name)
        metadata = distribution.read_text("METADATA")
        record = distribution.read_text("RECORD")
        if metadata is None or record is None:
            raise ValueError("SSH fixture dependency metadata or installed file record is absent")
        packages.append({
            "name": name, "version": version,
            "metadataSha256": hashlib.sha256(metadata.encode()).hexdigest(),
            "installedRecordSha256": hashlib.sha256(record.encode()).hexdigest(),
        })
    return {"pythonVersion": platform.python_version(), "packages": packages,
            "scope": "Hash-locked fixture wheels and installed metadata observations only; not plugin inputs."}


def inspect_proof(output):
    record = json.loads((output / "curl-ssh-proof.json").read_text())
    target = record["target"]
    files = [p.relative_to(output).as_posix() for p in output.rglob("*")
             if p.is_file() and p.name != "curl-ssh-proof.json"]
    expected = {"payload.bin", "known_hosts", "wrong_known_hosts", *("recipes/" + p for p in RECIPES)}
    for variant in ("candidate", "baseline"):
        expected.update(variant + "/" + p for p in (
            "compile.log", "transfer.map",
            "curl-ssh-transfer.exe" if target == "windows-x86_64" else "curl-ssh-transfer"))
        if target == "windows-x86_64":
            expected.add(variant + "/curl-ssh-transfer.obj")
        for case in CASES:
            expected.update(variant + "/" + case["case"] + suffix
                            for suffix in (".stdout", ".stderr", ".server.json"))
            if case["operation"] == "upload":
                expected.add(variant + "/" + case["case"] + ".uploaded")
    if (record.get("schemaVersion") != 1
            or record.get("status") != "not-approved-for-production"
            or target not in ("macos-arm64", "macos-x86_64", "windows-x86_64")
            or set(record["results"]) != {"candidate", "baseline"}
            or set(record["compile"]) != {"candidate", "baseline"}
            or expected != set(files)
            or any(p.is_symlink() for p in output.rglob("*"))
            or record["recipeInputs"] != archive_hashes(output / "recipes", RECIPES)
            or record["files"] != archive_hashes(output, files)
            or (output / "payload.bin").read_bytes() != transfers.PAYLOAD):
        raise ValueError("SSH transfer proof source/input/output binding changed")
    versions = re.findall(r"^([a-z0-9-]+)==([0-9.]+)",
                          (output / "recipes/build/dependencies/ssh-fixture-requirements.txt").read_text(),
                          re.MULTILINE)
    if (not versions or not record["fixtureRuntime"]["pythonVersion"].startswith("3.12.")
            or [(p["name"], p["version"]) for p in record["fixtureRuntime"]["packages"]] != versions
            or any(not re.fullmatch(r"[a-f0-9]{64}", p[field])
                   for p in record["fixtureRuntime"]["packages"]
                   for field in ("metadataSha256", "installedRecordSha256"))):
        raise ValueError("SSH fixture runtime differs from its retained lock")
    for variant, results in record["results"].items():
        if [r["case"] for r in results] != [c["case"] for c in CASES]:
            raise ValueError("SSH transfer case set changed")
        for result, case in zip(results, CASES):
            name, code = case["case"], case["code"]
            stdout = (output / variant / (name + ".stdout")).read_bytes()
            body = transfers.PAYLOAD if code == 0 and case["operation"] == "download" else b""
            original_server = json.loads((output / variant / (name + ".server.json")).read_text())
            server = {key: value for key, value in result["server"].items() if key != "uploadSha256"}
            if (stdout != body
                    or json.loads((output / variant / (name + ".stderr")).read_text()) != {"curlCode": code}
                    or result["exitCode"] != code
                    or result["responseSha256"] != hashlib.sha256(body).hexdigest()
                    or result["responseBytes"] != len(body)
                    or server["errors"] or original_server != {"sessions": [server], "fatal": []}
                    or server["case"] != variant + "-" + name):
                raise ValueError("SSH original response or rejection evidence changed")
            authentications = result["server"]["authentications"]
            if name == "sftp-host-key-rejected":
                if authentications or server["requests"]:
                    raise ValueError("SSH host mismatch reached user authentication")
            elif (len(authentications) != 1
                  or authentications[0] != {"username": "fixture",
                                           "accepted": name != "sftp-auth-rejected"}):
                raise ValueError("SSH password acceptance/rejection differs from the fixture")
            requests = server["requests"]
            if name == "sftp-auth-rejected":
                if requests:
                    raise ValueError("Rejected SSH authentication reached file access")
            elif name.startswith("sftp-") and name != "sftp-host-key-rejected":
                expected_request = ["open-write" if case["operation"] == "upload" else "open-read",
                                    "/" + case["path"]]
                if expected_request not in requests:
                    raise ValueError("SSH fixture did not observe the expected SFTP request")
            elif name.startswith("scp-"):
                download = case["operation"] == "download"
                allowed = ([["scp", "-f"]], [["scp", "-pf"]]) if download else ([["scp", "-t"]],)
                if requests not in allowed:
                    raise ValueError("SSH fixture did not observe the expected SCP request")
                field, values = (("downloadFinalAck", ("acknowledged", "peer-closed")) if download
                                 else ("uploadTerminator", ("nul", "peer-eof")))
                if server.get(field) not in values:
                    raise ValueError("SSH fixture omitted its SCP protocol-closure observation")
            if case["operation"] == "upload":
                data = (output / variant / (name + ".uploaded")).read_bytes()
                if (data != transfers.PAYLOAD
                        or result["server"]["uploadSha256"] != hashlib.sha256(data).hexdigest()):
                    raise ValueError("SSH original server-received upload bytes changed")
    return record


def bind_plugin_selection(output, link_path):
    record = inspect_proof(output)
    link = json.loads(link_path.read_text())
    if (link["target"] != record["target"]
            or not re.fullmatch(r"[a-f0-9]{64}", link.get("binarySha256", ""))):
        raise ValueError("SSH archive binding requires the actual matching plugin link")
    path_type = PureWindowsPath if record["target"] == "windows-x86_64" else PurePosixPath
    root = path_type(record["project"])
    inputs = []
    for archive in record["compile"]["candidate"]["archives"]:
        relative = path_type(archive["path"]).relative_to(root).as_posix()
        matches = [row for row in link["selectedArchives"]
                   if row.get("scope") == "repository"
                   and path_type(row["candidatePath"]) == path_type(relative)
                   and row["sha256"] == archive["sha256"]]
        if len(matches) != 1:
            raise ValueError("SSH probe archive does not match an actual plugin selection: " + relative)
        inputs.append({"path": relative, "sha256": archive["sha256"]})
    if not inputs or len({path_type(item["path"]) for item in inputs}) != len(inputs):
        raise ValueError("SSH probe archive binding is empty or duplicated")
    return {"target": record["target"], "proofSha256": digest(output / "curl-ssh-proof.json"),
            "linkSha256": digest(link_path), "binarySha256": link["binarySha256"],
            "inputs": inputs}


def probe(project, baseline, target, output):
    if (output.exists() or project == baseline or output.is_relative_to(project)
            or output.is_relative_to(baseline)
            or platform.system() != ("Windows" if target.startswith("windows") else "Darwin")):
        raise ValueError("Use fresh SSH output on the matching native operating system")
    runtime = fixture_runtime()
    recipes = archive_hashes(ROOT, RECIPES)
    output.mkdir(parents=True)
    for item in recipes:
        destination = output / "recipes" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], destination)
    (output / "payload.bin").write_bytes(transfers.PAYLOAD)
    models, results = {}, {}
    with ssh_fixture.serve(transfers.PAYLOAD) as fixture:
        for name, public_key in (("known_hosts", fixture.public_key),
                                 ("wrong_known_hosts", fixture.wrong_public_key)):
            (output / name).write_text("[127.0.0.1]:" + str(fixture.port) + " " + public_key + "\n")
        for variant, root in (("candidate", project), ("baseline", baseline)):
            folder = output / variant
            binary, models[variant] = transfers.build_probe(
                root, folder, target, project, ROOT / "build/dependencies/native/curl-ssh-transfer.c")
            results[variant] = []
            for case in CASES:
                name = case["case"]
                session = variant + "-" + name
                fixture.begin(session)
                known = output / ("wrong_known_hosts" if name == "sftp-host-key-rejected" else "known_hosts")
                password = "wrong-fixture-password" if name == "sftp-auth-rejected" else "loopback-fixture"
                url = case["scheme"] + "://127.0.0.1:" + str(fixture.port) + "/" + case["path"]
                command = [str(binary), url, str(known), "fixture", password,
                           case["operation"], str(output / "payload.bin")]
                if target.startswith("macos"):
                    command = ["arch", "-" + target.removeprefix("macos-"), *command]
                completed = subprocess.run(command, capture_output=True, timeout=25)
                (folder / (name + ".stdout")).write_bytes(completed.stdout)
                (folder / (name + ".stderr")).write_bytes(completed.stderr)
                write_json(folder / (name + ".server.json"), fixture.diagnostics(session))
                expected_body = (transfers.PAYLOAD
                                 if case["code"] == 0 and case["operation"] == "download" else b"")
                if (completed.returncode != case["code"]
                        or completed.stdout != expected_body
                        or json.loads(completed.stderr) != {"curlCode": case["code"]}):
                    raise ValueError("Actual SSH transfer or authentication expectation failed: " + session)
                server = fixture.inspect(session, case["scheme"] if case["operation"] == "upload" else None)
                if case["operation"] == "upload":
                    (folder / (name + ".uploaded")).write_bytes(fixture.uploaded(session, case["scheme"]))
                results[variant].append({
                    "case": name, "command": command, "exitCode": completed.returncode,
                    "responseSha256": hashlib.sha256(completed.stdout).hexdigest(),
                    "responseBytes": len(completed.stdout), "server": server,
                })
            transfers.verify_inputs(root, models[variant])
    if runtime != fixture_runtime() or recipes != archive_hashes(ROOT, RECIPES):
        raise ValueError("SSH fixture runtime or recipe inputs changed during transfer checks")
    write_json(output / "curl-ssh-proof.json", {
        "schemaVersion": 1, "status": "not-approved-for-production", "target": target,
        "project": str(project),
        "fixtureRuntime": runtime, "recipeInputs": recipes, "compile": models, "results": results,
        "files": archive_hashes(output, [
            p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()]),
        "scope": "Loopback SFTP/SCP uploads/downloads and host-key/password/missing-file rejection; exact frozen non-provider comparison with shared source providers. No plugin/4D initialization or host SSH changes.",
    })
    return inspect_proof(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--target", choices=("macos-arm64", "macos-x86_64", "windows-x86_64"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    if not args.inspect_only and (not args.project or not args.baseline or not args.target):
        parser.error("A native run requires --project, --baseline and --target")
    result = (inspect_proof(args.output.resolve()) if args.inspect_only else probe(
        args.project.resolve(), args.baseline.resolve(), args.target, args.output.resolve()))
    print(json.dumps({"target": result["target"],
                      "casesPerVariant": len(result["results"]["candidate"])}, indent=2))
