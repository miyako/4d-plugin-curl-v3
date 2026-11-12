#!/usr/bin/env python3
"""Receipt-backed standalone TLS checks; never load the plugin or a 4D host."""

import argparse
import json
from pathlib import Path
import platform
import shutil
import subprocess

from build_native import ROOT
import provenance


def validate_results(lines):
    if len(lines) != 6:
        raise ValueError("TLS probe did not report all six independent cases")
    for index, version in enumerate(("TLSv1.2", "TLSv1.3")):
        positive, hostname, untrusted = lines[index * 3:index * 3 + 3]
        if (not positive.startswith(version + " ")
                or not positive.endswith(" verified-hostname authenticated-data")
                or hostname != version + " rejected-hostname verify=62"
                or untrusted != version + " rejected-untrusted verify=18"):
            raise ValueError("TLS authentication, hostname or trust rejection differs")


def inspect_proof(install, output):
    record_path = install / provenance.RECORD
    record = provenance.read_record(record_path)
    receipt = json.loads((output / "tls-proof.json").read_text())
    binary = output / ("tls-probe.exe" if record["target"] == "windows-x86_64" else "tls-probe")
    if (receipt["schemaVersion"] != 1 or receipt["target"] != record["target"]
            or receipt["providerRecordSha256"] != provenance.digest(record_path)
            or receipt["providerInputs"] != provenance.archive_hashes(
                install, [p["path"] for p in receipt["providerInputs"]])
            or receipt["recipeInputs"] != provenance.archive_hashes(
                output / "recipes", [p["path"] for p in receipt["recipeInputs"]])
            or receipt["files"] != provenance.archive_hashes(
                output, [p["path"] for p in receipt["files"]])
            or receipt["binarySha256"] != provenance.digest(binary)
            or receipt["results"] != (output / "stdout.txt").read_text().splitlines()):
        raise ValueError("Persisted TLS proof differs from its original provider or executed inputs")
    validate_results(receipt["results"])
    return receipt


def probe(install, output):
    install, output = install.resolve(), output.resolve()
    record_path = install / provenance.RECORD
    record = provenance.read_record(record_path)
    target = record["target"]
    windows = target == "windows-x86_64"
    if output.exists() or platform.system() != ("Windows" if windows else "Darwin"):
        raise ValueError("Use fresh output on the matching native platform")
    output.mkdir(parents=True)
    compiler = shutil.which("cl") if windows else "/usr/bin/cc"
    if not compiler:
        raise FileNotFoundError("Native TLS probe compiler is unavailable")
    source = ROOT / "build/dependencies/native/provider-tls-probe.c"
    binary = output / ("tls-probe.exe" if windows else "tls-probe")
    archives = [install / name for name in reversed(provenance.expected_archives(target))]
    inputs = provenance.archive_hashes(install, [
        provenance.RECORD, *provenance.expected_archives(target),
        *[p.relative_to(install).as_posix() for p in (install / "include").rglob("*.h")]])
    recipes = ["LICENSE", "build/dependencies/probe_provider_tls.py",
               "build/dependencies/native/provider-tls-probe.c"]
    recipe_hashes = provenance.archive_hashes(ROOT, recipes)
    compiler_sha = provenance.digest(Path(compiler))
    if windows:
        command = [compiler, "/nologo", "/W4", "/MT", "/O2",
                   "/I" + str(install / "include"), str(source),
                   "/Fo" + str(output / "tls-probe.obj"), "/Fe" + str(binary),
                   *map(str, archives), "ws2_32.lib", "crypt32.lib", "bcrypt.lib",
                   "user32.lib", "advapi32.lib"]
        invocation = [str(binary)]
    else:
        arch = target.removeprefix("macos-")
        command = [compiler, "-arch", arch, "-mmacosx-version-min=10.13",
                   "-Wall", "-Wextra", "-I" + str(install / "include"), str(source),
                   *map(str, archives), "-o", str(binary)]
        invocation = ["arch", "-" + arch, str(binary)]
    with (output / "compile.log").open("w") as stream:
        subprocess.run(command, cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True)
    result = subprocess.run(invocation, cwd=output, text=True, capture_output=True)
    (output / "stdout.txt").write_text(result.stdout)
    (output / "stderr.txt").write_text(result.stderr)
    result.check_returncode()
    lines = result.stdout.splitlines()
    validate_results(lines)
    if (inputs != provenance.archive_hashes(install, [p["path"] for p in inputs])
            or recipe_hashes != provenance.archive_hashes(ROOT, recipes)
            or compiler_sha != provenance.digest(Path(compiler))):
        raise ValueError("TLS probe inputs changed during execution")
    for item in recipe_hashes:
        destination = output / "recipes" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], destination)
    if recipe_hashes != provenance.archive_hashes(output / "recipes", recipes):
        raise ValueError("Delivered TLS probe recipes differ from executed inputs")
    receipt = {
        "schemaVersion": 1, "target": target, "providerRecordSha256": provenance.digest(record_path),
        "providerInputs": inputs, "recipeInputs": recipe_hashes,
        "compiler": {"path": compiler, "sha256": compiler_sha},
        "compileCommand": command, "runCommand": invocation,
        "results": lines, "binarySha256": provenance.digest(binary),
        "files": provenance.archive_hashes(output, ["compile.log", "stdout.txt", "stderr.txt"]),
        "scope": "Standalone dependency memory-BIO TLS authentication and negative trust/hostname "
                 "checks; not curl transfers, released-archive comparison or 4D host verification.",
    }
    provenance.write_json(output / "tls-proof.json", receipt)
    inspect_proof(install, output)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(probe(args.openssl, args.output), indent=2))
