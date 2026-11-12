#!/usr/bin/env python3
"""Rebuild delivered GNU iconv sources with a dated benign modification on Mac."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys

import build_iconv as iconv
from provenance import archive_hashes, digest, write_json


modified_source = iconv.modified_source


def rebuild(candidate, output):
    if platform.system() != "Darwin":
        raise ValueError("GNU iconv Mac relinking requires macOS")
    original = json.loads((candidate / "native-build-provenance.json").read_text())
    target = original["target"]
    if target not in ("macos-arm64", "macos-x86_64"):
        raise ValueError("Both input and native toolchain must be for macOS")
    iconv.inspect(candidate)
    if output.exists() or any(c.isspace() for c in str(output)):
        raise ValueError("Use a fresh GNU build directory without whitespace")
    output.mkdir(parents=True)
    source = output / "source"
    iconv.extract(candidate / "upstream-source.tar.gz", source, original["version"])
    if iconv.tree_files(source) != original["sourceFiles"]:
        raise ValueError("Delivered GNU iconv sources differ from the original build")
    recipe = output / "recipe"
    shutil.copytree(candidate / "recipe", recipe)
    path = source / "lib/iconv.c"
    date = datetime.now(timezone.utc).date().isoformat()
    before = path.read_bytes()
    path.write_bytes(modified_source(before, date))
    sources = iconv.tree_files(source)
    work = output / "build"
    work.mkdir()
    calls = output / "compiler-calls"
    calls.mkdir()
    tools, sdk = iconv.tools(target)
    compiler = tools["clang"]["path"]
    flags = ["-O2", "-fPIC", "-arch", target.removeprefix("macos-"),
             "-mmacosx-version-min=10.13", "-isysroot", sdk]
    env = os.environ.copy()
    env.update({
        "CC": shlex.join([sys.executable, str(recipe / "build/dependencies/trace_compiler.py"),
                         str(calls), compiler]),
        "CFLAGS": shlex.join(flags + ["-MMD"]), "CPPFLAGS": "", "LDFLAGS": shlex.join(flags),
        "AR": tools["ar"]["path"], "RANLIB": tools["ranlib"]["path"],
        "CONFIG_SHELL": "/bin/sh", "SHELL": "/bin/sh",
    })
    arguments = list(original["configure_arguments"])
    arguments[0] = str(source / "configure")
    prefixes = [i for i, a in enumerate(arguments) if a.startswith("--prefix=")]
    if len(prefixes) != 1:
        raise ValueError("Original GNU configure prefix is ambiguous")
    arguments[prefixes[0]] = "--prefix=" + str(output / "install")
    iconv.execute(arguments, output / "configure.log", cwd=work, env=env)
    make_arguments = [tools["make"]["path"], "-C", str(work / "lib"), "-j3"]
    iconv.execute(make_arguments, output / "build.log", env=env)
    archive = work / "lib/.libs/libiconv.a"
    iconv.verify_architecture(archive, target)
    if digest(archive) == digest(candidate / original["builtArchive"]):
        raise ValueError("GNU user modification did not change the library")
    probe = output / "probe.c"
    probe.write_text(
        '#define main original_iconv_probe\n#include "recipe/build/dependencies/native/iconv-probe.c"\n'
        '#undef main\nextern int iconv_user_relink_probe(void);\n'
        'int main(void) { if (iconv_user_relink_probe() != 1) return 1; '
        'return original_iconv_probe(); }\n')
    binary = output / "probe"
    probe_arguments = [compiler, *flags, "-DLIBICONV_STATIC", "-I" + str(work / "include"),
                       str(probe), str(archive), "-o", str(binary)]
    iconv.execute(probe_arguments, output / "probe-build.log")
    with (output / "candidate.json").open("w") as stream:
        subprocess.run([str(binary)], check=True, stdout=stream, stderr=subprocess.PIPE)
    iconv.compare(json.loads((output / "candidate.json").read_text()),
                  json.loads((candidate / "baseline.json").read_text()), original["version"])
    if sources != iconv.tree_files(source) or iconv.tools(target) != (tools, sdk):
        raise ValueError("GNU source/toolchain changed during the user rebuild")
    if original["recipeFiles"] != archive_hashes(recipe, [a["path"] for a in original["recipeFiles"]]):
        raise ValueError("Delivered GNU build recipe changed")
    records = [json.loads(p.read_text()) for p in calls.glob("*.json")]
    core = {(source / p).as_posix() for p in iconv.core_sources(target)}
    compiled = [c for c in records if c["cwd"] == (work / "lib").as_posix()
                and any(p["path"] in core for p in c["inputs"])]
    closure = iconv.object_evidence(output, archive.relative_to(output).as_posix(),
                                   [{"output": c["object"]["path"]} for c in compiled], work)
    record = {
        "schemaVersion": 1, "status": "not-approved-for-production", "target": target,
        "candidateRecordSha256": digest(candidate / "native-build-provenance.json"),
        "deliveredSourceSha256": digest(candidate / "upstream-source.tar.gz"),
        "modification": {"path": "lib/iconv.c", "dateUtc": date,
                         "beforeSha256": next(a["sha256"] for a in original["sourceFiles"]
                                             if a["path"] == "lib/iconv.c"),
                         "afterSha256": digest(path)},
        "configureArguments": arguments, "makeArguments": make_arguments,
        "conversionProbeCommand": probe_arguments, "toolchain": tools,
        "relinkDriverSha256": digest(Path(__file__)),
        "compilerEnvironment": {k: env[k] for k in (
            "CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "AR", "RANLIB", "CONFIG_SHELL", "SHELL")},
        "modifiedArchiveSha256": digest(archive), "conversionProbeSha256": digest(binary),
        "sourceFiles": sources, "originalBuild": work.as_posix(),
        "compiledSources": compiled, **closure,
        "files": archive_hashes(output, [p.relative_to(output).as_posix()
                                        for p in output.rglob("*")
                                        if p.is_file() and not p.is_symlink()]),
        "scope": "Modified GNU library, defined-code and baseline conversion checks; full-plugin relinking/host proof are separate.",
    }
    write_json(output / "iconv-user-relink-proof.json", record)
    inspect(candidate, output)
    return record


def inspect(candidate, output):
    iconv.inspect(candidate)
    original = json.loads((candidate / "native-build-provenance.json").read_text())
    record = json.loads((output / "iconv-user-relink-proof.json").read_text())
    if (record["schemaVersion"] != 1 or record["status"] != "not-approved-for-production"
            or record["target"] != original["target"]
            or record["candidateRecordSha256"] != digest(candidate / "native-build-provenance.json")
            or record["deliveredSourceSha256"] != digest(candidate / "upstream-source.tar.gz")
            or record["files"] != archive_hashes(output, [a["path"] for a in record["files"]])):
        raise ValueError("GNU modified-source proof or delivered input binding changed")
    path = output / "source/lib/iconv.c"
    expected = modified_source((candidate / "source/lib/iconv.c").read_bytes(),
                               record["modification"]["dateUtc"])
    files = [dict(a) for a in original["sourceFiles"]]
    changed = next(a for a in files if a["path"] == "lib/iconv.c")
    if (path.read_bytes() != expected
            or record["modification"]["path"] != "lib/iconv.c"
            or record["modification"]["beforeSha256"] != changed["sha256"]
            or record["modification"]["afterSha256"] != digest(path)):
        raise ValueError("GNU modification is not the dated benign probe")
    changed["sha256"] = digest(path)
    if record["sourceFiles"] != files or iconv.tree_files(output / "source") != files:
        raise ValueError("Additional GNU sources changed during user relinking")
    archive = output / "build/lib/.libs/libiconv.a"
    iconv.verify_architecture(archive, record["target"])
    if (record["modifiedArchiveSha256"] != digest(archive)
            or record["conversionProbeSha256"] != digest(output / "probe")
            or record["modifiedArchiveSha256"] == digest(candidate / original["builtArchive"])):
        raise ValueError("GNU modified archive/probe bytes changed")
    closure = iconv.object_evidence(
        output, archive.relative_to(output).as_posix(),
        [{"output": c["object"]["path"]} for c in record["compiledSources"]],
        record["originalBuild"])
    if any(record[key] != value for key, value in closure.items()):
        raise ValueError("GNU compiled-object/archive closure changed")
    iconv.compare(json.loads((output / "candidate.json").read_text()),
                  json.loads((candidate / "baseline.json").read_text()), original["version"])
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    result = (inspect if args.inspect_only else rebuild)(args.candidate.resolve(), args.output.resolve())
    print(json.dumps({k: result[k] for k in ("target", "status", "modifiedArchiveSha256")}, indent=2))
