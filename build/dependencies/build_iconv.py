#!/usr/bin/env python3
"""Isolated GNU libiconv macOS source builds and old/new conversion checks."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile

from build_native import ROOT, RECIPES, tree_files, object_evidence, probe_selections as selections
from inspect_proxy import verify_architecture, verify_tar
from observe_curl import baseline
from provenance import archive_hashes, digest, write_json

ICONV_RECIPES = RECIPES + [
    "build/dependencies/build_iconv.py", "build/dependencies/trace_compiler.py",
    "build/dependencies/observe_curl.py",
    "build/dependencies/native/iconv-probe.c",
    "build/dependencies/native/probe-json.h"]
CHECKS = ["shift-jis", "shift-jis-roundtrip", "iso-2022-jp-flush", "non-bmp-utf16",
          "cp1252", "latin1", "invalid-input", "truncated-input", "small-output"]
CORE = {"lib/iconv.c", "lib/relocatable.c", "libcharset/lib/localcharset.c"}


def pin(target):
    lock = json.loads((ROOT / "build/dependencies/native-sources.json").read_text())
    return next(p for p in lock["sourceArchives"]
                if p["library"] == "libiconv" and target in p["targets"])


def extract(archive, destination, version):
    if destination.exists():
        raise ValueError("Use a fresh GNU source extraction directory")
    with tarfile.open(archive) as source:
        seen = set()
        entries = source.getmembers()
        for entry in entries:
            path = PurePosixPath(entry.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in entry.name
                    or ":" in entry.name or not path.parts
                    or path.parts[0] != "libiconv-" + version
                    or path in seen or not (entry.isfile() or entry.isdir())):
                raise ValueError("Unsafe, duplicate or unexpected GNU source archive member")
            seen.add(path)
        destination.mkdir(parents=True)
        for entry in entries:
            relative = PurePosixPath(entry.name).relative_to("libiconv-" + version)
            path = destination / relative
            if entry.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.extractfile(entry).read())
                path.chmod(0o755 if entry.mode & 0o111 else 0o644)


def compare(new, old, version):
    for info in (new, old):
        if (info.get("version") != version or info.get("checks") != CHECKS
                or not isinstance(info.get("aliases"), list) or not info["aliases"]
                or any(not isinstance(group, list) or not group
                       or any(not isinstance(a, str) or not a for a in group)
                       for group in info["aliases"])):
            raise ValueError("libiconv observations lack the required version, encodings or conversion checks")
    if new != old:
        raise ValueError("libiconv aliases/conversion behavior differs from the measured baseline")


def tools():
    paths = {name: subprocess.check_output(["xcrun", "--find", name], text=True).strip()
             for name in ("clang", "ar", "ranlib", "ld")}
    paths["make"] = shutil.which("make")
    paths["python"] = sys.executable
    paths["sh"] = "/bin/sh"
    sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    paths["SDKSettings.json"] = str(Path(sdk) / "SDKSettings.json")
    return {name: {"path": path, "sha256": digest(Path(path))} for name, path in paths.items()}, sdk


def execute(arguments, log, *, cwd=None, env=None):
    with log.open("w") as stream:
        result = subprocess.run(arguments, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        sys.stderr.write(log.read_text())
        raise subprocess.CalledProcessError(result.returncode, arguments)


def inspect(output):
    record = json.loads((output / "native-build-provenance.json").read_text())
    expected = pin(record["target"])
    if (record.get("schema_version") != 1 or record.get("library") != "libiconv"
            or record.get("version") != expected["version"] or record.get("sourceArchive") != expected
            or record.get("evidence_type") != "isolated-source-build-candidate"
            or record.get("status") != "not-approved-for-production"
            or record.get("licenseFile") != expected["licenseFile"]
            or record.get("licenseFileSha256") != expected["licenseSha256"]
            or digest(output / "upstream-source.tar.gz") != expected["sha256"]
            or record["sourceFiles"] != tree_files(output / "source")
            or digest(output / "source" / expected["licenseFile"]) != expected["licenseSha256"]):
        raise ValueError("GNU iconv source, acquisition pin or candidate status changed")
    prefix = "libiconv-" + expected["version"] + "/"
    verify_tar(output / "upstream-source.tar.gz",
               [{"path": prefix + p["path"], "sha256": p["sha256"]} for p in record["sourceFiles"]],
               directories=True)
    if (set(p["path"] for p in record["recipeFiles"]) != set(ICONV_RECIPES)
            or record["recipeFiles"] != archive_hashes(
                output / "recipe", [p["path"] for p in record["recipeFiles"]])):
        raise ValueError("GNU iconv original recipe changed")
    paths = [p["path"] for p in record["buildFiles"]]
    required = {"configure.log", "build.log", "baseline-build.log", "candidate-build.log",
                "baseline.json", "candidate.json", "baseline.map", "candidate.map",
                "baseline", "candidate", "baseline.stderr", "candidate.stderr",
                "build/config.h", "build/lib/Makefile", "build/lib/.libs/libiconv.a",
                "interface/iconv.h", "build/include/iconv.h", "build/config.log"}
    if not required.issubset(paths) or record["buildFiles"] != archive_hashes(output, paths):
        raise ValueError("GNU iconv original compile/validation records changed")
    if (record["installFiles"] != tree_files(output / "install")
            or {p["path"] for p in record["installFiles"]} != {
                "lib/libiconv.a", "include/iconv.h", "share/licenses/libiconv/COPYING.LIB"}
            or record["archives"] != archive_hashes(output / "install", ["lib/libiconv.a"])
            or digest(output / "install/include/iconv.h") != digest(output / "build/include/iconv.h")
            or digest(output / "install/share/licenses/libiconv/COPYING.LIB") != expected["licenseSha256"]):
        raise ValueError("GNU iconv installed archive/interface changed")
    if digest(output / "install/lib/libiconv.a") != digest(output / "build/lib/.libs/libiconv.a"):
        raise ValueError("GNU iconv installed archive differs from the actual build output")
    before = json.loads((output / "baseline.json").read_text())
    after = json.loads((output / "candidate.json").read_text())
    compare(after, before, expected["version"])
    call_paths = [p["path"] for p in record["compilerCalls"]]
    if (not set(call_paths).issubset(paths)
            or record["compilerCalls"] != archive_hashes(output, call_paths)):
        raise ValueError("GNU iconv original compiler-call metadata changed")
    calls = [json.loads((output / p).read_text()) for p in call_paths]
    original_source = record["originalSource"]
    if record["originalCorePaths"] != sorted(original_source + "/" + p for p in CORE):
        raise ValueError("GNU iconv compiled-source allowlist changed")
    compiled = [c for c in calls if any(
        p["path"] in record["originalCorePaths"] for p in c["inputs"])]
    if (compiled != record["compiledSources"] or len(compiled) != len(CORE)
            or any(c["returnCode"] or "object" not in c for c in compiled)
            or Counter(p["path"] for c in compiled for p in c["inputs"])
            != Counter(record["originalCorePaths"])):
        raise ValueError("GNU iconv actual core compiler invocations are incomplete")
    proof = object_evidence(output, "build/lib/.libs/libiconv.a",
                            [{"output": c["object"]["path"]} for c in compiled],
                            record["originalBuild"])
    if any(record.get(k) != v for k, v in proof.items()):
        raise ValueError("GNU iconv compiler-object/archive-member binding changed")
    source_hashes = {original_source + "/" + p["path"]: p["sha256"] for p in record["sourceFiles"]}
    if (any(p["sha256"] != source_hashes[p["path"]] for c in compiled for p in c["inputs"])
            or Counter(c["object"]["sha256"] for c in compiled)
            != Counter(p["sha256"] for p in proof["compiledObjects"])):
        raise ValueError("GNU iconv original compiler input/output hashes changed")
    for call in compiled:
        arguments = call["arguments"]
        if (call["compiler"] != record["toolchain"]["clang"]["path"]
                or "-mmacosx-version-min=10.13" not in arguments
                or arguments.count("-arch") != 1 or arguments[-1] == "-arch"
                or arguments[arguments.index("-arch") + 1] != record["target"].removeprefix("macos-")):
            raise ValueError("GNU iconv actual compiler/architecture/deployment settings changed")
    old_archive = next(p for p in baseline(record["target"]) if p["name"] == "libiconv")
    if (record["baselineArchive"] != old_archive
            or record["probeInputs"]["baseline"]["libiconv"]["sha256"] != old_archive["sha256"]
            or record["probeInputs"]["candidate"]["libiconv"]["sha256"]
            != digest(output / "build/lib/.libs/libiconv.a")):
        raise ValueError("GNU iconv selected probe archives differ from actual old/new inputs")
    for kind in ("baseline", "candidate"):
        selected = selections(output, record["target"], record["probeInputs"][kind],
                              map_name=kind + ".map", log_name=kind + "-build.log")
        if selected != record["linkSelections"][kind]:
            raise ValueError("GNU iconv probe selection changed")
    count = verify_architecture(output / "install/lib/libiconv.a", record["target"])
    return {"library": "libiconv", "version": expected["version"], "target": record["target"],
            "objectMembers": count, "aliasGroups": len(after["aliases"]),
            "conversionChecks": len(CHECKS), "status": record["status"]}


def build(archive, output, target):
    if platform.system() != "Darwin" or not target.startswith("macos-"):
        raise ValueError("This producer implements the macOS GNU recipe; Windows needs its Cygwin/MSVC recipe")
    output = output.resolve()
    expected = pin(target)
    if output.exists():
        raise ValueError("Use a fresh GNU iconv evidence directory")
    if digest(archive) != expected["sha256"]:
        raise ValueError("GNU iconv source archive does not match the reviewed acquisition pin")
    selected = next(p for p in baseline(target) if p["name"] == "libiconv")
    original = ROOT / selected["path"]
    if digest(original) != selected["sha256"]:
        raise ValueError("The exact selected old libiconv archive changed")
    output.mkdir(parents=True)
    shutil.copyfile(archive, output / "upstream-source.tar.gz")
    source = output / "source"
    extract(archive, source, expected["version"])
    files = tree_files(source)
    if digest(source / expected["licenseFile"]) != expected["licenseSha256"]:
        raise ValueError("GNU iconv library license text differs from the reviewed pin")
    recipes = archive_hashes(ROOT, ICONV_RECIPES)
    for item in recipes:
        destination = output / "recipe" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], destination)
    (output / "interface").mkdir()
    shutil.copyfile(ROOT / "include/iconv.h", output / "interface/iconv.h")
    tool, sdk = tools()
    compiler = tool["clang"]["path"]
    flags = ["-O2", "-fPIC", "-arch", target.removeprefix("macos-"),
             "-mmacosx-version-min=10.13", "-isysroot", sdk]
    probe_inputs, link_proof = {}, {}
    probe_source = ROOT / "build/dependencies/native/iconv-probe.c"

    def probe(kind, header, library):
        arguments = [compiler, *flags, "-DLIBICONV_STATIC", "-I" + str(header),
                     str(probe_source), str(library), "-Wl,-map," + str(output / (kind + ".map")),
                     "-o", str(output / kind)]
        execute(arguments, output / (kind + "-build.log"))
        with (output / (kind + ".json")).open("w") as stdout, (
                output / (kind + ".stderr")).open("w") as stderr:
            subprocess.run([str(output / kind)], stdout=stdout, stderr=stderr, check=True)
        probe_inputs[kind] = {"libiconv": {"path": str(library), "sha256": digest(library)}}
        link_proof[kind] = selections(output, target, probe_inputs[kind],
                                     map_name=kind + ".map", log_name=kind + "-build.log")
        return json.loads((output / (kind + ".json")).read_text())

    old = probe("baseline", output / "interface", original)
    extra = {s for group in old["aliases"] for s in group}
    extra_enabled = "ATARIST" in extra
    work = output / "build"
    work.mkdir()
    calls = output / "compiler-calls"
    calls.mkdir()
    env = os.environ.copy()
    env.update({"CC": shlex.join([sys.executable,
                    str(ROOT / "build/dependencies/trace_compiler.py"), str(calls), compiler]),
                "CFLAGS": shlex.join(flags + ["-MMD"]),
                "CPPFLAGS": "", "LDFLAGS": shlex.join(flags),
                "AR": tool["ar"]["path"], "RANLIB": tool["ranlib"]["path"],
                "CONFIG_SHELL": "/bin/sh", "SHELL": "/bin/sh"})
    host = "aarch64" if target == "macos-arm64" else "x86_64"
    build_host = "aarch64" if platform.machine() == "arm64" else "x86_64"
    arguments = [str(source / "configure"), "--disable-shared", "--enable-static",
                 "--disable-nls", "--build=" + build_host + "-apple-darwin",
                 "--host=" + host + "-apple-darwin", "--prefix=" + str(output / "install")]
    # GNU 1.16 enables extras even for --disable-extra-encodings.
    if extra_enabled:
        arguments.append("--enable-extra-encodings")
    execute(arguments, output / "configure.log", cwd=work, env=env)
    execute([tool["make"]["path"], "-C", str(work / "lib"), "-j3"],
            output / "build.log", env=env)
    built = work / "lib/.libs/libiconv.a"
    new = probe("candidate", work / "include", built)
    compare(new, old, expected["version"])
    if (files != tree_files(source) or recipes != archive_hashes(ROOT, ICONV_RECIPES)
            or tools() != (tool, sdk) or digest(original) != selected["sha256"]):
        raise ValueError("GNU iconv source/recipe/toolchain/baseline changed during compilation")
    install = output / "install"
    (install / "lib").mkdir(parents=True)
    (install / "include").mkdir()
    shutil.copyfile(built, install / "lib/libiconv.a")
    shutil.copyfile(work / "include/iconv.h", install / "include/iconv.h")
    (install / "share/licenses/libiconv").mkdir(parents=True)
    shutil.copyfile(source / "COPYING.LIB", install / "share/licenses/libiconv/COPYING.LIB")
    compiler_calls = archive_hashes(output, [p.relative_to(output).as_posix()
                                           for p in sorted(calls.glob("*.json"))])
    all_calls = [json.loads((output / p["path"]).read_text()) for p in compiler_calls]
    core_paths = sorted(str(source / p) for p in CORE)
    compiled = [c for c in all_calls if any(p["path"] in core_paths for p in c["inputs"])]
    proof = object_evidence(output, "build/lib/.libs/libiconv.a",
                            [{"output": c["object"]["path"]} for c in compiled], work)
    build_paths = [p.relative_to(output).as_posix() for p in work.rglob("*")
                   if p.is_file() and not p.is_symlink()]
    build_paths += [p.relative_to(output).as_posix() for p in output.iterdir()
                    if p.is_file() and p.name != "upstream-source.tar.gz"]
    build_paths += ["interface/iconv.h"] + [p["path"] for p in compiler_calls]
    record = {
        "schema_version": 1, "evidence_type": "isolated-source-build-candidate",
        "status": "not-approved-for-production", "library": "libiconv", "target": target,
        "version": expected["version"], "sourceArchive": expected,
        "licenseFile": "COPYING.LIB", "licenseFileSha256": expected["licenseSha256"],
        "licenseScope": "iconv.c LGPL-2.1-or-later; localcharset/relocatable LGPL-2.0-or-later; original notices preserved; static redistribution/relink gate remains",
        "sourceFiles": files, "recipeFiles": recipes, "configure_arguments": arguments,
        "compilerEnvironment": {k: env[k] for k in (
            "CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "AR", "RANLIB", "CONFIG_SHELL", "SHELL")},
        "toolchain": tool, "compilerCalls": compiler_calls, "compiledSources": compiled,
        "originalCorePaths": core_paths, "originalBuild": str(work),
        "originalSource": str(source), **proof,
        "buildFiles": archive_hashes(output, build_paths), "installFiles": tree_files(install),
        "archives": archive_hashes(install, ["lib/libiconv.a"]),
        "baselineArchive": selected, "probeInputs": probe_inputs, "linkSelections": link_proof,
        "validationScope": "ordered encoding aliases and nine old/new conversion/rejection checks; not full-plugin or all upstream tests",
        "exclusions": ["Unused libtool convenience symlinks; their direct archive/configuration targets are hashed.",
                       "This is not a full-plugin corresponding-source/relink distribution or host validation."],
    }
    write_json(output / "native-build-provenance.json", record)
    return inspect(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("build")
    sub.add_argument("--archive", type=Path, required=True)
    sub.add_argument("--output", type=Path, required=True)
    sub.add_argument("--target", choices=("macos-arm64", "macos-x86_64"), required=True)
    sub = commands.add_parser("inspect")
    sub.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.output) if args.command == "inspect"
                     else build(args.archive, args.output, args.target), indent=2))
