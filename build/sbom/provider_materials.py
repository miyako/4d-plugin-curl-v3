"""Optional fresh compiler/source/object closure for the existing provider records."""

import hashlib
import json
import ntpath
from pathlib import Path, PurePosixPath
import shutil
import subprocess

from native_archive_objects import members, region, unpack
from provenance import archive_hashes, digest


def source_commit(record):
    values = {record[key] for key in ("source_commit", "sourceCommit") if record.get(key)}
    if len(values) != 1:
        raise ValueError("Provider source commit is missing or ambiguous")
    return values.pop()


def compiler_path(path):
    return path.replace("\\", "/") if ntpath.splitdrive(path)[0] else path


def compile_profile(call, target):
    arguments = call["arguments"]
    if target == "windows-x86_64":
        if all(p["path"].endswith(".asm") for p in call["inputs"]):
            if not any(a == "-f" and i + 1 < len(arguments) and arguments[i + 1] == "win64"
                       for i, a in enumerate(arguments)):
                raise ValueError("Provider assembler changed the Windows x64 profile")
        elif [a.lstrip("/-") for a in arguments
              if a.lstrip("/-") in ("MT", "MTd", "MD", "MDd")] != ["MT"]:
            raise ValueError("Provider compiler changed the release static CRT profile")
    elif target in ("macos-arm64", "macos-x86_64"):
        architectures = [arguments[i + 1] for i, a in enumerate(arguments[:-1]) if a == "-arch"]
        deployment = [a for a in arguments if a.startswith("-mmacosx-version-min=")]
        if (architectures != [target.removeprefix("macos-")]
                or deployment != ["-mmacosx-version-min=10.13"]):
            raise ValueError("Provider compiler changed architecture/deployment profile")
    else:
        raise ValueError("Unsupported fresh provider target")


def object_profile(data, target):
    if target == "windows-x86_64":
        if unpack("<H", data, 0)[0] != 0x8664:
            raise ValueError("Provider object is not Windows x64 COFF")
        return
    expected_cpu, maximum = {
        "macos-arm64": (0x0100000C, 11 << 16),
        "macos-x86_64": (0x01000007, (10 << 16) | (13 << 8)),
    }[target]
    magic, cpu, _, kind, count, size, _, _ = unpack("<8I", data, 0)
    if magic != 0xFEEDFACF or cpu != expected_cpu or kind != 1:
        raise ValueError("Provider object is not the expected thin Mac architecture")
    region(data, 32, size)
    offset, versions = 32, []
    for _ in range(count):
        command, length = unpack("<II", data, offset)
        if length < 8 or offset + length > 32 + size:
            raise ValueError("Invalid provider object load commands")
        if command == 0x32:
            platform_, minimum = unpack("<II", data, offset + 8)
            if length < 24 or platform_ != 1:
                raise ValueError("Provider object is not a macOS deployment")
            versions.append(minimum)
        elif command == 0x24:
            if length != 16:
                raise ValueError("Invalid provider minimum macOS load command")
            versions.append(unpack("<I", data, offset + 8)[0])
        offset += length
    if offset != 32 + size or len(versions) != 1 or versions[0] > maximum:
        raise ValueError("Provider object exceeds supported macOS deployment")


def inspect(install, record):
    proof = record["buildMaterials"]
    root = install / "build-materials"
    if (proof["schemaVersion"] != 1
            or proof["sourceCommit"] != source_commit(record)
            or record["archives"] != archive_hashes(install, [p["path"] for p in record["archives"]])
            or proof["files"] != archive_hashes(root, [p["path"] for p in proof["files"]])):
        raise ValueError("Fresh provider source/compiler materials changed")
    sources = {p["path"]: p["sha256"] for p in proof["sources"]}
    if len(sources) != len(proof["sources"]):
        raise ValueError("Duplicate provider source snapshot path")
    if proof["sources"] != archive_hashes(root / "source", sorted(sources)):
        raise ValueError("Provider source snapshot changed")
    for path_key, hash_key in (("version_file", "version_file_sha256"),
                               ("versionFile", "versionFileSha256"),
                               ("licenseFile", "licenseFileSha256")):
        if path_key in record or hash_key in record:
            if not record.get(path_key) or sources.get(record[path_key]) != record.get(hash_key):
                raise ValueError("Provider identity source differs from delivered snapshot")
    for link in proof.get("sourceLinks", []):
        archive_hashes(root, [link["textFile"]])
        raw = (root / link["textFile"]).read_bytes()
        blob = b"blob " + str(len(raw)).encode() + b"\0" + raw
        algorithm = hashlib.sha1 if len(link["gitObject"]) == 40 else hashlib.sha256
        if raw.decode() != link["target"] or algorithm(blob).hexdigest() != link["gitObject"]:
            raise ValueError("Provider original Git symlink text changed")
    if (len(proof["archives"]) != len(record["archives"])
            or {a["archive"] for a in proof["archives"]} != {a["path"] for a in record["archives"]}):
        raise ValueError("Provider archive-closure set differs from installed archives")
    source_prefix = PurePosixPath(proof["originalSource"])
    for archive in proof["archives"]:
        contents = list(members((install / archive["archive"]).read_bytes()))
        actual = [{"member": name, "sha256": hashlib.sha256(data).hexdigest()}
                  for name, _, data in contents]
        if "target" in proof:
            if record.get("target", proof["target"]) != proof["target"]:
                raise ValueError("Provider material target differs from source record")
            for _, _, data in contents:
                object_profile(data, proof["target"])
        if actual != [{"member": p["member"], "sha256": p["sha256"]} for p in archive["objects"]]:
            raise ValueError("Installed provider archive members differ from compiler closure")
        for item in archive["objects"]:
            archive_hashes(root, [item["compilerRecord"], item["objectFile"]])
            call = json.loads((root / item["compilerRecord"]).read_text())
            if (call["returnCode"] != 0 or not call["inputs"]
                    or compiler_path(call["compiler"]) not in {
                        compiler_path(p["path"]) for p in proof["toolchain"].values()}
                    or call["object"]["sha256"] != item["sha256"]
                    or digest(root / item["objectFile"]) != item["sha256"]
                    or ntpath.basename(call["object"]["path"]) != ntpath.basename(item["member"])):
                raise ValueError("Provider compiler output does not match its archive member")
            if "target" in proof:
                compile_profile(call, proof["target"])
            for source in call["inputs"]:
                relative = PurePosixPath(source["path"]).relative_to(source_prefix).as_posix()
                if sources.get(relative) != source["sha256"]:
                    raise ValueError("Provider compiled source differs from delivered snapshot")
    return proof


def compact_record(path, expected=None):
    record = json.loads(path.read_text(encoding="utf-8"))
    if expected is not None and record != expected:
        raise ValueError("Original provider record changed before aggregation")
    if "buildMaterials" not in record:
        if "buildMaterialEvidence" in record:
            raise ValueError("A compact provider summary is not an original build record")
        return record
    proof = inspect(path.parent, record)
    return {
        **{key: value for key, value in record.items() if key != "buildMaterials"},
        "buildMaterialEvidence": {
            "schemaVersion": 1, "originalRecordSha256": digest(path),
            "sourceCommit": source_commit(record),
            "sourceFiles": len(proof["sources"]), "materialFiles": len(proof["files"]),
            "sourceLinks": len(proof.get("sourceLinks", [])),
            "excludedGitlinks": proof.get("excludedGitlinks", []),
            "archives": [{"path": item["archive"], "objectMembers": len(item["objects"])}
                         for item in proof["archives"]],
            "detailLocation": "Original provider record and complete build-materials tree "
                              "retained in the source-provider artifacts.",
            "scope": "Whole provider build, not selected-library or selected-member coverage.",
        },
    }


def inventory_record(path, originals=()):
    """Verify delivered originals before accepting a bounded inventory summary."""
    record = json.loads(path.read_text(encoding="utf-8"))
    if "buildMaterials" in record:
        return compact_record(path, record)
    referenced = [record]
    referenced.extend(build.get("record", build) for build in record.get("source_builds", []))
    for build in referenced:
        if "buildMaterials" in build:
            raise ValueError("Aggregate provider materials need original-record-bound compaction")
        evidence = build.get("buildMaterialEvidence")
        if evidence is None:
            continue
        matches = [p for p in originals if digest(p) == evidence.get("originalRecordSha256")]
        if len(matches) != 1:
            raise ValueError("Provider material summary needs exactly one matching original record")
        if compact_record(matches[0]) != build:
            raise ValueError("Provider material summary differs from its inspected original")
    return record


def capture(source, install, record, calls, configuration, logs, recipes, toolchain, target):
    """Only call after a fresh successful build; never enrich historical caches."""
    root = install / "build-materials"
    if root.exists():
        raise ValueError("Do not restamp existing provider material")
    source = source.resolve()
    root.mkdir()
    index = subprocess.check_output(["git", "-C", str(source), "ls-files", "--stage", "-z"]).decode()
    files, excluded, links = set(), [], []
    for entry in filter(None, index.split("\0")):
        metadata, name = entry.split("\t", 1)
        mode, sha, stage = metadata.split()
        if stage != "0":
            raise ValueError("Unmerged provider source index")
        if mode == "160000":
            excluded.append({"path": name, "gitObject": sha,
                             "scope": "Upstream external test/integration gitlink; not a compiled input."})
        elif mode in ("100644", "100755"):
            files.add(name)
        elif mode == "120000":
            raw = subprocess.check_output(["git", "-C", str(source), "cat-file", "blob", sha])
            link_target = raw.decode()
            if (PurePosixPath(link_target).is_absolute()
                    or not (source / name).parent.joinpath(link_target).resolve().is_relative_to(source)):
                raise ValueError("Provider Git symlink leaves its source tree: " + name)
            path = root / "source-links" / (name + ".txt")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            links.append({"path": name, "target": link_target, "gitObject": sha,
                          "textFile": path.relative_to(root).as_posix()})
        else:
            raise ValueError("Provider source needs explicit non-regular file delivery: " + name)
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain",
                                "--untracked-files=no"]).strip():
        raise ValueError("Provider tracked source changed during compilation")
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"],
                               text=True).strip() != source_commit(record):
        raise ValueError("Provider checkout differs from its original source record")
    for path in source.rglob("*.h"):
        if ".git" not in path.relative_to(source).parts and not path.is_relative_to(install):
            files.add(path.relative_to(source).as_posix())
    compiled = []
    for path in sorted(calls.glob("*.json")):
        call = json.loads(path.read_text())
        if call["returnCode"] == 0 and call.get("object") and call["inputs"]:
            compiled.append((path, call))
    closures = []
    copied = {}
    for archive in record["archives"]:
        bound = []
        for name, _, data in members((install / archive["path"]).read_bytes()):
            sha = hashlib.sha256(data).hexdigest()
            matches = [(path, c) for path, c in compiled
                       if c["object"]["sha256"] == sha
                       and ntpath.basename(c["object"]["path"]) == ntpath.basename(name)]
            if len(matches) != 1:
                raise ValueError("Expected one actual compiler invocation for provider member: " + name)
            path, call = matches[0]
            object_path = Path(call["object"]["path"])
            if digest(object_path) != sha:
                raise ValueError("Provider compiler object changed before material capture")
            entry = {"member": name, "sha256": sha,
                     "objectFile": "objects/" + sha,
                     "compilerRecord": "compiler-calls/" + path.name}
            for original, relative in ((object_path, entry["objectFile"]),
                                       (path, entry["compilerRecord"])):
                if relative not in copied:
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(original, destination)
                    copied[relative] = original
            for item in call["inputs"]:
                relative = Path(item["path"]).relative_to(source).as_posix()
                if digest(source / relative) != item["sha256"]:
                    raise ValueError("Provider compiled input changed after compilation")
                files.add(relative)
            bound.append(entry)
        if not bound:
            raise ValueError("Provider archive has no compiler-bound objects")
        closures.append({"archive": archive["path"], "objects": bound})
    for name in sorted(files):
        original = source / name
        if original.is_symlink() or not original.is_file():
            raise ValueError("Provider source needs explicit non-regular file delivery: " + name)
        destination = root / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
    for category, paths in (("configuration", configuration), ("logs", logs), ("recipes", recipes)):
        for original, name in paths:
            destination = root / category / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, destination)
    proof = {
        "schemaVersion": 1, "sourceCommit": source_commit(record), "target": target,
        "originalSource": source.as_posix(), "toolchain": toolchain,
        "excludedGitlinks": excluded,
        "sourceLinks": links,
        "sources": archive_hashes(root / "source", sorted(files)), "archives": closures,
        "scope": "Fresh original successful compiler invocations, source snapshots and exact "
                 "installed archive member bytes; not historical build recovery or reproducibility.",
    }
    proof["files"] = archive_hashes(root, [p.relative_to(root).as_posix()
                                         for p in root.rglob("*") if p.is_file()])
    record["buildMaterials"] = proof
    inspect(install, record)
    return proof
