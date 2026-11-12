"""Optional fresh compiler/source/object closure for the existing provider records."""

import hashlib
import json
import ntpath
from pathlib import Path, PurePosixPath
import shutil
import subprocess

from native_archive_objects import members
from provenance import archive_hashes, digest


def source_commit(record):
    values = {record[key] for key in ("source_commit", "sourceCommit") if record.get(key)}
    if len(values) != 1:
        raise ValueError("Provider source commit is missing or ambiguous")
    return values.pop()


def compiler_path(path):
    return path.replace("\\", "/") if ntpath.splitdrive(path)[0] else path


def inspect(install, record):
    proof = record["buildMaterials"]
    root = install / "build-materials"
    if (proof["schemaVersion"] != 1
            or proof["sourceCommit"] != source_commit(record)
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
        actual = [{"member": name, "sha256": hashlib.sha256(data).hexdigest()}
                  for name, _, data in members((install / archive["archive"]).read_bytes())]
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
            for source in call["inputs"]:
                relative = PurePosixPath(source["path"]).relative_to(source_prefix).as_posix()
                if sources.get(relative) != source["sha256"]:
                    raise ValueError("Provider compiled source differs from delivered snapshot")
    return proof


def capture(source, install, record, calls, configuration, logs, recipes, toolchain):
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
            target = raw.decode()
            if (PurePosixPath(target).is_absolute()
                    or not (source / name).parent.joinpath(target).resolve().is_relative_to(source)):
                raise ValueError("Provider Git symlink leaves its source tree: " + name)
            path = root / "source-links" / (name + ".txt")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            links.append({"path": name, "target": target, "gitObject": sha,
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
        "schemaVersion": 1, "sourceCommit": source_commit(record),
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
