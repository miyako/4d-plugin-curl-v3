"""Adapt inspected native candidate kits into the existing rebuilt-archive inventory."""

import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import quote

import provenance


LIBRARIES = {
    "curl": ("build_curl", "curl", "a/libcurl.a", "lib/64/libcurl.lib"),
    "zlib": ("build_native", "Zlib", "a/libz.a", "lib/64/zlib.lib"),
    "nghttp2": ("build_http", "MIT", "a/libnghttp2.a", "lib/64/nghttp2.lib"),
    "nghttp3": ("build_http", "MIT", "a/libnghttp3.a", None),
}
TARGETS = {
    "macos-universal": {"macos-arm64", "macos-x86_64"},
    "windows-x86_64": {"windows-x86_64"},
}


def _inspect(module, kit):
    dependencies = str(Path(__file__).resolve().parents[1] / "dependencies")
    if dependencies not in sys.path:
        sys.path.insert(0, dependencies)
    importlib.import_module(module).inspect(kit)


def _read_kits(target, kits):
    if target not in TARGETS:
        raise ValueError("Unsupported native inventory target")
    grouped = {}
    for path in kits:
        kit = Path(path).resolve()
        record_path = kit / "native-build-provenance.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        library = record.get("library")
        if library not in LIBRARIES:
            raise ValueError("Native inventory adapter does not cover this library")
        module, license_id, mac_path, windows_path = LIBRARIES[library]
        if record.get("target") not in TARGETS[target]:
            raise ValueError("Native source kit target does not match final inventory")
        if target == "windows-x86_64" and windows_path is None:
            raise ValueError("Library is not selected for this target")
        _inspect(module, kit)
        if (len(record["archives"]) != 1
                or record["status"] != "not-approved-for-production"):
            raise ValueError("Unexpected native candidate archive/status")
        archive = record["archives"][0]
        relative = Path(archive["path"])
        if (relative.is_absolute() or ".." in relative.parts
                or "\\" in archive["path"] or ":" in archive["path"]
                or not (kit / "install" / relative).resolve().is_relative_to(kit / "install")):
            raise ValueError("Native installed archive escapes its source kit")
        installed = kit / "install" / relative
        if provenance.digest(installed) != archive["sha256"]:
            raise ValueError("Native archive differs from original build record")
        rows = grouped.setdefault(library, {})
        if record["target"] in rows:
            raise ValueError("Duplicate native source target")
        rows[record["target"]] = (record, installed, provenance.digest(record_path))

    for library, rows in sorted(grouped.items()):
        if set(rows) != TARGETS[target]:
            raise ValueError("Native source kit architecture coverage is incomplete")
        _, license_id, mac_path, windows_path = LIBRARIES[library]
        models = [rows[t][0] for t in sorted(rows)]
        first = models[0]
        identity = {key: first.get(key) for key in
                    ("version", "source_commit", "source_repository", "sourceArchive")}
        if any(any(model.get(key) != value for key, value in identity.items())
               for model in models):
            raise ValueError("Native architecture source identities disagree")
    return grouped


def collect(root, target, kits):
    """Recheck original records and bind copies/universal slices, without executing probes."""
    grouped = _read_kits(target, kits)
    rebuilt = []
    for library, rows in sorted(grouped.items()):
        _, license_id, mac_path, windows_path = LIBRARIES[library]
        first = rows[sorted(rows)[0]][0]
        destination = mac_path if target == "macos-universal" else windows_path
        copied = Path(root) / destination
        if target == "macos-universal":
            provenance.verify_universal_archive(copied, {
                0x0100000C: rows["macos-arm64"][1],
                0x01000007: rows["macos-x86_64"][1],
            })
        elif provenance.digest(copied) != provenance.digest(rows[target][1]):
            raise ValueError("Copied native archive differs from original build")
        source_archive = first.get("sourceArchive")
        if library == "curl":
            if not isinstance(source_archive, dict):
                raise ValueError("Curl requires its verified release source archive")
            origin = "https://github.com/curl/curl"
            source = {"sourceArchive": source_archive}
            purl = ("pkg:generic/" + library + "@" + first["version"]
                    + "?download_url=" + quote(source_archive["url"], safe=""))
            license_hash = source_archive["licenseSha256"]
        else:
            if source_archive is not None:
                raise ValueError("Unexpected source archive on a Git-built native library")
            origin = first["source_repository"]
            source = {"sourceCommit": first["source_commit"]}
            repository = origin.removeprefix("https://github.com/").removesuffix(".git")
            purl = "pkg:github/" + repository + "@" + first["source_commit"]
            license_hash = first["licenseFileSha256"]
        rebuilt.append({
            "name": library, "version": first["version"], "sourceRepository": origin,
            **source, "license": license_id, "licenseFileSha256": license_hash, "purl": purl,
            "status": "not-approved-for-production",
            "evidenceType": "inspected-original-native-source-and-archive-build-records",
            "archives": [{"path": destination, "sha256": provenance.digest(copied)}],
            "originalBuildRecords": [{
                "target": architecture, "sha256": rows[architecture][2],
                "configureArguments": rows[architecture][0]["configure_arguments"],
                "toolchain": rows[architecture][0]["toolchain"],
                "recipeFiles": rows[architecture][0]["recipeFiles"],
            } for architecture in sorted(rows)],
            "limitations": [
                "Original source/compiler/archive kits must accompany these record hashes.",
                "Source inspection and archive binding do not approve production adoption, "
                "prove transfers or establish full-plugin relinking/host compatibility.",
            ],
        })
    return rebuilt


def stage(output, target, kits):
    """Create fresh isolated vendor-layout copies; never replace existing archives."""
    if output.exists():
        raise ValueError("Native candidate staging requires a new output directory")
    grouped = _read_kits(target, kits)
    if not grouped:
        raise ValueError("Native candidate staging requires source kits")
    tool = None
    if target == "macos-universal":
        tool = Path(subprocess.check_output(["xcrun", "--find", "lipo"], text=True).strip())
    output.mkdir(parents=True)
    commands = []
    for library, rows in sorted(grouped.items()):
        destination = output / LIBRARIES[library][2 if target == "macos-universal" else 3]
        destination.parent.mkdir(parents=True, exist_ok=True)
        if tool:
            arguments = [str(tool), "-create",
                         *[str(rows[t][1]) for t in sorted(rows)], "-output", str(destination)]
            subprocess.run(arguments, check=True)
            commands.append(arguments)
        else:
            shutil.copyfile(rows[target][1], destination)
    record = {
        "target": target, "status": "not-approved-for-production",
        "rebuiltArchiveEvidence": collect(output, target, kits),
        "mergeTool": {"path": str(tool), "sha256": provenance.digest(tool)} if tool else None,
        "mergeCommands": commands,
    }
    provenance.write_json(output / "native-source-provenance.json", record)
    return record


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--kit", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = stage(args.output, args.target, args.kit)
    print(json.dumps({"target": result["target"], "status": result["status"],
                      "libraries": [r["name"] for r in result["rebuiltArchiveEvidence"]]}))
