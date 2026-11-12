"""Shared source/recipe delivery for isolated native plugin object-relink kits."""

import json
from pathlib import Path
import shutil
import subprocess

import build_iconv
import inspect_proxy
from provenance import archive_hashes, digest


def relative_path(root, name):
    path = root / name
    if (Path(name).is_absolute() or "\\" in name or ":" in name
            or ".." in Path(name).parts or not path.resolve().is_relative_to(root.resolve())):
        raise ValueError("Portable material path escapes its kit")
    return path


def copy_delivery(project, output, evidence, targets):
    tracked = subprocess.check_output(["git", "-C", str(project), "ls-files", "-z"]).decode().split("\0")
    for name in filter(None, tracked):
        path = relative_path(project, name)
        if (Path(name).parts[0] in ("a", "lib") or name.startswith("test/Plugins/")
                or path.suffix.lower() in (".a", ".lib", ".dll", ".dylib", ".4dx", ".exe")):
            continue
        if not path.is_file() or path.is_symlink():
            raise ValueError("Product source is not a regular in-project file: " + name)
        destination = output / "product-source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    staging = json.loads((project.parent / "plugin-candidate-staging.json").read_text())
    materials = []
    for name in staging["nativeSourceKits"]:
        source = Path(name)
        proxy = source / "proxy-build-provenance.json"
        record_path = proxy if proxy.is_file() else source / "native-build-provenance.json"
        original = json.loads(record_path.read_text())
        library = "libproxy" if proxy.is_file() else original.get("library")
        if library not in ("libproxy", "libiconv"):
            continue
        (inspect_proxy.inspect if library == "libproxy" else build_iconv.inspect)(source)
        binding = next(a for a in evidence["rebuiltArchiveEvidence"] if a["name"] == library)
        if not any(a["target"] == original["target"] and a["sha256"] == digest(record_path)
                   for a in binding["originalBuildRecords"]):
            raise ValueError("Delivered LGPL sources do not match the actual selected build")
        if any(p.is_symlink() for p in source.rglob("*")):
            raise ValueError("Library-material symlinks require separate delivery review")
        destination = output / "library-materials" / original["target"] / library
        shutil.copytree(source, destination)
        materials.append({"library": library, "target": original["target"],
                          "directory": destination.relative_to(output).as_posix(),
                          "originalBuildRecordSha256": digest(record_path)})
    if {(a["library"], a["target"]) for a in materials} != {
            (library, target) for library in ("libproxy", "libiconv") for target in targets
    } or len(materials) != 2 * len(targets):
        raise ValueError("Both original LGPL source kits are required for every target")
    for folder in ("dependencies", "sbom"):
        source = Path(__file__).resolve().parents[1] / folder
        for path in source.iterdir():
            if path.is_file() and path.suffix in (".py", ".json"):
                destination = output / "tools/build" / folder / path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
    return materials


def verify_files(kit, record):
    if record["files"] != archive_hashes(kit, [a["path"] for a in record["files"]]):
        raise ValueError("Portable object/link materials changed")
