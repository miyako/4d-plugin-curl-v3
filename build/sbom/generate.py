#!/usr/bin/env python3
"""Conservative, non-executing inventory of this project's release containers."""

import argparse
import contextlib
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
import zipfile

import archives


REPOSITORY = "https://github.com/miyako/4d-plugin-curl-v3"
SUPPLIER = "Keisuke Miyako"
LIMITATIONS = (
    "Partial inventory, not a complete dependency graph. Binary observations are "
    "identifying strings, not runtime verification or proof of active features. "
    "Build evidence distinguishes declared candidates, selected archive members and "
    "map-visible live symbols; neither selection nor symbols quantify retained bytes "
    "under dead stripping/COMDAT/LTO. Missing markers do not prove absence. "
    "OS libraries, toolchain/CRT, 4D SDK, embedded source and resources are not "
    "exhaustively inventoried. Unverified origins/licenses/identifiers remain unknown."
)
MAC = "cURL.bundle/Contents/MacOS/cURL"
WIN = "cURL.bundle/Contents/Windows64/cURL.4DX"
PLIST = "cURL.bundle/Contents/Info.plist"
VERSION = rb"[0-9]+\.[0-9]+\.[0-9]+(?:[._-][A-Za-z0-9]+)*"
MARKERS = {
    "curl": rb"(?:libcurl/|CLIENT libcurl )(" + VERSION + rb")",
    "OpenSSL": rb"OpenSSL (" + VERSION + rb") ",
    "libssh2": rb"SSH-2\.0-libssh2_(" + VERSION + rb")",
    "zlib": rb"(?:inflate|deflate) (" + VERSION + rb") Copyright",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True
    ).strip()


def normalized_provenance(value):
    value = dict(value)
    for canonical, alternate in (
        ("name", "library"), ("sourceRepository", "source_repository"),
        ("sourceCommit", "source_commit"),
    ):
        if alternate in value:
            if canonical in value and value[canonical] != value[alternate]:
                raise ValueError(f"Conflicting source provenance field: {canonical}")
            value[canonical] = value.pop(alternate)
        if not value.get(canonical):
            raise ValueError(f"Missing source provenance field: {canonical}")
    return value


def brotli_provenance(args):
    header = args.source / "c/common/version.h"
    text = header.read_text(encoding="utf-8")
    parts = []
    for part in ("MAJOR", "MINOR", "PATCH"):
        match = re.search(r"^#define BROTLI_VERSION_" + part + r"\s+([0-9]+)$", text, re.M)
        if not match:
            raise ValueError(f"Missing Brotli {part} source version")
        parts.append(match.group(1))
    archives = sorted([*args.vendor.glob("a/libbrotli*.a"),
                       *args.vendor.glob("lib/64/brotli*.lib")])
    if len(archives) != 3:
        raise ValueError("Expected three built Brotli archives")
    license_path = args.source / "LICENSE"
    license_text = license_path.read_text(encoding="utf-8")
    if ("Permission is hereby granted, free of charge" not in license_text
            or 'THE SOFTWARE IS PROVIDED "AS IS"' not in license_text):
        raise ValueError("Brotli source license is not the expected MIT license")
    write_json(args.vendor / "brotli-provenance.json", {
        "name": "Brotli", "version": ".".join(parts),
        "evidenceType": "build-derived-source-and-archive-hashes-not-binary-detection",
        "sourceRepository": "https://github.com/google/brotli",
        "sourceCommit": git(args.source, "rev-parse", "HEAD"),
        "versionFile": "c/common/version.h", "versionFileSha256": sha256(header.read_bytes()),
        "license": "MIT", "licenseFile": "LICENSE",
        "licenseFileSha256": sha256(license_path.read_bytes()),
        "purl": "pkg:github/google/brotli@" + ".".join(parts),
        "archives": [{"path": p.relative_to(args.vendor).as_posix(), "sha256": sha256(p.read_bytes())}
                     for p in archives],
    })


def collect(args):
    """Bind declarations, verified identities and linker diagnostics to a binary."""
    root = args.root.resolve()
    search_directories = []
    if args.target == "windows-x86_64":
        project = "cURL.vcxproj"
        tree = ET.parse(root / project)
        ns = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        groups = [
            g for g in tree.findall("m:ItemDefinitionGroup", ns)
            if g.get("Condition") == "'$(Configuration)|$(Platform)'=='Release|x64'"
        ]
        if len(groups) != 1:
            raise ValueError("Expected one Release|x64 linker configuration")
        text = groups[0].find("m:Link/m:AdditionalDependencies", ns).text
        paths = ["lib/64/" + p for p in text.split(";") if p.endswith(".lib")]
        search = groups[0].find("m:Link/m:AdditionalLibraryDirectories", ns)
        if search is not None and search.text:
            search_directories = search.text.split(";")
    else:
        project = "cURL.xcodeproj/project.pbxproj"
        objects = plistlib.loads(subprocess.check_output(
            ["plutil", "-convert", "xml1", "-o", "-", str(root / project)]
        ))["objects"]
        phases = [v for v in objects.values()
                  if v.get("isa") == "PBXFrameworksBuildPhase"]
        if len(phases) != 1:
            raise ValueError("Expected one Xcode frameworks phase")
        paths = []
        for key in phases[0]["files"]:
            ref = objects[objects[key]["fileRef"]]
            if ref["path"].endswith(".a"):
                paths.append(ref["path"])
    inputs = []
    for path in sorted(set(paths)):
        file = root / path
        item = {"path": path, "status": "unresolved-declaration"}
        if file.is_file():
            item.update(status="available-declared-input", sha256=sha256(file.read_bytes()))
        inputs.append(item)
    configs = [project, ".github/workflows/release.yml",
               ".github/workflows/build-brotli.yml"]
    record = {
        "target": args.target,
        "binarySha256": sha256(args.binary.read_bytes()),
        "sourceCommit": git(root, "rev-parse", "HEAD"),
        "evidenceType": "build-derived-declarations-not-linker-map",
        "configuration": [{"path": p, "sha256": sha256((root / p).read_bytes())}
                          for p in configs],
        "declaredInputs": inputs,
        "librarySearchDirectoryDeclarations": search_directories,
        "searchResolution": "Project declarations are not evaluated search order; "
                            "actual diagnostics determine resolved inputs. Inherited/toolchain "
                            "directories and absolute developer paths are not rewritten.",
        "tooling": [{"path": p.name, "sha256": sha256(p.read_bytes())}
                    for p in sorted(Path(__file__).parent.glob("*.py"))],
    }
    rebuilt = []
    for provenance_path in [args.brotli_provenance, getattr(args, "openssl_provenance", None)]:
        if not provenance_path:
            continue
        provenance = normalized_provenance(json.loads(provenance_path.read_text(encoding="utf-8")))
        declared = {item["path"]: item for item in inputs}
        for archive in provenance["archives"]:
            if declared.get(archive["path"], {}).get("sha256") != archive["sha256"]:
                raise ValueError(f"{provenance.get('name', 'Library')} build provenance does not match declared archive")
        rebuilt.append(provenance)
    if rebuilt:
        record["rebuiltArchiveEvidence"] = rebuilt
    manifest_path = getattr(args, "manifest", None)
    if manifest_path:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        rebuilt_paths = {a["path"] for p in rebuilt for a in p["archives"]}
        entries = {e["path"]: e for e in manifest["archives"]}
        inventory_entries = []
        patterns = ["a/**/*.a"] if args.target == "macos-universal" else ["lib/64/**/*.lib"]
        for pattern in patterns:
            for path in sorted(root.glob(pattern)):
                relative = path.relative_to(root).as_posix()
                entry = entries.get(relative)
                digest = sha256(path.read_bytes())
                if relative in rebuilt_paths:
                    inventory_entries.append({"path": relative, "sha256": digest,
                                              "identityStatus": "source-build-provenance"})
                elif entry and entry["sha256"] == digest:
                    archives.verify_manifest({"archives": [entry]}, root)
                    inventory_entries.append({**entry, "identityStatus": "hash-bound-manifest"})
                else:
                    raise ValueError(f"Archive manifest hash mismatch or unreviewed archive: {relative}")
        record["archiveInventory"] = inventory_entries
        record["manifestSha256"] = sha256(manifest_path.read_bytes())
    diagnostic_paths = getattr(args, "link_map", [])
    if diagnostic_paths:
        import linker
        maps = {}
        for value in diagnostic_paths:
            target, separator, path = value.partition("=")
            if not separator or target in maps:
                raise ValueError("Use one --link-map TARGET=PATH per target")
            maps[target] = Path(path)
        required = ({"macos-arm64", "macos-x86_64"} if args.target == "macos-universal"
                    else {"windows-x86_64"})
        if set(maps) != required:
            raise ValueError(f"Expected link maps for {sorted(required)}")
        known = {item["path"]: item for item in record.get("archiveInventory", inputs)}
        record["linkEvidence"] = {}
        for target, path in maps.items():
            trace = linker.collect(root, target, {
                "map": path, "verbose": getattr(args, "link_log", None),
            }, inputs)
            selections = trace.pop("selectedArchives")
            for selection in selections:
                resolved = selection.get("resolvedPath")
                if not resolved:
                    continue
                try:
                    relative = Path(resolved).resolve().relative_to(root).as_posix()
                except ValueError:
                    continue
                if relative in known:
                    if selection.get("sha256") != known[relative].get("sha256"):
                        raise ValueError(f"Selected archive hash mismatch: {relative}")
                    selection["candidatePath"] = relative
            trace["archives"] = selections
            record["linkEvidence"][target] = trace
        record["evidenceType"] = "build-derived-resolved-linker-inputs"
    write_json(args.output, record)


def mac_slices(data):
    if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("Expected a universal Mach-O (fat32) macOS binary")
    count = struct.unpack_from(">I", data, 4)[0]
    if count != 2 or len(data) < 8 + count * 20:
        raise ValueError("Expected exactly arm64 and x86_64 slices")
    result = {}
    ranges = []
    for i in range(count):
        cpu, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + i * 20)
        arch = {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cpu)
        if (not arch or arch in result or offset < 8 + count * 20 or size < 32
                or offset + size > len(data)):
            raise ValueError("Invalid/unsupported universal Mach-O slice")
        part = data[offset:offset + size]
        if part[:4] != b"\xcf\xfa\xed\xfe" or struct.unpack_from("<I", part, 4)[0] != cpu:
            raise ValueError("Mach-O slice header disagrees with fat header")
        if any(offset < end and start < offset + size for start, end in ranges):
            raise ValueError("Overlapping Mach-O slices")
        ranges.append((offset, offset + size))
        result["macos-" + arch] = part
    return result


def check_pe(data):
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("Expected a Windows PE binary")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if (offset + 26 > len(data) or data[offset:offset + 4] != b"PE\0\0"
            or struct.unpack_from("<H", data, offset + 4)[0] != 0x8664
            or struct.unpack_from("<H", data, offset + 24)[0] != 0x20B):
        raise ValueError("Expected Windows x86_64 PE32+")


@contextlib.contextmanager
def container_reader(path):
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in (MAC, WIN, PLIST):
                if archive.namelist().count(name) != 1:
                    raise ValueError(f"Expected exactly one {name}")
            yield archive.read
    elif path.suffix.lower() == ".dmg":
        with tempfile.TemporaryDirectory(prefix="curl-sbom-") as mount:
            subprocess.run(
                ["hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
                 "-mountpoint", mount, str(path.resolve())],
                check=True, stdout=subprocess.DEVNULL,
            )
            try:
                # hdiutil -srcfolder bundle puts Contents at the volume root.
                base = Path(mount)
                if (base / "cURL.bundle").is_dir():
                    base = base / "cURL.bundle"
                def read(name):
                    file = base / name.removeprefix("cURL.bundle/")
                    if file.is_symlink() or base.resolve() not in file.resolve().parents:
                        raise ValueError(f"Unsafe DMG member: {name}")
                    return file.read_bytes()
                yield read
            finally:
                subprocess.run(["hdiutil", "detach", mount], check=True,
                               stdout=subprocess.DEVNULL)
    else:
        raise ValueError("Only release ZIP and DMG containers are supported")


def observations(data):
    found = []
    for name, pattern in MARKERS.items():
        matches = list(re.finditer(pattern, data))
        versions = {m.group(1).decode("ascii") for m in matches}
        if len(versions) > 1:
            raise ValueError(f"Conflicting {name} version markers: {versions}")
        if matches:
            match = matches[0]
            found.append({
                "name": name, "version": match.group(1).decode("ascii"),
                "evidenceType": "analyzed-binary-identifying-string",
                "marker": match.group().decode("ascii"), "offsetWithinAnalyzedBytes": match.start(),
            })
    if not any(item["name"] == "curl" for item in found):
        raise ValueError("No identifying curl version marker; refusing empty inventory")
    return found


def build_dependencies(record, target, observed):
    """Promote only hash-matched identities tied to an actually selected archive."""
    diagnostics = record.get("linkEvidence", {})
    selections = diagnostics.get(target, {}).get("archives", [])
    entries = {item["path"]: item for item in record.get("archiveInventory", [])}
    sources = {}
    for provenance in record.get("rebuiltArchiveEvidence", []):
        for archive in provenance["archives"]:
            sources[archive["path"]] = (archive, provenance)
    dependencies = {item["name"]: dict(item) for item in observed}
    for selection in selections:
        path = selection.get("candidatePath")
        if not path or not selection.get("sha256"):
            continue
        identities = []
        if path in sources:
            archive, provenance = sources[path]
            if selection["sha256"] != archive["sha256"]:
                raise ValueError(f"{target}: selected archive disagrees with source provenance: {path}")
            identities = [{
                "name": provenance["name"], "version": provenance["version"],
                "evidenceType": "source-build-and-selected-archive",
                "origin": provenance["sourceRepository"],
                **{key: provenance[key] for key in ("license", "purl") if key in provenance},
                "sourceEvidence": provenance,
            }]
        elif path in entries:
            entry = entries[path]
            if entry["sha256"] != selection["sha256"]:
                raise ValueError(f"{target}: selected archive disagrees with manifest: {path}")
            identities = entry.get("targets", {}).get(target, {}).get("identities", [])
        for identity in identities:
            name, version = identity["name"], identity["version"]
            previous = dependencies.get(name)
            if previous and previous["version"] != version:
                raise ValueError(f"{target}: binary/build version disagreement for {name}")
            if not previous or "selectedArchives" not in previous:
                dependencies[name] = {
                    "name": name, "version": version,
                    **({"binaryObservation": previous} if previous else {}),
                    "evidenceType": "hash-bound-selected-archive-identity",
                    "selectedArchives": [],
                    "archiveIdentities": [],
                    "incorporation": "linker-selected-members; retained bytes not established",
                }
            dependency = dependencies[name]
            for key in ("license", "purl", "origin"):
                value = identity.get(key)
                if value:
                    if dependency.get(key) and dependency[key] != value:
                        raise ValueError(f"{target}: conflicting {key} evidence for {name}")
                    dependency[key] = value
            dependency["selectedArchives"].append(selection)
            dependency["archiveIdentities"].append({"path": path, "identity": identity})
    for dependency in dependencies.values():
        if "selectedArchives" in dependency:
            dependency["selectedArchives"].sort(key=lambda item: item["candidatePath"])
            dependency["archiveIdentities"].sort(key=lambda item: item["path"])
    return [dependencies[name] for name in sorted(dependencies)]


def inventory(path, version, evidence):
    with container_reader(path) as read:
        info = plistlib.loads(read(PLIST))
        if info["CFBundleShortVersionString"] != version:
            raise ValueError(f"{path.name}: bundle version does not match {version}")
        mac, win = read(MAC), read(WIN)
    check_pe(win)
    slices = mac_slices(mac)
    slices["windows-x86_64"] = win
    targets = []
    for target, data in sorted(slices.items()):
        file_data = win if target.startswith("windows") else mac
        item = {
            "id": target, "binaryPath": WIN if target.startswith("windows") else MAC,
            "binarySha256": sha256(file_data), "analyzedSha256": sha256(data),
            "dependencies": observations(data),
        }
        if evidence:
            key = "windows-x86_64" if target.startswith("windows") else "macos-universal"
            record = evidence[key]
            if record["binarySha256"] != item["binarySha256"]:
                raise ValueError(f"{target}: build evidence does not match packaged binary")
            item["buildEvidence"] = record
            item["dependencies"] = build_dependencies(record, target, item["dependencies"])
        targets.append(item)
    return {
        "inventoryVersion": 1, "name": "cURL", "version": version,
        "supplier": SUPPLIER, "repository": REPOSITORY,
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifact": {"name": path.name, "sha256": sha256(path.read_bytes())},
        "limitations": LIMITATIONS, "targets": targets,
    }


def component_rows(inv):
    for target in inv["targets"]:
        ident = target["id"]
        yield {
            "id": ident, "target": ident, "name": f"cURL ({ident})", "version": inv["version"],
            "kind": "file", "sha256": target["analyzedSha256"],
            "description": json.dumps({k: v for k, v in target.items() if k != "dependencies"},
                                      sort_keys=True),
        }
        for dep in target["dependencies"]:
            yield {
                "id": ident + "-" + dep["name"], "name": dep["name"],
                "target": ident,
                "version": dep["version"], "kind": "library",
                "description": json.dumps({"target": ident, **dep}, sort_keys=True),
                **{key: dep[key] for key in ("license", "purl", "origin") if dep.get(key)},
                "buildSupported": bool(dep.get("selectedArchives")),
            }


def cyclonedx(inv):
    root = {
        "type": "application", "bom-ref": "release", "name": inv["name"],
        "version": inv["version"], "supplier": {"name": inv["supplier"]},
        "hashes": [{"alg": "SHA-256", "content": inv["artifact"]["sha256"]}],
        "description": inv["limitations"],
        "properties": [{"name": "release:artifact", "value": inv["artifact"]["name"]}],
    }
    components = []
    for row in component_rows(inv):
        item = {
            "bom-ref": row["id"], "type": row["kind"], "name": row["name"],
            "version": row["version"], "description": row["description"],
            "properties": [{"name": "release:target", "value": row["target"]}],
        }
        if "sha256" in row:
            item["hashes"] = [{"alg": "SHA-256", "content": row["sha256"]}]
        if row.get("license"):
            item["licenses"] = [{"license": {"id": row["license"]}}]
        if row.get("purl"):
            item["purl"] = row["purl"]
        if row.get("origin"):
            item["externalReferences"] = [{"type": "vcs", "url": row["origin"]}]
        components.append(item)
    result = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "metadata": {"timestamp": inv["created"], "component": root},
        "components": components,
        "compositions": [{"aggregate": "incomplete", "assemblies": ["release"]}],
    }
    supported = [row for row in component_rows(inv) if row.get("buildSupported")]
    if supported:
        result["dependencies"] = [
            {"ref": target["id"], "dependsOn": [row["id"] for row in supported
                                                if row["target"] == target["id"]]}
            for target in inv["targets"]
        ]
    return result


def spdx(inv):
    def package(ident, name, version, description, digest=None):
        item = {
            "SPDXID": "SPDXRef-" + ident, "name": name, "versionInfo": version,
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION", "description": description,
        }
        if digest:
            item["checksums"] = [{"algorithm": "SHA256", "checksumValue": digest}]
        return item
    root = package("release", inv["name"], inv["version"], inv["limitations"],
                   inv["artifact"]["sha256"])
    root.update(supplier="Person: " + inv["supplier"],
                packageFileName=inv["artifact"]["name"])
    packages = [root]
    relations = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                  "relatedSpdxElement": "SPDXRef-release"}]
    for row in component_rows(inv):
        item = package(row["id"], row["name"], row["version"],
                       row["description"], row.get("sha256"))
        if row.get("license"):
            item["licenseDeclared"] = row["license"]
        if row.get("origin"):
            item["homepage"] = row["origin"]
        if row.get("purl"):
            item["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER",
                                     "referenceType": "purl", "referenceLocator": row["purl"]}]
        packages.append(item)
        relations.append({
            "spdxElementId": "SPDXRef-" + (row["target"] if row["kind"] == "library" else "release"),
            "relationshipType": "DEPENDS_ON" if row.get("buildSupported") else "CONTAINS",
            "relatedSpdxElement": "SPDXRef-" + row["id"],
            "comment": ("Build-supported archive member selection, not exact retained bytes or a transitive graph."
                        if row.get("buildSupported") else
                        "Scoped binary slice or identifying-string observation, not a dependency edge."),
        })
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": inv["artifact"]["name"],
        "documentNamespace": REPOSITORY + "/sbom/" + str(uuid.uuid4()),
        "creationInfo": {"created": inv["created"], "creators": ["Tool: curl-release-sbom-poc"]},
        "comment": inv["limitations"], "packages": packages,
        "relationships": relations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inputs = commands.add_parser("inputs", help="Capture declared linker inputs on the build runner")
    inputs.add_argument("--root", type=Path, default=Path("."))
    inputs.add_argument("--target", choices=["macos-universal", "windows-x86_64"], required=True)
    inputs.add_argument("--binary", type=Path, required=True)
    inputs.add_argument("--output", type=Path, required=True)
    inputs.add_argument("--brotli-provenance", type=Path)
    inputs.add_argument("--openssl-provenance", type=Path)
    inputs.add_argument("--manifest", type=Path)
    inputs.add_argument("--link-map", action="append", default=[])
    inputs.add_argument("--link-log", type=Path)
    brotli = commands.add_parser("brotli", help="Record freshly built Brotli source/archive evidence")
    brotli.add_argument("--source", type=Path, required=True)
    brotli.add_argument("--vendor", type=Path, required=True)
    generate = commands.add_parser("generate", help="Analyze packaged artifacts without executing code")
    generate.add_argument("--version", required=True, help="Exact bundle version, without v")
    generate.add_argument("--output", type=Path, required=True)
    generate.add_argument("--evidence", type=Path, action="append", default=[])
    generate.add_argument("artifacts", type=Path, nargs="+")
    args = parser.parse_args()
    if args.command == "brotli":
        brotli_provenance(args)
        return
    if args.command == "inputs":
        collect(args)
        return
    evidence = {}
    for path in args.evidence:
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["target"] in evidence:
            raise ValueError("Duplicate build evidence target")
        evidence[record["target"]] = record
    if evidence and set(evidence) != {"macos-universal", "windows-x86_64"}:
        raise ValueError("Supply both platform build evidence records, or neither")
    for path in args.artifacts:
        inv = inventory(path, args.version, evidence)
        for suffix, document in (
            ("inventory.json", inv), ("cdx.json", cyclonedx(inv)), ("spdx.json", spdx(inv))
        ):
            write_json(args.output / (path.name + "." + suffix), document)
        print(f"{path.name}: {inv['artifact']['sha256']}; "
              f"{len(inv['targets'])} targets; "
              f"{sum(len(t['dependencies']) for t in inv['targets'])} observations")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError,
            zipfile.BadZipFile, plistlib.InvalidFileException, ET.ParseError) as error:
        print(f"SBOM error: {error}", file=sys.stderr)
        sys.exit(1)
