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


REPOSITORY = "https://github.com/miyako/4d-plugin-curl-v3"
SUPPLIER = "Keisuke Miyako"
LIMITATIONS = (
    "Partial inventory, not a complete dependency graph. Binary observations are "
    "identifying strings, not runtime verification or proof of active features. "
    "Declared linker inputs are build-derived candidates: archive selection and "
    "dead stripping are not resolved. Missing markers do not prove absence. "
    "OS libraries, toolchain/CRT, 4D SDK, embedded source and resources are not "
    "exhaustively inventoried. Dependency licenses, suppliers and PURLs are unknown."
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
    write_json(args.vendor / "brotli-provenance.json", {
        "name": "Brotli", "version": ".".join(parts),
        "evidenceType": "build-derived-source-and-archive-hashes-not-binary-detection",
        "sourceRepository": "https://github.com/google/brotli",
        "sourceCommit": git(args.source, "rev-parse", "HEAD"),
        "versionFile": "c/common/version.h", "versionFileSha256": sha256(header.read_bytes()),
        "archives": [{"path": p.relative_to(args.vendor).as_posix(), "sha256": sha256(p.read_bytes())}
                     for p in archives],
    })


def collect(args):
    """Record declarations, not an asserted list of incorporated packages."""
    root = args.root.resolve()
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
    }
    if args.brotli_provenance:
        provenance = json.loads(args.brotli_provenance.read_text(encoding="utf-8"))
        declared = {item["path"]: item for item in inputs}
        for archive in provenance["archives"]:
            if declared.get(archive["path"], {}).get("sha256") != archive["sha256"]:
                raise ValueError("Brotli build provenance does not match declared archive")
        record["rebuiltArchiveEvidence"] = [provenance]
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
        components.append(item)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "metadata": {"timestamp": inv["created"], "component": root},
        "components": components,
        # No dependsOn edges: identifying strings do not establish a dependency graph.
        "compositions": [{"aggregate": "incomplete", "assemblies": ["release"]}],
    }


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
        packages.append(package(row["id"], row["name"], row["version"],
                                row["description"], row.get("sha256")))
        relations.append({
            "spdxElementId": "SPDXRef-release", "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-" + row["id"],
            "comment": "Scoped binary slice or identifying-string observation, not a dependency edge.",
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
