"""Inspect selected toolchain archives; never redistribute or execute their objects."""

import hashlib
import json
import ntpath
from pathlib import Path
import struct

from native_archive_objects import members, region, unpack

POLICY = "all-selected-windows-external-archives-classified"
DOC = "https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features"
CRT = {
    "libvcruntime.lib": "Microsoft Visual C++ runtime support",
    "libcmt.lib": "Microsoft Visual C++ runtime support",
    "libcpmt.lib": "Microsoft C++ standard library",
    "libucrt.lib": "Microsoft Universal C Runtime",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def key(path):
    return ntpath.normcase(ntpath.normpath(str(path)))


def snapshot(properties, root):
    """Hash effective MSBuild library inputs before linking, including unselected files."""
    result = {"schemaVersion": 1, "target": "windows-x86_64",
              "evidenceType": "pre-link-effective-toolchain-library-snapshot",
              "properties": properties, "archives": [], "missingDirectories": []}
    seen = set()
    for value in properties["LibraryPath"].split(";"):
        if not value:
            continue
        if "$(" in value:
            raise ValueError("Unevaluated MSBuild library path")
        directory = Path(value).resolve()
        if directory.is_relative_to(root.resolve()) or key(directory) in seen:
            continue
        seen.add(key(directory))
        if not directory.is_dir():
            result["missingDirectories"].append(str(directory))
            continue
        for path in sorted(directory.glob("*.lib")):
            if path.is_symlink() or not path.is_file():
                raise ValueError("Toolchain snapshot needs regular archive files")
            result["archives"].append({"path": str(path), "sha256": digest(path.read_bytes())})
    if not result["archives"]:
        raise ValueError("Effective MSBuild library paths contain no external archives")
    return result


def object_kind(data):
    """Separate real AMD64 objects from short imports and import descriptors."""
    if data[:4] == b"\0\0\xff\xff":
        version, machine = unpack("<HH", data, 4)
        if machine != 0x8664:
            raise ValueError("External object is not AMD64")
        if version == 0:
            amount, _, flags = unpack("<IHH", data, 12)
            payload = region(data, 20, amount)
            fields = payload.split(b"\0")
            expected_fields = 4 if flags >> 2 & 7 == 4 else 3
            if (len(data) != 20 + amount or len(fields) != expected_fields or fields[-1]
                    or not fields[0] or not fields[1].lower().endswith(b".dll")
                    or flags & 3 > 2 or flags >> 2 & 7 > 4 or flags & ~0x1F):
                raise ValueError("Malformed short COFF import object")
            return "import-only"
        # Bigobj has the documented anonymous COFF class ID and 56-byte header.
        if version == 2 and region(data, 12, 16) == bytes.fromhex(
                "c7a1bad1eebaa94baf20faf66aa4dcb8"):
            count = unpack("<I", data, 44)[0]
            start = 56
        else:
            return "unclassified"
    else:
        machine, count, _, _, _, optional, _ = unpack("<HHIIIHH", data, 0)
        if machine != 0x8664 or optional:
            raise ValueError("External object is not relocatable AMD64 COFF")
        start = 20
    region(data, start, count * 40)
    allocated = []
    for index in range(count):
        position = start + index * 40
        name = region(data, position, 8).rstrip(b"\0")
        amount, offset = unpack("<II", data, position + 16)
        flags = unpack("<I", data, position + 36)[0]
        if amount and offset:
            region(data, offset, amount)
        if (flags & (0x20 | 0x40 | 0x80) and amount
                and not name.startswith((b".debug", b".drectve", b".llvm"))):
            allocated.append(name)
    if allocated and all(name.startswith(b".idata") for name in allocated):
        return "import-only"
    return "native-object" if allocated else "unclassified"


def inspect_members(data, selected):
    requested = set(selected)
    matches = {name: [] for name in requested}
    for name, _, payload in members(data):
        for requested_name in requested:
            if key(name) == key(requested_name) or ntpath.basename(name).lower() == ntpath.basename(requested_name).lower():
                matches[requested_name].append((digest(payload), object_kind(payload)))
    result = []
    for name, candidates in sorted(matches.items()):
        if not candidates:
            raise ValueError("Selected external member not found in actual archive: " + name)
        kinds = {kind for _, kind in candidates}
        classification = next(iter(kinds)) if len(kinds) == 1 else "unclassified"
        result.append({
            "member": name, "classification": classification, "candidateCount": len(candidates),
            "candidatePayloadSetSha256": digest(json.dumps(sorted(candidates)).encode()),
            "scope": "All name-matching candidate payloads; ambiguous names do not establish "
                     "which exact object bytes survived linking.",
        })
    return result


def owner(path, properties):
    normalized = key(path)
    vc = properties.get("VCToolsInstallDir")
    sdk = properties.get("WindowsSdkDir")
    if vc and normalized.startswith(key(vc).rstrip("\\") + "\\"):
        return "MSVC"
    if sdk and normalized.startswith(key(sdk).rstrip("\\") + "\\"):
        return "Windows SDK"
    raise ValueError("Selected external archive is outside evaluated toolchain roots: " + str(path))


def collect(trace, before, binary):
    if (before.get("schemaVersion") != 1 or before.get("target") != "windows-x86_64"
            or trace.get("target") != "windows-x86_64"):
        raise ValueError("External snapshot/selection target mismatch")
    ledger = {key(a["path"]): a["sha256"] for a in before["archives"]}
    if len(ledger) != len(before["archives"]):
        raise ValueError("Duplicate pre-link external archive paths")
    result = {
        "schemaVersion": 1, "target": "windows-x86_64", "coveragePolicy": POLICY,
        "binarySha256": digest(binary.read_bytes()),
        "evidenceType": "selected-external-archive-inspection-and-toolchain-context",
        "preLinkSnapshotSha256": digest(json.dumps(before, sort_keys=True).encode()),
        "preLinkSnapshot": before,
        "toolchainContext": before["properties"], "archives": [],
        "limitations": "Toolchain context is not a library release version or vendor-signed "
                      "archive receipt. No source provenance, license conclusion, exact retained "
                      "bytes or redistributable toolchain object delivery is asserted.",
    }
    for selected in trace["archives"]:
        if selected.get("scope") != "external":
            continue
        path = Path(selected["resolvedPath"])
        data = path.read_bytes()
        sha = digest(data)
        if ledger.get(key(path)) != sha or selected.get("sha256") != sha:
            raise ValueError("Selected external archive changed or lacks a pre-link snapshot: " + str(path))
        receipt = {"path": selected["resolvedPath"], "sha256": sha,
                   "ownerContext": owner(path, before["properties"]),
                   "selectedMembers": inspect_members(data, selected["selectedMembers"])}
        kinds = {m["classification"] for m in receipt["selectedMembers"]}
        receipt["classification"] = (
            "import-only" if kinds == {"import-only"} else
            "unclassified" if "unclassified" in kinds else "static-library-input")
        basename = ntpath.basename(str(path)).lower()
        if receipt["classification"] == "static-library-input":
            if basename in CRT:
                expected_owner = "Windows SDK" if basename == "libucrt.lib" else "MSVC"
                if receipt["ownerContext"] != expected_owner:
                    raise ValueError("CRT archive is outside its documented toolchain owner")
                receipt["package"] = {"name": CRT[basename], "identityReference": DOC}
            elif receipt["ownerContext"] == "Windows SDK":
                receipt["package"] = {"name": "Microsoft Windows SDK native support",
                                      "identityReference": "https://developer.microsoft.com/windows/downloads/windows-sdk/"}
            else:
                raise ValueError("Unreviewed MSVC static-library identity: " + str(path))
        result["archives"].append(receipt)
    return result


def dependencies(record, target):
    evidence = record.get("externalArchiveEvidence")
    if not evidence:
        return [], None
    if (target != "windows-x86_64" or evidence.get("target") != target
            or evidence.get("schemaVersion") != 1 or evidence.get("coveragePolicy") != POLICY
            or evidence.get("binarySha256") != record["binarySha256"]):
        raise ValueError("External archive evidence is not bound to this binary/target")
    snapshot = evidence["preLinkSnapshot"]
    if (evidence["preLinkSnapshotSha256"] != digest(json.dumps(snapshot, sort_keys=True).encode())
            or snapshot["properties"] != evidence["toolchainContext"]):
        raise ValueError("Original external pre-link snapshot/context changed")
    ledger = {key(a["path"]): a["sha256"] for a in snapshot["archives"]}
    if len(ledger) != len(snapshot["archives"]):
        raise ValueError("Repeated pre-link external archive")
    selected = {key(a["resolvedPath"]): a for a in
                record["linkEvidence"][target]["archives"] if a.get("scope") == "external"}
    inspected = {}
    packages = {}
    imports, unclassified = [], []
    for archive in evidence["archives"]:
        path = key(archive["path"])
        actual = selected.get(path)
        if (path in inspected or not actual or archive["sha256"] != actual.get("sha256")
                or ledger.get(path) != archive["sha256"]
                or {m["member"] for m in archive["selectedMembers"]} != set(actual["selectedMembers"])):
            raise ValueError("External classification differs from actual linker selection")
        inspected[path] = archive
        if archive["classification"] == "import-only":
            if any(m["classification"] != "import-only" for m in archive["selectedMembers"]):
                raise ValueError("Import exclusion conceals non-import members")
            imports.append(archive["path"])
        elif archive["classification"] == "unclassified":
            unclassified.append(archive["path"])
        elif archive["classification"] == "static-library-input":
            if (not any(m["classification"] == "native-object" for m in archive["selectedMembers"])
                    or any(m["classification"] == "unclassified" for m in archive["selectedMembers"])):
                raise ValueError("Static archive classification lacks supported native members")
            context = owner(archive["path"], evidence["toolchainContext"])
            basename = ntpath.basename(archive["path"]).lower()
            expected_name = CRT.get(basename)
            if expected_name:
                if context != ("Windows SDK" if basename == "libucrt.lib" else "MSVC"):
                    raise ValueError("CRT identity differs from evaluated toolchain owner")
                expected_reference = DOC
            elif context == "Windows SDK":
                expected_name = "Microsoft Windows SDK native support"
                expected_reference = "https://developer.microsoft.com/windows/downloads/windows-sdk/"
            else:
                raise ValueError("Unreviewed external static library")
            if archive["package"] != {"name": expected_name, "identityReference": expected_reference}:
                raise ValueError("External static package identity changed")
            name = archive["package"]["name"]
            package = packages.setdefault(name, {
                "name": name, "kind": "toolchain-supplied-static-library",
                "evidenceType": evidence["evidenceType"],
                "externalSelectedArchives": [],
                "identityReference": archive["package"]["identityReference"],
                "toolchainContext": evidence["toolchainContext"],
                "limitations": evidence["limitations"],
            })
            package["externalSelectedArchives"].append(archive)
        else:
            raise ValueError("Unsupported external archive classification")
    if set(inspected) != set(selected):
        raise ValueError("External archive classification has missing/extra selections")
    coverage = {
        "selectedExternalArchives": len(selected),
        "namedStaticLibraryArchives": sum(len(p["externalSelectedArchives"]) for p in packages.values()),
        "versionedStaticLibraryArchives": 0,
        "unknownVersionPackages": sorted(packages),
        "importOnlyArchives": sorted(imports), "unclassifiedArchives": sorted(unclassified),
        "licenseStatus": "NOASSERTION; toolchain distribution terms not yet established per package",
    }
    if unclassified:
        raise ValueError("Selected external members remain unclassified: " + ", ".join(unclassified))
    return list(packages.values()), coverage
