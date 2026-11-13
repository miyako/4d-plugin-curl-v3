#!/usr/bin/env python3
"""Verify and deliver notice inputs bound to the existing normalized inventory."""

import argparse
import json
from pathlib import Path
import shutil
import sys
import tarfile

sys.dont_write_bytecode = True
from plugin_relink_materials import relative_path
from provenance import archive_hashes, digest, write_json


INPUT = "notice-materials.json"
OUTPUT = "notice-delivery.json"
SOURCE_CONTEXT = "source-distribution-license-context-not-library-license-conclusion"
ROLES = {"primary-license", "additional-source-notice", "embedded-source-license-text",
         "normalized-license-evidence", "pinned-source-notice-context", SOURCE_CONTEXT}


def identity(value):
    return value["name"], value.get("version"), value.get("purl")


def verify_tree(root, files, manifest):
    paths = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if (paths != set(files) | {manifest} or any(p.is_symlink() for p in root.rglob("*"))
            or manifest in files):
        raise ValueError("Notice material file set changed")
    for name, expected in files.items():
        if digest(relative_path(root, name)) != expected:
            raise ValueError("Notice material bytes changed: " + name)


def inspect(materials, inventory_path):
    inventory = json.loads(inventory_path.read_text())
    manifest = json.loads((materials / INPUT).read_text())
    if (inventory.get("inventoryVersion") != 1 or manifest.get("schemaVersion") != 1
            or manifest.get("evidenceType") != "inventory-referenced-notice-input-recovery"
            or manifest.get("status") != "not-approved-for-production"
            or manifest["inventorySha256"] != digest(inventory_path)
            or manifest["referencedArtifact"] != inventory["artifact"]):
        raise ValueError("Notice inputs differ from their normalized inventory")
    verify_tree(materials, manifest["files"], INPUT)
    if manifest["files"].get("inventory.json") != digest(inventory_path):
        raise ValueError("Delivered inventory differs from the original inventory")
    rows = manifest["components"]
    assignments = [[] for _ in rows]
    for target in inventory["targets"]:
        for dependency in target["dependencies"]:
            matches = [i for i, row in enumerate(rows) if identity(row) == identity(dependency)
                       and target["id"] in row["targets"]]
            if len(matches) != 1:
                raise ValueError("Missing or repeated target-scoped notice coverage")
            assignments[matches[0]].append((target["id"], dependency))
    references = {"inventory.json"}
    for row, related in zip(rows, assignments):
        if (not related or len(set(row["targets"])) != len(row["targets"])
                or set(row["targets"]) != {target for target, _ in related}
                or any(row.get("declaredLicense") != dep.get("license") for _, dep in related)
                or row["selectedArchiveBindings"] != [
                    {"target": target, **archive} for target, dep in related
                    for archive in dep.get("selectedArchives", [])]):
            raise ValueError("Notice identity, license assertion or selected archive binding changed")
        files = row["files"]
        keys = {(f["role"], f["sourcePath"], f["sha256"]) for f in files}
        if len(keys) != len(files) or any(f["role"] not in ROLES for f in files):
            raise ValueError("Repeated or unsupported notice input")
        for f in files:
            if manifest["files"].get(f["path"]) != f["sha256"]:
                raise ValueError("Notice reference differs from delivered bytes")
            references.add(f["path"])
        dependencies = [dep for _, dep in related]
        sources = [a["identity"]["sourceEvidence"] for dep in dependencies
                   for a in dep.get("archiveIdentities", [])]
        if sources:
            primary = [f for f in files if f["role"] == "primary-license"]
            if (len(primary) != 1 or
                    {s["licenseFileSha256"] for s in sources} != {primary[0]["sha256"]}):
                raise ValueError("Primary license differs from selected source evidence")
            additional = [f for f in files if f["role"] == "additional-source-notice"]
            actual = {(f["sourcePath"], f["sha256"]) for f in additional}
            if len(actual) != len(additional) or any(
                    actual != {(f["path"], f["sha256"])
                               for f in s.get("additionalNoticeFiles", [])} for s in sources):
                raise ValueError("Recorded additional notices are missing or changed")
        else:
            embedded = [f for f in files if f["role"] == "embedded-source-license-text"]
            if len(embedded) != 1:
                raise ValueError("Embedded source needs its original license text")
            raw = (materials / embedded[0]["path"]).read_bytes()
            if any(raw != dep.get("licenseText", dep.get("licenseEvidence", {})).get(
                    "text", "").encode("utf-8") for dep in dependencies):
                raise ValueError("Embedded notice differs from the normalized inventory")
        extracted = [f for f in files if f["role"] == "normalized-license-evidence"]
        expected = [dep["licenseEvidence"]["text"] for dep in dependencies
                    if sources and dep.get("licenseEvidence")]
        if ((expected and (len(extracted) != 1 or any(
                (materials / extracted[0]["path"]).read_bytes() != text.encode("utf-8")
                for text in expected))) or (not expected and extracted)):
            raise ValueError("Extracted license collection differs from the normalized inventory")
        if sources and any(f["role"] == "embedded-source-license-text" for f in files):
            raise ValueError("Archive dependency cannot substitute an embedded-source notice")
        if not sources and any(f["role"] != "embedded-source-license-text" for f in files):
            raise ValueError("Unsupported extra embedded-source notice")
        records = []
        allowed = {(r["target"], r["sha256"]) for s in sources
                   for r in s.get("originalBuildRecords", [])}
        for r in row.get("originalBuildRecords", []):
            if ((r["target"], r["sha256"]) not in allowed
                    or manifest["files"].get(r["path"]) != r["sha256"]):
                raise ValueError("Supplemental notice lacks an original-record binding")
            references.add(r["path"])
            records.append(json.loads((materials / r["path"]).read_text()))
        for f in files:
            if f["role"] == "pinned-source-notice-context" and not any(
                    {"path": f["sourcePath"], "sha256": f["sha256"]}.items() <= p.items()
                    for record in records for p in record["sourceFiles"]):
                raise ValueError("Supplemental source notice differs from original source bytes")
            if f["role"] == SOURCE_CONTEXT:
                acquisition = f["acquisition"]
                expected_sha = acquisition["archiveSha256"]
                if (manifest["files"].get(acquisition["archivePath"]) != expected_sha
                        or not any(s.get("sourceArchive", {}).get("sha256") == expected_sha
                                   for s in sources)):
                    raise ValueError("Source-distribution context lacks its pinned source archive")
                references.add(acquisition["archivePath"])
                with tarfile.open(relative_path(materials, acquisition["archivePath"]), "r:*") as tar:
                    members = [m for m in tar.getmembers() if m.name == acquisition["member"]]
                    if (len(members) != 1 or not members[0].isfile()
                            or members[0].size > 2 * 1024 * 1024
                            or tar.extractfile(members[0]).read() !=
                            (materials / f["path"]).read_bytes()):
                        raise ValueError("Source-distribution context differs from its source archive")
    if references != set(manifest["files"]):
        raise ValueError("Unreferenced notice material is not part of this delivery")
    return manifest


def render(materials, manifest):
    lines = [
        "cURL candidate third-party notice review materials",
        "================================================",
        "",
        "NOT APPROVED FOR PRODUCTION. This is a notice-input delivery, not a complete",
        "corresponding-source/object kit, host-installation proof or legal certification.",
        "The product's own MIT license does not relicense third-party code.",
        "Package identities and license assertions come from the normalized inventory.",
        "Source-context files retain complete original comments and may also contain code.",
        "A source-distribution license context is not an additional binary-license conclusion.",
        "Raw files, including distinct Windows line-ending variants, remain unchanged in inputs/.",
        "",
        "Referenced artifact: " + manifest["referencedArtifact"]["name"],
        "Inventory SHA-256: " + manifest["inventorySha256"],
    ]
    for row in manifest["components"]:
        lines += ["", "=" * 72, row["name"] + " " + row.get("version", "(version not verified)"),
                  "Targets: " + ", ".join(row["targets"])]
        if row.get("declaredLicense"):
            lines.append("Inventory license: " + row["declaredLicense"])
        if row.get("supplementalScope"):
            lines.append(row["supplementalScope"])
        for f in row["files"]:
            lines += ["", "--- " + f["role"] + ": " + f["sourcePath"] + " ---",
                      "Complete original input: inputs/" + f["path"],
                      "SHA-256: " + f["sha256"], "",
                      (materials / f["path"]).read_bytes().decode("utf-8")]
    return ("\n".join(lines) + "\n").encode("utf-8")


def inspect_delivery(output, inventory):
    record = json.loads((output / OUTPUT).read_text())
    if (record.get("schemaVersion") != 1 or record.get("evidenceType") != "candidate-notice-delivery"
            or record.get("status") != "not-approved-for-production"
            or record["inventorySha256"] != digest(inventory)):
        raise ValueError("Notice delivery identity changed")
    verify_tree(output, record["files"], OUTPUT)
    manifest = inspect(output / "inputs", inventory)
    if (record["inputManifestSha256"] != digest(output / "inputs" / INPUT)
            or (output / "NOTICES.txt").read_bytes() != render(output / "inputs", manifest)):
        raise ValueError("Rendered notices differ from the verified original inputs")
    return {"logicalComponents": len({identity(c) for c in manifest["components"]}),
            "componentNoticeVariants": len(manifest["components"]),
            "noticeInputs": sum(len(c["files"]) for c in manifest["components"]),
            "selectedArchiveBindings": sum(len(c["selectedArchiveBindings"])
                                          for c in manifest["components"]),
            "status": record["status"], "deliveryManifestSha256": digest(output / OUTPUT)}


def deliver(materials, inventory, output):
    manifest = inspect(materials, inventory)
    if output.exists() or output.resolve().is_relative_to(materials.resolve()):
        raise ValueError("Notice delivery needs a fresh output outside its inputs")
    output.mkdir(parents=True)
    shutil.copytree(materials, output / "inputs")
    (output / "NOTICES.txt").write_bytes(render(materials, manifest))
    files = archive_hashes(output, sorted(p.relative_to(output).as_posix()
                                        for p in output.rglob("*") if p.is_file()))
    write_json(output / OUTPUT, {
        "schemaVersion": 1, "evidenceType": "candidate-notice-delivery",
        "status": "not-approved-for-production", "inventorySha256": digest(inventory),
        "inputManifestSha256": digest(materials / INPUT),
        "files": {p["path"]: p["sha256"] for p in files},
        "scope": "Inventory-bound notice inputs, not complete redistribution or host verification.",
    })
    return inspect_delivery(output, inventory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--materials", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    if not args.inspect_only and args.materials is None:
        parser.error("--materials is required when creating a delivery")
    result = (inspect_delivery(args.output, args.inventory) if args.inspect_only
              else deliver(args.materials, args.inventory, args.output))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
