#!/usr/bin/env python3
"""Validate official schemas and release identity/target/hash invariants."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

from jsonschema import Draft7Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

import generate


CDX_BASE = (
    "https://raw.githubusercontent.com/CycloneDX/specification/"
    "55343ba19dee1785acf1ce9191540d5fd7b590db/schema/"
)
SPDX_URL = (
    "https://raw.githubusercontent.com/spdx/spdx-spec/"
    "aadf3b0b8dbbabdb4d880b0fc714255fea436ff7/schemas/spdx-schema.json"
)


def load_schemas(directory):
    directory.mkdir(parents=True, exist_ok=True)
    schemas = {}
    for name, url in {
        "bom-1.6.schema.json": CDX_BASE + "bom-1.6.schema.json",
        "spdx.schema.json": CDX_BASE + "spdx.schema.json",
        "jsf-0.82.schema.json": CDX_BASE + "jsf-0.82.schema.json",
        "spdx-2.3.schema.json": SPDX_URL,
    }.items():
        file = directory / name
        if not file.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                file.write_bytes(response.read())
        schemas[name] = json.loads(file.read_text(encoding="utf-8"))
    resources = [
        ("http://cyclonedx.org/schema/" + name, Resource.from_contents(schema))
        for name, schema in schemas.items() if name != "spdx-2.3.schema.json"
    ]
    return schemas, Registry().with_resources(resources)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_documents(inv, cdx, spdx, path, version, schemas, registry):
    for name, doc in [("bom-1.6.schema.json", cdx), ("spdx-2.3.schema.json", spdx)]:
        Draft7Validator(schemas[name], registry=registry,
                        format_checker=Draft7Validator.FORMAT_CHECKER).validate(doc)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    require(inv["artifact"] == {"name": path.name, "sha256": digest}, "Artifact hash/name mismatch")
    require(inv["version"] == version, "Inventory release version mismatch")
    root = cdx["metadata"]["component"]
    require(root["name"] == "cURL" and root["version"] == version
            and root["supplier"]["name"] == generate.SUPPLIER, "CycloneDX root identity mismatch")
    require(root["hashes"] == [{"alg": "SHA-256", "content": digest}],
            "CycloneDX artifact hash mismatch")
    require(root["properties"] == [{"name": "release:artifact", "value": path.name}],
            "CycloneDX artifact filename mismatch")
    packages = {p["SPDXID"]: p for p in spdx["packages"]}
    release = packages["SPDXRef-release"]
    require(release["name"] == "cURL" and release["versionInfo"] == version
            and release["supplier"] == "Person: " + generate.SUPPLIER
            and release["packageFileName"] == path.name, "SPDX root identity mismatch")
    require(release["checksums"] == [{"algorithm": "SHA256", "checksumValue": digest}],
            "SPDX artifact hash mismatch")
    require({t["id"] for t in inv["targets"]} ==
            {"macos-arm64", "macos-x86_64", "windows-x86_64"}, "Missing/extra target")
    require("incomplete" == cdx["compositions"][0]["aggregate"],
            "Partial coverage must be declared")
    components = {c["bom-ref"]: c for c in cdx["components"]}
    rows = list(generate.component_rows(inv))
    require(len(components) == len(cdx["components"]) == len(rows), "CycloneDX duplicate/missing rows")
    require(len(packages) == len(spdx["packages"]) == len(rows) + 1, "SPDX duplicate/missing rows")
    for target in inv["targets"]:
        curl = [d for d in target["dependencies"] if d["name"] == "curl"]
        require(len(curl) == 1 and curl[0]["version"], f"Missing curl identity: {target['id']}")
    for row in rows:
        component = components[row["id"]]
        package = packages["SPDXRef-" + row["id"]]
        require(component["name"] == package["name"] == row["name"]
                and component.get("version") == package.get("versionInfo") == row.get("version"),
                f"Cross-format component mismatch: {row['id']}")
        require(component["description"] == package["description"] == row["description"],
                f"Lost evidence/target distinction: {row['id']}")
        require(component["properties"] == [{"name": "release:target", "value": row["target"]}],
                f"Lost CycloneDX target property: {row['id']}")
        if "sha256" in row:
            require(component["hashes"] == [{"alg": "SHA-256", "content": row["sha256"]}]
                    and package["checksums"] ==
                    [{"algorithm": "SHA256", "checksumValue": row["sha256"]}],
                    f"Binary/slice hash mismatch: {row['id']}")
    expected_cdx, expected_spdx = generate.cyclonedx(inv), generate.spdx(inv)
    require(cdx["metadata"].get("tools") == expected_cdx["metadata"]["tools"]
            and spdx["creationInfo"] == expected_spdx["creationInfo"],
            "SBOM generator identity mismatch")
    require(cdx["components"] == expected_cdx["components"],
            "CycloneDX package identity/license/origin evidence mismatch")
    require(cdx.get("dependencies") == expected_cdx.get("dependencies"),
            "CycloneDX build-supported dependency mismatch")
    require(spdx["packages"] == expected_spdx["packages"],
            "SPDX package identity/license/origin evidence mismatch")
    require(spdx["relationships"] == expected_spdx["relationships"],
            "SPDX containment/build-supported dependency mismatch")
    require(spdx.get("hasExtractedLicensingInfos") == expected_spdx.get("hasExtractedLicensingInfos"),
            "SPDX extracted license evidence mismatch")
    # Re-read actual container members, checking architecture, version, markers and
    # evidence-to-binary bindings rather than trusting the inventory's assertions.
    evidence = {}
    for target in inv["targets"]:
        if "buildEvidence" in target:
            record = target["buildEvidence"]
            evidence[record["target"]] = record
    actual = generate.inventory(path, version, evidence)
    actual["created"] = inv["created"]
    require(actual == inv, "Inventory disagrees with packaged binary observations")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("artifacts", type=Path, nargs="+")
    args = parser.parse_args()
    schemas, registry = load_schemas(args.schema_dir)
    for path in args.artifacts:
        docs = [
            json.loads((args.output / (path.name + "." + suffix)).read_text(encoding="utf-8"))
            for suffix in ("inventory.json", "cdx.json", "spdx.json")
        ]
        validate_documents(*docs, path, args.version, schemas, registry)
        print(f"Validated schemas, identity, hashes, native observations and targets: {path.name}")


if __name__ == "__main__":
    try:
        main()
    except ValidationError as error:
        print(f"SBOM schema error at {error.json_path}: {error.message}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError, OSError) as error:
        print(f"SBOM validation error: {error}", file=sys.stderr)
        sys.exit(1)
