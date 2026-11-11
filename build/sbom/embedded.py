"""Versioned embedded inputs: third-party SDK/parser and first-party product source."""

import copy
import json
from pathlib import Path
import re
import subprocess

import embedded_v1 as legacy
import sdk_reviewed


TARGETS = legacy.TARGETS
EVIDENCE = legacy.EVIDENCE
WITNESSES = legacy.WITNESSES
sha256 = legacy.sha256
_file = legacy._file
_openstep = legacy._openstep
SDK_COMMIT = "ad7944bc7a13d93db8097c4c8ff55ba2f6e36f86"
PIN_PATH = "build/sbom/sdk-pin.json"
LIMITATIONS = [
    legacy.LIMITATIONS[0],
    "Reviewed third-party compiled source and first-party product helpers only; "
    "other vendor headers, host APIs, toolchain and resources are outside coverage.",
    legacy.LIMITATIONS[2],
    legacy.LIMITATIONS[3],
    "First-party ownership is not an independent package version or a new license "
    "grant. Existing notices and the repository license scope remain unchanged.",
]

# Populated with reviewed exact bytes when the SDK pin is updated, not at collection.
HASHES = {
    p: h for p, h in legacy.HASHES.items()
    if not p.startswith("include/json/") and
    (not p.startswith("4D Plugin API/") or "/Classes/" in p)
}
CRLF_HASHES = {p: legacy.CRLF_HASHES[p] for p in HASHES}
LF_HASHES = {p: legacy.LF_HASHES[p] for p in HASHES if p in legacy.LF_HASHES}
HASHES.update(sdk_reviewed.HASHES)
CRLF_HASHES.update(sdk_reviewed.CRLF_HASHES)
LF_HASHES.update(sdk_reviewed.LF_HASHES)
SDK_PIN = sdk_reviewed.SDK_PIN


def _approved_hashes(path):
    return {HASHES[path], CRLF_HASHES[path], LF_HASHES.get(path, HASHES[path])}


def _components(target):
    components = legacy._components(target)[:5]
    for component in components:
        if component["id"] == "embedded-4d-sdk":
            component.update(
                origin=legacy.SDK + "/tree/" + SDK_COMMIT,
                sourceCommit=SDK_COMMIT,
                version=SDK_COMMIT,
                purl="pkg:github/4d/4D-Plugin-SDK@" + SDK_COMMIT,
                limitations=[
                    "Exact upstream commit, not a release tag. The SDK's own MIT "
                    "license does not relicense local Classes or product helpers. "
                    "All SDK source/license bytes match the pinned upstream snapshot.",
                ],
            )
            component["licenseText"] = legacy._license(
                "MIT", "MIT License", sdk_reviewed.SDK_LICENSE_TEXT,
                legacy.SDK_LICENSE_URL, legacy.SDK_ATTRIBUTION,
            )
            component["sourceFiles"].extend([
                {"path": "4D Plugin API/LICENSE.md", "sha256": HASHES["4D Plugin API/LICENSE.md"],
                 "role": "license"},
                {"path": "4D Plugin API/Readme.md", "sha256": HASHES["4D Plugin API/Readme.md"],
                 "role": "source-metadata"},
            ])
        elif component["id"] != "embedded-ftpparse":
            component.update(scope="first-party-product-source",
                             origin=legacy.REPOSITORY,
                             limitations=[
                                 "User-owned product implementation, not an independently "
                                 "packaged/versioned third-party dependency. Ownership does "
                                 "not establish an imported license or erase source notices.",
                             ])
        for source in component["sourceFiles"]:
            source["sha256"] = HASHES[source["path"]]
        component["sourceFiles"].sort(key=lambda row: row["path"])
    return components


def _expected_lists(target):
    files = [f for c in _components(target) for f in c["sourceFiles"]]
    return (
        sorted([f["path"] for f in files if f["role"] == "translation-unit"] + [WITNESSES[0]]),
        sorted([f["path"] for f in files if f["role"] == "header-interface"] + [WITNESSES[1]]),
    )


def collect(root, target):
    if target not in TARGETS:
        raise ValueError("Unsupported embedded-source target")
    root = Path(root)
    project = legacy._project(target)
    data = _file(root, project)
    parser = legacy._msbuild if target == "windows-x86_64" else legacy._xcode
    sources, headers, directories = parser(data)
    if (sorted(sources), sorted(headers)) != _expected_lists(target):
        raise ValueError("Project source/header lists differ from reviewed coverage")
    components = _components(target)
    for component in components:
        for source in component["sourceFiles"]:
            digest = sha256(_file(root, source["path"]))
            if digest not in _approved_hashes(source["path"]):
                raise ValueError("Unreviewed embedded source hash: " + source["path"])
            source["sha256"] = digest
    plugin_header = _file(root, WITNESSES[1]).decode("utf-8")
    for name in ("4DPluginAPI.h", "4DPlugin-JSON.h", "ftpparse.h",
                 "C_TEXT.h", "C_BLOB.h", "C_LONGINT.h"):
        if not re.search(r'^\s*#include\s+"' + re.escape(name) + r'"', plugin_header, re.M):
            raise ValueError("Missing reviewed plugin include: " + name)
    if re.search(r'json[/\\]json\.h|jsoncpp|libjson', plugin_header + data.decode("utf-8"), re.I):
        raise ValueError("Obsolete JSON dependency declaration")
    commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    record = {
        "schemaVersion": 2, "target": target, "evidenceType": EVIDENCE,
        "productSource": {"repository": legacy.REPOSITORY, "commit": commit,
                          "binding": "exact source hashes and build declarations below"},
        "sdkPin": json.loads(_file(root, PIN_PATH)),
        "configuration": [{"path": project, "sha256": sha256(data)}],
        "declarations": {"translationUnits": sorted(sources), "headers": sorted(headers),
                         "includeDirectories": directories},
        "sourceWitnesses": [{"path": p, "sha256": sha256(_file(root, p))} for p in WITNESSES],
        "components": components, "limitations": list(LIMITATIONS),
    }
    return validate(record, target)


def validate(record, target=None):
    if not isinstance(record, dict):
        raise ValueError("Invalid embedded-source record")
    if type(record.get("schemaVersion")) is int and record["schemaVersion"] == 1:
        return legacy.validate(record, target)
    actual_target = record.get("target")
    if (type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 2
            or actual_target not in TARGETS or (target is not None and target != actual_target)
            or record.get("evidenceType") != EVIDENCE):
        raise ValueError("Unsupported embedded-source record/target")
    expected = _components(actual_target)
    components = record.get("components")
    if not isinstance(components, list) or len(components) != len(expected):
        raise ValueError("Embedded source identity/hash/license metadata mismatch")
    for component, model in zip(components, expected):
        files = component.get("sourceFiles") if isinstance(component, dict) else None
        if not isinstance(files, list) or len(files) != len(model["sourceFiles"]):
            raise ValueError("Embedded source identity/hash/license metadata mismatch")
        for source, original in zip(files, model["sourceFiles"]):
            digest = source.get("sha256") if isinstance(source, dict) else None
            if not isinstance(digest, str) or digest not in _approved_hashes(original["path"]):
                raise ValueError("Embedded source identity/hash/license metadata mismatch")
            original["sha256"] = digest
    if components != expected:
        raise ValueError("Embedded source identity/hash/license metadata mismatch")
    sources, headers = _expected_lists(actual_target)
    declarations = record.get("declarations")
    if (not isinstance(declarations, dict)
            or set(declarations) != {"translationUnits", "headers", "includeDirectories"}
            or declarations["translationUnits"] != sources or declarations["headers"] != headers
            or not isinstance(declarations["includeDirectories"], list)
            or not declarations["includeDirectories"]
            or not all(isinstance(d, str) and d for d in declarations["includeDirectories"])):
        raise ValueError("Invalid embedded-source declarations")
    for key, paths in (("configuration", [legacy._project(actual_target)]),
                       ("sourceWitnesses", list(WITNESSES))):
        rows = record.get(key)
        if (not isinstance(rows, list) or len(rows) != len(paths)
                or any(not isinstance(row, dict) or set(row) != {"path", "sha256"}
                       or row["path"] != path or not isinstance(row["sha256"], str)
                       or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
                       for row, path in zip(rows, paths))):
            raise ValueError("Invalid embedded-source " + key)
    product = record.get("productSource")
    if (not isinstance(product, dict) or set(product) != {"repository", "commit", "binding"}
            or product["repository"] != legacy.REPOSITORY
            or not isinstance(product["commit"], str)
            or not re.fullmatch(r"[a-f0-9]{40}", product["commit"])
            or product["binding"] != "exact source hashes and build declarations below"):
        raise ValueError("Invalid product source provenance")
    if record.get("sdkPin") != SDK_PIN:
        raise ValueError("Invalid immutable SDK pin metadata")
    if (record.get("limitations") != LIMITATIONS or set(record) != {
            "schemaVersion", "target", "evidenceType", "productSource", "sdkPin",
            "configuration", "declarations", "sourceWitnesses", "components", "limitations"}):
        raise ValueError("Invalid embedded-source coverage metadata")
    return record


def verify(record, root, target):
    validate(record, target)
    if record != collect(root, target):
        raise ValueError("Embedded source record does not match current build inputs")
    return copy.deepcopy(record)


def verify_record(record, root=None):
    validate(record)
    if root is not None:
        return verify(record, root, record["target"])
    return copy.deepcopy(record)
