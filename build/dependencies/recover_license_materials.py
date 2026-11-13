#!/usr/bin/env python3
"""Recover exact-hash notices for the measured all-source plugin inventory."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.request
from urllib.parse import urlsplit


def sha(data):
    return hashlib.sha256(data).hexdigest()


def recover(originals, curl_archive, providers, output):
    inventory_path = originals / "unsigned-native-sboms/unsigned-native.zip.inventory.json"
    inventory_bytes = inventory_path.read_bytes()
    inventory = json.loads(inventory_bytes)
    if output.exists() or inventory["inventoryVersion"] != 1:
        raise ValueError("Use fresh output and the measured normalized inventory")
    output.mkdir(parents=True)
    for folder in ("texts", "records", "archives"):
        (output / folder).mkdir()
    (output / "inventory.json").write_bytes(inventory_bytes)
    manifest = {
        "schemaVersion": 1, "evidenceType": "inventory-referenced-notice-input-recovery",
        "status": "not-approved-for-production", "inventorySha256": sha(inventory_bytes),
        "referencedArtifact": inventory["artifact"], "components": [],
        "scope": "Exact-hash notice input recovery. Original review status is retained; "
                 "release authorization and final signed-artifact bindings are separate. "
                 "Not a legal-compliance certification or historical archive provenance.",
    }
    components = {}
    for target in inventory["targets"]:
        for dependency in target["dependencies"]:
            first = dependency.get("archiveIdentities", [{}])[0].get("identity", {}).get(
                "sourceEvidence", {})
            signature = (first.get("licenseFileSha256"),
                         json.dumps(first.get("additionalNoticeFiles", []), sort_keys=True))
            key = (dependency["name"], dependency.get("version"), dependency.get("purl"), signature)
            group = components.setdefault(key, {"dependency": dependency, "targets": [],
                                                "bindings": [], "dependencies": []})
            group["dependencies"].append(dependency)
            group["targets"].append(target["id"])
            group["bindings"].extend({"target": target["id"], **archive}
                                      for archive in dependency.get("selectedArchives", []))

    for (name, version, purl, _), group in components.items():
        dependency = group["dependency"]
        entry = {"name": name, "targets": group["targets"], "files": [],
                 "selectedArchiveBindings": group["bindings"]}
        if version is not None:
            entry["version"] = version
        if purl:
            entry["purl"] = purl
        if dependency.get("license"):
            entry["declaredLicense"] = dependency["license"]

        def retain(path, data, expected, acquisition, role):
            if expected is not None and sha(data) != expected:
                raise ValueError("Notice differs from measured source: " + name + "/" + path)
            destination = "texts/" + sha(data)
            (output / destination).write_bytes(data)
            entry["files"].append({"sourcePath": path, "sha256": sha(data),
                                   "path": destination, "role": role, "acquisition": acquisition})

        if not dependency.get("archiveIdentities"):
            evidence = dependency.get("licenseText", dependency.get("licenseEvidence"))
            if evidence is None:
                raise ValueError("Missing embedded-source notice evidence")
            retain(evidence["id"], evidence["text"].encode("utf-8"), evidence.get("sha256"),
                   "verbatim normalized inventory text", "embedded-source-license-text")
            manifest["components"].append(entry)
            continue

        source = dependency["archiveIdentities"][0]["identity"]["sourceEvidence"]
        primary = source["licenseFileSha256"]
        if any(a["identity"]["sourceEvidence"]["licenseFileSha256"] != primary
               or a["identity"]["sourceEvidence"].get("additionalNoticeFiles", [])
               != source.get("additionalNoticeFiles", [])
               for d in group["dependencies"] for a in d["archiveIdentities"]):
            raise ValueError("Conflicting target-scoped license inputs")
        notices = list(source.get("additionalNoticeFiles", []))
        if name in ("Brotli", "OpenSSL"):
            provider = providers / ("isolated-provider-materials-" + group["targets"][0])
            base = (provider / "provider-openssl/install" if name == "OpenSSL"
                    else provider / "provider-brotli/vendor")
            filename = source["licenseFile"]
            retain(filename, (base / "build-materials/source" / filename).read_bytes(), primary,
                   {"sourceCommit": source["sourceCommit"]}, "primary-license")
        elif name == "curl":
            pin = source["sourceArchive"]
            if sha(curl_archive.read_bytes()) != pin["sha256"]:
                raise ValueError("Pinned curl release archive changed")
            with tarfile.open(curl_archive, "r:*") as archive:
                for path, expected, role in [(pin["licenseFile"], primary, "primary-license"),
                        *[(p["path"], p["sha256"], "additional-source-notice") for p in notices]]:
                    member = archive.getmember("curl-" + version + "/" + path)
                    if not member.isfile() or member.size > 2 * 1024 * 1024:
                        raise ValueError("Invalid source notice member")
                    retain(path, archive.extractfile(member).read(), expected,
                           {"archiveSha256": pin["sha256"], "url": pin["url"]}, role)
        elif name in ("libiconv", "libproxy", "libmodman"):
            target = group["targets"][0]
            system = "Windows" if target.startswith("windows") else "macOS"
            library = "libiconv" if name == "libiconv" else "libproxy"
            material = (originals / ("isolated-selected-plugin-delivery-" + system)
                        / "Moved selected plugin kit/library-materials" / target / library)
            if name == "libiconv":
                for path, expected, role in [("COPYING.LIB", primary, "primary-license"),
                        *[(p["path"], p["sha256"], "additional-source-notice") for p in notices]]:
                    retain(path, (material / "source" / path).read_bytes(), expected,
                           "verified derived source kit", role)
                archive_path = material / "upstream-source.tar.gz"
                pin = source["sourceArchive"]
                data = archive_path.read_bytes()
                if sha(data) != pin["sha256"]:
                    raise ValueError("Delivered GNU source archive changed")
                relative = "archives/" + pin["sha256"] + ".tar.gz"
                (output / relative).write_bytes(data)
                with tarfile.open(archive_path, "r:*") as archive:
                    member = archive.getmember("libiconv-" + version + "/COPYING")
                    if not member.isfile() or member.size > 2 * 1024 * 1024:
                        raise ValueError("Invalid GNU source-distribution license member")
                    retain("COPYING", archive.extractfile(member).read(), None,
                           {"archiveSha256": pin["sha256"], "url": pin["url"],
                            "archivePath": relative, "member": member.name},
                           "source-distribution-license-context-not-library-license-conclusion")
            else:
                data = (material / "proxy-build-provenance.json").read_bytes()
                original = [r for r in source["originalBuildRecords"] if r["target"] == target]
                if len(original) != 1 or sha(data) != original[0]["sha256"]:
                    raise ValueError("Proxy notice context differs from original build")
                relative = "records/" + sha(data) + ".json"
                (output / relative).write_bytes(data)
                entry["originalBuildRecords"] = [
                    {"target": target, "sha256": sha(data), "path": relative}]
                record = json.loads(data)
                if record["source_commit"] != source["sourceCommit"]:
                    raise ValueError("Proxy source commit changed")
                files = {p["path"]: p["sha256"] for p in record["sourceFiles"]}
                extras = (["libproxy/proxy.cpp", "libproxy/url.cpp", "libproxy/modules/pacutils.h"]
                          if name == "libproxy" else
                          ["libmodman/module_manager.cpp", "libmodman/module_manager.hpp"])
                with tarfile.open(material / "upstream-source.tar", "r:*") as archive:
                    for path, expected, role in [("COPYING", primary, "primary-license"),
                            *[(p, files[p], "pinned-source-notice-context") for p in extras]]:
                        member = archive.getmember(path)
                        if not member.isfile() or member.size > 2 * 1024 * 1024:
                            raise ValueError("Invalid proxy notice member")
                        retain(path, archive.extractfile(member).read(), expected,
                               {"sourceCommit": source["sourceCommit"]}, role)
                if name == "libproxy":
                    entry["supplementalScope"] = (
                        "Complete PAC NPL/GPL/LGPL alternative notice retained; reviewed LGPL "
                        "option for compiled Mac PAC code, not unbuilt Windows PAC code.")
        else:
            origin = urlsplit(dependency["origin"])
            commit = source.get("sourceCommit", source.get("source_commit"))
            repository = origin.path.strip("/").removesuffix(".git")
            if (origin.scheme != "https" or origin.netloc != "github.com"
                    or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
                    or not re.fullmatch(r"[0-9a-f]{40}", commit or "")):
                raise ValueError("Only immutable supported GitHub source acquisitions")
            filename = source.get("licenseFile") or {
                "libssh2": "COPYING", "nghttp2": "COPYING", "nghttp3": "COPYING", "zlib": "LICENSE",
            }[name]
            for path, expected, role in [(filename, primary, "primary-license"),
                    *[(p["path"], p["sha256"], "additional-source-notice") for p in notices]]:
                if (PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                        or "\\" in path or ":" in path):
                    raise ValueError("Noncanonical source notice path")
                url = "https://raw.githubusercontent.com/" + repository + "/" + commit + "/" + path
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise ValueError("Unexpectedly large notice input")
                retain(path, data, expected, {"url": url, "sourceCommit": commit}, role)
        if dependency.get("licenseEvidence"):
            evidence = dependency["licenseEvidence"]
            retain(evidence["id"], evidence["text"].encode("utf-8"), None,
                   "verbatim inventory extracted notice collection", "normalized-license-evidence")
        manifest["components"].append(entry)

    if sum(len(c["selectedArchiveBindings"]) for c in manifest["components"]) != 35:
        raise ValueError("Expected all 35 measured selected archive bindings")
    manifest["files"] = {p.relative_to(output).as_posix(): sha(p.read_bytes())
                         for p in output.rglob("*") if p.is_file()}
    (output / "notice-materials.json").write_text(json.dumps(manifest, indent=2) + "\n")
    import license_materials
    license_materials.inspect(output, inventory_path)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("originals", "curl-archive", "providers", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = recover(args.originals, args.curl_archive, args.providers, args.output)
    print(json.dumps({"noticeVariants": len(result["components"]),
                      "noticeInputs": sum(len(c["files"]) for c in result["components"])}))
