"""Account for actual repository archive selections, not project declarations."""


def selected_archive_coverage(target):
    record = target.get("buildEvidence", {})
    selections = record.get("linkEvidence", {}).get(target["id"], {}).get("archives", [])
    selected = {}
    for archive in selections:
        path, digest = archive.get("candidatePath"), archive.get("sha256")
        if path and digest:
            if path in selected and selected[path] != digest:
                raise ValueError(f"Conflicting selected archive hashes: {path}")
            selected[path] = digest
    named, versioned = set(), set()
    unknown_versions = set()
    for package in target["dependencies"]:
        for archive in package.get("selectedArchives", []):
            path = archive.get("candidatePath")
            if path not in selected or archive.get("sha256") != selected[path]:
                raise ValueError(f"Package selection is not an actual selected archive: {path}")
            named.add(path)
            if package.get("version"):
                versioned.add(path)
            else:
                unknown_versions.add(package["name"])
    return {
        "selectedRepositoryArchives": len(selected),
        "namedPackageArchives": len(named),
        "versionedPackageArchives": len(versioned),
        "unknownVersionPackages": sorted(unknown_versions),
        "uncoveredArchives": sorted(set(selected) - named),
    }


def require_selected_coverage(target):
    result = selected_archive_coverage(target)
    if result["uncoveredArchives"]:
        raise ValueError(f"{target['id']}: selected repository archives lack named packages: "
                         + ", ".join(result["uncoveredArchives"]))
    return result


def require_selected_source_coverage(target):
    """Require source bindings after ingestion has verified the original kits."""
    result = require_selected_coverage(target)
    if not result["selectedRepositoryArchives"]:
        raise ValueError("Source coverage requires actual selected repository archives")
    expected_targets = ({"macos-arm64", "macos-x86_64"} if target["id"].startswith("macos-")
                        else {"windows-x86_64"})
    source_bound = set()
    for package in target["dependencies"]:
        identities = package.get("archiveIdentities", [])
        by_path = {a["path"]: a["identity"] for a in identities}
        if len(by_path) != len(identities):
            raise ValueError("Duplicate selected archive source identity")
        for selected in package.get("selectedArchives", []):
            path = selected["candidatePath"]
            identity = by_path.get(path, {})
            source = identity.get("sourceEvidence", {})
            if (identity.get("evidenceType") != "source-build-and-selected-archive"
                    or identity.get("name") != package["name"]
                    or source.get("name") != package["name"]
                    or {"path": path, "sha256": selected["sha256"]}
                    not in source.get("archives", [])):
                raise ValueError(f"{target['id']}: selected archive lacks source binding: {path}")
            originals = source.get("originalBuildRecords", [])
            if originals and package["name"] not in ("OpenSSL", "Brotli"):
                if (len(originals) != len(expected_targets)
                        or {r["target"] for r in originals} != expected_targets
                        or any(not r.get("sha256") or not r.get("recipeFiles")
                               or not r.get("toolchain") for r in originals)):
                    raise ValueError("Selected native source requires complete original build references")
            elif package["name"] in ("OpenSSL", "Brotli"):
                builds = source.get("source_builds", [])
                if (len(builds) != len(expected_targets)
                        or {r["target"] for r in builds} != expected_targets):
                    raise ValueError("Selected provider requires all original native targets")
                for build in builds:
                    original = build["record"] if package["name"] == "Brotli" else build
                    material = original.get("buildMaterialEvidence", {})
                    original_sha = material.get("originalRecordSha256")
                    commit = original.get("sourceCommit", original.get("source_commit"))
                    if (material.get("schemaVersion") != 1 or not original_sha
                            or material.get("sourceCommit") != commit
                            or not material.get("sourceFiles") or not material.get("materialFiles")
                            or (package["name"] == "Brotli"
                                and build.get("originalRecordSha256") != original_sha)
                            or not any(a["path"].split("/")[-1] == path.split("/")[-1]
                                       and a.get("objectMembers", 0) > 0
                                       for a in material.get("archives", []))):
                        raise ValueError("Selected provider lacks original compiler/object materials")
            else:
                raise ValueError("Selected archive lacks verified original source build references")
            source_bound.add(path)
    if len(source_bound) != result["selectedRepositoryArchives"]:
        raise ValueError("Selected repository archive source coverage is incomplete")
    return {**result, "sourceBoundArchives": len(source_bound)}
