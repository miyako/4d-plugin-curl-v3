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
