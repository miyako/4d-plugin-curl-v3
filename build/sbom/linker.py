#!/usr/bin/env python3
"""Conservative linker diagnostics; never inspects or executes native binaries."""

import argparse
import hashlib
import json
import ntpath
from pathlib import Path
import re


LIMITATIONS = (
    "Archive member selection is not proof of live contribution. Dead stripping, "
    "COMDAT folding and LTO can remove, merge or synthesize code. Map symbols are "
    "limited observations, not a complete inventory of live code or dependencies."
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_member(text):
    text = text.strip()
    match = re.match(r"^(.*\.(?:a|lib))(?:\[\d+\])?\((.*)\)$", text, re.I)
    if not match:
        match = re.match(r"^(.*\.(?:a|lib))\[(.*)\]$", text, re.I)
    return match.groups() if match else None


def parse_apple(text, arch):
    """Apple ld classic archive(member) and modern archive[member] maps."""
    header = re.search(r"^# Arch:\s*(\S+)", text, re.M)
    if not header or header[1] != arch:
        raise ValueError(f"Link map architecture does not match {arch}")
    objects, symbols = {}, []
    section = None
    for line in text.splitlines():
        if line in ("# Object files:", "# Sections:", "# Symbols:",
                    "# Dead Stripped Symbols:"):
            section = line[2:].strip()
        if section == "Object files:":
            match = re.match(r"\[\s*(\d+)\]\s+(.+)", line)
            if match:
                member = archive_member(match[2])
                if member:
                    objects[match[1]] = {
                        "archive": member[0], "member": member[1],
                        "selection": "map-object-table",
                        "liveSymbolCount": 0, "deadSymbolCount": 0,
                    }
        elif section in ("Symbols:", "Dead Stripped Symbols:"):
            match = re.match(r"(?:0x[0-9a-f]+|<<dead>>)\s+0x[0-9a-f]+\s+"
                             r"\[\s*(\d+)\]\s+(.+)", line, re.I)
            if match and match[1] in objects:
                dead = section == "Dead Stripped Symbols:"
                objects[match[1]]["deadSymbolCount" if dead else "liveSymbolCount"] += 1
                symbols.append({"objectIndex": match[1], "symbol": match[2],
                                "status": "dead-stripped" if dead else "map-live-symbol",
                                "archivePath": objects[match[1]]["archive"],
                                "member": objects[match[1]]["member"]})
    if not re.search(r"^# Object files:", text, re.M):
        raise ValueError("Missing Apple object table")
    return list(objects.values()), symbols


def parse_msvc(verbose, map_text):
    """Combine explicit loads or positive map attribution with resolved searches."""
    if "Publics by Value" not in map_text:
        raise ValueError("Missing MSVC map public symbol table")
    selected, searching, found, searched = [], None, None, {}
    for line in verbose.splitlines():
        match = re.match(r"\s*Searching\s+(.+):\s*$", line)
        if match:
            searching, found = match[1].strip().strip('"'), None
            searched[ntpath.normcase(ntpath.normpath(searching))] = searching
        match = re.match(r"\s*Found\s+(.+)", line)
        if match:
            found = match[1].strip()
        match = re.match(r"\s*Loaded\s+(.+?)\s*$", line)
        if match:
            pair = archive_member(match[1])
            if not pair:
                continue
            archive, member = pair
            # Only contextualize a bare Loaded basename with its explicit search.
            if (ntpath.basename(archive) == archive and searching
                    and ntpath.basename(searching).lower() == archive.lower()):
                archive = searching
            selected.append({"archive": archive, "member": member,
                             "selection": "verbose-loaded", "foundSymbol": found,
                             "liveSymbolCount": 0})
    symbols = []
    public = False
    for line in map_text.splitlines():
        if "Publics by Value" in line or "Static symbols" in line:
            public = True
            continue
        if not public:
            continue
        match = re.match(r"\s*[0-9a-f]+:[0-9a-f]+\s+(\S+)\s+[0-9a-f]+"
                         r"\s+(?:[fi]\s+)*(.+?)\s*$", line, re.I)
        if match and ":" in match[2]:
            lib, obj = match[2].rsplit(":", 1)
            symbols.append({"symbol": match[1], "libraryLabel": lib,
                            "member": obj})
    # LTCG can emit only Searching lines. A positive map member attribution plus
    # one explicit searched file establishes selection; a search alone does not.
    possible = {}
    for path in [*searched.values(), *(item["archive"] for item in selected)]:
        label = ntpath.splitext(ntpath.basename(path))[0].lower()
        possible.setdefault(label, {})[ntpath.normcase(ntpath.normpath(path))] = path
    represented = {(ntpath.normcase(ntpath.normpath(item["archive"])),
                    item["member"].lower()) for item in selected}
    for symbol in symbols:
        label = ntpath.splitext(ntpath.basename(symbol["libraryLabel"]))[0].lower()
        choices = possible.get(label, {})
        symbol["pathCandidates"] = sorted(choices.values())
        if len(choices) != 1:
            continue
        key, archive = next(iter(choices.items()))
        identity = (key, symbol["member"].lower())
        if identity not in represented:
            selected.append({
                "archive": archive, "member": symbol["member"],
                "selection": "map-symbol-and-unique-diagnostic-path",
                "foundSymbol": symbol["symbol"], "liveSymbolCount": 0,
            })
            represented.add(identity)
    return selected, symbols


def collect(root, target, diagnostic_paths, candidates):
    """Return one target's linkEvidence. Relative paths use root as linker cwd.

    diagnostic_paths: {"map": path, "verbose": path (Windows only)}.
    candidates: iterable of {"path": repo-relative or absolute path, "sha256": ...}.
    Foreign absolute Windows paths are retained, never relocated by basename.
    Returns archives[] with selectedMembers, liveSymbols and deadSymbols.
    candidatePath is emitted only for repo-local, path-and-hash-matched inputs.
    selectedArchives is a compatibility alias for archives.
    """
    root = Path(root).resolve()
    windows = target == "windows-x86_64"
    if target not in ("macos-arm64", "macos-x86_64", "windows-x86_64"):
        raise ValueError(f"Unsupported link target: {target}")

    def resolve(raw):
        if windows and ntpath.isabs(raw) and not Path(raw).is_absolute():
            return None, ntpath.normcase(ntpath.normpath(raw))
        path = Path(raw.replace("\\", "/") if windows else raw)
        path = (root / path).resolve()
        key = str(path).lower() if windows else str(path)
        return path, key

    indexed = {}
    for candidate in candidates:
        _, key = resolve(candidate["path"])
        indexed.setdefault(key, []).append(candidate)
    raw, texts = [], {}
    for kind in (("map", "verbose") if windows else ("map",)):
        if not diagnostic_paths.get(kind):
            raise ValueError(f"{target} requires {kind} diagnostics")
        path = Path(diagnostic_paths[kind])
        path = (root / path).resolve()
        data = path.read_bytes()
        raw.append({"kind": kind, "path": str(path),
                    "sha256": hashlib.sha256(data).hexdigest()})
        texts[kind] = data.decode("utf-8-sig", errors="replace")
    if windows:
        selected, symbols = parse_msvc(texts["verbose"], texts["map"])
    else:
        selected, symbols = parse_apple(texts["map"], target.removeprefix("macos-"))

    archives = {}
    for item in selected:
        path, key = resolve(item["archive"])
        if key not in archives:
            record = {"reportedPath": item["archive"],
                      "resolvedPath": str(path) if path else ntpath.normpath(item["archive"]),
                      "status": "unresolved-selection", "members": [],
                      "candidatePaths": [c["path"] for c in indexed.get(key, [])]}
            record["scope"] = ("repository" if path and path.is_relative_to(root)
                               else "external")
            record["resolution"] = ("foreign-host-path" if path is None else "missing-file")
            if path and path.is_file():
                record["sha256"] = digest(path)
                record["resolution"] = "existing-file"
                for candidate in indexed.get(key, []):
                    if candidate.get("sha256") and candidate["sha256"] != record["sha256"]:
                        raise ValueError(f"Selected archive hash mismatch: {path}")
                if path.is_relative_to(root) and any(
                        c.get("sha256") == record["sha256"] for c in indexed.get(key, [])):
                    record["candidatePath"] = path.relative_to(root).as_posix()
                record["status"] = ("selected-repository-candidate" if key in indexed
                                    else "selected-existing-untracked")
            archives[key] = record
        archives[key]["members"].append(item)

    if windows:
        for symbol in symbols:
            if len(symbol.get("pathCandidates", [])) > 1:
                symbol["status"] = "ambiguous-map-library"
                continue
            label = ntpath.basename(symbol["libraryLabel"]).lower()
            keys = [key for key, archive in archives.items()
                    if ntpath.splitext(ntpath.basename(archive["reportedPath"]))[0].lower()
                    == ntpath.splitext(label)[0]]
            symbol["status"] = "ambiguous-map-library" if len(keys) > 1 else "unresolved-map-library"
            if len(keys) == 1:
                matches = [m for m in archives[keys[0]]["members"]
                           if m["member"].lower() == symbol["member"].lower()]
                if len(matches) == 1:
                    matches[0]["liveSymbolCount"] += 1
                    symbol["status"] = "map-live-symbol"
                    symbol["archivePath"] = archives[keys[0]]["reportedPath"]
    for key, archive in archives.items():
        archive["selectedMembers"] = sorted({m["member"] for m in archive["members"]})
        attributed = [s for s in symbols if s.get("archivePath")
                      and resolve(s["archivePath"])[1] == key]
        archive["liveSymbols"] = [s for s in attributed if s["status"] == "map-live-symbol"]
        archive["deadSymbols"] = [s for s in attributed if s["status"] == "dead-stripped"]
    selections = list(archives.values())
    return {"target": target, "evidenceType": "linker-diagnostics",
            "limitations": LIMITATIONS, "diagnostics": raw,
            "archives": selections, "selectedArchives": selections, "mapSymbols": symbols}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--target", required=True)
    parser.add_argument("--map", required=True)
    parser.add_argument("--verbose")
    parser.add_argument("--candidates", type=Path,
                        help="JSON array, or record with declaredInputs")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    candidates = json.loads(args.candidates.read_text()) if args.candidates else []
    if isinstance(candidates, dict):
        candidates = candidates["declaredInputs"]
    result = collect(args.root, args.target, {"map": args.map, "verbose": args.verbose}, candidates)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
