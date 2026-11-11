"""Hash-bound native archive inventory; headers and filenames are not versions."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from native_archive_identities import identities as reviewed_identities


MARKERS = {
    "curl": rb"(?:libcurl/|CLIENT libcurl )([0-9]+\.[0-9]+\.[0-9]+(?:[._-][A-Za-z0-9]+)*)",
    "OpenSSL": rb"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+(?:[._-][A-Za-z0-9]+)*) ",
    "libssh2": rb"SSH-2\.0-libssh2_([0-9]+\.[0-9]+\.[0-9]+(?:[._-][A-Za-z0-9]+)*)",
    "zlib": rb"(?:inflate|deflate) ([0-9]+\.[0-9]+\.[0-9]+) Copyright",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identities(data):
    found = []
    for name, pattern in MARKERS.items():
        matches = list(re.finditer(pattern, data))
        versions = {m.group(1).decode("ascii") for m in matches}
        if len(versions) > 1:
            raise ValueError(f"Conflicting archive {name} markers: {sorted(versions)}")
        if matches:
            match = matches[0]
            found.append({
                "name": name, "version": match.group(1).decode("ascii"),
                "evidenceType": "archive-identifying-string",
                "marker": match.group().decode("ascii"), "offset": match.start(),
                "origin": None, "license": None, "purl": None,
            })
    return found + reviewed_identities(data)


def archive_targets(path, data):
    if path.suffix == ".lib":
        # This is the intended directory target, not a COFF member architecture audit.
        return {"windows-x86_64": data}
    if len(data) < 48 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError(f"Expected universal vendored macOS archive: {path}")
    count = struct.unpack_from(">I", data, 4)[0]
    if count != 2:
        raise ValueError(f"Expected exactly arm64 and x86_64 archive slices: {path}")
    parts = {}
    ranges = []
    for index in range(count):
        cpu, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + 20 * index)
        arch = {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cpu)
        if (not arch or "macos-" + arch in parts or offset < 48 or size < 8
                or offset + size > len(data)
                or any(offset < end and start < offset + size for start, end in ranges)
                or not data[offset:offset + size].startswith(b"!<arch>\n")):
            raise ValueError(f"Unsupported archive slice: {path}")
        parts["macos-" + arch] = data[offset:offset + size]
        ranges.append((offset, offset + size))
    return parts


def refresh(root):
    entries = []
    for path in sorted([*(root / "a").rglob("*.a"), *(root / "lib/64").rglob("*.lib")]):
        data = path.read_bytes()
        targets = archive_targets(path, data)
        entries.append({
            "path": path.relative_to(root).as_posix(), "sha256": digest(path),
            "targets": {
                target: {"identities": identities(part),
                         "targetEvidence": "universal-archive-header" if target.startswith("macos")
                         else "repository-directory-intent-not-member-audit"}
                for target, part in sorted(targets.items())
            },
            "limitations": "Identifying strings and reviewed object evidence establish archive observations, not acquisition "
                            "provenance or live linked code. Origin/license unknown unless separately recorded.",
        })
    return {
        "manifestVersion": 1,
        "repository": "https://github.com/miyako/4d-plugin-curl-v3",
        "reviewedSourceCommit": subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
        "archives": entries,
    }


def verify_manifest(manifest, root):
    if "repository" in manifest:
        actual_paths = {path.relative_to(root).as_posix()
                        for path in [*(root / "a").rglob("*.a"),
                                     *(root / "lib/64").rglob("*.lib")]}
        listed = [entry["path"] for entry in manifest["archives"]]
        if len(listed) != len(set(listed)) or set(listed) != actual_paths:
            raise ValueError("Archive manifest has missing, extra or duplicate paths; refresh/review it")
    for entry in manifest["archives"]:
        path = root / entry["path"]
        if not path.is_file() or digest(path) != entry["sha256"]:
            raise ValueError(f"Archive manifest hash mismatch: {entry['path']}; refresh/review the manifest")
        actual = archive_targets(path, path.read_bytes())
        if set(entry["targets"]) != set(actual):
            raise ValueError(f"Archive manifest target mismatch: {entry['path']}")
        for target, data in actual.items():
            if entry["targets"][target]["identities"] != identities(data):
                raise ValueError(f"Archive manifest identity mismatch: {entry['path']} ({target})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["refresh", "verify"])
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=Path("build/sbom/native-archives.json"))
    args = parser.parse_args()
    if args.command == "refresh":
        args.manifest.write_text(json.dumps(refresh(args.root), indent=2) + "\n", encoding="utf-8")
    else:
        verify_manifest(json.loads(args.manifest.read_text(encoding="utf-8")), args.root)


if __name__ == "__main__":
    main()
