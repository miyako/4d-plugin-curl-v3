#!/usr/bin/env python3
"""OpenSSL build evidence, not binary detection or a signed attestation.

source-record writes INSTALL/openssl-build-provenance.json only after a build.
verify checks that cached record against the checkout, expected configuration,
and installed archive bytes. combine rechecks installed bytes and hashes the
copied/merged vendor archives into openssl-provenance.json for SBOM ingestion.
Configuration arguments follow ``--`` and include the Configure platform first.
All archive paths are relative to their install/vendor root.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess


REPOSITORY = "https://github.com/openssl/openssl"
RECORD = "openssl-build-provenance.json"
EVIDENCE = "build-derived-source-and-archive-hashes-not-binary-detection"
PLATFORMS = {
    "windows-x86_64": "VC-WIN64A",
    "macos-arm64": "darwin64-arm64-cc",
    "macos-x86_64": "darwin64-x86_64-cc",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def git(source, *args):
    return subprocess.check_output(
        ["git", "-C", str(source), *args], text=True, stderr=subprocess.PIPE
    ).strip()


def source_identity(source):
    git(source, "ls-files", "--error-unmatch", "VERSION.dat", "LICENSE.txt")
    if git(source, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("OpenSSL tracked source must be clean")
    text = (source / "VERSION.dat").read_text(encoding="utf-8")
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z_]+)=(.*?)\s*", line)
        if match:
            values[match[1]] = match[2].strip("'\"")
    parts = [values.get(key, "") for key in ("MAJOR", "MINOR", "PATCH")]
    if not all(re.fullmatch(r"[0-9]+", part) for part in parts):
        raise ValueError("Invalid OpenSSL VERSION.dat version")
    if int(parts[0]) < 3:
        raise ValueError("Apache-2.0 source identity requires OpenSSL 3 or newer")
    version = ".".join(parts)
    if values.get("PRE_RELEASE_TAG"):
        version += "-" + values["PRE_RELEASE_TAG"]
    if values.get("BUILD_METADATA"):
        version += "+" + values["BUILD_METADATA"]
    commit = git(source, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("Invalid OpenSSL source commit")
    return {
        "library": "OpenSSL", "version": version,
        "source_repository": REPOSITORY, "source_commit": commit,
        "version_file": "VERSION.dat",
        "version_file_sha256": digest(source / "VERSION.dat"),
        "license": "Apache-2.0",
        "licenseFile": "LICENSE.txt",
        "licenseFileSha256": digest(source / "LICENSE.txt"),
        "purl": "pkg:github/openssl/openssl@" + commit,
        "evidence_type": EVIDENCE,
    }


def archive_hashes(root, paths):
    result = []
    for name in sorted(paths):
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
            raise ValueError("Archive paths must be relative POSIX paths")
        file = root / path
        if not file.resolve().is_relative_to(root.resolve()):
            raise ValueError("Archive escapes its root")
        result.append({"path": name, "sha256": digest(file)})
    if not result or len({item["path"] for item in result}) != len(result):
        raise ValueError("Expected distinct archive paths")
    return result


def configuration(target, arguments):
    if not arguments or arguments[0] != PLATFORMS[target]:
        raise ValueError("Configure platform does not match target")
    return {"target": target, "platform": arguments[0],
            "configure_arguments": arguments}


def expected_archives(target):
    if target == "windows-x86_64":
        return ["lib/libcrypto.lib", "lib/libssl.lib"]
    return ["lib/libcrypto.a", "lib/libssl.a"]


def source_record(source, install, target, arguments):
    config = configuration(target, arguments)
    # Read Configure's actual result only for a fresh build, never from a cache.
    actual = json.loads(subprocess.check_output([
        "perl", "-I", str(source.resolve()), "-Mconfigdata", "-MJSON::PP", "-e",
        "print encode_json({platform => $configdata::config{target}, "
        "configure_arguments => $configdata::config{perlargv}})",
    ], text=True, cwd=source))
    if any(actual.get(key) != config[key] for key in ("platform", "configure_arguments")):
        raise ValueError("Actual OpenSSL Configure arguments do not match expected configuration")
    record = {
        "schema_version": 1,
        **source_identity(source),
        **config,
        "archives": archive_hashes(install, expected_archives(target)),
    }
    write_json(install / RECORD, record)
    return record


def read_record(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    target = record.get("target")
    if target not in PLATFORMS or record.get("schema_version") != 1:
        raise ValueError("Unsupported OpenSSL build record")
    if (record.get("library") != "OpenSSL"
            or record.get("source_repository") != REPOSITORY
            or record.get("license") != "Apache-2.0"
            or record.get("licenseFile") != "LICENSE.txt"
            or not re.fullmatch(r"[0-9a-f]{64}", record.get("licenseFileSha256", ""))
            or record.get("evidence_type") != EVIDENCE
            or not re.fullmatch(r"[0-9a-f]{40,64}", record.get("source_commit", ""))
            or record.get("purl") != "pkg:github/openssl/openssl@" + record["source_commit"]):
        raise ValueError("Invalid OpenSSL source identity")
    expected = archive_hashes(path.parent, expected_archives(target))
    if record.get("archives") != expected:
        raise ValueError("Installed OpenSSL archives do not match build record")
    config = configuration(target, record.get("configure_arguments", []))
    if record.get("platform") != config["platform"]:
        raise ValueError("Recorded Configure platform does not match target")
    return record


def verify(source, install, target, arguments):
    record = read_record(install / RECORD)
    expected = {**source_identity(source), **configuration(target, arguments)}
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError("OpenSSL cached source/configuration mismatch: " + key)
    return record


def verify_universal_archive(path, sources):
    """Bind each fat archive slice to its build input, not just its CPU label."""
    data = path.read_bytes()
    formats = {
        b"\xca\xfe\xba\xbe": (">", "IIIII"),
        b"\xbe\xba\xfe\xca": ("<", "IIIII"),
        b"\xca\xfe\xba\xbf": (">", "IIQQII"),
        b"\xbf\xba\xfe\xca": ("<", "IIQQII"),
    }
    if data[:4] not in formats or len(data) < 8:
        raise ValueError("Merged OpenSSL archive is not a universal archive")
    endian, layout = formats[data[:4]]
    count = struct.unpack_from(endian + "I", data, 4)[0]
    entry_size = struct.calcsize(endian + layout)
    if count != len(sources) or len(data) < 8 + count * entry_size:
        raise ValueError("Merged OpenSSL archive has unexpected architecture count")
    seen = set()
    ranges = []
    for index in range(count):
        cpu, _, offset, size, *_ = struct.unpack_from(
            endian + layout, data, 8 + index * entry_size
        )
        if (cpu not in sources or cpu in seen or offset < 8 + count * entry_size
                or offset + size > len(data) or size == 0
                or any(offset < end and start < offset + size for start, end in ranges)):
            raise ValueError("Merged OpenSSL archive has invalid architecture slices")
        seen.add(cpu)
        ranges.append((offset, offset + size))
        original = sources[cpu].read_bytes()
        sliced = data[offset:offset + size]
        # lipo may include zero alignment padding; do not normalize ar members,
        # symbol tables or object contents, which would weaken the byte binding.
        if not (sliced.startswith(original) and not sliced[len(original):].strip(b"\0")):
            raise ValueError("Merged OpenSSL slice does not match installed source archive")


def combine(records, vendor, target):
    builds = [read_record(path) for path in records]
    required = ({"windows-x86_64"} if target == "windows-x86_64"
                else {"macos-arm64", "macos-x86_64"})
    if len(builds) != len(required) or {b["target"] for b in builds} != required:
        raise ValueError("OpenSSL build targets do not match output target")
    first = builds[0]
    identity_keys = (
        "library", "version", "source_repository", "source_commit", "version_file",
        "version_file_sha256", "license", "licenseFile", "licenseFileSha256",
        "purl", "evidence_type",
    )
    identity = {key: first[key] for key in identity_keys}
    if any(any(build[key] != value for key, value in identity.items()) for build in builds):
        raise ValueError("OpenSSL source builds have different identities")
    paths = (["lib/64/libcrypto.lib", "lib/64/libssl.lib"] if target == "windows-x86_64"
             else ["a/libcrypto.a", "a/libssl.a"])
    archives = archive_hashes(vendor, paths)
    if target == "windows-x86_64":
        for installed, copied in zip(first["archives"], archives):
            if installed["sha256"] != copied["sha256"]:
                raise ValueError("Copied OpenSSL archive does not match installed archive")
    else:
        installs = {build["target"]: path.parent for path, build in zip(records, builds)}
        for name in ("libcrypto.a", "libssl.a"):
            verify_universal_archive(vendor / "a" / name, {
                0x0100000C: installs["macos-arm64"] / "lib" / name,
                0x01000007: installs["macos-x86_64"] / "lib" / name,
            })
    result = {"schema_version": 1, **identity, "target": target,
              "archives": archives, "source_builds": sorted(builds, key=lambda b: b["target"])}
    write_json(vendor / "openssl-provenance.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("source-record", "verify"):
        sub = commands.add_parser(command)
        sub.add_argument("--source", type=Path, required=True)
        sub.add_argument("--install", type=Path, required=True)
        sub.add_argument("--target", choices=PLATFORMS, required=True)
        sub.add_argument("configure_arguments", nargs=argparse.REMAINDER)
    sub = commands.add_parser("combine")
    sub.add_argument("--record", type=Path, action="append", required=True)
    sub.add_argument("--vendor", type=Path, required=True)
    sub.add_argument("--target", choices=("windows-x86_64", "macos-universal"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "combine":
            combine(args.record, args.vendor, args.target)
        else:
            arguments = args.configure_arguments
            if arguments[:1] == ["--"]:
                arguments = arguments[1:]
            action = source_record if args.command == "source-record" else verify
            action(args.source, args.install, args.target, arguments)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"OpenSSL provenance: {error}\n")


if __name__ == "__main__":
    main()
