#!/usr/bin/env python3
"""Join source/relink delivery and signature-only transformations to a release."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/sbom"))
sys.path.insert(0, str(ROOT / "build/dependencies"))
import generate
import license_materials
import recover_license_materials
import relink_review_delivery
from provenance import digest, write_json
from coverage import require_selected_source_coverage


def require_source_inventory(inventory):
    targets = inventory["targets"]
    if len(targets) != 3 or {t["id"] for t in targets} != set(relink_review_delivery.TARGETS):
        raise ValueError("Release requires all three distinct source-built targets")
    for target in targets:
        require_selected_source_coverage(target)
        coverage = target["selectedArchiveCoverage"]
        expected = 11 if target["id"] == "windows-x86_64" else 12
        if (coverage["selectedRepositoryArchives"] != expected
                or coverage["namedPackageArchives"] != expected
                or coverage["versionedPackageArchives"] != expected - 1
                or coverage["unknownVersionPackages"] != ["libmodman"]):
            raise ValueError("Selected source/package/version coverage changed")


def prepare(inputs, providers, output):
    inventory = inputs / "unsigned-native-sboms/unsigned-native.zip.inventory.json"
    record = json.loads(inventory.read_text())
    require_source_inventory(record)
    pin = next(p for p in record["targets"][0]["dependencies"] if p["name"] == "curl")[
        "archiveIdentities"][0]["identity"]["sourceEvidence"]["sourceArchive"]
    if pin["url"] != "https://curl.se/download/curl-" + pin["version"] + ".tar.xz":
        raise ValueError("Unexpected curl source acquisition URL")
    if output.exists():
        raise ValueError("Use a fresh external release-material directory")
    output.mkdir()
    archive = output / "curl-source.tar.xz"
    with urllib.request.urlopen(pin["url"], timeout=60) as response, archive.open("xb") as stream:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 64 * 1024 * 1024:
                raise ValueError("Unexpectedly large curl source archive")
            stream.write(chunk)
    if digest(archive) != pin["sha256"]:
        raise ValueError("Curl source hash differs from original selected-source evidence")
    recovered = output / "notice-inputs"
    recover_license_materials.recover(inputs, archive, providers, recovered)
    notices = output / "notices"
    license_materials.deliver(recovered, inventory, notices)
    provider_records = [
        providers / ("isolated-provider-materials-" + target) / path
        for target in relink_review_delivery.TARGETS
        for path in ("provider-openssl/install/openssl-build-provenance.json",
                     "provider-brotli/vendor/brotli-provenance.json")
    ]
    (output / "release").mkdir()
    for system, target in (("macOS", "macos-universal"), ("Windows", "windows-x86_64")):
        shutil.copyfile(
            inputs / ("unsigned-native-build-" + system) / "native-trace/build-evidence.json",
            output / "release" / ("original-build-evidence-" + target + ".json"))
    relink_review_delivery.deliver(
        inventory, inputs / "unsigned-native-containers/unsigned-native.zip",
        inputs / "isolated-selected-plugin-delivery-macOS/Moved selected plugin kit",
        inputs / "isolated-selected-plugin-delivery-Windows/Moved selected plugin kit",
        notices, provider_records, output / "release/corresponding-source")
    bundle = inputs / "unsigned-native-build-macOS/test/Plugins/cURL.bundle"
    windows = (inputs / "unsigned-native-build-Windows/test/Plugins/cURL.bundle/"
               "Contents/Windows64/cURL.4DX")
    destination = bundle / "Contents/Windows64/cURL.4DX"
    destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(windows, destination)
    for target in record["targets"]:
        binary = bundle / Path(target["binaryPath"]).relative_to("cURL.bundle")
        if digest(binary) != target["binarySha256"]:
            raise ValueError("Prepared bundle differs from original measured unsigned binary")
    (bundle / "Contents/MacOS/cURL").chmod(0o755)
    resources = bundle / "Contents/Resources"
    resources.mkdir(exist_ok=True)
    original_notice = (notices / "NOTICES.txt").read_bytes()
    separator = b"\n" + b"=" * 72 + b"\n"
    position = original_notice.index(separator)
    (resources / "THIRD-PARTY-NOTICES.txt").write_bytes(
        ("cURL " + record["version"] + " third-party notices\n"
         "Original notices follow verbatim. Root MIT permission does not relicense "
         "third-party code.\nCorresponding library sources, patches, build scripts and "
         "application relink materials accompany this release in the sources ZIP.\n"
         "No maintainer signing key is required for user-created relinks.\n").encode()
        + original_notice[position:])
    shutil.copyfile(ROOT / "LICENSE", resources / "PROJECT-LICENSE.txt")


def has_signature(data):
    for part in generate.mac_slices(data).values():
        count, size = struct.unpack_from("<II", part, 16)
        end, cursor = 32 + size, 32
        if end > len(part):
            raise ValueError("Truncated Mach-O load commands")
        for _ in range(count):
            command, length = struct.unpack_from("<II", part, cursor)
            if length < 8 or cursor + length > end:
                raise ValueError("Invalid Mach-O load command")
            if command == 0x1D:
                if length != 16:
                    raise ValueError("Invalid code-signature command")
                offset, amount = struct.unpack_from("<II", part, cursor + 8)
                if offset < end or offset + amount > len(part):
                    raise ValueError("Invalid code-signature range")
                if amount:
                    return True
            cursor += length
        if cursor != end:
            raise ValueError("Mach-O command count/size mismatch")
    return False


def normalized_code(path, destination):
    original = generate.mac_slices(path.read_bytes())
    shutil.copyfile(path, destination)
    if has_signature(destination.read_bytes()):
        subprocess.run(["/usr/bin/codesign", "--remove-signature", str(destination)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if has_signature(destination.read_bytes()):
        raise ValueError("Code-signature normalization left signature bytes")
    normalized = generate.mac_slices(destination.read_bytes())
    if normalized.keys() != original.keys():
        raise ValueError("Signature removal changed CPU slices")
    return {target: canonical_code(data, original[target]) for target, data in normalized.items()}


def linkedit(data):
    count, size = struct.unpack_from("<II", data, 16)
    cursor, end, result, segments = 32, 32 + size, None, []
    if end > len(data):
        raise ValueError("Truncated Mach-O load commands")
    for _ in range(count):
        if cursor + 8 > end:
            raise ValueError("Truncated Mach-O load command")
        command, length = struct.unpack_from("<II", data, cursor)
        if length < 8 or cursor + length > end:
            raise ValueError("Invalid Mach-O load command")
        if command == 0x19:
            if length < 72:
                raise ValueError("Truncated Mach-O segment")
            vmaddr, vmsize, offset, amount, maximum, initial, sections, flags = struct.unpack_from(
                "<QQQQiiII", data, cursor + 24)
            segments.append((vmaddr, vmsize, cursor))
            if data[cursor + 8:cursor + 24] == b"__LINKEDIT".ljust(16, b"\0"):
                if (result is not None or length != 72 or sections or flags
                        or (maximum, initial) != (1, 1)
                        or offset < end or not amount or offset + amount != len(data)):
                    raise ValueError("Unsupported read-only LINKEDIT layout")
                result = {"commandOffset": cursor, "vmaddr": vmaddr, "vmsize": vmsize,
                          "fileoff": offset, "filesize": amount}
        cursor += length
    if result is None or cursor != end or any(
            position != result["commandOffset"] and start + amount > result["vmaddr"]
            for start, amount, position in segments):
        raise ValueError("LINKEDIT is missing or is not the final nonoverlapping segment")
    return result


def canonical_code(normalized, original):
    before, after = linkedit(original), linkedit(normalized)
    if before["vmaddr"] != after["vmaddr"] or before["fileoff"] != after["fileoff"]:
        raise ValueError("Signature removal moved LINKEDIT")
    rounding = lambda size: {(size + page - 1) // page * page
                             for page in (4096, 16384, 65536)}
    if (before["vmsize"] not in rounding(before["filesize"])
            or after["vmsize"] not in rounding(before["filesize"]) | rounding(after["filesize"])):
        raise ValueError("LINKEDIT VM size is not bounded signing/page-allocation rounding")
    # codesign removes the signature but retains its page-rounded VM allocation.
    # Canonicalize only that read-only, sectionless final segment's allocation.
    data = bytearray(normalized)
    struct.pack_into("<Q", data, after["commandOffset"] + 32, after["filesize"])
    return generate.sha256(data)


def rebind(unsigned, signed, evidence, output):
    record = json.loads(evidence.read_text())
    if record["target"] != "macos-universal" or record["binarySha256"] != digest(unsigned):
        raise ValueError("Original unsigned build-evidence binding changed")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", str(signed)],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with tempfile.TemporaryDirectory(prefix="release-signature-check-") as directory:
        folder = Path(directory)
        before = normalized_code(unsigned, folder / "before")
        after = normalized_code(signed, folder / "after")
    if before != after:
        raise ValueError("Signing changed code or metadata outside bounded signature normalization")
    derived = copy.deepcopy(record)
    derived["binarySha256"] = digest(signed)
    derived["codeSigningEvidence"] = {
        "evidenceType": "verified-code-signing-derived-binary-binding",
        "originalUnsignedEvidenceSha256": digest(evidence),
        "originalUnsignedBinarySha256": digest(unsigned),
        "signedBinarySha256": digest(signed),
        "canonicalCodeSliceSha256": before,
        "normalizer": "/usr/bin/codesign --remove-signature",
        "normalizerSha256": digest(Path("/usr/bin/codesign")),
        "bindingScriptSha256": digest(Path(__file__)),
        "additionalNormalization": "Only the read-only, sectionless final __LINKEDIT "
            "segment's vmsize, bounded by 4/16/64 KiB rounding of its signed/unsigned "
            "file extent. All other normalized bytes must match per CPU slice.",
        "scope": "Original producer/build records are unchanged. Signatures and bounded "
                 "signer allocation metadata are normalized; application code, data, "
                 "other commands and all remaining metadata must be byte-identical per slice.",
    }
    write_json(output, derived)
    return derived


def finalize(source, inventories, output, version):
    original = json.loads((source / "inventory.json").read_text())
    relink_review_delivery.inspect(source)
    originals = {t["id"]: t for t in original["targets"]}
    artifacts, snapshots = [], []
    for path in inventories:
        inventory = json.loads(path.read_text())
        require_source_inventory(inventory)
        if inventory["version"] != version:
            raise ValueError("Final source binding release version changed")
        artifact = path.parent.parent / inventory["artifact"]["name"]
        if digest(artifact) != inventory["artifact"]["sha256"]:
            raise ValueError("Final container hash differs from inventory")
        snapshot = {}
        for target in inventory["targets"]:
            baseline = originals[target["id"]]
            old = baseline["buildEvidence"]
            new = copy.deepcopy(target["buildEvidence"])
            if target["id"].startswith("macos-"):
                signing = new.pop("codeSigningEvidence")
                if (signing["originalUnsignedBinarySha256"] != baseline["binarySha256"]
                        or signing["signedBinarySha256"] != target["binarySha256"]
                        or signing["originalUnsignedEvidenceSha256"] != digest(
                            source.parent / "original-build-evidence-macos-universal.json")):
                    raise ValueError("Signed release differs from original source-kit binding")
                new["binarySha256"] = old["binarySha256"]
            elif target["binarySha256"] != baseline["binarySha256"]:
                raise ValueError("Windows binary changed after measured build")
            if old != new:
                raise ValueError("Source/archive/compiler/link evidence changed during signing")
            snapshot[target["id"]] = {
                "binarySha256": target["binarySha256"], "analyzedSha256": target["analyzedSha256"]}
        artifacts.append({"artifact": inventory["artifact"], "inventorySha256": digest(path)})
        snapshots.append(snapshot)
    if (len(snapshots) != 2 or snapshots[0] != snapshots[1]
            or {a["artifact"]["name"] for a in artifacts} !=
            {"cURL-" + version + ".zip", "cURL-" + version + ".dmg"}):
        raise ValueError("Expected identical ZIP/DMG targets")
    write_json(source.parent / "release-binding.json", {
        "evidenceType": "final-release-to-original-source-object-kit-binding",
        "version": version, "artifacts": artifacts, "targets": snapshots[0],
        "originalInventorySha256": digest(source / "inventory.json"),
        "originalDeliveryManifestSha256": digest(source / relink_review_delivery.MANIFEST),
        "originalBuildEvidence": {p.name: digest(p)
                                  for p in source.parent.glob("original-build-evidence-*.json")},
        "manualHostTesting": "not a release gate; not claimed passed",
        "scope": "Original candidate records retain their historical status. This additional "
                 "binding connects the authorized release to unchanged original library, "
                 "compiler and application relink materials; not legal certification.",
    })
    (source.parent / "RELEASE-README.txt").write_text(
        "Corresponding source and relink materials for cURL " + version + "\n\n"
        "release-binding.json joins the final signed ZIP/DMG to the original unsigned "
        "reference and unchanged selected source/object materials.\n"
        "Original review records and their candidate-only labels are historical evidence, "
        "not restamped production provenance. The corresponding-source directory retains "
        "its complete original manifest and is independently inspectable.\n"
        "See corresponding-source/RELINKING.md for user relink commands, toolchain prerequisites, permissions "
        "and notices. Proprietary host applications, SDK/toolchain binaries, signing "
        "credentials and license keys are not included.\n"
        "Manual 4D testing is optional and is not a release gate. Older-OS and Windows "
        "host-runtime behavior is not established by static linking or this source kit.\n"
        "No vulnerability-free or universal legal-compliance guarantee is made.\n")
    if output.exists():
        raise ValueError("Source archive output already exists")
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.parent.rglob("*")):
            if path.is_symlink():
                raise ValueError("Unexpected source delivery symlink")
            if path.is_file():
                archive.write(path, "cURL-" + version + "-sources/" + path.relative_to(source.parent).as_posix())
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError("Persisted source ZIP failed CRC rereading")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    for name in ("inputs", "providers", "output"):
        preparation.add_argument("--" + name, type=Path, required=True)
    signing = commands.add_parser("rebind")
    for name in ("unsigned", "signed", "evidence", "output"):
        signing.add_argument("--" + name, type=Path, required=True)
    final = commands.add_parser("finalize")
    for name in ("source", "output"):
        final.add_argument("--" + name, type=Path, required=True)
    final.add_argument("--version", required=True)
    final.add_argument("inventories", type=Path, nargs=2)
    args = parser.parse_args()
    options = vars(args)
    command = options.pop("command")
    {"prepare": prepare, "rebind": rebind, "finalize": finalize}[command](**options)


if __name__ == "__main__":
    main()
