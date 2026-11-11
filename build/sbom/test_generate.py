import copy
import argparse
import json
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

import generate
import validate


def macho(cpu, marker):
    return struct.pack("<IIIIIIII", 0xFEEDFACF, cpu, 0, 8, 0, 0, 0, 0) + marker


def fat(arm_marker=b"CLIENT libcurl 8.21.0\0OpenSSL 3.5.8 date\0"):
    x64 = macho(0x01000007, b"CLIENT libcurl 8.20.0\0")
    arm = macho(0x0100000C, arm_marker)
    return (struct.pack(">II", 0xCAFEBABE, 2)
            + struct.pack(">IIIII", 0x01000007, 0, 48, len(x64), 0)
            + struct.pack(">IIIII", 0x0100000C, 0, 48 + len(x64), len(arm), 0)
            + x64 + arm)


def pe():
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, 0x8664)
    struct.pack_into("<H", data, 88, 0x20B)
    return bytes(data) + b"CLIENT libcurl 8.19.0\0SSH-2.0-libssh2_1.11.1_DEV\0"


def archive(path, mac=None):
    with zipfile.ZipFile(path, "w") as file:
        file.writestr(generate.MAC, fat() if mac is None else mac)
        file.writestr(generate.WIN, pe())
        file.writestr(generate.PLIST, plistlib.dumps({"CFBundleShortVersionString": "4.9.6"}))


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cURL-4.9.6.zip"
        archive(self.path)

    def test_hash_identity_and_architecture_scoping(self):
        inv = generate.inventory(self.path, "4.9.6", {})
        self.assertEqual(inv["artifact"]["sha256"], generate.sha256(self.path.read_bytes()))
        versions = {t["id"]: t["dependencies"][0]["version"] for t in inv["targets"]}
        self.assertEqual(versions, {"macos-arm64": "8.21.0", "macos-x86_64": "8.20.0",
                                    "windows-x86_64": "8.19.0"})
        self.assertEqual(inv["targets"][-1]["dependencies"][-1]["version"], "1.11.1_DEV")
        self.assertNotEqual(inv["targets"][0]["analyzedSha256"], inv["targets"][1]["analyzedSha256"])
        self.assertEqual(inv["targets"][0]["binarySha256"], inv["targets"][1]["binarySha256"])
        cdx, spdx = generate.cyclonedx(inv), generate.spdx(inv)
        self.assertEqual(cdx["metadata"]["component"]["supplier"]["name"], "Keisuke Miyako")
        self.assertEqual(spdx["packages"][0]["versionInfo"], "4.9.6")
        self.assertNotIn("dependencies", cdx)
        self.assertTrue(all(p["licenseConcluded"] == "NOASSERTION" for p in spdx["packages"]))

    def test_version_mismatch_is_error(self):
        with self.assertRaisesRegex(ValueError, "bundle version"):
            generate.inventory(self.path, "0.0.0", {})

    def test_malformed_architectures_are_errors(self):
        for data in (b"bad", fat()[:45]):
            with self.assertRaises(ValueError):
                generate.mac_slices(data)
        bad_pe = bytearray(pe())
        struct.pack_into("<H", bad_pe, 68, 0xAA64)
        with self.assertRaisesRegex(ValueError, "x86_64"):
            generate.check_pe(bad_pe)

    def test_missing_and_conflicting_markers_are_errors(self):
        for marker in (b"8.21.0", b"CLIENT libcurl 8.21.0\0libcurl/8.20.0\0"):
            with self.assertRaises(ValueError):
                generate.observations(marker)
        self.assertEqual(len(generate.observations(b"CLIENT libcurl 8.21.0\0nghttp2/%s\01.70.0")), 1)

    def test_stale_evidence_is_error(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            generate.inventory(self.path, "4.9.6", {
                "macos-universal": {"binarySha256": "0" * 64},
                "windows-x86_64": {"binarySha256": "0" * 64},
            })

    def test_evidence_is_preserved_in_both_formats(self):
        records = {
            "macos-universal": {"target": "macos-universal", "binarySha256": generate.sha256(fat()),
                                "declaredInputs": [{"path": "a/libbrotlidec.a", "sha256": "a" * 64}]},
            "windows-x86_64": {"target": "windows-x86_64", "binarySha256": generate.sha256(pe()),
                               "declaredInputs": [{"path": "lib/64/brotlidec.lib", "sha256": "b" * 64}]},
        }
        inv = generate.inventory(self.path, "4.9.6", records)
        cdx = generate.cyclonedx(inv)
        detail = json.loads(cdx["components"][0]["description"])
        self.assertEqual(detail["buildEvidence"], records["macos-universal"])

    def test_duplicate_zip_members_are_errors(self):
        with warnings.catch_warnings(), zipfile.ZipFile(self.path, "a") as file:
            warnings.simplefilter("ignore", UserWarning)
            file.writestr(generate.PLIST, b"duplicate")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            generate.inventory(self.path, "4.9.6", {})


class SchemaTests(unittest.TestCase):
    setUp = InventoryTests.setUp
    @classmethod
    def setUpClass(cls):
        cls.schema_temp = tempfile.TemporaryDirectory()
        cls.schemas, cls.registry = validate.load_schemas(Path(cls.schema_temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.schema_temp.cleanup()

    def test_official_schemas_and_semantic_tampering(self):
        inv = generate.inventory(self.path, "4.9.6", {})
        cdx, spdx = generate.cyclonedx(inv), generate.spdx(inv)
        validate.validate_documents(inv, cdx, spdx, self.path, "4.9.6", self.schemas, self.registry)
        damaged = copy.deepcopy(cdx)
        damaged["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "artifact hash mismatch"):
            validate.validate_documents(inv, damaged, spdx, self.path, "4.9.6",
                                        self.schemas, self.registry)
        damaged = copy.deepcopy(inv)
        damaged["targets"][0]["dependencies"][0]["version"] = "99.0.0"
        with self.assertRaises(ValueError):
            validate.validate_documents(damaged, generate.cyclonedx(damaged),
                                        generate.spdx(damaged), self.path, "4.9.6",
                                        self.schemas, self.registry)

    def test_build_supported_known_packages_and_relations_in_official_schemas(self):
        records = {}
        for platform, binary, targets, prefix, suffix in (
            ("macos-universal", fat(), ["macos-arm64", "macos-x86_64"], "a/lib", ".a"),
            ("windows-x86_64", pe(), ["windows-x86_64"], "lib/64/", ".lib"),
        ):
            sources, selected = [], []
            for name, archive_name, version, license_id, origin, purl in (
                ("Brotli", "brotlidec", "1.2.1", "MIT", "https://github.com/google/brotli",
                 "pkg:github/google/brotli@1.2.1"),
                ("OpenSSL", "ssl", "3.5.8", "Apache-2.0", "https://github.com/openssl/openssl",
                 "pkg:generic/openssl@3.5.8"),
            ):
                path = prefix + archive_name + suffix
                digest = generate.sha256(path.encode())
                sources.append({
                    "name": name, "version": version, "license": license_id,
                    "sourceRepository": origin, "sourceCommit": "a" * 40, "purl": purl,
                    "archives": [{"path": path, "sha256": digest}],
                })
                selected.append({"candidatePath": path, "sha256": digest,
                                 "selectedMembers": ["object.o"], "liveSymbols": []})
            records[platform] = {
                "target": platform, "binarySha256": generate.sha256(binary),
                "rebuiltArchiveEvidence": sources,
                "linkEvidence": {target: {"archives": selected} for target in targets},
            }
        inv = generate.inventory(self.path, "4.9.6", records)
        cdx, spdx = generate.cyclonedx(inv), generate.spdx(inv)
        validate.validate_documents(inv, cdx, spdx, self.path, "4.9.6", self.schemas, self.registry)
        for target in inv["targets"]:
            packages = {dep["name"]: dep for dep in target["dependencies"]}
            self.assertEqual(packages["Brotli"]["version"], "1.2.1")
            self.assertEqual(packages["OpenSSL"]["license"], "Apache-2.0")
            self.assertEqual(sum(dep["name"] == "OpenSSL" for dep in target["dependencies"]), 1)
        self.assertEqual(len([p for p in spdx["packages"] if p["licenseDeclared"] == "MIT"]), 3)
        self.assertEqual(sum(len(d["dependsOn"]) for d in cdx["dependencies"]), 6)
        self.assertEqual(sum(r["relationshipType"] == "DEPENDS_ON" for r in spdx["relationships"]), 6)
        damaged = copy.deepcopy(cdx)
        next(c for c in damaged["components"] if c["name"] == "Brotli")["purl"] = "pkg:generic/wrong@1"
        with self.assertRaisesRegex(ValueError, "identity/license/origin"):
            validate.validate_documents(inv, damaged, spdx, self.path, "4.9.6", self.schemas, self.registry)
        damaged = copy.deepcopy(spdx)
        next(r for r in damaged["relationships"] if r["relationshipType"] == "DEPENDS_ON")[
            "relationshipType"] = "CONTAINS"
        with self.assertRaisesRegex(ValueError, "dependency mismatch"):
            validate.validate_documents(inv, cdx, damaged, self.path, "4.9.6", self.schemas, self.registry)


class BuildEvidenceTests(unittest.TestCase):
    def test_windows_declarations_and_brotli_hash_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/release.yml").write_text("release workflow\n")
            (root / ".github/workflows/build-brotli.yml").write_text("brotli workflow\n")
            (root / "cURL.vcxproj").write_text(
                '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
                '<ItemDefinitionGroup Condition="\'$(Configuration)|$(Platform)\'==\'Release|x64\'">'
                '<Link><AdditionalDependencies>libcurl.lib;brotlicommon.lib;brotlidec.lib;'
                'brotlienc.lib;kernel32.lib;%(AdditionalDependencies)</AdditionalDependencies>'
                '</Link></ItemDefinitionGroup></Project>'
            )
            (root / "lib/64").mkdir(parents=True)
            for name in ("libcurl", "brotlicommon", "brotlidec", "brotlienc"):
                (root / f"lib/64/{name}.lib").write_bytes(name.encode())
            source = root / "brotli-src"
            (source / "c/common").mkdir(parents=True)
            (source / "c/common/version.h").write_text(
                "#define BROTLI_VERSION_MAJOR 1\n#define BROTLI_VERSION_MINOR 2\n"
                "#define BROTLI_VERSION_PATCH 1\n"
            )
            (source / "LICENSE").write_text(
                'Permission is hereby granted, free of charge\nTHE SOFTWARE IS PROVIDED "AS IS"\n'
            )
            output = root / "evidence.json"
            binary = root / "cURL.4DX"
            binary.write_bytes(pe())
            args = argparse.Namespace(root=root, target="windows-x86_64", binary=binary,
                                      output=output, brotli_provenance=root / "brotli-provenance.json")
            with patch.object(generate, "git", return_value="a" * 40):
                generate.brotli_provenance(argparse.Namespace(source=source, vendor=root))
                generate.collect(args)
                record = json.loads(output.read_text())
                self.assertEqual(record["binarySha256"], generate.sha256(pe()))
                self.assertEqual(record["rebuiltArchiveEvidence"][0]["version"], "1.2.1")
                missing = [i for i in record["declaredInputs"] if i["status"] == "unresolved-declaration"]
                self.assertEqual(missing, [{"path": "lib/64/kernel32.lib", "status": "unresolved-declaration"}])
                args.link_map = ["windows-x86_64=plugin.map"]
                args.link_log = root / "link.log"
                selected = {
                    "target": "windows-x86_64", "selectedArchives": [{
                        "resolvedPath": str(root / "lib/64/brotlidec.lib"),
                        "sha256": generate.sha256(b"brotlidec"),
                        "members": [{"member": "decode.obj", "selection": "verbose-loaded"}],
                    }],
                }
                with patch("linker.collect", return_value=copy.deepcopy(selected)):
                    generate.collect(args)
                traced = json.loads(output.read_text())
                chosen = traced["linkEvidence"]["windows-x86_64"]["archives"][0]
                self.assertEqual(chosen["candidatePath"], "lib/64/brotlidec.lib")
                self.assertEqual(generate.build_dependencies(traced, "windows-x86_64", [])[0]["name"], "Brotli")
                selected["selectedArchives"][0]["sha256"] = "0" * 64
                with patch("linker.collect", return_value=selected):
                    with self.assertRaisesRegex(ValueError, "Selected archive hash mismatch"):
                        generate.collect(args)
                args.link_map = ["macos-arm64=plugin.map"]
                with self.assertRaisesRegex(ValueError, "Expected link maps"):
                    generate.collect(args)
                args.link_map = []
                (root / "lib/64/brotlidec.lib").write_bytes(b"stale replacement")
                with self.assertRaisesRegex(ValueError, "does not match"):
                    generate.collect(args)


if __name__ == "__main__":
    unittest.main()
