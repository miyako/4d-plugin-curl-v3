import copy
import json
from pathlib import Path
import tempfile
import unittest
import struct

import archives
import generate


class ArchiveIdentityTests(unittest.TestCase):
    def test_bad_universal_archive_headers_are_not_target_evidence(self):
        for data in (b"bad", b"\xca\xfe\xba\xbe" + b"\x00" * 44,
                     struct.pack(">II", 0xCAFEBABE, 2) + b"\x00" * 40):
            with self.assertRaises(ValueError):
                archives.archive_targets(Path("a/libtest.a"), data)

    def test_strong_archive_marker_not_headers_or_bare_numbers(self):
        self.assertEqual(archives.identities(b"1.3.2 ZLIB_VERSION=1.3.2 nghttp2/%s"), [])
        found = archives.identities(b"1.3.2\0inflate 1.3.1 Copyright")
        self.assertEqual(found[0]["version"], "1.3.1")
        self.assertIsNone(found[0]["license"])
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            archives.identities(b"CLIENT libcurl 8.21.0\0CLIENT libcurl 8.20.0\0")

    def test_checked_in_manifest_is_hash_bound_and_target_specific(self):
        root = Path(__file__).resolve().parents[2]
        manifest = json.loads((root / "build/sbom/native-archives.json").read_text())
        archives.verify_manifest(manifest, root)
        entries = {entry["path"]: entry for entry in manifest["archives"]}
        actual = {p.relative_to(root).as_posix()
                  for p in [*(root / "a").rglob("*.a"), *(root / "lib/64").rglob("*.lib")]}
        self.assertEqual(set(entries), actual)
        self.assertEqual(entries["lib/64/zlib.lib"]["targets"]["windows-x86_64"]
                         ["identities"][0]["version"], "1.3.1")
        self.assertEqual(entries["a/libz.a"]["targets"]["macos-arm64"]
                         ["identities"][0]["version"], "1.3.2")
        damaged = copy.deepcopy(manifest)
        damaged["archives"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            archives.verify_manifest(damaged, root)

    def test_hash_identity_and_target_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "test.lib").write_bytes(b"!<arch>\nCLIENT libcurl 8.21.0")
            entry = {"path": "test.lib", "sha256": archives.digest(root / "test.lib"),
                     "targets": {"windows-x86_64": {"identities": []}}}
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                archives.verify_manifest({"archives": [entry]}, root)
            entry["targets"] = {"macos-arm64": {"identities": []}}
            with self.assertRaisesRegex(ValueError, "target mismatch"):
                archives.verify_manifest({"archives": [entry]}, root)


class SelectedIdentityTests(unittest.TestCase):
    def test_source_record_spelling_is_normalized_without_losing_evidence(self):
        source = {
            "library": "OpenSSL", "source_repository": "https://github.com/openssl/openssl",
            "source_commit": "a" * 40, "source_builds": [{"target": "macos-arm64"}],
        }
        normalized = generate.normalized_provenance(source)
        self.assertEqual(normalized["name"], "OpenSSL")
        self.assertEqual(normalized["sourceRepository"], source["source_repository"])
        self.assertEqual(normalized["source_builds"], source["source_builds"])
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            generate.normalized_provenance({**source, "name": "Brotli"})

    def record(self):
        return {
            "rebuiltArchiveEvidence": [{
                "name": "Brotli", "version": "1.2.1",
                "sourceRepository": "https://github.com/google/brotli",
                "sourceCommit": "a" * 40, "license": "MIT",
                "purl": "pkg:github/google/brotli@1.2.1",
                "archives": [{"path": "a/libbrotlidec.a", "sha256": "b" * 64}],
            }],
            "linkEvidence": {"macos-arm64": {"archives": [{
                "candidatePath": "a/libbrotlidec.a", "sha256": "b" * 64,
                "selectedMembers": ["decode.o"], "liveSymbols": [],
            }]}},
        }

    def test_source_package_selected_even_without_live_symbols_under_lto(self):
        dependencies = generate.build_dependencies(self.record(), "macos-arm64", [])
        self.assertEqual(dependencies[0]["name"], "Brotli")
        self.assertEqual(dependencies[0]["version"], "1.2.1")
        self.assertEqual(dependencies[0]["license"], "MIT")
        self.assertIn("retained bytes not established", dependencies[0]["incorporation"])
        self.assertEqual(generate.build_dependencies(self.record(), "macos-x86_64", []), [])

    def test_no_selection_is_not_incorporated_and_stale_hash_rejected(self):
        record = self.record()
        record["linkEvidence"] = {}
        self.assertEqual(generate.build_dependencies(record, "macos-arm64", []), [])
        record = self.record()
        record["linkEvidence"]["macos-arm64"]["archives"][0]["sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "disagrees"):
            generate.build_dependencies(record, "macos-arm64", [])

    def test_binary_build_version_disagreement_rejected(self):
        record = self.record()
        record["rebuiltArchiveEvidence"][0]["name"] = "OpenSSL"
        with self.assertRaisesRegex(ValueError, "version disagreement"):
            generate.build_dependencies(record, "macos-arm64", [{"name": "OpenSSL", "version": "3.5.8"}])

    def test_multi_archive_identity_merge_is_order_independent_and_conflicts_fail(self):
        record = self.record()
        identity = {"name": "Brotli", "version": "1.2.1", "license": None, "purl": None, "origin": None}
        record["archiveInventory"] = [{
            "path": "a/libbrotlicommon.a", "sha256": "c" * 64,
            "targets": {"macos-arm64": {"identities": [identity]}},
        }]
        selections = record["linkEvidence"]["macos-arm64"]["archives"]
        selections.append({"candidatePath": "a/libbrotlicommon.a", "sha256": "c" * 64,
                           "selectedMembers": ["common.o"]})
        forward = generate.build_dependencies(record, "macos-arm64", [])
        selections.reverse()
        backward = generate.build_dependencies(record, "macos-arm64", [])
        self.assertEqual(forward, backward)
        self.assertEqual(forward[0]["license"], "MIT")
        self.assertEqual(len(forward[0]["archiveIdentities"]), 2)
        identity["license"] = "Apache-2.0"
        with self.assertRaisesRegex(ValueError, "conflicting license"):
            generate.build_dependencies(record, "macos-arm64", [])


if __name__ == "__main__":
    unittest.main()
