import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import generate
import native_provenance
import provenance


class NativeProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vendor = self.root / "vendor"
        self.inspect = patch.object(native_provenance, "_inspect")
        self.inspector = self.inspect.start()
        self.addCleanup(self.inspect.stop)

    def kit(self, target, version="8.21.0"):
        kit = self.root / target
        installed = kit / "install/lib/libcurl.a"
        installed.parent.mkdir(parents=True)
        installed.write_bytes(b"!<arch>\n" + target.encode())
        record = {
            "library": "curl", "target": target, "version": version,
            "sourceArchive": {"library": "curl", "version": version,
                              "url": "https://curl.se/download/curl-8.21.0.tar.xz",
                              "sha256": "a" * 64, "licenseSha256": "b" * 64},
            "archives": [{"path": "lib/libcurl.a", "sha256": provenance.digest(installed)}],
            "status": "not-approved-for-production", "configure_arguments": ["static"],
            "toolchain": {}, "recipeFiles": [],
        }
        (kit / "native-build-provenance.json").write_text(json.dumps(record))
        return kit

    def copy_windows(self, kit):
        path = self.vendor / "lib/64/libcurl.lib"
        path.parent.mkdir(parents=True)
        path.write_bytes((kit / "install/lib/libcurl.a").read_bytes())
        return path

    def test_original_inspector_and_selected_hash_gate_are_retained(self):
        kit = self.kit("windows-x86_64")
        copied = self.copy_windows(kit)
        rows = native_provenance.collect(self.vendor, "windows-x86_64", [kit])
        self.inspector.assert_called_once_with("build_curl", kit.resolve())
        self.assertNotIn("sourceCommit", generate.normalized_provenance(rows[0]))
        self.assertEqual(generate.build_dependencies(
            {"rebuiltArchiveEvidence": rows}, "windows-x86_64", []), [])
        record = {
            "rebuiltArchiveEvidence": rows,
            "linkEvidence": {"windows-x86_64": {"archives": [{
                "candidatePath": "lib/64/libcurl.lib", "sha256": provenance.digest(copied),
            }]}},
        }
        dependency = generate.build_dependencies(record, "windows-x86_64", [])[0]
        self.assertEqual((dependency["name"], dependency["version"], dependency["license"]),
                         ("curl", "8.21.0", "curl"))
        record["linkEvidence"]["windows-x86_64"]["archives"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "disagrees with source"):
            generate.build_dependencies(record, "windows-x86_64", [])
        copied.write_bytes(b"other archive")
        with self.assertRaisesRegex(ValueError, "Copied native archive"):
            native_provenance.collect(self.vendor, "windows-x86_64", [kit])

    def test_failed_original_inspection_cannot_be_promoted(self):
        kit = self.kit("windows-x86_64")
        self.inspector.side_effect = ValueError("original compiler record changed")
        with self.assertRaisesRegex(ValueError, "original compiler"):
            native_provenance.collect(self.vendor, "windows-x86_64", [kit])

    def test_staging_is_fresh_and_rechecks_copied_bytes(self):
        kit = self.kit("windows-x86_64")
        result = native_provenance.stage(self.vendor, "windows-x86_64", [kit])
        self.assertEqual(len(result["rebuiltArchiveEvidence"]), 1)
        self.assertEqual((self.vendor / "lib/64/libcurl.lib").read_bytes(),
                         (kit / "install/lib/libcurl.a").read_bytes())
        with self.assertRaisesRegex(ValueError, "new output directory"):
            native_provenance.stage(self.vendor, "windows-x86_64", [kit])
        self.assertEqual(native_provenance.collect(
            self.vendor, "windows-x86_64", [kit]), result["rebuiltArchiveEvidence"])

    def test_duplicate_missing_and_disagreeing_architectures_fail(self):
        arm = self.kit("macos-arm64")
        intel = self.kit("macos-x86_64", version="8.20.0")
        for kits, message in (([arm, arm], "Duplicate"), ([arm], "incomplete"),
                              ([arm, intel], "identities disagree")):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                native_provenance.collect(self.vendor, "macos-universal", kits)
        with self.assertRaisesRegex(ValueError, "target does not match"):
            native_provenance.collect(self.vendor, "windows-x86_64", [arm])

    def test_every_universal_slice_must_match_its_original(self):
        arm, intel = self.kit("macos-arm64"), self.kit("macos-x86_64")
        slices = [(0x0100000C, arm), (0x01000007, intel)]
        header, data = bytearray(struct.pack(">II", 0xCAFEBABE, 2)), bytearray()
        for cpu, kit in slices:
            payload = (kit / "install/lib/libcurl.a").read_bytes()
            header.extend(struct.pack(">IIIII", cpu, 0, 48 + len(data), len(payload), 0))
            data.extend(payload)
        copied = self.vendor / "a/libcurl.a"
        copied.parent.mkdir(parents=True)
        copied.write_bytes(header + data)
        rows = native_provenance.collect(self.vendor, "macos-universal", [intel, arm])
        self.assertEqual(len(rows[0]["originalBuildRecords"]), 2)
        altered = bytearray(copied.read_bytes())
        altered[-1] ^= 1
        copied.write_bytes(altered)
        with self.assertRaisesRegex(ValueError, "slice does not match"):
            native_provenance.collect(self.vendor, "macos-universal", [arm, intel])

    def test_tarball_identity_cannot_inherit_a_related_git_commit(self):
        kit = self.kit("windows-x86_64")
        self.copy_windows(kit)
        value = native_provenance.collect(self.vendor, "windows-x86_64", [kit])[0]
        value["sourceArchive"]["relatedGitTagCommit"] = "1" * 40
        normalized = generate.normalized_provenance(value)
        self.assertNotIn("sourceCommit", normalized)
        for field in ("sha256", "url", "version", "library"):
            invalid = copy.deepcopy(value)
            invalid["sourceArchive"].pop(field)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "pinned sourceArchive"):
                generate.normalized_provenance(invalid)
