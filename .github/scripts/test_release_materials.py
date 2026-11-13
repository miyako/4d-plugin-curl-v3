import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release_materials as release


class SigningBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.unsigned = self.root / "unsigned"
        self.signed = self.root / "signed"
        self.evidence = self.root / "original.json"
        self.output = self.root / "derived.json"
        self.unsigned.write_bytes(b"unsigned fixture")
        self.signed.write_bytes(b"signed fixture")
        self.record = {
            "target": "macos-universal", "binarySha256": release.digest(self.unsigned),
            "originalSourceBuild": {"sourceCommit": "unchanged"},
        }
        self.evidence.write_text(json.dumps(self.record))

    def test_signature_only_derivation_preserves_original_record_and_source_identity(self):
        original = self.evidence.read_bytes()
        with patch.object(release.subprocess, "run") as verify, patch.object(
                release, "normalized_code", return_value="same-code"):
            result = release.rebind(self.unsigned, self.signed, self.evidence, self.output)
        self.assertEqual(self.evidence.read_bytes(), original)
        self.assertEqual(result["originalSourceBuild"], self.record["originalSourceBuild"])
        self.assertEqual(result["binarySha256"], release.digest(self.signed))
        self.assertEqual(result["codeSigningEvidence"]["originalUnsignedEvidenceSha256"],
                         release.digest(self.evidence))
        self.assertIn("--all-architectures", verify.call_args.args[0])

    def test_changed_code_rejected_not_silently_restamped(self):
        with patch.object(release.subprocess, "run"), patch.object(
                release, "normalized_code", side_effect=["old-code", "different-code"]):
            with self.assertRaisesRegex(ValueError, "more than"):
                release.rebind(self.unsigned, self.signed, self.evidence, self.output)
        self.assertFalse(self.output.exists())

    def test_wrong_original_binary_rejected_before_signature_work(self):
        self.unsigned.write_bytes(b"changed after original capture")
        with patch.object(release.subprocess, "run") as verify:
            with self.assertRaisesRegex(ValueError, "binding changed"):
                release.rebind(self.unsigned, self.signed, self.evidence, self.output)
            verify.assert_not_called()

    def test_malformed_signature_range_not_treated_as_unsigned(self):
        header = bytearray(32)
        struct.pack_into("<II", header, 16, 1, 16)
        malformed = bytes(header) + struct.pack("<IIII", 0x1D, 16, 0, 1000)
        with patch.object(release.generate, "mac_slices", return_value={"macos-arm64": malformed}):
            with self.assertRaisesRegex(ValueError, "signature range"):
                release.has_signature(b"fixture")


class ReleasePipelineTests(unittest.TestCase):
    def test_release_uses_read_only_source_build_and_verified_source_delivery(self):
        workflow = (release.ROOT / ".github/workflows/release.yml").read_text()
        source = workflow.split("  source-native:", 1)[1].split("  build-macos:", 1)[0]
        self.assertIn("uses: ./.github/workflows/native-trace.yml", source)
        self.assertNotIn("secrets:", source)
        self.assertNotIn("contents: write", source)
        self.assertLess(workflow.index("release_materials.py prepare"),
                        workflow.index("import Developer ID"))
        self.assertLess(workflow.index("release_materials.py rebind"),
                        workflow.index("notarytool submit"))
        self.assertLess(workflow.index("release_materials.py finalize"),
                        workflow.index("  publish:"))


class FinalSourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source/corresponding-source"
        self.source.mkdir(parents=True)
        (self.source / release.relink_review_delivery.MANIFEST).write_text("original manifest")
        original_mac = {"binarySha256": "before", "selectedArchives": ["same"]}
        original_win = {"binarySha256": "windows", "selectedArchives": ["same"]}
        original_file = self.source.parent / "original-build-evidence-macos-universal.json"
        original_file.write_text(json.dumps(original_mac))
        signed = {**original_mac, "binarySha256": "after", "codeSigningEvidence": {
            "originalUnsignedBinarySha256": "before", "signedBinarySha256": "after",
            "originalUnsignedEvidenceSha256": release.digest(original_file)}}
        original, final = [], []
        for target in ("macos-arm64", "macos-x86_64", "windows-x86_64"):
            mac = target.startswith("macos")
            original.append({"id": target, "binarySha256": "before" if mac else "windows",
                             "buildEvidence": original_mac if mac else original_win})
            final.append({"id": target, "binarySha256": "after" if mac else "windows",
                          "analyzedSha256": target, "buildEvidence": signed if mac else original_win})
        (self.source / "inventory.json").write_text(json.dumps({"targets": original}))
        self.paths = []
        (self.root / "sbom").mkdir()
        for suffix in ("zip", "dmg"):
            artifact = self.root / ("cURL-1.2.3." + suffix)
            artifact.write_bytes(suffix.encode())
            path = self.root / "sbom" / (artifact.name + ".inventory.json")
            path.write_text(json.dumps({
                "version": "1.2.3", "targets": copy.deepcopy(final),
                "artifact": {"name": artifact.name, "sha256": release.digest(artifact)}}))
            self.paths.append(path)

    def test_release_binding_does_not_invalidate_original_kit_manifest(self):
        original = {p.name: p.read_bytes() for p in self.source.iterdir()}
        output = self.root / "sources.zip"
        with patch.object(release.relink_review_delivery, "inspect"), patch.object(
                release, "require_source_inventory"):
            release.finalize(self.source, self.paths, output, "1.2.3")
        self.assertEqual(original, {p.name: p.read_bytes() for p in self.source.iterdir()})
        with zipfile.ZipFile(output) as archive:
            self.assertIn("cURL-1.2.3-sources/release-binding.json", archive.namelist())
            self.assertIn("cURL-1.2.3-sources/corresponding-source/inventory.json", archive.namelist())

    def test_changed_linker_evidence_cannot_inherit_original_source_kit(self):
        for path in self.paths:
            inventory = json.loads(path.read_text())
            inventory["targets"][0]["buildEvidence"]["selectedArchives"] = ["different"]
            path.write_text(json.dumps(inventory))
        output = self.root / "sources.zip"
        with patch.object(release.relink_review_delivery, "inspect"), patch.object(
                release, "require_source_inventory"):
            with self.assertRaisesRegex(ValueError, "evidence changed"):
                release.finalize(self.source, self.paths, output, "1.2.3")
        self.assertFalse(output.exists())
