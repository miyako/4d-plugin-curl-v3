import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import relink_review_delivery as review
from provenance import digest


class ReviewDeliveryTests(unittest.TestCase):
    def fixture(self, root):
        kits, summaries, targets = {}, {}, []
        for platform in set(review.TARGETS.values()):
            kit = root / platform
            kit.mkdir()
            kits[platform] = kit
            architectures = [{"target": t, "originalSliceSha256": t + "-slice"}
                             for t, p in review.TARGETS.items() if p == platform]
            (kit / review.plugins.PORTABLE[platform]).write_text(json.dumps({
                "originalBinarySha256": platform + "-binary", "architectures": architectures}))
            summaries[kit] = {"selectedArchives": {"project/lib/library.a": "archive-sha"}}
        for target, platform in review.TARGETS.items():
            targets.append({
                "id": target, "binarySha256": platform + "-binary",
                "analyzedSha256": target + "-slice" if target.startswith("macos-")
                else platform + "-binary",
                "dependencies": [{"name": "Fixture", "selectedArchives": [
                    {"candidatePath": "lib/library.a", "sha256": "archive-sha"}],
                    "archiveIdentities": [{"identity": {"sourceEvidence": {}}}]}],
            })
        return {"inventoryVersion": 1, "targets": targets}, kits, summaries

    def test_exact_target_bindings_preserve_unknown_numeric_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory, kits, summaries = self.fixture(Path(temporary))
            with patch.object(review.plugins, "inspect", side_effect=lambda p: summaries[p]):
                bound = review.join_selected(inventory, kits)
            self.assertEqual(len(bound), 3)
            self.assertTrue(all(b["version"] is None for b in bound))

    def test_rejects_archive_binary_slice_and_repeated_assignment(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory, kits, summaries = self.fixture(Path(temporary))
            variants = []
            for key in ("binarySha256", "analyzedSha256"):
                changed = copy.deepcopy(inventory)
                changed["targets"][0][key] = "wrong"
                variants.append(changed)
            changed = copy.deepcopy(inventory)
            changed["targets"][0]["dependencies"][0]["selectedArchives"][0]["sha256"] = "wrong"
            variants.append(changed)
            changed = copy.deepcopy(inventory)
            changed["targets"][0]["dependencies"] *= 2
            variants.append(changed)
            changed = copy.deepcopy(inventory)
            changed["targets"][0]["dependencies"][0]["archiveIdentities"] = []
            variants.append(changed)
            with patch.object(review.plugins, "inspect", side_effect=lambda p: summaries[p]):
                for changed in variants:
                    with self.subTest(changed=changed), self.assertRaises(ValueError):
                        review.join_selected(changed, kits)

    def test_provider_join_deduplicates_fat_archive_references_but_rejects_conflict(self):
        record = {"target": "macos-arm64", "buildMaterialEvidence": {
            "originalRecordSha256": "a" * 64}}
        source = {"source_builds": [record, copy.deepcopy(record)]}
        inventory = {"targets": [{"dependencies": [{"name": "Provider", "archiveIdentities": [
            {"identity": {"sourceEvidence": source}}]}]}]}
        self.assertEqual(len(review.provider_references(inventory)), 1)
        source["source_builds"][1]["target"] = "macos-x86_64"
        with self.assertRaises(ValueError):
            review.provider_references(inventory)
        source["source_builds"] = [{"target": "macos-arm64"}]
        with self.assertRaises(ValueError):
            review.provider_references(inventory)

    def test_provider_subset_rejects_overwrite_of_unmodified_original_record(self):
        record = {"buildMaterials": {"files": []},
                  "archives": [{"path": "original-build-record.json"}]}
        with self.assertRaises(ValueError):
            review.provider_paths(record)

    def test_reference_checks_actual_binary_even_when_container_hash_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reference.zip"
            with zipfile.ZipFile(path, "w") as archive:
                for name in (review.generate.MAC, review.generate.WIN, review.generate.PLIST):
                    archive.writestr(name, b"not a native executable")
            inventory = {"artifact": {"sha256": digest(path)}, "targets": [{
                "id": "windows-x86_64", "binaryPath": review.generate.WIN,
                "binarySha256": "wrong", "analyzedSha256": "wrong"}]}
            with self.assertRaisesRegex(ValueError, "binary differs"):
                review.reference_plugin(path, inventory)
            sha = review.generate.sha256(b"not a native executable")
            inventory["targets"][0].update(binarySha256=sha, analyzedSha256=sha)
            with self.assertRaisesRegex(ValueError, "PE binary"):
                review.reference_plugin(path, inventory)


if __name__ == "__main__":
    unittest.main()
