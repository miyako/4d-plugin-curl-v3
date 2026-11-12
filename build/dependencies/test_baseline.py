import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import freeze_baseline
from provenance import digest


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.targets = []
        for target in sorted(freeze_baseline.TARGETS):
            selection = {"candidatePath": "vendor/proxy.a", "sha256": "c" * 64,
                         "selectedMembers": ["proxy.o"]}
            self.targets.append({
                "id": target, "binaryPath": "plugin", "binarySha256": "a" * 64,
                "analyzedSha256": "b" * 64, "selectedArchiveCoverage": {},
                "dependencies": [{"name": "libproxy", "selectedArchives": [selection]}],
                "buildEvidence": {
                    "sourceCommit": freeze_baseline.COMMIT, "rebuiltArchiveEvidence": [],
                    "archiveInventory": [{"path": "vendor/proxy.a", "sha256": "c" * 64}],
                    "linkEvidence": {target: {"archives": [selection]}}, "configuration": [],
                },
            })
        (self.root / "run.json").write_text(json.dumps({
            "headSha": freeze_baseline.COMMIT, "url": "https://example.invalid/run"}))
        (self.root / "build.log").write_text("compiler -target arm64-apple-macos10.13 /MT")
        for suffix in ("zip", "dmg"):
            artifact = self.root / ("cURL-4.9.10." + suffix)
            artifact.write_bytes(("synthetic " + suffix).encode())
            for kind in ("cdx", "spdx"):
                Path(str(artifact) + "." + kind + ".json").write_text("{}")
        self.save()

    def save(self):
        for suffix in ("zip", "dmg"):
            artifact = self.root / ("cURL-4.9.10." + suffix)
            Path(str(artifact) + ".inventory.json").write_text(json.dumps({
                "artifact": {"name": artifact.name, "sha256": digest(artifact)},
                "targets": self.targets}))
        assets = [{"name": p.name, "digest": "sha256:" + digest(p)}
                  for p in self.root.glob("cURL-*")]
        (self.root / "release.json").write_text(json.dumps({
            "url": "https://example.invalid/release", "assets": assets}))

    def freeze(self):
        def observed(path, version, evidence):
            return {"artifact": {"name": path.name, "sha256": digest(path)},
                    "targets": copy.deepcopy(self.targets)}
        with mock.patch.object(freeze_baseline, "inventory", side_effect=observed):
            return freeze_baseline.freeze(self.root)

    def test_selected_package_name_does_not_invent_source_build_provenance(self):
        result = self.freeze()
        self.assertFalse(result["targets"][0]["selectedArchives"][0]["sourceBuilt"])
        self.targets[0]["buildEvidence"]["rebuiltArchiveEvidence"] = [{
            "name": "libproxy", "sourceCommit": "d" * 40,
            "sourceRepository": "https://example.invalid/source",
            "archives": [{"path": "vendor/proxy.a", "sha256": "c" * 64}]}]
        self.save()
        selected = self.freeze()["targets"][0]["selectedArchives"][0]
        self.assertTrue(selected["sourceBuilt"])
        self.assertEqual(selected["sourceCommit"], "d" * 40)

    def test_asset_mutation_is_rejected(self):
        (self.root / "cURL-4.9.10.zip.cdx.json").write_text("mutated")
        with self.assertRaisesRegex(ValueError, "asset hash mismatch"):
            self.freeze()

    def test_linker_selection_cannot_be_substituted_by_package_declaration(self):
        first = self.targets[0]
        first["buildEvidence"]["linkEvidence"][first["id"]]["archives"] = []
        self.save()
        with self.assertRaisesRegex(ValueError, "actual linker selections"):
            self.freeze()


if __name__ == "__main__":
    unittest.main()
