import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import release_notes


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "sbom").mkdir()
        self.paths = []
        for suffix in ("zip", "dmg"):
            artifact = self.root / ("cURL-1.2.3." + suffix)
            artifact.write_bytes(suffix.encode())
            inventory = {
                "version": "1.2.3",
                "artifact": {"name": artifact.name, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
                "targets": [
                    {"id": target, "binarySha256": target, "analyzedSha256": target,
                     "dependencies": [
                         {"name": "libssh2", "version": "1.11.1_DEV"},
                         {"name": "libiconv", "version": "1.18" if target.startswith("windows") else "1.16"},
                         {"name": "libproxy"},
                     ]}
                    for target in release_notes.TARGETS
                ],
            }
            path = self.root / "sbom" / (artifact.name + ".inventory.json")
            path.write_text(json.dumps(inventory))
            self.paths.append(path)

    def test_preserves_suffixes_platform_differences_and_unknowns(self):
        notes = release_notes.render(self.paths, "1.2.3")
        self.assertIn("| libiconv | 1.16 | 1.16 | 1.18 |", notes)
        self.assertIn("1.11.1_DEV", notes)
        self.assertIn("Version not verified", notes)
        self.assertIn("not a vulnerability assessment", notes)
        self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", notes)

    def test_mismatch_and_duplicate_target_rejected(self):
        for mutation in (
            lambda inv: inv.update(version="1.2.4"),
            lambda inv: inv["targets"][0]["dependencies"][0].update(version="1.11.2"),
            lambda inv: inv["targets"][0].update(binarySha256="different"),
            lambda inv: inv["targets"].append(inv["targets"][0]),
            lambda inv: inv["targets"][0]["dependencies"].append({"name": "libssh2"}),
        ):
            original = self.paths[0].read_text()
            inventory = json.loads(original)
            mutation(inventory)
            self.paths[0].write_text(json.dumps(inventory))
            with self.assertRaises(ValueError):
                release_notes.render(self.paths, "1.2.3")
            self.paths[0].write_text(original)
        with self.assertRaises(ValueError):
            release_notes.render([self.paths[0], self.paths[0]], "1.2.3")

    def test_mutated_final_container_rejected(self):
        (self.root / "cURL-1.2.3.dmg").write_bytes(b"changed after SBOM")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            release_notes.render(self.paths, "1.2.3")
