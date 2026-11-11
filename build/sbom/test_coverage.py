import copy
import unittest

from coverage import require_selected_coverage, selected_archive_coverage


class CoverageTests(unittest.TestCase):
    def target(self):
        selected = {"candidatePath": "a/known.a", "sha256": "a" * 64}
        return {
            "id": "macos-arm64",
            "buildEvidence": {"linkEvidence": {"macos-arm64": {"archives": [
                selected, {"resolvedPath": "/usr/lib/system.a", "sha256": "b" * 64},
            ]}}, "declaredInputs": [{"path": "a/unused.a", "sha256": "c" * 64}]},
            "dependencies": [{"name": "known", "selectedArchives": [copy.deepcopy(selected)]}],
        }

    def test_unknown_version_is_named_not_version_verified(self):
        target = self.target()
        result = require_selected_coverage(target)
        self.assertEqual(result["selectedRepositoryArchives"], 1)
        self.assertEqual(result["namedPackageArchives"], 1)
        self.assertEqual(result["versionedPackageArchives"], 0)
        self.assertEqual(result["unknownVersionPackages"], ["known"])
        target["dependencies"][0]["version"] = "1.0"
        self.assertEqual(require_selected_coverage(target)["versionedPackageArchives"], 1)

    def test_new_selected_archive_cannot_silently_remain_hash_only(self):
        target = self.target()
        target["buildEvidence"]["linkEvidence"]["macos-arm64"]["archives"].append(
            {"candidatePath": "a/new.a", "sha256": "d" * 64})
        with self.assertRaisesRegex(ValueError, "lack named packages: a/new.a"):
            require_selected_coverage(target)

    def test_package_hash_mismatch_or_unselected_archive_rejected(self):
        for change in ({"sha256": "0" * 64}, {"candidatePath": "a/unused.a"}):
            target = self.target()
            target["dependencies"][0]["selectedArchives"][0].update(change)
            with self.assertRaisesRegex(ValueError, "not an actual selected"):
                selected_archive_coverage(target)

    def test_historical_no_evidence_has_no_reconstructed_selections(self):
        result = require_selected_coverage({"id": "macos-arm64", "dependencies": []})
        self.assertEqual(result["selectedRepositoryArchives"], 0)
