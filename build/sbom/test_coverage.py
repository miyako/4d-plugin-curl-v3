import copy
import unittest

from coverage import (
    require_selected_coverage, require_selected_source_coverage, selected_archive_coverage,
)


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

    def source_target(self, provider=False):
        target = self.target()
        package = target["dependencies"][0]
        source = {
            "name": "known",
            "archives": [{"path": "a/known.a", "sha256": "a" * 64}],
            "originalBuildRecords": [
                {"target": arch, "sha256": "b" * 64,
                 "recipeFiles": [{"path": "recipe", "sha256": "c" * 64}],
                 "toolchain": {"compiler": "recorded"}}
                for arch in ("macos-arm64", "macos-x86_64")],
        }
        if provider:
            package["name"] = source["name"] = "OpenSSL"
            source.pop("originalBuildRecords")
            source["source_builds"] = [
                {"target": arch, "source_commit": "d" * 40,
                 "buildMaterialEvidence": {
                     "schemaVersion": 1, "originalRecordSha256": "e" * 64,
                     "sourceCommit": "d" * 40, "sourceFiles": 2, "materialFiles": 3,
                     "archives": [{"path": "lib/known.a", "objectMembers": 1}],
                 }} for arch in ("macos-arm64", "macos-x86_64")]
        package["archiveIdentities"] = [{
            "path": "a/known.a", "identity": {
                "name": package["name"], "evidenceType": "source-build-and-selected-archive",
                "sourceEvidence": source}}]
        return target

    def test_source_gate_accepts_original_build_references_without_inventing_version(self):
        result = require_selected_source_coverage(self.source_target())
        self.assertEqual(result["sourceBoundArchives"], 1)
        self.assertEqual(result["versionedPackageArchives"], 0)

    def test_source_gate_rejects_named_but_non_source_archive(self):
        target = self.source_target()
        target["dependencies"][0]["archiveIdentities"][0]["identity"]["evidenceType"] = "hash-only"
        self.assertEqual(require_selected_coverage(target)["namedPackageArchives"], 1)
        with self.assertRaisesRegex(ValueError, "lacks source binding"):
            require_selected_source_coverage(target)

    def test_source_gate_rejects_missing_original_native_reference(self):
        target = self.source_target()
        source = target["dependencies"][0]["archiveIdentities"][0]["identity"]["sourceEvidence"]
        source["originalBuildRecords"].pop()
        with self.assertRaisesRegex(ValueError, "complete original build references"):
            require_selected_source_coverage(target)

    def test_provider_source_gate_requires_original_compiler_materials(self):
        target = self.source_target(provider=True)
        self.assertEqual(require_selected_source_coverage(target)["sourceBoundArchives"], 1)
        source = target["dependencies"][0]["archiveIdentities"][0]["identity"]["sourceEvidence"]
        for change in ("missing", "no-objects", "different-source"):
            changed = copy.deepcopy(target)
            material = changed["dependencies"][0]["archiveIdentities"][0]["identity"][
                "sourceEvidence"]["source_builds"][0]["buildMaterialEvidence"]
            if change == "missing":
                material.clear()
            elif change == "no-objects":
                material["archives"][0]["objectMembers"] = 0
            else:
                material["sourceCommit"] = "f" * 40
            with self.subTest(change=change), self.assertRaisesRegex(
                    ValueError, "original compiler/object materials"):
                require_selected_source_coverage(changed)
        source["source_builds"].pop()
        with self.assertRaisesRegex(ValueError, "all original native targets"):
            require_selected_source_coverage(target)

    def test_source_gate_rejects_mismatched_or_duplicate_archive_identity(self):
        for change in ("hash", "duplicate"):
            target = self.source_target()
            identities = target["dependencies"][0]["archiveIdentities"]
            if change == "hash":
                identities[0]["identity"]["sourceEvidence"]["archives"][0]["sha256"] = "0" * 64
            else:
                identities.append(copy.deepcopy(identities[0]))
            with self.subTest(change=change), self.assertRaises(ValueError):
                require_selected_source_coverage(target)

    def test_brotli_materials_must_reference_the_same_original_record(self):
        target = self.source_target(provider=True)
        package = target["dependencies"][0]
        identity = package["archiveIdentities"][0]["identity"]
        source = identity["sourceEvidence"]
        package["name"] = identity["name"] = source["name"] = "Brotli"
        source["source_builds"] = [
            {"target": original["target"], "originalRecordSha256": "e" * 64,
             "record": original} for original in source["source_builds"]]
        self.assertEqual(require_selected_source_coverage(target)["sourceBoundArchives"], 1)
        source["source_builds"][0]["originalRecordSha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "original compiler/object materials"):
            require_selected_source_coverage(target)
