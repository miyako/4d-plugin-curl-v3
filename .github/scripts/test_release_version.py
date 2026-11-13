import contextlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_version as release


@contextlib.contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def sources(root, version="1.2.3", variable=True):
    (root / release.PROJECT).parent.mkdir(parents=True, exist_ok=True)
    (root / release.PROJECT).write_text(
        f"MARKETING_VERSION = {version};\nMARKETING_VERSION = {version};\n",
        encoding="utf-8")
    (root / release.PLIST).write_bytes(plistlib.dumps({
        "CFBundleShortVersionString": "$(MARKETING_VERSION)" if variable else version,
    }))


class SourceVersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        sources(self.root)

    def test_build_reads_real_project_without_tag_input(self):
        self.assertRegex(release.source_version(Path(__file__).resolve().parents[2]), release.SEMVER)

    def test_patch_minor_major_and_build_variable_preservation(self):
        for mode, expected in (("patch", "1.2.4"), ("minor", "1.3.0"), ("major", "2.0.0")):
            with self.subTest(mode=mode):
                sources(self.root)
                self.assertEqual(release.bump_source(mode, self.root), expected)
                self.assertEqual(release.source_version(self.root), expected)
                info = plistlib.loads((self.root / release.PLIST).read_bytes())
                self.assertEqual(info["CFBundleShortVersionString"], "$(MARKETING_VERSION)")

    def test_literal_plist_and_existing_build_versions_updated(self):
        sources(self.root, variable=False)
        project = self.root / release.PROJECT
        project.write_text(project.read_text() + "CURRENT_PROJECT_VERSION = 1.2.3;\n")
        plist = self.root / release.PLIST
        info = plistlib.loads(plist.read_bytes())
        info["CFBundleVersion"] = "1.2.3"
        plist.write_bytes(plistlib.dumps(info))
        release.bump_source("patch", self.root)
        self.assertEqual(plistlib.loads(plist.read_bytes())["CFBundleVersion"], "1.2.4")
        self.assertIn("CURRENT_PROJECT_VERSION = 1.2.4;", project.read_text())

    def test_drift_invalid_whitespace_and_injection_rejected_before_writes(self):
        for invalid in ("1.2.3 ", "v1.2.3", "01.2.3", "1.2", '1.2.3"; echo unsafe'):
            with self.subTest(invalid=invalid):
                sources(self.root)
                project = self.root / release.PROJECT
                project.write_text(f"MARKETING_VERSION = {invalid};\n")
                original = project.read_bytes()
                with self.assertRaises(ValueError):
                    release.bump_source("patch", self.root)
                self.assertEqual(project.read_bytes(), original)
        sources(self.root)
        project.write_text("MARKETING_VERSION = 1.2.3;\nMARKETING_VERSION = 1.2.4;\n")
        with self.assertRaisesRegex(ValueError, "disagree"):
            release.source_version(self.root)

    def test_literal_plist_build_and_release_drift_rejected(self):
        for info in ({"CFBundleShortVersionString": "1.2.4"},
                     {"CFBundleShortVersionString": "$(OTHER_VERSION)"},
                     {"CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "1.2.2"},
                     {"CFBundleShortVersionString": "1.2.3",
                      "CFBundleVersion": "$(CURRENT_PROJECT_VERSION)"}):
            with self.subTest(info=info):
                sources(self.root)
                (self.root / release.PLIST).write_bytes(plistlib.dumps(info))
                with self.assertRaises(ValueError):
                    release.source_version(self.root)


class PublicationTests(unittest.TestCase):
    def test_existing_release_never_overwritten(self):
        with patch.object(release, "api_optional", return_value={"id": 123}):
            with self.assertRaisesRegex(ValueError, "already exists"):
                release.publication_check("owner/repo", "v1.2.3", "a" * 40)

    def test_tag_on_another_commit_rejected(self):
        with patch.object(release, "api_optional", side_effect=[
                None, {"object": {"type": "commit", "sha": "b" * 40}}]):
            with self.assertRaisesRegex(ValueError, "another commit"):
                release.publication_check("owner/repo", "v1.2.3", "a" * 40)

    def test_matching_existing_lightweight_and_annotated_tags_allowed(self):
        for kind in ("commit", "tag"):
            with self.subTest(kind=kind):
                ref = {"object": {"type": kind, "sha": "a" * 40}}
                with patch.object(release, "api_optional", side_effect=[None, ref]), patch.object(
                        release, "run", return_value=json.dumps(
                            {"object": {"type": "commit", "sha": "a" * 40}})):
                    self.assertEqual(release.publication_check(
                        "owner/repo", "v1.2.3", "a" * 40), ref)

    def test_tag_whitespace_rejected_before_network(self):
        with patch.object(release, "api_optional") as network:
            with self.assertRaisesRegex(ValueError, "Invalid release tag"):
                release.publication_check("owner/repo", "v1.2.3 ", "a" * 40)
            network.assert_not_called()

    def test_only_404_is_absence(self):
        for error, absent in (("gh: Not Found (HTTP 404)", True),
                              ("gh: SSO required (HTTP 403)", False),
                              ("connection timeout", False)):
            with self.subTest(error=error):
                result = subprocess.CompletedProcess([], 1, "", error)
                with patch.object(subprocess, "run", return_value=result):
                    if absent:
                        self.assertIsNone(release.api_optional("endpoint"))
                    else:
                        with self.assertRaisesRegex(ValueError, "lookup failed"):
                            release.api_optional("endpoint")

    def test_publish_pins_tag_then_creates_never_clobbers(self):
        with tempfile.TemporaryDirectory() as temp:
            asset = Path(temp) / "artifact.zip"
            asset.write_bytes(b"already validated container")
            notes = Path(temp) / "notes.md"
            notes.write_text("Dependency and security context")
            for existing in (None, {"object": {"sha": "a" * 40}}):
                with self.subTest(existing=existing):
                    with patch.object(release, "run", return_value="a" * 40) as run, patch.object(
                            release, "source_version", return_value="1.2.3"), patch.object(
                            release, "publication_check", return_value=existing):
                        release.publish("a" * 40, "owner/repo", "1.2.3", [asset], notes)
                        calls = [call.args for call in run.call_args_list]
                        self.assertEqual(len([c for c in calls if "--method" in c]),
                                         1 if existing is None else 0)
                        self.assertEqual(calls[-1][:4], ("gh", "release", "create", "v1.2.3"))
                        self.assertIn("--verify-tag", calls[-1])
                        self.assertIn("--notes-file", calls[-1])
                        self.assertFalse(any("--clobber" in c for c in calls))

    def test_missing_asset_or_changed_version_blocks_publication(self):
        with patch.object(release, "run", return_value="a" * 40), patch.object(
                release, "source_version", return_value="1.2.3"), patch.object(
                release, "publication_check") as network:
            for version, assets in (("1.2.3", []), ("1.2.4", [Path("missing")])):
                with self.subTest(version=version):
                    with self.assertRaises(ValueError):
                        release.publish("a" * 40, "owner/repo", version, assets, Path("missing-notes"))
                    network.assert_not_called()

    def test_missing_notes_blocks_tag_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            asset = Path(temp) / "artifact.zip"
            asset.write_bytes(b"container")
            with patch.object(release, "run", return_value="a" * 40), patch.object(
                    release, "source_version", return_value="1.2.3"), patch.object(
                    release, "publication_check") as network:
                with self.assertRaisesRegex(ValueError, "release notes"):
                    release.publish("a" * 40, "owner/repo", "1.2.3", [asset], Path(temp) / "missing")
                network.assert_not_called()


class BranchBumpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.origin = self.root / "origin.git"
        self.repo = self.root / "work"
        subprocess.run(["git", "init", "--bare", "-q", str(self.origin)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "selected", str(self.repo)], check=True)
        with working_directory(self.repo):
            sources(self.repo)
            release.run("git", "config", "user.name", "Test")
            release.run("git", "config", "user.email", "test@example.invalid")
            release.run("git", "add", ".")
            release.run("git", "commit", "-qm", "Initial")
            release.run("git", "remote", "add", "origin", str(self.origin))
            release.run("git", "push", "-q", "origin", "HEAD:refs/heads/selected")
            self.sha = release.run("git", "rev-parse", "HEAD")

    def test_bump_updates_only_selected_source_branch_without_tags(self):
        with working_directory(self.repo):
            with patch.object(release, "api_optional") as network:
                self.assertEqual(release.bump_branch(self.sha, "refs/heads/selected", "patch"), "1.2.4")
                network.assert_not_called()
            new = release.run("git", "rev-parse", "HEAD")
            self.assertEqual(release.remote_sha("refs/heads/selected"), new)
            self.assertEqual(release.run("git", "ls-remote", "--tags", "origin"), "")
            self.assertTrue(release.run("git", "log", "-1", "--format=%B").endswith(release.TRAILER))
            self.assertEqual(release.run("git", "diff-tree", "--no-commit-id", "--name-only",
                                         "-r", "HEAD"), str(release.PROJECT))

    def test_tag_selection_dirty_wrong_sha_and_stale_remote_block_bump(self):
        with working_directory(self.repo):
            with self.assertRaisesRegex(ValueError, "Select a branch"):
                release.bump_branch(self.sha, "refs/tags/v1.2.3", "patch")
            with self.assertRaisesRegex(ValueError, "immutable"):
                release.bump_branch("b" * 40, "refs/heads/selected", "patch")
            (self.repo / "untracked").write_text("dirty")
            with self.assertRaisesRegex(ValueError, "clean"):
                release.bump_branch(self.sha, "refs/heads/selected", "patch")
            (self.repo / "untracked").unlink()
            with patch.object(release, "remote_sha", return_value="b" * 40):
                with self.assertRaisesRegex(ValueError, "moved since dispatch"):
                    release.bump_branch(self.sha, "refs/heads/selected", "patch")
            self.assertEqual(release.run("git", "rev-parse", "HEAD"), self.sha)

    def test_preflight_validates_source_and_existing_publication_without_mutation(self):
        with working_directory(self.repo), patch.object(release, "publication_check") as publication:
            self.assertEqual(release.preflight(
                self.sha, "refs/heads/selected", "owner/repo"), "1.2.3")
            publication.assert_called_once_with("owner/repo", "v1.2.3", self.sha)
            self.assertEqual(release.run("git", "status", "--porcelain"), "")


class WorkflowContractTests(unittest.TestCase):
    def test_build_and_bump_are_independent_manual_decisions(self):
        root = Path(__file__).resolve().parents[2]
        build = (root / ".github/workflows/release.yml").read_text()
        bump = (root / ".github/workflows/bump-version.yml").read_text()
        self.assertIn("name: Build\n", build)
        self.assertNotIn("inputs.tag", build)
        self.assertNotIn("  push:", build)
        self.assertNotIn("inputs:", build)
        self.assertIn('preflight --sha "$GITHUB_SHA" --ref "$GITHUB_REF"', build)
        self.assertEqual(build.count("ref: ${{ github.sha }}"), 3)
        source = build.split("  source-native:", 1)[1].split("  build-macos:", 1)[0]
        self.assertIn("needs: version", source)
        self.assertIn("uses: ./.github/workflows/native-trace.yml", source)
        self.assertIn("release_version.py publish", build)
        self.assertNotIn("softprops/action-gh-release", build)
        self.assertIn("release_version.py bump", bump)
        self.assertNotIn("git tag", bump)
        self.assertNotIn("workflow_run", build)
        self.assertIn("--schema-dir", build)
        self.assertIn("notarytool submit", build)

    def test_final_artifacts_only_attested_after_mutation_in_separate_job(self):
        root = Path(__file__).resolve().parents[2]
        build = (root / ".github/workflows/release.yml").read_text()
        native, publish = build.split("\n  publish:\n")
        self.assertIn("permissions:\n  contents: read", native)
        self.assertNotIn("id-token: write", native)
        self.assertNotIn("attestations: write", native)
        self.assertLess(native.index("xcrun stapler staple"), native.index("generate and validate"))
        self.assertLess(native.index("generate and validate"), native.index("name: finalized-release"))
        self.assertIn("needs: [version, build-macos]", publish)
        self.assertIn("id-token: write", publish)
        self.assertIn("attestations: write", publish)
        self.assertLess(publish.index("name: finalized-release"), publish.index("actions/attest-build-provenance@"))
        self.assertLess(publish.rindex("actions/attest-sbom@"), publish.index("name: create GitHub Release"))
        for container in ("zip", "dmg"):
            for document in ("cdx", "spdx"):
                self.assertIn(f".{container}.{document}.json", publish)
        self.assertNotIn("notarytool", publish)
        self.assertNotIn("secrets.", publish)

    def test_external_actions_are_immutable(self):
        import re
        root = Path(__file__).resolve().parents[2]
        for workflow in (root / ".github/workflows").glob("*.yml"):
            for action in re.findall(r"uses:\s+([^\s#]+)", workflow.read_text()):
                if not action.startswith("./"):
                    self.assertRegex(action, r"^[^@]+@[a-f0-9]{40}$", str(workflow))


if __name__ == "__main__":
    unittest.main()
