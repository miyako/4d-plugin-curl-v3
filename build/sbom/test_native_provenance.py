import copy
import argparse
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
            "toolchain": {}, "recipeFiles": [], "sourceFiles": [],
        }
        (kit / "native-build-provenance.json").write_text(json.dumps(record))
        return kit

    def copy_windows(self, kit):
        path = self.vendor / "lib/64/libcurl.lib"
        path.parent.mkdir(parents=True)
        path.write_bytes((kit / "install/lib/libcurl.a").read_bytes())
        return path

    def proxy_kit(self):
        kit = self.root / "proxy"
        (kit / "install/lib").mkdir(parents=True)
        archives = []
        for name in ("libproxy.lib", "modman.lib"):
            path = kit / "install/lib" / name
            path.write_bytes(("Synthetic " + name).encode())
            archives.append({"path": "lib/" + name, "sha256": provenance.digest(path)})
        record = {
            "schema_version": 2, "target": "windows-x86_64",
            "components": [{"name": "libproxy", "version": "0.4.17"},
                           {"name": "libmodman"}],
            "source_repository": "https://github.com/libproxy/libproxy",
            "source_commit": "1" * 40, "licenseFileSha256": "b" * 64,
            "status": "isolated-candidate-not-approved-for-production",
            "archives": archives, "toolchainExecutables": [], "recipeFiles": [],
            "configure_arguments": ["static"], "patches": [], "acceptedCandidateChanges": [],
            "compilerArchiveEvidence": {"proxy": {"compiledObjects": ["proxy fixture"]},
                                       "modman": {"compiledObjects": ["modman fixture"]}},
            "limitations": ["Bundled libmodman has no independently established release version."],
        }
        (kit / "proxy-build-provenance.json").write_text(json.dumps(record))
        return kit

    def test_proxy_components_keep_distinct_source_scope_and_unknown_modman_version(self):
        kit = self.proxy_kit()
        result = native_provenance.stage(self.vendor, "windows-x86_64", [kit])
        rows = {r["name"]: r for r in result["rebuiltArchiveEvidence"]}
        self.assertEqual(set(rows), {"libproxy", "libmodman"})
        self.assertEqual(rows["libproxy"]["version"], "0.4.17")
        modman = rows["libmodman"]
        self.assertNotIn("version", modman)
        self.assertEqual(modman["sourceSubpath"], "libmodman")
        self.assertTrue(modman["purl"].endswith("#libmodman"))
        self.assertEqual(modman["originalBuildRecords"][0]["compilerArchiveEvidence"],
                         {"compiledObjects": ["modman fixture"]})
        self.assertEqual(modman["originalBuildRecords"][0]["sha256"],
                         provenance.digest(kit / "proxy-build-provenance.json"))
        record = {
            "rebuiltArchiveEvidence": list(rows.values()),
            "linkEvidence": {"windows-x86_64": {"archives": [
                {"candidatePath": a["path"], "sha256": a["sha256"]}
                for row in rows.values() for a in row["archives"]]}},
        }
        dependencies = generate.build_dependencies(record, "windows-x86_64", [])
        self.assertEqual({d["name"]: d["version"] for d in dependencies},
                         {"libproxy": "0.4.17", "libmodman": None})
        self.assertIn("not compliance proof", modman["licenseScope"])

    def test_proxy_schema1_is_not_promoted_and_ambiguous_records_fail(self):
        kit = self.proxy_kit()
        path = kit / "proxy-build-provenance.json"
        record = json.loads(path.read_text())
        record["schema_version"] = 1
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "fresh compiler-object/archive"):
            native_provenance.collect(self.vendor, "windows-x86_64", [kit])
        self.inspector.assert_not_called()
        (kit / "native-build-provenance.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            native_provenance.collect(self.vendor, "windows-x86_64", [kit])

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
                         ("curl", "8.21.0", "curl AND ISC"))
        record["linkEvidence"]["windows-x86_64"]["archives"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "disagrees with source"):
            generate.build_dependencies(record, "windows-x86_64", [])
        copied.write_bytes(b"other archive")
        with self.assertRaisesRegex(ValueError, "Copied native archive"):
            native_provenance.collect(self.vendor, "windows-x86_64", [kit])

    def test_inspected_source_candidates_need_not_be_explicit_project_declarations(self):
        kit = self.kit("windows-x86_64")
        copied = self.copy_windows(kit)
        (self.vendor / "cURL.vcxproj").write_text(
            '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
            '<ItemDefinitionGroup Condition="\'$(Configuration)|$(Platform)\'==\'Release|x64\'">'
            '<Link><AdditionalDependencies>system.lib;</AdditionalDependencies></Link>'
            '</ItemDefinitionGroup></Project>')
        workflows = self.vendor / ".github/workflows"
        workflows.mkdir(parents=True)
        for name in ("release.yml", "build-brotli.yml"):
            (workflows / name).write_text("Synthetic configuration fixture")
        binary = self.root / "binary"
        binary.write_bytes(b"Synthetic binary fixture")
        args = argparse.Namespace(
            root=self.vendor, target="windows-x86_64", binary=binary,
            native_source_kit=[kit], brotli_provenance=None, openssl_provenance=None,
            output=self.root / "evidence.json", manifest=None, link_map=[])
        with patch.object(generate, "git", return_value="1" * 40):
            generate.collect(args)
            record = json.loads(args.output.read_text())
            self.assertEqual(len(record["rebuiltArchiveEvidence"]), 1)
            self.assertEqual(generate.build_dependencies(record, "windows-x86_64", []), [])
            original = self.root / "legacy-provenance.json"
            original.write_text(json.dumps(record["rebuiltArchiveEvidence"][0]))
            args.native_source_kit = []
            args.brotli_provenance = original
            with self.assertRaisesRegex(ValueError, "does not match declared archive"):
                generate.collect(args)
            args.brotli_provenance = None
            args.native_source_kit = [kit]
            copied.write_bytes(b"Unrelated replacement")
            with self.assertRaisesRegex(ValueError, "Copied native archive"):
                generate.collect(args)

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

    def test_project_staging_never_reuses_output_or_accepts_a_partial_candidate_stack(self):
        self.vendor.mkdir()
        with self.assertRaisesRegex(ValueError, "new output directory"):
            native_provenance.stage_project(self.root, self.vendor, "windows-x86_64", [])
        output = self.root / "project-candidate"
        with self.assertRaisesRegex(ValueError, "every selected native"):
            native_provenance.stage_project(
                self.root, output, "windows-x86_64", [self.kit("windows-x86_64")])
        self.assertFalse(output.exists())

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

    def test_mixed_ssh_notices_are_preserved_without_relicensing_public_domain(self):
        kit = self.kit("windows-x86_64")
        record_path = kit / "native-build-provenance.json"
        record = json.loads(record_path.read_text())
        record.pop("sourceArchive")
        record.update(library="libssh2", version="1.11.1_DEV", source_commit="1" * 40,
                      source_repository="https://github.com/libssh2/libssh2",
                      licenseFileSha256="b" * 64, noticeFiles=[])
        for name, text in (("COPYING", "BSD terms fixture"),
                           ("src/chacha.c", "/* Public domain fixture */\nint not_license;"),
                           ("src/bcrypt.c", "/* Permission to use: ISC-style fixture */")):
            path = kit / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            record["noticeFiles"].append({"path": name, "sha256": provenance.digest(path)})
        record_path.write_text(json.dumps(record))
        copied = self.vendor / "lib/64/libssh2.lib"
        copied.parent.mkdir(parents=True)
        copied.write_bytes((kit / "install/lib/libcurl.a").read_bytes())
        row = native_provenance.collect(self.vendor, "windows-x86_64", [kit])[0]
        self.assertNotIn("license", row)
        self.assertIn("Public domain fixture", row["licenseEvidence"]["text"])
        self.assertIn("ISC-style fixture", row["licenseEvidence"]["text"])
        self.assertNotIn("int not_license", row["licenseEvidence"]["text"])
        self.assertTrue(row["licenseEvidence"]["id"].startswith("LicenseRef-"))

    def test_source_reuse_rejects_foreign_runs_and_failed_latest_attempts(self):
        run = {"id": 1, "head_sha": "1" * 40, "head_repository": {"full_name": "owner/repo"},
               "head_branch": "candidate", "path": ".github/workflows/native-trace.yml",
               "event": "workflow_dispatch"}
        jobs = {"total_count": 3, "jobs": [
            {"id": i, "name": "curl-source / curl-source (runner, " + target + ")",
             "run_attempt": 1, "conclusion": "success"}
            for i, target in enumerate(("macos-arm64", "macos-x86_64", "windows-x86_64"))]}
        result = native_provenance.verify_producer_run(run, jobs, "owner/repo", "candidate", "curl")
        self.assertEqual(len(result["producers"]), 3)
        with self.assertRaisesRegex(ValueError, "same-repository/branch"):
            native_provenance.verify_producer_run(run, jobs, "other/repo", "candidate", "curl")
        jobs["jobs"].append(dict(jobs["jobs"][0], run_attempt=2, conclusion="failure"))
        jobs["total_count"] += 1
        with self.assertRaisesRegex(ValueError, "Latest exact source producer"):
            native_provenance.verify_producer_run(run, jobs, "owner/repo", "candidate", "curl")
        jobs["jobs"].pop()
        with self.assertRaisesRegex(ValueError, "complete bounded enumeration"):
            native_provenance.verify_producer_run(run, jobs, "owner/repo", "candidate", "curl")

    def test_proxy_reuse_requires_all_exact_target_jobs_and_latest_success(self):
        run = {"id": 1, "head_sha": "1" * 40, "head_repository": {"full_name": "owner/repo"},
               "head_branch": "candidate", "path": ".github/workflows/native-trace.yml",
               "event": "workflow_dispatch"}
        jobs = {"total_count": 3, "jobs": [
            {"id": i, "name": "Isolated proxy candidate (" + target + ")",
             "run_attempt": 1, "conclusion": "success"}
            for i, target in enumerate(("macos-arm64", "macos-x86_64", "windows-x86_64"))]}
        self.assertEqual(len(native_provenance.verify_producer_run(
            run, jobs, "owner/repo", "candidate", "libproxy")["producers"]), 3)
        jobs["jobs"][0]["name"] = "Isolated proxy candidate (wrong, macos-arm64)"
        with self.assertRaisesRegex(ValueError, "Latest exact source producer"):
            native_provenance.verify_producer_run(
                run, jobs, "owner/repo", "candidate", "libproxy")
        jobs["jobs"][0]["name"] = "Isolated proxy candidate (macos-arm64)"
        jobs["jobs"].append(dict(jobs["jobs"][0], run_attempt=2, conclusion="failure"))
        jobs["total_count"] += 1
        with self.assertRaisesRegex(ValueError, "Latest exact source producer"):
            native_provenance.verify_producer_run(
                run, jobs, "owner/repo", "candidate", "libproxy")

    def test_inventory_reuse_checks_its_own_latest_aggregation_job(self):
        run = {"id": 1, "head_sha": "1" * 40, "head_repository": {"full_name": "owner/repo"},
               "head_branch": "candidate", "path": ".github/workflows/native-trace.yml",
               "event": "workflow_dispatch"}
        job = {"id": 1, "name": "curl-source / inventory",
               "run_attempt": 1, "conclusion": "success"}
        jobs = {"total_count": 1, "jobs": [job]}
        self.assertEqual(len(native_provenance.verify_producer_run(
            run, jobs, "owner/repo", "candidate", "inventory")["producers"]), 1)
        jobs["jobs"].append(dict(job, run_attempt=2, conclusion="failure"))
        jobs["total_count"] += 1
        with self.assertRaisesRegex(ValueError, "Latest exact source producer"):
            native_provenance.verify_producer_run(
                run, jobs, "owner/repo", "candidate", "inventory")
