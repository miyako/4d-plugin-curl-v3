import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import license_materials as notices
from provenance import digest, write_json


class Fixture:
    def __init__(self, root):
        self.root = root
        self.materials = root / "materials"
        self.materials.mkdir()
        self.inventory_path = root / "inventory.json"
        self.inventory = {"inventoryVersion": 1, "artifact": {
            "name": "unsigned.zip", "sha256": "a" * 64}, "targets": []}
        self.manifest = {
            "schemaVersion": 1, "evidenceType": "inventory-referenced-notice-input-recovery",
            "status": "not-approved-for-production", "components": [],
            "referencedArtifact": self.inventory["artifact"],
        }
        extra = self.file(b"/* Copyright fixture; additional permission notice. */\n",
                          "extra.c", "additional-source-notice")
        for target, newline in (("macos-arm64", b"\n"), ("windows-x86_64", b"\r\n")):
            primary = self.file(b"Fixture license" + newline, "COPYING", "primary-license")
            source = {"licenseFileSha256": primary["sha256"], "additionalNoticeFiles": [
                {"path": "extra.c", "sha256": extra["sha256"]}]}
            dependency = {
                "name": "Fixture", "version": "1", "license": "MIT",
                "selectedArchives": [{"path": "library.a", "sha256": "b" * 64}],
                "archiveIdentities": [{"identity": {"sourceEvidence": source}}],
            }
            self.inventory["targets"].append({"id": target, "dependencies": [dependency]})
            self.manifest["components"].append({
                "name": "Fixture", "version": "1", "declaredLicense": "MIT",
                "targets": [target], "files": [primary, copy.deepcopy(extra)],
                "selectedArchiveBindings": [
                    {"target": target, **dependency["selectedArchives"][0]}],
            })
        embedded = {"name": "Embedded fixture", "licenseEvidence": {
            "id": "LicenseRef-Fixture", "text": "Fixture public-domain dedication.\n"}}
        self.inventory["targets"][0]["dependencies"].append(embedded)
        self.manifest["components"].append({
            "name": embedded["name"], "targets": ["macos-arm64"], "selectedArchiveBindings": [],
            "files": [self.file(embedded["licenseEvidence"]["text"].encode(), "LicenseRef-Fixture",
                                "embedded-source-license-text")],
        })
        self.seal()

    def file(self, raw, name, role):
        sha = hashlib.sha256(raw).hexdigest()
        relative = "texts/" + sha
        path = self.materials / relative
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
        return {"sourcePath": name, "sha256": sha, "path": relative, "role": role}

    def seal(self):
        write_json(self.inventory_path, self.inventory)
        (self.materials / "inventory.json").write_bytes(self.inventory_path.read_bytes())
        self.manifest["inventorySha256"] = digest(self.inventory_path)
        self.manifest["files"] = {
            p.relative_to(self.materials).as_posix(): digest(p)
            for p in self.materials.rglob("*") if p.is_file() and p.name != notices.INPUT}
        write_json(self.materials / notices.INPUT, self.manifest)


class LicenseMaterialsTests(unittest.TestCase):
    def test_roundtrip_preserves_native_license_variants_and_unknown_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            output = fixture.root / "delivery"
            proof = notices.deliver(fixture.materials, fixture.inventory_path, output)
            self.assertEqual((proof["logicalComponents"], proof["componentNoticeVariants"],
                              proof["selectedArchiveBindings"]), (2, 3, 2))
            for row in fixture.manifest["components"]:
                for item in row["files"]:
                    self.assertEqual((output / "inputs" / item["path"]).read_bytes(),
                                     (fixture.materials / item["path"]).read_bytes())
            text = (output / "NOTICES.txt").read_bytes()
            self.assertIn(b"Fixture license\r\n", text)
            self.assertIn(b"Embedded fixture (version not verified)", text)
            self.assertEqual(notices.inspect_delivery(output, fixture.inventory_path), proof)

    def test_rejects_changed_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            item = fixture.manifest["components"][0]["files"][0]
            (fixture.materials / item["path"]).write_bytes(b"Changed license")
            with self.assertRaisesRegex(ValueError, "bytes changed"):
                notices.inspect(fixture.materials, fixture.inventory_path)

    def test_rejects_lf_substitution_for_recorded_windows_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            rows = fixture.manifest["components"]
            rows[1]["files"][0] = copy.deepcopy(rows[0]["files"][0])
            fixture.seal()
            with self.assertRaisesRegex(ValueError, "Primary license"):
                notices.inspect(fixture.materials, fixture.inventory_path)

    def test_rejects_missing_coverage_changed_archive_and_missing_additional_notice(self):
        for change in ("target", "archive", "additional"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                row = fixture.manifest["components"][0]
                if change == "target":
                    row["targets"] = []
                elif change == "archive":
                    row["selectedArchiveBindings"][0]["sha256"] = "c" * 64
                else:
                    row["files"].pop()
                fixture.seal()
                with self.assertRaises(ValueError):
                    notices.inspect(fixture.materials, fixture.inventory_path)

    def test_supplemental_notice_requires_original_source_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            extra = fixture.file(b"/* Original alternative-grant notice. */\n", "pac.h",
                                 "pinned-source-notice-context")
            record = {"sourceFiles": [{"path": extra["sourcePath"], "sha256": extra["sha256"]}]}
            record_path = fixture.materials / "record.json"
            write_json(record_path, record)
            ref = {"target": "macos-arm64", "sha256": digest(record_path), "path": "record.json"}
            source = fixture.inventory["targets"][0]["dependencies"][0]["archiveIdentities"][0][
                "identity"]["sourceEvidence"]
            source["originalBuildRecords"] = [ref]
            row = fixture.manifest["components"][0]
            row["files"].append(extra)
            row["originalBuildRecords"] = [copy.deepcopy(ref)]
            fixture.seal()
            notices.inspect(fixture.materials, fixture.inventory_path)
            row["originalBuildRecords"][0]["sha256"] = "0" * 64
            fixture.seal()
            with self.assertRaisesRegex(ValueError, "original-record binding"):
                notices.inspect(fixture.materials, fixture.inventory_path)

    def test_source_distribution_context_must_match_pinned_archive_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            raw = b"Source-tool license; not an additional library-license conclusion.\n"
            archive = fixture.materials / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                member = tarfile.TarInfo("fixture/COPYING")
                member.size = len(raw)
                tar.addfile(member, io.BytesIO(raw))
            context = fixture.file(raw, "COPYING", notices.SOURCE_CONTEXT)
            context["acquisition"] = {
                "archivePath": "source.tar.gz", "archiveSha256": digest(archive),
                "member": "fixture/COPYING"}
            source = fixture.inventory["targets"][0]["dependencies"][0]["archiveIdentities"][0][
                "identity"]["sourceEvidence"]
            source["sourceArchive"] = {"sha256": digest(archive)}
            fixture.manifest["components"][0]["files"].append(context)
            fixture.seal()
            notices.inspect(fixture.materials, fixture.inventory_path)
            context["acquisition"]["member"] = "fixture/absent"
            fixture.seal()
            with self.assertRaisesRegex(ValueError, "differs from its source archive"):
                notices.inspect(fixture.materials, fixture.inventory_path)

    def test_rejects_rehashed_but_incorrect_rendered_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            output = fixture.root / "delivery"
            notices.deliver(fixture.materials, fixture.inventory_path, output)
            (output / "NOTICES.txt").write_bytes(b"Wrong notice text\n")
            path = output / notices.OUTPUT
            record = json.loads(path.read_text())
            record["files"]["NOTICES.txt"] = digest(output / "NOTICES.txt")
            write_json(path, record)
            with self.assertRaisesRegex(ValueError, "Rendered notices"):
                notices.inspect_delivery(output, fixture.inventory_path)


if __name__ == "__main__":
    unittest.main()
