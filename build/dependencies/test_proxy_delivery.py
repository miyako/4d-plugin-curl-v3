import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import proxy_source_delivery as delivery
from provenance import archive_hashes, digest, write_json


class ProxySourceDeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.candidate = self.root / "original"
        self.candidate.mkdir()
        self.output = self.root / "delivery"
        sources = {"COPYING": b"fixture library terms", "libproxy/proxy.h": b"fixture header"}
        support = {"LICENSE": b"fixture recipe license",
                   "build/sbom/provenance.py": b"fixture helper",
                   "build/sbom/native_archive_objects.py": b"fixture reader"}
        self.lock = {
            "commit": "a" * 40, "repository": "https://github.com/libproxy/libproxy",
            "status": "isolated-candidate-not-approved-for-production",
            "components": [{"name": "libproxy", "version": "0.4.17"}, {"name": "libmodman"}],
            "patches": [], "acceptedCandidateChanges": [], "licenseFile": "COPYING",
            "modules": {"macos": ["fixture"], "windows": ["fixture"]},
        }

        def archive(name, entries):
            with tarfile.open(self.candidate / name, "w") as tar:
                for path, data in entries.items():
                    member = tarfile.TarInfo(path)
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))

        import hashlib
        hashes = lambda entries: [{"path": p, "sha256": hashlib.sha256(b).hexdigest()}
                                  for p, b in sorted(entries.items())]
        archive("upstream-base.tar", sources)
        archive("upstream-source.tar", sources)
        archive("candidate-recipe.tar", support)
        for path, data in (
                ("install/include/proxy.h", sources["libproxy/proxy.h"]),
                ("install/share/licenses/libproxy/COPYING", sources["COPYING"]),
                ("build/proxy_baseline_behavior", b"historical executable not for delivery")):
            target = self.candidate / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        record = {
            **copy.deepcopy(self.lock), "source_commit": self.lock["commit"],
            "source_repository": self.lock["repository"],
            "schema_version": 2, "evidence_type": "isolated-source-build-candidate",
            "target": "macos-arm64", "modules": ["fixture"],
            "baseSourceFiles": hashes(sources), "sourceFiles": hashes(sources),
            "recipeFiles": [], "recipeSupportFiles": hashes(support),
            "recipeLicenseSha256": hashes({"LICENSE": support["LICENSE"]})[0]["sha256"],
            "licenseFileSha256": hashes({"COPYING": sources["COPYING"]})[0]["sha256"],
        }
        write_json(self.candidate / delivery.RECORD, record)
        self.lock_patch = patch.object(delivery, "source_lock", return_value=self.lock)
        self.lock_patch.start()
        self.addCleanup(self.lock_patch.stop)

    def export(self):
        with patch.object(delivery.inspect_proxy, "inspect", return_value={
                "compilerArchiveBinding": True, "validationStatus": "passed",
                "target": "macos-arm64"}):
            return delivery.export(self.candidate, self.output)

    def test_delivery_excludes_historical_executables_and_preserves_original_record(self):
        result = self.export()
        self.assertEqual(result["target"], "macos-arm64")
        self.assertEqual(digest(self.output / delivery.RECORD), digest(self.candidate / delivery.RECORD))
        self.assertFalse((self.output / "build").exists())
        self.assertTrue((self.candidate / "build/proxy_baseline_behavior").is_file())
        self.assertTrue((self.output / "tools/build/dependencies/relink_candidate.py").is_file())
        with patch.object(delivery.inspect_proxy, "inspect", side_effect=AssertionError("full inspector")):
            delivery.inspect_candidate(self.output)

    def test_original_or_failed_candidate_is_not_silently_exported(self):
        with patch.object(delivery.inspect_proxy, "inspect", return_value={
                "compilerArchiveBinding": False, "validationStatus": "passed"}):
            with self.assertRaisesRegex(ValueError, "successful original compiler-bound"):
                delivery.export(self.candidate, self.output)
        with patch.object(delivery.inspect_proxy, "inspect") as original:
            delivery.inspect_candidate(self.candidate)
        original.assert_called_once_with(self.candidate)

    def test_mutated_source_or_rehashed_extra_binary_is_rejected(self):
        self.export()
        source = self.output / "upstream-source.tar"
        source.write_bytes(source.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            delivery.inspect(self.output)
        source.write_bytes((self.candidate / source.name).read_bytes())
        extra = self.output / "unknown.lib"
        extra.write_bytes(b"not an approved input")
        manifest_path = self.output / delivery.MANIFEST
        manifest = json.loads(manifest_path.read_text())
        manifest["files"] = archive_hashes(self.output, [
            p.relative_to(self.output).as_posix() for p in self.output.rglob("*")
            if p.is_file() and p != manifest_path])
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            delivery.inspect(self.output)

    def test_producer_reference_and_copied_tools_are_bound(self):
        self.export()
        record = self.output / delivery.RECORD
        record.write_text(record.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            delivery.inspect(self.output)
        record.write_bytes((self.candidate / delivery.RECORD).read_bytes())
        (self.output / "tools/LICENSE").write_text("different")
        with self.assertRaisesRegex(ValueError, "changed"):
            delivery.inspect(self.output)


if __name__ == "__main__":
    unittest.main()
