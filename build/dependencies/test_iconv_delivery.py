import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import build_iconv as iconv
import iconv_relink_delivery as delivery
from provenance import archive_hashes, digest, write_json


class IconvDeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.candidate, self.output = self.root / "original", self.root / "delivery"
        files = {
            "source/COPYING.LIB": b"fixture library terms",
            "source/lib/iconv.c": b"fixture original library source",
            "recipe/LICENSE": b"fixture recipe license",
            "install/lib/libiconv.a": b"fixture known-source reference archive",
            "install/include/iconv.h": b"fixture generated header",
            "install/share/licenses/libiconv/COPYING.LIB": b"fixture library terms",
            "interface/iconv.h": b"fixture interface",
            "baseline": b"historical executable not for delivery",
        }
        for name, data in files.items():
            path = self.candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        comparison = {"version": "1.16", "aliases": [["UTF-8"]], "checks": iconv.CHECKS}
        for name in ("baseline.json", "candidate.json"):
            write_json(self.candidate / name, comparison)
        archive = self.candidate / "upstream-source.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name in ("COPYING.LIB", "lib/iconv.c"):
                data = (self.candidate / "source" / name).read_bytes()
                member = tarfile.TarInfo("libiconv-1.16/" + name)
                member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        pin = {
            "library": "libiconv", "version": "1.16", "sha256": digest(archive),
            "licenseFile": "COPYING.LIB",
            "licenseSha256": digest(self.candidate / "source/COPYING.LIB"),
        }
        record = {
            "schema_version": 1, "library": "libiconv", "version": "1.16",
            "evidence_type": "isolated-source-build-candidate",
            "status": "not-approved-for-production", "target": "macos-arm64",
            "sourceArchive": pin, "licenseFile": "COPYING.LIB",
            "licenseFileSha256": pin["licenseSha256"],
            "sourceFiles": iconv.tree_files(self.candidate / "source"),
            "recipeFiles": iconv.tree_files(self.candidate / "recipe"),
            "installFiles": iconv.tree_files(self.candidate / "install"),
            "archives": archive_hashes(self.candidate / "install", ["lib/libiconv.a"]),
            "buildFiles": archive_hashes(self.candidate, [
                "baseline.json", "candidate.json", "interface/iconv.h"]),
        }
        write_json(self.candidate / delivery.RECORD, record)
        mocked_pin = patch.object(iconv, "pin", return_value=pin)
        mocked_pin.start()
        self.addCleanup(mocked_pin.stop)

    def export(self):
        with patch.object(iconv, "inspect") as original:
            result = delivery.export(self.candidate, self.output)
        original.assert_called_once_with(self.candidate)
        return result

    def test_delivery_retains_known_source_reference_but_excludes_historical_probe(self):
        self.export()
        self.assertFalse((self.output / "baseline").exists())
        self.assertTrue((self.candidate / "baseline").is_file())
        self.assertEqual(digest(self.output / delivery.RECORD), digest(self.candidate / delivery.RECORD))
        self.assertEqual(iconv.user_baseline(self.output)["sha256"],
                         digest(self.output / "install/lib/libiconv.a"))
        with self.assertRaises((ValueError, KeyError, OSError)):
            iconv.inspect(self.output)

    def test_changed_source_or_reference_archive_is_rejected(self):
        self.export()
        for name in ("source/lib/iconv.c", "install/lib/libiconv.a"):
            path = self.output / name
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, "changed"):
                delivery.inspect(self.output)
            path.write_bytes(original)

    def test_rehashed_extra_historical_binary_is_not_allowed(self):
        self.export()
        (self.output / "historical.exe").write_bytes(b"not for delivery")
        path = self.output / iconv.DELIVERY_MANIFEST
        manifest = json.loads(path.read_text())
        manifest["files"] = archive_hashes(self.output, [
            p.relative_to(self.output).as_posix() for p in self.output.rglob("*")
            if p.is_file() and p != path])
        write_json(path, manifest)
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            delivery.inspect(self.output)

    def test_modified_candidate_cannot_become_pristine_delivery(self):
        path = self.candidate / delivery.RECORD
        record = json.loads(path.read_text())
        record["schema_version"] = 2
        write_json(path, record)
        with patch.object(iconv, "inspect") as inspect:
            with self.assertRaisesRegex(ValueError, "original unmodified"):
                delivery.export(self.candidate, self.output)
        inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
