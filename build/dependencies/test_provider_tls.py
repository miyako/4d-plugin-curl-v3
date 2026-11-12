"""Persisted TLS receipt bindings; native authentication runs separately in CI."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import probe_provider_tls as tls
import provenance


class PersistedTLSProofTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.install, self.output = root / "install", root / "proof"
        self.target = "macos-arm64"
        for name in [provenance.RECORD, *provenance.expected_archives(self.target),
                     "include/openssl/ssl.h"]:
            path = self.install / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        for name in tls.RECIPES:
            path = self.output / "recipes" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        self.lines = [
            line for version in ("TLSv1.2", "TLSv1.3") for line in (
                version + " TEST verified-hostname authenticated-data",
                version + " rejected-hostname verify=62",
                version + " rejected-untrusted verify=18")]
        (self.output / "tls-probe").write_bytes(b"fixture, not an executed native binary")
        (self.output / "compile.log").write_text("fixture")
        (self.output / "stdout.txt").write_text("\n".join(self.lines) + "\n")
        (self.output / "stderr.txt").write_text("")
        self.receipt = {
            "schemaVersion": 1, "target": self.target,
            "providerRecordSha256": provenance.digest(self.install / provenance.RECORD),
            "providerInputs": tls.provider_inputs(self.install, self.target),
            "recipeInputs": provenance.archive_hashes(self.output / "recipes", tls.RECIPES),
            "files": provenance.archive_hashes(
                self.output, ["compile.log", "stdout.txt", "stderr.txt"]),
            "binarySha256": provenance.digest(self.output / "tls-probe"),
            "results": self.lines,
        }

    def inspect(self, receipt):
        (self.output / "tls-proof.json").write_text(json.dumps(receipt))
        with mock.patch.object(provenance, "read_record", return_value={"target": self.target}):
            return tls.inspect_proof(self.install, self.output)

    def test_complete_receipt_and_six_cases(self):
        self.assertEqual(self.inspect(self.receipt)["results"], self.lines)

    def test_omitting_original_bound_inputs_fails(self):
        for key in ("providerInputs", "recipeInputs", "files"):
            with self.subTest(key=key):
                receipt = copy.deepcopy(self.receipt)
                receipt[key].pop()
                with self.assertRaisesRegex(ValueError, "Persisted TLS proof"):
                    self.inspect(receipt)

    def test_changed_binary_or_header_fails(self):
        for path in (self.output / "tls-probe", self.install / "include/openssl/ssl.h"):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "Persisted TLS proof"):
                    self.inspect(self.receipt)
                path.write_bytes(original)

    def test_rejection_case_cannot_be_substituted(self):
        lines = list(self.lines)
        lines[-1] = "TLSv1.3 rejected-hostname verify=62"
        with self.assertRaisesRegex(ValueError, "TLS authentication"):
            tls.validate_results(lines)


if __name__ == "__main__":
    unittest.main()
