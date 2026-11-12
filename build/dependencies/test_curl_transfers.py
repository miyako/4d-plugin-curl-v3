import gzip
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest import mock
import zlib

import probe_curl_transfers as transfers
import provenance


class CurlTransferTests(unittest.TestCase):
    def test_persisted_receipt_rejects_omitted_cases_and_rehashed_bad_response(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name in transfers.RECIPES:
                path = output / "recipes" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(transfers.ROOT / name, path)
            for name in ("localhost.crt", "untrusted.crt"):
                (output / name).write_text("public test fixture")
            cases = ["http-" + name for name in ("identity", "gzip", "deflate", "br")]
            cases.append("explicit-http-proxy")
            cases += ["openssl-tls" + version + "-" + suffix for version in ("1.2", "1.3")
                      for suffix in ("trusted", "hostname", "untrusted")]
            results = {}
            for variant in ("candidate", "baseline"):
                root = output / variant
                root.mkdir()
                for name in ("compile.log", "transfer.map", "curl-transfer"):
                    (root / name).write_text("nonexecuted receipt fixture")
                results[variant] = []
                for name in cases:
                    rejected = name.endswith(("-hostname", "-untrusted"))
                    body = b"" if rejected else transfers.PAYLOAD
                    status = {"curlCode": 60 if rejected else 0, "httpStatus": 0 if rejected else 200}
                    (root / (name + ".stdout")).write_bytes(body)
                    (root / (name + ".stderr")).write_text(json.dumps(status))
                    results[variant].append({
                        "case": name, **status, "exitCode": status["curlCode"],
                        "responseBytes": len(body), "responseSha256": hashlib.sha256(body).hexdigest()})
            receipt = {"schemaVersion": 1, "target": "macos-arm64", "results": results,
                       "compile": {"candidate": {}, "baseline": {}},
                       "recipeInputs": provenance.archive_hashes(output / "recipes", transfers.RECIPES)}

            def save():
                receipt["files"] = provenance.archive_hashes(output, [
                    p.relative_to(output).as_posix() for p in output.rglob("*")
                    if p.is_file() and p.name != "curl-transfer-proof.json"])
                (output / "curl-transfer-proof.json").write_text(json.dumps(receipt))

            save()
            transfers.inspect_proof(output)
            removed = results["candidate"].pop()
            save()
            with self.assertRaisesRegex(ValueError, "coverage"):
                transfers.inspect_proof(output)
            results["candidate"].append(removed)
            (output / "candidate/http-br.stdout").write_bytes(b"not decoded")
            save()
            with self.assertRaisesRegex(ValueError, "response/authentication"):
                transfers.inspect_proof(output)

    def test_loopback_fixture_handles_compression_and_absolute_proxy_form(self):
        body = transfers.PAYLOAD
        encoded = {"identity": body, "gzip": gzip.compress(body), "deflate": zlib.compress(body)}
        with transfers.serve(encoded) as port:
            for name in encoded:
                with self.subTest(encoding=name):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    self.addCleanup(connection.close)
                    connection.request("GET", "http://native-source-test.invalid/" + name)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    actual = response.read()
                    if name == "gzip":
                        actual = gzip.decompress(actual)
                    elif name == "deflate":
                        actual = zlib.decompress(actual)
                    self.assertEqual(actual, body)

    def test_body_status_and_process_failure_cannot_masquerade_as_transfer_success(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for code, body, status, rejected in (
                    (0, transfers.PAYLOAD, 200, False), (60, b"", 0, True),
                    (0, b"wrong", 200, False), (1, transfers.PAYLOAD, 200, False),
                    (0, transfers.PAYLOAD, 404, False), (0, b"", 0, True),
                    (60, b"unauthenticated", 0, True)):
                with self.subTest(code=code, status=status, rejected=rejected):
                    result = subprocess.CompletedProcess(
                        [], code, body, json.dumps({"curlCode": code, "httpStatus": status}).encode())
                    with mock.patch.object(transfers.subprocess, "run", return_value=result):
                        arguments = (output / "probe", output, "windows-x86_64", "fixture",
                                     "openssl", "http://127.0.0.1/")
                        if ((code == 0 and body == transfers.PAYLOAD and status == 200 and not rejected)
                                or (code == 60 and body == b"" and status == 0 and rejected)):
                            transfers.check_transfer(*arguments, rejected=rejected)
                        else:
                            with self.assertRaisesRegex(ValueError, "expectation failed"):
                                transfers.check_transfer(*arguments, rejected=rejected)


if __name__ == "__main__":
    unittest.main()
