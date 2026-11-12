import copy
import json
from pathlib import Path
import tempfile
import unittest

import observe_curl


class CurlObservationTests(unittest.TestCase):
    def setUp(self):
        self.selected = observe_curl.baseline("macos-arm64")
        versions = {a["name"]: a["version"] for a in self.selected if "version" in a}
        self.info = {
            "version": versions["curl"], "libzVersion": versions["zlib"],
            "brotliVersion": "brotli/" + versions["Brotli"],
            "libsshVersion": "libssh2/" + versions["libssh2"],
            "nghttp2Version": versions["nghttp2"],
            "sslVersion": "OpenSSL/" + versions["OpenSSL"],
            "featuresMask": 1, "features": ["SSL"], "protocols": ["https"],
        }

    def test_exact_baseline_versions_are_required(self):
        observe_curl.validate_observations(self.info, self.selected, "macos-arm64")
        for name in ("version", "libzVersion", "brotliVersion", "libsshVersion",
                     "nghttp2Version", "sslVersion"):
            changed = dict(self.info, **{name: "99.0.0"})
            with self.subTest(field=name), self.assertRaisesRegex(ValueError, "frozen versions"):
                observe_curl.validate_observations(changed, self.selected, "macos-arm64")
        changed = dict(self.info, features=["SSL", "SSL"])
        with self.assertRaisesRegex(ValueError, "frozen versions"):
            observe_curl.validate_observations(changed, self.selected, "macos-arm64")

    def test_offline_observation_rejects_missing_or_changed_baseline_archive(self):
        expected = [{"path": a["path"], "sha256": a["sha256"]}
                    for a in observe_curl.baseline_inputs(self.selected, "macos-arm64")]
        for inputs in (expected[:1], expected + [expected[0]],
                       [dict(a, sha256="0" * 64) for a in expected]):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record = {
                    "target": "macos-arm64",
                    "evidenceType": "exact-baseline-curl-runtime-with-rebuilt-matching-providers",
                    "baselineArchiveInputs": inputs,
                }
                (root / "curl-baseline-observation.json").write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, "exact selected baseline"):
                    observe_curl.inspect(root)

    def test_unknown_proxy_versions_are_not_required_or_invented(self):
        selected = copy.deepcopy(self.selected)
        self.assertTrue(any("version" not in a for a in selected))
        observe_curl.validate_observations(self.info, selected, "macos-arm64")

    def test_ssh_algorithm_baseline_requires_every_method_without_duplicates(self):
        info = dict(self.info, sshAlgorithms={name: ["test-algorithm"]
                                             for name in observe_curl.SSH_METHODS})
        observe_curl.validate_observations(info, self.selected, "macos-arm64")
        for algorithms in (None, {},
                           dict(info["sshAlgorithms"], kex=[]),
                           dict(info["sshAlgorithms"], kex=["duplicate", "duplicate"])):
            with self.subTest(algorithms=algorithms), self.assertRaisesRegex(ValueError, "SSH algorithm"):
                observe_curl.validate_observations(
                    dict(info, sshAlgorithms=algorithms), self.selected, "macos-arm64")

    def test_windows_multissl_banner_is_not_a_single_backend_or_version_mismatch(self):
        selected = observe_curl.baseline("windows-x86_64")
        info = dict(self.info, libzVersion="1.3.1", sslVersion="OpenSSL/3.5.8 (Schannel)",
                    tlsBackends=["openssl", "schannel"])
        observe_curl.validate_observations(info, selected, "windows-x86_64")
        for changed in (dict(info, sslVersion="OpenSSL/3.5.8"),
                        dict(info, sslVersion="OpenSSL/99.0.0 (Schannel)"),
                        dict(info, tlsBackends=["openssl"])):
            with self.subTest(info=changed), self.assertRaises(ValueError):
                observe_curl.validate_observations(changed, selected, "windows-x86_64")


if __name__ == "__main__":
    unittest.main()
