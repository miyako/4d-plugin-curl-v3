import copy
from pathlib import Path
import tempfile
import unittest

import build_ssh


class SSHTests(unittest.TestCase):
    def test_algorithm_order_and_source_banner_must_match(self):
        candidate = {"version": "1.11.1_DEV", "sshAlgorithms": {"kex": ["first", "second"]}}
        baseline = copy.deepcopy(candidate)
        build_ssh.compare(candidate, baseline)
        changed = copy.deepcopy(candidate)
        changed["sshAlgorithms"]["kex"].reverse()
        for invalid in (changed, dict(candidate, version="1.11.1"), {"version": "1.11.1_DEV"}):
            with self.subTest(candidate=invalid), self.assertRaises(ValueError):
                build_ssh.compare(invalid, baseline)
        with self.assertRaises(ValueError):
            build_ssh.compare({"version": "1.11.1_DEV"}, {})

    def test_standalone_test_cannot_be_missing_or_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "results.xml"
            path.write_text('<testsuite tests="1" failures="0">'
                            '<testcase name="test_simple" status="run"/></testsuite>')
            build_ssh.verify_tests(path)
            for content in (
                    '<testsuite failures="0"/>',
                    '<testsuite tests="1" failures="0"><testcase name="test_simple" status="run"><skipped/></testcase></testsuite>',
                    '<testsuite failures="1"><testcase name="test_simple" status="fail"/></testsuite>'):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    build_ssh.verify_tests(path)

    def test_same_basename_is_not_proof_of_actual_archive_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "probe.map").write_text(
                "# Arch: arm64\n# Object files:\n[  1] /other/libssh2.a(session.o)\n")
            with self.assertRaisesRegex(ValueError, "exact libssh2 archive"):
                build_ssh.selections(output, "macos-arm64",
                                     {"libssh2": {"path": "/expected/libssh2.a"}})
            (output / "probe.map").write_bytes(
                b"# Arch: arm64\n# Object files:\n[  1] /expected/libssh2.a(session.o)\n"
                b"# Symbols:\n# literal string: \xff\n")
            self.assertTrue(build_ssh.selections(
                output, "macos-arm64", {"libssh2": {"path": "/expected/libssh2.a"}})["libssh2"])


if __name__ == "__main__":
    unittest.main()
