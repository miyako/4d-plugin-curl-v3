from pathlib import Path
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import build_http


class HttpSourceTests(unittest.TestCase):
    def test_upstream_suite_cannot_skip_or_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tests.xml"
            suite = ET.Element("testsuite", tests="1", failures="0")
            test = ET.SubElement(suite, "testcase", name="main", status="run")
            ET.ElementTree(suite).write(path)
            build_http.verify_tests(path)
            for name in ("skipped", "failure", "error"):
                node = ET.SubElement(test, name)
                ET.ElementTree(suite).write(path)
                with self.assertRaisesRegex(ValueError, "did not pass completely"):
                    build_http.verify_tests(path)
                test.remove(node)
            test.set("status", "notrun")
            ET.ElementTree(suite).write(path)
            with self.assertRaisesRegex(ValueError, "did not pass completely"):
                build_http.verify_tests(path)

    def test_source_pin_and_clean_checkout_are_required(self):
        for responses in (["wrong-commit"], ["expected-commit", " M source.c"]):
            with mock.patch.object(build_http, "git", side_effect=responses):
                with self.assertRaisesRegex(ValueError, "clean at its immutable pin"):
                    build_http.snapshot(Path("."), "expected-commit")

    def test_nghttp3_does_not_expand_selected_windows_scope(self):
        with mock.patch.object(build_http.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(ValueError, "not a selected Windows"):
                build_http.build(Path("."), Path("unused"), "nghttp3", "windows-x86_64")


if __name__ == "__main__":
    unittest.main()
