import ast
import hashlib
import json
from pathlib import Path
import re
import unittest

import embedded_v1
import sdk_reviewed


ROOT = Path(__file__).resolve().parents[2]
SDK_SOURCE = "4D Plugin API/4DPluginAPI.c"
FILLER_SETTERS = (
    "PA_SetStringVariable",
    "PA_SetBlobVariable",
    "PA_SetBlobHandleVariable",
    "PA_SetPictureVariable",
    "PA_SetRealVariable",
    "PA_SetLongintVariable",
    "PA_SetTimeVariable",
    "PA_SetDateVariable",
    "PA_SetBooleanVariable",
    "PA_SetObjectVariable",
    "PA_SetCollectionVariable",
)
ZERO_INITIALIZERS = {
    "PA_CreateObject": 2,
    "PA_DuplicateObject": 1,
    "PA_RemoveObjectProperty": 2,
    "PA_HasObjectProperty": 2,
    "PA_GetObjectPropertyType": 2,
    "PA_JsonParse": 2,
    "PA_JsonStringify": 2,
}


def canonical_bytes(path):
    return (ROOT / path).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class SDKPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = json.loads((ROOT / "build/sbom/sdk-pin.json").read_text(encoding="utf-8"))
        cls.files = {row["path"]: row for row in cls.pin["files"]}

    def test_reviewed_evidence_is_literal_and_pin_matches(self):
        tree = ast.parse((ROOT / "build/sbom/sdk_reviewed.py").read_text(encoding="utf-8"))
        literals = {}
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                self.assertIsInstance(node.value.value, str)
                continue
            self.assertIsInstance(node, ast.Assign)
            self.assertEqual(len(node.targets), 1)
            self.assertIsInstance(node.targets[0], ast.Name)
            literals[node.targets[0].id] = ast.literal_eval(node.value)
        self.assertEqual(literals["SDK_PIN"], self.pin)
        self.assertEqual(sdk_reviewed.SDK_PIN, self.pin)
        self.assertEqual(self.pin["commit"], "ad7944bc7a13d93db8097c4c8ff55ba2f6e36f86")
        self.assertEqual(self.pin["tree"], "db4adb91d6060dd891cd4fc02b42899ab2890bf7")
        self.assertEqual(self.pin["committer_date"], "2026-11-06T09:46:19Z")
        self.assertEqual(self.pin["selection"]["cutoff"], "2026-11-08T14:59:59Z")
        self.assertEqual(self.pin["selection"]["latest_commit_before_cutoff"], self.pin["commit"])

    def test_all_top_level_canonical_hashes_match_pin_and_reviewed(self):
        paths = {p.relative_to(ROOT).as_posix()
                 for p in (ROOT / "4D Plugin API").iterdir() if p.is_file()}
        self.assertEqual(len(paths), 9)
        self.assertEqual(paths, set(self.files))
        self.assertEqual(paths, set(sdk_reviewed.HASHES))
        self.assertEqual(paths, set(sdk_reviewed.LF_HASHES))
        self.assertEqual(paths, set(sdk_reviewed.CRLF_HASHES))
        for path in sorted(paths):
            with self.subTest(path=path):
                actual = sha256(canonical_bytes(path))
                self.assertEqual(actual, self.files[path]["after_sha256"])
                self.assertEqual(actual, sdk_reviewed.HASHES[path])
                self.assertEqual(actual, sdk_reviewed.LF_HASHES[path])

    def test_seven_command_parameter_arrays_remain_zero_initialized(self):
        source = canonical_bytes(SDK_SOURCE)
        all_initializers = re.findall(
            rb"\bPA_Variable\s+params\[[12]\] = \{0\}", source
        )
        self.assertEqual(len(all_initializers), 7)
        for function, size in ZERO_INITIALIZERS.items():
            with self.subTest(function=function):
                body = re.search(
                    rb"(?m)^[^\n;]*\b" + function.encode()
                    + rb"\([^;\n]*\)\n\{(?P<body>.*?)^\}",
                    source, re.DOTALL | re.MULTILINE,
                )
                self.assertIsNotNone(body)
                declaration = (
                    rb"\bPA_Variable\s+params\[" + str(size).encode()
                    + rb"\] = \{0\}(?:, result)?;"
                )
                self.assertRegex(body["body"], declaration)

    def test_only_eleven_documented_filler_assignments_differ_from_upstream(self):
        patches = self.pin["compatibility_patches"]
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["path"], SDK_SOURCE)
        source = canonical_bytes(SDK_SOURCE)
        assignment = b"\tvariable->fFiller = 0;\n"
        self.assertEqual(source.count(assignment), 11)
        for function in FILLER_SETTERS:
            with self.subTest(function=function):
                self.assertIn(function, patches[0]["description"])
                prefix = (
                    rb"(?m)(^void " + function.encode()
                    + rb"\([^\n]*\)\n\{\n\tvariable->fType = [^\n]+;\n)"
                )
                source, count = re.subn(
                    prefix + re.escape(assignment), rb"\1", source
                )
                self.assertEqual(count, 1)
        self.assertNotIn(assignment, source)
        upstream = self.files[SDK_SOURCE]
        self.assertNotEqual(upstream["after_sha256"], upstream["upstream_sha256"])
        self.assertEqual(sha256(source), upstream["upstream_sha256"])
        blob = b"blob " + str(len(source)).encode() + b"\0" + source
        self.assertEqual(hashlib.sha1(blob).hexdigest(), upstream["upstream_blob_sha"])

    def test_all_other_source_and_license_bytes_match_upstream(self):
        for path, row in self.files.items():
            if path == SDK_SOURCE:
                continue
            with self.subTest(path=path):
                source = canonical_bytes(path)
                self.assertEqual(sha256(source), row["upstream_sha256"])
                self.assertEqual(row["after_sha256"], row["upstream_sha256"])
                blob = b"blob " + str(len(source)).encode() + b"\0" + source
                self.assertEqual(hashlib.sha1(blob).hexdigest(), row["upstream_blob_sha"])
                expected_upstream = "LICENSE.md" if path.endswith("/LICENSE.md") else path
                self.assertEqual(row["upstream_path"], expected_upstream)

    def test_license_text_and_hash_match_exact_reviewed_bytes(self):
        license_row = self.pin["license"]
        self.assertEqual(license_row["spdx_id"], "MIT")
        self.assertEqual(license_row["path"], "4D Plugin API/LICENSE.md")
        self.assertEqual(license_row["upstream_path"], "LICENSE.md")
        license_bytes = sdk_reviewed.SDK_LICENSE_TEXT.encode("utf-8")
        self.assertEqual(license_bytes, canonical_bytes(license_row["path"]))
        self.assertEqual(sha256(license_bytes), license_row["sha256"])
        self.assertEqual(license_row["sha256"],
                         self.files[license_row["path"]]["upstream_sha256"])

    def test_seven_old_api_hashes_match_frozen_legacy_evidence(self):
        paths = {path for path in self.files if path.endswith((".c", ".h", ".def"))}
        self.assertEqual(len(paths), 7)
        for path in sorted(paths):
            with self.subTest(path=path):
                self.assertEqual(self.files[path]["before_sha256"], embedded_v1.HASHES[path])
        self.assertIsNone(self.files["4D Plugin API/LICENSE.md"]["before_sha256"])


if __name__ == "__main__":
    unittest.main()
