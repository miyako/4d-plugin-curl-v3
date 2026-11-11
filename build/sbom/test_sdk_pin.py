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

    def test_sdk_source_is_pristine_without_local_setter_patches(self):
        self.assertEqual(self.pin["compatibility_patches"], [])
        source = canonical_bytes(SDK_SOURCE)
        self.assertNotIn(b"variable->fFiller = 0;", source)
        upstream = self.files[SDK_SOURCE]
        self.assertEqual(upstream["after_sha256"], upstream["upstream_sha256"])
        self.assertEqual(sha256(source), upstream["upstream_sha256"])
        blob = b"blob " + str(len(source)).encode() + b"\0" + source
        self.assertEqual(hashlib.sha1(blob).hexdigest(), upstream["upstream_blob_sha"])

    def test_all_nine_source_and_license_bytes_match_upstream(self):
        for path, row in self.files.items():
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

    def test_firstparty_command_arguments_are_initialized_before_use(self):
        core = canonical_bytes("4DPlugin-cURL.cpp")
        self.assertRegex(
            core,
            rb"PA_Variable params\[2\];\s*"
            rb"params\[0\] = PA_CreateVariable\(eVK_Longint\);\s*"
            rb"PA_SetLongintVariable\(&params\[0\], currentProcessNumber\);\s*"
            rb"params\[1\] = PA_CreateVariable\(eVK_Real\);\s*"
            rb"PA_SetRealVariable\(&params\[1\], 6\);[^\n]*\n\s*"
            rb"PA_ExecuteCommandByID\(323 /\*DELAY_PROCESS\*/ , params, 2\);",
        )
        self.assertRegex(
            core,
            rb"PA_Variable params;\s*"
            rb"bool isProcessDying = PA_GetBooleanVariable\(PA_ExecuteCommandByID"
            rb"\(672/\* Process aborted \*/, &params, 0\)\);",
        )
        support = canonical_bytes("support/4DPlugin-JSON.cpp")
        self.assertRegex(
            support,
            rb"PA_Variable\s+_params\[1\];\n"
            rb"\s*_params\[0\] = PA_CreateVariable\(eVK_Object\);\n"
            rb"\s*PA_SetObjectVariable\(&_params\[0\], PA_DuplicateObject\(obj\)\);",
        )

    def test_every_firstparty_setter_destination_has_reviewed_initialization(self):
        paths = [ROOT / "4DPlugin-cURL.cpp"]
        paths += sorted((ROOT / "support").rglob("*"))
        paths += sorted((ROOT / "4D Plugin API/Classes").rglob("*"))
        counts = {}
        for path in paths:
            if not path.is_file() or path.suffix not in (".cpp", ".h", ".c"):
                continue
            relative = path.relative_to(ROOT).as_posix()
            source = canonical_bytes(relative)
            for call in re.finditer(rb"\bPA_Set\w*Variable\s*\(\s*&([^,]+),", source):
                counts[relative] = counts.get(relative, 0) + 1
                destination = call[1].strip()
                with self.subTest(path=relative, destination=destination, offset=call.start()):
                    prefix = source[:call.start()].rsplit(b"\n}", 1)[-1]
                    if destination == b"v":
                        self.assertRegex(
                            prefix, rb"\bPA_Variable v = PA_CreateVariable\(eVK_\w+\);"
                        )
                    elif destination in (b"params[0]", b"params[1]", b"_params[0]"):
                        self.assertIn(
                            destination + b" = PA_CreateVariable(", prefix
                        )
                    else:
                        self.assertEqual(relative, "4DPlugin-cURL.cpp")
                        self.assertIn(destination, (b"cbparams[0]", b"cbparams[2]"))
                        self.assertRegex(prefix, rb"PA_Variable\s+cbparams\[4\];")
        self.assertEqual(counts, {"4DPlugin-cURL.cpp": 11, "support/4DPlugin-JSON.cpp": 13})

    def test_existing_callback_variants_and_host_copies_are_not_reset(self):
        core = canonical_bytes("4DPlugin-cURL.cpp")
        self.assertRegex(
            core,
            rb"if \(method_id\)\s*\{\s*"
            rb"cbparams\[0\] = PA_CreateVariable\(eVK_Object\);\s*"
            rb"cbparams\[1\] = PA_CreateVariable\(eVK_Unistring\);",
        )
        self.assertRegex(
            core,
            rb"if \(execute_callback_method\)\s*\{\s*"
            rb"cbparams\[0\] = PA_CreateVariable\(eVK_Unistring\);\s*"
            rb"cbparams\[1\] = PA_CreateVariable\(eVK_Boolean\);\s*"
            rb"cbparams\[2\] = PA_CreateVariable\(eVK_Object\);\s*"
            rb"cbparams\[3\] = PA_CreateVariable\(eVK_Unistring\);",
        )
        self.assertIn(b"PA_Variable statusCode = cbparams[1];", core)
        self.assertNotRegex(core, rb"cbparams\[[0-3]\]\s*=\s*\{\s*\}")
        self.assertNotRegex(core, rb"memset\s*\(\s*(?:&\s*)?cbparams\b")
        arrays = canonical_bytes("4D Plugin API/Classes/ARRAY_TEXT.cpp")
        self.assertEqual(
            arrays.count(b"PA_Variable arr = *((PA_Variable*) pParams[index - 1]);"), 2
        )


if __name__ == "__main__":
    unittest.main()
