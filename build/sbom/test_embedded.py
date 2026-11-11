import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import embedded


ROOT = Path(__file__).resolve().parents[2]


class EmbeddedTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix="embedded-test-", dir=Path(__file__).resolve().parent
        )
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        paths = {*embedded.HASHES, *embedded.WITNESSES,
                 "cURL.vcxproj", "cURL.xcodeproj/project.pbxproj"}
        for name in paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)

    def collect(self, target="windows-x86_64"):
        return embedded.collect(self.root, target)

    def edit(self, name, old, new):
        path = self.root / name
        data = path.read_bytes()
        self.assertIn(old.encode(), data)
        path.write_bytes(data.replace(old.encode(), new.encode(), 1))

    def test_real_project_coverage_and_serializable_round_trip(self):
        for target in embedded.TARGETS:
            with self.subTest(target=target):
                record = self.collect(target)
                self.assertEqual(len(record["components"]), 6)
                self.assertEqual(len(record["declarations"]["translationUnits"]), 8)
                self.assertEqual(len(record["declarations"]["headers"]), 13)
                self.assertEqual(
                    embedded.verify(json.loads(json.dumps(record)), self.root, target),
                    record,
                )
                self.assertEqual(embedded.verify_record(record), record)
                self.assertEqual(embedded.verify_record(record, self.root), record)
                for component in record["components"]:
                    for source in component["sourceFiles"]:
                        self.assertEqual(
                            source["sha256"],
                            hashlib.sha256((self.root / source["path"]).read_bytes()).hexdigest(),
                        )
                self.assertEqual(
                    record["configuration"][0]["sha256"],
                    hashlib.sha256((self.root / record["configuration"][0]["path"]).read_bytes()).hexdigest(),
                )

    def test_identities_versions_and_license_scope(self):
        components = {c["id"]: c for c in self.collect()["components"]}
        ftp = components["embedded-ftpparse"]
        self.assertEqual(ftp["version"], "20001223")
        self.assertEqual(ftp["license"], "LicenseRef-ftpparse-public-domain")
        self.assertIn("8d3ad77f80704b513d4edf3b01629205", ftp["licenseEvidence"]["text"])
        self.assertIn("f12d28cc60a3c0475d42ae6a79552d4a", ftp["licenseEvidence"]["text"])
        self.assertNotIn("MIT", ftp["licenseEvidence"]["text"])
        self.assertNotIn("CC0", ftp["licenseEvidence"]["text"])
        sdk = components["embedded-4d-sdk"]
        self.assertEqual(sdk["license"], "MIT")
        self.assertIn("2017-present, 4D, Inc.", sdk["licenseText"]["text"])
        self.assertNotIn("Keisuke", sdk["licenseText"]["text"])
        self.assertIn("LICENSE.md", sdk["licenseText"]["url"])
        for component in components.values():
            self.assertNotIn("purl", component)
            self.assertNotIn("sourceCommit", component)
            self.assertNotIn("dependencies", component)
            if component is not ftp:
                self.assertNotIn("version", component)
            evidence = component.get("licenseText", component.get("licenseEvidence"))
            if evidence:
                self.assertEqual(evidence["sha256"],
                                 embedded.sha256(evidence["text"].encode()))
        for name in ("embedded-4d-cpp-wrappers", "embedded-json-helper",
                     "embedded-utf-path-helper"):
            self.assertNotIn("license", components[name])
            self.assertNotIn("licenseEvidence", components[name])
        jsoncpp = components["interface-jsoncpp"]
        self.assertEqual(jsoncpp["kind"], "build-interface")
        self.assertEqual(jsoncpp["scope"], "sdk-interface")
        self.assertEqual(sdk["scope"], "compiled-source")
        self.assertTrue(all(f["role"] == "header-interface"
                            for f in jsoncpp["sourceFiles"]))
        self.assertIn("numeric patch 3", jsoncpp["limitations"][0])

    def test_sdk_interfaces_do_not_become_runtime_components(self):
        win, mac = [self.collect(t) for t in embedded.TARGETS]
        for record in (win, mac):
            sdk = next(c for c in record["components"] if c["id"] == "embedded-4d-sdk")
            sources = [f for f in sdk["sourceFiles"] if f["role"] == "translation-unit"]
            self.assertEqual([f["path"] for f in sources], ["4D Plugin API/4DPluginAPI.c"])
            self.assertFalse(any("ARRAY_TEXT" in f["path"] for c in record["components"]
                                 for f in c["sourceFiles"]))
        self.assertTrue(any(f["role"] == "linker-interface"
                            for f in win["components"][1]["sourceFiles"]))
        self.assertFalse(any(f["role"] == "linker-interface"
                             for f in mac["components"][1]["sourceFiles"]))

    def test_every_reviewed_source_hash_fails_closed(self):
        for name in embedded.HASHES:
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n/* unreviewed */\n")
                with self.assertRaisesRegex(ValueError, "Unreviewed embedded source hash"):
                    self.collect()
                path.write_bytes(original)

    def test_missing_source_and_escaped_symlink_rejected(self):
        path = self.root / "include/ftpparse.c"
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.collect()
        path.symlink_to(ROOT / "include/ftpparse.c")
        with self.assertRaisesRegex(ValueError, "escapes repository"):
            self.collect()

    def test_changed_checkout_configuration_and_witness_reject_verify(self):
        record = self.collect()
        for name in ("cURL.vcxproj", *embedded.WITNESSES):
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, "current build inputs"):
                    embedded.verify(record, self.root, record["target"])
                path.write_bytes(original)

    def test_saved_evidence_validation_does_not_read_current_checkout(self):
        record = self.collect()
        (self.root / "include/ftpparse.c").unlink()
        self.assertEqual(embedded.validate(record, record["target"]), record)
        self.assertEqual(embedded.verify_record(record), record)
        with self.assertRaises(FileNotFoundError):
            embedded.verify(record, self.root, record["target"])
        with self.assertRaises(FileNotFoundError):
            embedded.verify_record(record, self.root)

    def test_msbuild_missing_duplicate_conditional_and_extra_sources(self):
        project = self.root / "cURL.vcxproj"
        original = project.read_bytes()
        old = '<ClCompile Include="support\\ufopen.c" />'
        changes = ["", old + old,
                   old.replace(" />", ' Condition="false" />'),
                   '<ClCompile Include="support\\unknown.c" />',
                   old.replace(" />", "><ExcludedFromBuild>true</ExcludedFromBuild></ClCompile>")]
        for replacement in changes:
            with self.subTest(replacement=replacement):
                self.edit("cURL.vcxproj", old, replacement)
                with self.assertRaises(ValueError):
                    self.collect()
                project.write_bytes(original)

    def test_msbuild_export_file_must_match_actual_configuration(self):
        self.edit("cURL.vcxproj",
                  '<ModuleDefinitionFile>.\\4D Plugin API\\4DPluginAPI.def</ModuleDefinitionFile>',
                  '<ModuleDefinitionFile>other.def</ModuleDefinitionFile>')
        # The first matching setting is Debug; Release must be changed as well.
        path = self.root / "cURL.vcxproj"
        path.write_bytes(path.read_bytes().replace(
            b".\\4D Plugin API\\4DPluginAPI.def", b"other.def"))
        with self.assertRaisesRegex(ValueError, "SDK export interface"):
            self.collect()

    def test_xcode_phase_and_resolved_group_paths_are_checked(self):
        project = self.root / "cURL.xcodeproj/project.pbxproj"
        original = project.read_bytes()
        for old, replacement in (
            ("D155A526261332130015464C /* ufopen.c in Sources */,", ""),
            ('path = "4D Plugin API";', 'path = "other API";'),
            ("path = support/ufopen.c;", "path = ../ufopen.c;"),
            ("isa = PBXSourcesBuildPhase;", "isa = PBXResourcesBuildPhase;"),
            ("settings = {COMPILER_FLAGS", 'platformFilter = ios; settings = {COMPILER_FLAGS'),
            ("buildSettings = {", 'buildSettings = { EXCLUDED_SOURCE_FILE_NAMES = "*.c";'),
        ):
            with self.subTest(change=replacement):
                self.edit(project.relative_to(self.root), old, replacement)
                with self.assertRaises(ValueError):
                    self.collect("macos-universal")
                project.write_bytes(original)

    def test_missing_include_witness_is_not_a_valid_build_interface(self):
        self.edit("4DPlugin-cURL.h", '#include "json/json.h"', '// no JsonCpp include')
        with self.assertRaisesRegex(ValueError, "Missing reviewed plugin include"):
            self.collect()

    def test_negative_identity_source_license_and_metadata_validation(self):
        record = self.collect()
        mutations = [
            lambda r: r["components"].pop(),
            lambda r: r["components"].append(copy.deepcopy(r["components"][0])),
            lambda r: r["components"][0].update(version="20001224"),
            lambda r: r["components"][0].update(license="MIT"),
            lambda r: r["components"][0].update(license="CC0-1.0"),
            lambda r: r["components"][0].update(origin="https://example.invalid"),
            lambda r: r["components"][0]["sourceFiles"][0].update(sha256="0" * 64),
            lambda r: r["components"][0]["sourceFiles"][0].update(path="../ftpparse.c"),
            lambda r: r["components"][0]["sourceFiles"][0].update(role="header-interface"),
            lambda r: r["components"][0]["licenseEvidence"].update(text="MIT"),
            lambda r: r["components"][0]["licenseEvidence"].update(sha256="0" * 64),
            lambda r: r["components"][0]["licenseEvidence"].update(attribution="Keisuke Miyako"),
            lambda r: r["components"][1]["licenseText"].update(text="root MIT"),
            lambda r: r["components"][1].update(version="14", purl="pkg:generic/4d@14"),
            lambda r: r["components"][2].update(license="MIT"),
            lambda r: r["components"][3].update(license="MIT"),
            lambda r: r["components"][5].update(kind="compiled-source", version="1.9.4"),
            lambda r: r["components"][5].update(scope="compiled-source"),
            lambda r: r["declarations"]["translationUnits"].append("unknown.c"),
            lambda r: r["declarations"].update(includeDirectories=[]),
            lambda r: r.update(declarations=None),
            lambda r: r["configuration"][0].update(sha256="not a sha256"),
            lambda r: r["sourceWitnesses"][0].update(path="/absolute.c"),
            lambda r: r["sourceWitnesses"][0].update(sha256="f" * 63),
            lambda r: r.update(schemaVersion=True),
            lambda r: r.update(schemaVersion=2),
            lambda r: r.update(target="linux"),
            lambda r: r.update(evidenceType="binary-detection"),
            lambda r: r.update(limitations=[]),
            lambda r: r.update(runtimeDependencies=["4D"]),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = copy.deepcopy(record)
                mutate(changed)
                with self.assertRaises(ValueError):
                    embedded.validate(changed)

    def test_matching_hash_of_forged_license_text_is_still_rejected(self):
        record = self.collect()
        evidence = record["components"][0]["licenseEvidence"]
        evidence["text"] = "The MIT License"
        evidence["sha256"] = embedded.sha256(evidence["text"].encode())
        with self.assertRaisesRegex(ValueError, "identity/hash/license metadata"):
            embedded.validate(record)

    def test_target_mismatch_unknown_target_and_malformed_record(self):
        record = self.collect()
        with self.assertRaises(ValueError):
            embedded.validate(record, "macos-universal")
        for value in (None, [], {}, {"target": "windows-x86_64"}):
            with self.subTest(record=value), self.assertRaises(ValueError):
                embedded.validate(value)
        with self.assertRaises(ValueError):
            self.collect("linux")

    def test_path_validation(self):
        for value in ("/absolute", "../escape", "a/../escape", r"a\b", "C:/file",
                      "a//b", "", "./cURL.vcxproj"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                embedded._file(self.root, value)

    def test_openstep_parser_rejects_bad_syntax_and_duplicate_keys(self):
        for data in (b'{ a = "unterminated; }', b"{ a = 1; a = 2; }",
                     b"{ a = (x y); }", b"{a=1;}", b"{} extra"):
            if data == b"{a=1;}":
                self.assertEqual(embedded._openstep(data), {"a": "1"})
            else:
                with self.subTest(data=data), self.assertRaises(ValueError):
                    embedded._openstep(data)


if __name__ == "__main__":
    unittest.main()
