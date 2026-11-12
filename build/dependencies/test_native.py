import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import build_native


class NativePrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_configure_rename_preserves_bytes_and_rejects_other_changes(self):
        before = [{"path": "zconf.h", "sha256": "a" * 64},
                  {"path": "deflate.c", "sha256": "b" * 64}]
        after = [{"path": "zconf.h.included", "sha256": "a" * 64}, before[1]]
        build_native.verify_layout(before, after, {"zconf.h": "zconf.h.included"})
        for changed in (
                [{"path": "zconf.h.included", "sha256": "c" * 64}, before[1]],
                after + [{"path": "extra.h", "sha256": "d" * 64}],
                after[:-1]):
            with self.assertRaisesRegex(ValueError, "reviewed configure"):
                build_native.verify_layout(before, changed, {"zconf.h": "zconf.h.included"})

    def test_runtime_config_comparison_rejects_version_or_compile_feature_changes(self):
        new, old = self.root / "new.json", self.root / "old.json"
        baseline = {"version": "1.3.2", "compileFlags": 169}
        old.write_text(json.dumps(baseline))
        new.write_text(json.dumps(baseline))
        build_native.compare_zlib(new, old)
        for value in ({"version": "1.3.1", "compileFlags": 169},
                      {"version": "1.3.2", "compileFlags": 169 | (1 << 17)}):
            new.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "differ from the exact selected baseline"):
                build_native.compare_zlib(new, old)

    def test_native_compatibility_requires_cross_reads_and_no_skips(self):
        path = self.root / "tests.xml"
        suite = ET.Element("testsuite", tests="5", failures="0")
        for name in sorted(build_native.TESTS):
            ET.SubElement(suite, "testcase", name=name, status="run")
        ET.ElementTree(suite).write(path)
        build_native.verify_tests(path)
        ET.SubElement(suite[0], "skipped")
        ET.ElementTree(suite).write(path)
        with self.assertRaisesRegex(ValueError, "Missing or skipped"):
            build_native.verify_tests(path)
        suite[0].remove(suite[0].find("skipped"))
        ET.SubElement(suite[0], "failure")
        suite[0].set("status", "fail")
        suite.set("failures", "1")
        ET.ElementTree(suite).write(path)
        with self.assertRaisesRegex(ValueError, "compatibility tests failed"):
            build_native.verify_tests(path)
        self.assertEqual(build_native.verify_tests(path, allow_failed=True),
                         [suite[0].get("name")])

    def test_staged_sources_reject_symbolic_directory_inputs(self):
        external = self.root / "external"
        external.mkdir()
        source = self.root / "source"
        source.mkdir()
        (source / "source.c").write_text("int source;\n")
        try:
            (source / "extra").symlink_to(external, target_is_directory=True)
        except OSError:
            self.skipTest("symbolic links require host permission")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            build_native.tree_files(source)

    @unittest.skipIf(os.name == "nt", "Windows does not enforce POSIX executable modes")
    def test_git_source_staging_preserves_upstream_script_executability(self):
        with tarfile.open(self.root / "upstream-source.tar", "w") as archive:
            for name, mode in (("configure", 0o755), ("header.h", 0o644)):
                entry = tarfile.TarInfo(name)
                entry.mode, entry.size = mode, 1
                archive.addfile(entry, io.BytesIO(b"x"))
        with mock.patch.object(build_native.subprocess, "run"):
            staged, _ = build_native.stage(
                self.root, self.root, "pinned", [{"path": "configure"}, {"path": "header.h"}])
        self.assertTrue((staged / "configure").stat().st_mode & 0o111)
        self.assertFalse((staged / "header.h").stat().st_mode & 0o111)

    def test_existing_outputs_cannot_receive_fresh_provenance(self):
        output = self.root / "old-output"
        output.mkdir()
        with mock.patch.object(build_native, "checkout_files", return_value=[]):
            with self.assertRaisesRegex(ValueError, "fresh output directory"):
                build_native.build(self.root, output, "zlib", "macos-arm64")

    def test_windows_linker_proof_resolves_each_probe_separately(self):
        (self.root / "build").mkdir()
        for kind, archive in (("candidate", r"D:\build\upstream\zlib.lib"),
                              ("baseline", r"C:\vendor\zlib.lib")):
            (self.root / "build" / (kind + ".map")).write_text("Publics by Value\n")
            (self.root / (kind + "-build.log")).write_text(
                " Searching " + archive + ":\n"
                " Found zlibVersion\n Loaded zlib.lib(zutil.obj)\n")
        proof = build_native.link_selections(
            self.root, "windows-x86_64", "D:/build", "C:/vendor/zlib.lib", "zlib.lib")
        self.assertEqual(len(proof["candidate"]), 1)
        (self.root / "candidate-build.log").write_text(
            " Searching C:\\vendor\\zlib.lib:\n"
            " Found zlibVersion\n Loaded zlib.lib(zutil.obj)\n")
        with self.assertRaisesRegex(ValueError, "exact candidate zlib"):
            build_native.link_selections(
                self.root, "windows-x86_64", "D:/build", "C:/vendor/zlib.lib", "zlib.lib")

    def test_archive_payload_must_equal_actual_compiler_outputs(self):
        (self.root / "build").mkdir()
        object_file = self.root / "build/source.o"
        object_file.write_bytes(b"compiled object")
        (self.root / "library.a").write_bytes(b"mock archive")
        with mock.patch("native_archive_objects.members",
                               return_value=[("source.o", 0, b"compiled object")]):
            proof = build_native.object_evidence(
                self.root, "library.a", [{"output": "source.o"}], "/original/build")
            self.assertEqual(len(proof["compiledObjects"]), 1)
            object_file.write_bytes(b"different compiler output")
            with self.assertRaisesRegex(ValueError, "actual compiled object outputs"):
                build_native.object_evidence(
                    self.root, "library.a", [{"output": "source.o"}], "/original/build")


if __name__ == "__main__":
    unittest.main()
