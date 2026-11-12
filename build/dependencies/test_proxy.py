import json
import io
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import build_proxy
import inspect_proxy
import relink_candidate
from provenance import digest


class ProxyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.source), *args], text=True, stderr=subprocess.PIPE).strip()

    def checkout(self):
        self.git("init", "--quiet")
        (self.source / "COPYING").write_text("Synthetic license fixture\n")
        self.git("add", "COPYING")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--quiet", "-m", "Synthetic source")
        return {"commit": self.git("rev-parse", "HEAD")}

    def test_pinned_source_rejects_wrong_revision_and_modified_or_extra_source(self):
        lock = self.checkout()
        original = build_proxy.source_snapshot(self.source, lock)
        self.assertEqual(original[0]["path"], "COPYING")
        with self.assertRaisesRegex(ValueError, "commit"):
            build_proxy.source_snapshot(self.source, {"commit": "f" * 40})
        (self.source / "COPYING").write_text("changed")
        with self.assertRaisesRegex(ValueError, "clean"):
            build_proxy.source_snapshot(self.source, lock)
        (self.source / "COPYING").write_text("Synthetic license fixture\n")
        (self.source / "injected.hpp").write_text("untracked input")
        with self.assertRaisesRegex(ValueError, "clean"):
            build_proxy.source_snapshot(self.source, lock)

    def test_baseline_requires_exact_original_archives(self):
        frozen = {"targets": [{"id": "windows-x86_64", "selectedArchives": []}]}
        for name in ("libproxy", "libmodman"):
            path = self.root / (name + ".lib")
            path.write_bytes(name.encode())
            frozen["targets"][0]["selectedArchives"].append({
                "name": name, "path": path.name, "sha256": digest(path)})
        (self.root / "baseline-v4.9.10.json").write_text(json.dumps(frozen))
        with mock.patch.object(build_proxy, "HERE", self.root):
            self.assertEqual(len(build_proxy.baseline_inputs(self.root, "windows-x86_64")), 2)
            (self.root / "libproxy.lib").write_bytes(b"replacement")
            with self.assertRaisesRegex(ValueError, "Baseline proxy archive hash"):
                build_proxy.baseline_inputs(self.root, "windows-x86_64")

    def commands(self, target="windows-x86_64"):
        paths = ["libmodman/module_manager.cpp", "libproxy/extension_config.cpp",
                 "libproxy/extension_pacrunner.cpp", "libproxy/extension_wpad.cpp",
                 "libproxy/proxy.cpp", "libproxy/url.cpp",
                 "libproxy/test/url-test.cpp", "libproxy/test/url-encode.cpp",
                 "libproxy/modules/ignore_domain.cpp"]
        flags = "/MT" if target.startswith("windows") else "-arch arm64 -mmacosx-version-min=10.13"
        output = self.root / "output"
        (output / "build").mkdir(parents=True, exist_ok=True)
        commands = [{"file": str(self.source / path), "command": "compiler " + flags}
                    for path in paths]
        self.save_commands(output, commands)
        return output, commands

    def save_commands(self, output, commands):
        (output / "build/compile_commands.json").write_text(json.dumps(commands))

    def test_rejects_missing_actual_module_and_dynamic_crt(self):
        output, commands = self.commands()
        build_proxy.check_commands(output, "windows-x86_64", ["ignore_domain"], self.source)
        commands[-1]["command"] = "cl /MD"
        self.save_commands(output, commands)
        with self.assertRaisesRegex(ValueError, "static MSVC CRT"):
            build_proxy.check_commands(output, "windows-x86_64", ["ignore_domain"], self.source)
        self.save_commands(output, commands[:-1])
        with self.assertRaisesRegex(ValueError, "compiled upstream sources"):
            build_proxy.check_commands(output, "windows-x86_64", ["ignore_domain"], self.source)

    def test_rejects_wrong_architecture_or_deployment_target(self):
        output, commands = self.commands("macos-arm64")
        build_proxy.check_commands(output, "macos-arm64", ["ignore_domain"], self.source)
        for flags in ("-arch x86_64 -mmacosx-version-min=10.13",
                      "-arch arm64 -mmacosx-version-min=12.0"):
            commands[0]["command"] = "clang " + flags
            self.save_commands(output, commands)
            with self.assertRaisesRegex(ValueError, "deployment compatibility"):
                build_proxy.check_commands(output, "macos-arm64", ["ignore_domain"], self.source)

    def test_old_output_cannot_be_blessed_as_fresh_source_build(self):
        output = self.root / "old-output"
        output.mkdir()
        with mock.patch.object(build_proxy, "source_snapshot", return_value=[]), \
                mock.patch.object(build_proxy, "recipe_snapshot", return_value=[]):
            with self.assertRaisesRegex(ValueError, "fresh output directory"):
                build_proxy.build(self.source, output, "macos-arm64", self.root)

    def test_persisted_source_tar_rejects_mutation_and_duplicate_members(self):
        path = self.root / "source.tar"
        def write(entries):
            with tarfile.open(path, "w") as archive:
                for name, data in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        write([("COPYING", b"license")])
        import hashlib
        files = [{"path": "COPYING", "sha256": hashlib.sha256(b"license").hexdigest()}]
        inspect_proxy.verify_tar(path, files)
        write([("COPYING", b"mutated")])
        with self.assertRaisesRegex(ValueError, "member hash"):
            inspect_proxy.verify_tar(path, files)
        write([("COPYING", b"license"), ("COPYING", b"license")])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            inspect_proxy.verify_tar(path, files)

    def test_archive_cpu_is_checked_not_just_compiler_flags(self):
        payload = struct.pack("<IIII", 0xFEEDFACF, 0x0100000C, 0, 1)
        header = (b"example.o/".ljust(16) + b"0".ljust(12) + b"0".ljust(6)
                  + b"0".ljust(6) + b"644".ljust(8)
                  + str(len(payload)).encode().ljust(10) + b"`\n")
        path = self.root / "libproxy.a"
        path.write_bytes(b"!<arch>\n" + header + payload)
        self.assertEqual(inspect_proxy.verify_architecture(path, "macos-arm64"), 1)
        with self.assertRaisesRegex(ValueError, "archive member target"):
            inspect_proxy.verify_architecture(path, "macos-x86_64")
        with self.assertRaisesRegex(ValueError, "archive member target"):
            inspect_proxy.verify_architecture(path, "windows-x86_64")

    def test_native_results_require_all_comparisons_and_no_skips(self):
        path = self.root / "test-results.xml"
        suite = ET.Element("testsuite", tests="5", failures="0")
        for name in ("proxy_behavior", "proxy_file_url", "proxy_url_test", "proxy_url_encode", "proxy_baseline_behavior"):
            ET.SubElement(suite, "testcase", name=name, status="run")
        ET.ElementTree(suite).write(path)
        inspect_proxy.verify_tests(path)
        ET.SubElement(suite[-1], "skipped")
        ET.ElementTree(suite).write(path)
        with self.assertRaisesRegex(ValueError, "successful native"):
            inspect_proxy.verify_tests(path)
        suite[-1].remove(suite[-1].find("skipped"))
        ET.SubElement(suite[-1], "failure")
        suite[-1].set("status", "fail")
        suite.set("failures", "1")
        ET.ElementTree(suite).write(path)
        with self.assertRaisesRegex(ValueError, "compatibility tests failed"):
            inspect_proxy.verify_tests(path)
        self.assertEqual(inspect_proxy.verify_tests(path, allow_failed=True),
                         ["proxy_baseline_behavior"])

    def test_patch_delta_rejects_unreviewed_changes_or_wrong_base(self):
        base = [{"path": "url.cpp", "sha256": "a" * 64}, {"path": "other.cpp", "sha256": "b" * 64}]
        compiled = [{"path": "url.cpp", "sha256": "c" * 64}, base[1]]
        patches = [{"files": [{"path": "url.cpp", "beforeSha256": "a" * 64,
                              "afterSha256": "c" * 64}]}]
        inspect_proxy.verify_source_delta(base, compiled, patches)
        with self.assertRaisesRegex(ValueError, "reviewed patch delta"):
            inspect_proxy.verify_source_delta(base, compiled + [{"path": "injected.h", "sha256": "d" * 64}], patches)
        patches[0]["files"][0]["beforeSha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "base source hash"):
            inspect_proxy.verify_source_delta(base, compiled, patches)

    def test_staged_source_is_isolated_and_rejects_extra_inputs(self):
        lock = self.checkout()
        lock["patches"] = []
        before = build_proxy.source_snapshot(self.source, lock)
        output = self.root / "staging"
        output.mkdir()
        staged, base, compiled = build_proxy.stage_source(self.source, output, lock, before)
        self.assertEqual(base, compiled)
        self.assertEqual(build_proxy.source_snapshot(self.source, lock), before)
        (staged / "injected.hpp").write_text("extra input")
        with self.assertRaisesRegex(ValueError, "Unexpected staged"):
            build_proxy.staged_snapshot(staged, compiled)

    def test_delivered_relink_material_paths_cannot_escape_the_new_directory(self):
        path = self.root / "recipe.tar"
        with tarfile.open(path, "w") as archive:
            item = tarfile.TarInfo("../escape.cpp")
            item.size = 1
            archive.addfile(item, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "Unsafe delivered"):
            relink_candidate.unpack(path, [{"path": "../escape.cpp", "sha256": "a" * 64}],
                                    self.root / "relink")

    def test_canonical_staging_ignores_git_archive_eol_conversion(self):
        lock = self.checkout()
        lock["patches"] = []
        canonical = digest(self.source / "COPYING")
        self.git("config", "core.autocrlf", "true")
        checkout = build_proxy.source_snapshot(self.source, lock)
        output = self.root / "staging"
        output.mkdir()
        staged, base, compiled = build_proxy.stage_source(self.source, output, lock, checkout)
        self.assertEqual(base[0]["sha256"], canonical)
        self.assertEqual(base, checkout)
        self.assertEqual(base, compiled)
        self.assertEqual(build_proxy.source_snapshot(self.source, lock), checkout)


if __name__ == "__main__":
    unittest.main()
