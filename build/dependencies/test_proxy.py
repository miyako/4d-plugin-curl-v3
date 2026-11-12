import hashlib
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
import relink_plugin_macos
import relink_plugin_windows
import portable_plugin_macos
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

    def test_portable_mac_relocation_preserves_order_and_rejects_external_inputs(self):
        project, sdk, driver = Path("/old/project"), Path("/sdk"), Path("/tools/clang++")
        command = [str(driver), "-isysroot", str(sdk), "-L/old/project/a", "-F/old/project",
                   "-filelist", "/old/project/objects", "-lssl", "-lproxy", "-lcrypto",
                   "/sdk/usr/lib/ssh-keychain.tbd", "-o", "/old/output",
                   "-Xlinker", "-map", "-Xlinker", "/old/map",
                   "-Xlinker", "-dependency_info", "-Xlinker", "/old/deps"]
        result = portable_plugin_macos.relocate(command, project, sdk, driver, "macos-arm64")
        self.assertEqual(result[:6], ["${DRIVER}", "-isysroot", "${SDK}",
                                     "-L${KIT}/project/a", "-F${KIT}/project", "-filelist"])
        self.assertEqual(result[7:11], ["-lssl", "-lproxy", "-lcrypto",
                                       "${SDK}/usr/lib/ssh-keychain.tbd"])
        self.assertIn("${OUTPUT}/macos-arm64/cURL", result)
        self.assertEqual(command[0], str(driver))
        with self.assertRaisesRegex(ValueError, "Unaccounted absolute"):
            portable_plugin_macos.relocate(command + ["/external/input.a"],
                                           project, sdk, driver, "macos-arm64")

    def test_portable_mac_materials_reject_path_escape_and_byte_change(self):
        for path in ("../escape", "/absolute", "a\\escape", "C:escape"):
            with self.assertRaisesRegex(ValueError, "escapes"):
                portable_plugin_macos.relative_path(self.root, path)
        (self.root / "object.o").write_bytes(b"changed")
        (self.root / portable_plugin_macos.MANIFEST).write_text(json.dumps({
            "schemaVersion": 1, "target": "macos-universal",
            "status": "not-approved-for-production",
            "files": [{"path": "object.o", "sha256": "0" * 64}],
        }))
        with mock.patch.object(portable_plugin_macos.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(ValueError, "materials changed"):
                portable_plugin_macos.replay(self.root, self.root.parent / "unused-output", {})

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

    def test_proxy_archive_proof_requires_exact_compiler_closure_and_installed_copy(self):
        output, commands = self.commands()
        for index, command in enumerate(commands):
            target = ("modman" if "module_manager.cpp" in command["file"] else
                      "tests" if "/test/" in command["file"].replace("\\", "/") else "proxy")
            command.update(directory="/original/build",
                           output="CMakeFiles/" + target + ".dir/" + str(index) + ".obj")
        self.save_commands(output, commands)
        (output / "install/lib").mkdir(parents=True)
        for filename in ("libproxy.lib", "modman.lib"):
            (output / "build" / filename).write_bytes(filename.encode())
            (output / "install/lib" / filename).write_bytes(filename.encode())
        with mock.patch.object(inspect_proxy, "object_evidence",
                               return_value={"compiledObjects": [], "archiveObjects": []}):
            proof = inspect_proxy.compiler_archive_evidence(
                output, "windows-x86_64", ["ignore_domain"], str(self.source), "/original/build")
            self.assertEqual(len(proof["proxy"]["compiledSources"]), 6)
            self.assertEqual(len(proof["modman"]["compiledSources"]), 1)
            commands[0]["command"] = "cl -MT"
            self.save_commands(output, commands)
            inspect_proxy.compiler_archive_evidence(
                output, "windows-x86_64", ["ignore_domain"], str(self.source), "/original/build")
            for flag in ("/MD", "-MD", "/MTd"):
                commands[0]["command"] = "cl " + flag
                self.save_commands(output, commands)
                with self.assertRaisesRegex(ValueError, "static release CRT"):
                    inspect_proxy.compiler_archive_evidence(
                    output, "windows-x86_64", ["ignore_domain"], str(self.source), "/original/build")
            commands[0]["command"] = "cl /MT"
            commands[1]["directory"] = "/wrong/build"
            self.save_commands(output, commands)
            with self.assertRaisesRegex(ValueError, "source closure or original"):
                inspect_proxy.compiler_archive_evidence(
                    output, "windows-x86_64", ["ignore_domain"], str(self.source), "/original/build")
            commands[1]["directory"] = "/original/build"
            self.save_commands(output, commands)
            (output / "install/lib/libproxy.lib").write_bytes(b"other archive")
            with self.assertRaisesRegex(ValueError, "actual build output"):
                inspect_proxy.compiler_archive_evidence(
                    output, "windows-x86_64", ["ignore_domain"], str(self.source), "/original/build")

    def test_only_the_observed_darwin_symbol_table_timestamp_can_change_on_install(self):
        built, installed = self.root / "built.a", self.root / "installed.a"
        data = bytearray(b"!<arch>\n" + b"__.SYMDEF".ljust(16) + b"1234567890  " + b"x" * 50)
        built.write_bytes(data)
        data[33] = ord("1")
        installed.write_bytes(data)
        self.assertEqual(inspect_proxy.install_transformation(built, installed, "macos-arm64"),
                         "darwin-ranlib-symbol-table-timestamp-only")
        with self.assertRaisesRegex(ValueError, "actual build output"):
            inspect_proxy.install_transformation(built, installed, "windows-x86_64")
        data[-1] ^= 1
        installed.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "actual build output"):
            inspect_proxy.install_transformation(built, installed, "macos-arm64")

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
        canonical = hashlib.sha256(subprocess.check_output(
            ["git", "-C", str(self.source), "cat-file", "blob", "HEAD:COPYING"])).hexdigest()
        self.git("config", "core.autocrlf", "true")
        checkout = build_proxy.source_snapshot(self.source, lock)
        output = self.root / "staging"
        output.mkdir()
        staged, base, compiled = build_proxy.stage_source(self.source, output, lock, checkout)
        self.assertEqual(base[0]["sha256"], canonical)
        self.assertEqual(base, compiled)
        self.assertEqual(build_proxy.source_snapshot(self.source, lock), checkout)

    def test_user_relink_proof_cannot_self_authorize_a_different_source_change(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        data = b"// Synthetic library source\n"
        source_hash = hashlib.sha256(data).hexdigest()
        record = {"sourceFiles": [{"path": "libproxy/url.cpp", "sha256": source_hash}]}
        (candidate / "proxy-build-provenance.json").write_text(json.dumps(record))
        (candidate / "candidate-recipe.tar").write_bytes(b"synthetic recipe identity")
        with tarfile.open(candidate / "upstream-source.tar", "w") as archive:
            item = tarfile.TarInfo("libproxy/url.cpp")
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
        output = self.root / "relink"
        modified = output / "source/libproxy/url.cpp"
        modified.parent.mkdir(parents=True)
        change = relink_candidate.MODIFICATION.format(date="2026-11-12").replace("417", "999")
        modified.write_bytes(data + change.encode())
        proof = {
            "target": "macos-arm64",
            "candidateRecordSha256": digest(candidate / "proxy-build-provenance.json"),
            "deliveredSourceSha256": digest(candidate / "upstream-source.tar"),
            "deliveredRecipeSha256": digest(candidate / "candidate-recipe.tar"),
            "modification": {"dateUtc": "2026-11-12", "appendedSource": change,
                             "beforeSha256": source_hash, "afterSha256": digest(modified)},
        }
        (output / "user-relink-proof.json").write_text(json.dumps(proof))
        with mock.patch.object(relink_candidate, "inspect", return_value={"target": "macos-arm64"}):
            with self.assertRaisesRegex(ValueError, "reviewed benign probe"):
                relink_candidate.inspect_relink(candidate, output)

    def test_full_plugin_replay_preserves_objects_and_search_order_and_redirects_all_outputs(self):
        original = ["clang++", "-bundle", "-filelist", "/original/objects.txt",
                    "-L/original/a", "-lcurl", "-liconv", "-lproxy", "-lssl",
                    "-Xlinker", "-map", "-Xlinker", "/original/link.map",
                    "-Xlinker", "-dependency_info", "-Xlinker", "/original/dependencies.dat",
                    "-o", "/original/cURL"]
        replay = relink_plugin_macos.link_arguments(original, self.root, self.root / "modified.a")
        self.assertEqual(replay[2:10], ["-filelist", "/original/objects.txt",
                                       "-L/original/a", "-lcurl", "-liconv",
                                       str(self.root / "modified.a"), "-lssl", "-Xlinker"])
        self.assertEqual(replay[12], str(self.root / "link.map"))
        self.assertEqual(replay[16], str(self.root / "dependencies.dat"))
        self.assertEqual(replay[18], str(self.root / "cURL"))
        self.assertEqual(replay[-1], "-Wl,-u,_proxy_user_relink_probe")
        self.assertEqual(original[-1], "/original/cURL")
        with self.assertRaisesRegex(ValueError, "one original plugin"):
            relink_plugin_macos.link_arguments(original + ["-lproxy"], self.root)
        with self.assertRaisesRegex(ValueError, "diagnostic output"):
            relink_plugin_macos.link_arguments(
                [a for a in original if a != "-map"], self.root)

    def test_full_plugin_marker_must_be_a_defined_symbol_not_an_import_or_plain_text(self):
        names = b"\0" + relink_plugin_macos.MARKER.encode() + b"\0"
        header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 8, 1, 24, 0, 0)
        table = struct.pack("<6I", 2, 24, 56, 1, 72, len(names))
        def image(kind, section):
            return header + table + struct.pack("<IBBHQ", 1, kind, section, 0, 4096) + names
        self.assertTrue(relink_plugin_macos.defines_marker(image(0x0F, 1)))
        self.assertFalse(relink_plugin_macos.defines_marker(image(0x01, 0)))
        self.assertFalse(relink_plugin_macos.defines_marker(image(0xEF, 1)))

    def test_windows_full_plugin_replay_redirects_outputs_without_changing_search_order(self):
        original = ["link.exe", "/OUT:old.4DX", "/PDB:old.pdb", "/MAP:old.map",
                    "/IMPLIB:old.lib", "/LTCGOUT:old.iobj", "/LIBPATH:original",
                    "libcurl.lib", "libproxy.lib", "libssl.lib", "original.obj"]
        result = relink_plugin_windows.link_arguments(original, self.root, self.root / "modified.lib")
        self.assertEqual(result[6:], ["/LIBPATH:original", "libcurl.lib",
                                     str(self.root / "modified.lib"), "libssl.lib",
                                     "original.obj", "/EXPORT:proxy_user_relink_probe"])
        self.assertEqual(result[1], "/OUT:" + str(self.root / "cURL.4DX"))
        with self.assertRaisesRegex(ValueError, "one original proxy"):
            relink_plugin_windows.link_arguments(original + ["libproxy.lib"], self.root)
        with self.assertRaisesRegex(ValueError, "additional Windows"):
            relink_plugin_windows.link_arguments(original + ["/DEBUG"], self.root)

    def test_windows_marker_must_export_own_executable_code_and_baseline_mask_is_narrow(self):
        data = bytearray(2048)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<HH", data, 132, 0x8664, 1)
        struct.pack_into("<H", data, 148, 240)
        struct.pack_into("<H", data, 152, 0x20B)
        struct.pack_into("<I", data, 260, 16)
        struct.pack_into("<II", data, 264, 4096, 128)
        struct.pack_into("<4I", data, 400, 1024, 4096, 1024, 512)
        struct.pack_into("<I", data, 428, 0x60000020)
        struct.pack_into("<5I", data, 532, 1, 1, 4144, 4148, 4152)
        struct.pack_into("<III", data, 560, 4608, 4160, 0)
        name = b"proxy_user_relink_probe\0"
        data[576:576 + len(name)] = name
        normal, exports, fields = relink_plugin_windows.pe_layout(data)
        self.assertIn("proxy_user_relink_probe", exports)
        for offset in fields.values():
            struct.pack_into("<I", data, offset, 12345)
        self.assertEqual(relink_plugin_windows.pe_layout(data)[0], normal)
        struct.pack_into("<II", data, 312, 4224, 56)
        for offset, kind in ((640, 13), (668, 14)):
            struct.pack_into("<I", data, offset + 4, 12345)
            struct.pack_into("<I", data, offset + 12, kind)
        normalized = relink_plugin_windows.pe_layout(data)[0]
        for offset in relink_plugin_windows.pe_layout(data)[2].values():
            struct.pack_into("<I", data, offset, 54321)
        self.assertEqual(relink_plugin_windows.pe_layout(data)[0], normalized)
        struct.pack_into("<I", data, 644, 7)
        with self.assertRaisesRegex(ValueError, "debug timestamp/type"):
            relink_plugin_windows.pe_layout(data)
        struct.pack_into("<I", data, 644, 54321)
        data[1024] = 1
        self.assertNotEqual(relink_plugin_windows.pe_layout(data)[0], normalized)
        struct.pack_into("<I", data, 560, 4100)
        with self.assertRaisesRegex(ValueError, "forwarder"):
            relink_plugin_windows.pe_layout(data)


if __name__ == "__main__":
    unittest.main()
