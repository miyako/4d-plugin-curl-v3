import copy
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import json
import os
import subprocess
import sys

import build_iconv
import prepare_cygwin
import trace_compiler


class IconvTests(unittest.TestCase):
    def test_acquisition_extraction_rejects_traversal_links_and_duplicate_members(self):
        cases = [
            [("libiconv-1.16/../../escape", tarfile.REGTYPE)],
            [("libiconv-1.16/link", tarfile.SYMTYPE)],
            [("libiconv-1.16/file", tarfile.REGTYPE), ("libiconv-1.16/file", tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                archive = root / "source.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    for name, kind in entries:
                        member = tarfile.TarInfo(name)
                        member.type = kind
                        member.size = 0
                        member.linkname = "/outside"
                        stream.addfile(member, io.BytesIO())
                with self.assertRaisesRegex(ValueError, "Unsafe, duplicate"):
                    build_iconv.extract(archive, root / "source", "1.16")
                self.assertFalse((root / "source").exists())

    def test_encoding_configuration_and_every_conversion_check_must_match(self):
        baseline = {"version": "1.16", "aliases": [["UTF-8", "UTF8"]],
                    "checks": build_iconv.CHECKS}
        build_iconv.compare(baseline, baseline, "1.16")
        for field, value in (("version", "1.18"), ("aliases", []),
                             ("aliases", [["UTF-8"]]), ("checks", build_iconv.CHECKS[:-1])):
            changed = copy.deepcopy(baseline)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                build_iconv.compare(changed, baseline, "1.16")

    def test_compiler_trace_preserves_arguments_and_does_not_reuse_failed_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, output = root / "input.c", root / "output.o"
            source.write_bytes(b"int value;")
            output.write_bytes(b"recorded object")
            arguments = ["-c", str(source), "-o", str(output)]
            for result in (0, 1):
                with mock.patch("trace_compiler.subprocess.run") as compiler:
                    compiler.return_value.returncode = result
                    self.assertEqual(trace_compiler.main(root, "/exact/compiler", arguments), result)
                    compiler.assert_called_once_with(["/exact/compiler", *arguments])
            records = [json.loads(p.read_text()) for p in root.glob("*.json")]
            good = next(p for p in records if p["returnCode"] == 0)
            self.assertEqual(good["inputs"], [
                {"path": source.as_posix(), "sha256": trace_compiler.digest(source)}])
            self.assertEqual(good["object"]["sha256"], trace_compiler.digest(output))
            self.assertNotIn("object", next(p for p in records if p["returnCode"] == 1))

    def test_resource_object_is_recorded_without_a_c_compiler_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, output = root / "version.rc", root / "version.o"
            source.write_bytes(b"resource input")
            output.write_bytes(b"COFF resource")
            with mock.patch("trace_compiler.subprocess.run") as compiler:
                compiler.return_value.returncode = 0
                trace_compiler.main(root, "windres", [
                    "-i", str(source), "-o", str(output), "--output-format=coff"])
            record = json.loads(next(root.glob("*.json")).read_text())
            self.assertEqual(record["object"]["sha256"], trace_compiler.digest(output))
            self.assertEqual(record["inputs"][0]["sha256"], trace_compiler.digest(source))

    def test_upstream_compile_wrapper_dash_fo_output_is_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, output = root / "input.c", root / "input.o"
            source.write_bytes(b"int value;")
            output.write_bytes(b"MSVC object")
            with mock.patch("trace_compiler.subprocess.run") as compiler:
                compiler.return_value.returncode = 0
                trace_compiler.main(root, "cl", ["-c", str(source), "-Fo" + str(output)])
            record = json.loads(next(root.glob("*.json")).read_text())
            self.assertEqual(record["object"]["sha256"], trace_compiler.digest(output))

    @unittest.skipIf(os.name == "nt", "The native Cygwin run covers the Windows shell boundary")
    def test_resource_shell_preserves_quoting_status_and_original_object_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, output = root / "input file.rc", root / "resource.obj"
            source.write_bytes(b"resource input")
            output.write_bytes(b"old object")
            compiler = root / "windres"
            compiler.write_text(
                "#!" + sys.executable + "\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))\n"
                "code = int(os.environ['RESULT'])\n"
                "if not code: pathlib.Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes(b'new object')\n"
                "sys.exit(code)\n")
            compiler.chmod(0o755)
            calls = root / "calls"
            calls.mkdir()
            arguments = ['-DPACKAGE_VERSION_STRING=\\"1.18\\"', "-i", str(source),
                         "-o", str(output), "--output-format=coff"]
            env = dict(os.environ, ICONV_TRACE_PYTHON=sys.executable,
                       ICONV_TRACE_SCRIPT=str(Path(trace_compiler.__file__).resolve()),
                       ICONV_TRACE_DIRECTORY=str(calls), ICONV_TRACE_WINDRES=str(compiler),
                       ICONV_TRACE_WINDRES_EXECUTABLE=str(compiler),
                       ARGUMENTS=str(root / "arguments.json"))
            for code in (0, 7):
                result = subprocess.run(["/bin/sh", str(
                    build_iconv.ROOT / "build/dependencies/native/msvc-trace/windres"),
                    *arguments], env=dict(env, RESULT=str(code)))
                self.assertEqual(result.returncode, code)
                self.assertEqual(json.loads((root / "arguments.json").read_text()), arguments)
            records = [json.loads(p.read_text()) for p in calls.glob("*.json")]
            good = next(p for p in records if p["returnCode"] == 0)
            self.assertEqual(good["arguments"], arguments)
            self.assertEqual(good["object"]["sha256"], trace_compiler.digest(output))
            self.assertNotIn("object", next(p for p in records if p["returnCode"] == 7))
            path = next(p for p in calls.glob("*.json")
                        if json.loads(p.read_text())["returnCode"] == 0)
            with self.assertRaisesRegex(ValueError, "completed twice"):
                trace_compiler.finish(path, 0)

    def test_changed_tool_installer_cannot_execute(self):
        with (
                tempfile.TemporaryDirectory() as temporary,
                mock.patch("prepare_cygwin.platform.system", return_value="Windows"),
                mock.patch("prepare_cygwin.urllib.request.urlretrieve",
                           side_effect=lambda url, path: path.write_bytes(b"changed")),
                mock.patch("prepare_cygwin.subprocess.run") as execute):
            with self.assertRaisesRegex(ValueError, "reviewed signed acquisition"):
                prepare_cygwin.prepare(Path(temporary) / "fresh")
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
