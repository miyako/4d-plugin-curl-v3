import copy
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import json

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
