from pathlib import Path, PurePosixPath
import struct
import tempfile
import unittest
from unittest.mock import patch

import probe_user_edit_windows as experiment
import user_relink_macos as mac
import user_relink_windows as user


class UserRelinkTests(unittest.TestCase):
    def test_mac_user_substitution_preserves_order_without_demo_linker_flags(self):
        kit = Path("kit").absolute()
        arguments = ["clang++", "-La", "-lproxy", "-lssl",
                     str(kit / "project/a/libiconv.a"), "-bundle", "-o", "cURL"]
        replacements = {"a/libproxy.a": Path("user proxy.a"),
                        "a/libiconv.a": Path("user conversion.a")}
        result = mac.substitute(arguments, kit,
                                {"a/libproxy.a": "p", "a/libiconv.a": "i"}, replacements)
        expected = list(arguments)
        expected[2], expected[4] = "user proxy.a", "user conversion.a"
        self.assertEqual(result, expected)
        self.assertEqual(arguments[2], "-lproxy")
        self.assertFalse(any("user_relink_probe" in a for a in result))

    def test_mac_user_substitution_rejects_unselected_ambiguous_or_repeated_inputs(self):
        for selected, arguments, replacements in (
                ({"a/libproxy.a": "p"}, ["-lproxy"], {"a/libother.a": Path("user.a")}),
                ({"a/libproxy.a": "p"}, ["-lssl"], {"a/libproxy.a": Path("user.a")}),
                ({"a/libproxy.a": "p"}, ["-lproxy"] * 2, {"a/libproxy.a": Path("user.a")}),
                ({"a/libproxy.a": "p", "b/libproxy.a": "q"}, ["-lproxy"],
                 {"a/libproxy.a": Path("user.a")})):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                mac.substitute(arguments, Path("kit"), selected, replacements)

    def test_mac_proof_commands_use_original_posix_roots_not_the_inspection_host(self):
        recipe = {"target": "macos-arm64", "arguments": [
            "${DRIVER}", "-isysroot", "${SDK}", "-filelist", "replaced-list", "-liconv",
            "-o", "${OUTPUT}/macos-arm64/cURL"]}
        output = PurePosixPath("/original user output")
        replacement = output / "replacements/macos-arm64/a/libiconv.a"
        result = mac.arguments_for(PurePosixPath("/original kit"), output, recipe,
                                   "/Xcode/clang++", "/Xcode/MacOSX.sdk",
                                   {"a/libiconv.a": "sha"}, {"a/libiconv.a": replacement})
        self.assertEqual(result[4], "/original user output/macos-arm64/objects.list")
        self.assertEqual(result[5], str(replacement))
        self.assertEqual(result[-1], "/original user output/macos-arm64/cURL")

    def test_mac_public_symbol_gate_excludes_private_local_undefined_and_debug_entries(self):
        symbols = [("_PluginMain", 0x0f, 1), ("_private", 0x1f, 1),
                   ("_undefined", 0x01, 0), ("_local", 0x0e, 1),
                   ("_debug", 0xef, 1), ("_repeat", 0x0e, 1), ("_repeat", 0x0e, 1)]
        strings, entries = b"\0", []
        for name, kind, section in symbols:
            entries.append(struct.pack("<IBBHQ", len(strings), kind, section, 0, 0))
            strings += name.encode() + b"\0"
        raw = b"".join(entries)
        binary = (struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 8, 1, 24, 0, 0)
                  + struct.pack("<6I", 2, 24, 56, len(entries), 56 + len(raw), len(strings))
                  + raw + strings)
        self.assertEqual(mac.public_symbols(binary), {"_PluginMain"})
        self.assertTrue(mac.portable.local.defines_marker(binary, "_local"))
        self.assertFalse(mac.portable.local.defines_marker(binary, "_repeat"))

    def test_working_copy_preserves_all_source_names_including_windows_lib_license_texts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "prepared"
            for name in ("source/COPYING.LIB", "source/libcharset/COPYING.LIB",
                         "source/fixture.a", "build/config.h", "recipe/builder.py"):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            experiment.copy_working_inputs(source, root / "working")
            for path in source.rglob("*"):
                if path.is_file():
                    self.assertEqual(path.read_bytes(), (
                        root / "working" / path.relative_to(source)).read_bytes())

    def test_selected_delivery_paths_become_repository_paths_not_basename_guesses(self):
        record = {"target": "windows-x86_64", "selectedArchives": {
            "project/lib/64/iconv.lib": "hash"}}
        with patch.object(user.delivery, "inspect", return_value=record):
            self.assertEqual(user.selected_inputs(Path("kit"))["selectedArchives"],
                             {"lib/64/iconv.lib": "hash"})

    def test_substitution_preserves_order_flags_and_accepts_arbitrary_user_archive_name(self):
        arguments = ["link.exe", "/LIBPATH:lib/64", "bcrypt.lib", "iconv.lib", "kernel32.lib",
                     "/OUT:output.dll", "/DLL"]
        replacements = {"lib/64/iconv.lib": Path("/user/My changed conversion.a")}
        changed = user.substitute(arguments, {"lib/64/iconv.lib": "hash"}, replacements)
        self.assertEqual(changed, arguments[:3] + [str(replacements["lib/64/iconv.lib"])]
                         + arguments[4:])
        self.assertEqual(arguments[3], "iconv.lib")
        self.assertFalse(any(a.startswith(("/EXPORT:", "/INCLUDE:")) for a in changed))

    def test_substitution_rejects_unselected_ambiguous_and_missing_or_repeated_inputs(self):
        for selected, arguments, replacements in (
                ({"lib/64/iconv.lib": "hash"}, ["iconv.lib"], {}),
                ({"lib/64/iconv.lib": "hash"}, ["other.lib"], {"lib/64/iconv.lib": "new.lib"}),
                ({"lib/64/iconv.lib": "hash"}, ["iconv.lib"] * 2, {"lib/64/iconv.lib": "new.lib"}),
                ({"lib/64/iconv.lib": "hash"}, ["other.lib"], {"lib/64/other.lib": "new.lib"}),
                ({"lib/64/iconv.lib": "a", "else/ICONV.LIB": "b"}, ["iconv.lib"],
                 {"lib/64/iconv.lib": "new.lib"})):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                user.substitute(arguments, selected, replacements)

    def test_replacement_cli_rejects_traversal_noncanonical_and_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            value = "lib/64/iconv.lib=" + str(Path(directory) / "my library.lib")
            self.assertEqual(list(user.replacement_options([value])), ["lib/64/iconv.lib"])
            for values in ([value, value], ["../iconv.lib=x"], ["C:/iconv.lib=x"],
                           ["lib\\64\\iconv.lib=x"], ["lib//64/iconv.lib=x"], ["lib/iconv.lib="]):
                with self.subTest(values=values), self.assertRaises(ValueError):
                    user.replacement_options(values)

    def test_source_experiment_edits_active_function_without_exported_marker(self):
        original = b"before\nint iconv_close (iconv_t icd)\n{\n  return 0;\n}\nafter\n"
        changed = experiment.edit_source(original, "2026-06-01")
        self.assertIn(b"volatile unsigned int user_selected_revision", changed)
        self.assertIn(b"2026-06-01", changed)
        self.assertNotIn(b"user_relink_probe", changed)
        self.assertTrue(changed.endswith(b"  return 0;\n}\nafter\n"))
        for invalid in (b"wrong source", original * 2):
            with self.assertRaises(ValueError):
                experiment.edit_source(invalid, "2026-06-01")
        with self.assertRaises(ValueError):
            experiment.edit_source(original, "2026-02-30")
