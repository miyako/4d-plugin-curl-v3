import hashlib
import json
from pathlib import Path
import shutil
import unittest
import uuid

import linker


FIXTURES = Path(__file__).parent / "fixtures/linker"


APPLE = """# Path: /build/cURL
# Arch: arm64
# Object files:
[  0] linker synthesized
[  1] {archive}(live.o)
[  2] {archive}[removed.o]
# Sections:
# Address Size Segment Section
# Symbols:
# Address Size File Name
0x100000000 0x00000010 [  1] _live
# Dead Stripped Symbols:
# Size File Name
<<dead>> 0x00000010 [  2] _removed
"""

MSVC_MAP = """
 cURL
 Timestamp is 00000000
 Preferred load address is 0000000180000000
 Start         Length     Name                   Class
 0001:00000000 00000010H .text                  CODE
 Address         Publics by Value              Rva+Base               Lib:Object
 0001:00000000       live                      0000000180001000 f   demo:live.obj
 0001:00000010       sdk                       0000000180001010 f   kernel32:import.obj
 entry point at        0001:00000000
 Static symbols
 0001:00000008       local                     0000000180001008     demo:live.obj
"""


class LinkerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd() / (".linker-test-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.lib = self.root / "lib/demo.lib"
        self.lib.parent.mkdir()
        self.lib.write_bytes(b"selected archive fixture")

    def write(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def windows(self, verbose, candidates=()):
        return linker.collect(
            self.root, "windows-x86_64",
            {"map": self.write("plugin.map", MSVC_MAP),
             "verbose": self.write("link.log", verbose)}, candidates)

    def test_apple_layouts_dead_strip_and_raw_binding(self):
        archive = self.root / "lib/libdemo.a"
        archive.write_bytes(b"mac archive")
        path = self.write("arm64.map", APPLE.format(archive=archive))
        evidence = linker.collect(self.root, "macos-arm64", {"map": path},
                                  [{"path": "lib/libdemo.a", "sha256": linker.digest(archive)}])
        selected = evidence["selectedArchives"][0]
        self.assertIs(evidence["archives"], evidence["selectedArchives"])
        self.assertEqual(selected["candidatePath"], "lib/libdemo.a")
        self.assertEqual(selected["sha256"], linker.digest(archive))
        self.assertEqual(selected["status"], "selected-repository-candidate")
        live, dead = selected["members"]
        self.assertEqual((live["liveSymbolCount"], dead["liveSymbolCount"]), (1, 0))
        self.assertEqual(dead["deadSymbolCount"], 1)
        self.assertEqual(selected["selectedMembers"], ["live.o", "removed.o"])
        self.assertEqual([s["symbol"] for s in selected["liveSymbols"]], ["_live"])
        self.assertEqual([s["symbol"] for s in selected["deadSymbols"]], ["_removed"])
        self.assertEqual(evidence["diagnostics"][0]["sha256"], linker.digest(path))
        json.dumps(evidence)

    def test_real_apple_maps_resolve_relative_archive_paths_against_link_cwd(self):
        for arch in ("arm64", "x86_64"):
            with self.subTest(arch=arch):
                directory = self.root / arch
                directory.mkdir()
                archive = directory / "libselected.a"
                archive.write_bytes(b"selected archive; used.o and unselected.o")
                unused = directory / "libneverloaded.a"
                unused.write_bytes(b"unselected archive")
                candidates = [
                    {"path": p.relative_to(self.root).as_posix(),
                     "sha256": linker.digest(p), "status": "available-declared-input"}
                    for p in (archive, unused)
                ]
                evidence = linker.collect(
                    self.root, "macos-" + arch,
                    {"map": (FIXTURES / f"apple-{arch}.map").resolve()}, candidates)
                self.assertEqual(len(evidence["selectedArchives"]), 1)
                selected = evidence["selectedArchives"][0]
                self.assertEqual(selected["resolvedPath"], str(archive))
                self.assertEqual(selected["sha256"], linker.digest(archive))
                self.assertEqual(selected["candidatePaths"], [f"{arch}/libselected.a"])
                self.assertEqual(len(selected["members"]), 1)
                member = selected["members"][0]
                self.assertEqual(member["member"], "used.o")
                self.assertEqual(member["liveSymbolCount"], 1)
                self.assertEqual(member["deadSymbolCount"], 1)
                self.assertEqual({s["status"] for s in evidence["mapSymbols"]},
                                 {"map-live-symbol", "dead-stripped"})
                self.assertNotIn("unselected.o", json.dumps(evidence))

    def test_indexed_apple_why_load_member_spelling(self):
        # Actual ld -why_load output uses an archive-local index before the member.
        line = ("'_used_dependency' caused load of "
                "/build/linker-probe/arm64/libselected.a[2](used.o)")
        pair = linker.archive_member(line.split(" caused load of ", 1)[1])
        self.assertEqual(pair, ("/build/linker-probe/arm64/libselected.a", "used.o"))
        self.assertEqual(linker.archive_member("libselected.a[used.o]"),
                         ("libselected.a", "used.o"))
        self.assertIsNone(linker.archive_member("libselected.a[used.o)"))

    def test_real_force_loaded_dead_and_lto_selections_survive_without_live_symbols(self):
        for arch in ("arm64", "x86_64"):
            for mode in ("force-loaded-dead", "lto"):
                with self.subTest(arch=arch, mode=mode):
                    directory = self.root / arch
                    if mode == "lto":
                        directory /= "lto"
                    directory.mkdir(parents=True, exist_ok=True)
                    names = ("libselected.a", "libunused.a") if mode == "force-loaded-dead" else (
                        "libselected.a",)
                    candidates = []
                    for name in names:
                        archive = directory / name
                        archive.write_bytes(b"selected archive fixture")
                        candidates.append({"path": archive.relative_to(self.root).as_posix(),
                                           "sha256": linker.digest(archive),
                                           "status": "available-declared-input"})
                    evidence = linker.collect(
                        self.root, "macos-" + arch,
                        {"map": (FIXTURES / f"apple-{arch}-{mode}.map").resolve()}, candidates)
                    self.assertEqual(len(evidence["selectedArchives"]), len(names))
                    archive = evidence["selectedArchives"][-1]
                    self.assertEqual(archive["status"], "selected-repository-candidate")
                    self.assertEqual(archive["members"][0]["liveSymbolCount"], 0)
                    self.assertEqual(archive["members"][0]["deadSymbolCount"],
                                     1 if mode == "force-loaded-dead" else 0)
                    self.assertEqual(archive["liveSymbols"], [])
                    self.assertIn("candidatePath", archive)
                    self.assertEqual(archive["sha256"], candidates[-1]["sha256"])
                    if mode == "lto":
                        self.assertEqual(evidence["mapSymbols"], [])

    def test_wrong_architecture_and_missing_map_fail(self):
        path = self.write("wrong.map", APPLE.format(archive="lib/libdemo.a"))
        with self.assertRaisesRegex(ValueError, "architecture"):
            linker.collect(self.root, "macos-x86_64", {"map": path}, [])
        with self.assertRaises(FileNotFoundError):
            linker.collect(self.root, "macos-arm64", {"map": "absent.map"}, [])

    def test_verbose_search_found_loaded_and_map_symbols(self):
        evidence = self.windows(f"""
 Searching {self.lib}:
   Found live
     Referenced in plugin.obj
     Loaded demo.lib(live.obj)
   Found unused
     Loaded demo.lib(removed.obj)
 Searching C:\\SDK\\kernel32.lib:
   Found sdk
     Loaded kernel32.lib(import.obj)
""", [{"path": "lib/demo.lib", "sha256": linker.digest(self.lib)}])
        selected, sdk = evidence["selectedArchives"]
        self.assertEqual(selected["status"], "selected-repository-candidate")
        self.assertEqual(selected["members"][0]["foundSymbol"], "live")
        self.assertEqual(selected["members"][0]["liveSymbolCount"], 2)
        self.assertEqual(selected["members"][1]["liveSymbolCount"], 0)
        self.assertEqual(sdk["status"], "unresolved-selection")
        self.assertEqual(sdk["reportedPath"], r"C:\SDK\kernel32.lib")

    def test_unresolved_windows_basename_is_not_relocated(self):
        evidence = self.windows(" Loaded demo.lib(live.obj)\n",
                                [{"path": "lib/demo.lib", "sha256": linker.digest(self.lib)}])
        archive = evidence["selectedArchives"][0]
        self.assertEqual(archive["status"], "unresolved-selection")
        self.assertNotIn("sha256", archive)
        self.assertNotIn("candidatePath", archive)
        self.assertEqual(archive["candidatePaths"], [])

    def test_foreign_absolute_path_is_not_relocated(self):
        evidence = self.windows(r"""
 Searching C:\developer\demo.lib:
   Found live
   Loaded demo.lib(live.obj)
""", [{"path": "lib/demo.lib", "sha256": linker.digest(self.lib)}])
        self.assertEqual(evidence["selectedArchives"][0]["status"], "unresolved-selection")
        self.assertEqual(evidence["selectedArchives"][0]["candidatePaths"], [])
        self.assertNotIn("candidatePath", evidence["archives"][0])

    def test_same_resolved_path_wrong_hash_fails(self):
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.windows(f" Loaded {self.lib}(live.obj)\n",
                         [{"path": "lib/demo.lib", "sha256": "0" * 64}])

    def test_map_basename_ambiguity_is_retained_not_guessed(self):
        other = self.root / "other/demo.lib"
        other.parent.mkdir()
        other.write_bytes(b"second archive")
        evidence = self.windows(
            f" Loaded {self.lib}(live.obj)\n Loaded {other}(live.obj)\n")
        self.assertEqual(evidence["mapSymbols"][0]["status"], "ambiguous-map-library")
        for archive in evidence["selectedArchives"]:
            self.assertEqual(archive["members"][0]["liveSymbolCount"], 0)

    def test_search_does_not_imply_selection_or_live_contribution(self):
        evidence = self.windows(f" Searching {self.root / 'lib/unused.lib'}:\n Found discarded\n")
        self.assertEqual(evidence["selectedArchives"], [])
        self.assertEqual(evidence["mapSymbols"][0]["status"], "unresolved-map-library")

    def test_ltcg_search_only_output_requires_positive_map_attribution(self):
        evidence = self.windows(
            f" Searching {self.lib}:\n Searching {self.lib}:\n"
            f" Searching {self.root / 'lib/unused.lib'}:\n",
            [{"path": "lib/demo.lib", "sha256": linker.digest(self.lib)}])
        selected = evidence["archives"]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["candidatePath"], "lib/demo.lib")
        self.assertEqual(selected[0]["selectedMembers"], ["live.obj"])
        self.assertEqual(selected[0]["members"][0]["selection"],
                         "map-symbol-and-unique-diagnostic-path")
        self.assertEqual(selected[0]["members"][0]["liveSymbolCount"], 2)

    def test_ltcg_duplicate_searched_basenames_are_never_guessed(self):
        evidence = self.windows(
            f" Searching {self.lib}:\n Searching C:\\developer\\demo.lib:\n",
            [{"path": "lib/demo.lib", "sha256": linker.digest(self.lib)}])
        self.assertEqual(evidence["archives"], [])
        self.assertEqual(evidence["mapSymbols"][0]["status"], "ambiguous-map-library")
        self.assertEqual(len(evidence["mapSymbols"][0]["pathCandidates"]), 2)

    def test_real_v143_ltcg_shapes_and_unused_encoder_not_selected(self):
        selected, symbols = linker.parse_msvc(
            (FIXTURES / "msvc-ltcg.log").read_text(),
            (FIXTURES / "msvc-ltcg.map").read_text())
        self.assertEqual({item["archive"] for item in selected}, {
            r"lib\64\brotlicommon.lib", r"lib\64\brotlidec.lib", r"lib\64\libcrypto.lib",
            r"lib\64\libssl.lib", r"lib\64\libcurl.lib", r"lib\64\zlib.lib",
        })
        self.assertEqual(len(symbols), 6)
        self.assertTrue(all(item["selection"] == "map-symbol-and-unique-diagnostic-path"
                            for item in selected))
        searched_only = " cURL\n Address Publics by Value Rva+Base Lib:Object\n"
        self.assertEqual(linker.parse_msvc(
            (FIXTURES / "msvc-ltcg.log").read_text(), searched_only)[0], [])

    def test_ltcg_diagnostic_path_with_spaces_and_absolute_ambiguity(self):
        library = self.root / "library with spaces/demo.lib"
        library.parent.mkdir()
        library.write_bytes(b"selected archive")
        evidence = self.windows(f' Searching "{library}":\n', [
            {"path": "library with spaces/demo.lib", "sha256": linker.digest(library)}])
        self.assertEqual(evidence["archives"][0]["candidatePath"], "library with spaces/demo.lib")
        selected, _ = linker.parse_msvc(
            " Searching C:\\first path\\demo.lib:\n Searching D:\\second path\\demo.lib:\n",
            MSVC_MAP)
        self.assertEqual(selected, [])

    def test_lto_synthetic_or_unknown_objects_not_assigned_to_archives(self):
        text = APPLE.format(archive="missing.a").replace(
            "[  0] linker synthesized", "[  0] /build/lto.o")
        text = text.replace("[  1] _live", "[  0] _lto_merged")
        path = self.write("lto.map", text)
        evidence = linker.collect(self.root, "macos-arm64", {"map": path}, [])
        self.assertEqual(evidence["selectedArchives"][0]["members"][0]["liveSymbolCount"], 0)
        self.assertNotIn("_lto_merged", json.dumps(evidence["mapSymbols"]))

    def test_raw_log_hash_covers_bytes_not_decoded_text(self):
        log = self.write("link.log", f" Loaded {self.lib}(live.obj)\n")
        log.write_bytes(b"\xef\xbb\xbf" + log.read_bytes())
        evidence = linker.collect(self.root, "windows-x86_64",
                                  {"map": self.write("p.map", MSVC_MAP), "verbose": log}, [])
        self.assertEqual(evidence["diagnostics"][1]["sha256"],
                         hashlib.sha256(log.read_bytes()).hexdigest())

    def test_bad_windows_map_rejected(self):
        with self.assertRaisesRegex(ValueError, "public symbol table"):
            linker.parse_msvc("", "unrelated build log")

    def test_existing_external_archive_is_hashed_not_hidden(self):
        outside = self.root / "toolchain/runtime.a"
        outside.parent.mkdir()
        outside.write_bytes(b"toolchain fixture")
        # Use a narrower source root, while keeping all fixture files in the repo.
        source = self.root / "source"
        source.mkdir()
        evidence = linker.collect(source, "macos-arm64",
                                  {"map": self.write("external.map", APPLE.format(archive=outside))},
                                  [])
        archive = evidence["selectedArchives"][0]
        self.assertEqual(archive["scope"], "external")
        self.assertEqual(archive["status"], "selected-existing-untracked")
        self.assertEqual(archive["sha256"], linker.digest(outside))
        self.assertNotIn("candidatePath", archive)

    def test_candidate_without_hash_is_not_promoted_as_hash_matched(self):
        evidence = self.windows(f" Loaded {self.lib}(live.obj)\n",
                                [{"path": "lib/demo.lib", "status": "declared"}])
        self.assertNotIn("candidatePath", evidence["archives"][0])
        self.assertEqual(evidence["archives"][0]["sha256"], linker.digest(self.lib))

    def test_windows_missing_verbose_log_has_actionable_error(self):
        with self.assertRaisesRegex(ValueError, "requires verbose diagnostics"):
            linker.collect(self.root, "windows-x86_64",
                           {"map": self.write("p.map", MSVC_MAP)}, [])


if __name__ == "__main__":
    unittest.main()
