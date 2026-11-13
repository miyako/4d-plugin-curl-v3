import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

import external_windows as external
import generate
import validate


def coff(section=b".text", machine=0x8664):
    header = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 0, 0)
    table = struct.pack("<8sIIIIIIHHI", section, 0, 0, 4, 60, 0, 0, 0, 0,
                        0x60000020 if section == b".text" else 0xC0000040)
    return header + table + b"abcd"


def imported():
    payload = b"Sleep\0KERNEL32.dll\0"
    return struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x8664, 0, len(payload), 0, 0) + payload


def archive(name, payload):
    header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0:<8}{len(payload):<10}`\n".encode()
    return b"!<arch>\n" + header + payload + (b"\n" if len(payload) % 2 else b"")


class ExternalTests(unittest.TestCase):
    def test_native_code_imports_descriptors_and_invalid_architecture(self):
        self.assertEqual(external.object_kind(coff()), "native-object")
        self.assertEqual(external.object_kind(imported()), "import-only")
        self.assertEqual(external.object_kind(coff(b".idata$2")), "import-only")
        for payload in (coff(machine=0x14C), imported()[:-1], coff()[:35]):
            with self.assertRaises(ValueError):
                external.object_kind(payload)

    def test_selected_members_must_exist_not_filename_only(self):
        data = archive("code.obj", coff())
        with self.assertRaisesRegex(ValueError, "not found"):
            external.inspect_members(data, ["missing.obj"])
        self.assertEqual(external.inspect_members(data, ["code.obj"])[0]["classification"],
                         "native-object")

    def fixture(self, root):
        root = root.resolve()
        lib = root / "vc/lib/x64/libcmt.lib"
        lib.parent.mkdir(parents=True)
        lib.write_bytes(archive("startup.obj", coff()))
        binary = root / "plugin"; binary.write_bytes(b"actual binary fixture")
        properties = {"LibraryPath": str(lib.parent), "VCToolsInstallDir": str(root / "vc"),
                      "VCToolsVersion": "14.44.35207", "WindowsSdkDir": str(root / "sdk")}
        before = external.snapshot(properties, root / "project")
        trace = {"target": "windows-x86_64", "archives": [{
            "scope": "external", "resolvedPath": str(lib), "sha256": external.digest(lib.read_bytes()),
            "selectedMembers": ["startup.obj"],
        }]}
        evidence = external.collect(trace, before, binary)
        record = {"binarySha256": external.digest(binary.read_bytes()),
                  "externalArchiveEvidence": evidence, "linkEvidence": {"windows-x86_64": trace}}
        return lib, binary, before, trace, record

    def test_binary_selection_snapshot_and_identity_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            lib, binary, before, trace, record = self.fixture(Path(name))
            packages, coverage = external.dependencies(record, "windows-x86_64")
            self.assertEqual(coverage["namedStaticLibraryArchives"], 1)
            self.assertNotIn("version", packages[0])
            for mutate in (
                    lambda r: r.update(binarySha256="different"),
                    lambda r: r["externalArchiveEvidence"]["archives"].clear(),
                    lambda r: r["externalArchiveEvidence"]["archives"][0].update(sha256="different"),
                    lambda r: r["externalArchiveEvidence"]["archives"][0]["package"].update(name="invented"),
                    lambda r: r["externalArchiveEvidence"]["archives"][0].update(classification="import-only")):
                changed = copy.deepcopy(record); mutate(changed)
                with self.assertRaises(ValueError):
                    external.dependencies(changed, "windows-x86_64")
            lib.write_bytes(archive("startup.obj", coff() + b"changed"))
            with self.assertRaisesRegex(ValueError, "changed"):
                external.collect(trace, before, binary)

    def test_standard_packages_and_edges_without_invented_versions_or_licenses(self):
        with tempfile.TemporaryDirectory() as name:
            _, _, _, _, record = self.fixture(Path(name))
            packages, coverage = external.dependencies(record, "windows-x86_64")
            inventory = {"name": "cURL", "version": "1.0.0", "supplier": "supplier",
                         "artifact": {"name": "plugin.zip", "sha256": "0" * 64}, "limitations": "",
                         "created": "2026-11-14T00:00:00Z", "targets": [{
                             "id": "windows-x86_64", "analyzedSha256": "1" * 64,
                             "dependencies": [], "externalDependencies": packages,
                             "externalArchiveCoverage": coverage}]}
            cdx, spdx = generate.cyclonedx(inventory), generate.spdx(inventory)
            component = next(c for c in cdx["components"] if c["name"] == packages[0]["name"])
            package = next(p for p in spdx["packages"] if p["name"] == packages[0]["name"])
            self.assertNotIn("version", component)
            self.assertNotIn("hashes", component)
            self.assertEqual(package["licenseDeclared"], "NOASSERTION")
            self.assertEqual(cdx["dependencies"][0]["dependsOn"], [component["bom-ref"]])
            self.assertTrue(any(r["relationshipType"] == "DEPENDS_ON"
                                and r["relatedSpdxElement"] == package["SPDXID"]
                                for r in spdx["relationships"]))
            self.assertEqual(json.loads(component["description"])["externalSelectedArchives"][0]["sha256"],
                             record["externalArchiveEvidence"]["archives"][0]["sha256"])
            schemas, registry = validate.load_schemas(Path(name) / "schemas")
            for filename, document in (("bom-1.6.schema.json", cdx), ("spdx-2.3.schema.json", spdx)):
                validate.Draft7Validator(
                    schemas[filename], registry=registry,
                    format_checker=validate.Draft7Validator.FORMAT_CHECKER).validate(document)
