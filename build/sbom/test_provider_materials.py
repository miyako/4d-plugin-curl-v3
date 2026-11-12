import copy
import hashlib
import json
import struct
from pathlib import Path
import tempfile
import unittest

import provider_materials
from provenance import archive_hashes, digest


class ProviderMaterialsTests(unittest.TestCase):
    def test_native_deployment_and_static_crt_are_measured_not_just_declared(self):
        call = {"inputs": [{"path": "/source/input.c"}], "arguments": ["-c", "-MT"]}
        provider_materials.compile_profile(call, "windows-x86_64")
        call["arguments"] = ["-c", "-MD"]
        with self.assertRaisesRegex(ValueError, "static CRT"):
            provider_materials.compile_profile(call, "windows-x86_64")
        for target, cpu, minimum in (("macos-arm64", 0x0100000C, 11 << 16),
                                     ("macos-x86_64", 0x01000007, (10 << 16) | (13 << 8))):
            call["arguments"] = ["-arch", target.removeprefix("macos-"),
                                 "-mmacosx-version-min=10.13", "-c"]
            provider_materials.compile_profile(call, target)
            call["arguments"][-2] = "-mmacosx-version-min=26.0"
            with self.assertRaisesRegex(ValueError, "deployment profile"):
                provider_materials.compile_profile(call, target)
            header = struct.pack("<8I", 0xFEEDFACF, cpu, 0, 1, 1, 24, 0, 0)
            provider_materials.object_profile(
                header + struct.pack("<6I", 0x32, 24, 1, minimum, 26 << 16, 0), target)
            with self.assertRaisesRegex(ValueError, "exceeds supported"):
                provider_materials.object_profile(
                    header + struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0), target)

    def test_compiler_source_and_member_binding_survive_manifest_rehashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary)
            root = install / "build-materials"
            for name in ("source", "objects", "compiler-calls"):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / "source/input.S").write_bytes(b"generated assembly")
            (root / "source/LICENSE").write_bytes(b"Synthetic license fixture")
            object_file = root / "objects/object"
            object_file.write_bytes(b"compiled object")
            data = object_file.read_bytes()
            header = (f"{'input.o/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n").encode()
            (install / "lib.a").write_bytes(b"!<arch>\n" + header + data + b"\n" * (len(data) % 2))
            sha = hashlib.sha256(data).hexdigest()
            call_path = root / "compiler-calls/call.json"
            call = {"returnCode": 0, "compiler": "C:\\actual\\cc.exe", "inputs": [
                {"path": "/original/input.S", "sha256": digest(root / "source/input.S")}],
                "object": {"path": "/original/input.o", "sha256": sha}}
            call_path.write_text(json.dumps(call))
            proof = {
                "schemaVersion": 1, "sourceCommit": "a" * 40, "originalSource": "/original",
                "toolchain": {"cc": {"path": "C:/actual/cc.exe"}},
                "sources": archive_hashes(root / "source", ["LICENSE", "input.S"]),
                "archives": [{"archive": "lib.a", "objects": [
                    {"member": "input.o", "sha256": sha, "objectFile": "objects/object",
                     "compilerRecord": "compiler-calls/call.json"}]}],
            }
            record = {"source_commit": "a" * 40, "archives": archive_hashes(install, ["lib.a"]),
                      "licenseFile": "LICENSE", "licenseFileSha256": digest(root / "source/LICENSE"),
                      "buildMaterials": proof}
            paths = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
            proof["files"] = archive_hashes(root, paths)
            provider_materials.inspect(install, record)
            original = install / "original.json"
            original.write_text(json.dumps(record))
            summary = provider_materials.compact_record(original)
            self.assertNotIn("buildMaterials", summary)
            self.assertEqual(summary["buildMaterialEvidence"]["originalRecordSha256"], digest(original))
            aggregate = install / "aggregate.json"
            aggregate.write_text(json.dumps({"source_builds": [summary]}))
            self.assertEqual(provider_materials.inventory_record(aggregate, [original]),
                             {"source_builds": [summary]})
            with self.assertRaisesRegex(ValueError, "matching original record"):
                provider_materials.inventory_record(aggregate)
            changed_summary = copy.deepcopy(summary)
            changed_summary["buildMaterialEvidence"]["archives"][0]["objectMembers"] += 1
            aggregate.write_text(json.dumps({"source_builds": [changed_summary]}))
            with self.assertRaisesRegex(ValueError, "differs from its inspected original"):
                provider_materials.inventory_record(aggregate, [original])
            (root / "source/input.S").write_bytes(b"tampered compiled source")
            with self.assertRaisesRegex(ValueError, "changed"):
                provider_materials.compact_record(original)
            (root / "source/input.S").write_bytes(b"generated assembly")
            changed = copy.deepcopy(record)
            changed["licenseFileSha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "identity source"):
                provider_materials.inspect(install, changed)
            raw = b"../source/input.S"
            link = root / "link-text"
            link.write_bytes(raw)
            blob = b"blob " + str(len(raw)).encode() + b"\0" + raw
            proof["sourceLinks"] = [{"path": "research/input.S", "target": raw.decode(),
                                     "gitObject": hashlib.sha1(blob).hexdigest(),
                                     "textFile": "link-text"}]
            paths.append("link-text")
            proof["files"] = archive_hashes(root, paths)
            provider_materials.inspect(install, record)
            link.write_bytes(b"changed link")
            proof["files"] = archive_hashes(root, paths)
            with self.assertRaisesRegex(ValueError, "symlink text"):
                provider_materials.inspect(install, record)
            link.write_bytes(raw)
            for field, value in (("returnCode", 1), ("compiler", "/unrecorded/compiler"), ("inputs", [
                    {"path": "/original/input.S", "sha256": "0" * 64}]),
                    ("object", {"path": "/original/other.o", "sha256": sha})):
                changed = copy.deepcopy(call)
                changed[field] = value
                call_path.write_text(json.dumps(changed))
                proof["files"] = archive_hashes(root, paths)
                with self.subTest(field=field), self.assertRaises(ValueError):
                    provider_materials.inspect(install, record)
            call_path.write_text(json.dumps(call))
            object_file.write_bytes(b"not the compiler output")
            proof["files"] = archive_hashes(root, paths)
            with self.assertRaises(ValueError):
                provider_materials.inspect(install, record)


if __name__ == "__main__":
    unittest.main()
