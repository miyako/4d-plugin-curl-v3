import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import provider_materials
from provenance import archive_hashes, digest


class ProviderMaterialsTests(unittest.TestCase):
    def test_compiler_source_and_member_binding_survive_manifest_rehashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary)
            root = install / "build-materials"
            for name in ("source", "objects", "compiler-calls"):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / "source/input.S").write_bytes(b"generated assembly")
            object_file = root / "objects/object"
            object_file.write_bytes(b"compiled object")
            data = object_file.read_bytes()
            header = (f"{'input.o/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n").encode()
            (install / "lib.a").write_bytes(b"!<arch>\n" + header + data + b"\n" * (len(data) % 2))
            sha = hashlib.sha256(data).hexdigest()
            call_path = root / "compiler-calls/call.json"
            call = {"returnCode": 0, "compiler": "/actual/cc", "inputs": [
                {"path": "/original/input.S", "sha256": digest(root / "source/input.S")}],
                "object": {"path": "/original/input.o", "sha256": sha}}
            call_path.write_text(json.dumps(call))
            proof = {
                "schemaVersion": 1, "sourceCommit": "a" * 40, "originalSource": "/original",
                "toolchain": {"cc": {"path": "/actual/cc"}},
                "sources": archive_hashes(root / "source", ["input.S"]),
                "archives": [{"archive": "lib.a", "objects": [
                    {"member": "input.o", "sha256": sha, "objectFile": "objects/object",
                     "compilerRecord": "compiler-calls/call.json"}]}],
            }
            record = {"source_commit": "a" * 40, "archives": [{"path": "lib.a"}],
                      "buildMaterials": proof}
            paths = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
            proof["files"] = archive_hashes(root, paths)
            provider_materials.inspect(install, record)
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
