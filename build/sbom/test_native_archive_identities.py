import copy
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import archives
import native_archive_identities as native
from native_archive_objects import Object, members, region


ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "a/libiconv.a": ("libiconv", "1.16"),
    "a/libmodman.a": ("libmodman", None),
    "a/libnghttp2.a": ("nghttp2", "1.70.0"),
    "a/libnghttp3.a": ("nghttp3", "1.15.0"),
    "a/libproxy.a": ("libproxy", None),
    "lib/64/iconv.lib": ("libiconv", "1.18"),
    "lib/64/modman.lib": ("libmodman", None),
    "lib/64/nghttp2.lib": ("nghttp2", "1.70.0"),
    "lib/64/libproxy.lib": ("libproxy", None),
}


def slices(path):
    return archives.archive_targets(Path(path), (ROOT / path).read_bytes())


class ReviewedArchiveIdentityTests(unittest.TestCase):
    def test_all_selected_bytes_have_independent_target_evidence(self):
        reviewed = set()
        for path, expected in EXPECTED.items():
            for target, data in slices(path).items():
                with self.subTest(path=path, target=target):
                    identity, = archives.identities(data)
                    self.assertEqual((identity["name"], identity["version"]), expected)
                    evidence = identity["evidence"]
                    self.assertEqual(evidence["sliceSha256"], native.sha256(data))
                    reviewed.add(evidence["sliceSha256"])
                    self.assertEqual(native.REVIEWED[evidence["sliceSha256"]][1], target)
                    member, = [item for item in members(data) if item[0] == evidence["member"]]
                    self.assertEqual(member[1], evidence["memberOffset"])
                    self.assertEqual(native.sha256(member[2]), evidence["memberSha256"])
                    obj = Object(member[2])
                    for definition in evidence["definitions"]:
                        self.assertEqual(definition, obj.definition(definition["symbol"]))
                    self.assertIsNone(identity["origin"])
                    self.assertIsNone(identity["license"])
                    self.assertIsNone(identity["purl"])
                    self.assertIn("origin and source revision unknown",
                                  identity["sourceMetadata"]["relationship"])
                    if expected[1] is None:
                        self.assertEqual(identity["evidenceType"], "archive-defined-symbols")
                        self.assertIn("unknown", identity["versionStatus"])
                        self.assertNotIn("versionData", evidence)
                    else:
                        value = evidence["versionData"]
                        raw = bytes.fromhex(value["hex"])
                        self.assertEqual(region(member[2], value["objectOffset"], len(raw)), raw)
                        if identity["name"].startswith("nghttp"):
                            self.assertEqual(value["relocatedString"], expected[1])
        self.assertEqual(reviewed, set(native.REVIEWED))

    def test_unreviewed_bytes_and_bare_strings_never_gain_a_reviewed_identity(self):
        self.assertEqual(archives.identities(
            b"!<arch>\n1.70.0\0nghttp2_version\0_libiconv_version\0"
            b"px_proxy_factory_new\0libmodman\0/usr/local/lib/libproxy/0.4.17/modules"), [])
        for path in EXPECTED:
            for data in slices(path).values():
                with self.subTest(path=path):
                    self.assertEqual(native.identities(data + b"\0"), [])

    def test_reviewed_version_and_unsupported_identity_are_rejected(self):
        data = slices("a/libnghttp2.a")["macos-arm64"]
        hash_ = native.sha256(data)
        name, target, member, _ = native.REVIEWED[hash_]
        for record, error in (
            ((name, target, member, "1.69.0"), "version disagreement"),
            (("unsupported", target, member, None), "Unsupported reviewed archive identity"),
        ):
            with self.subTest(record=record), patch.dict(native.REVIEWED, {hash_: record}):
                with self.assertRaisesRegex(ValueError, error):
                    native.identities(data)

    def test_nghttp_version_must_match_relocated_string_not_an_incidental_number(self):
        data = slices("a/libnghttp2.a")["macos-arm64"]
        member = next(payload for name, _, payload in members(data)
                      if name == "nghttp2_version.c.o")
        obj = Object(member)
        offset, _ = obj.value("_version", 8)
        bad = bytearray(member)
        struct.pack_into("<I", bad, offset + 4, 0x014500)
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            native.inspect_member("nghttp2", "macos-arm64", Object(bytes(bad)))
        # A missing pointer relocation must not fall back to scanning 1.70.0.
        bad = bytearray(member)
        section, _, _ = obj.location(obj.symbols["_version"])
        for index in range(section["nreloc"]):
            position = section["reloc"] + index * 8
            if struct.unpack_from("<I", bad, position)[0] == 8:
                struct.pack_into("<I", bad, position, 0x7FFFFFFF)
        with self.assertRaisesRegex(ValueError, "one version string relocation"):
            native.inspect_member("nghttp2", "macos-arm64", Object(bytes(bad)))

    def test_undefined_names_are_not_symbol_identity_evidence(self):
        data = slices("a/libproxy.a")["macos-arm64"]
        member = next(payload for name, _, payload in members(data) if name == "proxy.o")
        obj = Object(member)
        del obj.symbols["_px_proxy_factory_new"]
        with self.assertRaises(KeyError):
            native.inspect_member("libproxy", "macos-arm64", obj)

    def test_manifest_rejects_forged_version_name_and_slice_hash(self):
        path = "a/libnghttp2.a"
        data = (ROOT / path).read_bytes()
        entry = {
            "path": path, "sha256": native.sha256(data),
            "targets": {target: {"identities": archives.identities(part)}
                        for target, part in archives.archive_targets(Path(path), data).items()},
        }
        for field, value in (("version", "1.69.0"), ("name", "unsupported")):
            bad = copy.deepcopy(entry)
            bad["targets"]["macos-arm64"]["identities"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "identity mismatch"):
                archives.verify_manifest({"archives": [bad]}, ROOT)
        bad = copy.deepcopy(entry)
        bad["targets"]["macos-arm64"]["identities"][0]["evidence"]["sliceSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            archives.verify_manifest({"archives": [bad]}, ROOT)

    def test_bounded_reader_rejects_truncated_or_unsupported_objects(self):
        for data in (b"", b"\xcf\xfa\xed\xfe", b"\x64\x86", b"unknown"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                Object(data)
        with self.assertRaises(ValueError):
            list(members(b"!<arch>\ntruncated"))


if __name__ == "__main__":
    unittest.main()
