import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest

import provenance


def universal(arm, x64):
    offset = 48
    return (
        struct.pack(">II", 0xCAFEBABE, 2)
        + struct.pack(">IIIII", 0x0100000C, 0, offset, len(arm), 0)
        + struct.pack(">IIIII", 0x01000007, 0, offset + len(arm), len(x64), 0)
        + arm + x64
    )


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="provenance-test-", dir=Path(__file__).resolve().parent
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Offline test")
        self.git("config", "user.email", "offline@example.invalid")
        self.version = self.source / "VERSION.dat"
        self.version.write_text(
            "MAJOR=3\nMINOR=5\nPATCH=8\nPRE_RELEASE_TAG=\nBUILD_METADATA=\n",
            encoding="utf-8",
        )
        self.license = self.source / "LICENSE.txt"
        self.license.write_text("Synthetic offline Apache-2.0 license fixture\n", encoding="utf-8")
        self.commit()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.source), *args], text=True,
            stderr=subprocess.PIPE,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        ).strip()

    def commit(self):
        self.git("add", "VERSION.dat", "LICENSE.txt")
        self.git("commit", "--quiet", "-m", "Synthetic source")

    def configdata(self, target, arguments):
        config = {"target": provenance.PLATFORMS[target], "perlargv": arguments}
        (self.source / "configdata.pm").write_text(
            "package configdata; use JSON::PP;\n"
            "our %config = %{decode_json(q!" + json.dumps(config) + "!)};\n1;\n",
            encoding="utf-8",
        )

    def build(self, target="windows-x86_64"):
        install = self.root / target
        arguments = [provenance.PLATFORMS[target], "no-shared", "no-tests",
                     "--prefix=" + str(install)]
        if target.startswith("macos"):
            arguments.append("-mmacosx-version-min=10.13")
        else:
            arguments.extend(["-MT", "--release"])
        for name in provenance.expected_archives(target):
            archive = install / name
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes((target + name).encode())
        self.configdata(target, arguments)
        record = provenance.source_record(self.source, install, target, arguments)
        return install, arguments, record

    def vendor_windows(self, install):
        vendor = self.root / "vendor"
        for source in (install / "lib").iterdir():
            path = vendor / "lib/64" / source.name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.read_bytes())
        return vendor

    def test_build_cache_verify_and_windows_combine(self):
        install, arguments, record = self.build()
        self.assertEqual(record["version"], "3.5.8")
        self.assertEqual(record["source_commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(record["license"], "Apache-2.0")
        self.assertEqual(record["licenseFile"], "LICENSE.txt")
        self.assertEqual(record["licenseFileSha256"], provenance.digest(self.license))
        self.assertEqual(record["platform"], "VC-WIN64A")
        self.assertEqual(record["configure_arguments"], arguments)
        # Cache verification does not require or execute generated configdata.pm.
        (self.source / "configdata.pm").unlink()
        self.assertEqual(
            provenance.verify(self.source, install, "windows-x86_64", arguments), record
        )
        vendor = self.vendor_windows(install)
        result = provenance.combine([install / provenance.RECORD], vendor, "windows-x86_64")
        self.assertEqual(result["source_builds"], [record])
        self.assertEqual(result["licenseFileSha256"], provenance.digest(self.license))
        self.assertEqual(result["archives"][0]["path"], "lib/64/libcrypto.lib")
        self.assertEqual(json.loads((vendor / "openssl-provenance.json").read_text()), result)

    def test_actual_configuration_must_match_requested(self):
        install, arguments, _ = self.build()
        with self.assertRaisesRegex(ValueError, "Actual OpenSSL Configure"):
            provenance.source_record(
                self.source, install, "windows-x86_64", arguments + ["no-asm"]
            )

    def test_missing_legacy_cache_record_is_not_regenerated(self):
        install, arguments, _ = self.build()
        record_path = install / provenance.RECORD
        record_path.unlink()
        with self.assertRaises(FileNotFoundError):
            provenance.verify(self.source, install, "windows-x86_64", arguments)
        self.assertFalse(record_path.exists())

    def test_changed_archive_is_rejected_by_verify_and_combine(self):
        install, arguments, _ = self.build()
        vendor = self.vendor_windows(install)
        (install / "lib/libcrypto.lib").write_bytes(b"stale cached archive")
        with self.assertRaisesRegex(ValueError, "archives do not match"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)
        with self.assertRaisesRegex(ValueError, "archives do not match"):
            provenance.combine([install / provenance.RECORD], vendor, "windows-x86_64")

    def test_changed_source_commit_never_assigned_to_cache(self):
        install, arguments, _ = self.build()
        path = install / provenance.RECORD
        original = path.read_bytes()
        self.version.write_text(self.version.read_text() + "# source change\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "source_commit"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)
        self.assertEqual(path.read_bytes(), original)

    def test_dirty_source_is_rejected(self):
        install, arguments, _ = self.build()
        self.version.write_text(self.version.read_text().replace("PATCH=8", "PATCH=9"))
        with self.assertRaisesRegex(ValueError, "source must be clean"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)

    def test_changed_configuration_is_rejected(self):
        install, arguments, _ = self.build()
        for changed in (arguments + ["no-asm"],
                        [value.replace("10.13", "11.0") for value in arguments] + ["-O3"]):
            with self.assertRaisesRegex(ValueError, "configure_arguments"):
                provenance.verify(self.source, install, "windows-x86_64", changed)
        with self.assertRaisesRegex(ValueError, "platform"):
            provenance.verify(self.source, install, "macos-arm64", arguments)

    def test_changed_version_file_hash_is_rejected(self):
        install, arguments, record = self.build()
        record["version_file_sha256"] = "0" * 64
        provenance.write_json(install / provenance.RECORD, record)
        with self.assertRaisesRegex(ValueError, "version_file_sha256"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)

    def test_changed_macos_deployment_target_is_rejected(self):
        install, arguments, _ = self.build("macos-arm64")
        changed = [value.replace("10.13", "11.0") for value in arguments]
        with self.assertRaisesRegex(ValueError, "configure_arguments"):
            provenance.verify(self.source, install, "macos-arm64", changed)

    def test_changed_license_hash_is_rejected(self):
        install, arguments, record = self.build()
        record["licenseFileSha256"] = "0" * 64
        provenance.write_json(install / provenance.RECORD, record)
        with self.assertRaisesRegex(ValueError, "licenseFileSha256"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)

    def test_legacy_record_without_license_hash_is_rejected(self):
        install, arguments, record = self.build()
        del record["licenseFileSha256"]
        provenance.write_json(install / provenance.RECORD, record)
        with self.assertRaisesRegex(ValueError, "source identity"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)

    def test_dirty_license_is_rejected(self):
        install, arguments, _ = self.build()
        self.license.write_text("changed source license\n")
        with self.assertRaisesRegex(ValueError, "source must be clean"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)

    def test_changed_recorded_version_is_rejected(self):
        install, arguments, record = self.build()
        record["version"] = "3.5.7"
        provenance.write_json(install / provenance.RECORD, record)
        with self.assertRaisesRegex(ValueError, "version"):
            provenance.verify(self.source, install, "windows-x86_64", arguments)

    def test_missing_installed_archive_is_rejected(self):
        install, arguments, _ = self.build()
        (install / "lib/libssl.lib").unlink()
        with self.assertRaises(FileNotFoundError):
            provenance.verify(self.source, install, "windows-x86_64", arguments)

    def test_wrong_copied_archive_is_rejected(self):
        install, _, _ = self.build()
        vendor = self.vendor_windows(install)
        (vendor / "lib/64/libssl.lib").write_bytes(b"wrong vendor input")
        with self.assertRaisesRegex(ValueError, "Copied OpenSSL archive"):
            provenance.combine([install / provenance.RECORD], vendor, "windows-x86_64")

    def test_macos_records_preserve_per_arch_and_merged_hashes(self):
        arm, _, arm_record = self.build("macos-arm64")
        x64, _, x64_record = self.build("macos-x86_64")
        vendor = self.root / "vendor"
        (vendor / "a").mkdir(parents=True)
        for name in ("libssl.a", "libcrypto.a"):
            (vendor / "a" / name).write_bytes(
                universal((arm / "lib" / name).read_bytes(), (x64 / "lib" / name).read_bytes())
            )
        result = provenance.combine(
            [x64 / provenance.RECORD, arm / provenance.RECORD], vendor, "macos-universal"
        )
        self.assertEqual(result["source_builds"], [arm_record, x64_record])
        self.assertEqual(result["archives"][0]["sha256"], provenance.digest(vendor / "a/libcrypto.a"))
        with self.assertRaisesRegex(ValueError, "targets"):
            provenance.combine([arm / provenance.RECORD], vendor, "macos-universal")
        with self.assertRaisesRegex(ValueError, "targets"):
            provenance.combine(
                [arm / provenance.RECORD, arm / provenance.RECORD], vendor, "macos-universal"
            )
        (vendor / "a/libssl.a").write_bytes(universal(
            b"unrelated arm64 archive", (x64 / "lib/libssl.a").read_bytes()
        ))
        with self.assertRaisesRegex(ValueError, "slice does not match"):
            provenance.combine(
                [arm / provenance.RECORD, x64 / provenance.RECORD], vendor, "macos-universal"
            )

    def test_universal_slice_alignment_padding_and_wrong_architecture(self):
        arm, _, _ = self.build("macos-arm64")
        x64, _, _ = self.build("macos-x86_64")
        path = self.root / "universal.a"
        sources = {0x0100000C: arm / "lib/libssl.a", 0x01000007: x64 / "lib/libssl.a"}
        path.write_bytes(universal(
            sources[0x0100000C].read_bytes() + b"\0\0", sources[0x01000007].read_bytes()
        ))
        provenance.verify_universal_archive(path, sources)
        data = bytearray(path.read_bytes())
        struct.pack_into(">I", data, 28, 0x0100000C)
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "invalid architecture"):
            provenance.verify_universal_archive(path, sources)

    def test_mixed_source_identities_are_rejected(self):
        arm, _, _ = self.build("macos-arm64")
        self.version.write_text(self.version.read_text().replace("PATCH=8", "PATCH=9"))
        self.commit()
        x64, _, _ = self.build("macos-x86_64")
        with self.assertRaisesRegex(ValueError, "different identities"):
            provenance.combine(
                [arm / provenance.RECORD, x64 / provenance.RECORD], self.root, "macos-universal"
            )

    def test_prerelease_and_build_metadata_from_version_dat(self):
        self.version.write_text(
            "MAJOR=4\nMINOR=0\nPATCH=0\nPRE_RELEASE_TAG=alpha1\nBUILD_METADATA=dev\n"
        )
        self.commit()
        _, _, record = self.build()
        self.assertEqual(record["version"], "4.0.0-alpha1+dev")

    def test_invalid_source_version_is_rejected(self):
        self.version.write_text("MAJOR=3\nMINOR=5\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "VERSION.dat"):
            self.build()

    def test_legacy_license_is_not_mislabeled_apache(self):
        self.version.write_text("MAJOR=1\nMINOR=1\nPATCH=1\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "Apache-2.0"):
            self.build()

    def test_cli_writes_and_verifies_and_fails_closed(self):
        install, arguments, _ = self.build()
        common = ["--source", str(self.source), "--install", str(install),
                  "--target", "windows-x86_64", "--", *arguments]
        provenance.main(["source-record", *common])
        provenance.main(["verify", *common])
        vendor = self.vendor_windows(install)
        provenance.main(["combine", "--record", str(install / provenance.RECORD),
                         "--vendor", str(vendor), "--target", "windows-x86_64"])
        (install / provenance.RECORD).unlink()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            provenance.main(["verify", *common])
        self.assertEqual(raised.exception.code, 1)

    def test_archive_path_traversal_is_rejected(self):
        for path in ("../outside.a", "/absolute.a", "C:/outside.lib", "lib\\outside.lib"):
            with self.assertRaisesRegex(ValueError, "relative POSIX paths"):
                provenance.archive_hashes(self.root, [path])


if __name__ == "__main__":
    unittest.main()
