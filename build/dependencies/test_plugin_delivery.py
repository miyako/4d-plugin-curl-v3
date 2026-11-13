import unittest

import plugin_relink_delivery as delivery


class PluginDeliveryTests(unittest.TestCase):
    def test_only_omitted_repository_flags_are_removed_without_reordering(self):
        arguments = ["${DRIVER}", "-L${KIT}/project/a", "-lcurl", "-lpsl", "-lsasl2",
                     "-lssl", "-L${KIT}/project/another", "-lcrypto"]
        result, removed = delivery.filtered_arguments(
            arguments, ["libpsl.a"], ["libcurl.a", "libssl.a", "libcrypto.a"])
        self.assertEqual(result, arguments[:3] + arguments[4:])
        self.assertEqual(removed, [{"index": 3, "argument": "-lpsl"}])

    def test_windows_sdk_arguments_and_import_output_are_not_removed(self):
        arguments = ["${DRIVER}", "/LIBPATH:lib\\64", "BCRYPT.lib", "NGTCP2.lib",
                     "libcurl.lib", "/IMPLIB:${OUTPUT}\\cURL.lib"]
        result, _ = delivery.filtered_arguments(
            arguments, ["ngtcp2.lib", "cURL.lib"], ["libcurl.lib"], ["bcrypt.lib"])
        self.assertEqual(result, arguments[:3] + arguments[4:])
        with self.assertRaisesRegex(ValueError, "collides"):
            delivery.filtered_arguments(arguments, ["BCRYPT.LIB"], [], ["bcrypt.lib"])

    def test_selected_archive_requires_consistent_exact_target_hashes(self):
        archive = {"scope": "repository", "candidatePath": "a/libcurl.a", "sha256": "a" * 64}
        evidence = {"linkEvidence": {"arm": {"archives": [archive]},
                                     "intel": {"archives": [dict(archive)]}}}
        self.assertEqual(delivery.selected_archives(evidence), {"project/a/libcurl.a": "a" * 64})
        evidence["linkEvidence"]["intel"]["archives"][0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "conflicting"):
            delivery.selected_archives(evidence)

    def test_selected_paths_cannot_escape_or_be_replaced_by_system_only_scope(self):
        for path in ("../outside.a", "/outside.a", "C:\\outside.lib"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "escapes"):
                delivery.selected_archives({"linkEvidence": {
                    "target": {"archives": [{"scope": "repository",
                                            "candidatePath": path, "sha256": "a" * 64}]}}})
        with self.assertRaisesRegex(ValueError, "selection is required"):
            delivery.selected_archives({"linkEvidence": {"target": {"archives": []}}})


if __name__ == "__main__":
    unittest.main()
