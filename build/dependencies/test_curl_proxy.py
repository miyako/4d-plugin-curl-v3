from contextlib import closing
import http.client
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import plugin_relink_delivery as delivery
import probe_curl_proxy as proxy
from provenance import write_json


class ProxyFixtureTests(unittest.TestCase):
    def test_real_direct_and_forwarded_payloads_and_pac(self):
        with proxy.fixture("manual") as fixture:
            target = urlsplit(fixture["url"])
            for endpoint, path, headers in (
                    (("127.0.0.1", target.port), target.path, {"Host": target.netloc}),
                    (("127.0.0.1", fixture["proxyPort"]), fixture["url"], {})):
                with closing(http.client.HTTPConnection(*endpoint, timeout=5)) as connection:
                    connection.request("GET", path, headers=headers)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), proxy.PAYLOAD)
            pac = urlsplit(fixture["pac"])
            with closing(http.client.HTTPConnection(pac.hostname, pac.port, timeout=5)) as connection:
                connection.request("GET", pac.path)
                self.assertEqual(connection.getresponse().read(), fixture["pacSource"])
        self.assertEqual([r["forwarded"] for r in fixture["events"]["origin"]], [False, True])
        self.assertEqual(fixture["events"]["proxy"], [{"url": fixture["url"]}])

    def test_proxy_refuses_any_other_destination(self):
        with self.assertRaisesRegex(RuntimeError, "request failed"):
            with proxy.fixture("manual") as fixture:
                with closing(http.client.HTTPConnection(
                        "127.0.0.1", fixture["proxyPort"], timeout=5)) as client:
                    client.request("GET", "http://127.0.0.1:1/private")
                    with self.assertRaises(http.client.RemoteDisconnected):
                        client.getresponse()
                self.assertEqual(fixture["events"]["origin"], [])

    def test_route_reader_rejects_success_metadata_without_observed_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "candidate").mkdir()
            case = root / "candidate/bypass"
            case.with_suffix(".response").write_bytes(proxy.PAYLOAD)
            write_json(case.with_suffix(".stdout"), {
                "curlCode": 0, "httpStatus": 200, "proxies": ["direct://"]})
            write_json(case.with_suffix(".exit.json"), 0)
            case.with_suffix(".pac").write_bytes(proxy.pac_bytes(12345, 12346))
            write_json(case.with_suffix(".server.json"), {
                "origin": [{"path": "/payload", "host": "bypass.invalid:12345", "forwarded": True}],
                "proxy": [], "pac": []})
            item = {"case": "bypass", "exitCode": 0, "url": "http://bypass.invalid:12345/payload",
                    "proxy": "http://127.0.0.1:12346", "route": "direct",
                    "responseSha256": proxy.digest(case.with_suffix(".response"))}
            with self.assertRaisesRegex(ValueError, "actual curl route"):
                proxy.inspect_case(root, "windows-x86_64", "candidate", item)


class ProbeBindingTests(unittest.TestCase):
    def test_windows_paths_and_selected_hash_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            kit = Path(temporary)
            write_json(kit / delivery.PORTABLE["windows-x86_64"], {
                "originalBinarySha256": "b" * 64})
            selected = {"target": "windows-x86_64", "deliveryManifestSha256": "d" * 64,
                        "selectedArchives": {"project/lib/64/proxy.lib": "a" * 64}}
            archives = [{"path": "C:/candidate/lib/64/proxy.lib", "sha256": "a" * 64}]
            with patch.object(delivery, "inspect", return_value=selected):
                result = delivery.bind_probe_inputs(
                    kit, "windows-x86_64", r"C:\candidate", archives)
                self.assertEqual(result["inputs"], [
                    {"path": "project/lib/64/proxy.lib", "sha256": "a" * 64}])
                with self.assertRaisesRegex(ValueError, "differ"):
                    delivery.bind_probe_inputs(kit, "macos-arm64", "C:/candidate", archives)
                with self.assertRaisesRegex(ValueError, "selected plugin"):
                    delivery.bind_probe_inputs(kit, "windows-x86_64", "C:/candidate", [
                        {**archives[0], "sha256": "c" * 64}])
                with self.assertRaises(ValueError):
                    delivery.bind_probe_inputs(kit, "windows-x86_64", "C:/candidate-other", archives)


if __name__ == "__main__":
    unittest.main()
