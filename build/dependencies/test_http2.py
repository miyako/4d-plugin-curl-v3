import gzip
import importlib.util
import socket
from pathlib import Path
import tempfile
import unittest

import http2_fixture
import probe_curl_http2 as probe
from provenance import digest


class Http2InputTests(unittest.TestCase):
    def test_explicit_compiler_header_root_is_verified_without_changing_original_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            headers = root / "retained-headers"
            for base, content in ((project, b"original interface"), (headers, b"candidate interface")):
                path = base / "include/curl/curl.h"
                path.parent.mkdir(parents=True)
                path.write_bytes(content)
            compiler, archive = root / "compiler", root / "archive.a"
            compiler.write_bytes(b"recorded compiler input")
            archive.write_bytes(b"recorded archive input")
            model = {"compiler": {"path": str(compiler), "sha256": digest(compiler)},
                     "archives": [{"path": str(archive), "sha256": digest(archive)}],
                     "interface": [{"path": "include/curl/curl.h",
                                    "sha256": digest(project / "include/curl/curl.h")}]}
            probe.transfers.verify_inputs(project, model)
            model["interfaceProject"] = str(headers)
            with self.assertRaises(ValueError):
                probe.transfers.verify_inputs(project, model)
            model["interface"][0]["sha256"] = digest(headers / "include/curl/curl.h")
            probe.transfers.verify_inputs(project, model)
            (headers / "include/curl/curl.h").write_bytes(b"changed after compilation")
            with self.assertRaises(ValueError):
                probe.transfers.verify_inputs(project, model)

    def test_unpinned_header_source_is_rejected_before_any_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "different-source.tar.xz"
            archive.write_bytes(b"not the verified curl source")
            with self.assertRaisesRegex(ValueError, "source pin"):
                probe.copy_public_interface(archive, root / "headers")
            self.assertFalse((root / "headers").exists())


@unittest.skipUnless(importlib.util.find_spec("h2"), "Install the reviewed HTTP/2 fixture lock")
class Http2FixtureTests(unittest.TestCase):
    def test_decoded_requests_large_flow_control_and_compressed_response(self):
        import h2.connection
        import h2.events

        payload = bytes(range(256)) * 1027
        for upload, compressed in ((False, False), (True, True)):
            with self.subTest(upload=upload), http2_fixture.serve(
                    payload, compressed=compressed) as (port, report):
                client = h2.connection.H2Connection()
                client.initiate_connection()
                client.send_headers(1, [
                    (":method", "POST" if upload else "GET"), (":scheme", "http"),
                    (":authority", "fixture.invalid"), (":path", "/fixture")], end_stream=not upload)
                pending = 0 if upload else len(payload)
                received = bytearray()
                done = False
                with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                    while not done:
                        while upload and pending < len(payload):
                            size = min(client.local_flow_control_window(1),
                                       client.max_outbound_frame_size, len(payload) - pending)
                            if size <= 0:
                                break
                            client.send_data(1, payload[pending:pending + size],
                                             end_stream=pending + size == len(payload))
                            pending += size
                        connection.sendall(client.data_to_send())
                        data = connection.recv(65536)
                        self.assertTrue(data)
                        for event in client.receive_data(data):
                            if isinstance(event, h2.events.DataReceived):
                                received.extend(event.data)
                                client.acknowledge_received_data(event.flow_controlled_length, 1)
                            elif isinstance(event, h2.events.StreamEnded):
                                done = True
                    client.close_connection()
                    connection.sendall(client.data_to_send())
                self.assertEqual(gzip.decompress(received) if compressed else received, payload)
            self.assertEqual(report["uploaded"], payload if upload else b"")
            self.assertEqual(report["completion"], "goaway-no-error")
            self.assertEqual(dict(report["requests"][0]["headers"])[":method"],
                             "POST" if upload else "GET")

    def test_fixture_rejects_unexpected_decoded_path_or_multiple_requests(self):
        import h2.connection

        class Connection:
            def __init__(self, data):
                self.data = data

            def sendall(self, data):
                pass

            def recv(self, size):
                data, self.data = self.data, b""
                return data

        for paths in (["/unexpected"], ["/fixture", "/fixture"]):
            with self.subTest(paths=paths):
                client = h2.connection.H2Connection()
                client.initiate_connection()
                for index, path in enumerate(paths):
                    client.send_headers(index * 2 + 1, [
                        (":method", "GET"), (":scheme", "http"), (":authority", "fixture.invalid"),
                        (":path", path)], end_stream=True)
                with self.assertRaises(ValueError):
                    http2_fixture.exchange(Connection(client.data_to_send()), b"response")


if __name__ == "__main__":
    unittest.main()
