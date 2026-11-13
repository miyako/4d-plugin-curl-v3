"""Single-connection, bounded loopback HTTP/2 fixture with real HPACK and flow control."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import gzip
import hashlib
import socket

LIMIT = 1024 * 1024


def exchange(connection, response, compressed=False):
    import h2.config
    import h2.connection
    import h2.events

    model = h2.connection.H2Connection(config=h2.config.H2Configuration(
        client_side=False, header_encoding="utf-8"))
    model.initiate_connection()
    connection.sendall(model.data_to_send())
    report = {"alpn": connection.selected_alpn_protocol() if hasattr(
        connection, "selected_alpn_protocol") else None, "requests": [],
        "tlsProtocol": connection.version() if hasattr(connection, "version") else None,
        "contentEncoding": "gzip" if compressed else None,
        "windowUpdates": 0, "dataFramesSent": 0, "uploadBytes": 0}
    encoded = gzip.compress(response, mtime=0) if compressed else response
    if not response or len(response) > LIMIT or len(encoded) > LIMIT:
        raise ValueError("Invalid bounded HTTP/2 response")
    stream = None
    headers = None
    uploaded = bytearray()
    pending = None
    # Drain control frames until normal peer closure; unread bytes can cause TCP reset on close.
    for _ in range(4096):
        data = connection.recv(65536)
        if not data:
            if pending == len(encoded):
                report.update({"uploaded": bytes(uploaded), "completion": "peer-eof"})
                return report
            raise EOFError("HTTP/2 peer closed before the complete exchange")
        for event in model.receive_data(data):
            if isinstance(event, h2.events.RequestReceived):
                if stream is not None:
                    raise ValueError("The fixture accepts exactly one HTTP/2 request")
                stream, headers = event.stream_id, dict(event.headers)
                if (headers.get(":method") not in ("GET", "POST")
                        or headers.get(":path") != "/fixture"
                        or headers.get(":scheme") not in ("http", "https")):
                    raise ValueError("Unexpected decoded HTTP/2 pseudo-headers")
                report["requests"].append({"stream": stream, "headers": event.headers})
            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id != stream or len(uploaded) + len(event.data) > LIMIT:
                    raise ValueError("Unexpected or oversized HTTP/2 upload")
                uploaded.extend(event.data)
                model.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id != stream or pending is not None:
                    raise ValueError("Unexpected HTTP/2 stream completion")
                if (headers[":method"] == "POST") != bool(uploaded):
                    raise ValueError("HTTP/2 request body and method disagree")
                response_headers = [(":status", "200"), ("content-length", str(len(encoded)))]
                if compressed:
                    response_headers.append(("content-encoding", "gzip"))
                model.send_headers(stream, response_headers)
                pending = 0
                report.update({"uploadBytes": len(uploaded),
                               "uploadSha256": hashlib.sha256(uploaded).hexdigest(),
                               "responseBytes": len(response),
                               "responseSha256": hashlib.sha256(response).hexdigest()})
            elif isinstance(event, h2.events.WindowUpdated):
                report["windowUpdates"] += 1
            elif isinstance(event, h2.events.ConnectionTerminated):
                if pending == len(encoded) and event.error_code == 0:
                    report.update({"uploaded": bytes(uploaded), "completion": "goaway-no-error"})
                    return report
                raise ValueError("Unexpected termination during HTTP/2 transfer")
            elif isinstance(event, h2.events.StreamReset):
                raise ValueError("Unexpected reset/termination during HTTP/2 transfer")
        if pending is not None:
            while pending < len(encoded):
                size = min(model.local_flow_control_window(stream), model.max_outbound_frame_size,
                           len(encoded) - pending)
                if size <= 0:
                    break
                model.send_data(stream, encoded[pending:pending + size],
                                end_stream=pending + size == len(encoded))
                pending += size
                report["dataFramesSent"] += 1
        connection.sendall(model.data_to_send())
    raise ValueError("HTTP/2 fixture exceeded its bounded frame-read budget")


@contextmanager
def serve(response, *, context=None, compressed=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    report = {}

    def handle():
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(20)
            if context is not None:
                with context.wrap_socket(connection, server_side=True) as secure:
                    if secure.selected_alpn_protocol() != "h2":
                        raise ValueError("TLS fixture did not negotiate HTTP/2 ALPN")
                    return exchange(secure, response, compressed)
            return exchange(connection, response, compressed)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(handle)
        try:
            yield listener.getsockname()[1], report
        finally:
            listener.close()
            report.update(future.result(timeout=25))
