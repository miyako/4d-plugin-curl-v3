"""Memory-only loopback SSH/SFTP/SCP fixture; never change host accounts or SSH."""

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import posixpath
import shlex
import socket
import stat
import threading


LIMIT = 1024 * 1024


def scp_command(command):
    words = shlex.split(command.decode("ascii"))
    if len(words) == 4 and words[2] == "--":
        words.pop(2)
    if words not in (["scp", "-f", "/download.bin"], ["scp", "-pf", "/download.bin"],
                     ["scp", "-t", "/upload.bin"]):
        raise ValueError("Only the two bounded SCP fixture commands are accepted")
    return words[1]


def receive(channel, count):
    if count < 0 or count > LIMIT:
        raise ValueError("SSH fixture receive exceeds its bound")
    data = b""
    while len(data) < count:
        part = channel.recv(count - len(data))
        if not part:
            raise EOFError("SSH fixture peer closed before its acknowledgement or payload")
        data += part
    return data


def line(channel):
    data = b""
    while len(data) < 128:
        data += receive(channel, 1)
        if data.endswith(b"\n"):
            return data
    raise ValueError("SCP fixture header exceeds its bound")


@contextmanager
def serve(payload):
    import paramiko

    if not payload or len(payload) > LIMIT:
        raise ValueError("Use a nonempty bounded SSH fixture payload")
    host_key, wrong_key = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
    uploads, sessions, workers, transports, fatal = {}, [], [], [], []
    lock, stopping = threading.Lock(), threading.Event()
    state = {"case": None}
    executor = ThreadPoolExecutor(max_workers=8)

    def launch(function, *args):
        with lock:
            workers.append(executor.submit(function, *args))

    def attributes(data=None):
        result = paramiko.SFTPAttributes()
        result.st_mode = (stat.S_IFDIR | 0o755) if data is None else (stat.S_IFREG | 0o644)
        result.st_size = 0 if data is None else len(data)
        return result

    class Handle(paramiko.SFTPHandle):
        def __init__(self, session, writable):
            super().__init__()
            self.session, self.writable, self.data = session, writable, bytearray()

        def read(self, offset, length):
            if self.writable or offset < 0 or length < 0 or offset + length > LIMIT:
                self.session["errors"].append("Invalid bounded SFTP read")
                return paramiko.SFTP_FAILURE
            return payload[offset:offset + length]

        def write(self, offset, data):
            if not self.writable or offset != len(self.data) or offset + len(data) > LIMIT:
                self.session["errors"].append("Invalid bounded SFTP write")
                return paramiko.SFTP_FAILURE
            self.data.extend(data)
            return paramiko.SFTP_OK

        def stat(self):
            return attributes(self.data if self.writable else payload)

        def close(self):
            if self.writable:
                uploads[(self.session["case"], "sftp")] = bytes(self.data)
            return paramiko.SFTP_OK

    class Files(paramiko.SFTPServerInterface):
        def __init__(self, server, *args, **kwargs):
            super().__init__(server, *args, **kwargs)
            self.session = server.session

        def canonicalize(self, path):
            return posixpath.normpath("/" + path.lstrip("/"))

        def stat(self, path):
            self.session["requests"].append(["stat", path])
            if path in (".", "/"):
                return attributes()
            if path == "/download.bin":
                return attributes(payload)
            return paramiko.SFTP_NO_SUCH_FILE

        lstat = stat

        def open(self, path, flags, attr):
            import os
            writable = bool(flags & (os.O_WRONLY | os.O_RDWR))
            self.session["requests"].append(["open-write" if writable else "open-read", path])
            if (path, writable) not in (("/download.bin", False), ("/upload.bin", True)):
                return paramiko.SFTP_NO_SUCH_FILE
            return Handle(self.session, writable)

    def scp(channel, mode, session):
        channel.settimeout(5)
        complete = False
        try:
            if mode in ("-f", "-pf"):
                if receive(channel, 1) != b"\0":
                    raise ValueError("SCP download acknowledgement changed")
                if mode == "-pf":
                    channel.sendall(b"T1700000000 0 1700000000 0\n")
                    if receive(channel, 1) != b"\0":
                        raise ValueError("SCP download timestamps were not acknowledged")
                channel.sendall(("C0644 " + str(len(payload)) + " download.bin\n").encode())
                if receive(channel, 1) != b"\0":
                    raise ValueError("SCP download header was not acknowledged")
                channel.sendall(payload + b"\0")
                final = channel.recv(1)
                if final not in (b"", b"\0"):
                    raise ValueError("Unexpected SCP download final acknowledgement")
                session["downloadFinalAck"] = "acknowledged" if final else "peer-closed"
                complete = True
            else:
                channel.sendall(b"\0")
                header = line(channel).decode("ascii").split()
                if header != ["C0644", str(len(payload)), "upload.bin"]:
                    raise ValueError("SCP upload header differs from the bounded fixture")
                channel.sendall(b"\0")
                data = receive(channel, len(payload))
                terminator = channel.recv(1)
                if terminator not in (b"", b"\0"):
                    raise ValueError("Unexpected SCP upload payload terminator")
                session["uploadTerminator"] = "nul" if terminator else "peer-eof"
                uploads[(session["case"], "scp")] = data
                complete = True
                if terminator:
                    channel.sendall(b"\0")
            channel.send_exit_status(0)
        except ValueError as error:
            session["errors"].append(type(error).__name__ + ": " + str(error))
        except (EOFError, OSError) as error:
            observation = type(error).__name__ + ": " + str(error)
            if complete:
                session["peerClosureAfterTransfer"] = observation
            else:
                session["errors"].append(observation)
        finally:
            try:
                channel.close()
            except (EOFError, OSError) as error:
                session["channelCloseObservation"] = type(error).__name__ + ": " + str(error)

    class Auth(paramiko.ServerInterface):
        def __init__(self, session):
            self.session = session

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            accepted = username == "fixture" and password == "loopback-fixture"
            self.session["authentications"].append({"username": username, "accepted": accepted})
            return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            return (paramiko.OPEN_SUCCEEDED if kind == "session"
                    else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

        def check_channel_exec_request(self, channel, command):
            try:
                mode = scp_command(command)
            except (ValueError, UnicodeDecodeError) as error:
                self.session["errors"].append(str(error))
                self.session["rejectedCommandHex"] = command.hex()
                return False
            self.session["requests"].append(["scp", mode])
            launch(scp, channel, mode, self.session)
            return True

    def connection(client, session):
        transport = paramiko.Transport(client)
        transport.banner_timeout = transport.handshake_timeout = transport.auth_timeout = 5
        with lock:
            transports.append(transport)
        transport.add_server_key(host_key)
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, Files)
        try:
            transport.start_server(server=Auth(session))
            session["algorithms"] = {
                "hostKey": transport.host_key_type, "incomingCipher": transport.remote_cipher,
                "outgoingCipher": transport.local_cipher}
            channels = []
            while transport.is_active() and not stopping.is_set():
                channel = transport.accept(timeout=0.1)
                if channel is not None:
                    channels.append(channel)
        except (paramiko.SSHException, EOFError, OSError) as error:
            session["peerClosure"] = type(error).__name__ + ": " + str(error)
        finally:
            transport.close()
            transport.join(timeout=5)
            if transport.is_alive():
                fatal.append("SSH fixture transport failed to stop")

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.1)

    def accept():
        while not stopping.is_set():
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError as error:
                if stopping.is_set():
                    return
                fatal.append(type(error).__name__ + ": " + str(error))
                return
            session = {"case": state["case"], "authentications": [], "requests": [], "errors": []}
            sessions.append(session)
            launch(connection, client, session)

    acceptor = threading.Thread(target=accept)
    acceptor.start()

    class Fixture:
        port = listener.getsockname()[1]
        public_key = host_key.get_name() + " " + host_key.get_base64()
        wrong_public_key = wrong_key.get_name() + " " + wrong_key.get_base64()

        def begin(self, name):
            self.settle()
            if fatal:
                raise RuntimeError("; ".join(fatal))
            state["case"] = name

        def settle(self):
            for worker in list(workers):
                worker.result(timeout=5)

        def inspect(self, name, protocol=None):
            self.settle()
            rows = [s for s in sessions if s["case"] == name]
            if len(rows) != 1 or rows[0]["errors"] or fatal:
                raise ValueError("SSH fixture request failed or has an unexpected session count")
            result = dict(rows[0])
            if protocol:
                data = uploads.get((name, protocol))
                if data != payload:
                    raise ValueError("SSH upload bytes differ from the expected payload")
                result["uploadSha256"] = hashlib.sha256(data).hexdigest()
            return result

        def diagnostics(self, name):
            self.settle()
            return {"sessions": [dict(s) for s in sessions if s["case"] == name],
                    "fatal": list(fatal)}

        def uploaded(self, name, protocol):
            return uploads[(name, protocol)]

    try:
        yield Fixture()
    finally:
        stopping.set()
        listener.close()
        acceptor.join(timeout=5)
        for transport in transports:
            transport.close()
        for worker in list(workers):
            worker.result(timeout=5)
        executor.shutdown(wait=True)
        if acceptor.is_alive() or fatal:
            raise RuntimeError("The bounded SSH fixture did not shut down cleanly")
