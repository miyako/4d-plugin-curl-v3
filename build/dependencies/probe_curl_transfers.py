#!/usr/bin/env python3
"""Loopback-only standalone curl transfers; never initialize the plugin or 4D."""

import argparse
from contextlib import contextmanager
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit
import zlib

from build_native import ROOT
import observe_curl
import provenance


PAYLOAD = (b"Native source-build transfer compatibility.\n" + bytes(range(256))) * 127
RECIPES = ["LICENSE", "build/dependencies/probe_curl_transfers.py",
           "build/dependencies/native/curl-transfer.c",
           "build/dependencies/baseline-v4.9.10.json"]


@contextmanager
def serve(encoded, context=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            encoding = urlsplit(self.path).path.removeprefix("/")
            if encoding not in encoded:
                self.send_error(404)
                return
            body = encoded[encoding]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            if encoding != "identity":
                self.send_header("Content-Encoding", encoding)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        if thread.is_alive():
            raise RuntimeError("The bounded loopback fixture failed to stop")


def verify_inputs(project, model):
    if (model["archives"] != [
            {"path": item["path"], "sha256": provenance.digest(Path(item["path"]))}
            for item in model["archives"]]
            or model["compiler"]["sha256"] != provenance.digest(Path(model["compiler"]["path"]))
            or model["interface"] != provenance.archive_hashes(
                Path(model.get("interfaceProject", project)),
                [item["path"] for item in model["interface"]])):
        raise ValueError("Curl transfer compiler, archives or interface changed")


def build_probe(project, output, target, provider_project, source=None, interface_project=None):
    windows = target.startswith("windows")
    selected = observe_curl.baseline(target)
    paths = []
    for name in ("curl", "libssh2", "nghttp2", "nghttp3", "OpenSSL", "zlib", "Brotli"):
        rows = [row for row in selected if row["name"] == name]
        rows.sort(key=lambda row: (0 if "ssl." in row["path"] or "dec." in row["path"]
                                   else 1, row["path"]))
        for row in rows:
            root = provider_project if name in ("OpenSSL", "Brotli") else project
            path = root / row["path"]
            if project != provider_project and name not in ("OpenSSL", "Brotli"):
                if provenance.digest(path) != row["sha256"]:
                    raise ValueError("The comparison must use the exact frozen non-provider archive")
            paths.append(path)
    source = source or ROOT / "build/dependencies/native/curl-transfer.c"
    interface_project = interface_project or project
    binary = output / (source.stem + (".exe" if windows else ""))
    output.mkdir(parents=True)
    compiler = shutil.which("cl") if windows else "/usr/bin/cc"
    if not compiler:
        raise FileNotFoundError("The selected native transfer compiler is unavailable")
    if windows:
        command = [compiler, "/nologo", "/W4", "/O2", "/MT", "/DCURL_STATICLIB",
                   "/I" + str(interface_project / "include"), str(source),
                   "/Fo" + str(output / (source.stem + ".obj")), "/Fe" + str(binary),
                   *map(str, paths), "/link", "/VERBOSE:LIB", "/MAP:" + str(output / "transfer.map"),
                   "ws2_32.lib", "crypt32.lib", "bcrypt.lib", "secur32.lib", "wldap32.lib",
                   "advapi32.lib", "normaliz.lib", "user32.lib", "iphlpapi.lib"]
    else:
        command = [compiler, "-arch", target.removeprefix("macos-"),
                   "-mmacosx-version-min=10.13", "-Wall", "-Wextra", "-DCURL_STATICLIB",
                   "-I" + str(interface_project / "include"), str(source), *map(str, paths),
                   "-framework", "Security", "-framework", "CoreFoundation",
                   "-framework", "SystemConfiguration", "-framework", "GSS",
                   "-framework", "LDAP", "-lresolv", "-liconv",
                   "-Wl,-map," + str(output / "transfer.map"), "-o", str(binary)]
    model = {
        "command": command, "compiler": {"path": compiler, "sha256": provenance.digest(Path(compiler))},
        "archives": [{"path": str(path), "sha256": provenance.digest(path)} for path in paths],
        "interface": provenance.archive_hashes(
            interface_project, [p.relative_to(interface_project).as_posix()
                                for p in (interface_project / "include/curl").glob("*.h")]),
    }
    if interface_project != project:
        model["interfaceProject"] = str(interface_project)
    with (output / "compile.log").open("w") as stream:
        subprocess.run(command, cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True)
    verify_inputs(project, model)
    return binary, model


def check_transfer(binary, output, target, name, backend, url, ca="-", proxy="-",
                   version="1.2", encoding="", rejected=False):
    command = [str(binary), backend, url, str(ca), proxy, version, encoding]
    if target.startswith("macos"):
        command = ["arch", "-" + target.removeprefix("macos-"), *command]
    result = subprocess.run(command, capture_output=True, timeout=25)
    (output / (name + ".stdout")).write_bytes(result.stdout)
    (output / (name + ".stderr")).write_bytes(result.stderr)
    expected = {"curlCode": 60, "httpStatus": 0} if rejected else {
        "curlCode": 0, "httpStatus": 200}
    if (result.returncode != expected["curlCode"]
            or json.loads(result.stderr) != expected
            or result.stdout != (b"" if rejected else PAYLOAD)):
        raise ValueError("Curl transfer/authentication expectation failed: " + name)
    return {"case": name, "command": command, "exitCode": result.returncode, **expected,
            "responseSha256": hashlib.sha256(result.stdout).hexdigest(),
            "responseBytes": len(result.stdout)}


def inspect_proof(output):
    receipt = json.loads((output / "curl-transfer-proof.json").read_text())
    target = receipt["target"]
    cases = ["http-" + name for name in ("identity", "gzip", "deflate", "br")]
    cases.append("explicit-http-proxy")
    for backend in (("openssl", "schannel") if target == "windows-x86_64" else ("openssl",)):
        for version in ("1.2", "1.3"):
            cases.extend(backend + "-tls" + version + "-" + suffix
                         for suffix in ("trusted", "hostname", "untrusted"))
    files = [p.relative_to(output).as_posix() for p in output.rglob("*")
             if p.is_file() and p != output / "curl-transfer-proof.json"]
    required = {"localhost.crt", "untrusted.crt", *("recipes/" + name for name in RECIPES)}
    for variant in ("candidate", "baseline"):
        required.update(variant + "/" + name for name in (
            "compile.log", "transfer.map",
            "curl-transfer.exe" if target == "windows-x86_64" else "curl-transfer"))
        required.update(variant + "/" + name + suffix for name in cases
                        for suffix in (".stdout", ".stderr"))
    if (receipt["schemaVersion"] != 1 or target not in provenance.PLATFORMS
            or set(receipt["results"]) != {"candidate", "baseline"}
            or set(receipt["compile"]) != {"candidate", "baseline"}
            or not required.issubset(files)
            or receipt["recipeInputs"] != provenance.archive_hashes(output / "recipes", RECIPES)
            or receipt["files"] != provenance.archive_hashes(output, files)
            or any(Path(name).suffix == ".key" for name in files)):
        raise ValueError("Persisted curl transfer proof input/output set changed")
    for variant, results in receipt["results"].items():
        if [item["case"] for item in results] != cases:
            raise ValueError("Curl transfer coverage has missing, duplicated or changed cases")
        for item in results:
            name = item["case"]
            rejected = name.endswith(("-hostname", "-untrusted"))
            expected = {"curlCode": 60, "httpStatus": 0} if rejected else {
                "curlCode": 0, "httpStatus": 200}
            stdout = (output / variant / (name + ".stdout")).read_bytes()
            stderr = (output / variant / (name + ".stderr")).read_bytes()
            if (stdout != (b"" if rejected else PAYLOAD)
                    or json.loads(stderr) != expected
                    or any(item[key] != value for key, value in expected.items())
                    or item["exitCode"] != expected["curlCode"]
                    or item["responseBytes"] != len(stdout)
                    or item["responseSha256"] != hashlib.sha256(stdout).hexdigest()):
                raise ValueError("Original curl response/authentication outputs changed")
    return receipt


def probe(project, baseline, kit, target, output):
    windows = target.startswith("windows")
    if (output.exists() or project == baseline
            or output.is_relative_to(project) or output.is_relative_to(baseline)
            or platform.system() != ("Windows" if windows else "Darwin")):
        raise ValueError("Use fresh transfer output on the matching native operating system")
    suffix = ".exe" if windows else ""
    openssl = kit / ("provider-openssl/install/bin/openssl" + suffix)
    brotli = kit / ("provider-brotli/install/bin/brotli" + suffix)
    tools = {str(path): provenance.digest(path) for path in (openssl, brotli)}
    if not windows:
        for path in (openssl, brotli):
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
    recipes = provenance.archive_hashes(ROOT, RECIPES)
    encoded = {"identity": PAYLOAD, "gzip": gzip.compress(PAYLOAD, mtime=0),
               "deflate": zlib.compress(PAYLOAD)}
    encoded["br"] = subprocess.run(
        [str(brotli), "-q", "5", "-c"], input=PAYLOAD,
        capture_output=True, check=True, timeout=30).stdout
    compiled = {name: build_probe(root, output / name, target, project)
                for name, root in (("candidate", project), ("baseline", baseline))}
    results = {}
    with tempfile.TemporaryDirectory(prefix="curl-native-tls-") as directory:
        temporary = Path(directory)
        config = temporary / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\n[dn]\n")
        for name in ("localhost", "untrusted"):
            subprocess.run([
                str(openssl), "req", "-new", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc", "-days", "1",
                "-config", str(config), "-subj", "/CN=" + name,
                "-addext", "subjectAltName=DNS:localhost",
                "-keyout", str(temporary / (name + ".key")),
                "-out", str(temporary / (name + ".crt"))],
                capture_output=True, check=True, timeout=30)
            shutil.copyfile(temporary / (name + ".crt"), output / (name + ".crt"))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(temporary / "localhost.crt", temporary / "localhost.key")
        with serve(encoded) as port, serve(encoded, context) as tls_port:
            for name, (binary, _) in compiled.items():
                destination = output / name
                cases = []
                for encoding in encoded:
                    cases.append(check_transfer(
                        binary, destination, target, "http-" + encoding, "openssl",
                        "http://127.0.0.1:" + str(port) + "/" + encoding, encoding=encoding))
                cases.append(check_transfer(
                    binary, destination, target, "explicit-http-proxy", "openssl",
                    "http://native-source-test.invalid/identity",
                    proxy="http://127.0.0.1:" + str(port)))
                for backend in (("openssl", "schannel") if windows else ("openssl",)):
                    for version in ("1.2", "1.3"):
                        prefix = backend + "-tls" + version
                        url = "https://localhost:" + str(tls_port) + "/identity"
                        ca = temporary / "localhost.crt"
                        cases.append(check_transfer(binary, destination, target,
                            prefix + "-trusted", backend, url, ca, version=version))
                        cases.append(check_transfer(binary, destination, target,
                            prefix + "-hostname", backend, url.replace("localhost", "127.0.0.1"),
                            ca, version=version, rejected=True))
                        cases.append(check_transfer(binary, destination, target,
                            prefix + "-untrusted", backend, url, temporary / "untrusted.crt",
                            version=version, rejected=True))
                results[name] = cases
    if (recipes != provenance.archive_hashes(ROOT, RECIPES)
            or tools != {str(path): provenance.digest(path) for path in (openssl, brotli)}):
        raise ValueError("Transfer test source, fixture tools or input archives changed")
    for name, (_, model) in compiled.items():
        verify_inputs(project if name == "candidate" else baseline, model)
    for item in recipes:
        destination = output / "recipes" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / item["path"], destination)
    receipt = {
        "schemaVersion": 1, "target": target, "results": results, "recipeInputs": recipes,
        "compile": {name: model for name, (_, model) in compiled.items()},
        "fixtureTools": tools, "serverTLS": ssl.OPENSSL_VERSION,
        "files": provenance.archive_hashes(
            output, [p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()]),
        "scope": "Loopback HTTP, gzip/deflate/Brotli, explicit HTTP proxy, TLS1.2/1.3 "
                 "hostname/trust authentication and rejection. Frozen non-provider archives "
                 "are compared using the same fresh source-matched TLS/Brotli providers. "
                 "No application/4D load, PAC/SSH transfer, old-system runtime or release proof. "
                 "Schannel disables revocation only for this ephemeral self-signed fixture. "
                 "Private test keys are temporary and not delivered.",
    }
    provenance.write_json(output / "curl-transfer-proof.json", receipt)
    inspect_proof(output)
    return {"target": target, "casesPerVariant": {k: len(v) for k, v in results.items()},
            "scope": receipt["scope"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("project", "baseline", "kit", "output"):
        parser.add_argument("--" + argument, type=Path, required=True)
    parser.add_argument("--target", choices=tuple(provenance.PLATFORMS), required=True)
    args = parser.parse_args()
    print(json.dumps(probe(args.project.resolve(), args.baseline.resolve(), args.kit.resolve(),
                           args.target, args.output.resolve()), indent=2))
