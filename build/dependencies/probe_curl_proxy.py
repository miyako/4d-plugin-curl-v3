#!/usr/bin/env python3
"""Observe synthetic OS proxy settings through real, standalone curl transfers."""

import argparse
from contextlib import closing, contextmanager, ExitStack
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PureWindowsPath
import platform
import shutil
import subprocess
import sys
import threading
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
from build_native import ROOT, probe_selections
import observe_curl
import plugin_relink_delivery
from probe_curl_http2 import copy_public_interface
import probe_curl_transfers as transfers
from provenance import archive_hashes, digest, write_json

PAYLOAD = bytes(range(256)) * 127
CASES = ("manual", "bypass", "pac-proxy", "pac-direct")
RECIPES = sorted(set(transfers.RECIPES + [
    "4DPlugin-cURL.cpp", "build/dependencies/probe_curl_proxy.py",
    "build/dependencies/probe_curl_http2.py", "build/dependencies/http2_fixture.py",
    "build/dependencies/plugin_relink_delivery.py",
    "build/dependencies/native-sources.json", "build/dependencies/proxy-source.json",
    "build/dependencies/proxy/behavior.cpp",
    "build/dependencies/native/probe-json.h",
    "build/dependencies/native/curl-proxy-transfer.cpp"]))


def pac_bytes(first_port, final_port):
    return (
        'function FindProxyForURL(url, host) { '
        'if (url.indexOf("/direct") >= 0) return "DIRECT"; '
        f'return "PROXY 127.0.0.1:{first_port}; PROXY 127.0.0.1:{final_port}; DIRECT"; }}\n'
    ).encode("ascii")


@contextmanager
def serve(handler):
    class Server(ThreadingHTTPServer):
        daemon_threads = False

        def handle_error(self, request, address):
            self.errors.append(sys.exception())

    server = Server(("127.0.0.1", 0), handler)
    server.errors = []
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        if thread.is_alive():
            raise RuntimeError("Proxy fixture listener did not stop")
        if server.errors:
            raise RuntimeError("Proxy fixture request failed") from server.errors[0]


@contextmanager
def fixture(name):
    events = {"origin": [], "proxy": [], "pac": []}
    host = "bypass.invalid" if name == "bypass" else "destination.invalid"
    path = "/direct" if name == "pac-direct" else "/payload"

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def respond(self, body, content_type="application/octet-stream"):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class Origin(Handler):
        def do_GET(self):
            if self.path != path or self.headers.get("Host") != f"{host}:{origin.server_port}":
                raise ValueError("Unexpected loopback origin request")
            events["origin"].append({
                "path": self.path, "host": self.headers["Host"],
                "forwarded": self.headers.get("X-Fixture-Proxy") == "forwarded"})
            self.respond(PAYLOAD)

    class Proxy(Handler):
        def do_GET(self):
            if self.path != url:
                raise ValueError("Proxy may forward only the exact loopback fixture URL")
            events["proxy"].append({"url": self.path})
            with closing(http.client.HTTPConnection(
                    "127.0.0.1", origin.server_port, timeout=5)) as connection:
                connection.request("GET", path, headers={
                    "Host": f"{host}:{origin.server_port}", "X-Fixture-Proxy": "forwarded"})
                response = connection.getresponse()
                body = response.read(len(PAYLOAD) + 1)
                if response.status != 200 or body != PAYLOAD:
                    raise ValueError("Incomplete loopback proxy forwarding")
            self.respond(body)

    class PAC(Handler):
        def do_GET(self):
            if self.path != "/proxy.pac":
                raise ValueError("Unexpected PAC request")
            events["pac"].append({"path": self.path})
            self.respond(pac_source, "application/x-ns-proxy-autoconfig")

    with ExitStack() as stack:
        origin = stack.enter_context(serve(Origin))
        url = f"http://{host}:{origin.server_port}{path}"
        proxy = stack.enter_context(serve(Proxy))
        pac_source = pac_bytes(origin.server_port, proxy.server_port)
        pac = stack.enter_context(serve(PAC))
        yield {"url": url, "proxy": f"http://127.0.0.1:{proxy.server_port}",
               "proxyPort": proxy.server_port, "pac": f"http://127.0.0.1:{pac.server_port}/proxy.pac",
               "resolution": f"{host}:{origin.server_port}:127.0.0.1",
               "pacSource": pac_source, "events": events}


def build_probe(project, output, target, providers, interface, proxy_header):
    windows = target.startswith("windows")
    paths = transfers.probe_archives(project, target, providers)
    for name in ("libproxy", "libmodman"):
        rows = [r for r in observe_curl.baseline(target) if r["name"] == name]
        if len(rows) != 1:
            raise ValueError("Expected one selected " + name + " archive")
        path = project / rows[0]["path"]
        if project != providers and digest(path) != rows[0]["sha256"]:
            raise ValueError("Comparison proxy archive differs from frozen baseline")
        paths.append(path)
    output.mkdir(parents=True)
    compiler = shutil.which("cl") if windows else "/usr/bin/c++"
    if not compiler:
        raise FileNotFoundError("Native C++ proxy probe compiler is unavailable")
    source = ROOT / "build/dependencies/native/curl-proxy-transfer.cpp"
    binary = output / ("curl-proxy-transfer.exe" if windows else "curl-proxy-transfer")
    if windows:
        command = [compiler, "/nologo", "/W4", "/O2", "/MT", "/EHsc", "/DCURL_STATICLIB",
                   "/DWIN32", "/D_CRT_SECURE_NO_WARNINGS",
                   "/I" + str(interface / "include"), "/I" + str(proxy_header.parent),
                   str(source), "/Fo" + str(output / "curl-proxy-transfer.obj"), "/Fe" + str(binary),
                   *map(str, paths), "/link", "/VERBOSE:LIB", "/MAP:" + str(output / "transfer.map"),
                   "ws2_32.lib", "crypt32.lib", "bcrypt.lib", "secur32.lib", "wldap32.lib",
                   "advapi32.lib", "normaliz.lib", "user32.lib", "iphlpapi.lib"]
    else:
        command = [compiler, "-std=c++11", "-arch", target.removeprefix("macos-"),
                   "-mmacosx-version-min=10.13", "-Wall", "-Wextra", "-DCURL_STATICLIB",
                   "-I" + str(interface / "include"), "-I" + str(proxy_header.parent), str(source),
                   *map(str, paths), "-framework", "Security", "-framework", "CoreFoundation",
                   "-framework", "SystemConfiguration", "-framework", "JavaScriptCore",
                   "-framework", "GSS", "-framework", "LDAP", "-lresolv", "-liconv",
                   "-Wl,-map," + str(output / "transfer.map"), "-o", str(binary)]
    model = {"command": command, "compiler": {"path": compiler, "sha256": digest(Path(compiler))},
             "archives": [{"path": str(p), "sha256": digest(p)} for p in paths],
             "interfaceProject": str(interface),
             "interface": archive_hashes(interface, [
                 p.relative_to(interface).as_posix() for p in (interface / "include/curl").glob("*.h")]),
             "proxyHeaderSha256": digest(proxy_header)}
    with (output / "compile.log").open("w") as stream:
        subprocess.run(command, cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True)
    transfers.verify_inputs(project, model)
    selected = probe_selections(output, target, {
        name: {"path": str(path), "sha256": digest(path)}
        for name, path in zip(("libproxy", "libmodman"), paths[-2:])},
        map_name="transfer.map", log_name="compile.log")
    write_json(output / "selected-members.json", selected)
    return binary, model


def expected_route(target, variant, name):
    if name == "manual" or (name == "pac-proxy" and target.startswith("macos")):
        return "proxy"
    if name == "bypass" and target.startswith("windows") and variant == "baseline":
        return "proxy"
    return "direct"


def inspect_case(output, target, variant, item):
    name = item["case"]
    root = output / variant
    metadata = json.loads((root / (name + ".stdout")).read_bytes())
    events = json.loads((root / (name + ".server.json")).read_text())
    body = (root / (name + ".response")).read_bytes()
    routed = expected_route(target, variant, name) == "proxy"
    proxies = [item["proxy"] if routed else "direct://"]
    if name == "pac-proxy" and target.startswith("macos"):
        proxies = [f'http://127.0.0.1:{urlsplit(item["url"]).port}', item["proxy"], "direct://"]
    expected_origin = {"path": urlsplit(item["url"]).path,
                       "host": urlsplit(item["url"]).netloc, "forwarded": routed}
    if (item["exitCode"] != 0 or metadata != {
            "curlCode": 0, "httpStatus": 200, "proxies": proxies}
            or body != PAYLOAD or events["origin"] != [expected_origin]
            or events["proxy"] != ([{"url": item["url"]}] if routed else [])
            or item["route"] != ("proxy" if routed else "direct")
            or item["responseSha256"] != hashlib.sha256(body).hexdigest()
            or json.loads((root / (name + ".exit.json")).read_text()) != item["exitCode"]
            or (root / (name + ".pac")).read_bytes() != pac_bytes(
                urlsplit(item["url"]).port, urlsplit(item["proxy"]).port)):
        raise ValueError("Proxy selection or actual curl route differs: " + variant + "/" + name)
    if name.startswith("pac") and target.startswith("macos"):
        if events["pac"] != [{"path": "/proxy.pac"}]:
            raise ValueError("macOS PAC was not actually retrieved and evaluated")
    elif (len(events["pac"]) > int(name.startswith("pac"))
          or any(p != {"path": "/proxy.pac"} for p in events["pac"])):
        raise ValueError("Unexpected PAC acquisition")


def inspect_proof(output):
    proof = json.loads((output / "curl-proxy-proof.json").read_text())
    target = proof["target"]
    if (proof["schemaVersion"] != 1 or target not in (
            "macos-arm64", "macos-x86_64", "windows-x86_64")
            or proof["status"] != "not-approved-for-production"
            or set(proof["compile"]) != {"candidate", "baseline"}
            or set(proof["results"]) != {"candidate", "baseline"}):
        raise ValueError("Invalid native proxy proof coverage")
    expected = {"interfaces/COPYING.curl", "interfaces/proxy.h",
                *("recipes/" + p for p in RECIPES)}
    source_pin = next(p for p in json.loads(
        (output / "recipes/build/dependencies/native-sources.json").read_text())["sourceArchives"]
                      if p["library"] == "curl")
    if (proof["curlSource"] != source_pin
            or digest(output / "interfaces/COPYING.curl") != source_pin["licenseSha256"]):
        raise ValueError("Pinned public curl source/license binding changed")
    for variant in ("candidate", "baseline"):
        model = proof["compile"][variant]
        interface = model["interface"]
        if (not interface or any(not p["path"].startswith("include/curl/")
                                 or not p["path"].endswith(".h") for p in interface)
                or interface != archive_hashes(output / "interfaces" / variant,
                                               [p["path"] for p in interface])):
            raise ValueError("Original proxy probe curl public interface changed")
        selected = json.loads((output / variant / "selected-members.json").read_text())
        inputs = {name: item for name, item in zip(
            ("libproxy", "libmodman"), model["archives"][-2:])}
        wanted = {name: PureWindowsPath(row["path"]).name for name, row in (
            (row["name"], row) for row in observe_curl.baseline(target)
            if row["name"] in ("libproxy", "libmodman"))}
        if (any(PureWindowsPath(item["path"]).name != wanted[name]
                for name, item in inputs.items())
                or selected != probe_selections(output / variant, target, inputs,
                                                map_name="transfer.map", log_name="compile.log")):
            raise ValueError("Actual selected proxy/module-manager member evidence changed")
        expected.update("interfaces/" + variant + "/" + p["path"]
                        for p in proof["compile"][variant]["interface"])
        expected.update(variant + "/" + p for p in (
            "compile.log", "transfer.map", "selected-members.json",
            "curl-proxy-transfer.exe" if target.startswith("windows") else "curl-proxy-transfer"))
        if target.startswith("windows"):
            expected.add(variant + "/curl-proxy-transfer.obj")
        expected.update(f"{variant}/{name}{suffix}" for name in CASES for suffix in (
            ".stdout", ".stderr", ".response", ".server.json", ".pac", ".command.json",
            ".exit.json"))
        if [r["case"] for r in proof["results"][variant]] != list(CASES):
            raise ValueError("Missing or repeated proxy integration cases")
        for item in proof["results"][variant]:
            inspect_case(output, target, variant, item)
        if proof["compile"][variant]["proxyHeaderSha256"] != digest(output / "interfaces/proxy.h"):
            raise ValueError("Proxy public interface changed")
    files = [p.relative_to(output).as_posix() for p in output.rglob("*")
             if p.is_file() and p.name != "curl-proxy-proof.json"]
    if (set(files) != expected or any(p.is_symlink() for p in output.rglob("*"))
            or proof["files"] != archive_hashes(output, files)
            or proof["recipeInputs"] != archive_hashes(output / "recipes", RECIPES)):
        raise ValueError("Persisted proxy integration files changed")
    return proof


def bind_plugin(kit, output):
    proof = inspect_proof(output)
    return {**plugin_relink_delivery.bind_probe_inputs(
        kit, proof["target"], proof["project"], proof["compile"]["candidate"]["archives"]),
        "proofSha256": digest(output / "curl-proxy-proof.json"),
        "scope": "Standalone probe inputs bound to actual selected plugin archive positions; "
                 "not a claim that every input contributes live code to this probe."}


def probe(project, baseline, proxy_header, curl_source, target, output):
    windows = target.startswith("windows")
    if (target not in ("macos-arm64", "macos-x86_64", "windows-x86_64")
            or output.exists() or project == baseline or output.is_relative_to(project)
            or output.is_relative_to(baseline)
            or platform.system() != ("Windows" if windows else "Darwin")):
        raise ValueError("Use fresh external output on the matching native operating system")
    output.mkdir(parents=True)
    interface = output / "interfaces/candidate"
    pin = copy_public_interface(curl_source, interface)
    shutil.move(interface / "COPYING", output / "interfaces/COPYING.curl")
    shutil.copytree(baseline / "include/curl", output / "interfaces/baseline/include/curl",
                    ignore=shutil.ignore_patterns("*Makefile*"))
    shutil.copyfile(proxy_header, output / "interfaces/proxy.h")
    for path in RECIPES:
        destination = output / "recipes" / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, destination)
    proof = {"schemaVersion": 1, "target": target, "project": str(project),
             "status": "not-approved-for-production", "curlSource": pin,
             "compile": {}, "results": {},
             "scope": "Standalone dependency executables; synthetic process-only OS settings; "
                      "no plugin/4D initialization. Windows retains no built-in PAC runner. "
                      "The observed multi-entry Windows bypass correction is intentional."}
    for variant, root in (("candidate", project), ("baseline", baseline)):
        binary, model = build_probe(
            root, output / variant, target, project, output / "interfaces" / variant,
            output / "interfaces/proxy.h")
        proof["compile"][variant] = model
        proof["results"][variant] = []
        for name in CASES:
            with fixture(name) as server:
                case = output / variant / name
                command = [str(binary), "pac" if name.startswith("pac") else name,
                           server["pac"], str(server["proxyPort"]), server["url"],
                           str(case.with_suffix(".response")), server["resolution"]]
                if not windows:
                    command = ["arch", "-" + target.removeprefix("macos-"), *command]
                environment = {k: v for k, v in os.environ.items()
                               if k.lower() not in ("http_proxy", "https_proxy", "all_proxy",
                                                    "no_proxy", "px_module_path")}
                environment["PX_MODULE_PATH"] = str(output / "absent-external-modules")
                write_json(case.with_suffix(".command.json"), command)
                result = subprocess.run(command, capture_output=True, timeout=35, env=environment)
                case.with_suffix(".stdout").write_bytes(result.stdout)
                case.with_suffix(".stderr").write_bytes(result.stderr)
                write_json(case.with_suffix(".exit.json"), result.returncode)
                case.with_suffix(".pac").write_bytes(server["pacSource"])
            write_json(case.with_suffix(".server.json"), server["events"])
            if result.returncode != 0:
                raise RuntimeError(f"Native proxy probe failed: {variant}/{name}, "
                                   f"exit {result.returncode}; see retained stdout/stderr")
            item = {"case": name, "exitCode": result.returncode, "url": server["url"],
                    "proxy": server["proxy"], "route": expected_route(target, variant, name),
                    "responseSha256": digest(case.with_suffix(".response"))}
            inspect_case(output, target, variant, item)
            proof["results"][variant].append(item)
        transfers.verify_inputs(root, model)
    proof["recipeInputs"] = archive_hashes(output / "recipes", RECIPES)
    proof["files"] = archive_hashes(output, [
        p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()])
    write_json(output / "curl-proxy-proof.json", proof)
    return inspect_proof(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", type=Path)
    parser.add_argument("--bind-plugin", type=Path)
    parser.add_argument("--project", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--proxy-header", type=Path)
    parser.add_argument("--curl-source", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.inspect:
        result = inspect_proof(args.inspect.resolve())
        if args.bind_plugin:
            result = bind_plugin(args.bind_plugin.resolve(), args.inspect.resolve())
    elif all((args.project, args.baseline, args.proxy_header,
              args.curl_source, args.target, args.output)):
        result = probe(args.project.resolve(), args.baseline.resolve(), args.proxy_header.resolve(),
                       args.curl_source.resolve(), args.target, args.output.resolve())
    else:
        parser.error("Provide --inspect or all native probe inputs")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
