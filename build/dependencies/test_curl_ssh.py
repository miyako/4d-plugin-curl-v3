import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

import probe_curl_ssh as ssh
import ssh_fixture
from provenance import archive_hashes, write_json


class CurlSshTests(unittest.TestCase):
    def test_native_selection_binding_requires_exact_paths_hashes_and_target(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "curl-ssh-proof.json").write_text("nonexecuted original proof")
            link_path = output / "link.json"
            for target, project, archive in (
                    ("macos-arm64", "/fixture/project", "/fixture/project/a/libcurl.a"),
                    ("windows-x86_64", r"C:\fixture\project",
                     r"C:\fixture\project\lib\64\libcurl.lib")):
                relative = "lib/64/libcurl.lib" if target.startswith("windows") else "a/libcurl.a"
                record = {"target": target, "project": project,
                          "compile": {"candidate": {"archives": [
                              {"path": archive, "sha256": "1" * 64}]}}}
                link = {"target": target, "binarySha256": "2" * 64, "selectedArchives": [
                    {"scope": "repository", "candidatePath": relative, "sha256": "1" * 64}]}
                with patch.object(ssh, "inspect_proof", return_value=record):
                    write_json(link_path, link)
                    self.assertEqual(len(ssh.bind_plugin_selection(output, link_path)["inputs"]), 1)
                    for field, value in (("candidatePath", "unused/libcurl.a"),
                                         ("sha256", "3" * 64), ("scope", "system")):
                        with self.subTest(target=target, changed=field):
                            altered = {**link, "selectedArchives": [
                                {**link["selectedArchives"][0], field: value}]}
                            write_json(link_path, altered)
                            with self.assertRaisesRegex(ValueError, "actual plugin selection"):
                                ssh.bind_plugin_selection(output, link_path)
                    write_json(link_path, {**link, "target": "other-target"})
                    with self.assertRaisesRegex(ValueError, "matching plugin link"):
                        ssh.bind_plugin_selection(output, link_path)

    def test_scp_parser_accepts_only_the_bounded_file_commands(self):
        for command, mode in (
                (b"scp -f /download.bin", "-f"), (b"scp -pf '/download.bin'", "-pf"),
                (b"scp -t -- /upload.bin", "-t")):
            self.assertEqual(ssh_fixture.scp_command(command), mode)
        for command in (b"scp -r /download.bin", b"scp -t /download.bin",
                        b"scp -f /download.bin; touch /tmp/unwanted",
                        b"scp -f /../../download.bin", b"scp -t /upload.bin extra"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                ssh_fixture.scp_command(command)

    def test_short_or_oversized_scp_frames_are_rejected(self):
        class Channel:
            def recv(self, count):
                return b""

        with self.assertRaises(EOFError):
            ssh_fixture.receive(Channel(), 1)
        for size in (-1, ssh_fixture.LIMIT + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                ssh_fixture.receive(Channel(), size)

    def test_reader_rejects_rehashed_bad_upload_server_observation_and_extra_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name in ssh.RECIPES:
                path = output / "recipes" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ssh.ROOT / name, path)
            (output / "payload.bin").write_bytes(ssh.transfers.PAYLOAD)
            for name in ("known_hosts", "wrong_known_hosts"):
                (output / name).write_text("nonexecuted public fixture key")
            results = {}
            for variant in ("candidate", "baseline"):
                folder = output / variant
                folder.mkdir()
                for name in ("compile.log", "transfer.map", "curl-ssh-transfer"):
                    (folder / name).write_text("nonexecuted receipt fixture")
                results[variant] = []
                for case in ssh.CASES:
                    name, code = case["case"], case["code"]
                    body = (ssh.transfers.PAYLOAD
                            if code == 0 and case["operation"] == "download" else b"")
                    server = {"case": variant + "-" + name, "errors": [], "requests": [],
                              "authentications": []}
                    if name != "sftp-host-key-rejected":
                        server["authentications"] = [
                            {"username": "fixture", "accepted": name != "sftp-auth-rejected"}]
                    if name.startswith("scp-"):
                        download = case["operation"] == "download"
                        server["requests"] = [["scp", "-pf" if download else "-t"]]
                        server["downloadFinalAck" if download else "uploadTerminator"] = (
                            "peer-closed" if download else "peer-eof")
                    elif name not in ("sftp-host-key-rejected", "sftp-auth-rejected"):
                        server["requests"] = [
                            ["open-write" if case["operation"] == "upload" else "open-read",
                             "/" + case["path"]]]
                    (folder / (name + ".stdout")).write_bytes(body)
                    write_json(folder / (name + ".stderr"), {"curlCode": code})
                    write_json(folder / (name + ".server.json"), {"sessions": [server], "fatal": []})
                    if case["operation"] == "upload":
                        (folder / (name + ".uploaded")).write_bytes(ssh.transfers.PAYLOAD)
                        server = {**server, "uploadSha256": hashlib.sha256(
                            ssh.transfers.PAYLOAD).hexdigest()}
                    results[variant].append({
                        "case": name, "exitCode": code, "responseBytes": len(body),
                        "responseSha256": hashlib.sha256(body).hexdigest(), "server": server})
            versions = re.findall(r"^([a-z0-9-]+)==([0-9.]+)",
                                  (output / "recipes/build/dependencies/ssh-fixture-requirements.txt")
                                  .read_text(), re.MULTILINE)
            record = {
                "schemaVersion": 1, "status": "not-approved-for-production",
                "target": "macos-arm64", "results": results,
                "compile": {"candidate": {}, "baseline": {}},
                "recipeInputs": archive_hashes(output / "recipes", ssh.RECIPES),
                "fixtureRuntime": {"pythonVersion": "3.12.0", "packages": [
                    {"name": name, "version": version, "metadataSha256": "1" * 64,
                     "installedRecordSha256": "2" * 64} for name, version in versions]}}

            def save():
                record["files"] = archive_hashes(output, [
                    p.relative_to(output).as_posix() for p in output.rglob("*")
                    if p.is_file() and p.name != "curl-ssh-proof.json"])
                write_json(output / "curl-ssh-proof.json", record)

            save()
            ssh.inspect_proof(output)
            upload = output / "candidate/scp-upload.uploaded"
            original = upload.read_bytes()
            upload.write_bytes(b"truncated")
            save()
            with self.assertRaisesRegex(ValueError, "upload bytes"):
                ssh.inspect_proof(output)
            upload.write_bytes(original)
            observation = output / "candidate/sftp-auth-rejected.server.json"
            original = observation.read_bytes()
            write_json(observation, {"sessions": [], "fatal": []})
            save()
            with self.assertRaisesRegex(ValueError, "rejection evidence"):
                ssh.inspect_proof(output)
            observation.write_bytes(original)
            (output / "unexpected-private.key").write_text("synthetic forbidden extra file")
            save()
            with self.assertRaisesRegex(ValueError, "input/output binding"):
                ssh.inspect_proof(output)


if __name__ == "__main__":
    unittest.main()
