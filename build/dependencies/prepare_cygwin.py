#!/usr/bin/env python3
"""Prepare a fresh, job-local GNU build environment without changing the host install."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import urllib.request

from build_native import ROOT
from provenance import digest, write_json


def prepare(output):
    if platform.system() != "Windows" or output.exists():
        raise ValueError("Cygwin preparation requires Windows and a fresh output directory")
    output.mkdir(parents=True)
    pin = json.loads((ROOT / "build/dependencies/windows-build-tools.json").read_text())["cygwin"]
    installer = output / "setup-x86_64.exe"
    urllib.request.urlretrieve(pin["url"], installer)
    with installer.open("rb") as stream:
        sha512 = hashlib.file_digest(stream, "sha512").hexdigest()
    if digest(installer) != pin["sha256"] or sha512 != pin["sha512"]:
        raise ValueError("Cygwin installer differs from the reviewed signed acquisition")
    arguments = [str(installer), "--quiet-mode", "--no-admin", "--no-shortcuts",
                 "--root", str(output / "root"), "--local-package-dir", str(output / "packages"),
                 "--site", pin["mirror"], "--packages", ",".join(pin["packages"])]
    with (output / "setup.log").open("w") as stream:
        subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT, cwd=output, check=True)
    root = output / "root"
    for name in ("bash.exe", "make.exe", "cygpath.exe", "x86_64-w64-mingw32-windres.exe"):
        if not (root / "bin" / name).is_file():
            raise ValueError("Cygwin installation did not provide " + name)
    shutil.copyfile(root / "etc/setup/installed.db", output / "installed.db")
    write_json(output / "acquisition.json", {
        "pin": pin, "installerSha256": digest(installer), "arguments": arguments,
        "installedDatabaseSha256": digest(output / "installed.db"),
        "scope": "Job-local build tools only; installer/package binaries are not plugin or source-kit contents."})
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    print(prepare(parser.parse_args().output.resolve()))
