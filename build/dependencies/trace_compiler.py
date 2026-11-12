#!/usr/bin/env python3
"""Pass compiler arguments unchanged and retain original invocation/object records."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def native_path(argument):
    if os.name == "nt" and argument.startswith("/cygdrive/"):
        drive, relative = argument[len("/cygdrive/"):].split("/", 1)
        if len(drive) != 1 or not drive.isalpha():
            raise ValueError("Unexpected Cygwin source/output drive path")
        argument = drive.upper() + ":/" + relative
    return Path(argument).resolve()


def main(directory, compiler, arguments):
    cwd = Path.cwd()
    sources = [native_path(a) for a in arguments
               if a.endswith((".c", ".rc")) and native_path(a).is_file()]
    inputs = [{"path": p.as_posix(), "sha256": digest(p)} for p in sources]
    output = None
    for index, argument in enumerate(arguments):
        if argument == "-o" and index + 1 < len(arguments):
            output = native_path(arguments[index + 1])
        elif argument.startswith(("/Fo", "-Fo")) and len(argument) > 3:
            output = native_path(argument[3:])
    result = subprocess.run([compiler, *arguments])
    record = {"cwd": cwd.as_posix(), "compiler": compiler, "arguments": arguments,
              "returnCode": result.returncode, "inputs": inputs}
    if result.returncode == 0 and output and output.is_file() and any(
            a in ("-c", "/c", "--output-format=coff") for a in arguments):
        record["object"] = {"path": output.as_posix(), "sha256": digest(output)}
    with (directory / (str(os.getpid()) + "-" + uuid.uuid4().hex + ".json")).open("x") as stream:
        json.dump(record, stream, indent=2)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), sys.argv[2], sys.argv[3:]))
