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


def main(directory, compiler, arguments):
    cwd = Path.cwd()
    sources = [Path(a).resolve() for a in arguments
               if a.endswith((".c", ".rc")) and Path(a).is_file()]
    inputs = [{"path": str(p), "sha256": digest(p)} for p in sources]
    output = None
    for index, argument in enumerate(arguments):
        if argument == "-o" and index + 1 < len(arguments):
            output = Path(arguments[index + 1]).resolve()
        elif argument.startswith("/Fo") and len(argument) > 3:
            output = Path(argument[3:]).resolve()
    result = subprocess.run([compiler, *arguments])
    record = {"cwd": str(cwd), "compiler": compiler, "arguments": arguments,
              "returnCode": result.returncode, "inputs": inputs}
    if result.returncode == 0 and output and output.is_file() and any(
            a in ("-c", "/c") for a in arguments):
        record["object"] = {"path": str(output), "sha256": digest(output)}
    with (directory / (str(os.getpid()) + "-" + uuid.uuid4().hex + ".json")).open("x") as stream:
        json.dump(record, stream, indent=2)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), sys.argv[2], sys.argv[3:]))
