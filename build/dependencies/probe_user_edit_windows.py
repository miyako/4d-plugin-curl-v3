#!/usr/bin/env python3
"""Exercise a marker-free Windows GNU source edit and full-plugin raw relink."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PureWindowsPath
import platform
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import build_iconv as iconv
from build_native import tree_files
import plugin_relink_delivery as delivery
from plugin_relink_materials import relative_path
from provenance import archive_hashes, digest, write_json
import trace_compiler
import user_relink_windows as user


edit_source = iconv.edit_active_function


def copy_working_inputs(prepared, work):
    for folder in ("source", "build", "recipe"):
        shutil.copytree(prepared / folder, work / folder)


def run(kit, prepared, output):
    if (platform.system() != "Windows" or output.exists()
            or any(output.is_relative_to(p) or p.is_relative_to(output) for p in (kit, prepared))):
        raise ValueError("Use a fresh external Windows source-edit directory")
    delivery.inspect(kit)
    iconv.inspect(prepared)
    portable = json.loads((kit / user.portable.MANIFEST).read_text())
    entry = next(m for m in portable["libraryMaterials"] if m["library"] == "libiconv")
    material = relative_path(kit, entry["directory"])
    original_path = prepared / "native-build-provenance.json"
    original = json.loads(original_path.read_text())
    if (original["target"] != "windows-x86_64"
            or original["userBaseRecordSha256"] != digest(material / "native-build-provenance.json")
            or original["userBaseDeliveryManifestSha256"] != digest(
                material / "iconv-relink-delivery.json")):
        raise ValueError("Prepared GNU tree is not bound to this delivered source")
    output.mkdir(parents=True)
    work = output / "working"
    copy_working_inputs(prepared, work)
    relative_path(work, original["builtArchive"]).unlink()
    shutil.copyfile(original_path, output / "original-demonstration-record-reference.json")
    source = work / "source/lib/iconv.c"
    pristine = material / "source/lib/iconv.c"
    date = datetime.now(timezone.utc).date().isoformat()
    source.write_bytes(edit_source(pristine.read_bytes(), date))
    before = {p["path"]: p["sha256"] for p in tree_files(material / "source")}
    after = {p["path"]: p["sha256"] for p in tree_files(work / "source")}
    changed = [p for p in after if after[p] != before.get(p)]
    if changed != ["lib/iconv.c"] or before.keys() != after.keys():
        raise ValueError("User source tree differs beyond the intended active-function edit")
    old_root = PureWindowsPath(original["originalBuild"]).parent
    receipts = [r for r in original["compiledSources"] if any(
        PureWindowsPath(p["path"]) == old_root / "source/lib/iconv.c" for p in r["inputs"])]
    if len(receipts) != 1 or receipts[0]["returnCode"] != 0:
        raise ValueError("Expected one successful original native iconv compilation")
    receipt = receipts[0]
    tools = {}
    for name in ("cl", "lib"):
        tool = Path(os.environ["VCToolsInstallDir"]) / "bin/HostX64/x64" / (name + ".exe")
        if digest(tool) != original["toolchain"][name]["sha256"]:
            raise ValueError("Recorded GNU compiler/librarian changed: " + name)
        tools[name] = tool

    def relocate(value):
        return value.replace(old_root.as_posix(), work.as_posix()).replace(str(old_root), str(work))

    arguments = [relocate(a) for a in receipt["arguments"]]
    if "-MT" not in arguments or any(a.upper() in ("-MD", "/MD", "-MTD", "/MTD") for a in arguments):
        raise ValueError("The original static release CRT flags changed")
    calls = output / "compiler-calls"
    calls.mkdir()
    with (output / "compile.log").open("w") as stream:
        subprocess.run([sys.executable, str(Path(trace_compiler.__file__)), str(calls),
                        str(tools["cl"]), *arguments], cwd=Path(relocate(receipt["cwd"])),
                       stdout=stream, stderr=subprocess.STDOUT, check=True)
    compiled = [json.loads(p.read_text()) for p in calls.glob("*.json")]
    object_path = work / "build/lib/iconv.obj"
    if (len(compiled) != 1 or compiled[0]["returnCode"] != 0
            or compiled[0]["inputs"] != [{"path": source.as_posix(), "sha256": digest(source)}]
            or compiled[0]["object"]["sha256"] != digest(object_path)
            or digest(object_path) == receipt["object"]["sha256"]):
        raise ValueError("Actual user compilation did not bind the changed source and object")
    objects = []
    for item in original["compiledObjects"]:
        path = relative_path(work, item["path"])
        if path != object_path and digest(path) != item["sha256"]:
            raise ValueError("An unchanged original object was modified")
        objects.append({"path": path.relative_to(output).as_posix(), "sha256": digest(path),
                        "origin": "user-compile" if path == object_path else "original-object-reuse"})
    archive = output / "iconv.lib"
    archive_command = [str(tools["lib"]), "/NOLOGO", "/OUT:" + str(archive), *[
        str(relative_path(work / "build/lib", p["member"])) for p in original["archiveObjects"]]]
    with (output / "archive.log").open("w") as stream:
        subprocess.run(archive_command, stdout=stream, stderr=subprocess.STDOUT, check=True)
    commands = [{"output": str(relative_path(output, p["path"]))} for p in objects]
    bound = iconv.object_evidence(work, archive, commands, work / "build")
    iconv.verify_architecture(archive, "windows-x86_64")
    probe_source = work / "recipe/build/dependencies/native/iconv-probe.c"
    executable = output / "conversions.exe"
    command = [str(tools["cl"]), "/nologo", "/O2", "/MT", "/DLIBICONV_STATIC",
               "/I" + str(work / "build/include"), str(probe_source), str(archive),
               "/Fo" + str(output / "conversions.obj"), "/Fe" + str(executable)]
    with (output / "conversion-build.log").open("w") as stream:
        subprocess.run(command, cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True)
    with (output / "conversions.json").open("w") as stdout, (
            output / "conversions.stderr").open("w") as stderr:
        subprocess.run([str(executable)], stdout=stdout, stderr=stderr, check=True)
    conversions = json.loads((output / "conversions.json").read_text())
    if conversions != json.loads((prepared / "candidate.json").read_text()):
        raise ValueError("Marker-free user conversion/alias behavior changed")
    link = user.replay(kit, output / "plugin", {"lib/64/iconv.lib": archive})
    baseline = user.portable.local.pe_layout(
        (output / "plugin/original-replay/baseline/cURL.4DX").read_bytes())
    binary = output / "plugin/user-linked/cURL.4DX"
    modified = user.portable.local.pe_layout(binary.read_bytes())
    map_path = output / "plugin/user-linked/link.map"
    lines = [line for line in map_path.read_text().splitlines()
             if "libiconv_close" in line.split()]
    if (baseline[0] == modified[0] or set(baseline[1]) != set(modified[1])
            or len(lines) != 1 or lines[0].split()[-1].lower() != "iconv:iconv.obj"
            or any(marker.encode() in p.read_bytes() for marker in (
                "iconv_user_relink_probe", "proxy_user_relink_probe") for p in (archive, binary))
            or any(a.upper().startswith(("/EXPORT:", "/INCLUDE:")) for a in link["command"])):
        raise ValueError("Raw full-plugin link did not select the active marker-free user function")
    proof = {"schemaVersion": 1, "evidenceType": "marker-free-user-source-edit-experiment",
             "target": "windows-x86_64", "status": "not-approved-for-production",
             "originalPreparedRecordSha256": digest(original_path),
             "originalKitManifestSha256": digest(kit / user.portable.MANIFEST),
             "sourceModification": {"path": "lib/iconv.c", "dateUtc": date,
                                    "beforeSha256": digest(pristine), "afterSha256": digest(source)},
             "compilerCall": compiled[0], "objects": objects, "boundObjects": bound["compiledObjects"],
             "archiveObjects": bound["archiveObjects"], "archiveSha256": digest(archive),
             "archiveCommand": archive_command, "conversionCommand": command,
             "conversionChecks": iconv.CHECKS, "activeFunctionMapLine": lines[0],
             "binarySha256": digest(binary), "exports": sorted(modified[1]),
             "scope": "One actual native source recompile plus three verified unchanged object reuses; "
                      "standalone conversions and raw full-plugin link, never DLL/4D initialization; "
                      "not host verification or legal-compliance certification."}
    proof["files"] = archive_hashes(output, [p.relative_to(output).as_posix()
                                           for p in output.rglob("*") if p.is_file()])
    write_json(output / "user-edit-proof.json", proof)
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kit", "prepared", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    proof = run(args.kit.resolve(), args.prepared.resolve(), args.output.resolve())
    print(json.dumps({k: proof[k] for k in ("status", "archiveSha256", "binarySha256")}, indent=2))
