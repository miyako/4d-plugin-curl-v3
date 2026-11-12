#!/usr/bin/env python3
"""Export and replay relocatable Mac object-link materials, never load a plugin."""

import argparse
import json
from pathlib import Path, PurePosixPath
import platform
import shlex
import shutil
import subprocess

import relink_plugin_macos as local
import build_iconv
import inspect_proxy
from provenance import archive_hashes, digest, write_json


MANIFEST = "portable-object-kit.json"


def relative_path(root, name):
    path = root / name
    if (Path(name).is_absolute() or "\\" in name or ":" in name
            or ".." in Path(name).parts or not path.resolve().is_relative_to(root.resolve())):
        raise ValueError("Portable material path escapes its kit")
    return path


def toolchain(driver, sdk):
    result = {"driverSha256": digest(driver), "sdkSettingsSha256": digest(sdk / "SDKSettings.json")}
    for name in ("ld", "lipo"):
        path = Path(subprocess.check_output(["xcrun", "--find", name], text=True).strip())
        result[name + "Sha256"] = digest(path)
    return result


def relocate(arguments, project, sdk, driver, target):
    arguments = local.link_arguments(arguments, PurePosixPath("${OUTPUT}") / target)
    if arguments[0] != str(driver) or arguments.count("-isysroot") != 1:
        raise ValueError("Unexpected original Mac driver/SDK arguments")
    arguments[0] = "${DRIVER}"
    result = []
    for argument in arguments:
        for prefix, token in ((str(project), "${KIT}/project"), (str(sdk), "${SDK}")):
            if argument == prefix or argument.startswith((prefix + "/", "-L" + prefix + "/",
                                                          "-F" + prefix + "/")):
                argument = argument.replace(prefix, token, 1)
            elif argument in ("-L" + prefix, "-F" + prefix):
                argument = argument.replace(prefix, token, 1)
        if argument.startswith(("/", "-L/", "-F/")):
            raise ValueError("Unaccounted absolute original link argument: " + argument)
        result.append(argument)
    return result


def export(project, output):
    if platform.system() != "Darwin":
        raise ValueError("Export requires the original Mac build/toolchain")
    if output.exists() or output.is_relative_to(project):
        raise ValueError("Use a fresh kit directory outside the original project")
    evidence_path = project / "native-trace/build-evidence.json"
    evidence = json.loads(evidence_path.read_text())
    binary = project / "test/Plugins/cURL.bundle/Contents/MacOS/cURL"
    if evidence["binarySha256"] != digest(binary):
        raise ValueError("Original source-candidate binary changed")
    for source in evidence["rebuiltArchiveEvidence"]:
        if source["archives"] != archive_hashes(project, [a["path"] for a in source["archives"]]):
            raise ValueError("Original source-candidate archives changed")
    driver = Path(subprocess.check_output(["xcrun", "--find", "clang++"], text=True).strip())
    active_sdk = Path(subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip())
    commands = local.original_commands(project, driver)
    sdk_paths = {a[a.index("-isysroot") + 1] for a in commands.values()}
    if len(sdk_paths) != 1 or Path(next(iter(sdk_paths))).resolve() != active_sdk.resolve():
        raise ValueError("Active SDK does not match the original build")
    sdk = Path(next(iter(sdk_paths)))
    output.mkdir(parents=True)

    def copy(path):
        name = path.resolve().relative_to(project).as_posix()
        destination = output / "project" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        return "project/" + name

    recipes = []
    for target, arguments in sorted(commands.items()):
        filelist, _ = local.object_inputs(project, arguments)
        names = [copy(Path(shlex.split(line)[0])) for line in filelist.read_text().splitlines()]
        for argument in arguments:
            if argument.startswith(("-L/", "-F/")):
                directory = Path(argument[2:]).resolve()
                if not directory.is_relative_to(project):
                    raise ValueError("Original library search escapes the project")
                (output / "project" / directory.relative_to(project)).mkdir(parents=True, exist_ok=True)
                for path in directory.iterdir() if directory.exists() else []:
                    if path.is_file():
                        copy(path)
        recipes.append({
            "target": target, "arguments": relocate(arguments, project, sdk, driver, target),
            "fileList": "project/" + filelist.relative_to(project).as_posix(),
            "objects": names,
            "originalSliceSha256": local.generate.sha256(
                local.generate.mac_slices(binary.read_bytes())[target]),
        })
    bundle = project / "test/Plugins/cURL.bundle"
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("Bundle symlinks require separate portable-material review")
        if path.is_file() and not {"Windows64", "_CodeSignature"}.intersection(path.relative_to(bundle).parts):
            copy(path)
    copy(evidence_path)
    copy(project / "native-trace/xcodebuild.log")
    tracked = subprocess.check_output(["git", "-C", str(project), "ls-files", "-z"]).decode().split("\0")
    for name in filter(None, tracked):
        path = relative_path(project, name)
        if (Path(name).parts[0] in ("a", "lib") or name.startswith("test/Plugins/")
                or path.suffix.lower() in (".a", ".lib", ".dll", ".dylib", ".4dx")):
            continue
        if not path.is_file() or path.is_symlink():
            raise ValueError("Product source is not a regular in-project file: " + name)
        destination = output / "product-source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    staging = json.loads((project.parent / "plugin-candidate-staging.json").read_text())
    materials = []
    for name in staging["nativeSourceKits"]:
        source = Path(name)
        proxy = source / "proxy-build-provenance.json"
        native = source / "native-build-provenance.json"
        record_path = proxy if proxy.is_file() else native
        original = json.loads(record_path.read_text())
        library = "libproxy" if proxy.is_file() else original.get("library")
        if library not in ("libproxy", "libiconv"):
            continue
        (inspect_proxy.inspect if library == "libproxy" else build_iconv.inspect)(source)
        binding = next(a for a in evidence["rebuiltArchiveEvidence"] if a["name"] == library)
        if not any(a["target"] == original["target"] and a["sha256"] == digest(record_path)
                   for a in binding["originalBuildRecords"]):
            raise ValueError("Delivered LGPL sources do not match the actual selected build")
        if any(p.is_symlink() for p in source.rglob("*")):
            raise ValueError("Library-material symlinks require separate delivery review")
        destination = output / "library-materials" / original["target"] / library
        shutil.copytree(source, destination)
        materials.append({"library": library, "target": original["target"],
                          "directory": destination.relative_to(output).as_posix(),
                          "originalBuildRecordSha256": digest(record_path)})
    if {(a["library"], a["target"]) for a in materials} != {
            (library, target) for library in ("libproxy", "libiconv")
            for target in ("macos-arm64", "macos-x86_64")} or len(materials) != 4:
        raise ValueError("Both original LGPL source kits are required for each Mac architecture")
    for folder in ("dependencies", "sbom"):
        source = Path(__file__).resolve().parents[1] / folder
        for path in source.iterdir():
            if path.is_file() and path.suffix in (".py", ".json"):
                destination = output / "tools" / folder / path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
    record = {
        "schemaVersion": 1, "status": "not-approved-for-production",
        "target": "macos-universal", "originalBinarySha256": digest(binary),
        "originalBuildEvidenceSha256": digest(evidence_path),
        "productSourceBaseCommit": evidence["sourceCommit"],
        "libraryMaterials": materials,
        "toolchain": toolchain(driver, sdk),
        "architectures": recipes,
        "limitations": [
            "Includes original proxy/modman/iconv source kits and product source snapshots; complete notices/other-library licensing delivery and modified-source rebuild verification remain separate gates.",
            "Unselected search-path files are retained to preserve the original link arguments, not promoted as selected dependencies.",
            "Requires the recorded Apple toolchain/SDK; redistribution of those tools is not included.",
            "No Windows delivery, signing/trust, 4D initialization or host/protocol verification.",
        ],
    }
    files = [p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()]
    record["files"] = archive_hashes(output, files)
    write_json(output / MANIFEST, record)
    return record


def replay(kit, output, replacements):
    if platform.system() != "Darwin":
        raise ValueError("Portable replay requires macOS and the recorded Apple toolchain")
    record = json.loads((kit / MANIFEST).read_text())
    if (record.get("schemaVersion") != 1 or record.get("target") != "macos-universal"
            or record.get("status") != "not-approved-for-production"):
        raise ValueError("Unsupported portable object materials")
    if output.exists() or output.is_relative_to(kit):
        raise ValueError("Use a fresh replay directory outside the kit")
    for item in record["files"]:
        if digest(relative_path(kit, item["path"])) != item["sha256"]:
            raise ValueError("Portable object/link materials changed: " + item["path"])
    driver = Path(subprocess.check_output(["xcrun", "--find", "clang++"], text=True).strip())
    sdk = Path(subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip())
    if record["toolchain"] != toolchain(driver, sdk):
        raise ValueError("Portable replay toolchain/SDK differs from the original build")
    if replacements and set(replacements) != {"macos-arm64", "macos-x86_64"}:
        raise ValueError("Both modified proxy architecture archives are required")
    if len(record["architectures"]) != 2 or {a["target"] for a in record["architectures"]} != {
            "macos-arm64", "macos-x86_64"}:
        raise ValueError("Portable architecture coverage changed")
    output.mkdir(parents=True)
    results = []
    for recipe in record["architectures"]:
        target = recipe["target"]
        folder = output / target
        folder.mkdir()
        filelist = folder / "objects.list"
        filelist.write_text("".join(str(relative_path(kit, name)) + "\n"
                                    for name in recipe["objects"]))
        values = {"${KIT}": str(kit), "${SDK}": str(sdk), "${DRIVER}": str(driver),
                  "${OUTPUT}": str(output)}
        arguments = []
        for argument in recipe["arguments"]:
            for token, value in values.items():
                argument = argument.replace(token, value)
            arguments.append(argument)
        arguments[arguments.index("-filelist") + 1] = str(filelist)
        if replacements:
            arguments[arguments.index("-lproxy")] = str(replacements[target])
            arguments.append("-Wl,-u,_proxy_user_relink_probe")
        with (folder / "link.log").open("w") as stream:
            subprocess.run(arguments, cwd=kit, stdout=stream, stderr=subprocess.STDOUT, check=True)
        binary = folder / "cURL"
        if replacements:
            if (not local.defines_marker(binary.read_bytes())
                    or digest(binary) == recipe["originalSliceSha256"]):
                raise ValueError("Modified portable replay did not retain defined proxy code")
        elif digest(binary) != recipe["originalSliceSha256"]:
            raise ValueError("Relocated baseline does not match the original plugin slice")
        results.append({"target": target, "sha256": digest(binary), "command": arguments})
    subprocess.run(["xcrun", "lipo", "-create",
                    *[str(output / a["target"] / "cURL") for a in results],
                    "-output", str(output / "cURL")], check=True)
    final = local.generate.mac_slices((output / "cURL").read_bytes())
    if any(local.generate.sha256(final[a["target"]]) != a["sha256"] for a in results):
        raise ValueError("Portable universal slices differ from their link outputs")
    if any(digest(relative_path(kit, item["path"])) != item["sha256"] for item in record["files"]):
        raise ValueError("Portable input bytes changed during relinking")
    proof = {"status": record["status"], "kitManifestSha256": digest(kit / MANIFEST),
             "modified": bool(replacements), "architectures": results,
             "binarySha256": digest(output / "cURL"),
             "replacementArchives": {t: digest(p) for t, p in replacements.items()}}
    write_json(output / "portable-replay-proof.json", proof)
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("export")
    create.add_argument("--project", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("replay")
    run.add_argument("--kit", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--proxy-arm64", type=Path)
    run.add_argument("--proxy-x86-64", type=Path)
    args = parser.parse_args()
    if args.command == "export":
        result = export(args.project.resolve(), args.output.resolve())
    else:
        replacements = {t: p.resolve() for t, p in (
            ("macos-arm64", args.proxy_arm64), ("macos-x86_64", args.proxy_x86_64)) if p}
        result = replay(args.kit.resolve(), args.output.resolve(), replacements)
    print(json.dumps({"status": result["status"], "target": "macos-universal"}, indent=2))
