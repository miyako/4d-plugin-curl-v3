"""Adapt inspected native candidate kits into the existing rebuilt-archive inventory."""

import hashlib
import importlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import quote

import provenance


LIBRARIES = {
    "curl": ("build_curl", "curl AND ISC", "a/libcurl.a", "lib/64/libcurl.lib"),
    "zlib": ("build_native", "Zlib", "a/libz.a", "lib/64/zlib.lib"),
    "nghttp2": ("build_http", "MIT", "a/libnghttp2.a", "lib/64/nghttp2.lib"),
    "nghttp3": ("build_http", "MIT", "a/libnghttp3.a", None),
    "libiconv": ("build_iconv", "LGPL-2.1-or-later AND LGPL-2.0-or-later",
                 "a/libiconv.a", "lib/64/iconv.lib"),
    "libssh2": ("build_ssh", None, "a/libssh2.a", "lib/64/libssh2.lib"),
    "libproxy": ("inspect_proxy", "LGPL-2.1-or-later", "a/libproxy.a", "lib/64/libproxy.lib"),
    "libmodman": ("inspect_proxy", "LGPL-2.1-or-later", "a/libmodman.a", "lib/64/modman.lib"),
}
ARCHIVE_ORIGINS = {
    "curl": "https://github.com/curl/curl",
    "libiconv": "https://savannah.gnu.org/git/?group=libiconv",
}
ADDITIONAL_NOTICES = {
    "curl": {"lib/vssh/vssh.c", "lib/curlx/inet_ntop.c", "lib/curlx/inet_pton.c"},
    "libiconv": {"libcharset/COPYING.LIB", "libcharset/lib/localcharset.c", "lib/relocatable.c"},
}
TARGETS = {
    "macos-universal": {"macos-arm64", "macos-x86_64"},
    "windows-x86_64": {"windows-x86_64"},
}


def verify_producer_run(run, jobs, repository, branch, role):
    if (run["head_repository"]["full_name"] != repository
            or run["head_branch"] != branch
            or run["path"] != ".github/workflows/native-trace.yml"
            or run["event"] != "workflow_dispatch"):
        raise ValueError("Source producer must be an explicit same-repository/branch native run")
    if jobs["total_count"] > 100 or len(jobs["jobs"]) != jobs["total_count"]:
        raise ValueError("Source producer jobs require complete bounded enumeration")
    prefix = {
        "curl": "curl-source / curl-source (",
        "libiconv": "native-prerequisites / iconv-prerequisites (",
        "nghttp3": "native-prerequisites / http-prerequisites (",
        "libproxy": "Isolated proxy candidate (",
        "inventory": "curl-source / inventory",
    }[role]
    targets = {"macos-arm64", "macos-x86_64"}
    if role == "inventory":
        targets = {"inventory"}
    elif role != "nghttp3":
        targets.add("windows-x86_64")
    producers = []
    for target in sorted(targets):
        if role == "inventory":
            suffix = ""
        elif role == "libproxy":
            suffix = target + ")"
        else:
            suffix = ", " + target + (", nghttp3, " if role == "nghttp3" else ")")
        matches = [j for j in jobs["jobs"] if
                   (j["name"] == prefix + suffix if role in ("libproxy", "inventory") else
                    j["name"].startswith(prefix) and suffix in j["name"])]
        attempt = max((j["run_attempt"] for j in matches), default=0)
        matches = [j for j in matches if j["run_attempt"] == attempt]
        if len(matches) != 1 or matches[0]["conclusion"] != "success":
            raise ValueError("Latest exact source producer must succeed: " + role + "/" + target)
        producers.append({k: matches[0][k] for k in ("id", "name", "run_attempt", "conclusion")})
    return {"run": {k: run[k] for k in ("id", "head_sha", "head_branch", "path", "event")},
            "producers": producers}


def _inspect(module, kit):
    dependencies = str(Path(__file__).resolve().parents[1] / "dependencies")
    if dependencies not in sys.path:
        sys.path.insert(0, dependencies)
    importlib.import_module(module).inspect(kit)


def _ssh_license(record, kit):
    notices = []
    seen = set()
    for item in record["noticeFiles"]:
        text = (kit / "source" / item["path"]).read_bytes().decode("utf-8")
        blocks = ([text] if item["path"] == "COPYING" else
                  [m.group() for m in re.finditer(r"/\*.*?\*/", text, re.S)
                   if re.search(r"copyright|permission|public[- ]domain|licen[cs]e",
                                m.group(), re.I)])
        if not blocks:
            raise ValueError("Missing original SSH notice: " + item["path"])
        for block in blocks:
            if block not in seen:
                notices.append(item["path"] + "\n" + block)
                seen.add(block)
    if not notices:
        raise ValueError("Missing original SSH license notices")
    text = "\n\n".join(notices)
    return {
        "id": "LicenseRef-libssh2-notices-" + hashlib.sha256(text.encode()).hexdigest()[:16],
        "name": "libssh2 BSD, ISC-style and public-domain source notices",
        "text": text,
    }


def _kit_records(kit):
    native = kit / "native-build-provenance.json"
    proxy = kit / "proxy-build-provenance.json"
    if native.exists() and proxy.exists():
        raise ValueError("Ambiguous native/proxy original build records")
    if not proxy.exists():
        return native, [json.loads(native.read_text(encoding="utf-8"))]
    original = json.loads(proxy.read_text(encoding="utf-8"))
    if original["schema_version"] != 2:
        raise ValueError("Proxy inventory requires fresh compiler-object/archive evidence")
    if (len(original["components"]) != 2 or
            {c["name"] for c in original["components"]} != {"libproxy", "libmodman"}):
        raise ValueError("Unexpected proxy source component set")
    records = []
    for component in original["components"]:
        name = component["name"]
        if name not in ("libproxy", "libmodman"):
            raise ValueError("Unexpected proxy source component")
        filename = ("libproxy.lib" if name == "libproxy" else "modman.lib") if original[
            "target"] == "windows-x86_64" else name + ".a"
        records.append({
            **original, "library": name, "version": component.get("version"),
            "sourceSubpath": name,
            "status": "not-approved-for-production",
            "originalStatus": original["status"],
            "toolchain": {"recordedExecutables": original["toolchainExecutables"]},
            "archives": [a for a in original["archives"] if a["path"] == "lib/" + filename],
            "compilerArchiveEvidence": original["compilerArchiveEvidence"][
                "proxy" if name == "libproxy" else "modman"],
            "licenseScope": "LGPL static-redistribution/relink materials and actual-host "
                            "verification remain open; source identification is not compliance proof.",
        })
    return proxy, records


def _read_kits(target, kits):
    if target not in TARGETS:
        raise ValueError("Unsupported native inventory target")
    grouped = {}
    for path in kits:
        kit = Path(path).resolve()
        record_path, records = _kit_records(kit)
        inspected = set()
        for record in records:
            library = record.get("library")
            if library not in LIBRARIES:
                raise ValueError("Native inventory adapter does not cover this library")
            module, license_id, mac_path, windows_path = LIBRARIES[library]
            if record.get("target") not in TARGETS[target]:
                raise ValueError("Native source kit target does not match final inventory")
            if target == "windows-x86_64" and windows_path is None:
                raise ValueError("Library is not selected for this target")
            if module not in inspected:
                _inspect(module, kit)
                inspected.add(module)
            if (len(record["archives"]) != 1
                    or record["status"] != "not-approved-for-production"):
                raise ValueError("Unexpected native candidate archive/status")
            archive = record["archives"][0]
            relative = Path(archive["path"])
            if (relative.is_absolute() or ".." in relative.parts
                    or "\\" in archive["path"] or ":" in archive["path"]
                    or not (kit / "install" / relative).resolve().is_relative_to(kit / "install")):
                raise ValueError("Native installed archive escapes its source kit")
            installed = kit / "install" / relative
            if provenance.digest(installed) != archive["sha256"]:
                raise ValueError("Native archive differs from original build record")
            rows = grouped.setdefault(library, {})
            if record["target"] in rows:
                raise ValueError("Duplicate native source target")
            rows[record["target"]] = (record, installed, provenance.digest(record_path), kit)

    for library, rows in sorted(grouped.items()):
        if set(rows) != TARGETS[target]:
            raise ValueError("Native source kit architecture coverage is incomplete")
        _, license_id, mac_path, windows_path = LIBRARIES[library]
        models = [rows[t][0] for t in sorted(rows)]
        first = models[0]
        identity = {key: first.get(key) for key in
                    ("version", "source_commit", "source_repository", "sourceArchive")}
        if any(any(model.get(key) != value for key, value in identity.items())
               for model in models):
            raise ValueError("Native architecture source identities disagree")
    return grouped


def collect(root, target, kits):
    """Recheck original records and bind copies/universal slices, without executing probes."""
    grouped = _read_kits(target, kits)
    rebuilt = []
    for library, rows in sorted(grouped.items()):
        _, license_id, mac_path, windows_path = LIBRARIES[library]
        first = rows[sorted(rows)[0]][0]
        destination = mac_path if target == "macos-universal" else windows_path
        copied = Path(root) / destination
        if target == "macos-universal":
            provenance.verify_universal_archive(copied, {
                0x0100000C: rows["macos-arm64"][1],
                0x01000007: rows["macos-x86_64"][1],
            })
        elif provenance.digest(copied) != provenance.digest(rows[target][1]):
            raise ValueError("Copied native archive differs from original build")
        source_archive = first.get("sourceArchive")
        if library in ARCHIVE_ORIGINS:
            if not isinstance(source_archive, dict):
                raise ValueError("Library requires its verified release source archive")
            origin = ARCHIVE_ORIGINS[library]
            source = {"sourceArchive": source_archive}
            purl = ("pkg:generic/" + library + "@" + first["version"]
                    + "?download_url=" + quote(source_archive["url"], safe=""))
            license_hash = source_archive["licenseSha256"]
        else:
            if source_archive is not None:
                raise ValueError("Unexpected source archive on a Git-built native library")
            origin = first["source_repository"]
            source = {"sourceCommit": first["source_commit"]}
            repository = origin.removeprefix("https://github.com/").removesuffix(".git")
            purl = "pkg:github/" + repository + "@" + first["source_commit"]
            if "sourceSubpath" in first:
                source["sourceSubpath"] = first["sourceSubpath"]
                purl += "#" + first["sourceSubpath"]
            license_hash = first["licenseFileSha256"]
        rebuilt.append({
            "name": library, "sourceRepository": origin,
            **({"version": first["version"]} if first.get("version") else {}),
            **source, **({"license": license_id} if license_id else {}),
            "licenseFileSha256": license_hash, "purl": purl,
            **({"licenseEvidence": _ssh_license(first, rows[sorted(rows)[0]][3]),
                "additionalNoticeFiles": first["noticeFiles"]} if library == "libssh2" else {}),
            "status": "not-approved-for-production",
            **({"licenseScope": first["licenseScope"]} if "licenseScope" in first else {}),
            "evidenceType": "inspected-original-native-source-and-archive-build-records",
            "archives": [{"path": destination, "sha256": provenance.digest(copied)}],
            "originalBuildRecords": [{
                "target": architecture, "sha256": rows[architecture][2],
                "configureArguments": rows[architecture][0]["configure_arguments"],
                "toolchain": rows[architecture][0]["toolchain"],
                "recipeFiles": rows[architecture][0]["recipeFiles"],
                **({key: rows[architecture][0][key] for key in
                    ("originalStatus", "patches", "acceptedCandidateChanges",
                     "compilerArchiveEvidence")} if library in ("libproxy", "libmodman") else {}),
            } for architecture in sorted(rows)],
            **({"additionalNoticeFiles": [
                item for item in first["sourceFiles"]
                if item["path"] in ADDITIONAL_NOTICES[library]
            ]} if library in ADDITIONAL_NOTICES else {}),
            "limitations": [
                *first.get("limitations", []),
                "Original source/compiler/archive kits must accompany these record hashes.",
                "Source inspection and archive binding do not approve production adoption, "
                "prove transfers or establish full-plugin relinking/host compatibility.",
            ],
        })
    return rebuilt


def stage(output, target, kits):
    """Create fresh isolated vendor-layout copies; never replace existing archives."""
    if output.exists():
        raise ValueError("Native candidate staging requires a new output directory")
    grouped = _read_kits(target, kits)
    if not grouped:
        raise ValueError("Native candidate staging requires source kits")
    tool = None
    if target == "macos-universal":
        tool = Path(subprocess.check_output(["xcrun", "--find", "lipo"], text=True).strip())
    output.mkdir(parents=True)
    commands = []
    for library, rows in sorted(grouped.items()):
        destination = output / LIBRARIES[library][2 if target == "macos-universal" else 3]
        destination.parent.mkdir(parents=True, exist_ok=True)
        if tool:
            arguments = [str(tool), "-create",
                         *[str(rows[t][1]) for t in sorted(rows)], "-output", str(destination)]
            subprocess.run(arguments, check=True)
            commands.append(arguments)
        else:
            shutil.copyfile(rows[target][1], destination)
    record = {
        "target": target, "status": "not-approved-for-production",
        "rebuiltArchiveEvidence": collect(output, target, kits),
        "mergeTool": {"path": str(tool), "sha256": provenance.digest(tool)} if tool else None,
        "mergeCommands": commands,
    }
    provenance.write_json(output / "native-source-provenance.json", record)
    return record


def stage_project(source, output, target, kits):
    """Prepare a separate committed-source checkout, never edit the caller's vendor files."""
    if output.exists():
        raise ValueError("Plugin candidate staging requires a new output directory")
    grouped = _read_kits(target, kits)
    required = set(LIBRARIES) - ({"nghttp3"} if target == "windows-x86_64" else set())
    if set(grouped) != required:
        raise ValueError("Plugin staging requires every selected native source candidate")
    source = source.resolve()
    if Path(provenance.git(source, "rev-parse", "--show-toplevel")).resolve() != source:
        raise ValueError("Plugin staging requires the project repository root")
    if provenance.git(source, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Plugin staging requires committed project source")
    commit = provenance.git(source, "rev-parse", "HEAD")
    headers = {}
    for library, relative in (("curl", "curl"), ("libiconv", "iconv.h"), ("libproxy", "proxy.h")):
        models = []
        for architecture in sorted(grouped[library]):
            path = grouped[library][architecture][3] / "install/include" / relative
            files = sorted(path.rglob("*")) if path.is_dir() else [path]
            models.append({p.relative_to(path.parent).as_posix(): (p, provenance.digest(p))
                           for p in files if not p.is_dir()})
        if (not models[0] or any({k: v[1] for k, v in model.items()} !=
                                {k: v[1] for k, v in models[0].items()} for model in models)):
            raise ValueError("Native public headers differ between architectures: " + library)
        headers.update(models[0])
    output.mkdir(parents=True)
    vendor = output / "vendor"
    staged = stage(vendor, target, kits)
    project = output / "project"
    clone = ["git", "clone", "--shared", "--no-checkout", "--", str(source), str(project)]
    subprocess.run(clone, check=True)
    subprocess.run(["git", "-C", str(project), "-c", "core.autocrlf=false",
                    "checkout", "--detach", commit], check=True)

    def destination(relative):
        path = project / relative
        if not path.resolve().is_relative_to(project.resolve()):
            raise ValueError("Project candidate destination escapes the isolated checkout")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    for row in staged["rebuiltArchiveEvidence"]:
        for archive in row["archives"]:
            shutil.copyfile(vendor / archive["path"], destination(archive["path"]))
    for relative, (path, _) in headers.items():
        copied = destination("include/" + relative)
        shutil.copyfile(path, copied)
        if provenance.digest(copied) != headers[relative][1]:
            raise ValueError("Copied public header differs from its original source kit")
    merge_commands = []
    tool = Path(staged["mergeTool"]["path"]) if staged["mergeTool"] else None

    def merge(originals, relative):
        copied = destination(relative)
        if tool:
            arguments = [str(tool), "-create",
                         *[str(originals[t]) for t in sorted(originals)],
                         "-output", str(copied)]
            subprocess.run(arguments, check=True)
            merge_commands.append(arguments)
            provenance.verify_universal_archive(copied, {
                0x0100000C: originals["macos-arm64"],
                0x01000007: originals["macos-x86_64"],
            })
        else:
            shutil.copyfile(originals[target], copied)
            if provenance.digest(copied) != provenance.digest(originals[target]):
                raise ValueError("Copied provider differs from original archive")

    curls = grouped["curl"]
    ssl_records = {t: curls[t][3] / "providers/ssh/provider/openssl-build-provenance.json"
                   for t in sorted(curls)}
    for name in ("crypto", "ssl"):
        extension = ".lib" if target.startswith("windows") else ".a"
        merge({t: p.parent / ("lib/lib" + name + extension) for t, p in ssl_records.items()},
              ("lib/64/" if target.startswith("windows") else "a/") + "lib" + name + extension)
    ssl = provenance.combine(list(ssl_records.values()), project, target)
    ssl["status"] = "not-approved-for-production"
    provenance.write_json(project / "openssl-provenance.json", ssl)
    brotli_records = {}
    for architecture, (_, _, _, kit) in sorted(curls.items()):
        record_path = kit / "providers/baseline/brotli-provenance.json"
        original = json.loads(record_path.read_text(encoding="utf-8"))
        provider = kit / "providers/baseline/rebuilt-providers/Brotli"
        if original["archives"] != provenance.archive_hashes(
                provider, [a["path"] for a in original["archives"]]):
            raise ValueError("Original Brotli provider archives changed")
        brotli_records[architecture] = (original, provider, provenance.digest(record_path))
    first = brotli_records[sorted(brotli_records)[0]][0]
    identity = {k: v for k, v in first.items() if k != "archives"}
    if any({k: v for k, v in r[0].items() if k != "archives"} != identity
           for r in brotli_records.values()):
        raise ValueError("Original Brotli provider source identities disagree")
    selected = [a["path"] for a in first["archives"]
                if Path(a["path"]).name in ("libbrotlidec.a", "libbrotlicommon.a",
                                           "brotlidec.lib", "brotlicommon.lib")]
    if len(selected) != 2:
        raise ValueError("Expected the two selected Brotli provider archives")
    for relative in selected:
        merge({t: r[1] / relative for t, r in brotli_records.items()}, relative)
    brotli = {
        **identity, "target": target, "status": "not-approved-for-production",
        "archives": provenance.archive_hashes(project, selected),
        "source_builds": [{"target": t, "originalRecordSha256": r[2], "record": r[0]}
                          for t, r in brotli_records.items()],
    }
    provenance.write_json(project / "brotli-provenance.json", brotli)
    if collect(project, target, kits) != staged["rebuiltArchiveEvidence"]:
        raise ValueError("Project candidate copies differ from inspected source staging")
    record = {
        "projectCommit": commit, "target": target, "status": "not-approved-for-production",
        "projectDirectory": "project", "cloneCommand": clone,
        "nativeSourceKits": [str(Path(p).resolve()) for p in kits],
        "rebuiltArchiveEvidence": staged["rebuiltArchiveEvidence"],
        "providerMergeCommands": merge_commands, "mergeTool": staged["mergeTool"],
        "publicHeaders": [{"path": "include/" + p, "sha256": sha}
                          for p, (_, sha) in sorted(headers.items())],
        "limitations": [
            "Prepared inputs only: no plugin compilation, linker selection or actual 4D host proof.",
            "OpenSSL/Brotli retain their original source/archive evidence class, not new "
            "compiler-object closure or retroactive build materials.",
            "The shared Git clone and externally referenced kits are not a portable LGPL "
            "source/relink delivery; complete self-contained materials remain required.",
        ],
    }
    provenance.write_json(output / "plugin-candidate-staging.json", record)
    return record


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--kit", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-source", type=Path,
                        help="Prepare a separate committed project checkout; never replace caller archives")
    args = parser.parse_args()
    result = (stage_project(args.project_source, args.output, args.target, args.kit)
              if args.project_source else stage(args.output, args.target, args.kit))
    print(json.dumps({"target": result["target"], "status": result["status"],
                      "libraries": [r["name"] for r in result["rebuiltArchiveEvidence"]]}))
