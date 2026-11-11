#!/usr/bin/env python3
"""Frozen schema-v1 interpretation for saved PR58 embedded-source evidence.

API: collect(root, target) -> JSON-compatible evidence; verify_record(record)
checks saved evidence without consulting a later checkout; verify_record(record,
root) additionally compares with the current build inputs. validate(record,
target) and verify(record, root, target) also accept an expected target.
Call collect beside
the native build and bind its result to the binary in the enclosing provenance
record. Never use collect to reconstruct evidence for an old release.

Components have id/name/kind/scope/origin/sourceFiles/description/limitations, optional
version and license, and licenseText (standard license) or licenseEvidence
(custom SPDX LicenseRef; use its name/text in CycloneDX, not license.id).
sourceFiles contain repository-relative path, exact-byte sha256 and role.
No component establishes a runtime DEPENDS_ON edge. In particular SDK headers,
the Windows export definition and JsonCpp headers are build interfaces.

The source allowlist is intentionally exact: updating vendored files requires
reviewing identities, attribution and licenses here, not merely refreshing hashes.
Only the reviewed originals and their deterministic all-LF/all-CRLF checkout
forms are allowed. Captured hashes always describe actual bytes, not normalized
content. Offline verification checks these pre-reviewed exact-byte alternatives.
There is no network access, Git requirement, timestamp, or binary detection.
"""

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET


TARGETS = ("windows-x86_64", "macos-universal")
EVIDENCE = "build-time-reviewed-embedded-source-inputs-not-binary-detection"
REPOSITORY = "https://github.com/miyako/4d-plugin-curl-v3"
SDK = "https://github.com/4d/4D-Plugin-SDK"
SDK_LICENSE_URL = (
    "https://raw.githubusercontent.com/4d/4D-Plugin-SDK/"
    "ad7944bc7a13d93db8097c4c8ff55ba2f6e36f86/LICENSE.md"
)
LIMITATIONS = [
    "Build-time source/declaration evidence, not historical release reconstruction, "
    "a signed attestation, proof of compiler execution or retained machine-code bytes.",
    "Only the reviewed embedded sources and JsonCpp header interface are covered; "
    "other vendor headers, OS/4D host APIs, toolchain, resources and transitive "
    "dependencies are outside this helper's coverage.",
    "Project lists are inspected, not evaluated MSBuild imports, compiler include "
    "resolution or conditional preprocessing. Include directory declarations are "
    "not proof of the compiler's effective search order.",
    "Source components are containment/build inputs, not inferred runtime dependency "
    "edges. An SDK's host-call interface is not a separately shipped runtime library.",
]

# Exact bytes inspected in this repository; ftpparse also matches the author's
# published files and the MD5 pair explicitly named in the dedication below.
HASHES = {
    "include/ftpparse.c": "08ed6b9847717a231386c4d566d4dba3900aaf5efe00641cc329dbe163d79651",
    "include/ftpparse.h": "0791f9a12a58e46f6d88b306f584c88b0a0033182efd8143456c0c6655e966a3",
    "4D Plugin API/4DPluginAPI.c": "5bac571c5c4cafd280fa7f23d775458a23701287e8735be27d4a2190002f4e3f",
    "4D Plugin API/4DPluginAPI.def": "ab72ac2a2e371e8ef97c1d0c9bb9597af6f21a8f2a1429ce839817ca800197b2",
    "4D Plugin API/4DPluginAPI.h": "c845a8ae3b552f514e16598605727bf5008eaa28df2401950ac2b7881df61f02",
    "4D Plugin API/EntryPoints.h": "60afb0b833c95d6c47b88d2d0eba0fb212c2c6b53a44e3cfc0b4c6956d25d2dd",
    "4D Plugin API/Flags.h": "c39ca489cb5dacd2ebcbb95d914795c60d557b87acc2456f6abf3fd63d66850b",
    "4D Plugin API/PrivateTypes.h": "329a5ba0d0369b4e96ad9afe4d0261407164dbf4c1379c5bbe1685669d20a53f",
    "4D Plugin API/PublicTypes.h": "7b8c3959f24267a2a398680ddd114acc14b33082974b1debc2a940a82cdb6155",
    "4D Plugin API/Classes/C_BLOB.cpp": "2a631b6111a16cc1ba6e4769a938d6bda09e1c91a92266e7e8d400adf7e89d0b",
    "4D Plugin API/Classes/C_BLOB.h": "1dd2d329855d56956434e58b99bfd39c5becc81e613b9992e79474d5ffa86631",
    "4D Plugin API/Classes/C_LONGINT.cpp": "685ba1c031c212df148ec7cbf9ab063d00f87388f8e6d7f527dd618735d7ccb8",
    "4D Plugin API/Classes/C_LONGINT.h": "7194dbdca04bafb410535af4503bfb409aacf8bb5735e1564b920feadcb9e9c8",
    "4D Plugin API/Classes/C_TEXT.cpp": "24aafc136c58448741235202aee4207eebe9770d1b458b48630b0fd0b78f5397",
    "4D Plugin API/Classes/C_TEXT.h": "7e3d01dcb328a958568a6517dea3ecae09895fa1330e2e4b308cf0651b99e840",
    "4D Plugin API/Classes/C_TYPES.h": "5859ff4d7004d983e68e38c974e19d20ad2d9dc670158564e2d9fceaf179a0af",
    "support/4DPlugin-JSON.cpp": "e403a82db1a2b071ee0ce2d7dab5691b9479de6cac562ee8dd7d8db448cfa052",
    "support/4DPlugin-JSON.h": "eba18fc6663838d25880e4c4bf0ee1dfde0a422d9cae63c84237cb040ee1093e",
    "support/ufopen.c": "1714d5260b61169073434df1059cbb171768580ea20ae643b39802cb4c6f5fec",
    "support/ufopen.h": "8499dae2c7357c61d80d4527c6fa0a2f2331ba6498c3eaf49e030c7af1dc5fbd",
    "include/json/allocator.h": "058a9743fdcc390c7534f9bcaf88f298a194e06ba25d4c037790a6701c638676",
    "include/json/assertions.h": "ea30b8fb30ef70a52a6435f6e6efbc37de03555fa192b33832e65cbd159b68bb",
    "include/json/config.h": "a607e32e34497e2c51df1c61e6627760618d7d6964d9f47dfa8165ad305063b9",
    "include/json/forwards.h": "4e5144062f296c821107af272c39df31b7ac6fcfefbeb66637958738fc09a117",
    "include/json/json.h": "05ccb35afa55a068f8cc2a195db46d89a7f6a458d1943ae009465834c6404a67",
    "include/json/json_features.h": "5a08a4c1e4afc047915a01dce28bbba69feeb2f452e0871c02d6f90f2d30cd68",
    "include/json/reader.h": "87a11f1c530c46bf6196976075d58907dfa27dea9a227d7580e0481f8e312da8",
    "include/json/value.h": "e8ecc50a7a5b8c7ab2aa25603cdc6fe3742c793fd113202dcaef6031d3d6f1ee",
    "include/json/version.h": "528690b85260c064a5e53ecb82601bf521dce082ba254f36a37eca16d8c141c2",
    "include/json/writer.h": "7fc693de912d4d571504aa350518fe675f319f00054eba09cd5afb7c82e6aa13",
}

# Generated once from the reviewed bytes above, never from an untrusted checkout
# during collection. The two mixed-ending originals remain separately approved.
CRLF_HASHES = {
    "include/ftpparse.c": "18465260fa1641f568138a26da654452b096472ee39cd4e9381181dd4832d719",
    "include/ftpparse.h": "a440b44306d4f9714e39410d4881fe9a72c3487a8f46926c1f17508bec0e88e9",
    "4D Plugin API/4DPluginAPI.c": "bc126d8e5baba27600843c72e40015b8e28ac1c5c61f3c5b5d22aff13829a5cd",
    "4D Plugin API/4DPluginAPI.def": "db4ccfe9dac3e987ddd8c1a143528b51dfb16425a2e65dcafb930c214dc4ba87",
    "4D Plugin API/4DPluginAPI.h": "0892201f07cf22ea8265a74688e2e5187d5945de9aef6e911201b39baf152f6f",
    "4D Plugin API/EntryPoints.h": "d6a06a21c3a380fe3828b6036c04ebefab65633b43132eb2af9203be7aa92061",
    "4D Plugin API/Flags.h": "8252981f0c6f99a16ba080933d04e2a0770d9aed50034b799d2e2cd481bd4fe5",
    "4D Plugin API/PrivateTypes.h": "421afd3e6178c308fe053fd6b25469c2cf17557f95df91cca723face35083cb5",
    "4D Plugin API/PublicTypes.h": "a166bbadc0b8dcd3bf2e21b5eaf879eb32968a7edce87b3958ae724701f5db93",
    "4D Plugin API/Classes/C_BLOB.cpp": "a7f0eacf158fcee7eba765843d703e1ca98afa3ee852c78f423af4cfdef19f3e",
    "4D Plugin API/Classes/C_BLOB.h": "3d6f8d6e8a3e222b39991319ff08bcd2ab69f284879a7f273039fa2e59f23a66",
    "4D Plugin API/Classes/C_LONGINT.cpp": "7a5145b9b91da813037a75113380123fd2e3f1f7e2a5af7e4ada818505ca257f",
    "4D Plugin API/Classes/C_LONGINT.h": "68a921711a9fe2f833afdb431d700f4a2d1142a48abd005dc5ec10d8b973e52e",
    "4D Plugin API/Classes/C_TEXT.cpp": "0539c0f83b20aa4a4968d1ee4cc491ce0ee46e9abb0bacccea1deac5a73c2311",
    "4D Plugin API/Classes/C_TEXT.h": "9c159256f0a71ab8e00eb746e630a0b4dc5c2ba8c6a462a289adad6ab5aa13ab",
    "4D Plugin API/Classes/C_TYPES.h": "5859ff4d7004d983e68e38c974e19d20ad2d9dc670158564e2d9fceaf179a0af",
    "support/4DPlugin-JSON.cpp": "f87141549a0553df4e6225dd8fce6bcb71ba32d53066ec3824ef91f013365fa8",
    "support/4DPlugin-JSON.h": "444119ca68bbf7cbe15d7a6850215331c4dc3ec8715cdebfb100016a7dc35dd0",
    "support/ufopen.c": "e02701b8a69686fa42f2c85efc4621dc3744bbbbead3f6522a7c8982bb24312f",
    "support/ufopen.h": "42d50edc0cfb9ddf872d901965061a7644326d4fad012a147df9627aa7282442",
    "include/json/allocator.h": "e4576213639d00bd3f7a2fee4ef2ee215411969f84dc8d62ad8a312d7bb544a6",
    "include/json/assertions.h": "50382957eccd1b2a5fa2a1975421de03329907dc3e987a5392ca10fe590a4383",
    "include/json/config.h": "6353f33cdb9df81531b87b7af4af3f8b1f5b29470b77107200fab2a71eb6af16",
    "include/json/forwards.h": "ade21d924814095f751dc2b8062d1ddcad4d6d4ae45fee2d3b1ff24819d6d340",
    "include/json/json.h": "6e41eb708610f65318a5ea4d02b37ba3ad2713a806e864af2c0eee44de645411",
    "include/json/json_features.h": "3d4992ca99b287e4fea8bb760adc61126a1e84369084e808a3c2024187a3f21f",
    "include/json/reader.h": "d6b1d5e21ac9c839d8666c37129f69530e4fa504b4e8f7464885c840851c7a58",
    "include/json/value.h": "d8a9b330253f8a0bfff18ce1ed8b876623c3c23a8738dc01ca54cd2b5613ed07",
    "include/json/version.h": "9f5304d790d6df24aa9e24ce3190bb52e3cef5f9af666e2da70cf974bcdab0b2",
    "include/json/writer.h": "d4e12e2110287b68bd282c7056f2b2cb5199f3686fff1df4255544994f13c38c",
}
LF_HASHES = {
    "4D Plugin API/Classes/C_TYPES.h": "07a2dbc6f772f53bf332dd87986890995e793678138216726897943a6a7d17c0",
    "support/4DPlugin-JSON.cpp": "fe791db1202de5847c162abbb18e659e0005e6670d69c850c6424b5ba526ff98",
    "support/4DPlugin-JSON.h": "361bd4eeb0ea309ec9c0e50a3ec9f7f96a8c6f4261a4ea0d6801440acfda649f",
}

MIT_BODY = """Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""
SDK_ATTRIBUTION = "Copyright (c) 2017-present, 4D, Inc."
SDK_LICENSE = "MIT License\n\n" + SDK_ATTRIBUTION + "\n\n" + MIT_BODY
FTP_LICENSE = (
    "2023.09.29: I hereby place the ftpparse package (in particular, ftpparse.c "
    "with MD5 checksum 8d3ad77f80704b513d4edf3b01629205 and ftpparse.h with MD5 "
    "checksum f12d28cc60a3c0475d42ae6a79552d4a) into the public domain. "
    "The package is no longer copyrighted."
)
JSON_NOTICE = (
    "// Copyright 2007-2010 Baptiste Lepilleur and The JsonCpp Authors\n"
    "// Distributed under MIT license, or public domain if desired and\n"
    "// recognized in your jurisdiction.\n"
    "// See file LICENSE for detail or copy at http://jsoncpp.sourceforge.net/LICENSE\n"
)
WITNESSES = ("4DPlugin-cURL.cpp", "4DPlugin-cURL.h")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _approved_hashes(path):
    return {HASHES[path], CRLF_HASHES[path], LF_HASHES.get(path, HASHES[path])}


def _file(root, name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or ".." in path.parts or "\\" in name
            or ":" in name or path.as_posix() != name):
        raise ValueError("Expected repository-relative POSIX path")
    file = root / name
    if not file.resolve().is_relative_to(root.resolve()):
        raise ValueError("Source input escapes repository: " + name)
    return file.read_bytes()


def _license(identifier, name, text, url, attribution):
    return {"id": identifier, "name": name, "text": text,
            "sha256": sha256(text.encode("utf-8")), "url": url,
            "attribution": attribution}


def _components(target):
    def component(ident, name, paths, description, limitations, origin, **extra):
        files = []
        for path in sorted(paths):
            role = ("translation-unit" if path.endswith((".c", ".cpp")) else
                    "linker-interface" if path.endswith(".def") else "header-interface")
            files.append({"path": path, "sha256": HASHES[path], "role": role})
        compiled = any(f["role"] == "translation-unit" for f in files)
        return {
            "id": ident, "name": name,
            "kind": "compiled-source" if compiled else "build-interface",
            "scope": "compiled-source" if compiled else "sdk-interface",
            "origin": origin, "sourceFiles": files, "description": description,
            "limitations": limitations, **extra,
        }

    sdk = [p for p in HASHES if p.startswith("4D Plugin API/")
           and "/Classes/" not in p and
           (target == "windows-x86_64" or not p.endswith(".def"))]
    return [
        component(
            "embedded-ftpparse", "ftpparse", ["include/ftpparse.c", "include/ftpparse.h"],
            "D. J. Bernstein FTP LIST parser, compiled directly into the plugin.",
            ["Reviewed published 20001223 bytes or their approved exact CRLF checkout "
             "form; the 2023 dedication supersedes the older "
             "commercial-use notification in the source. Public domain is not "
             "relabelled as MIT or CC0; no package-manager identifier is inferred."],
            "https://cr.yp.to/ftpparse.html", version="20001223",
            license="LicenseRef-ftpparse-public-domain",
            licenseEvidence=_license(
                "LicenseRef-ftpparse-public-domain", "ftpparse public-domain dedication",
                FTP_LICENSE, "https://cr.yp.to/distributors.html", "D. J. Bernstein"),
        ),
        component(
            "embedded-4d-sdk", "4D Plugin SDK", sdk,
            "Compiled 4DPluginAPI.c host-call glue plus SDK header/export interfaces.",
            ["Local API source/header revisions v14/v13 are not an SDK release version. "
             "No upstream commit/version is proven: several local files differ from "
             "the upstream license-reference commit. The referenced MIT text is the "
             "4D SDK's own license, not the plugin repository's root license."],
            SDK, license="MIT",
            licenseText=_license("MIT", "MIT License", SDK_LICENSE,
                                 SDK_LICENSE_URL, SDK_ATTRIBUTION),
        ),
        component(
            "embedded-4d-cpp-wrappers", "4D plugin C++ wrappers",
            [p for p in HASHES if "/Classes/" in p],
            "C_BLOB, C_LONGINT and C_TEXT local C++ glue and C_TYPES header interface.",
            ["Files attribute creation to miyako, not to the 4D SDK copyright holder. "
             "No independent version or explicit per-file license; no SDK/root MIT "
             "inheritance is asserted. ARRAY_TEXT.cpp/.h are not project inputs."],
            REPOSITORY + "/tree/master/4D%20Plugin%20API/Classes",
        ),
        component(
            "embedded-json-helper", "4DPlugin-JSON helper",
            ["support/4DPlugin-JSON.cpp", "support/4DPlugin-JSON.h"],
            "Local JSON/UTF conversion glue calling 4D host object APIs.",
            ["Not JsonCpp or a separately versioned JSON parser. No upstream author, "
             "independent version or per-file license is established; root MIT is "
             "not automatically assigned."],
            REPOSITORY + "/tree/master/support",
        ),
        component(
            "embedded-utf-path-helper", "ufopen UTF-8 path helper",
            ["support/ufopen.c", "support/ufopen.h"],
            "Local UTF-8 Windows path wrappers with POSIX branches, compiled directly.",
            ["No third-party upstream, independent version, author or per-file "
             "license is established; root MIT is not automatically assigned."],
            REPOSITORY + "/tree/master/support",
        ),
        component(
            "interface-jsoncpp", "JsonCpp header interface",
            [p for p in HASHES if p.startswith("include/json/")],
            "JsonCpp headers reachable through 4DPlugin-cURL.h; build interface only.",
            ["version.h reports string 1.9.4 but numeric patch 3; no unambiguous "
             "package version or corresponding binary identity is inferred. "
             "The headers explicitly offer MIT or jurisdiction-dependent public "
             "domain; MIT is the selected declared option. The captured text is "
             "the source notice, not an extracted full MIT license. No JsonCpp "
             "implementation translation unit is in either project's source list."],
            "https://github.com/open-source-parsers/jsoncpp", license="MIT",
            licenseText=_license(
                "MIT", "JsonCpp source license notice", JSON_NOTICE,
                "https://github.com/open-source-parsers/jsoncpp/blob/1.9.4/LICENSE",
                "Copyright 2007-2010 Baptiste Lepilleur and The JsonCpp Authors"),
        ),
    ]


def _expected_lists(target):
    files = [f for c in _components(target) for f in c["sourceFiles"]
             if not c["id"].startswith("interface-")]
    sources = sorted([f["path"] for f in files if f["role"] == "translation-unit"]
                     + [WITNESSES[0]])
    headers = sorted([f["path"] for f in files if f["role"] == "header-interface"]
                     + [WITNESSES[1]])
    return sources, headers


def _msbuild(data):
    tree = ET.fromstring(data)
    ns = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
    lists = []
    for kind in ("ClCompile", "ClInclude"):
        paths = []
        for group in tree.findall("m:ItemGroup", ns):
            for item in group.findall("m:" + kind, ns):
                if group.get("Condition") or set(item.attrib) != {"Include"}:
                    raise ValueError("Conditional/indirect MSBuild source item")
                if any(child.tag.rsplit("}", 1)[-1] != "CompileAs" for child in item):
                    raise ValueError("Unsupported MSBuild source item metadata")
                paths.append(item.attrib["Include"].replace("\\", "/"))
        lists.append(paths)
    groups = [g for g in tree.findall("m:ItemDefinitionGroup", ns)
              if g.get("Condition") == "'$(Configuration)|$(Platform)'=='Release|x64'"]
    if len(groups) != 1:
        raise ValueError("Expected one Release|x64 compile configuration")
    directories = groups[0].find("m:ClCompile/m:AdditionalIncludeDirectories", ns)
    if directories is None or not directories.text:
        raise ValueError("Missing MSBuild include directories")
    exports = groups[0].find("m:Link/m:ModuleDefinitionFile", ns)
    if (exports is None or exports.text is None
            or exports.text.replace("\\", "/") != "./4D Plugin API/4DPluginAPI.def"):
        raise ValueError("Unexpected MSBuild SDK export interface")
    return *lists, directories.text.split(";")


def _openstep(data):
    """Parse OpenStep plist syntax without macOS plutil (also runs on Windows)."""
    token = re.compile(r'\s+|/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|'
                       r'[{}()=;,]|[^\s{}()=;,"]+')
    text = data.decode("utf-8")
    tokens = []
    end = 0
    for match in token.finditer(text):
        if match.start() != end:
            raise ValueError("Unsupported Xcode plist syntax")
        end = match.end()
        value = match.group()
        if not (value.isspace() or value.startswith(("/*", "//"))):
            tokens.append(value)
    if end != len(text):
        raise ValueError("Incomplete Xcode plist")
    index = 0

    def take(expected=None):
        nonlocal index
        if index == len(tokens) or (expected and tokens[index] != expected):
            raise ValueError("Malformed Xcode plist")
        value = tokens[index]
        index += 1
        return value

    def parse():
        value = take()
        if value == "{":
            result = {}
            while index < len(tokens) and tokens[index] != "}":
                key = take()
                key = json.loads(key) if key.startswith('"') else key
                take("=")
                if key in result:
                    raise ValueError("Duplicate Xcode plist key")
                result[key] = parse()
                take(";")
            take("}")
            return result
        if value == "(":
            result = []
            while index < len(tokens) and tokens[index] != ")":
                result.append(parse())
                if index < len(tokens) and tokens[index] != ")":
                    take(",")
            take(")")
            return result
        if value in ("}", ")", "=", ";", ","):
            raise ValueError("Unexpected Xcode plist punctuation")
        return json.loads(value) if value.startswith('"') else value

    result = parse()
    if index != len(tokens):
        raise ValueError("Trailing Xcode plist input")
    return result


def _xcode(data):
    plist = _openstep(data)
    objects = plist["objects"]
    project = objects[plist["rootObject"]]
    targets = [objects[key] for key in project["targets"]
               if objects[key].get("isa") == "PBXNativeTarget"]
    if len(targets) != 1 or targets[0].get("name") != "cURL":
        raise ValueError("Expected one cURL Xcode target")
    paths = {}

    def walk(key, parent="", ancestors=()):
        if key in ancestors or key in paths:
            raise ValueError("Ambiguous/cyclic Xcode group path")
        obj = objects[key]
        if obj.get("sourceTree") not in ("<group>", "SOURCE_ROOT"):
            return
        base = "" if obj.get("sourceTree") == "SOURCE_ROOT" else parent
        path = str(PurePosixPath(base) / obj.get("path", ""))
        paths[key] = path
        if obj.get("isa") == "PBXGroup":
            for child in obj["children"]:
                walk(child, path, (*ancestors, key))

    walk(project["mainGroup"])
    lists = []
    for kind in ("PBXSourcesBuildPhase", "PBXHeadersBuildPhase"):
        phases = [objects[key] for key in targets[0]["buildPhases"]
                  if objects[key].get("isa") == kind]
        if len(phases) != 1:
            raise ValueError("Expected one Xcode source/header phase")
        files = []
        for key in phases[0]["files"]:
            obj = objects[key]
            if obj.get("isa") != "PBXBuildFile" or any(
                    key in obj for key in ("platformFilter", "platformFilters")):
                raise ValueError("Unsupported Xcode conditional source item")
            files.append(paths[obj["fileRef"]])
        lists.append(files)
    directories = []
    for obj in objects.values():
        settings = obj.get("buildSettings", {})
        if any(key.startswith(("EXCLUDED_SOURCE_FILE_NAMES", "INCLUDED_SOURCE_FILE_NAMES"))
               for key in settings):
            raise ValueError("Unsupported Xcode source exclusions")
        for key, value in settings.items():
            if "HEADER_SEARCH_PATHS" in key:
                directories.extend(value if isinstance(value, list) else [value])
    return *lists, sorted(set(directories))


def _project(target):
    return ("cURL.vcxproj" if target == "windows-x86_64"
            else "cURL.xcodeproj/project.pbxproj")


def collect(root, target):
    """Fail closed on unreviewed source bytes or changed source/header lists."""
    if target not in TARGETS:
        raise ValueError("Unsupported embedded-source target")
    root = Path(root)
    project = _project(target)
    data = _file(root, project)
    parser = _msbuild if target == "windows-x86_64" else _xcode
    sources, headers, directories = parser(data)
    expected_sources, expected_headers = _expected_lists(target)
    if sorted(sources) != expected_sources or sorted(headers) != expected_headers:
        raise ValueError("Project source/header lists differ from reviewed coverage")
    components = _components(target)
    for component in components:
        for source in component["sourceFiles"]:
            actual_hash = sha256(_file(root, source["path"]))
            if actual_hash not in _approved_hashes(source["path"]):
                raise ValueError("Unreviewed embedded source hash: " + source["path"])
            source["sha256"] = actual_hash
    witnesses = [{"path": p, "sha256": sha256(_file(root, p))} for p in WITNESSES]
    plugin_header = _file(root, WITNESSES[1]).decode("utf-8")
    for name in ("4DPluginAPI.h", "4DPlugin-JSON.h", "json/json.h", "ftpparse.h",
                 "C_TEXT.h", "C_BLOB.h", "C_LONGINT.h"):
        if not re.search(r'^\s*#include\s+"' + re.escape(name) + r'"', plugin_header, re.M):
            raise ValueError("Missing reviewed plugin include: " + name)
    return {
        "schemaVersion": 1, "target": target, "evidenceType": EVIDENCE,
        "configuration": [{"path": project, "sha256": sha256(data)}],
        "declarations": {"translationUnits": sorted(sources), "headers": sorted(headers),
                         "includeDirectories": directories},
        "sourceWitnesses": witnesses, "components": components,
        "limitations": list(LIMITATIONS),
    }


def validate(record, target=None):
    """Validate metadata and pinned source hashes offline; not authentication."""
    if not isinstance(record, dict):
        raise ValueError("Invalid embedded-source record")
    actual_target = record.get("target")
    if (actual_target not in TARGETS or (target is not None and actual_target != target)
            or type(record.get("schemaVersion")) is not int
            or record.get("schemaVersion") != 1 or record.get("evidenceType") != EVIDENCE):
        raise ValueError("Unsupported embedded-source record/target")
    sources, headers = _expected_lists(actual_target)
    declarations = record.get("declarations", {})
    if not isinstance(declarations, dict):
        raise ValueError("Invalid embedded-source declarations")
    directories = declarations.get("includeDirectories")
    if (declarations.get("translationUnits") != sources
            or declarations.get("headers") != headers
            or not isinstance(directories, list) or not directories
            or not all(isinstance(d, str) and d for d in directories)
            or set(declarations) != {"translationUnits", "headers", "includeDirectories"}):
        raise ValueError("Invalid embedded-source declarations")
    expected_components = _components(actual_target)
    components = record.get("components")
    if not isinstance(components, list) or len(components) != len(expected_components):
        raise ValueError("Embedded source identity/hash/license metadata mismatch")
    for component, expected in zip(components, expected_components):
        files = component.get("sourceFiles") if isinstance(component, dict) else None
        if not isinstance(files, list) or len(files) != len(expected["sourceFiles"]):
            raise ValueError("Embedded source identity/hash/license metadata mismatch")
        for source, expected_source in zip(files, expected["sourceFiles"]):
            actual_hash = source.get("sha256") if isinstance(source, dict) else None
            if (not isinstance(actual_hash, str)
                    or actual_hash not in _approved_hashes(expected_source["path"])):
                raise ValueError("Embedded source identity/hash/license metadata mismatch")
            expected_source["sha256"] = actual_hash
    if components != expected_components:
        raise ValueError("Embedded source identity/hash/license metadata mismatch")
    for key, paths in (("configuration", [_project(actual_target)]),
                       ("sourceWitnesses", list(WITNESSES))):
        rows = record.get(key)
        if (not isinstance(rows, list) or len(rows) != len(paths)
                or any(not isinstance(row, dict) or set(row) != {"path", "sha256"}
                       or row.get("path") != path
                       or not isinstance(row.get("sha256"), str)
                       or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                       for row, path in zip(rows, paths))):
            raise ValueError("Invalid embedded-source " + key)
    if (record.get("limitations") != LIMITATIONS or set(record) != {
            "schemaVersion", "target", "evidenceType", "configuration", "declarations",
            "sourceWitnesses", "components", "limitations"}):
        raise ValueError("Invalid embedded-source coverage metadata")
    return record


def verify(record, root, target):
    """Use only against the build's checkout, not a later release-analysis tree."""
    validate(record, target)
    if record != collect(root, target):
        raise ValueError("Embedded source record does not match current build inputs")
    return copy.deepcopy(record)


def verify_record(record, root=None):
    """Validate captured evidence offline, optionally recheck the build checkout."""
    validate(record)
    if root is not None:
        return verify(record, root, record["target"])
    return copy.deepcopy(record)
