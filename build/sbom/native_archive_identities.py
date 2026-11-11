"""Reviewed identities for selected archives lacking self-identifying strings.

The allowlist binds review to exact thin-archive bytes, not filenames. New or
changed archives stay unidentified until reviewed; do not extend it from nearby
headers, build dates, module search paths, or bare version strings. Versions are
recomputed from defined object data, including nghttp's relocated version string.
Refresh and verify require no platform tools, network access, or code execution.

Review: Xcode llvm-objdump --syms --reloc --section-headers and nm -g, followed
by the independent bounded reader below. Upstream references explain the API
layout/symbol names only; they do not prove archive acquisition or source origin.
"""

import hashlib
import re
import struct

from native_archive_objects import Object, members


# sha256(thin archive): (identity, intended target, member basename, version).
# A review of additional bytes must add a separate row, including each fat slice.
REVIEWED = {
    "82bc874148487608408c904ff3acc4c080b4f009e330bc5ac789f72a62bedcff":
        ("libiconv", "macos-x86_64", "iconv.o", "1.16"),
    "18a7d1093833726f715ac425bb960cd10f8e7dcac00843ce93a0601327143ae1":
        ("libiconv", "macos-arm64", "iconv.o", "1.16"),
    "b6ec6797d66824c6fd2076e56e1e9739319aa04f121f2879673fd1548f512822":
        ("libiconv", "windows-x86_64", "iconv.obj", "1.18"),
    "e13190a374d20c5d4a69628dc63c546d4a33e3c967bc6e7410ad8efeef522680":
        ("nghttp2", "macos-x86_64", "nghttp2_version.c.o", "1.70.0"),
    "bd03b62de58593d0db7b3130e7cf689f488250ace172615be4c4084e67bcd79d":
        ("nghttp2", "macos-arm64", "nghttp2_version.c.o", "1.70.0"),
    "7f2728adf08ffd4cabaf05581e539afbd36510623d8aae577cdb0711bf42492d":
        ("nghttp2", "windows-x86_64", "nghttp2_version.c.obj", "1.70.0"),
    "b9b48d4a288b93b7887dddd63ef0593ca922d9a6d25893b4db3736b07c69eefe":
        ("nghttp3", "macos-x86_64", "nghttp3_version.o", "1.15.0"),
    "23c73903217f27d41161d29f2736fc8c5da32ce8c60e6e5419af5171fa228973":
        ("nghttp3", "macos-arm64", "nghttp3_version.o", "1.15.0"),
    "c9127497928cab0f48f1bf4c2468149262abdf213698eac3c8a807e4f1f5314b":
        ("libmodman", "macos-arm64", "module_manager.o", None),
    "dfe9b2ec5b51f2c8d22177777167ec6446c76a626c46e1fa8f7c5a9b19213421":
        ("libmodman", "macos-x86_64", "module_manager.o", None),
    "4cd35ae3f56ec7ea9202ab8d5ab93e3884a9efb6ddfb14b3002d14a07e4bd775":
        ("libmodman", "windows-x86_64", "module_manager.obj", None),
    "1a6bf0a9de67201ead76b7d7ff71484f0c146ef17cb7750d2944a1584a8a9417":
        ("libproxy", "macos-arm64", "proxy.o", None),
    "0b2fbb63f4dafad308f6d297ed0e4be66ad7376758f93a8fbdaa74d80e8fe9a5":
        ("libproxy", "macos-x86_64", "proxy.o", None),
    "4fcfa7563d122ea3858fb76606a3ead7bbfacac3822cf0d978255e1eeb837dee":
        ("libproxy", "windows-x86_64", "proxy.obj", None),
}

ICONV_SOURCE = "https://github.com/arthenica/libiconv/blob/baaba39736e3b498e1597bf0e5e899b1f753fb01/"
NGHTTP2_SOURCE = "https://github.com/nghttp2/nghttp2/blob/28d4846d201f0444f208cf6373b8563258feaafb/"
NGHTTP3_SOURCE = "https://github.com/ngtcp2/nghttp3/blob/a1a435bf85dc1cf1f18d799ca81d1e75ac27b7a1/"
PROXY_SOURCE = "https://github.com/libproxy/libproxy/blob/e78a5ccfe0a2340f2c73e419767f8492ffc2787a/"
SOURCES = {
    "libiconv": [ICONV_SOURCE + "lib/iconv.c", ICONV_SOURCE + "include/iconv.h.in"],
    "nghttp2": [NGHTTP2_SOURCE + "lib/nghttp2_version.c",
                NGHTTP2_SOURCE + "lib/includes/nghttp2/nghttp2.h",
                NGHTTP2_SOURCE + "lib/includes/nghttp2/nghttp2ver.h.in"],
    "nghttp3": [NGHTTP3_SOURCE + "lib/nghttp3_version.c",
                NGHTTP3_SOURCE + "lib/includes/nghttp3/nghttp3.h",
                NGHTTP3_SOURCE + "lib/includes/nghttp3/version.h.in"],
    "libmodman": [PROXY_SOURCE + "libmodman/module_manager.hpp"],
    "libproxy": [PROXY_SOURCE + "libproxy/proxy.h"],
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def inspect_member(name, target, obj):
    """Derive identity evidence from object definitions, never symbol references."""
    mac = target.startswith("macos-")
    prefix = "_" if mac else ""
    version, value = None, None
    if name == "libiconv":
        symbol = prefix + "_libiconv_version"
        definitions = [symbol, prefix + "libiconv_open", prefix + "libiconv_close"]
        offset, raw = obj.value(symbol, 4)
        number = struct.unpack("<I", raw)[0]
        if not 0 < number <= 0xFFFF:
            raise ValueError("Unsupported libiconv version integer")
        version = f"{number >> 8}.{number & 255}"
        value = {"symbol": symbol, "objectOffset": offset, "hex": raw.hex(),
                 "encoding": "(major << 8) | minor"}
    elif name in ("nghttp2", "nghttp3"):
        symbol = prefix + "version"
        definitions = [prefix + name + "_version", symbol]
        offset, raw = obj.value(symbol, 8)
        age, number = struct.unpack("<II", raw)
        string_offset, version = obj.pointed_string(symbol, 8)
        decoded = f"{number >> 16}.{(number >> 8) & 255}.{number & 255}"
        if age != 1 or number > 0xFFFFFF or not re.fullmatch(r"\d+\.\d+\.\d+", version) or version != decoded:
            raise ValueError("Conflicting or unsupported nghttp version record")
        value = {"symbol": symbol, "objectOffset": offset, "hex": raw.hex(),
                 "encoding": "age=1; (major << 16) | (minor << 8) | patch",
                 "relocatedStringObjectOffset": string_offset, "relocatedString": version}
    elif name == "libproxy":
        definitions = [prefix + "px_proxy_factory_" + suffix
                       for suffix in ("new", "free", "get_proxies", "free_proxies")]
    elif name == "libmodman":
        definitions = (["__ZN9libmodman14module_manager12load_builtinEP9mm_module",
                        "__ZN9libmodman14module_managerD1Ev"] if mac else
                       ["?load_builtin@module_manager@libmodman@@QEAA_NPEAUmm_module@@@Z",
                        "??1module_manager@libmodman@@QEAA@XZ"])
    else:
        raise ValueError(f"Unsupported reviewed archive identity: {name}")
    evidence = {"objectFormat": obj.format,
                "definitions": [obj.definition(symbol) for symbol in definitions]}
    if value is not None:
        evidence["versionData"] = value
    return version, evidence


def identities(data):
    part_hash = sha256(data)
    if part_hash not in REVIEWED:
        return []
    name, target, basename, expected = REVIEWED[part_hash]
    matches = [(member, offset, payload) for member, offset, payload in members(data)
               if member.replace("\\", "/").rsplit("/", 1)[-1] == basename]
    if len(matches) != 1:
        raise ValueError("Expected one reviewed archive identity member")
    member, offset, payload = matches[0]
    version, evidence = inspect_member(name, target, Object(payload))
    if version != expected:
        raise ValueError(f"Reviewed archive version disagreement: {name}")
    evidence.update({"sliceSha256": part_hash, "member": member, "memberOffset": offset,
                     "memberSha256": sha256(payload)})
    identity = {
        "name": name, "version": version,
        "evidenceType": "archive-version-object-data" if version else "archive-defined-symbols",
        "evidence": evidence, "origin": None, "license": None, "purl": None,
        "sourceMetadata": {
            "references": list(SOURCES[name]),
            "relationship": "API/symbol interpretation only; archive origin and source revision unknown.",
        },
    }
    if version is None:
        identity["versionStatus"] = (
            "unknown; defined library-specific symbols establish name, not release version")
    return [identity]
